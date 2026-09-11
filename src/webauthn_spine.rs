//! Async orchestration "spine" for the WebAuthn register/login ceremony
//! (feature `ceremony`).
//!
//! [`crate::webauthn_ceremony`] holds the **pure** wrappers over `webauthn-rs`:
//! they verify attestations/assertions and derive credential material, but touch
//! no storage and no sessions. This module threads those wrappers together with
//! the challenge-state store and the async credential store
//! ([`crate::webauthn_store::WebauthnCredentialBackend`]) so a consumer gets a
//! ready-made start/finish flow instead of re-writing the same orchestration in
//! aqua-node and aquafier.
//!
//! ## Design decision: return an outcome DTO, host issues its own session
//!
//! The finish functions return a plain **outcome DTO** ([`RegisterOutcome`],
//! [`LoginOutcome`]) describing the verified result. They do NOT mint a session,
//! set a cookie, or take a session trait: session issuance stays OUTSIDE
//! `aqua-auth`, in the host, because sessions are a host concern (cookie shape,
//! CAIP-122 `SessionStore`, JWT, …) and vary per consumer. Keeping the spine
//! session-agnostic means one flow serves every host.
//!
//! ## Why a dedicated ceremony-state store, not `ChallengeStore`
//!
//! [`crate::challenge::ChallengeStore`] is CAIP-122-specific: it is gated on the
//! `http` feature, is keyed by nonce, and its stored [`crate::types::Challenge`]
//! carries a rendered CAIP-122 *message* with no slot for arbitrary bytes. The
//! WebAuthn ceremony must persist a `webauthn-rs` `PasskeyRegistration` /
//! `PasskeyAuthentication` (plus an optional `intended_did`) between start and
//! finish, which that struct cannot hold — and `ChallengeStore` is on the
//! semver-locked public surface, so it is not extended here. [`CeremonyStateStore`]
//! reuses `ChallengeStore`'s *semantics* (in-memory, per-entry TTL, single-use,
//! bounded capacity) over the ceremony state instead.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse,
};

use crate::webauthn_ceremony::{
    build_webauthn, login_finish, login_start, passkey_from_blob, register_finish, register_start,
    CeremonyError, RegisterMode, WebauthnConfig,
};
use crate::webauthn_store::{CredentialId, WebauthnCredentialBackend};

/// Default cap on concurrently pending ceremonies, mirroring
/// [`crate::challenge::MAX_CHALLENGES`]. Pending ceremony state is pre-auth,
/// single-use and short-TTL, so the store is never unbounded.
pub const MAX_PENDING_CEREMONIES: usize = 8192;

// ── Ceremony-state store ────────────────────────────────────────────────────

enum CeremonyState {
    Registration {
        state: PasskeyRegistration,
        intended_did: Option<String>,
    },
    Authentication {
        state: PasskeyAuthentication,
    },
}

struct Entry {
    state: CeremonyState,
    expires_at: Instant,
}

/// In-memory, single-use, TTL-bounded store for in-flight WebAuthn ceremony
/// state, keyed by a fresh challenge id (a v4 UUID).
///
/// Semantics mirror [`crate::challenge::ChallengeStore`]: a `take_*` consumes the
/// entry (single-use), entries past their per-entry TTL are treated as absent and
/// purged lazily, and the store is hard-capped (expired entries purged first,
/// then the oldest-expiring entry evicted) so a flood of `*_start` calls cannot
/// grow it without bound.
pub struct CeremonyStateStore {
    entries: Mutex<HashMap<String, Entry>>,
    max: usize,
}

impl Default for CeremonyStateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CeremonyStateStore {
    pub fn new() -> Self {
        Self::with_capacity(MAX_PENDING_CEREMONIES)
    }

    pub fn with_capacity(max: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max: max.max(1),
        }
    }

    /// Number of pending (not-yet-purged) ceremonies.
    pub fn len(&self) -> usize {
        self.entries.lock().map(|m| m.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn poisoned() -> CeremonyError {
        CeremonyError::Internal("ceremony-state store lock poisoned".into())
    }

    /// Store registration state (+ optional `intended_did`) under a fresh
    /// challenge id, returning that id.
    pub fn put_registration(
        &self,
        state: PasskeyRegistration,
        intended_did: Option<String>,
        ttl: Duration,
    ) -> Result<String, CeremonyError> {
        self.insert(
            CeremonyState::Registration {
                state,
                intended_did,
            },
            ttl,
        )
    }

    /// Store authentication state under a fresh challenge id, returning that id.
    pub fn put_authentication(
        &self,
        state: PasskeyAuthentication,
        ttl: Duration,
    ) -> Result<String, CeremonyError> {
        self.insert(CeremonyState::Authentication { state }, ttl)
    }

    fn insert(&self, state: CeremonyState, ttl: Duration) -> Result<String, CeremonyError> {
        let mut map = self.entries.lock().map_err(|_| Self::poisoned())?;
        if map.len() >= self.max {
            Self::purge_expired(&mut map);
            if map.len() >= self.max {
                Self::evict_oldest(&mut map);
            }
        }
        let id = Uuid::new_v4().to_string();
        map.insert(
            id.clone(),
            Entry {
                state,
                expires_at: Instant::now() + ttl,
            },
        );
        Ok(id)
    }

    /// Consume the registration state at `challenge_id` (single-use). Errors if
    /// the id is unknown or the entry has expired.
    pub fn take_registration(
        &self,
        challenge_id: &str,
    ) -> Result<(PasskeyRegistration, Option<String>), CeremonyError> {
        match self.take(challenge_id)? {
            CeremonyState::Registration {
                state,
                intended_did,
            } => Ok((state, intended_did)),
            CeremonyState::Authentication { .. } => Err(CeremonyError::BadRequest(
                "challenge is not a registration ceremony".into(),
            )),
        }
    }

    /// Consume the authentication state at `challenge_id` (single-use). Errors if
    /// the id is unknown or the entry has expired.
    pub fn take_authentication(
        &self,
        challenge_id: &str,
    ) -> Result<PasskeyAuthentication, CeremonyError> {
        match self.take(challenge_id)? {
            CeremonyState::Authentication { state } => Ok(state),
            CeremonyState::Registration { .. } => Err(CeremonyError::BadRequest(
                "challenge is not a login ceremony".into(),
            )),
        }
    }

    fn take(&self, challenge_id: &str) -> Result<CeremonyState, CeremonyError> {
        let mut map = self.entries.lock().map_err(|_| Self::poisoned())?;
        let entry = map.remove(challenge_id).ok_or_else(|| {
            CeremonyError::BadRequest("unknown or expired ceremony challenge".into())
        })?;
        if Instant::now() >= entry.expires_at {
            return Err(CeremonyError::BadRequest(
                "ceremony challenge expired".into(),
            ));
        }
        Ok(entry.state)
    }

    fn purge_expired(map: &mut HashMap<String, Entry>) {
        let now = Instant::now();
        map.retain(|_, e| e.expires_at > now);
    }

    fn evict_oldest(map: &mut HashMap<String, Entry>) {
        if let Some(victim) = map
            .iter()
            .min_by(|a, b| {
                a.1.expires_at
                    .cmp(&b.1.expires_at)
                    .then_with(|| a.0.cmp(b.0))
            })
            .map(|(k, _)| k.clone())
        {
            map.remove(&victim);
        }
    }
}

// ── Outcome DTOs ─────────────────────────────────────────────────────────────

/// Options + challenge id returned by [`register_start_flow`]. `options` is the
/// browser `navigator.credentials.create()` payload; `challenge_id` is echoed
/// back to [`register_finish_flow`].
#[derive(Serialize)]
pub struct StartedRegistrationFlow {
    pub options: CreationChallengeResponse,
    pub challenge_id: String,
}

/// Options + challenge id returned by [`login_start_flow`]. `options` is the
/// browser `navigator.credentials.get()` payload; `challenge_id` is echoed back
/// to [`login_finish_flow`].
#[derive(Serialize)]
pub struct StartedLoginFlow {
    pub options: RequestChallengeResponse,
    pub challenge_id: String,
}

/// Verified result of a registration. The host stores nothing further and issues
/// its own session (if any) from `did`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterOutcome {
    /// The DID the credential is bound to (the credential's own `did:key` for an
    /// anonymous/passkey-as-identity registration, or the wallet DID for a
    /// second factor).
    pub did: String,
    pub credential_id: CredentialId,
    pub credential_id_hex: String,
    pub label: Option<String>,
}

/// Verified result of a login. The host mints its own session from `did`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginOutcome {
    pub did: String,
    pub credential_id: CredentialId,
    /// The credential's sign counter after the monotonic bump (never decreases).
    pub new_sign_count: u32,
}

// ── Flow functions ──────────────────────────────────────────────────────────

/// Phase 1 (register): build the creation challenge and persist ceremony state.
///
/// Returns the browser `options` and a fresh `challenge_id` to echo back to
/// [`register_finish_flow`]. For [`RegisterMode::SecondFactor`] the mode's `did`
/// is recorded as the challenge's `intended_did`.
pub async fn register_start_flow(
    config: &dyn WebauthnConfig,
    states: &CeremonyStateStore,
    mode: &RegisterMode,
) -> Result<StartedRegistrationFlow, CeremonyError> {
    let webauthn = build_webauthn(config)?;
    let started = register_start(&webauthn, mode)?;
    let challenge_id = states.put_registration(
        started.state,
        started.intended_did,
        config.challenge_ttl_register(),
    )?;
    Ok(StartedRegistrationFlow {
        options: started.options,
        challenge_id,
    })
}

/// Phase 2 (register): consume the challenge, verify the attestation, persist the
/// credential, and return the [`RegisterOutcome`].
///
/// The challenge is consumed **before** verification (single-use: a replay of a
/// spent or expired `challenge_id` fails). For a second-factor registration the
/// challenge's recorded `intended_did` MUST equal `completing_did` — this is
/// checked here in the spine as defense in depth, before any `webauthn-rs` work,
/// in addition to the same check inside [`register_finish`].
pub async fn register_finish_flow(
    config: &dyn WebauthnConfig,
    states: &CeremonyStateStore,
    cred_backend: &dyn WebauthnCredentialBackend,
    challenge_id: &str,
    attestation: &RegisterPublicKeyCredential,
    completing_did: Option<&str>,
    label: Option<String>,
) -> Result<RegisterOutcome, CeremonyError> {
    // Consume first: single-use holds even if verification below fails.
    let (state, intended_did) = states.take_registration(challenge_id)?;
    check_intended_did(intended_did.as_deref(), completing_did)?;

    let webauthn = build_webauthn(config)?;
    let finished = register_finish(
        &webauthn,
        attestation,
        &state,
        intended_did.as_deref(),
        completing_did,
        label,
    )?;
    finalize_registration(cred_backend, finished).await
}

/// Phase 1 (login): build the request challenge and persist ceremony state.
///
/// For a targeted login pass `Some(did)`: the DID's stored passkeys are fetched
/// via [`WebauthnCredentialBackend::list_for_did`] to constrain
/// `allowCredentials`. For discoverable (usernameless) login pass `None`.
pub async fn login_start_flow(
    config: &dyn WebauthnConfig,
    states: &CeremonyStateStore,
    cred_backend: &dyn WebauthnCredentialBackend,
    did: Option<&str>,
) -> Result<StartedLoginFlow, CeremonyError> {
    let passkeys = match did {
        Some(did) => {
            let stored = cred_backend
                .list_for_did(did)
                .await
                .map_err(|e| CeremonyError::Internal(format!("list credentials for {did}: {e}")))?;
            stored
                .iter()
                .filter_map(|c| passkey_from_blob(&c.public_key))
                .collect::<Vec<_>>()
        }
        None => Vec::new(),
    };
    let webauthn = build_webauthn(config)?;
    let (options, state) = login_start(&webauthn, &passkeys)?;
    let challenge_id = states.put_authentication(state, config.challenge_ttl_login())?;
    Ok(StartedLoginFlow {
        options,
        challenge_id,
    })
}

/// Phase 2 (login): consume the challenge, verify the assertion, bump the
/// authenticator's sign count (monotonically), and return the [`LoginOutcome`].
///
/// The challenge is consumed before verification (single-use). The authenticated
/// credential is looked up to recover its bound DID; an assertion for a
/// credential the store does not know is rejected.
pub async fn login_finish_flow(
    config: &dyn WebauthnConfig,
    states: &CeremonyStateStore,
    cred_backend: &dyn WebauthnCredentialBackend,
    challenge_id: &str,
    assertion: &PublicKeyCredential,
) -> Result<LoginOutcome, CeremonyError> {
    let state = states.take_authentication(challenge_id)?;
    let webauthn = build_webauthn(config)?;
    let finished = login_finish(&webauthn, assertion, &state)?;
    finalize_login(cred_backend, finished).await
}

// ── Internal helpers (store wiring; unit-tested directly) ────────────────────

/// Defense-in-depth gate: a second-factor challenge (`intended_did.is_some()`)
/// may only be completed by the caller it was issued to. Anonymous challenges
/// (`intended_did == None`) impose no such constraint.
fn check_intended_did(
    intended_did: Option<&str>,
    completing_did: Option<&str>,
) -> Result<(), CeremonyError> {
    match intended_did {
        Some(intended) if completing_did != Some(intended) => Err(CeremonyError::BadRequest(
            "second-factor registration: completing DID does not match the challenge's intended DID"
                .into(),
        )),
        _ => Ok(()),
    }
}

/// Persist the verified credential and build the [`RegisterOutcome`].
async fn finalize_registration(
    cred_backend: &dyn WebauthnCredentialBackend,
    finished: crate::webauthn_ceremony::FinishedRegistration,
) -> Result<RegisterOutcome, CeremonyError> {
    let did = finished.did;
    let credential_id_hex = finished.credential_id_hex;
    let credential_id = finished.credential.credential_id.clone();
    let label = finished.credential.label.clone();
    cred_backend
        .insert(finished.credential)
        .await
        .map_err(|e| CeremonyError::Internal(format!("persist credential: {e}")))?;
    Ok(RegisterOutcome {
        did,
        credential_id,
        credential_id_hex,
        label,
    })
}

/// Recover the DID, apply the monotonic sign-count bump, and build the
/// [`LoginOutcome`].
async fn finalize_login(
    cred_backend: &dyn WebauthnCredentialBackend,
    finished: crate::webauthn_ceremony::FinishedLogin,
) -> Result<LoginOutcome, CeremonyError> {
    let cred_id = finished.credential_id;
    let stored = cred_backend
        .get_by_id(&cred_id)
        .await
        .map_err(|e| CeremonyError::Internal(format!("lookup credential: {e}")))?
        .ok_or_else(|| {
            CeremonyError::BadRequest("authenticated credential is not registered".into())
        })?;
    cred_backend
        .update_sign_count(&cred_id, finished.counter)
        .await
        .map_err(|e| CeremonyError::Internal(format!("update sign count: {e}")))?;
    // Read back the effective (monotonic) count so the outcome never reports a
    // regression the store rejected.
    let new_sign_count = cred_backend
        .get_by_id(&cred_id)
        .await
        .map_err(|e| CeremonyError::Internal(format!("reload credential: {e}")))?
        .map(|c| c.sign_count)
        .unwrap_or(finished.counter);
    Ok(LoginOutcome {
        did: stored.did,
        credential_id: cred_id,
        new_sign_count,
    })
}

#[cfg(test)]
mod tests {
    //! ## What these tests DO cover
    //!
    //! - The spine's own orchestration logic end-to-end for the START phases
    //!   (`register_start_flow`, `login_start_flow`), which need no authenticator.
    //! - [`CeremonyStateStore`]: single-use consumption, TTL expiry, unknown id,
    //!   wrong-kind, and bounded-capacity eviction.
    //! - The `intended_did` second-factor equality gate ([`check_intended_did`]),
    //!   the exact predicate `register_finish_flow` enforces before any
    //!   `webauthn-rs` work.
    //! - The store-wiring helpers [`finalize_registration`] (insert + outcome)
    //!   and [`finalize_login`] (DID recovery, monotonic sign-count, outcome),
    //!   driven with hand-built `Finished*` values against `InMemoryWebauthnStore`.
    //! - That the ceremony's `did:key` derivation matches the crate's canonical
    //!   P-256 `did:key` encoding (`key::P256_PREFIX`).
    //!
    //! ## What these tests do NOT cover
    //!
    //! A full `register_finish_flow` / `login_finish_flow` round trip cannot be
    //! exercised in a unit test: it requires a real `webauthn-rs` attestation /
    //! assertion, and this crate has no software-authenticator dev-dependency to
    //! synthesize one. So the `webauthn-rs` verification step inside the FINISH
    //! flows — and thus a live register→login round trip — is left to the
    //! consumer's integration/e2e layer with a real authenticator. Everything the
    //! spine adds *around* that verification (challenge lifecycle, the gate, store
    //! reads/writes, outcome construction) is covered here. No test fakes a pass.

    use super::*;
    use crate::webauthn_ceremony::{
        did_key_from_p256_compressed, FinishedLogin, FinishedRegistration,
    };
    use crate::webauthn_store::{InMemoryWebauthnStore, NewCredential};

    struct TestConfig {
        origins: Vec<String>,
    }

    impl Default for TestConfig {
        fn default() -> Self {
            Self {
                origins: vec!["http://localhost:3000".to_string()],
            }
        }
    }

    impl WebauthnConfig for TestConfig {
        fn rp_id(&self) -> &str {
            "localhost"
        }
        fn rp_name(&self) -> &str {
            "Aqua Test"
        }
        fn allowed_origins(&self) -> &[String] {
            &self.origins
        }
    }

    fn a_registration_state() -> PasskeyRegistration {
        let cfg = TestConfig::default();
        let webauthn = build_webauthn(&cfg).unwrap();
        register_start(&webauthn, &RegisterMode::Anonymous)
            .unwrap()
            .state
    }

    fn new_cred(did: &str, id: &[u8], sign_count: u32, label: Option<&str>) -> NewCredential {
        NewCredential {
            did: did.into(),
            credential_id: CredentialId(id.to_vec()),
            public_key: vec![1, 2, 3],
            sign_count,
            transports: vec![],
            label: label.map(Into::into),
        }
    }

    // ── CeremonyStateStore ──────────────────────────────────────────────

    #[test]
    fn ceremony_state_is_single_use() {
        let states = CeremonyStateStore::new();
        let id = states
            .put_registration(a_registration_state(), None, Duration::from_secs(300))
            .unwrap();
        assert_eq!(states.len(), 1);
        assert!(states.take_registration(&id).is_ok());
        assert_eq!(states.len(), 0, "take must consume the entry");
        // Reusing a consumed id fails.
        assert!(states.take_registration(&id).is_err());
    }

    #[test]
    fn ceremony_state_expires() {
        let states = CeremonyStateStore::new();
        let id = states
            .put_registration(a_registration_state(), None, Duration::from_millis(0))
            .unwrap();
        std::thread::sleep(Duration::from_millis(5));
        let err = states.take_registration(&id).unwrap_err();
        assert!(matches!(err, CeremonyError::BadRequest(_)), "got {err:?}");
    }

    #[test]
    fn take_unknown_challenge_is_err() {
        let states = CeremonyStateStore::new();
        assert!(states.take_registration("no-such-id").is_err());
        assert!(states.take_authentication("no-such-id").is_err());
    }

    #[test]
    fn wrong_ceremony_kind_is_rejected() {
        // A registration id cannot be consumed as a login (and vice versa).
        let states = CeremonyStateStore::new();
        let id = states
            .put_registration(a_registration_state(), None, Duration::from_secs(300))
            .unwrap();
        assert!(states.take_authentication(&id).is_err());
    }

    #[test]
    fn capacity_is_bounded_by_eviction() {
        let states = CeremonyStateStore::with_capacity(2);
        let _a = states
            .put_registration(a_registration_state(), None, Duration::from_secs(300))
            .unwrap();
        let _b = states
            .put_registration(a_registration_state(), None, Duration::from_secs(300))
            .unwrap();
        assert_eq!(states.len(), 2);
        // Third insert must not grow the store past its cap.
        let _c = states
            .put_registration(a_registration_state(), None, Duration::from_secs(300))
            .unwrap();
        assert!(states.len() <= 2, "hard cap must not be exceeded");
    }

    // ── intended_did gate ───────────────────────────────────────────────

    #[test]
    fn intended_did_gate_matrix() {
        // Anonymous (no intended_did): any completing_did is fine.
        assert!(check_intended_did(None, None).is_ok());
        assert!(check_intended_did(None, Some("did:key:zAnything")).is_ok());
        // Second factor: completing_did must equal intended_did.
        assert!(check_intended_did(Some("did:x:A"), Some("did:x:A")).is_ok());
        assert!(matches!(
            check_intended_did(Some("did:x:A"), Some("did:x:B")),
            Err(CeremonyError::BadRequest(_))
        ));
        assert!(matches!(
            check_intended_did(Some("did:x:A"), None),
            Err(CeremonyError::BadRequest(_))
        ));
    }

    // ── Start flows (no authenticator needed) ───────────────────────────

    #[tokio::test]
    async fn register_start_flow_anonymous_persists_and_returns_options() {
        let cfg = TestConfig::default();
        let states = CeremonyStateStore::new();
        let out = register_start_flow(&cfg, &states, &RegisterMode::Anonymous)
            .await
            .unwrap();
        assert!(!out.challenge_id.is_empty());
        assert_eq!(states.len(), 1);
        // Options are browser-facing JSON.
        serde_json::to_string(&out.options).unwrap();
        // Anonymous records no intended_did.
        let (_state, intended) = states.take_registration(&out.challenge_id).unwrap();
        assert!(intended.is_none());
        assert_eq!(states.len(), 0);
    }

    #[tokio::test]
    async fn register_start_flow_second_factor_records_intended_did() {
        let cfg = TestConfig::default();
        let states = CeremonyStateStore::new();
        let did = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
        let out = register_start_flow(
            &cfg,
            &states,
            &RegisterMode::SecondFactor {
                did: did.into(),
                existing_credential_ids: vec![],
            },
        )
        .await
        .unwrap();
        let (_state, intended) = states.take_registration(&out.challenge_id).unwrap();
        assert_eq!(intended.as_deref(), Some(did));
    }

    #[tokio::test]
    async fn login_start_flow_discoverable_persists_and_returns_options() {
        let cfg = TestConfig::default();
        let states = CeremonyStateStore::new();
        let store = InMemoryWebauthnStore::new();
        let out = login_start_flow(&cfg, &states, &store, None).await.unwrap();
        assert!(!out.challenge_id.is_empty());
        assert_eq!(states.len(), 1);
        serde_json::to_string(&out.options).unwrap();
        assert!(states.take_authentication(&out.challenge_id).is_ok());
    }

    #[tokio::test]
    async fn login_start_flow_targeted_reads_stored_credentials() {
        // Targeted login must fetch the DID's credentials via list_for_did. The
        // stored blobs here are not valid Passkeys, so they filter out to an
        // empty allowCredentials — exercising the fetch+filter path without a
        // real authenticator.
        let cfg = TestConfig::default();
        let states = CeremonyStateStore::new();
        let store = InMemoryWebauthnStore::new();
        let did = "did:key:zDnTargeted";
        store.insert(new_cred(did, b"cid", 0, None)).await.unwrap();
        let out = login_start_flow(&cfg, &states, &store, Some(did))
            .await
            .unwrap();
        assert!(!out.challenge_id.is_empty());
        assert_eq!(states.len(), 1);
    }

    // ── Finish-flow store wiring (helpers, hand-built Finished* values) ──

    #[tokio::test]
    async fn finalize_registration_inserts_and_builds_outcome() {
        let store = InMemoryWebauthnStore::new();
        let cred_id = CredentialId(b"newcid".to_vec());
        let finished = FinishedRegistration {
            credential: new_cred("did:key:zNew", b"newcid", 0, Some("laptop")),
            did: "did:key:zNew".into(),
            credential_id_hex: hex::encode(b"newcid"),
        };
        let out = finalize_registration(&store, finished).await.unwrap();
        assert_eq!(out.did, "did:key:zNew");
        assert_eq!(out.credential_id, cred_id);
        assert_eq!(out.credential_id_hex, hex::encode(b"newcid"));
        assert_eq!(out.label.as_deref(), Some("laptop"));
        // Credential is persisted and listable.
        let listed = store.list_for_did("did:key:zNew").await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].credential_id, cred_id);
    }

    #[tokio::test]
    async fn finalize_login_recovers_did_and_is_monotonic() {
        let store = InMemoryWebauthnStore::new();
        let cred_id = CredentialId(b"cid".to_vec());
        store
            .insert(new_cred("did:key:zLogin", b"cid", 0, None))
            .await
            .unwrap();

        let out = finalize_login(
            &store,
            FinishedLogin {
                credential_id: cred_id.clone(),
                counter: 5,
            },
        )
        .await
        .unwrap();
        assert_eq!(out.did, "did:key:zLogin");
        assert_eq!(out.credential_id, cred_id);
        assert_eq!(out.new_sign_count, 5);

        // A lower counter is ignored (monotonic).
        let out2 = finalize_login(
            &store,
            FinishedLogin {
                credential_id: cred_id.clone(),
                counter: 3,
            },
        )
        .await
        .unwrap();
        assert_eq!(out2.new_sign_count, 5);

        // A higher counter advances it.
        let out3 = finalize_login(
            &store,
            FinishedLogin {
                credential_id: cred_id.clone(),
                counter: 8,
            },
        )
        .await
        .unwrap();
        assert_eq!(out3.new_sign_count, 8);
    }

    #[tokio::test]
    async fn finalize_login_rejects_unknown_credential() {
        let store = InMemoryWebauthnStore::new();
        let err = finalize_login(
            &store,
            FinishedLogin {
                credential_id: CredentialId(b"ghost".to_vec()),
                counter: 1,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, CeremonyError::BadRequest(_)), "got {err:?}");
    }

    // ── DID derivation matches the crate's canonical P-256 did:key ──────

    #[test]
    fn did_derivation_matches_canonical_p256_encoding() {
        let key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let compressed = key.verifying_key().to_encoded_point(true);
        let mut c = [0u8; 33];
        c.copy_from_slice(compressed.as_bytes());

        let did = did_key_from_p256_compressed(&c);

        let mut bytes = crate::key::P256_PREFIX.to_vec();
        bytes.extend_from_slice(compressed.as_bytes());
        let canonical = format!("did:key:z{}", bs58::encode(&bytes).into_string());

        assert_eq!(did, canonical);
        assert!(did.starts_with("did:key:zDn"), "got {did}");
    }
}
