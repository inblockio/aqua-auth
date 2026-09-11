//! Real software-authenticator drive of the WebAuthn ceremony spine.
//!
//! The spine's own `#[cfg(test)]` suite (`src/webauthn_spine.rs`) covers every
//! part of the register/login flow that needs no authenticator: the START
//! phases, the ceremony-state store (single-use, TTL, capacity), the
//! `intended_did` gate, and the store-wiring helpers driven with hand-built
//! `Finished*` values. What it *cannot* cover — and what this suite adds — is a
//! live pass through the FINISH flows, because that needs a real `webauthn-rs`
//! attestation/assertion, which only a software authenticator can synthesize.
//!
//! This lives in the testkit (publish = false) on purpose: it pulls
//! `webauthn-authenticator-rs`, which must stay OUT of the crates.io-bound core
//! `aqua-auth` crate's dependency graph. See this crate's `Cargo.toml`.
//!
//! ## Why the versions must match
//!
//! `webauthn-authenticator-rs = "=0.6.1-dev"` is built on the same
//! `webauthn-rs-proto`/`webauthn-rs-core` `0.6.1-dev` that aqua-auth's
//! `webauthn-rs = "=0.6.1-dev"` re-exports, so `CreationChallengeResponse`,
//! `RegisterPublicKeyCredential`, `RequestChallengeResponse` and
//! `PublicKeyCredential` are literally the *same* types on both sides of the
//! wire. A mismatched authenticator version would be a different `-proto`
//! struct and would not compile against the spine's signatures, let alone
//! interop.

use aqua_auth::webauthn_ceremony::{
    did_key_from_p256_compressed, p256_compressed_from_passkey_blob, CeremonyError, RegisterMode,
    WebauthnConfig,
};
use aqua_auth::webauthn_spine::{
    login_finish_flow, login_start_flow, register_finish_flow, register_start_flow,
    CeremonyStateStore,
};
use aqua_auth::webauthn_store::{InMemoryWebauthnStore, WebauthnCredentialBackend};

use webauthn_authenticator_rs::prelude::{Url, WebauthnAuthenticator};
use webauthn_authenticator_rs::softpasskey::SoftPasskey;

/// RP config the software authenticator can satisfy: `rp_id = "localhost"` is a
/// registrable-domain suffix of the origin's host, and the origin is one the
/// authenticator drives against. This matches the spine's own `TestConfig`.
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

fn origin() -> Url {
    Url::parse("http://localhost:3000").unwrap()
}

/// A `SoftPasskey` with `falsify_uv = true`: webauthn-rs treats passkeys as
/// user-verified, and the soft token has no real UV, so it must assert the UV
/// flag or every `finish_*` would reject the ceremony for a missing UV.
fn authenticator() -> SoftPasskey {
    SoftPasskey::new(true)
}

/// Full register -> login round trip through the FINISH flows, verified by a
/// real software authenticator.
#[tokio::test]
async fn register_then_login_round_trip_with_software_authenticator() {
    let cfg = TestConfig::default();
    let states = CeremonyStateStore::new();
    let store = InMemoryWebauthnStore::new();
    let mut auth = authenticator();

    // ── Register: start -> authenticator attestation -> finish ──────────────
    let started = register_start_flow(&cfg, &states, &RegisterMode::Anonymous)
        .await
        .expect("register_start_flow");

    // The software authenticator produces a real attestation for these options.
    let attestation = auth
        .do_registration(origin(), started.options)
        .expect("authenticator.do_registration");

    let reg = register_finish_flow(
        &cfg,
        &states,
        &store,
        &started.challenge_id,
        &attestation,
        None, // anonymous: no completing DID
        Some("test-laptop".to_string()),
    )
    .await
    .expect("register_finish_flow");

    // A credential is stored, bound to the DID the outcome reports.
    let stored = store
        .list_for_did(&reg.did)
        .await
        .expect("list_for_did")
        .into_iter()
        .next()
        .expect("a credential was persisted for the bound DID");
    assert_eq!(stored.credential_id, reg.credential_id);
    assert_eq!(stored.label.as_deref(), Some("test-laptop"));
    assert_eq!(stored.sign_count, 0, "fresh credential starts at 0");

    // The bound DID is exactly did:key(...) of the authenticator's OWN P-256
    // public key, recovered from the stored credential blob — proving the
    // anonymous binding is the derivation of real key material, not a stub.
    let pubkey = p256_compressed_from_passkey_blob(&stored.public_key)
        .expect("stored blob carries a P-256 public key");
    assert_eq!(
        reg.did,
        did_key_from_p256_compressed(&pubkey),
        "bound DID must be did:key of the authenticator's P-256 key"
    );
    assert!(
        reg.did.starts_with("did:key:zDn"),
        "P-256 did:key: {}",
        reg.did
    );

    // ── Login: start(did) -> authenticator assertion -> finish ──────────────
    let login_started = login_start_flow(&cfg, &states, &store, &reg.did)
        .await
        .expect("login_start_flow");

    let assertion = auth
        .do_authentication(origin(), login_started.options)
        .expect("authenticator.do_authentication");

    let login = login_finish_flow(
        &cfg,
        &states,
        &store,
        &login_started.challenge_id,
        &assertion,
    )
    .await
    .expect("login_finish_flow");

    // Authenticates as the same DID and credential we registered.
    assert_eq!(
        login.did, reg.did,
        "login authenticates as the registered DID"
    );
    assert_eq!(login.credential_id, reg.credential_id);
    // SoftPasskey registers at counter 0 and reports 1 on its first assertion;
    // the store applies that as the new monotonic sign count.
    assert_eq!(
        login.new_sign_count, 1,
        "sign count is what the authenticator reported on first use"
    );
    assert_eq!(
        store
            .get_by_id(&reg.credential_id)
            .await
            .expect("get_by_id")
            .expect("credential still present")
            .sign_count,
        1,
        "the bumped count is persisted"
    );
}

/// Replay-after-consume (negative), REGISTER: a second `register_finish_flow`
/// with the same `challenge_id` fails because the ceremony state was consumed
/// (single-use) before verification. Guards the take-before-verify ordering.
#[tokio::test]
async fn register_finish_replay_after_consume_fails() {
    let cfg = TestConfig::default();
    let states = CeremonyStateStore::new();
    let store = InMemoryWebauthnStore::new();
    let mut auth = authenticator();

    let started = register_start_flow(&cfg, &states, &RegisterMode::Anonymous)
        .await
        .unwrap();
    let attestation = auth.do_registration(origin(), started.options).unwrap();

    // First finish consumes the challenge and succeeds.
    register_finish_flow(
        &cfg,
        &states,
        &store,
        &started.challenge_id,
        &attestation,
        None,
        None,
    )
    .await
    .expect("first register_finish_flow succeeds");
    assert!(states.is_empty(), "state consumed on success");

    // Replaying the SAME challenge_id (even with the same, otherwise-valid
    // attestation) fails: the state is gone, so the flow errors BEFORE any
    // webauthn-rs verification could run.
    let err = register_finish_flow(
        &cfg,
        &states,
        &store,
        &started.challenge_id,
        &attestation,
        None,
        None,
    )
    .await
    .expect_err("replay of a consumed register challenge must fail");
    assert!(
        matches!(err, CeremonyError::BadRequest(_)),
        "consumed challenge is a bad request, got {err:?}"
    );
}

/// Replay-after-consume (negative), LOGIN: a second `login_finish_flow` with the
/// same `challenge_id` fails for the same single-use reason.
#[tokio::test]
async fn login_finish_replay_after_consume_fails() {
    let cfg = TestConfig::default();
    let states = CeremonyStateStore::new();
    let store = InMemoryWebauthnStore::new();
    let mut auth = authenticator();

    // Register first so there is a credential to log in with.
    let started = register_start_flow(&cfg, &states, &RegisterMode::Anonymous)
        .await
        .unwrap();
    let attestation = auth.do_registration(origin(), started.options).unwrap();
    let reg = register_finish_flow(
        &cfg,
        &states,
        &store,
        &started.challenge_id,
        &attestation,
        None,
        None,
    )
    .await
    .unwrap();

    // Login start -> assertion -> first finish succeeds and consumes the state.
    let login_started = login_start_flow(&cfg, &states, &store, &reg.did)
        .await
        .unwrap();
    let assertion = auth
        .do_authentication(origin(), login_started.options)
        .unwrap();
    login_finish_flow(
        &cfg,
        &states,
        &store,
        &login_started.challenge_id,
        &assertion,
    )
    .await
    .expect("first login_finish_flow succeeds");
    assert!(states.is_empty(), "login state consumed on success");

    // Replaying the same login challenge_id fails: state consumed before verify.
    let err = login_finish_flow(
        &cfg,
        &states,
        &store,
        &login_started.challenge_id,
        &assertion,
    )
    .await
    .expect_err("replay of a consumed login challenge must fail");
    assert!(
        matches!(err, CeremonyError::BadRequest(_)),
        "consumed challenge is a bad request, got {err:?}"
    );
}
