//! WebAuthn register/login ceremony over `webauthn-rs` (feature `ceremony`).
//!
//! These are **pure** wrappers: they call `webauthn-rs` and derive credential
//! material, but touch NO storage and NO sessions. The consumer orchestrates
//! persistence (via [`crate::webauthn_store`]) and session issuance around them,
//! so one ceremony implementation serves aqua-node and aquafier alike instead of
//! each carrying its own near-identical copy.
//!
//! Split from the light `webauthn` verifier feature: only `ceremony` pulls the
//! heavy `webauthn-rs` stack.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, CredentialID, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Url, Webauthn,
    WebauthnBuilder,
};

use crate::webauthn_store::{CredentialId, NewCredential};

/// Re-export the `webauthn-rs` challenge-state + credential types a consumer must
/// name to persist ceremony state, so it can depend on `aqua-auth` alone.
pub use webauthn_rs::prelude::{
    Passkey as WebauthnPasskey, PasskeyAuthentication as WebauthnAuthState,
    PasskeyRegistration as WebauthnRegState, PublicKeyCredential as WebauthnAssertion,
    RegisterPublicKeyCredential as WebauthnAttestation,
};

/// P-256 multicodec prefix — identical to the SDK's `P256_CODEC` and this
/// crate's `key::P256_PREFIX`, so a `did:key` derived here matches every other
/// producer byte-for-byte.
const P256_MULTICODEC: [u8; 2] = [0x80, 0x24];

#[derive(Debug, thiserror::Error)]
pub enum CeremonyError {
    #[error("webauthn error: {0}")]
    Webauthn(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("internal: {0}")]
    Internal(String),
}

/// Per-deployment RP configuration (moved here from aqua-node so both consumers
/// share one trait). RP-ID, name, and allowed origins are per-host decisions.
pub trait WebauthnConfig: Send + Sync {
    fn rp_id(&self) -> &str;
    fn rp_name(&self) -> &str;
    fn allowed_origins(&self) -> &[String];
    fn challenge_ttl_register(&self) -> std::time::Duration {
        std::time::Duration::from_secs(300)
    }
    fn challenge_ttl_login(&self) -> std::time::Duration {
        std::time::Duration::from_secs(300)
    }
    fn challenge_ttl_sign(&self) -> std::time::Duration {
        std::time::Duration::from_secs(60)
    }
}

/// Build a `Webauthn` instance from a [`WebauthnConfig`]. First allowed origin is
/// the primary; the rest are appended.
pub fn build_webauthn(config: &dyn WebauthnConfig) -> Result<Webauthn, CeremonyError> {
    let origins: Vec<Url> = config
        .allowed_origins()
        .iter()
        .map(|o| Url::parse(o).map_err(|e| CeremonyError::Internal(format!("invalid origin {o}: {e}"))))
        .collect::<Result<Vec<_>, _>>()?;
    let first = origins
        .first()
        .ok_or_else(|| CeremonyError::Internal("allowed_origins must be non-empty".into()))?;
    let mut builder = WebauthnBuilder::new(config.rp_id(), first)
        .map_err(|e| CeremonyError::Internal(format!("webauthn builder: {e}")))?
        .rp_name(config.rp_name());
    for origin in origins.iter().skip(1) {
        builder = builder.append_allowed_origin(origin);
    }
    builder
        .build()
        .map_err(|e| CeremonyError::Internal(format!("webauthn build: {e}")))
}

/// Stable WebAuthn user handle from a DID: `Sha3_256(did)` (32 bytes). Matches
/// aqua-node/aquafier `user_handle_for`.
pub fn user_handle_for(did: &str) -> [u8; 32] {
    let digest = Sha3_256::digest(did.as_bytes());
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    bytes
}

/// `did:key:zDn…` from a compressed (SEC1, 33-byte) P-256 public key. SDK-free —
/// same multicodec + base58btc encoding every other producer uses.
pub fn did_key_from_p256_compressed(pubkey: &[u8; 33]) -> String {
    let mut bytes = P256_MULTICODEC.to_vec();
    bytes.extend_from_slice(pubkey);
    format!("did:key:z{}", bs58::encode(&bytes).into_string())
}

/// Extract the compressed (33-byte SEC1) P-256 public key from a `Passkey`'s COSE
/// key. Errors if the credential isn't P-256.
pub fn p256_compressed_from_passkey(passkey: &Passkey) -> Result<[u8; 33], CeremonyError> {
    use webauthn_rs::prelude::{COSEKeyType, ECDSACurve};
    let cose_key = passkey.get_public_key();
    match &cose_key.key {
        COSEKeyType::EC_EC2(ec2) => {
            if ec2.curve != ECDSACurve::SECP256R1 {
                return Err(CeremonyError::BadRequest(format!(
                    "credential uses unsupported curve {:?} (expected P-256)",
                    ec2.curve
                )));
            }
            let x_bytes: &[u8] = ec2.x.as_ref();
            if x_bytes.len() != 32 {
                return Err(CeremonyError::Internal(format!(
                    "P-256 x-coordinate must be 32 bytes, got {}",
                    x_bytes.len()
                )));
            }
            let y_bytes: &[u8] = ec2.y.as_ref();
            let y_is_odd = y_bytes.last().is_some_and(|b| b & 1 == 1);
            let mut out = [0u8; 33];
            out[0] = if y_is_odd { 0x03 } else { 0x02 };
            out[1..].copy_from_slice(x_bytes);
            Ok(out)
        }
        other => Err(CeremonyError::BadRequest(format!(
            "credential key type {other:?} is not P-256 EC2"
        ))),
    }
}

/// Same, from a serialized `Passkey` blob (as stored in the credential store).
pub fn p256_compressed_from_passkey_blob(blob: &[u8]) -> Result<[u8; 33], CeremonyError> {
    let passkey: Passkey = serde_json::from_slice(blob)
        .map_err(|e| CeremonyError::Internal(format!("deserialize Passkey blob: {e}")))?;
    p256_compressed_from_passkey(&passkey)
}

/// Deserialize a stored credential blob into a `Passkey` (for `allowCredentials`
/// in `login_start`). Returns `None` on a malformed blob.
pub fn passkey_from_blob(blob: &[u8]) -> Option<Passkey> {
    serde_json::from_slice(blob).ok()
}

/// How a registration binds its new credential.
pub enum RegisterMode {
    /// Passkey-as-identity: no session; bind to the credential's OWN `did:key`
    /// (derived at finish). The passkey IS the identity.
    Anonymous,
    /// Second factor under an existing session: bind to `did`, and exclude the
    /// DID's already-registered credential ids so the authenticator warns on a
    /// duplicate.
    SecondFactor {
        did: String,
        existing_credential_ids: Vec<Vec<u8>>,
    },
}

/// Output of `register_start`: options for the browser + the state to persist
/// (with the DID this will bind to, if already known).
pub struct StartedRegistration {
    pub options: CreationChallengeResponse,
    pub state: PasskeyRegistration,
    /// `Some(did)` for `SecondFactor` (bind target known now); `None` for
    /// `Anonymous` (derived at finish from the credential's own key).
    pub intended_did: Option<String>,
}

/// Phase 1: build the creation challenge. The consumer persists `state`
/// (+ `intended_did`) against a challenge id and returns `options`.
pub fn register_start(
    webauthn: &Webauthn,
    mode: &RegisterMode,
) -> Result<StartedRegistration, CeremonyError> {
    let (user_uuid, username, exclude, intended_did) = match mode {
        RegisterMode::SecondFactor {
            did,
            existing_credential_ids,
        } => {
            let handle = user_handle_for(did);
            let user_uuid = Uuid::from_slice(&handle[..16])
                .map_err(|e| CeremonyError::Internal(format!("uuid from did: {e}")))?;
            let exclude = if existing_credential_ids.is_empty() {
                None
            } else {
                Some(
                    existing_credential_ids
                        .iter()
                        .map(|id| CredentialID::from(id.clone()))
                        .collect::<Vec<_>>(),
                )
            };
            (user_uuid, did.clone(), exclude, Some(did.clone()))
        }
        RegisterMode::Anonymous => (Uuid::new_v4(), "aqua passkey".to_string(), None, None),
    };
    let (options, state) = webauthn
        .start_passkey_registration(user_uuid, &username, &username, exclude)
        .map_err(|e| CeremonyError::BadRequest(format!("start_passkey_registration: {e}")))?;
    Ok(StartedRegistration {
        options,
        state,
        intended_did,
    })
}

/// Output of `register_finish`: the credential to store + its bound DID.
pub struct FinishedRegistration {
    pub credential: NewCredential,
    pub did: String,
    pub credential_id_hex: String,
}

/// Phase 2: verify the attestation, derive the bound DID, and build the
/// `NewCredential` the consumer persists.
///
/// `intended_did` is what the challenge recorded at start (`Some` for a
/// second-factor registration, `None` for anonymous). For a second factor, pass
/// the completing caller's DID as `completing_did`; it MUST equal `intended_did`
/// (defense in depth). For anonymous, the DID is derived from the credential's
/// own P-256 key.
pub fn register_finish(
    webauthn: &Webauthn,
    attestation: &RegisterPublicKeyCredential,
    state: &PasskeyRegistration,
    intended_did: Option<&str>,
    completing_did: Option<&str>,
    label: Option<String>,
) -> Result<FinishedRegistration, CeremonyError> {
    let passkey = webauthn
        .finish_passkey_registration(attestation, state)
        .map_err(|e| CeremonyError::BadRequest(format!("finish_passkey_registration: {e}")))?;

    let credential_id_bytes = AsRef::<[u8]>::as_ref(passkey.cred_id()).to_vec();
    let credential_id_hex = hex::encode(&credential_id_bytes);
    let public_key = serde_json::to_vec(&passkey)
        .map_err(|e| CeremonyError::Internal(format!("serialize passkey: {e}")))?;

    let did = match intended_did {
        Some(intended) => match completing_did {
            Some(c) if c == intended => intended.to_string(),
            _ => {
                return Err(CeremonyError::BadRequest(
                    "challenge does not belong to the completing caller".into(),
                ))
            }
        },
        None => {
            let pubkey = p256_compressed_from_passkey_blob(&public_key)?;
            did_key_from_p256_compressed(&pubkey)
        }
    };

    Ok(FinishedRegistration {
        credential: NewCredential {
            did: did.clone(),
            credential_id: CredentialId(credential_id_bytes),
            public_key,
            sign_count: 0,
            transports: vec![],
            label,
        },
        did,
        credential_id_hex,
    })
}

/// Phase 1 (login): build the request challenge. Pass the DID's stored passkeys
/// to constrain `allowCredentials`, or an empty slice for discoverable
/// (usernameless) login. The consumer persists `state` against a challenge id.
pub fn login_start(
    webauthn: &Webauthn,
    passkeys: &[Passkey],
) -> Result<(RequestChallengeResponse, PasskeyAuthentication), CeremonyError> {
    webauthn
        .start_passkey_authentication(passkeys)
        .map_err(|e| CeremonyError::BadRequest(format!("start_passkey_authentication: {e}")))
}

/// Output of `login_finish`: which credential authenticated + its new counter.
pub struct FinishedLogin {
    pub credential_id: CredentialId,
    pub counter: u32,
}

/// Phase 2 (login): verify the assertion. The consumer then looks the credential
/// up (to recover the DID), runs the sign-count regression check against the
/// stored value, persists the new counter, and mints its own session.
pub fn login_finish(
    webauthn: &Webauthn,
    assertion: &PublicKeyCredential,
    state: &PasskeyAuthentication,
) -> Result<FinishedLogin, CeremonyError> {
    let result = webauthn
        .finish_passkey_authentication(assertion, state)
        .map_err(|e| CeremonyError::BadRequest(format!("finish_passkey_authentication: {e}")))?;
    Ok(FinishedLogin {
        credential_id: CredentialId(AsRef::<[u8]>::as_ref(result.cred_id()).to_vec()),
        counter: result.counter(),
    })
}

// Kept so downstream `serde` derives on request/response wrappers can live in
// the consumer without re-importing serde traits piecemeal.
#[allow(unused_imports)]
use {Deserialize as _, Serialize as _};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_key_derivation_has_p256_prefix() {
        // A did:key from a P-256 key must render as `did:key:zDn…` (the P-256
        // multibase multicodec), matching the SDK + siwx-oidc encoding.
        let pubkey = [0x02u8; 33];
        let did = did_key_from_p256_compressed(&pubkey);
        assert!(did.starts_with("did:key:zDn"), "got {did}");
    }

    #[test]
    fn user_handle_is_stable_and_32_bytes() {
        let a = user_handle_for("did:key:zDnFoo");
        let b = user_handle_for("did:key:zDnFoo");
        let c = user_handle_for("did:key:zDnBar");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 32);
    }
}
