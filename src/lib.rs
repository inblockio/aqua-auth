//! # aqua-auth
//!
//! DID-based authentication for the Aqua Protocol.
//!
//! **Default features (crypto/DID layer):**
//! - CipherSuite and DIDMethod trait registries
//! - did:pkh (eip155, ed25519, p256), did:key, did:peer verification
//! - DID parsing, identifier extraction, EIP-55 checksumming
//! - `verify_caip122()` signature verification dispatch
//!
//! **`http` feature (session/auth layer):**
//! - CAIP-122 message construction
//! - ChallengeStore (in-memory, 5-min TTL, single-use nonces)
//! - SessionStore (in-memory, 1-hr TTL, background sweep)
//!
//! **`client` feature (implies `http`):**
//! - reqwest-based challenge-response authentication flow
//!
//! **`http-sig` feature (per-request signatures, EXPERIMENTAL):**
//! - RFC 9421 HTTP Message Signatures over a narrow profile
//! - Aqua-internal (DID `keyid`) and web-bot-auth interop profiles
//! - Tracks an IETF draft, so it is exempt from the semver stability promise
//!   until that draft settles (see [`http_sig`])

// --- Always available (crypto/DID layer) ---
pub mod cipher_suite;
pub mod crypto_error;
pub mod did;
pub mod did_method;
pub mod key;
pub mod peer;
pub mod pkh;
pub mod principal;
pub mod signer;

pub use cipher_suite::{all_cipher_suites, find_cipher_suite, CipherSuite};
pub use crypto_error::CryptoError;
pub use did::{
    address_from_did, address_from_verifying_key, checksummed_address, eip55_checksum,
    identifier_from_did, identifier_from_message, parse_did_namespace, pubkey_from_ed25519_did,
    pubkey_from_p256_did,
};
pub use did_method::{all_did_methods, find_did_method, DIDMethod};
pub use key::{ed25519_pubkey_from_did_key, Ed25519Suite, KeyMethod, P256Suite};
pub use peer::PeerMethod;
pub use pkh::{Eip155Suite, PkhMethod};
pub use principal::{authenticate, Principal};
pub use signer::{FnSigner, SignError, Signer};

// --- Behind `http` feature (session/auth layer) ---
#[cfg(feature = "http")]
pub mod auth_error;
#[cfg(feature = "http")]
pub mod challenge;
#[cfg(feature = "http")]
pub mod message;
#[cfg(feature = "http")]
pub mod session;
#[cfg(feature = "http")]
pub mod session_backend;
#[cfg(feature = "http")]
pub mod types;
#[cfg(feature = "http")]
pub mod wire;

#[cfg(feature = "http")]
pub use auth_error::AuthError;
#[cfg(feature = "http")]
pub use challenge::ChallengeStore;
#[cfg(feature = "http")]
pub use message::{build_message, MessageParams};
#[cfg(feature = "http")]
pub use session::SessionStore;
#[cfg(feature = "http")]
pub use session_backend::{InMemoryBackend, SessionBackend};
#[cfg(feature = "http")]
pub use types::{AuthenticatedDid, Challenge, Session, SessionInfo};
#[cfg(feature = "http")]
pub use wire::{ChallengeEnvelope, SessionRequest, SessionResponse};

// --- Behind `client` feature ---
#[cfg(feature = "client")]
pub mod client;

// --- Behind `http-sig` feature (RFC 9421 per-request signatures) ---
#[cfg(feature = "http-sig")]
pub mod http_sig;
#[cfg(feature = "http-sig")]
pub use http_sig::{
    sign_request, verify_request, HttpSigError, NonceReplayGuard, Profile, RequestParts,
    SignedHeaders, VerifyOptions,
};

// --- Behind `webauthn` feature ---
#[cfg(feature = "webauthn")]
pub mod webauthn;
#[cfg(feature = "webauthn")]
pub use webauthn::{verify_webauthn_assertion, WebAuthnAssertionParams};

// Credential store (the persistence half of passkey support). The trait +
// in-memory backend need no `redis`; the Redis backend adds it.
#[cfg(feature = "webauthn")]
pub mod webauthn_store;
#[cfg(feature = "webauthn")]
pub use webauthn_store::{
    CredentialId, InMemoryWebauthnStore, NewCredential, StoredCredential,
    WebauthnCredentialBackend, WebauthnStoreError,
};

// --- Behind `webauthn` + `redis` features ---
#[cfg(all(feature = "webauthn", feature = "redis"))]
pub mod redis_webauthn;
#[cfg(all(feature = "webauthn", feature = "redis"))]
pub use redis_webauthn::RedisWebauthnStore;

// --- Behind `ceremony` feature (register/login over webauthn-rs) ---
#[cfg(feature = "ceremony")]
pub mod webauthn_ceremony;
#[cfg(feature = "ceremony")]
pub use webauthn_ceremony::{
    build_webauthn, did_key_from_p256_compressed, login_finish, login_start,
    p256_compressed_from_passkey, p256_compressed_from_passkey_blob, passkey_from_blob,
    register_finish, register_start, user_handle_for, CeremonyError, FinishedLogin,
    FinishedRegistration, RegisterMode, StartedRegistration, WebauthnConfig,
};

/// Verify a CAIP-122 session signature.
///
/// Dispatches to the DIDMethod registry (did:pkh, did:key, did:peer).
pub fn verify_caip122(did: &str, message: &str, signature: &[u8]) -> Result<bool, CryptoError> {
    let method =
        find_did_method(did).ok_or_else(|| CryptoError::UnsupportedMethod(did.to_string()))?;
    method.verify(did, message, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_eip155() {
        use k256::ecdsa::SigningKey;
        use rand::rngs::OsRng;
        use sha3::{Digest, Keccak256};

        let secret = k256::SecretKey::random(&mut OsRng);
        let signing_key = SigningKey::from(&secret);
        let addr = address_from_verifying_key(signing_key.verifying_key());
        let did_str = format!("did:pkh:eip155:1:0x{}", eip55_checksum(&addr));

        let msg = "test dispatch eip155";
        let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
        let prehash: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(prefix.as_bytes());
            h.update(msg.as_bytes());
            h.finalize().into()
        };
        let (sig, rec_id) = signing_key.sign_prehash_recoverable(&prehash).unwrap();
        let mut sig_bytes = [0u8; 65];
        sig_bytes[..64].copy_from_slice(&sig.to_bytes());
        sig_bytes[64] = u8::from(rec_id) + 27;

        assert!(verify_caip122(&did_str, msg, &sig_bytes).unwrap());
    }

    #[test]
    fn dispatch_ed25519() {
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let pubkey = signing_key.verifying_key();
        let did_str = format!("did:pkh:ed25519:0x{}", hex::encode(pubkey.as_bytes()));

        let msg = "test dispatch ed25519";
        let sig = signing_key.sign(msg.as_bytes());

        assert!(verify_caip122(&did_str, msg, &sig.to_bytes()).unwrap());
    }

    #[test]
    fn dispatch_p256() {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        use rand::rngs::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let compressed = verifying_key.to_encoded_point(true);
        let did_str = format!("did:pkh:p256:0x{}", hex::encode(compressed.as_bytes()));

        let msg = "test dispatch p256";
        let sig: Signature = signing_key.sign(msg.as_bytes());

        assert!(verify_caip122(&did_str, msg, &sig.to_bytes()).unwrap());
    }

    #[test]
    fn unsupported_namespace_returns_error() {
        let result = verify_caip122("did:pkh:solana:0xabc", "msg", &[0u8; 64]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, CryptoError::UnsupportedMethod(_)));
    }

    #[test]
    fn invalid_did_prefix_returns_error() {
        let result = verify_caip122("not:a:did", "msg", &[0u8; 64]);
        assert!(result.is_err());
    }

    #[test]
    fn did_key_dispatches() {
        assert!(find_did_method("did:key:z6MkiTBz1y").is_some());
    }
}
