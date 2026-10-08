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
pub mod did_format;
pub mod did_method;
pub mod key;
pub mod peer;
pub mod pkh;
pub mod principal;
pub mod signer;

pub use cipher_suite::{all_cipher_suites, find_cipher_suite, CipherSuite};
pub use crypto_error::CryptoError;
pub use did::{
    address_from_did, address_from_verifying_key, checksummed_address, ed25519_did_key_from_pubkey,
    eip55_checksum, identifier_from_did, identifier_from_message, p256_did_key_from_pubkey,
    parse_did_namespace, pubkey_from_ed25519_did, pubkey_from_p256_did,
};
pub use did_format::validate_did_well_formed;
pub use did_method::{all_did_methods, find_did_method, DIDMethod};
pub use key::{
    ed25519_pubkey_from_did_key, p256_pubkey_from_did_key, Ed25519Suite, KeyMethod, P256Suite,
};
pub use peer::PeerMethod;
pub use pkh::{Eip155Suite, PkhMethod};
pub use principal::{authenticate, authenticate_with_public_key, Principal};
pub use signer::{FnSigner, SignError, Signer};

// --- Behind `local-key` feature (in-process PKCS#8 key custody) ---
#[cfg(feature = "local-key")]
pub mod local_key;
#[cfg(feature = "local-key")]
pub use local_key::{LocalKeyError, LocalKeySigner};

// --- Behind `did-aqua` feature (ML-DSA-87 post-quantum namespace) ---
#[cfg(feature = "did-aqua")]
pub mod aqua;
#[cfg(feature = "did-aqua")]
pub use aqua::{
    aqua_did_binds_pubkey, aqua_did_from_pubkey, multihash_from_aqua_did, AquaMethod,
    ML_DSA_87_PUBLIC_KEY_BYTES, ML_DSA_87_SIGNATURE_BYTES,
};

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

// Store-free passkey login (0.9.0): which RPs and origins an assertion may
// come from, independent of any credential store.
#[cfg(feature = "webauthn")]
pub mod webauthn_policy;
#[cfg(feature = "webauthn")]
pub use webauthn_policy::{AssertionPolicy, AssertionPolicyBuilder, PolicyError, RpEntry};
#[cfg(feature = "webauthn")]
pub mod webauthn_recover;
#[cfg(feature = "webauthn")]
pub use webauthn_recover::{
    verify_and_recover, AssertionError, AssertionJson, AssertionResponseJson, ExpectedChallenge,
    RecoveredAssertion,
};

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
///
/// This cannot serve `did:aqua`, whose verifier needs the signer's public key:
/// that DID commits to an ML-DSA-87 key by hash and the scheme has no
/// public-key recovery, so there is nothing to dispatch on. Calling this with
/// a `did:aqua` returns an error naming
/// [`verify_caip122_with_public_key`]; use that instead when a deployment
/// accepts post-quantum identities.
///
/// # Deprecated in favour of [`authenticate`]
///
/// Ruled 2026-09-11: [`authenticate`] is the correct entry point, because a
/// `bool` is the wrong return type for proof of possession. Nothing in the
/// type system stops a caller from verifying one DID and then creating a
/// session for another, and `Ok(false)` is as easy to ignore as any other
/// boolean. [`Principal`] can only be constructed by a successful
/// verification, so "this DID demonstrably signed this message" becomes a
/// value you have to hold rather than a check you have to remember.
///
/// This is a warning, not a removal. The function still works and is still
/// supported for callers that genuinely only want the yes/no.
#[deprecated(
    since = "0.8.0",
    note = "use `authenticate(did, message, signature)`, which returns \
            `Result<Principal, CryptoError>` instead of `Result<bool, _>`. \
            Two things change at the call site: you get a `Principal` rather \
            than `true`, so pass `principal.did()` on to session creation \
            instead of the DID string you started with; and a bad signature \
            is now `Err(CryptoError::InvalidSignature)` rather than \
            `Ok(false)`, so the `Ok(false) => reject` arm becomes part of the \
            error arm. For `did:aqua`, call `authenticate_with_public_key` \
            and pass the key from the session request. This function is not \
            being removed; silence this warning with `#[allow(deprecated)]` \
            if you only need the boolean."
)]
pub fn verify_caip122(did: &str, message: &str, signature: &[u8]) -> Result<bool, CryptoError> {
    let method =
        find_did_method(did).ok_or_else(|| CryptoError::UnsupportedMethod(did.to_string()))?;
    method.verify(did, message, signature)
}

/// Verify a CAIP-122 session signature, with the signer's public key supplied
/// separately for methods that need it.
///
/// The key-aware twin of [`verify_caip122`]. Pass `None` for every classical
/// namespace, where it is ignored, and `Some` for `did:aqua`. Where the key
/// comes from is the caller's choice: the session request body today, a store
/// or a resolver later. Whatever the source, the key is bound back to the DID
/// before it is trusted.
pub fn verify_caip122_with_public_key(
    did: &str,
    message: &str,
    signature: &[u8],
    public_key: Option<&[u8]>,
) -> Result<bool, CryptoError> {
    let method =
        find_did_method(did).ok_or_else(|| CryptoError::UnsupportedMethod(did.to_string()))?;
    method.verify_with_public_key(did, message, signature, public_key)
}

// These tests use the boolean verifier deliberately: they assert that a
// signature does or does not verify, which is exactly the yes/no question
// `verify_caip122` still exists to answer. Not a pending migration.
#[cfg(test)]
#[allow(deprecated)]
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
