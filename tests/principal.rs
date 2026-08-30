//! #167 item #10; the scoped-self `Principal` type + `authenticate()`.
//!
//! aqua-auth authenticates (returns *who signed*); it does NOT store sessions;
//! aqua-node takes the `Principal` and persists the session. A `Principal` can
//! only be constructed by successful authentication or explicit validation, and
//! carries NO delegation state, so an impersonated identity is unrepresentable.

use aqua_auth::{authenticate, CryptoError, Principal};

/// Produce a valid CAIP-122 (eip155 personal_sign) signature; mirrors the
/// `dispatch_eip155` pattern in lib.rs. Returns the signer's did:pkh and the
/// 65-byte signature.
fn signed_eip155(msg: &str) -> (String, Vec<u8>) {
    use k256::ecdsa::SigningKey;
    use rand::rngs::OsRng;
    use sha3::{Digest, Keccak256};

    let secret = k256::SecretKey::random(&mut OsRng);
    let signing_key = SigningKey::from(&secret);
    let addr = aqua_auth::address_from_verifying_key(signing_key.verifying_key());
    let did = format!("did:pkh:eip155:1:0x{}", aqua_auth::eip55_checksum(&addr));

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
    sig_bytes[64] = u8::from(rec_id) + 27; // Ethereum recovery id convention
    (did, sig_bytes.to_vec())
}

#[test]
fn authenticate_returns_the_signing_principal_for_a_valid_signature() {
    let msg = "log in to aqua-node";
    let (did, sig) = signed_eip155(msg);

    let principal = authenticate(&did, msg, &sig).expect("a valid signature yields a Principal");
    assert_eq!(
        principal.did(),
        did,
        "the principal IS the DID that signed; no actor/delegate indirection"
    );
}

#[test]
fn authenticate_rejects_a_tampered_message_as_invalid_signature() {
    let msg = "log in to aqua-node";
    let (did, sig) = signed_eip155(msg);

    let err = authenticate(&did, "a different message", &sig)
        .expect_err("a signature over a different message must not authenticate");
    assert!(
        matches!(err, CryptoError::InvalidSignature(_)),
        "expected InvalidSignature, got {err:?}"
    );
}

#[test]
fn from_trusted_did_accepts_recognised_methods_and_rejects_unknown() {
    assert!(
        Principal::from_trusted_did("did:pkh:eip155:1:0x1111111111111111111111111111111111111111")
            .is_ok(),
        "did:pkh:eip155 is a recognised method"
    );
    assert!(
        Principal::from_trusted_did("did:key:z6MknSLrJoTcukLRyR5GLJ2BFqNaGMkHMGLLPT68F2nHZN7L")
            .is_ok(),
        "did:key is a recognised method"
    );
    assert!(
        matches!(
            Principal::from_trusted_did("did:madeupmethod:whatever"),
            Err(CryptoError::UnsupportedMethod(_))
        ),
        "an unrecognised method must be rejected, not silently accepted"
    );
}

#[test]
fn principal_subject_and_method_match_the_registry() {
    let did = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
    let principal = Principal::from_trusted_did(did).unwrap();
    let method = aqua_auth::find_did_method(did).expect("registry recognises the DID");

    assert_eq!(
        principal.canonical_subject().unwrap(),
        method.canonical_subject(did).unwrap(),
        "Principal's canonical subject must be the registry's"
    );
    assert_eq!(
        principal.method_label().unwrap(),
        method.method_label(did).unwrap(),
        "Principal's method label must be the registry's"
    );
}
