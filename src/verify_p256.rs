//! P-256 (NIST) ECDSA signature verification.
//!
//! Covers: P256Signer (+ WebAuthn/passkeys) — `did:pkh:p256:0x{33-byte compressed pubkey hex}`.
//! Signs raw bytes (no message prefix wrapping).

use crate::did::pubkey_from_p256_did;
use crate::error::AuthError;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::EncodedPoint;

/// Verify a P-256 ECDSA signature against a `p256` DID.
///
/// 1. Extract the 33-byte compressed public key from the DID
/// 2. Decompress into a P-256 verifying key
/// 3. Verify the signature over the raw message bytes
pub fn verify(did: &str, message: &str, signature: &[u8]) -> Result<bool, AuthError> {
    let pubkey_bytes = pubkey_from_p256_did(did)?;

    let point = EncodedPoint::from_bytes(pubkey_bytes)
        .map_err(|e| AuthError::InvalidSignature(format!("invalid p256 encoded point: {e}")))?;

    let verifying_key = VerifyingKey::from_encoded_point(&point)
        .map_err(|e| AuthError::InvalidSignature(format!("invalid p256 pubkey: {e}")))?;

    let sig = Signature::from_der(signature)
        .or_else(|_| {
            // Also try fixed-size (64-byte r||s) format
            Signature::from_slice(signature)
        })
        .map_err(|e| AuthError::InvalidSignature(format!("invalid p256 signature: {e}")))?;

    match verifying_key.verify(message.as_bytes(), &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};
    use rand::rngs::OsRng;

    fn make_keypair() -> (SigningKey, String) {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let compressed = verifying_key.to_encoded_point(true);
        let did = format!("did:pkh:p256:0x{}", hex::encode(compressed.as_bytes()));
        (signing_key, did)
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let (key, did) = make_keypair();
        let msg = "hello aqua-node";
        let sig: Signature = key.sign(msg.as_bytes());
        // Use fixed-size encoding (64 bytes)
        assert!(verify(&did, msg, &sig.to_bytes()).unwrap());
    }

    #[test]
    fn sign_and_verify_der_encoding() {
        let (key, did) = make_keypair();
        let msg = "hello aqua-node";
        let sig: Signature = key.sign(msg.as_bytes());
        // Use DER encoding
        assert!(verify(&did, msg, sig.to_der().as_bytes()).unwrap());
    }

    #[test]
    fn wrong_did_rejects() {
        let (key, _did) = make_keypair();
        let (_key2, did2) = make_keypair();
        let sig: Signature = key.sign(b"test");
        assert!(!verify(&did2, "test", &sig.to_bytes()).unwrap());
    }

    #[test]
    fn tampered_message_rejects() {
        let (key, did) = make_keypair();
        let sig: Signature = key.sign(b"original");
        assert!(!verify(&did, "tampered", &sig.to_bytes()).unwrap());
    }
}
