//! Ed25519 signature verification.
//!
//! Covers: Ed25519Signer — `did:pkh:ed25519:0x{32-byte pubkey hex}`.
//! Signs raw bytes (no message prefix wrapping).

use crate::did::pubkey_from_ed25519_did;
use crate::error::AuthError;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Verify an Ed25519 signature against an `ed25519` DID.
///
/// 1. Extract the 32-byte public key from the DID
/// 2. Verify the signature over the raw message bytes
pub fn verify(did: &str, message: &str, signature: &[u8]) -> Result<bool, AuthError> {
    let pubkey_bytes = pubkey_from_ed25519_did(did)?;

    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|e| AuthError::InvalidSignature(format!("invalid ed25519 pubkey: {e}")))?;

    if signature.len() != 64 {
        return Err(AuthError::InvalidSignature(format!(
            "Ed25519 signature must be 64 bytes, got {}",
            signature.len()
        )));
    }

    let sig = Signature::from_slice(signature)
        .map_err(|e| AuthError::InvalidSignature(format!("invalid ed25519 signature: {e}")))?;

    match verifying_key.verify(message.as_bytes(), &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn make_keypair() -> (SigningKey, String) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pubkey = signing_key.verifying_key();
        let did = format!("did:pkh:ed25519:0x{}", hex::encode(pubkey.as_bytes()));
        (signing_key, did)
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let (key, did) = make_keypair();
        let msg = "hello aqua-node";
        let sig = key.sign(msg.as_bytes());
        assert!(verify(&did, msg, &sig.to_bytes()).unwrap());
    }

    #[test]
    fn wrong_did_rejects() {
        let (key, _did) = make_keypair();
        let (_key2, did2) = make_keypair();
        let sig = key.sign(b"test");
        assert!(!verify(&did2, "test", &sig.to_bytes()).unwrap());
    }

    #[test]
    fn tampered_message_rejects() {
        let (key, did) = make_keypair();
        let sig = key.sign(b"original");
        assert!(!verify(&did, "tampered", &sig.to_bytes()).unwrap());
    }

    #[test]
    fn bad_signature_length() {
        let (_, did) = make_keypair();
        assert!(verify(&did, "msg", &[0u8; 32]).is_err());
    }
}
