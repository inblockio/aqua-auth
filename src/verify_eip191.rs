//! EIP-191 signature verification (secp256k1 ecrecover).
//!
//! Covers: Secp256k1Signer, MetaMaskSigner, CliSigner — all produce identical
//! EIP-191 signatures over `did:pkh:eip155:1:0x{address}` DIDs.

use crate::did::{address_from_did, address_from_verifying_key};
use crate::error::AuthError;
use sha3::{Digest, Keccak256};

/// Verify an EIP-191 `personal_sign` signature against an `eip155` DID.
///
/// 1. Compute `keccak256("\x19Ethereum Signed Message:\n{len}" + message)`
/// 2. Recover the secp256k1 public key from (prehash, signature, recovery_id)
/// 3. Derive the Ethereum address from the recovered key
/// 4. Compare with the address embedded in the DID
pub fn verify(did: &str, message: &str, signature: &[u8]) -> Result<bool, AuthError> {
    let expected_addr = address_from_did(did)?;

    // EIP-191 prefix
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let prehash: [u8; 32] = {
        let mut h = Keccak256::new();
        h.update(prefix.as_bytes());
        h.update(message.as_bytes());
        h.finalize().into()
    };

    if signature.len() != 65 {
        return Err(AuthError::InvalidSignature(format!(
            "EIP-191 signature must be 65 bytes, got {}",
            signature.len()
        )));
    }

    let v = signature[64];
    let recovery_byte = v
        .checked_sub(27)
        .ok_or_else(|| AuthError::InvalidSignature(format!("invalid v={v}; expected 27 or 28")))?;
    let rec_id = k256::ecdsa::RecoveryId::from_byte(recovery_byte)
        .ok_or_else(|| AuthError::InvalidSignature(format!("invalid recovery id {recovery_byte}")))?;
    let sig = k256::ecdsa::Signature::from_slice(&signature[..64])
        .map_err(|e| AuthError::InvalidSignature(e.to_string()))?;

    let recovered = k256::ecdsa::VerifyingKey::recover_from_prehash(&prehash, &sig, rec_id)
        .map_err(|e| AuthError::InvalidSignature(format!("ecrecover failed: {e}")))?;

    Ok(address_from_verifying_key(&recovered) == expected_addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::eip55_checksum;
    use sha3::Keccak256;

    /// Helper: sign a message with a raw secp256k1 signing key (EIP-191).
    fn eth_sign(key: &k256::ecdsa::SigningKey, msg: &str) -> Vec<u8> {
        let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
        let prehash: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(prefix.as_bytes());
            h.update(msg.as_bytes());
            h.finalize().into()
        };
        let (sig, rec_id) = key.sign_prehash_recoverable(&prehash).unwrap();
        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(&sig.to_bytes());
        bytes[64] = u8::from(rec_id) + 27;
        bytes.to_vec()
    }

    fn make_keypair() -> (k256::ecdsa::SigningKey, String) {
        use rand::rngs::OsRng;
        let secret = k256::SecretKey::random(&mut OsRng);
        let signing_key = k256::ecdsa::SigningKey::from(&secret);
        let addr = address_from_verifying_key(signing_key.verifying_key());
        let did = format!("did:pkh:eip155:1:0x{}", eip55_checksum(&addr));
        (signing_key, did)
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let (key, did) = make_keypair();
        let msg = "hello aqua-node";
        let sig = eth_sign(&key, msg);
        assert!(verify(&did, msg, &sig).unwrap());
    }

    #[test]
    fn wrong_did_rejects() {
        let (key, _did) = make_keypair();
        let (_key2, did2) = make_keypair();
        let sig = eth_sign(&key, "test");
        assert!(!verify(&did2, "test", &sig).unwrap());
    }

    #[test]
    fn tampered_message_rejects() {
        let (key, did) = make_keypair();
        let sig = eth_sign(&key, "original");
        assert!(!verify(&did, "tampered", &sig).unwrap());
    }

    #[test]
    fn bad_signature_length() {
        let (_, did) = make_keypair();
        assert!(verify(&did, "msg", &[0u8; 32]).is_err());
    }
}
