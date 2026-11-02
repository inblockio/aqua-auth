//! EIP-191 cipher suite for `did:pkh:eip155`.

use crate::cipher_suite::CipherSuite;
use crate::crypto_error::CryptoError;
use crate::did::{address_from_did, address_from_verifying_key};
use sha3::{Digest, Keccak256};

pub struct Eip155Suite;

impl CipherSuite for Eip155Suite {
    fn namespace(&self) -> &str {
        "eip155"
    }

    fn has_chain_id(&self) -> bool {
        true
    }

    fn did_segments(&self) -> usize {
        2 // chain_id + address
    }

    fn verify(&self, did: &str, message: &str, signature: &[u8]) -> Result<bool, CryptoError> {
        let expected_addr = address_from_did(did)?;

        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let prehash: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(prefix.as_bytes());
            h.update(message.as_bytes());
            h.finalize().into()
        };

        if signature.len() != 65 {
            return Err(CryptoError::InvalidSignature(format!(
                "EIP-191 signature must be 65 bytes, got {}",
                signature.len()
            )));
        }

        let v = signature[64];
        let recovery_byte = v.checked_sub(27).ok_or_else(|| {
            CryptoError::InvalidSignature(format!("invalid v={v}; expected 27 or 28"))
        })?;
        let rec_id = k256::ecdsa::RecoveryId::from_byte(recovery_byte).ok_or_else(|| {
            CryptoError::InvalidSignature(format!("invalid recovery id {recovery_byte}"))
        })?;
        let sig = k256::ecdsa::Signature::from_slice(&signature[..64])
            .map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;

        let recovered = k256::ecdsa::VerifyingKey::recover_from_prehash(&prehash, &sig, rec_id)
            .map_err(|e| CryptoError::InvalidSignature(format!("ecrecover failed: {e}")))?;
        // ecdsa 0.16 ended `recover_from_prehash` by verifying the signature
        // against the recovered key, which on secp256k1 refuses a high-`s`
        // signature; ecdsa 0.17 no longer does. Keep that post-condition here
        // (same fix as aqua-rs-sdk `recover_wallet_address`).
        k256::ecdsa::signature::hazmat::PrehashVerifier::verify_prehash(&recovered, &prehash, &sig)
            .map_err(|e| CryptoError::InvalidSignature(format!("ecrecover failed: {e}")))?;

        Ok(address_from_verifying_key(&recovered) == expected_addr)
    }

    /// Parse `"1:0xAbCd..."` into `("0xAbCd...", Some("eip155:1"))`.
    fn parse_did_parts(
        &self,
        did_remainder: &str,
    ) -> Result<(String, Option<String>), CryptoError> {
        let mut parts = did_remainder.splitn(2, ':');
        let chain_num = parts.next().ok_or_else(|| {
            CryptoError::InvalidDid(format!(
                "missing chain_id in eip155 remainder: {did_remainder}"
            ))
        })?;
        let address = parts.next().ok_or_else(|| {
            CryptoError::InvalidDid(format!(
                "missing address in eip155 remainder: {did_remainder}"
            ))
        })?;
        Ok((address.to_string(), Some(format!("eip155:{chain_num}"))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::eip55_checksum;
    use ::p256::elliptic_curve::Generate as _;
    use k256::ecdsa::SigningKey;
    use sha3::Keccak256;

    fn eth_sign(key: &SigningKey, msg: &str) -> Vec<u8> {
        let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
        let prehash: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(prefix.as_bytes());
            h.update(msg.as_bytes());
            h.finalize().into()
        };
        let (sig, rec_id) = key.sign_prehash_recoverable(&prehash);
        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(&sig.to_bytes());
        bytes[64] = u8::from(rec_id) + 27;
        bytes.to_vec()
    }

    fn make_keypair() -> (SigningKey, String) {
        let secret = k256::SecretKey::generate();
        let signing_key = SigningKey::from(&secret);
        let addr = address_from_verifying_key(signing_key.verifying_key());
        let did = format!("did:pkh:eip155:1:0x{}", eip55_checksum(&addr));
        (signing_key, did)
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let (key, did) = make_keypair();
        let msg = "hello siwx";
        let sig = eth_sign(&key, msg);
        assert!(Eip155Suite.verify(&did, msg, &sig).unwrap());
    }

    #[test]
    fn wrong_did_rejects() {
        let (key, _) = make_keypair();
        let (_, did2) = make_keypair();
        let sig = eth_sign(&key, "test");
        assert!(!Eip155Suite.verify(&did2, "test", &sig).unwrap());
    }

    #[test]
    fn tampered_message_rejects() {
        let (key, did) = make_keypair();
        let sig = eth_sign(&key, "original");
        assert!(!Eip155Suite.verify(&did, "tampered", &sig).unwrap());
    }

    /// The high-`s` twin of a valid signature (`s' = n - s`, recovery parity
    /// flipped) recovers the same signer, and is still refused: secp256k1
    /// verification accepts low `s` only. ecdsa 0.16 enforced this inside
    /// `recover_from_prehash`; on 0.17 `verify` must do it itself.
    #[test]
    fn high_s_twin_is_refused() {
        let (key, did) = make_keypair();
        let msg = "hello siwx";
        let low = eth_sign(&key, msg);
        let sig = k256::ecdsa::Signature::from_slice(&low[..64]).unwrap();
        let (r, s) = sig.split_scalars();
        let high_sig = k256::ecdsa::Signature::from_scalars(r.to_bytes(), (-*s).to_bytes())
            .expect("n - s is a valid nonzero scalar");
        let mut high = high_sig.to_bytes().to_vec();
        high.push(((low[64] - 27) ^ 1) + 27);
        assert!(Eip155Suite.verify(&did, msg, &low).unwrap());
        assert!(Eip155Suite.verify(&did, msg, &high).is_err());
    }

    #[test]
    fn bad_signature_length_errors() {
        let (_, did) = make_keypair();
        assert!(Eip155Suite.verify(&did, "msg", &[0u8; 32]).is_err());
    }

    #[test]
    fn parse_did_parts_eip155() {
        let (addr, chain) = Eip155Suite.parse_did_parts("1:0xAbCd").unwrap();
        assert_eq!(addr, "0xAbCd");
        assert_eq!(chain, Some("eip155:1".to_string()));
    }
}
