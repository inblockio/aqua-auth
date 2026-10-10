//! Ed25519 cipher suite for `did:pkh:ed25519`.

use crate::cipher_suite::CipherSuite;
use crate::crypto_error::CryptoError;
use crate::did::pubkey_from_ed25519_did;
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, VerifyingKey};

/// Turn 32 public key bytes into a verifying key, refusing every key that
/// should never identify a principal:
///
/// - bytes that do not decompress to a curve point,
/// - a non-canonical encoding (the point re-compresses to different bytes),
/// - a weak (small order) key,
/// - a key with a torsion component (not in the prime-order subgroup).
///
/// Used by every decoder of an Ed25519 key out of a DID, so the accepted set
/// is the same for `did:key`, `did:pkh:ed25519` and `did:peer`. The refusal is
/// [`CryptoError::InvalidDid`], the error the DID decoders already use for an
/// invalid key.
pub(crate) fn strict_verifying_key(bytes: &[u8; 32]) -> Result<VerifyingKey, CryptoError> {
    let compressed = CompressedEdwardsY(*bytes);
    let point = compressed
        .decompress()
        .ok_or_else(|| CryptoError::InvalidDid("Ed25519 public key is not a curve point".into()))?;
    if point.compress().as_bytes() != bytes {
        return Err(CryptoError::InvalidDid(
            "Ed25519 public key has a non-canonical encoding".into(),
        ));
    }
    let key = VerifyingKey::from_bytes(bytes)
        .map_err(|e| CryptoError::InvalidDid(format!("invalid Ed25519 public key: {e}")))?;
    if key.is_weak() {
        return Err(CryptoError::InvalidDid(
            "Ed25519 public key is a weak (small order) key".into(),
        ));
    }
    if !point.is_torsion_free() {
        return Err(CryptoError::InvalidDid(
            "Ed25519 public key is not in the prime-order subgroup".into(),
        ));
    }
    Ok(key)
}

pub struct Ed25519Suite;

impl CipherSuite for Ed25519Suite {
    fn namespace(&self) -> &str {
        "ed25519"
    }

    fn has_chain_id(&self) -> bool {
        false
    }

    fn did_segments(&self) -> usize {
        1 // address (pubkey) only
    }

    fn verify(&self, did: &str, message: &str, signature: &[u8]) -> Result<bool, CryptoError> {
        let pubkey_bytes = pubkey_from_ed25519_did(did)?;
        let verifying_key = strict_verifying_key(&pubkey_bytes)?;

        if signature.len() != 64 {
            return Err(CryptoError::InvalidSignature(format!(
                "Ed25519 signature must be 64 bytes, got {}",
                signature.len()
            )));
        }

        let sig = Signature::from_slice(signature).map_err(|e| {
            CryptoError::InvalidSignature(format!("invalid ed25519 signature: {e}"))
        })?;

        match verifying_key.verify_strict(message.as_bytes(), &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Parse `"0x{pubkey_hex}"` into `("0x{pubkey_hex}", None)`.
    fn parse_did_parts(
        &self,
        did_remainder: &str,
    ) -> Result<(String, Option<String>), CryptoError> {
        Ok((did_remainder.to_string(), None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::pubkey_from_ed25519_did;
    use crate::did_method::DIDMethod;
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
        let msg = "hello siwx";
        let sig = key.sign(msg.as_bytes());
        assert!(Ed25519Suite.verify(&did, msg, &sig.to_bytes()).unwrap());
    }

    #[test]
    fn wrong_did_rejects() {
        let (key, _) = make_keypair();
        let (_, did2) = make_keypair();
        let sig = key.sign(b"test");
        assert!(!Ed25519Suite.verify(&did2, "test", &sig.to_bytes()).unwrap());
    }

    #[test]
    fn tampered_message_rejects() {
        let (key, did) = make_keypair();
        let sig = key.sign(b"original");
        assert!(!Ed25519Suite
            .verify(&did, "tampered", &sig.to_bytes())
            .unwrap());
    }

    #[test]
    fn bad_signature_length_errors() {
        let (_, did) = make_keypair();
        assert!(Ed25519Suite.verify(&did, "msg", &[0u8; 32]).is_err());
    }

    #[test]
    fn parse_did_parts_ed25519() {
        let (address, chain) = Ed25519Suite.parse_did_parts("0xdeadbeef").unwrap();
        assert_eq!(address, "0xdeadbeef");
        assert_eq!(chain, None);
    }

    // ---- strict key handling ----

    use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
    use curve25519_dalek::edwards::EdwardsPoint;

    fn did_for(bytes: &[u8; 32]) -> String {
        format!("did:pkh:ed25519:0x{}", hex::encode(bytes))
    }

    fn did_key_for(bytes: &[u8; 32]) -> String {
        crate::did::ed25519_did_key_from_pubkey(bytes)
    }

    /// Signature with R = the given point and s = 0.
    fn zero_s_signature(r: &EdwardsPoint) -> [u8; 64] {
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(r.compress().as_bytes());
        sig
    }

    #[test]
    fn small_order_points_are_refused_at_decode() {
        // Identity plus every other point of order 2, 4 and 8.
        for (i, p) in EIGHT_TORSION.iter().enumerate() {
            let bytes = p.compress().to_bytes();
            assert!(
                matches!(
                    pubkey_from_ed25519_did(&did_for(&bytes)),
                    Err(CryptoError::InvalidDid(_))
                ),
                "did:pkh decode accepted small-order point {i}"
            );
            assert!(
                matches!(
                    crate::key::ed25519_pubkey_from_did_key(&did_key_for(&bytes)),
                    Err(CryptoError::InvalidDid(_))
                ),
                "did:key decode accepted small-order point {i}"
            );
        }
    }

    #[test]
    fn zero_s_signatures_over_small_order_keys_do_not_verify() {
        for (i, p) in EIGHT_TORSION.iter().enumerate() {
            let bytes = p.compress().to_bytes();
            let sig = zero_s_signature(p);
            let pkh = Ed25519Suite.verify(&did_for(&bytes), "any message", &sig);
            assert!(!matches!(pkh, Ok(true)), "did:pkh verified for point {i}");
            let key = crate::key::KeyMethod.verify(&did_key_for(&bytes), "any message", &sig);
            assert!(!matches!(key, Ok(true)), "did:key verified for point {i}");
        }
    }

    #[test]
    fn key_plus_torsion_point_is_refused() {
        let (key, did) = make_keypair();
        // Control: the clean key is accepted.
        assert!(pubkey_from_ed25519_did(&did).is_ok());
        let a = key.verifying_key().to_edwards();
        let order8 = EIGHT_TORSION[1];
        let mixed = (a + order8).compress().to_bytes();
        assert_ne!(mixed, key.verifying_key().to_bytes());
        assert!(matches!(
            pubkey_from_ed25519_did(&did_for(&mixed)),
            Err(CryptoError::InvalidDid(_))
        ));
        assert!(matches!(
            crate::key::ed25519_pubkey_from_did_key(&did_key_for(&mixed)),
            Err(CryptoError::InvalidDid(_))
        ));
        let sig = key.sign(b"m");
        assert!(!matches!(
            Ed25519Suite.verify(&did_for(&mixed), "m", &sig.to_bytes()),
            Ok(true)
        ));
    }

    #[test]
    fn non_canonical_encoding_is_refused() {
        // y is stored mod 2^255, so a point with y < 19 also has an encoding
        // y + p. The canonical check runs before the weak and torsion checks,
        // so the error text shows which rule fired.
        let p_bytes = {
            let mut b = [0xffu8; 32];
            b[0] = 0xed;
            b[31] = 0x7f;
            b
        };
        let mut tried = 0;
        for y in 0u8..19 {
            let mut canon = [0u8; 32];
            canon[0] = y;
            if CompressedEdwardsY(canon).decompress().is_none() {
                continue;
            }
            let mut alt = [0u8; 32];
            let mut carry = 0u16;
            for i in 0..32 {
                let v = canon[i] as u16 + p_bytes[i] as u16 + carry;
                alt[i] = (v & 0xff) as u8;
                carry = v >> 8;
            }
            assert_eq!(carry, 0);
            // The library's decompression accepts the alternate form...
            assert!(CompressedEdwardsY(alt).decompress().is_some());
            // ...and the strict decoder refuses it for its encoding.
            let err = strict_verifying_key(&alt).unwrap_err().to_string();
            assert!(err.contains("non-canonical"), "y={y}: {err}");
            assert!(pubkey_from_ed25519_did(&did_for(&alt)).is_err());
            tried += 1;
        }
        assert!(tried > 0, "no test point with an alternate encoding found");
    }

    #[test]
    fn bytes_that_are_not_a_point_are_refused() {
        // Scan for a y that does not decompress.
        let mut bytes = [0u8; 32];
        let mut refused = false;
        for y in 2u8..=255 {
            bytes[0] = y;
            if CompressedEdwardsY(bytes).decompress().is_none() {
                assert!(matches!(
                    strict_verifying_key(&bytes),
                    Err(CryptoError::InvalidDid(_))
                ));
                refused = true;
                break;
            }
        }
        assert!(refused, "no non-point encoding found");
    }

    #[test]
    fn basepoint_is_an_ordinary_valid_key() {
        let bytes = ED25519_BASEPOINT_POINT.compress().to_bytes();
        assert!(strict_verifying_key(&bytes).is_ok());
    }

    #[test]
    fn normal_key_round_trips_through_both_spellings() {
        let key = SigningKey::generate(&mut OsRng);
        let bytes = key.verifying_key().to_bytes();
        let sig = key.sign(b"round trip").to_bytes();
        assert!(Ed25519Suite
            .verify(&did_for(&bytes), "round trip", &sig)
            .unwrap());
        assert!(crate::key::KeyMethod
            .verify(&did_key_for(&bytes), "round trip", &sig)
            .unwrap());
    }
}
