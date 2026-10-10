//! `DIDMethod` for `did:key`.
//!
//! Supports Ed25519 (`z6Mk...`) and P-256 (`zDn...`) key types.
//! Encoding: `z` (base58btc multibase) + multicodec varint prefix + raw key bytes.

use crate::{crypto_error::CryptoError, did_method::DIDMethod};
use ::p256::ecdsa::signature::Verifier;
use ::p256::{
    ecdsa::{Signature as P256Sig, VerifyingKey as P256Key},
    EncodedPoint,
};
use ed25519_dalek::{Signature as Ed25519Sig, VerifyingKey as Ed25519Key};

/// Multicodec varint for Ed25519 public key (0xED01).
pub(crate) const ED25519_PREFIX: &[u8] = &[0xED, 0x01];
/// Multicodec varint for P-256 public key (0x1200).
pub(crate) const P256_PREFIX: &[u8] = &[0x80, 0x24];

pub(crate) enum KeyType {
    Ed25519(Vec<u8>), // 32-byte raw pubkey
    P256(Vec<u8>),    // 33-byte compressed SEC1 point
}

/// Decode the base58btc body of a `z{body}` multibase+multicodec key string.
/// `z_body` must NOT include the leading `z`.
pub(crate) fn decode_multibase_key(z_body: &str) -> Result<KeyType, CryptoError> {
    let bytes = bs58::decode(z_body)
        .into_vec()
        .map_err(|e| CryptoError::InvalidDid(format!("base58btc decode error: {e}")))?;
    if bytes.starts_with(ED25519_PREFIX) {
        let raw = bytes[ED25519_PREFIX.len()..].to_vec();
        // A wrong length is reported by the callers; a 32-byte key must be a
        // strict one.
        if let Ok(key) = <&[u8; 32]>::try_from(raw.as_slice()) {
            ed25519::strict_verifying_key(key)?;
        }
        Ok(KeyType::Ed25519(raw))
    } else if bytes.starts_with(P256_PREFIX) {
        Ok(KeyType::P256(bytes[P256_PREFIX.len()..].to_vec()))
    } else {
        Err(CryptoError::InvalidDid(format!(
            "unknown multicodec prefix {:02x?}",
            &bytes[..2.min(bytes.len())]
        )))
    }
}

/// Verify a signature given a decoded KeyType and the message.
pub(crate) fn verify_with_key(
    key: KeyType,
    message: &str,
    signature: &[u8],
) -> Result<bool, CryptoError> {
    match key {
        KeyType::Ed25519(raw) => {
            let key_bytes: [u8; 32] = raw.try_into().map_err(|_| {
                CryptoError::InvalidSignature("Ed25519 public key must be 32 bytes".to_string())
            })?;
            let verifying_key: Ed25519Key = ed25519::strict_verifying_key(&key_bytes)?;
            if signature.len() != 64 {
                return Err(CryptoError::InvalidSignature(format!(
                    "Ed25519 signature must be 64 bytes, got {}",
                    signature.len()
                )));
            }
            let sig = Ed25519Sig::from_slice(signature)
                .map_err(|e| CryptoError::InvalidSignature(format!("invalid Ed25519 sig: {e}")))?;
            Ok(verifying_key
                .verify_strict(message.as_bytes(), &sig)
                .is_ok())
        }
        KeyType::P256(raw) => {
            let point = EncodedPoint::from_bytes(&raw).map_err(|e| {
                CryptoError::InvalidSignature(format!("invalid P-256 encoded point: {e}"))
            })?;
            let verifying_key = P256Key::from_encoded_point(&point)
                .map_err(|e| CryptoError::InvalidSignature(format!("invalid P-256 key: {e}")))?;
            let sig = P256Sig::from_der(signature)
                .or_else(|_| P256Sig::from_slice(signature))
                .map_err(|e| CryptoError::InvalidSignature(format!("invalid P-256 sig: {e}")))?;
            Ok(verifying_key.verify(message.as_bytes(), &sig).is_ok())
        }
    }
}

/// Extract the raw 32-byte Ed25519 public key from a `did:key:z6Mk...` DID.
///
/// Companion to [`crate::did::pubkey_from_ed25519_did`], which reads the
/// `did:pkh:ed25519:0x{hex}` spelling of the same underlying key. Both
/// spellings are accepted at login and are deliberately distinct principals
/// (see #182), so a caller holding raw key material must pick the parser that
/// matches the spelling it was given; neither parser accepts the other form.
///
/// Exists so that key-advertisement code (the `aqua-auth-directory` crate)
/// can publish the JWK `x` member without re-implementing multibase and
/// multicodec decoding, which would leave two disagreeing definitions of what
/// a valid `did:key` is.
pub fn ed25519_pubkey_from_did_key(did: &str) -> Result<[u8; 32], CryptoError> {
    let z_body = did
        .strip_prefix("did:key:z")
        .ok_or_else(|| CryptoError::InvalidDid(format!("expected did:key DID: {did}")))?;
    match decode_multibase_key(z_body)? {
        KeyType::Ed25519(raw) => raw.try_into().map_err(|_| {
            CryptoError::InvalidDid("Ed25519 public key must be 32 bytes".to_string())
        }),
        other => Err(CryptoError::InvalidDid(format!(
            "expected an Ed25519 did:key, got {}",
            key_type_label(&other)
        ))),
    }
}

/// Extract the 33-byte compressed SEC1 P-256 public key from a
/// `did:key:zDn...` DID.
///
/// The P-256 twin of [`ed25519_pubkey_from_did_key`] and the inverse of
/// [`crate::did::p256_did_key_from_pubkey`]. The key is validated as a point on
/// the curve, so an `Ok` value always decodes to a usable verifying key. The
/// `did:pkh:p256:0x{hex}` spelling is a distinct principal (#182) with its own
/// parser, [`crate::did::pubkey_from_p256_did`]; this one accepts `did:key`
/// only.
pub fn p256_pubkey_from_did_key(did: &str) -> Result<[u8; 33], CryptoError> {
    let z_body = did
        .strip_prefix("did:key:z")
        .ok_or_else(|| CryptoError::InvalidDid(format!("expected did:key DID: {did}")))?;
    let raw = match decode_multibase_key(z_body)? {
        KeyType::P256(raw) => raw,
        other => {
            return Err(CryptoError::InvalidDid(format!(
                "expected a P-256 did:key, got {}",
                key_type_label(&other)
            )))
        }
    };
    let compressed: [u8; 33] = raw.as_slice().try_into().map_err(|_| {
        CryptoError::InvalidDid(format!(
            "P-256 did:key must carry a 33-byte compressed point, got {} bytes",
            raw.len()
        ))
    })?;
    ::p256::PublicKey::from_sec1_bytes(&compressed)
        .map_err(|_| CryptoError::InvalidDid("P-256 did:key is not a point on the curve".into()))?;
    Ok(compressed)
}

pub(crate) fn key_type_label(key: &KeyType) -> &'static str {
    match key {
        KeyType::Ed25519(_) => "Ed25519",
        KeyType::P256(_) => "P-256",
    }
}

pub mod ed25519;
pub mod p256;

pub use ed25519::Ed25519Suite;
pub use p256::P256Suite;

pub struct KeyMethod;

impl DIDMethod for KeyMethod {
    fn method_name(&self) -> &str {
        "key"
    }

    fn method_label(&self, did: &str) -> Result<&'static str, CryptoError> {
        let z_body = did
            .strip_prefix("did:key:z")
            .ok_or_else(|| CryptoError::InvalidDid(did.to_string()))?;
        match decode_multibase_key(z_body)? {
            KeyType::Ed25519(_) => Ok("Ed25519"),
            KeyType::P256(_) => Ok("P-256"),
        }
    }

    fn display_label(&self, did: &str) -> Result<String, CryptoError> {
        let z_body = did
            .strip_prefix("did:key:z")
            .ok_or_else(|| CryptoError::InvalidDid(did.to_string()))?;
        let label = key_type_label(&decode_multibase_key(z_body)?);
        let short = &z_body[..z_body.len().min(8)];
        Ok(format!("z{short}... ({label})"))
    }

    fn address_for_message(&self, did: &str) -> Result<String, CryptoError> {
        did.strip_prefix("did:key:")
            .map(|s| s.to_string())
            .ok_or_else(|| CryptoError::InvalidDid(did.to_string()))
    }

    fn has_chain_id(&self, _did: &str) -> bool {
        false
    }

    fn chain_id(&self, _did: &str) -> Result<Option<String>, CryptoError> {
        Ok(None)
    }

    fn canonical_subject(&self, did: &str) -> Result<String, CryptoError> {
        Ok(did.to_string())
    }

    fn verify(&self, did: &str, message: &str, signature: &[u8]) -> Result<bool, CryptoError> {
        let z_body = did
            .strip_prefix("did:key:z")
            .ok_or_else(|| CryptoError::InvalidDid(did.to_string()))?;
        verify_with_key(decode_multibase_key(z_body)?, message, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
    use ed25519_dalek::{Signer, SigningKey as Ed25519SigningKey};
    use rand::rngs::OsRng;

    pub(super) fn ed25519_did(key: &Ed25519SigningKey) -> String {
        let mut bytes = ED25519_PREFIX.to_vec();
        bytes.extend_from_slice(key.verifying_key().as_bytes());
        format!("did:key:z{}", bs58::encode(&bytes).into_string())
    }

    pub(super) fn p256_did(key: &P256SigningKey) -> String {
        let compressed = key.verifying_key().to_encoded_point(true);
        let mut bytes = P256_PREFIX.to_vec();
        bytes.extend_from_slice(compressed.as_bytes());
        format!("did:key:z{}", bs58::encode(&bytes).into_string())
    }

    #[test]
    fn ed25519_roundtrip() {
        let key = Ed25519SigningKey::generate(&mut OsRng);
        let did = ed25519_did(&key);
        assert!(
            did.starts_with("did:key:z6Mk"),
            "expected z6Mk prefix, got {did}"
        );
        let sig = key.sign(b"hello did:key");
        assert!(KeyMethod
            .verify(&did, "hello did:key", &sig.to_bytes())
            .unwrap());
    }

    #[test]
    fn ed25519_wrong_key_rejects() {
        let key = Ed25519SigningKey::generate(&mut OsRng);
        let key2 = Ed25519SigningKey::generate(&mut OsRng);
        let did2 = ed25519_did(&key2);
        let sig = key.sign(b"test");
        assert!(!KeyMethod.verify(&did2, "test", &sig.to_bytes()).unwrap());
    }

    #[test]
    fn p256_roundtrip_fixed() {
        let key = P256SigningKey::random(&mut OsRng);
        let did = p256_did(&key);
        let sig: P256Signature = key.sign(b"hello p256 key");
        assert!(KeyMethod
            .verify(&did, "hello p256 key", &sig.to_bytes())
            .unwrap());
    }

    #[test]
    fn p256_roundtrip_der() {
        let key = P256SigningKey::random(&mut OsRng);
        let did = p256_did(&key);
        let sig: P256Signature = key.sign(b"hello p256 key");
        assert!(KeyMethod
            .verify(&did, "hello p256 key", sig.to_der().as_bytes())
            .unwrap());
    }

    #[test]
    fn p256_wrong_key_rejects() {
        let key = P256SigningKey::random(&mut OsRng);
        let key2 = P256SigningKey::random(&mut OsRng);
        let did2 = p256_did(&key2);
        let sig: P256Signature = key.sign(b"test");
        assert!(!KeyMethod.verify(&did2, "test", &sig.to_bytes()).unwrap());
    }

    #[test]
    fn display_label_ed25519() {
        let key = Ed25519SigningKey::generate(&mut OsRng);
        let label = KeyMethod.display_label(&ed25519_did(&key)).unwrap();
        assert!(label.contains("Ed25519"), "{label}");
    }

    #[test]
    fn display_label_p256() {
        let key = P256SigningKey::random(&mut OsRng);
        let label = KeyMethod.display_label(&p256_did(&key)).unwrap();
        assert!(label.contains("P-256"), "{label}");
    }

    #[test]
    fn canonical_subject_is_full_did() {
        let key = Ed25519SigningKey::generate(&mut OsRng);
        let did = ed25519_did(&key);
        assert_eq!(KeyMethod.canonical_subject(&did).unwrap(), did);
    }

    #[test]
    fn address_for_message_strips_did_key() {
        let key = Ed25519SigningKey::generate(&mut OsRng);
        let did = ed25519_did(&key);
        let addr = KeyMethod.address_for_message(&did).unwrap();
        assert!(addr.starts_with("z6Mk"));
    }

    #[test]
    fn ed25519_pubkey_from_did_key_roundtrip() {
        let key = Ed25519SigningKey::generate(&mut OsRng);
        let did = ed25519_did(&key);
        let raw = ed25519_pubkey_from_did_key(&did).unwrap();
        assert_eq!(&raw, key.verifying_key().as_bytes());
    }

    #[test]
    fn ed25519_pubkey_from_did_key_rejects_p256() {
        let key = P256SigningKey::random(&mut OsRng);
        assert!(ed25519_pubkey_from_did_key(&p256_did(&key)).is_err());
    }

    #[test]
    fn ed25519_pubkey_from_did_key_rejects_pkh_spelling() {
        // The did:pkh spelling is a separate principal with its own parser
        // (did::pubkey_from_ed25519_did); this one accepts did:key only.
        let did = format!("did:pkh:ed25519:0x{}", hex::encode([0xAAu8; 32]));
        assert!(ed25519_pubkey_from_did_key(&did).is_err());
    }

    #[test]
    fn p256_did_key_roundtrip() {
        use rand::{rngs::StdRng, SeedableRng};
        let mut rng = StdRng::seed_from_u64(0x0a0a_d1d0);
        for _ in 0..64 {
            let key = P256SigningKey::random(&mut rng);
            let compressed: [u8; 33] = key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap();
            let did = crate::did::p256_did_key_from_pubkey(&compressed);
            assert!(did.starts_with("did:key:zDn"), "{did}");
            assert_eq!(p256_pubkey_from_did_key(&did).unwrap(), compressed);
        }
    }

    #[test]
    fn p256_did_key_decoder_rejects_wrong_multicodec_length_and_off_curve() {
        // An Ed25519 did:key is a valid DID of the wrong key type.
        let ed = Ed25519SigningKey::generate(&mut OsRng);
        assert!(p256_pubkey_from_did_key(&ed25519_did(&ed)).is_err());

        // A P-256 multicodec prefix over a 34-byte body.
        let mut long = P256_PREFIX.to_vec();
        long.push(0x02);
        long.extend_from_slice(&[0x11u8; 33]);
        let did = format!("did:key:z{}", bs58::encode(&long).into_string());
        assert!(p256_pubkey_from_did_key(&did).is_err());

        // A well-formed compressed encoding whose x has no point on the curve:
        // x = 1 gives x^3 - 3x + b, a quadratic non-residue mod p (checked with
        // Euler's criterion outside this crate).
        let mut off_curve = P256_PREFIX.to_vec();
        off_curve.push(0x02);
        let mut x = [0u8; 32];
        x[31] = 1;
        off_curve.extend_from_slice(&x);
        let did = format!("did:key:z{}", bs58::encode(&off_curve).into_string());
        assert!(p256_pubkey_from_did_key(&did).is_err());

        // The did:pkh spelling is a separate principal with its own parser.
        let key = P256SigningKey::random(&mut OsRng);
        let compressed = key.verifying_key().to_encoded_point(true);
        let pkh = format!("did:pkh:p256:0x{}", hex::encode(compressed.as_bytes()));
        assert!(p256_pubkey_from_did_key(&pkh).is_err());
    }

    #[test]
    fn invalid_multicodec_errors() {
        // base58btc of [0x00, 0x01, ...] -- unknown prefix
        let bad_body = bs58::encode(&[0x00u8, 0x01, 0x02, 0x03]).into_string();
        let did = format!("did:key:z{bad_body}");
        assert!(KeyMethod.verify(&did, "msg", &[0u8; 64]).is_err());
    }
}
