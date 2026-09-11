//! `did:aqua`: ML-DSA-87 post-quantum login (PCA-0017).
//!
//! # What makes this namespace different
//!
//! Every other namespace this crate supports resolves the public key from
//! material the verifier already holds. `did:key`, `did:pkh:ed25519`,
//! `did:pkh:p256` and `did:peer` all **embed** the key in the DID string and
//! decode it out. `did:pkh:eip155` **hashes** the key into the DID, and can
//! still verify because secp256k1 ECDSA is recoverable: the verifier
//! recovers the key from the signature and compares the derived address.
//!
//! `did:aqua` hashes the key of a scheme that is **not** recoverable.
//! ML-DSA is Fiat-Shamir with Aborts over module lattices, and the public
//! key is an input to the verification relation, not an output of it. So
//! `did:aqua` is the first namespace where the verifier can obtain the key
//! neither from the DID nor from the signature, and the key has to arrive
//! separately. That is the whole reason this module exists and the whole
//! reason [`crate::DIDMethod`] needed a fourth argument.
//!
//! Why hash at all: an ML-DSA-87 public key is 2592 bytes, and embedding it
//! the way `did:key` embeds an Ed25519 key gives a roughly 3552-character
//! DID threaded through every signer field and every registry entry
//! (PCA-0017 Section 1.4). The content-addressed identity is 56 characters
//! regardless of key size.
//!
//! # Transport
//!
//! The key travels as an optional `public_key` field on the session request
//! ([`crate::wire::SessionRequest`]). This is transport A of the four
//! evaluated on 2026-09-11; see `SPEC.md` Section 6.6 for the alternatives
//! and why this one was taken.
//!
//! Whatever the transport, the key is worthless until
//! [`codec::aqua_did_binds_pubkey`] binds it back to the DID that claimed
//! it. Because the DID is a hash of the key, that one check makes every
//! transport trustless: a caller cannot pair a key it holds with a DID it
//! does not own, so `did:aqua` needs no registration authority and has no
//! squatting surface.
//!
//! # Scope: authentication only, for now
//!
//! A `did:aqua` identity can authenticate and be issued a session. It
//! cannot yet hold a grant or a delegation, because both servers carry
//! their own DID dispatch outside this crate's registry. See `CHANGELOG.md`
//! and `docs/did-aqua-phase-2.md` for what remains.

pub mod codec;
pub mod ml_dsa;

use crate::crypto_error::CryptoError;
use crate::did_method::DIDMethod;

pub use codec::{
    aqua_did_binds_pubkey, aqua_did_from_pubkey, multihash_from_aqua_did, MLDSA_87_PUB_CODEC,
    MLDSA_87_PUB_CODEC_VARINT, ML_DSA_87_PUBLIC_KEY_BYTES,
};
pub use ml_dsa::{hint_encoding_is_canonical, HintDefect, ML_DSA_87_SIGNATURE_BYTES};

/// The `did:aqua` DID method: ML-DSA-87 signatures over a content-addressed
/// identity.
pub struct AquaMethod;

impl DIDMethod for AquaMethod {
    fn method_name(&self) -> &str {
        "aqua"
    }

    fn method_label(&self, did: &str) -> Result<&'static str, CryptoError> {
        multihash_from_aqua_did(did)?;
        Ok("ML-DSA-87")
    }

    fn display_label(&self, did: &str) -> Result<String, CryptoError> {
        multihash_from_aqua_did(did)?;
        // Mirrors KeyMethod: the leading characters of the identifier plus
        // the scheme, short enough to sit in a UI line.
        let body = &did["did:aqua:".len()..];
        let short = &body[..body.len().min(9)];
        Ok(format!("{short}... (ML-DSA-87)"))
    }

    /// The identifier line of the CAIP-122 message: the `z...` body, exactly
    /// as `did:key` uses its own multibase body.
    fn address_for_message(&self, did: &str) -> Result<String, CryptoError> {
        multihash_from_aqua_did(did)?;
        did.strip_prefix("did:aqua:")
            .map(str::to_string)
            .ok_or_else(|| CryptoError::InvalidDid(did.to_string()))
    }

    fn has_chain_id(&self, _did: &str) -> bool {
        false
    }

    fn chain_id(&self, _did: &str) -> Result<Option<String>, CryptoError> {
        Ok(None)
    }

    fn canonical_subject(&self, did: &str) -> Result<String, CryptoError> {
        multihash_from_aqua_did(did)?;
        Ok(did.to_string())
    }

    /// Always an error: ML-DSA-87 has no public-key recovery and `did:aqua`
    /// commits to the key rather than encoding it, so there is no way to
    /// verify from three arguments. Callers must route through
    /// [`DIDMethod::verify_with_public_key`].
    ///
    /// This is deliberately loud rather than a silent `Ok(false)`: a server
    /// that upgrades without plumbing the key through should see a
    /// diagnosable error, not a login that fails as though the signature
    /// were wrong.
    fn verify(
        &self,
        _did: &str,
        _canonical_msg: &str,
        _signature: &[u8],
    ) -> Result<bool, CryptoError> {
        Err(CryptoError::InvalidSignature(
            "did:aqua requires the signer's public key; call verify_with_public_key".to_string(),
        ))
    }

    fn verify_with_public_key(
        &self,
        did: &str,
        canonical_msg: &str,
        signature: &[u8],
        public_key: Option<&[u8]>,
    ) -> Result<bool, CryptoError> {
        let public_key = public_key.ok_or_else(|| {
            CryptoError::InvalidSignature(
                "did:aqua requires the signer's public key, none supplied".to_string(),
            )
        })?;

        // Bind first. Verifying before binding would prove possession of
        // some key, which says nothing about the identity being claimed.
        if !aqua_did_binds_pubkey(did, public_key)? {
            return Ok(false);
        }

        ml_dsa::verify(public_key, signature, canonical_msg.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::ml_dsa::{KeyInit, Keypair, MlDsa87, SigningKey};

    /// Seed-derived, matching the SDK's test idiom, so these cases are
    /// reproducible byte-for-byte.
    fn signer(seed: u8) -> (SigningKey<MlDsa87>, Vec<u8>, String) {
        let sk = SigningKey::<MlDsa87>::new(&[seed; 32].into());
        let pk = Keypair::verifying_key(&sk).encode().as_slice().to_vec();
        let did = aqua_did_from_pubkey(&pk);
        (sk, pk, did)
    }

    fn sign(sk: &SigningKey<MlDsa87>, msg: &str) -> Vec<u8> {
        use ::ml_dsa::signature::Signer as _;
        sk.sign(msg.as_bytes()).encode().as_slice().to_vec()
    }

    #[test]
    fn the_registry_routes_did_aqua_here() {
        let (_, _, did) = signer(1);
        let m = crate::did_method::find_did_method(&did).expect("registry must know did:aqua");
        assert_eq!(m.method_name(), "aqua");
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let (sk, pk, did) = signer(2);
        let msg = "aqua-node wants you to sign in";
        let sig = sign(&sk, msg);
        assert!(AquaMethod
            .verify_with_public_key(&did, msg, &sig, Some(&pk))
            .unwrap());
    }

    /// The binding check is the security of the whole scheme: a valid
    /// signature under a key that is not the one the DID commits to must
    /// fail, even though the signature itself is perfectly good.
    #[test]
    fn a_valid_signature_under_the_wrong_identity_is_rejected() {
        let (sk, pk, _) = signer(3);
        let (_, _, other_did) = signer(4);
        let msg = "m";
        let sig = sign(&sk, msg);
        assert!(!AquaMethod
            .verify_with_public_key(&other_did, msg, &sig, Some(&pk))
            .unwrap());
    }

    #[test]
    fn a_tampered_message_is_rejected() {
        let (sk, pk, did) = signer(5);
        let sig = sign(&sk, "original");
        assert!(!AquaMethod
            .verify_with_public_key(&did, "tampered", &sig, Some(&pk))
            .unwrap());
    }

    #[test]
    fn the_three_argument_verify_refuses_loudly() {
        let (_, _, did) = signer(6);
        let err = AquaMethod.verify(&did, "m", &[0u8; 32]).unwrap_err();
        assert!(
            err.to_string().contains("verify_with_public_key"),
            "got: {err}"
        );
    }

    #[test]
    fn a_missing_public_key_is_an_error_not_a_false() {
        let (_, _, did) = signer(7);
        assert!(AquaMethod
            .verify_with_public_key(&did, "m", &[0u8; 32], None)
            .is_err());
    }

    /// The default implementation on every other method ignores the extra
    /// argument, so passing a key to an ed25519 DID changes nothing.
    #[test]
    fn the_default_implementation_is_transparent_for_other_methods() {
        use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey};
        let key = EdSigningKey::generate(&mut rand::rngs::OsRng);
        let did = crate::did::ed25519_did_key_from_pubkey(&key.verifying_key().to_bytes());
        let msg = "m";
        let sig = key.sign(msg.as_bytes()).to_bytes();

        let m = crate::did_method::find_did_method(&did).unwrap();
        assert!(m.verify(&did, msg, &sig).unwrap());
        assert!(m.verify_with_public_key(&did, msg, &sig, None).unwrap());
        // A stray key is ignored rather than consulted.
        assert!(m
            .verify_with_public_key(&did, msg, &sig, Some(&[0u8; 2592]))
            .unwrap());
    }

    #[test]
    fn message_identifier_is_the_multibase_body() {
        let (_, _, did) = signer(8);
        let id = AquaMethod.address_for_message(&did).unwrap();
        assert!(id.starts_with('z'));
        assert_eq!(format!("did:aqua:{id}"), did);
    }

    #[test]
    fn malformed_dids_are_rejected_by_every_accessor() {
        let bad = "did:aqua:znot-a-real-identifier";
        assert!(AquaMethod.method_label(bad).is_err());
        assert!(AquaMethod.display_label(bad).is_err());
        assert!(AquaMethod.address_for_message(bad).is_err());
        assert!(AquaMethod.canonical_subject(bad).is_err());
    }
}
