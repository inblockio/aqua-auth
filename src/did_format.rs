//! SPEC section 7 rule 5 (DID well-formedness) as its own enforcement layer.
//!
//! # Why this module exists
//!
//! SPEC section 7 lists seven MUSTs. Rule 5, "the DID passes namespace-specific
//! format checks (correct prefix, correct byte-length for the identifier)", had
//! no code of its own: the only thing that rejected a malformed identifier was
//! the signature-verification path incidentally failing to parse a key out of
//! it. Measured 2026-09-11 against the conformance suite's seven malformed
//! shapes (`aqua-auth-testkit/src/conformance/cases_nonce_and_did.rs`, case
//! `spec_7_5_did_well_formed`), five of the seven reached
//! [`crate::ChallengeStore::create`] and were handed a real nonce:
//!
//! | Shape | Refused at challenge time before this module | Why |
//! |---|---|---|
//! | `did:pkh:ed25519` with a 31, 33 or non-hex identifier, or no `0x` | no | `Ed25519Suite::parse_did_parts` (`src/key/ed25519.rs:46-51`) returns its input unread |
//! | `did:pkh:p256` with a 32-byte identifier | no | `P256Suite::parse_did_parts` (`src/key/p256.rs:44-49`) likewise |
//! | `did:pkh:eip155` with a 19-byte address | yes | `PkhMethod::address_for_message` special-cases eip155 to `checksummed_address` (`src/pkh/method.rs:50-53`), which length-checks |
//! | `did:key` with an undecodable multibase body | yes | `build_message` also calls `method_label`, and `KeyMethod::method_label` decodes (`src/key/mod.rs:125-133`) |
//!
//! So whether rule 5 held at challenge time depended on whether a *display and
//! message-formatting* helper happened to parse the identifier on the way past.
//! That is not an enforcement layer, it is a coincidence, and the negative
//! control `nc4_skipped_verification_fails_both_signature_cases_and_its_cascade`
//! demonstrated the consequence: deleting the verification path deleted rule 5
//! along with it.
//!
//! [`validate_did_well_formed`] gives rule 5 a layer that does not depend on
//! verification succeeding, or on verification running at all.
//!
//! # The invariant, and why this cannot refuse a legitimate caller
//!
//! **Every DID this function rejects is one the verification path also rejects
//! on format grounds, before it ever looks at a signature.** The set of refusals
//! here is a strict subset, never a superset, and it is a subset by
//! construction rather than by review: each arm below calls the *same* parser
//! that the corresponding `DIDMethod`/`CipherSuite` verifier calls as its first
//! act, so a second definition of "well-formed" is not written down anywhere.
//!
//! Where the verifier checks more, this deliberately stops short. Rule 5 is
//! worded as a format check ("correct prefix, correct byte-length"), so this
//! never checks curve membership or SEC1 point validity even though
//! `verify_with_key` (`src/key/mod.rs:64-74`) does. Stopping short keeps the
//! subset property true: a DID that is well-formed but whose key material is
//! cryptographically unusable is still a rule 6 problem, refused at verification
//! time with the error it has always had.
//!
//! The distinction between the two failures is preserved in the error type and
//! is load-bearing for a consumer mapping these onto status codes: a method no
//! registered [`crate::DIDMethod`] recognises is
//! [`CryptoError::UnsupportedMethod`] (rule 4), while a recognised method
//! carrying a malformed identifier is [`CryptoError::InvalidDid`] or
//! [`CryptoError::HexDecode`] (rule 5).
//!
//! # Feature gating
//!
//! Only the `did:aqua` arm is feature-gated, and it is unreachable without the
//! feature because [`find_did_method`] returns `None` for `did:aqua` first. This
//! adds no new cross-build divergence: the challenge path has always consulted
//! the feature-gated registry, inside `build_message`'s own `find_did_method`
//! call (`src/message.rs:30-32`). The four classical namespaces behave
//! identically in every feature combination.

use crate::crypto_error::CryptoError;
use crate::did_method::find_did_method;
use crate::key::{decode_multibase_key, KeyType};

/// Raw byte length of an Ed25519 public key, as `did:key`/`did:peer` carry it
/// after the multicodec prefix. The same number `verify_with_key` enforces via
/// `TryInto<[u8; 32]>` (`src/key/mod.rs:49-51`); the parity tests below assert
/// the two agree rather than trusting that they do.
const ED25519_PUBKEY_BYTES: usize = 32;

/// Raw byte length of a compressed SEC1 P-256 point, per SPEC section 3. The
/// same number `EncodedPoint::from_bytes` enforces inside `verify_with_key`.
const P256_COMPRESSED_PUBKEY_BYTES: usize = 33;

/// Check that `did` is well-formed: a method some registered
/// [`crate::DIDMethod`] recognises (SPEC section 7 rule 4), carrying an
/// identifier with the prefix and byte length SPEC section 3 gives that
/// namespace (rule 5).
///
/// This answers only "could this DID ever be authenticated?", never "did
/// someone authenticate as it". It performs no cryptography, touches no
/// signature, and proves nothing about possession: a `true` here is a
/// necessary condition for a login, never a sufficient one. Use
/// [`crate::authenticate`] for proof of possession.
///
/// Called at three independent points, so that no single change can remove
/// rule 5 from the system:
///
/// 1. [`crate::ChallengeStore::create`], so the challenge endpoint cannot mint
///    and store a nonce for an identity that is not representable.
/// 2. [`crate::authenticate_with_public_key`], so the session entry point
///    enforces rule 5 whether or not the verifier beneath it runs.
/// 3. [`crate::Principal::from_trusted_did`], the one path into a
///    [`crate::Principal`] that never verifies anything.
///
/// The per-method verifiers keep their own checks unchanged underneath all
/// three. This multiplies the check rather than relocating it: a relocated
/// check leaves exactly the single point of failure it was meant to remove.
pub fn validate_did_well_formed(did: &str) -> Result<(), CryptoError> {
    let method =
        find_did_method(did).ok_or_else(|| CryptoError::UnsupportedMethod(did.to_string()))?;

    match method.method_name() {
        "pkh" => validate_pkh(did),
        "key" => {
            let z_body = did.strip_prefix("did:key:z").ok_or_else(|| {
                CryptoError::InvalidDid(format!("did:key body must be multibase 'z': {did}"))
            })?;
            validate_multibase_key_body(z_body)
        }
        "peer" => validate_multibase_key_body(&crate::peer::extract_z_body(did)?),
        #[cfg(feature = "did-aqua")]
        "aqua" => crate::aqua::multihash_from_aqua_did(did).map(|_| ()),
        other => Err(CryptoError::UnsupportedMethod(other.to_string())),
    }
}

/// SPEC section 3's `did:pkh` table, checked through the exact parsers each
/// `CipherSuite::verify` calls first: `address_from_did` for eip155
/// (`src/pkh/eip155.rs:24`), `pubkey_from_ed25519_did` for ed25519
/// (`src/key/ed25519.rs:24`), `pubkey_from_p256_did` for p256
/// (`src/key/p256.rs:25`).
///
/// An unrecognised namespace is rule 4, not rule 5, and gets
/// `UnsupportedMethod` exactly as `PkhMethod::verify` does
/// (`src/pkh/method.rs:85-86`): `PkhMethod::supports_did` matches the whole
/// `did:pkh:` prefix, so the registry cannot make this distinction by itself.
fn validate_pkh(did: &str) -> Result<(), CryptoError> {
    match crate::did::parse_did_namespace(did)? {
        "eip155" => crate::did::address_from_did(did).map(|_| ()),
        "ed25519" => crate::did::pubkey_from_ed25519_did(did).map(|_| ()),
        "p256" => crate::did::pubkey_from_p256_did(did).map(|_| ()),
        other => Err(CryptoError::UnsupportedMethod(other.to_string())),
    }
}

/// The multibase+multicodec body shared by `did:key` and `did:peer`: decodable
/// base58btc, a multicodec prefix this crate knows, and the raw key length SPEC
/// section 3 gives that key type.
///
/// Length is checked here and not left to `decode_multibase_key`, which
/// deliberately reports only the prefix: a `z6Mk...` body that decodes to 31
/// bytes is a well-formed multicodec envelope around an identifier that is the
/// wrong size, which is precisely rule 5's second clause.
fn validate_multibase_key_body(z_body: &str) -> Result<(), CryptoError> {
    match decode_multibase_key(z_body)? {
        KeyType::Ed25519(raw) if raw.len() != ED25519_PUBKEY_BYTES => {
            Err(CryptoError::InvalidDid(format!(
                "Ed25519 public key must be {ED25519_PUBKEY_BYTES} bytes, got {}",
                raw.len()
            )))
        }
        KeyType::P256(raw) if raw.len() != P256_COMPRESSED_PUBKEY_BYTES => {
            Err(CryptoError::InvalidDid(format!(
                "P-256 compressed public key must be {P256_COMPRESSED_PUBKEY_BYTES} bytes, got {}",
                raw.len()
            )))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did_method::DIDMethod;

    /// The seven shapes SPEC section 7 rule 5 is tested against over HTTP by
    /// `spec_7_5_did_well_formed`
    /// (`aqua-auth-testkit/src/conformance/cases_nonce_and_did.rs:360-427`),
    /// mirrored here so rule 5 is asserted **without a server, without a
    /// signature, and without the verification path existing at all**. That is
    /// the independence the conformance suite structurally cannot provide: its
    /// own case is allowed to observe a refusal at either endpoint, so it can
    /// never distinguish "rule 5 has a layer" from "verification happened to
    /// catch it".
    ///
    /// Fixed rather than random values, unlike the conformance table: a unit
    /// test that fails must fail reproducibly.
    fn malformed_shapes() -> Vec<(&'static str, String)> {
        let h = |n: usize| -> String { "ab".repeat(n / 2) };
        vec![
            (
                "ed25519 did:pkh, 31-byte key (needs 32)",
                format!("did:pkh:ed25519:0x{}", h(62)),
            ),
            (
                "ed25519 did:pkh, 33-byte key (needs 32)",
                format!("did:pkh:ed25519:0x{}", h(66)),
            ),
            (
                "ed25519 did:pkh, missing 0x prefix",
                format!("did:pkh:ed25519:{}", h(64)),
            ),
            (
                "ed25519 did:pkh, non-hex character present",
                format!("did:pkh:ed25519:0xz{}", h(62) + "a"),
            ),
            (
                "p256 did:pkh, 32-byte key (needs 33, compressed point)",
                format!("did:pkh:p256:0x{}", h(64)),
            ),
            (
                "eip155 did:pkh, 19-byte address (needs 20)",
                format!("did:pkh:eip155:1:0x{}", h(38)),
            ),
            (
                "did:key with a corrupted multibase body (0/O/I/l chars)",
                "did:key:z6Mk0OIl0000CORRUPTEDMULTIBASE0000".to_string(),
            ),
        ]
    }

    /// Shapes the conformance table does not reach, added because this layer
    /// can see them: a `did:key` and a `did:peer` whose multibase body decodes
    /// cleanly under a known multicodec prefix but carries the wrong number of
    /// key bytes. Before this module nothing rejected these until
    /// `verify_with_key` tried to build a key out of them.
    fn malformed_multibase_lengths() -> Vec<(&'static str, String)> {
        let short_ed = {
            let mut b = crate::key::ED25519_PREFIX.to_vec();
            b.extend_from_slice(&[7u8; 31]);
            bs58::encode(&b).into_string()
        };
        let long_p256 = {
            let mut b = crate::key::P256_PREFIX.to_vec();
            b.extend_from_slice(&[2u8; 40]);
            bs58::encode(&b).into_string()
        };
        vec![
            (
                "did:key ed25519 multicodec wrapping 31 key bytes",
                format!("did:key:z{short_ed}"),
            ),
            (
                "did:peer variant 0 p256 multicodec wrapping 40 key bytes",
                format!("did:peer:0z{long_p256}"),
            ),
        ]
    }

    /// Every valid spelling SPEC section 3 lists, generated from real keys.
    /// The half of rule 5 that a verifier refusing everything would otherwise
    /// pass trivially.
    fn valid_spellings() -> Vec<(&'static str, String)> {
        use ed25519_dalek::SigningKey as EdKey;
        use rand::rngs::OsRng;

        let ed = EdKey::generate(&mut OsRng);
        let ed_pk = *ed.verifying_key().as_bytes();
        let p = p256::ecdsa::SigningKey::random(&mut OsRng);
        let p_compressed = p.verifying_key().to_encoded_point(true);
        let p_pk: [u8; 33] = p_compressed.as_bytes().try_into().unwrap();

        let peer_body = {
            let mut b = crate::key::ED25519_PREFIX.to_vec();
            b.extend_from_slice(&ed_pk);
            bs58::encode(&b).into_string()
        };

        vec![
            (
                "ed25519 did:key",
                crate::did::ed25519_did_key_from_pubkey(&ed_pk),
            ),
            (
                "ed25519 did:pkh",
                format!("did:pkh:ed25519:0x{}", hex::encode(ed_pk)),
            ),
            ("p256 did:key", crate::did::p256_did_key_from_pubkey(&p_pk)),
            (
                "p256 did:pkh",
                format!("did:pkh:p256:0x{}", hex::encode(p_pk)),
            ),
            (
                "eip155 did:pkh",
                format!("did:pkh:eip155:1:0x{}", hex::encode([0x42u8; 20])),
            ),
            (
                "ed25519 did:peer variant 0",
                format!("did:peer:0z{peer_body}"),
            ),
        ]
    }

    #[test]
    fn every_malformed_shape_is_refused_without_any_verification() {
        for (label, did) in malformed_shapes()
            .into_iter()
            .chain(malformed_multibase_lengths())
        {
            assert!(
                validate_did_well_formed(&did).is_err(),
                "rule 5 must refuse {label} ({did:?}) on its own, with no verifier involved"
            );
        }
    }

    #[test]
    fn every_valid_spelling_is_accepted() {
        for (label, did) in valid_spellings() {
            validate_did_well_formed(&did).unwrap_or_else(|e| {
                panic!("rule 5 wrongly refused the valid {label} {did:?}: {e}")
            });
        }
    }

    /// **The subset invariant.** Everything this layer refuses, the verification
    /// path also refuses on format grounds, so adding the layer can never reject
    /// a caller the crate used to accept. Asserted against the verifier directly
    /// rather than reasoned about: a garbage signature is supplied, and the
    /// verifier must still fail on the DID rather than return `Ok(false)`.
    #[test]
    fn everything_this_layer_refuses_the_verifier_also_refuses() {
        for (label, did) in malformed_shapes()
            .into_iter()
            .chain(malformed_multibase_lengths())
        {
            let method = match find_did_method(&did) {
                Some(m) => m,
                // Rule 4, not rule 5: no verifier exists to compare against.
                None => continue,
            };
            let verdict = method.verify(&did, "any message", &[0u8; 64]);
            assert!(
                verdict.is_err(),
                "{label} ({did:?}) is refused by rule 5 but the verifier returned {verdict:?}, \
                 which would mean this layer is stricter than verification and could refuse a \
                 legitimate caller"
            );
        }
    }

    /// The other direction of the same invariant: a valid DID that this layer
    /// accepts still verifies a real signature end to end, so the layer has not
    /// quietly become a gate on the happy path.
    #[test]
    fn a_valid_did_this_layer_accepts_still_verifies_a_real_signature() {
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;

        let key = SigningKey::generate(&mut OsRng);
        let did = crate::did::ed25519_did_key_from_pubkey(key.verifying_key().as_bytes());
        let msg = "aqua-node wants you to sign in";
        let sig = key.sign(msg.as_bytes());

        validate_did_well_formed(&did).expect("a freshly minted did:key must be well-formed");
        assert!(crate::key::KeyMethod
            .verify(&did, msg, &sig.to_bytes())
            .unwrap());
    }

    /// Rule 4 and rule 5 stay distinguishable by error variant, which is what
    /// lets a consumer map an unknown namespace and a malformed identifier onto
    /// different responses instead of collapsing both to one 401.
    #[test]
    fn an_unknown_method_and_a_malformed_identifier_are_different_errors() {
        assert!(matches!(
            validate_did_well_formed("did:madeupmethod:whatever"),
            Err(CryptoError::UnsupportedMethod(_))
        ));
        assert!(matches!(
            validate_did_well_formed("did:pkh:solana:0xabc"),
            Err(CryptoError::UnsupportedMethod(_))
        ));
        assert!(!matches!(
            validate_did_well_formed(&format!("did:pkh:ed25519:0x{}", "ab".repeat(31))),
            Err(CryptoError::UnsupportedMethod(_))
        ));
    }

    /// `did:aqua` is recognised only when its feature is on, and this layer
    /// inherits that from the registry rather than adding a second gate of its
    /// own. Both halves are asserted so the cross-build difference is recorded
    /// as intended behaviour rather than discovered later as a surprise.
    #[test]
    fn did_aqua_is_recognised_exactly_when_its_feature_is_on() {
        // 56 characters total, the shape `codec.rs` requires, but not a real
        // multihash: the point is which error comes back, not that it passes.
        let did = format!("did:aqua:z{}", "1".repeat(46));
        let verdict = validate_did_well_formed(&did);
        #[cfg(feature = "did-aqua")]
        assert!(
            !matches!(verdict, Err(CryptoError::UnsupportedMethod(_))),
            "with did-aqua on, the namespace is known and the body is judged on its merits: \
             {verdict:?}"
        );
        #[cfg(not(feature = "did-aqua"))]
        assert!(
            matches!(verdict, Err(CryptoError::UnsupportedMethod(_))),
            "with did-aqua off, the registry does not know the namespace at all: {verdict:?}"
        );
    }

    /// Layer 1 of the three: the challenge endpoint can no longer mint and
    /// store a nonce for an identity that is not representable. This is the
    /// five-of-seven finding, asserted directly.
    #[cfg(feature = "http")]
    #[test]
    fn the_challenge_store_refuses_every_malformed_shape() {
        let store = crate::ChallengeStore::new(300, "test".into(), "http://127.0.0.1:1".into());
        for (label, did) in malformed_shapes()
            .into_iter()
            .chain(malformed_multibase_lengths())
        {
            assert!(
                store.create(&did).is_err(),
                "the challenge store minted a nonce for {label} ({did:?}), which can never \
                 authenticate"
            );
        }
        assert_eq!(
            store.len(),
            0,
            "a refused challenge must leave no state behind in the store"
        );
    }

    /// Layer 1 must not have become a gate on real logins.
    #[cfg(feature = "http")]
    #[test]
    fn the_challenge_store_still_mints_for_every_valid_spelling() {
        let store = crate::ChallengeStore::new(300, "test".into(), "http://127.0.0.1:1".into());
        for (label, did) in valid_spellings() {
            store
                .create(&did)
                .unwrap_or_else(|e| panic!("challenge wrongly refused for {label} {did:?}: {e}"));
        }
    }

    /// Layer 3: the one path into a `Principal` that never verifies anything.
    #[test]
    fn from_trusted_did_refuses_every_malformed_shape() {
        for (label, did) in malformed_shapes()
            .into_iter()
            .chain(malformed_multibase_lengths())
        {
            assert!(
                crate::Principal::from_trusted_did(&did).is_err(),
                "a malformed DID became a Principal with no verification at all: {label} ({did:?})"
            );
        }
    }
}
