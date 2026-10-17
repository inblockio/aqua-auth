//! `did:aqua` identifier construction and grammar validation (PCA-0017
//! v0.11.0 Section 2.3).
//!
//! `did:aqua` is a content-addressed public-key-hash DID: the identifier is
//! the RFC 7638 JWK Thumbprint (SHA-256) of the RFC 9964 AKP form of the
//! key, wrapped as a multihash. It commits to a `(scheme, key)` pair and
//! carries no key material. It is the hash-of-key analogue of `did:pkh`,
//! generalized off the blockchain account namespace so an arbitrarily large
//! public key gets a fixed 56-character identity.
//!
//! ```text
//! jwk    = '{"alg":"ML-DSA-87","kty":"AKP","pub":"' + base64url_nopad(pk) + '"}'
//!          # members in lexicographic order, no whitespace; pk = the
//!          # 2592-byte FIPS 204 pkEncode
//! digest = SHA-256(UTF-8 bytes of jwk)    # the RFC 7638 thumbprint
//! mh     = 0x12 || 0x20 || digest         # multihash: sha2-256, length 32
//! id     = "z" || base58btc(mh)
//! did    = "did:aqua:" || id
//! ```
//!
//! The scheme is bound by `kty` and `alg` inside the hashed JSON, so no
//! separate multicodec tag enters the preimage. Two schemes that shared a
//! key encoding would still mint different identities, because their `alg`
//! members differ.
//!
//! # Why this is reimplemented rather than imported
//!
//! The SDK owns the normative implementation in
//! `aqua_rs_sdk::primitives::did_aqua`. This crate deliberately depends on no
//! Aqua crate, so that an auth verifier never inherits the SDK's pin (ruling,
//! 2026-09-11). The cost is a second producer of an identity string, which is
//! the failure that cost a day on 2026-09-09, so the mitigation is that the
//! known-answer vectors in this module's tests (the all-zero key, the NIST ACVP
//! ML-DSA-87 `sigGen` key and a key generated from a fixed seed) pin this
//! implementation byte-for-byte to the values the SDK produces and to an
//! independent Python and OpenSSL reference. If the two ever disagree, those
//! tests fail here rather than a signature failing in production.
//!
//! The one remaining difference from the SDK's source is shape, not
//! behaviour: this module checks the fixed 34-byte `0x12 0x20` header
//! directly, and the SDK now does the same rather than going through its
//! general PCA-0015 `multihash_decode`. For the one construction PCA-0017
//! defines the direct check is exact, because both the code and the length
//! are single-byte varints whose minimal encoding is the byte itself, and the
//! total length is fixed. A future `did:aqua` construction (a new PCA) would
//! need a general multihash decoder.

use crate::crypto_error::CryptoError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

/// FIPS 204 ML-DSA-87 `pkEncode` length.
pub const ML_DSA_87_PUBLIC_KEY_BYTES: usize = 2592;

const DID_AQUA_PREFIX: &str = "did:aqua:";

/// `did:aqua:` (9) + `z` (1) + 46 base58btc characters. Constant, not
/// typical: the leading multihash byte is the fixed nonzero `0x12`, which
/// precludes base58 leading-`1` padding and pins the digit count for every
/// possible digest, so the body always starts `zQm` (PCA-0017 Section 2.3).
const DID_AQUA_LEN: usize = 56;

/// Multihash code `0x12` = sha2-256, the RFC 7638 thumbprint hash.
const MULTIHASH_SHA2_256: u8 = 0x12;

/// Multihash digest length `0x20` = 32 bytes.
const MULTIHASH_DIGEST_LEN: u8 = 0x20;

/// 1 code byte + 1 length byte + 32 digest bytes.
const MULTIHASH_LEN: usize = 34;

/// Encode an ML-DSA-87 public key as its `did:aqua` identity.
///
/// The identity is the RFC 7638 JWK Thumbprint (SHA-256) of the RFC 9964
/// AKP key, as a sha2-256 multihash (PCA-0017 v0.11.0 Section 2.3). The JSON
/// is built by hand rather than serialized: RFC 7638 fixes the exact bytes
/// (members in lexicographic order, no whitespace), and a serializer's
/// formatting choices must not be able to move an identity.
///
/// `pubkey` is expected to be [`ML_DSA_87_PUBLIC_KEY_BYTES`] long. This
/// function does not enforce that, mirroring the SDK: callers building a
/// signer identity are responsible for the length, and
/// [`aqua_did_binds_pubkey`] is the checked entry point for verification.
pub fn aqua_did_from_pubkey(pubkey: &[u8]) -> String {
    let jwk = format!(
        r#"{{"alg":"ML-DSA-87","kty":"AKP","pub":"{}"}}"#,
        URL_SAFE_NO_PAD.encode(pubkey)
    );

    let digest = Sha256::digest(jwk.as_bytes());

    let mut mh = Vec::with_capacity(MULTIHASH_LEN);
    mh.push(MULTIHASH_SHA2_256);
    mh.push(MULTIHASH_DIGEST_LEN);
    mh.extend_from_slice(&digest);

    format!("did:aqua:z{}", bs58::encode(&mh).into_string())
}

/// Validate a `did:aqua` string against PCA-0017 Section 2.3's grammar and
/// multihash discipline, returning the decoded 34-byte multihash.
///
/// Checks run in the same order as the SDK's `did_aqua::validate`, so a
/// string rejected by one is rejected by the other for the same reason:
///
/// 1. no forbidden DID component (`/`, `?`, `#`, `;`)
/// 2. total length is exactly 56 characters
/// 3. the literal `did:aqua:` prefix
/// 4. the identifier begins with the single multibase prefix `z`
/// 5. the remainder decodes as base58btc
/// 6. the decoded bytes begin with the multihash code `0x12` (sha2-256),
///    then the length byte `0x20`, and are exactly 34 bytes long
///
/// The code is checked first, so an identity in the superseded format (a
/// `0x16` sha3-256 multihash over a tagged preimage) is refused with an
/// error that names the expected code. A `did:aqua` whose multihash carries
/// any other code or length belongs to no construction any PCA has defined
/// and is rejected rather than accepted as an opaque identity.
pub fn multihash_from_aqua_did(did: &str) -> Result<[u8; MULTIHASH_LEN], CryptoError> {
    let bad = |why: &str| CryptoError::InvalidDid(format!("did:aqua: {why}"));

    if did.contains(['/', '?', '#', ';']) {
        return Err(bad(
            "forbidden component (path, query, fragment or parameter)",
        ));
    }

    if did.len() != DID_AQUA_LEN {
        return Err(bad(&format!(
            "wrong total length (expected {DID_AQUA_LEN} characters, got {})",
            did.len()
        )));
    }

    let rest = did
        .strip_prefix(DID_AQUA_PREFIX)
        .ok_or_else(|| bad("missing or incorrect \"did:aqua:\" prefix"))?;

    let body = rest
        .strip_prefix('z')
        .ok_or_else(|| bad("missing or wrong multibase prefix (expected 'z')"))?;

    let raw = bs58::decode(body)
        .into_vec()
        .map_err(|_| bad("non-base58btc characters or decode failure"))?;

    // Code first, then length byte, then total length: an old-format
    // `0x16` body must fail on the code, whatever else is true of it.
    if raw.first() != Some(&MULTIHASH_SHA2_256) {
        return Err(bad(
            "wrong multihash code (expected 0x12 / sha2-256, the RFC 7638 thumbprint hash)",
        ));
    }
    if raw.get(1) != Some(&MULTIHASH_DIGEST_LEN) {
        return Err(bad("wrong digest length (expected 0x20 / 32 bytes)"));
    }
    // With a leading `0x12` and a 46-character body this cannot fail (a
    // 33-byte value that long needs a first byte of at least 0xC2, and a
    // 35-byte one needs 47 characters), so it is a guard against the
    // grammar checks above ever being loosened, not a reachable path.
    let mh: [u8; MULTIHASH_LEN] = raw
        .as_slice()
        .try_into()
        .map_err(|_| bad("multihash is not 34 bytes"))?;

    Ok(mh)
}

/// The V3 co-located-key binding: does `did` commit to `pubkey`?
///
/// This is the check that makes every `did:aqua` transport trustless. The
/// public key arrives out of band (on the wire, from a store, from a
/// resolver) and is worthless until it is bound back to the identity that
/// claimed it. Because the DID is a hash of the key, a caller cannot pair a
/// key it holds with a DID it does not own, so no registration authority
/// and no anti-squatting rule is required anywhere.
///
/// Returns `Err` when `did` is not a well-formed `did:aqua` at all, and
/// `Ok(false)` when it is well formed but commits to a different key. The
/// split matters: the first is a malformed request, the second is a failed
/// authentication.
///
/// Comparison is byte-for-byte over the recomputed multihash. Equality of
/// `did:aqua` strings is likewise byte-for-byte and case-sensitive
/// (PCA-0017 Section 2.3); base58btc is case-sensitive by construction, so
/// any case folding here would admit two distinct identities as one.
pub fn aqua_did_binds_pubkey(did: &str, pubkey: &[u8]) -> Result<bool, CryptoError> {
    let claimed = multihash_from_aqua_did(did)?;
    let derived = multihash_from_aqua_did(&aqua_did_from_pubkey(pubkey))?;
    Ok(claimed == derived)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer vector 1, the all-zero key. The expected values come
    /// from an independent Python (stdlib) and OpenSSL 3.5 reference, not
    /// from this implementation, and the SDK reproduces them too: both
    /// implementations produce this string or one of them is wrong.
    #[test]
    fn known_answer_zero_key() {
        let pk = vec![0u8; ML_DSA_87_PUBLIC_KEY_BYTES];

        // The hashed JSON is 3496 bytes: a 38-byte opening, 3456 base64url
        // characters for 2592 bytes (no padding) and the 2-byte closing `"}`.
        let jwk = format!(
            r#"{{"alg":"ML-DSA-87","kty":"AKP","pub":"{}"}}"#,
            URL_SAFE_NO_PAD.encode(&pk)
        );
        assert_eq!(jwk.len(), 3496, "RFC 7638 preimage length diverged");

        assert_eq!(
            hex::encode(Sha256::digest(jwk.as_bytes())),
            "98979630d849dd49b51db9521352802c7376eceb9910c02a5644aea316fdb683",
            "RFC 7638 thumbprint diverged from the reference"
        );

        let did = aqua_did_from_pubkey(&pk);
        assert_eq!(
            did, "did:aqua:zQmYcJk5pSrCsbnVeghcVhcQsjcwLgJ96Pd63pcuDxS1ikJ",
            "did:aqua encoding diverged from the reference"
        );
        assert_eq!(did.len(), DID_AQUA_LEN);
        assert!(
            did.starts_with("did:aqua:zQm"),
            "the body always starts zQm"
        );

        let mh = multihash_from_aqua_did(&did).expect("the reference vector must validate");
        assert_eq!(
            hex::encode(mh),
            "122098979630d849dd49b51db9521352802c7376eceb9910c02a5644aea316fdb683"
        );
    }

    /// Known-answer vector 2, a real ML-DSA-87 public key: the one in NIST
    /// ACVP `sigGen` test case 63 (ACVP-Server, ML-DSA-87, external
    /// interface). The thumbprint is also given in its RFC 7638 text form.
    #[test]
    fn known_answer_nist_acvp_sig_gen_tc63_key() {
        let pk = hex::decode(
            include_str!("../../tests/vectors/acvp-ml-dsa-87-sigGen-tc63-pk.hex").trim(),
        )
        .expect("fixture is hex");
        assert_eq!(pk.len(), ML_DSA_87_PUBLIC_KEY_BYTES);

        let jwk = format!(
            r#"{{"alg":"ML-DSA-87","kty":"AKP","pub":"{}"}}"#,
            URL_SAFE_NO_PAD.encode(&pk)
        );
        let thumbprint = Sha256::digest(jwk.as_bytes());
        assert_eq!(
            hex::encode(thumbprint),
            "c1cc661d694174111647b7841859b1a9d1c35caf7b4cef9953cfbc1ce4d84663"
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(thumbprint),
            "wcxmHWlBdBEWR7eEGFmxqdHDXK97TO-ZU8-8HOTYRmM",
            "RFC 7638 base64url thumbprint diverged"
        );
        assert_eq!(
            aqua_did_from_pubkey(&pk),
            "did:aqua:zQmbPAAckcZZXF8hXB87MvjR3LRCDjJPkxe8gqK2ZBYSYsU"
        );
    }

    /// Known-answer vector 3, ML-DSA-87 KeyGen from the 32-byte seed
    /// `00 01 02 ... 1f`. The public key is first pinned by its SHA3-256 so
    /// a KeyGen difference cannot be mistaken for a derivation difference.
    #[test]
    fn known_answer_keygen_from_seed() {
        use ml_dsa::KeyInit;
        use sha3::{Digest as _, Sha3_256};

        let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
        let key = ml_dsa::SigningKey::<ml_dsa::MlDsa87>::new(&seed.into());
        let pk = ml_dsa::Keypair::verifying_key(&key)
            .encode()
            .as_slice()
            .to_vec();

        assert_eq!(pk.len(), ML_DSA_87_PUBLIC_KEY_BYTES);
        assert_eq!(
            hex::encode(Sha3_256::digest(&pk)),
            "e6cf50a9c2fa5234f59949ff61f8161db4d629532127f4aefa8bb10811ecfb1e",
            "KeyGen produced a different public key; this is not a derivation failure"
        );
        assert_eq!(
            aqua_did_from_pubkey(&pk),
            "did:aqua:zQmYbHLs8G7uDZZuPAT62wWott6mN7XTi1cDchj9xJPMTTZ"
        );
    }

    /// The superseded construction (SHA3-256 over a tagged preimage, code
    /// `0x16`) must be refused outright, and refused on the code, so a
    /// consumer who still holds an old identity learns what changed.
    #[test]
    fn the_superseded_zero_key_identity_is_rejected_on_the_code() {
        let old = "did:aqua:zW1n7u1YcZFfZuNcDv5XBZc5npJAArkE7nrv7gv3NCstHJh";
        assert_eq!(old.len(), DID_AQUA_LEN, "fixture must pass the length gate");
        let err = multihash_from_aqua_did(old).unwrap_err().to_string();
        assert!(err.contains("wrong multihash code"), "got: {err}");
        assert!(err.contains("0x12"), "must name the expected code: {err}");
        assert!(
            err.contains("sha2-256"),
            "must name the expected hash: {err}"
        );
        assert!(
            aqua_did_binds_pubkey(old, &[0u8; ML_DSA_87_PUBLIC_KEY_BYTES]).is_err(),
            "binding must not treat an old-format identity as merely unequal"
        );
    }

    /// A `0x12` code with any length byte other than `0x20` is refused,
    /// even when the total is still 34 bytes (and so 56 characters).
    #[test]
    fn a_0x12_body_with_a_wrong_length_byte_is_rejected() {
        let mut mh = vec![0x12, 0x1f];
        mh.extend_from_slice(&Sha256::digest([0u8; 8]));
        let s = format!("did:aqua:z{}", bs58::encode(&mh).into_string());
        assert_eq!(s.len(), DID_AQUA_LEN, "fixture must stay 56 characters");
        let err = multihash_from_aqua_did(&s).unwrap_err().to_string();
        assert!(err.contains("wrong digest length"), "got: {err}");
    }

    #[test]
    fn encode_then_validate_round_trips() {
        let did = aqua_did_from_pubkey(&[0xab; ML_DSA_87_PUBLIC_KEY_BYTES]);
        let mh = multihash_from_aqua_did(&did).expect("round trip must validate");
        assert_eq!(mh[0], MULTIHASH_SHA2_256);
        assert_eq!(mh[1], MULTIHASH_DIGEST_LEN);
    }

    /// Every identity is 56 characters whatever the key hashes to. The
    /// length gate is only a valid sanity bound if this holds.
    #[test]
    fn every_identity_is_exactly_56_characters() {
        for seed in 0u8..64 {
            let did = aqua_did_from_pubkey(&[seed; ML_DSA_87_PUBLIC_KEY_BYTES]);
            assert_eq!(did.len(), DID_AQUA_LEN, "{did} is not 56 characters");
        }
    }

    #[test]
    fn binding_accepts_the_matching_key_and_rejects_every_other() {
        let pk = [1u8; ML_DSA_87_PUBLIC_KEY_BYTES];
        let did = aqua_did_from_pubkey(&pk);
        assert!(aqua_did_binds_pubkey(&did, &pk).unwrap());
        assert!(!aqua_did_binds_pubkey(&did, &[2u8; ML_DSA_87_PUBLIC_KEY_BYTES]).unwrap());
    }

    /// A key one byte different produces a different identity. Without this
    /// the binding check would be decorative.
    #[test]
    fn a_single_flipped_byte_changes_the_identity() {
        let mut pk = [0u8; ML_DSA_87_PUBLIC_KEY_BYTES];
        let a = aqua_did_from_pubkey(&pk);
        pk[ML_DSA_87_PUBLIC_KEY_BYTES - 1] = 1;
        assert_ne!(a, aqua_did_from_pubkey(&pk));
    }

    /// The identity is the thumbprint of the AKP JSON, not a bare hash of
    /// the key: `kty` and `alg` inside the hashed bytes are what bind the
    /// scheme, so a hash over the raw key alone must not reproduce it.
    #[test]
    fn the_scheme_members_are_part_of_the_preimage() {
        let pk = [3u8; ML_DSA_87_PUBLIC_KEY_BYTES];
        let bare = Sha256::digest(pk);
        let mh = multihash_from_aqua_did(&aqua_did_from_pubkey(&pk)).unwrap();
        assert_ne!(&mh[2..], bare.as_slice(), "identity must hash the AKP JSON");
    }

    #[test]
    fn reject_wrong_length() {
        let did = aqua_did_from_pubkey(&[0u8; ML_DSA_87_PUBLIC_KEY_BYTES]);
        assert!(multihash_from_aqua_did(&did[..did.len() - 1]).is_err());
        assert!(multihash_from_aqua_did(&format!("{did}1")).is_err());
    }

    #[test]
    fn reject_forbidden_components() {
        let did = aqua_did_from_pubkey(&[0u8; ML_DSA_87_PUBLIC_KEY_BYTES]);
        for bad in ['/', '?', '#', ';'] {
            // Replace rather than append, so this exercises the component
            // check and not the length check.
            let mut s = did.clone();
            s.pop();
            s.push(bad);
            let err = multihash_from_aqua_did(&s).unwrap_err().to_string();
            assert!(err.contains("forbidden component"), "got: {err}");
        }
    }

    #[test]
    fn reject_wrong_method_prefix() {
        // 56 characters, but did:key rather than did:aqua.
        let s = format!("did:key:zz{}", "1".repeat(46));
        assert_eq!(s.len(), DID_AQUA_LEN);
        assert!(multihash_from_aqua_did(&s).is_err());
    }

    #[test]
    fn reject_missing_multibase_prefix() {
        let did = aqua_did_from_pubkey(&[0u8; ML_DSA_87_PUBLIC_KEY_BYTES]);
        let s = format!("did:aqua:q{}", &did[10..]);
        assert_eq!(s.len(), DID_AQUA_LEN);
        let err = multihash_from_aqua_did(&s).unwrap_err().to_string();
        assert!(err.contains("multibase prefix"), "got: {err}");
    }

    #[test]
    fn reject_non_base58_characters() {
        let did = aqua_did_from_pubkey(&[0u8; ML_DSA_87_PUBLIC_KEY_BYTES]);
        // 0, O, I and l are all outside the base58btc alphabet.
        for bad in ['0', 'O', 'I', 'l'] {
            let mut s = did.clone();
            s.pop();
            s.push(bad);
            let err = multihash_from_aqua_did(&s).unwrap_err().to_string();
            assert!(err.contains("base58btc"), "got: {err}");
        }
    }

    #[test]
    fn reject_wrong_multihash_code() {
        // blake3-256 (0x1e) is a registered code and a well-formed
        // multihash, so this must be rejected for the code specifically.
        let mut mh = vec![0x1e, 0x20];
        mh.extend_from_slice(&Sha256::digest([0u8; 8]));
        let s = format!("did:aqua:z{}", bs58::encode(&mh).into_string());
        assert_eq!(s.len(), DID_AQUA_LEN, "fixture must stay 56 characters");
        let err = multihash_from_aqua_did(&s).unwrap_err().to_string();
        assert!(err.contains("wrong multihash code"), "got: {err}");
    }

    /// Case folding would admit two distinct identities as one. base58btc
    /// is case-sensitive by construction and PCA-0017 forbids folding.
    #[test]
    fn identity_comparison_is_case_sensitive() {
        let did = aqua_did_from_pubkey(&[0u8; ML_DSA_87_PUBLIC_KEY_BYTES]);
        let idx = "did:aqua:z".len();
        let c = did[idx..].chars().next().unwrap();
        let flipped = if c.is_ascii_lowercase() {
            c.to_ascii_uppercase()
        } else {
            c.to_ascii_lowercase()
        };
        let other = format!("{}{}{}", &did[..idx], flipped, &did[idx + 1..]);

        assert_ne!(did, other);
        // The case variant is a different string, and it must not validate
        // into the same identity. base58's avalanche makes it overwhelmingly
        // likely to break the multihash structure outright.
        match multihash_from_aqua_did(&other) {
            Err(_) => {}
            Ok(mh) => assert_ne!(
                mh,
                multihash_from_aqua_did(&did).unwrap(),
                "a case variant must never resolve to the same identity"
            ),
        }
    }
}
