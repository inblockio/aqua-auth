//! `did:aqua` identifier construction and grammar validation (PCA-0017
//! Section 2.3).
//!
//! `did:aqua` is a content-addressed public-key-hash DID: the identifier
//! commits to a `(scheme, key)` pair through a multihash of a tagged
//! preimage, and carries no key material. It is the hash-of-key analogue of
//! `did:pkh`, generalized off the blockchain account namespace so an
//! arbitrarily large public key gets a fixed 56-character identity.
//!
//! ```text
//! tag    = varint(MLDSA_87_PUB_CODEC)   # 0x92 0x24
//! digest = SHA3-256(tag || pk)          # always SHA3-256
//! mh     = 0x16 || 0x20 || digest       # multihash: sha3-256, length 32
//! id     = "z" || base58btc(mh)
//! did    = "did:aqua:" || id
//! ```
//!
//! # Why this is reimplemented rather than imported
//!
//! The SDK owns the normative implementation in
//! `aqua_rs_sdk::primitives::did_aqua`. This crate deliberately depends on no
//! Aqua crate, so that an auth verifier never inherits the SDK's pin (ruling,
//! 2026-09-11). The cost is a second producer of an identity string, which is
//! the failure that cost a day on 2026-09-09, so the mitigation is that
//! [`tests::pca0017_section_5_1_vector`] pins this implementation to PCA-0017
//! Section 5.1's published vector byte-for-byte. If the two ever disagree,
//! that test fails here rather than a signature failing in production.
//!
//! The only structural deviation from the SDK: the SDK routes through its
//! general PCA-0015 `multihash_decode` and then checks the code and length,
//! whereas this module checks the 34-byte `0x16 0x20` header directly. For
//! the one construction PCA-0017 defines these are equivalent, because both
//! the code and the length are single-byte varints whose minimal encoding is
//! the byte itself, and the total length is fixed. A future `did:aqua`
//! construction (a new PCA) would need the general decoder.

use crate::crypto_error::CryptoError;
use sha3::{Digest, Sha3_256};

/// The `mldsa-87-pub` key-type multicodec code (PCA-0017 Section 2.3,
/// point 1). Pinned normatively by the PCA: if the upstream multiformats
/// registry ever renumbers it, this value still governs `did:aqua`.
pub const MLDSA_87_PUB_CODEC: u16 = 0x1212;

/// The unsigned-varint encoding of [`MLDSA_87_PUB_CODEC`], exactly two
/// bytes. A literal rather than a computed value so a general-purpose
/// varint encoder changing elsewhere cannot silently move every identity.
pub const MLDSA_87_PUB_CODEC_VARINT: [u8; 2] = [0x92, 0x24];

/// FIPS 204 ML-DSA-87 `pkEncode` length.
pub const ML_DSA_87_PUBLIC_KEY_BYTES: usize = 2592;

const DID_AQUA_PREFIX: &str = "did:aqua:";

/// `did:aqua:` (9) + `z` (1) + 46 base58btc characters. Constant, not
/// typical: the leading multihash byte is the fixed nonzero `0x16`, which
/// precludes base58 leading-`1` padding and pins the digit count for every
/// possible digest (PCA-0017 Section 2.3).
const DID_AQUA_LEN: usize = 56;

/// Multihash code `0x16` = sha3-256 (PCA-0015 Section 3.1).
const MULTIHASH_SHA3_256: u8 = 0x16;

/// Multihash digest length `0x20` = 32 bytes.
const MULTIHASH_DIGEST_LEN: u8 = 0x20;

/// 1 code byte + 1 length byte + 32 digest bytes.
const MULTIHASH_LEN: usize = 34;

/// Encode an ML-DSA-87 public key as its `did:aqua` identity.
///
/// The identity hash is always SHA3-256, independent of any revision hash
/// algorithm in force elsewhere (PCA-0017 Section 2.3, point 3).
///
/// `pubkey` is expected to be [`ML_DSA_87_PUBLIC_KEY_BYTES`] long. This
/// function does not enforce that, mirroring the SDK: callers building a
/// signer identity are responsible for the length, and
/// [`aqua_did_binds_pubkey`] is the checked entry point for verification.
pub fn aqua_did_from_pubkey(pubkey: &[u8]) -> String {
    let mut preimage = Vec::with_capacity(MLDSA_87_PUB_CODEC_VARINT.len() + pubkey.len());
    preimage.extend_from_slice(&MLDSA_87_PUB_CODEC_VARINT);
    preimage.extend_from_slice(pubkey);

    let digest = Sha3_256::digest(&preimage);

    let mut mh = Vec::with_capacity(MULTIHASH_LEN);
    mh.push(MULTIHASH_SHA3_256);
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
/// 6. the decoded bytes are 34 long with code `0x16` and length `0x20`
///
/// A `did:aqua` whose multihash carries any other code or length belongs to
/// no construction any PCA has defined and is rejected rather than accepted
/// as an opaque identity.
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

    let mh: [u8; MULTIHASH_LEN] = raw
        .as_slice()
        .try_into()
        .map_err(|_| bad("multihash is not 34 bytes"))?;

    if mh[0] != MULTIHASH_SHA3_256 {
        return Err(bad("wrong multihash code (expected 0x16 / sha3-256)"));
    }
    if mh[1] != MULTIHASH_DIGEST_LEN {
        return Err(bad("wrong digest length (expected 0x20 / 32 bytes)"));
    }

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

    /// PCA-0017 Section 5.1, verbatim. This is the contract between this
    /// crate and the SDK: both implementations independently reproduce this
    /// string or one of them is wrong.
    #[test]
    fn pca0017_section_5_1_vector() {
        let pk = vec![0u8; ML_DSA_87_PUBLIC_KEY_BYTES];

        let mut preimage = Vec::new();
        preimage.extend_from_slice(&MLDSA_87_PUB_CODEC_VARINT);
        preimage.extend_from_slice(&pk);
        assert_eq!(
            hex::encode(Sha3_256::digest(&preimage)),
            "bc43fdb14017ec9b095aaa7f5741a8de41be42253c6c4da23e965bea02a17a7a",
            "digest diverged from the PCA-0017 Section 5.1 vector"
        );

        let did = aqua_did_from_pubkey(&pk);
        assert_eq!(
            did, "did:aqua:zW1n7u1YcZFfZuNcDv5XBZc5npJAArkE7nrv7gv3NCstHJh",
            "did:aqua encoding diverged from the PCA-0017 Section 5.1 vector"
        );
        assert_eq!(did.len(), DID_AQUA_LEN);

        let mh = multihash_from_aqua_did(&did).expect("the published vector must validate");
        assert_eq!(
            hex::encode(mh),
            format!(
                "1620{}",
                "bc43fdb14017ec9b095aaa7f5741a8de41be42253c6c4da23e965bea02a17a7a"
            )
        );
    }

    /// The varint literal is consistent with the codec value it claims to
    /// encode, so the two constants cannot drift apart unnoticed.
    #[test]
    fn codec_varint_is_consistent_with_the_codec_value() {
        let [b0, b1] = MLDSA_87_PUB_CODEC_VARINT;
        assert_eq!(b0 & 0x80, 0x80, "first byte must set the continuation bit");
        assert_eq!(b1 & 0x80, 0, "second byte must be the final group");
        let decoded = (b0 & 0x7f) as u32 | (((b1 & 0x7f) as u32) << 7);
        assert_eq!(decoded, MLDSA_87_PUB_CODEC as u32);
    }

    #[test]
    fn encode_then_validate_round_trips() {
        let did = aqua_did_from_pubkey(&[0xab; ML_DSA_87_PUBLIC_KEY_BYTES]);
        let mh = multihash_from_aqua_did(&did).expect("round trip must validate");
        assert_eq!(mh[0], MULTIHASH_SHA3_256);
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

    /// The tag is what stops two schemes that share a key encoding from
    /// minting the same identity (PCA-0017 Section 2.3, point 2).
    #[test]
    fn the_codec_tag_is_part_of_the_preimage() {
        let pk = [3u8; ML_DSA_87_PUBLIC_KEY_BYTES];
        let untagged = Sha3_256::digest(pk);
        let mh = multihash_from_aqua_did(&aqua_did_from_pubkey(&pk)).unwrap();
        assert_ne!(&mh[2..], untagged.as_slice(), "identity must hash the tag");
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
        mh.extend_from_slice(&Sha3_256::digest([0u8; 8]));
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
