//! ML-DSA-87 (FIPS 204) verification for `did:aqua`, with PCA-0017 Section
//! 2.5's decode/verify split preserved.
//!
//! # Why the split matters here
//!
//! PCA-0017 Section 2.5 cuts the failure surface at FIPS 204's own
//! `sigDecode` / `Verify` boundary so that monolithic and split
//! implementations classify identically:
//!
//! - **malformed** is `sigDecode`'s structural failures only: wrong
//!   component lengths, and the canonical hint-encoding checks of
//!   `HintBitUnpack` (Algorithm 21).
//! - **invalid** is the entire `ML-DSA.Verify(pk, M, sig, ctx = "")`
//!   boolean, explicitly including the `z` infinity-norm bound, which FIPS
//!   204 computes inside Verify rather than inside `sigDecode`.
//!
//! This crate expresses the split with its existing convention, the same one
//! [`crate::key::Ed25519Suite`] uses: a malformed input is `Err`, a
//! well-formed input that does not verify is `Ok(false)`.
//!
//! # The ported hint gate (required, not an optimisation)
//!
//! RustCrypto `ml-dsa` 0.1.1's `Signature::decode` implements Algorithm 21
//! in full, but it also folds in `if z.infinity_norm() >= GAMMA1_MINUS_BETA
//! { return None }`, which PCA-0017 pins as a verify-stage conjunct. Using
//! `decode` as the malformed gate would therefore re-bucket every
//! out-of-range-`z` signature from invalid to malformed, which is precisely
//! the cross-implementation divergence the split exists to close.
//! `Hint::bit_unpack` is `pub(crate)` upstream, so the gate cannot be called
//! in isolation.
//!
//! [`hint_encoding_is_canonical`] below is therefore a faithful port of the
//! SDK's `core::signature::ml_dsa::hint_encoding_is_canonical`, reproducing
//! Algorithm 21's failure set exactly over the trailing 83 hint bytes. It
//! runs as the malformed gate; `Signature::decode` is called only afterwards,
//! for the algebra, at which point a `None` can only be the `z` bound and is
//! routed to the invalid class.
//!
//! Porting rather than importing follows the ruling that this crate depends
//! on no Aqua crate (2026-09-11). The two implementations must not diverge,
//! so both are pinned to the same `ml-dsa` version and the gate is covered by
//! the tests below.

use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa87, Signature, VerifyingKey};

use crate::crypto_error::CryptoError;

/// FIPS 204 ML-DSA-87 `sigEncode` length.
pub const ML_DSA_87_SIGNATURE_BYTES: usize = 4627;

/// ML-DSA-87 `omega`: the maximum total number of hint bits (FIPS 204 Table 1).
const OMEGA: usize = 75;

/// ML-DSA-87 `k`: the number of polynomials in the hint vector.
const K: usize = 8;

/// Offset of the `sigEncode` hint region. The layout is fixed-width:
/// `c_tilde` (64 bytes) then the packed `z` (4480 bytes), so the hint region
/// is always `[4544, 4627)`.
const HINT_OFFSET: usize = ML_DSA_87_SIGNATURE_BYTES - (OMEGA + K);

/// Why a signature failed the V4-decode gate. Every variant is the
/// **malformed** class (PCA-0017 Section 2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HintDefect {
    /// A per-polynomial cumulative hint-count byte is less than the running
    /// total (the counts are not monotone non-decreasing).
    CumulativeCountNotMonotone,
    /// A cumulative hint-count byte exceeds `omega`.
    CumulativeCountAboveOmega,
    /// Hint indices are not strictly increasing within one polynomial's range.
    IndicesNotStrictlyIncreasing,
    /// An unused hint byte (beyond the last cumulative count) is non-zero.
    UnusedHintByteNonZero,
}

impl std::fmt::Display for HintDefect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::CumulativeCountNotMonotone => "cumulative hint counts are not monotone",
            Self::CumulativeCountAboveOmega => "a cumulative hint count exceeds omega",
            Self::IndicesNotStrictlyIncreasing => {
                "hint indices are not strictly increasing within a polynomial"
            }
            Self::UnusedHintByteNonZero => "an unused hint byte is non-zero",
        };
        f.write_str(s)
    }
}

/// FIPS 204 Algorithm 21 `HintBitUnpack`, as a pure acceptance predicate over
/// the 4627-byte `sigEncode` encoding.
///
/// The rejection set is exactly the set of inputs on which Algorithm 21
/// returns failure. Implementing a subset (omitting the cumulative-count
/// gate, say) moves those inputs from the malformed class to the invalid
/// class, which PCA-0017 Section 2.5 forbids.
///
/// Bounded: two passes over 83 bytes, no allocation, no recursion.
pub fn hint_encoding_is_canonical(sig: &[u8; ML_DSA_87_SIGNATURE_BYTES]) -> Result<(), HintDefect> {
    let hint = &sig[HINT_OFFSET..];
    debug_assert_eq!(hint.len(), OMEGA + K);
    let indices = &hint[..OMEGA];
    let cuts = &hint[OMEGA..];

    // Gates 1 and 2: cumulative counts are monotone non-decreasing and never
    // exceed omega. `cuts` has exactly K entries, so the walk is bounded.
    let mut running = 0usize;
    for &cut in cuts {
        let cut = usize::from(cut);
        if cut < running {
            return Err(HintDefect::CumulativeCountNotMonotone);
        }
        if cut > OMEGA {
            return Err(HintDefect::CumulativeCountAboveOmega);
        }
        running = cut;
    }
    // `running` is now the last (maximum) cut, the total hint count.
    let max_cut = running;

    // Gate 3: every unused index byte is zero.
    if indices[max_cut..].iter().any(|&b| b != 0) {
        return Err(HintDefect::UnusedHintByteNonZero);
    }

    // Gate 4: indices strictly increase within each polynomial's range.
    let mut start = 0usize;
    for &cut in cuts {
        let end = usize::from(cut);
        let window = &indices[start..end];
        if window.windows(2).any(|w| w[0] >= w[1]) {
            return Err(HintDefect::IndicesNotStrictlyIncreasing);
        }
        start = end;
    }

    Ok(())
}

/// Verify an ML-DSA-87 signature over `message` under `public_key`.
///
/// Runs the PCA-0017 Section 2.5 pipeline in order:
///
/// 1. length checks on the key and signature (V2 and V4-decode structural)
/// 2. [`hint_encoding_is_canonical`] (the rest of V4-decode)
/// 3. `ML-DSA.Verify(pk, M, sig, ctx = "")` over the external interface with
///    the empty context string
///
/// `Err` is the malformed class: the caller sent something that is not an
/// ML-DSA-87 signature at all. `Ok(false)` is the invalid class: a
/// well-formed signature that does not verify, which includes the `z`
/// infinity-norm bound.
///
/// `VerifyingKey::decode` is total on 2592-byte input (FIPS 204 Algorithm
/// 23), which is why step 1 is a length check and nothing more.
pub fn verify(public_key: &[u8], signature: &[u8], message: &[u8]) -> Result<bool, CryptoError> {
    let pk: &[u8; super::codec::ML_DSA_87_PUBLIC_KEY_BYTES] =
        public_key.try_into().map_err(|_| {
            CryptoError::InvalidSignature(format!(
                "ML-DSA-87 public key must be {} bytes, got {}",
                super::codec::ML_DSA_87_PUBLIC_KEY_BYTES,
                public_key.len()
            ))
        })?;

    let sig: &[u8; ML_DSA_87_SIGNATURE_BYTES] = signature.try_into().map_err(|_| {
        CryptoError::InvalidSignature(format!(
            "ML-DSA-87 signature must be {ML_DSA_87_SIGNATURE_BYTES} bytes, got {}",
            signature.len()
        ))
    })?;

    hint_encoding_is_canonical(sig)
        .map_err(|d| CryptoError::InvalidSignature(format!("ML-DSA-87 hint encoding: {d}")))?;

    let vk = VerifyingKey::<MlDsa87>::decode(&EncodedVerifyingKey::<MlDsa87>::from(*pk));

    let Some(decoded) = Signature::<MlDsa87>::decode(&EncodedSignature::<MlDsa87>::from(*sig))
    else {
        // Past the hint gate the only remaining decode rejection is the `z`
        // infinity-norm bound, a verify-stage conjunct: invalid, not
        // malformed.
        return Ok(false);
    };

    Ok(vk.verify_with_context(message, b"", &decoded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::{KeyInit, Keypair, MlDsa87, SigningKey};

    /// Seed-derived rather than random, matching the SDK's own test idiom
    /// (`core::signature::ml_dsa::fixed_keypair`), so every case here is
    /// reproducible byte-for-byte.
    fn keypair(seed: u8) -> (SigningKey<MlDsa87>, Vec<u8>) {
        let sk = SigningKey::<MlDsa87>::new(&[seed; 32].into());
        let pk = Keypair::verifying_key(&sk).encode().as_slice().to_vec();
        (sk, pk)
    }

    fn sign(sk: &SigningKey<MlDsa87>, msg: &[u8]) -> Vec<u8> {
        use ml_dsa::signature::Signer as _;
        sk.sign(msg).encode().as_slice().to_vec()
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let (sk, pk) = keypair(1);
        let msg = b"hello did:aqua";
        assert!(verify(&pk, &sign(&sk, msg), msg).unwrap());
    }

    #[test]
    fn a_different_message_does_not_verify() {
        let (sk, pk) = keypair(2);
        assert!(!verify(&pk, &sign(&sk, b"one"), b"two").unwrap());
    }

    #[test]
    fn a_different_key_does_not_verify() {
        let (sk, _) = keypair(3);
        let (_, other_pk) = keypair(4);
        assert!(!verify(&other_pk, &sign(&sk, b"m"), b"m").unwrap());
    }

    /// Wrong lengths are malformed (`Err`), never a silent false.
    #[test]
    fn wrong_lengths_are_malformed_not_invalid() {
        let (_, pk) = keypair(5);
        assert!(verify(&pk, &[0u8; 64], b"m").is_err(), "short signature");
        assert!(
            verify(&[0u8; 32], &[0u8; ML_DSA_87_SIGNATURE_BYTES], b"m").is_err(),
            "short key"
        );
    }

    /// A real signature whose hint region is corrupted must be rejected by
    /// the gate as malformed, not fall through to the verify stage.
    #[test]
    fn corrupted_hint_region_is_malformed() {
        let (sk, pk) = keypair(6);
        let mut sig = sign(&sk, b"m");
        // Force a non-monotone cumulative count: the last cut byte is the
        // running total, so setting the first cut above it breaks gate 1.
        sig[HINT_OFFSET + OMEGA] = 0xff;
        let err = verify(&pk, &sig, b"m").unwrap_err().to_string();
        assert!(err.contains("hint encoding"), "got: {err}");
    }

    #[test]
    fn gate_rejects_count_above_omega() {
        let mut sig = [0u8; ML_DSA_87_SIGNATURE_BYTES];
        sig[HINT_OFFSET + OMEGA] = (OMEGA + 1) as u8;
        assert_eq!(
            hint_encoding_is_canonical(&sig),
            Err(HintDefect::CumulativeCountAboveOmega)
        );
    }

    #[test]
    fn gate_rejects_non_monotone_counts() {
        let mut sig = [0u8; ML_DSA_87_SIGNATURE_BYTES];
        sig[HINT_OFFSET + OMEGA] = 5;
        sig[HINT_OFFSET + OMEGA + 1] = 4;
        // Indices must be strictly increasing for the first window so the
        // monotone gate is what fires.
        for i in 0..5 {
            sig[HINT_OFFSET + i] = i as u8;
        }
        assert_eq!(
            hint_encoding_is_canonical(&sig),
            Err(HintDefect::CumulativeCountNotMonotone)
        );
    }

    #[test]
    fn gate_rejects_non_zero_unused_index_bytes() {
        let mut sig = [0u8; ML_DSA_87_SIGNATURE_BYTES];
        // All cuts zero, so every index byte is unused.
        sig[HINT_OFFSET] = 1;
        assert_eq!(
            hint_encoding_is_canonical(&sig),
            Err(HintDefect::UnusedHintByteNonZero)
        );
    }

    #[test]
    fn gate_rejects_non_increasing_indices() {
        let mut sig = [0u8; ML_DSA_87_SIGNATURE_BYTES];
        // One polynomial holding two hints, indices equal rather than rising.
        for c in 0..K {
            sig[HINT_OFFSET + OMEGA + c] = 2;
        }
        sig[HINT_OFFSET] = 7;
        sig[HINT_OFFSET + 1] = 7;
        assert_eq!(
            hint_encoding_is_canonical(&sig),
            Err(HintDefect::IndicesNotStrictlyIncreasing)
        );
    }

    /// An all-zero hint region is canonical: no hints set, nothing unused
    /// that is non-zero, no ordering to violate.
    #[test]
    fn gate_accepts_an_empty_hint_region() {
        let sig = [0u8; ML_DSA_87_SIGNATURE_BYTES];
        assert_eq!(hint_encoding_is_canonical(&sig), Ok(()));
    }

    /// Every signature this crate's own signer produces passes the gate. If
    /// the port were stricter than Algorithm 21, valid traffic would break.
    #[test]
    fn genuine_signatures_always_pass_the_gate() {
        let (sk, _) = keypair(7);
        for i in 0..8u8 {
            let sig = sign(&sk, &[i; 32]);
            let arr: &[u8; ML_DSA_87_SIGNATURE_BYTES] = sig.as_slice().try_into().unwrap();
            assert_eq!(hint_encoding_is_canonical(arr), Ok(()), "iteration {i}");
        }
    }
}
