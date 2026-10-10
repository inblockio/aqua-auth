//! Candidate selection: which of the two keys a verified assertion recovers
//! made the signature.
//!
//! [`RecoveredAssertion::select`] decides in a fixed order:
//!
//! 1. **Hint.** A [`DidHint`] (the `aqua_did_hint` cookie, or the key hint a
//!    sign-up sends) that names exactly one candidate selects it.
//! 2. **Known principal.** Otherwise, if exactly one candidate is a principal
//!    the service already knows (the consumer precomputes `known`), it is
//!    selected.
//! 3. **Second assertion.** Otherwise nothing is guessed: the consumer asks
//!    for a second assertion by the same credential (`allowCredentials =
//!    [rawId]`, fresh challenge) and [`PendingRecovery::resolve`] keeps the
//!    one key both assertions recover.
//!
//! Every path ends on a key the signature verifies under, because both
//! candidates are such keys. A hint therefore only picks between keys the
//! user's own signature already narrowed down to two: a wrong or tossed hint
//! cannot select another identity, at worst it forces step 2 or 3.

use crate::crypto_error::CryptoError;
use crate::did::p256_did_key_from_pubkey;
use crate::key::p256_pubkey_from_did_key;
use crate::principal::Principal;
use crate::webauthn_recover::RecoveredAssertion;
use serde::{Deserialize, Serialize};

/// A candidate selector: a P-256 `did:key:zDn...` in its canonical spelling.
///
/// Only a selector, never an identity: it means nothing until it equals a
/// candidate of a verified assertion. Canonical spelling only, so comparing
/// the strings compares the keys.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DidHint(String);

impl DidHint {
    /// Parse a P-256 `did:key`. `None` for anything else (other methods and
    /// curves, `did:pkh:p256`, malformed or non-canonical spellings).
    pub fn parse(s: &str) -> Option<DidHint> {
        let point = p256_pubkey_from_did_key(s).ok()?;
        (p256_did_key_from_pubkey(&point) == s).then(|| DidHint(s.to_owned()))
    }

    /// The hint for the key in a DER SubjectPublicKeyInfo, as
    /// `AuthenticatorAttestationResponse.getPublicKey()` returns it after
    /// `create()`. P-256 on the named curve only. The client supplies these
    /// bytes, so the result is a selector like any other hint: it names the
    /// account only if the following assertion recovers this key.
    pub fn from_spki_der(spki: &[u8]) -> Result<DidHint, CryptoError> {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use p256::pkcs8::DecodePublicKey;

        let key = p256::PublicKey::from_public_key_der(spki).map_err(|e| {
            CryptoError::InvalidDid(format!("not a P-256 SubjectPublicKeyInfo: {e}"))
        })?;
        let point = key.to_encoded_point(true);
        let compressed: &[u8; 33] = point
            .as_bytes()
            .try_into()
            .expect("a compressed P-256 point is 33 bytes");
        Ok(DidHint(p256_did_key_from_pubkey(compressed)))
    }

    /// The `did:key` string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DidHint {
    type Error = CryptoError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        DidHint::parse(&s)
            .ok_or_else(|| CryptoError::InvalidDid(format!("not a canonical P-256 did:key: {s}")))
    }
}

impl From<DidHint> for String {
    fn from(h: DidHint) -> String {
        h.0
    }
}

/// The outcome of [`RecoveredAssertion::select`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// The signer is known: log `principal` in.
    Selected {
        /// The signer's `did:key:zDn...`.
        principal: Principal,
        /// Which rule picked it.
        by: SelectedBy,
    },
    /// Ambiguous: keep the [`PendingRecovery`] server-side and ask for a
    /// second assertion by [`PendingRecovery::credential_id`].
    NeedSecondAssertion(PendingRecovery),
}

/// The rule that picked the signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectedBy {
    /// A [`DidHint`] named exactly one candidate.
    Hint,
    /// Exactly one candidate was a known principal.
    KnownPrincipal,
    /// [`PendingRecovery::resolve`]: the key two assertions share. `select`
    /// never returns it; consumers use it to label that path.
    Intersection,
}

/// Why [`PendingRecovery::resolve`] refused a second assertion.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SelectionError {
    /// The second assertion is by another credential.
    #[error("second assertion is by another credential")]
    CredentialMismatch,
    /// The second assertion recovers neither pending candidate: another key
    /// signed it.
    #[error("second assertion shares no candidate key with the first")]
    NoCommonCandidate,
    /// Both candidates match: the same signature again, not a second proof.
    #[error("second assertion does not narrow the candidates")]
    Ambiguous,
}

/// The state between the two prompts of a first visit: the first
/// assertion's two candidates and its credential id.
///
/// Keep it server-side (next to the second challenge). It holds public keys
/// only, and even a tampered value cannot select a key the second assertion
/// does not recover, but it is state the server issued, not client input.
/// Serialises as `{"candidates": [did, did], "credential_id": base64url}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRecovery {
    candidates: [DidHint; 2],
    #[serde(with = "b64url_bytes")]
    credential_id: Vec<u8>,
}

impl PendingRecovery {
    /// The credential the second assertion must come from (its
    /// `allowCredentials` entry).
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// Resolve the signer from a second verified assertion by the same
    /// credential over a fresh challenge (checking that challenge is the
    /// caller's job, through `verify_and_recover`). Exactly one key must be
    /// recovered by both assertions; any other outcome is refused.
    pub fn resolve(&self, second: &RecoveredAssertion) -> Result<Principal, SelectionError> {
        if second.credential_id != self.credential_id {
            return Err(SelectionError::CredentialMismatch);
        }
        let theirs = second.candidate_dids();
        let mut common = self
            .candidates
            .iter()
            .filter(|c| theirs.iter().any(|t| t == c.as_str()));
        match (common.next(), common.next()) {
            (Some(one), None) => Ok(Principal::from_proven_did_key(one.as_str().to_owned())),
            (None, _) => Err(SelectionError::NoCommonCandidate),
            (Some(_), Some(_)) => Err(SelectionError::Ambiguous),
        }
    }
}

impl RecoveredAssertion {
    /// Pick the signer among [`RecoveredAssertion::candidate_dids`]; see the
    /// module docs for the order. `hints` are every hint the request carried
    /// (all cookie values, the sign-up key hint), in any order; `known[i]` says
    /// whether `candidate_dids()[i]` is a principal this service knows.
    pub fn select(&self, hints: &[DidHint], known: [bool; 2]) -> Selection {
        let dids = self.candidate_dids();
        let hinted = dids
            .each_ref()
            .map(|d| hints.iter().any(|h| h.as_str() == d.as_str()));
        let pick = |i: usize, by| Selection::Selected {
            principal: Principal::from_proven_did_key(dids[i].clone()),
            by,
        };
        if let Some(i) = the_only(hinted) {
            return pick(i, SelectedBy::Hint);
        }
        if let Some(i) = the_only(known) {
            return pick(i, SelectedBy::KnownPrincipal);
        }
        Selection::NeedSecondAssertion(PendingRecovery {
            candidates: dids.map(DidHint),
            credential_id: self.credential_id.clone(),
        })
    }
}

/// The index of the single `true`, if exactly one is set.
fn the_only(flags: [bool; 2]) -> Option<usize> {
    match flags {
        [true, false] => Some(0),
        [false, true] => Some(1),
        _ => None,
    }
}

/// `Vec<u8>` as an unpadded base64url string (padding accepted on input).
mod b64url_bytes {
    use crate::webauthn_recover::B64URL;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64URL.encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64URL.decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webauthn_policy::AssertionPolicy;
    use crate::webauthn_recover::{verify_and_recover, ExpectedChallenge, RecoveredAssertion};
    use crate::webauthn_testkit::{AssertOpts, SoftPasskey};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use p256::ecdsa::SigningKey;

    const RP: &str = "inblock.io";
    const ORIGIN: &str = "https://aquafire.local.inblock.io:8443";
    const CRED: &[u8] = b"credential-one";
    /// The did:key method spec's own Ed25519 example.
    const ED25519_DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    fn policy() -> AssertionPolicy {
        AssertionPolicy::builder()
            .rp(RP, &[ORIGIN])
            .unwrap()
            .build()
            .unwrap()
    }

    fn compressed(sk: &SigningKey) -> [u8; 33] {
        let point = sk.verifying_key().to_encoded_point(true);
        point.as_bytes().try_into().unwrap()
    }

    fn did_of(sk: &SigningKey) -> String {
        p256_did_key_from_pubkey(&compressed(sk))
    }

    /// The key of the seeded software passkey.
    fn key(seed: u64) -> SigningKey {
        SoftPasskey::new_seeded(seed, RP).key
    }

    /// A verified assertion by `sk` over `challenge` with credential `cred`.
    fn recovered(sk: &SigningKey, cred: &[u8], challenge: &[u8]) -> RecoveredAssertion {
        let passkey = SoftPasskey {
            key: sk.clone(),
            credential_id: cred.to_vec(),
            rp_id: RP.to_owned(),
            user_handle: None,
        };
        let a = passkey.assert(&AssertOpts::new(challenge, ORIGIN));
        verify_and_recover(&a, ExpectedChallenge::Exact(challenge), &policy()).unwrap()
    }

    /// `known` with only the signer's candidate set.
    fn signer_known(rec: &RecoveredAssertion, sk: &SigningKey) -> [bool; 2] {
        let me = did_of(sk);
        rec.candidate_dids().map(|c| c == me)
    }

    fn hint(did: &str) -> DidHint {
        DidHint::parse(did).expect("a P-256 did:key")
    }

    fn selected(s: Selection) -> (Principal, SelectedBy) {
        match s {
            Selection::Selected { principal, by } => (principal, by),
            other => panic!("expected a selection, got {other:?}"),
        }
    }

    fn pending(s: Selection) -> PendingRecovery {
        match s {
            Selection::NeedSecondAssertion(p) => p,
            other => panic!("expected a second assertion, got {other:?}"),
        }
    }

    #[test]
    fn select_by_hint() {
        let sk = key(21);
        let me = did_of(&sk);
        let rec = recovered(&sk, CRED, b"challenge-1");
        let (p, by) = selected(rec.select(&[hint(&me)], [false, false]));
        assert_eq!((p.did(), by), (me.as_str(), SelectedBy::Hint));
        // The hint outranks the known-principal lookup, even when only the
        // other candidate is known here.
        let other_known = signer_known(&rec, &sk).map(|k| !k);
        let (p, by) = selected(rec.select(&[hint(&me)], other_known));
        assert_eq!((p.did(), by), (me.as_str(), SelectedBy::Hint));
    }

    #[test]
    fn select_ignores_bogus_hint_and_uses_genuine() {
        let sk = key(22);
        let me = did_of(&sk);
        let rec = recovered(&sk, CRED, b"challenge-2");
        let bogus = hint(&did_of(&key(99)));
        // A tossed value alone selects nothing.
        pending(rec.select(std::slice::from_ref(&bogus), [false, false]));
        // A tossed value next to the genuine one, in either order: genuine wins.
        for hints in [
            vec![bogus.clone(), hint(&me)],
            vec![hint(&me), bogus.clone()],
        ] {
            let (p, by) = selected(rec.select(&hints, [false, false]));
            assert_eq!((p.did(), by), (me.as_str(), SelectedBy::Hint));
        }
        // Hints naming both candidates decide nothing; the lookup decides.
        let both: Vec<DidHint> = rec.candidate_dids().iter().map(|d| hint(d)).collect();
        pending(rec.select(&both, [false, false]));
        let (p, by) = selected(rec.select(&both, signer_known(&rec, &sk)));
        assert_eq!((p.did(), by), (me.as_str(), SelectedBy::KnownPrincipal));
    }

    #[test]
    fn select_by_unique_known() {
        let sk = key(23);
        let rec = recovered(&sk, CRED, b"challenge-3");
        let (p, by) = selected(rec.select(&[], signer_known(&rec, &sk)));
        assert_eq!(
            (p.did(), by),
            (did_of(&sk).as_str(), SelectedBy::KnownPrincipal)
        );
    }

    #[test]
    fn both_known_needs_second() {
        let rec = recovered(&key(24), CRED, b"challenge-4");
        let p = pending(rec.select(&[], [true, true]));
        assert_eq!(p.credential_id(), CRED);
    }

    #[test]
    fn none_known_no_hint_needs_second() {
        let rec = recovered(&key(25), CRED, b"challenge-5");
        let p = pending(rec.select(&[], [false, false]));
        assert_eq!(p.credential_id(), CRED);
    }

    #[test]
    fn intersection_yields_signer() {
        let sk = key(26);
        let first = recovered(&sk, CRED, b"challenge-6a");
        let p = pending(first.select(&[], [false, false]));
        let second = recovered(&sk, CRED, b"challenge-6b");
        assert_eq!(p.resolve(&second).unwrap().did(), did_of(&sk));
        // The first assertion again is no second proof: both candidates match.
        assert_eq!(p.resolve(&first), Err(SelectionError::Ambiguous));
    }

    #[test]
    fn intersection_with_assertion_by_other_key_fails() {
        let first = recovered(&key(27), CRED, b"challenge-7a");
        let p = pending(first.select(&[], [false, false]));
        let second = recovered(&key(28), CRED, b"challenge-7b");
        assert_eq!(p.resolve(&second), Err(SelectionError::NoCommonCandidate));
    }

    #[test]
    fn intersection_requires_same_credential_id() {
        let sk = key(29);
        let p = pending(recovered(&sk, CRED, b"challenge-8a").select(&[], [false, false]));
        let second = recovered(&sk, b"credential-two", b"challenge-8b");
        assert_eq!(p.resolve(&second), Err(SelectionError::CredentialMismatch));
    }

    #[test]
    fn pending_recovery_serde_roundtrip() {
        let sk = key(30);
        let first = recovered(&sk, CRED, b"challenge-9a");
        let p = pending(first.select(&[], [false, false]));
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"candidates": first.candidate_dids(), "credential_id": URL_SAFE_NO_PAD.encode(CRED)})
        );
        let back: PendingRecovery = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(back, p);
        let second = recovered(&sk, CRED, b"challenge-9b");
        assert_eq!(back.resolve(&second).unwrap().did(), did_of(&sk));
        // A stored value that is not two P-256 did:keys, or whose credential
        // id is not base64url, does not deserialize.
        let mut bad = json.clone();
        bad["candidates"][1] = ED25519_DID.into();
        assert!(serde_json::from_value::<PendingRecovery>(bad).is_err());
        let mut bad = json.clone();
        bad["candidates"] = serde_json::json!([first.candidate_dids()[0]]);
        assert!(serde_json::from_value::<PendingRecovery>(bad).is_err());
        let mut bad = json;
        bad["credential_id"] = "not+base64url/".into();
        assert!(serde_json::from_value::<PendingRecovery>(bad).is_err());
    }

    #[test]
    fn selected_principal_is_did_key_zdn() {
        let sk = key(31);
        let rec = recovered(&sk, CRED, b"challenge-10");
        let (p, _) = selected(rec.select(&[hint(&did_of(&sk))], [false, false]));
        assert!(p.did().starts_with("did:key:zDn"), "{}", p.did());
        assert_eq!(Principal::from_trusted_did(p.did()).unwrap(), p);
        assert_eq!(p.method_label().unwrap(), "P-256");
    }

    #[test]
    fn did_hint_parse_rejects_non_p256() {
        let sk = key(32);
        let good = did_of(&sk);
        assert_eq!(DidHint::parse(&good).unwrap().as_str(), good);
        let pkh = format!("did:pkh:p256:0x{}", hex::encode(compressed(&sk)));
        let padded = format!(" {good}");
        let truncated = &good[..good.len() - 1];
        let upper = good.to_uppercase();
        for bad in [
            "",
            "did:key:",
            "did:key:zDn",
            ED25519_DID,
            pkh.as_str(),
            padded.as_str(),
            truncated,
            upper.as_str(),
            "did:pkh:eip155:1:0x0000000000000000000000000000000000000000",
        ] {
            assert!(DidHint::parse(bad).is_none(), "{bad:?}");
        }
    }

    /// A throwaway 1024-bit RSA SubjectPublicKeyInfo (openssl genpkey).
    const RSA_SPKI_HEX: &str = "30819f300d06092a864886f70d010101050003818d0030818902818100e0b11e70af955e8d86153d92d001a0015695ad1476ba93fe72c0e47f642a16b90a8e24fa4e5f7e29ac270e6f2537ede2a5e63b7b67731cd95237ddc7a77fb5172ae095fe4839167468b2456c674598222cbf288b825043ee3ef18e9a453cd870e4b9f6b7ee56e69cc62a69d61d037dd2da3ba93e0303c5a6c2511c9c712ba5ad0203010001";

    #[test]
    fn did_hint_from_spki_der() {
        use p256::pkcs8::EncodePublicKey;
        use rand::{rngs::StdRng, SeedableRng};

        let sk = key(33);
        let spki = sk.verifying_key().to_public_key_der().unwrap();
        let spki = spki.as_bytes();
        // The uncompressed named-curve form `getPublicKey()` returns for ES256.
        assert_eq!(spki.len(), 91);
        let hint = DidHint::from_spki_der(spki).unwrap();
        assert_eq!(hint.as_str(), did_of(&sk));
        assert!(hint.as_str().starts_with("did:key:zDn"));

        let secp256k1 = k256::ecdsa::SigningKey::random(&mut StdRng::seed_from_u64(1))
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        let mut ed25519 = hex::decode("302a300506032b6570032100").unwrap();
        ed25519.extend_from_slice(&[7u8; 32]);
        let mut trailing = spki.to_vec();
        trailing.push(0);
        let mut off_curve = spki.to_vec();
        off_curve[90] ^= 1;
        for (label, bytes) in [
            ("RSA", hex::decode(RSA_SPKI_HEX).unwrap()),
            ("secp256k1", secp256k1),
            ("Ed25519", ed25519),
            ("trailing byte", trailing),
            ("truncated", spki[..90].to_vec()),
            ("point off the curve", off_curve),
            ("empty", Vec::new()),
        ] {
            assert!(DidHint::from_spki_der(&bytes).is_err(), "{label}");
        }
    }
}
