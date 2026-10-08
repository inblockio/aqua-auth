//! Store-free passkey assertion verification with P-256 public-key recovery.
//!
//! [`verify_and_recover`] checks everything about an assertion that does not
//! need the credential's public key (type, challenge, RP ID, origin,
//! cross-origin use, user presence and verification) and then recovers the
//! two P-256 public keys the ECDSA signature verifies under. The signer is one
//! of them; picking which one is candidate selection, not verification.

use crate::did::p256_did_key_from_pubkey;
use crate::webauthn::{
    parse_authenticator_data, signed_payload, FLAG_BE, FLAG_BS, FLAG_UP, FLAG_UV,
};
use crate::webauthn_policy::AssertionPolicy;
use base64::{
    alphabet,
    engine::{
        general_purpose::{GeneralPurpose, GeneralPurposeConfig},
        DecodePaddingMode,
    },
    Engine as _,
};
use ecdsa::RecoveryId;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// base64url, padding optional on input, none on output.
pub(crate) const B64URL: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// A WebAuthn assertion as the browser's `PublicKeyCredential.toJSON()` (or
/// webauthn-rs's `PublicKeyCredential`) serialises it. Binary members are
/// base64url strings; padding is accepted but not required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssertionJson {
    /// base64url of `raw_id`; must agree with it.
    pub id: String,
    /// The credential ID, base64url.
    #[serde(rename = "rawId")]
    pub raw_id: String,
    /// Always `public-key`.
    #[serde(rename = "type")]
    pub type_: String,
    /// The authenticator's response.
    pub response: AssertionResponseJson,
    /// Unsigned client extension outputs; carried, never trusted.
    /// webauthn-rs serialises this member as `extensions`.
    #[serde(
        rename = "clientExtensionResults",
        alias = "extensions",
        default = "empty_object"
    )]
    pub client_extension_results: serde_json::Value,
}

/// The `response` member of an [`AssertionJson`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssertionResponseJson {
    /// base64url of the raw authenticator data.
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    /// base64url of the exact clientDataJSON bytes that were signed.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// base64url of the ASN.1 DER ECDSA signature.
    pub signature: String,
    /// base64url of the user handle, when the authenticator returned one.
    #[serde(rename = "userHandle", default)]
    pub user_handle: Option<String>,
}

fn empty_object() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

/// The challenge the assertion must carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedChallenge<'a> {
    /// The exact challenge bytes the server issued.
    Exact(&'a [u8]),
}

/// A verified assertion: every check passed and the signature verifies under
/// both recovered candidate keys. It does NOT yet say who signed; that takes
/// candidate selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredAssertion {
    /// The policy RP ID whose hash the authenticator data carried.
    pub rp_id: String,
    /// The origin from clientDataJSON (listed for `rp_id`).
    pub origin: String,
    /// The UV flag.
    pub user_verified: bool,
    /// The BE flag.
    pub backup_eligible: bool,
    /// The BS flag.
    pub backup_state: bool,
    /// The credential ID (`rawId`).
    pub credential_id: Vec<u8>,
    /// The user handle, when the authenticator returned one.
    pub user_handle: Option<Vec<u8>>,
    /// The two keys the signature verifies under (y parity even, then odd).
    candidates: [VerifyingKey; 2],
}

impl RecoveredAssertion {
    /// The two candidate signers as `did:key:zDn...` DIDs, in a fixed order.
    /// Exactly one of them made the signature; neither is a principal until
    /// candidate selection picks it.
    pub fn candidate_dids(&self) -> [String; 2] {
        self.candidates.each_ref().map(did_key_of)
    }
}

/// The `did:key` of a P-256 verifying key (compressed SEC1 point).
fn did_key_of(vk: &VerifyingKey) -> String {
    let point = vk.to_encoded_point(true);
    let compressed: &[u8; 33] = point
        .as_bytes()
        .try_into()
        .expect("a compressed P-256 point is 33 bytes");
    p256_did_key_from_pubkey(compressed)
}

/// Why an assertion was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AssertionError {
    /// Structurally invalid: bad base64, JSON, lengths or duplicate keys.
    #[error("malformed assertion: {0}")]
    Malformed(String),
    /// `rpIdHash` matches no RP ID in the policy.
    #[error("assertion RP ID is not allowed")]
    RpIdNotAllowed,
    /// The origin is not listed for the matched RP ID.
    #[error("assertion origin is not allowed for its RP ID")]
    OriginNotAllowed,
    /// `crossOrigin` is true (the ceremony ran in a cross-origin iframe).
    #[error("cross-origin assertions are refused")]
    CrossOrigin,
    /// `topOrigin` is present.
    #[error("assertions carrying topOrigin are refused")]
    TopOriginPresent,
    /// `type` is not `webauthn.get`.
    #[error("clientDataJSON type is not webauthn.get")]
    WrongType,
    /// The challenge differs from the expected one.
    #[error("challenge mismatch")]
    ChallengeMismatch,
    /// The UP flag is clear.
    #[error("user presence flag not set")]
    UserPresenceMissing,
    /// The UV flag is clear and the policy requires it.
    #[error("user verification flag not set")]
    UserVerificationMissing,
    /// The signature is not a P-256 DER ECDSA signature or recovers no key.
    #[error("invalid signature")]
    BadSignature,
}

/// Verify a passkey assertion without a stored public key and recover the two
/// candidate signer keys. See the module docs.
pub fn verify_and_recover(
    a: &AssertionJson,
    expected: ExpectedChallenge<'_>,
    policy: &AssertionPolicy,
) -> Result<RecoveredAssertion, AssertionError> {
    use AssertionError as E;

    // Structure: every binary member decodes, `id` agrees with `rawId`.
    if a.type_ != "public-key" {
        return Err(E::Malformed(format!(
            "credential type {:?} is not public-key",
            a.type_
        )));
    }
    let credential_id = decode("rawId", &a.raw_id)?;
    if decode("id", &a.id)? != credential_id {
        return Err(E::Malformed("id does not match rawId".into()));
    }
    let auth_data_bytes = decode("authenticatorData", &a.response.authenticator_data)?;
    let client_data_json = decode("clientDataJSON", &a.response.client_data_json)?;
    let signature = decode("signature", &a.response.signature)?;
    let user_handle = a
        .response
        .user_handle
        .as_deref()
        .map(|h| decode("userHandle", h))
        .transpose()?;
    let auth_data = parse_authenticator_data(&auth_data_bytes).map_err(E::Malformed)?;
    let client: ClientData = serde_json::from_slice(&client_data_json)
        .map_err(|e| E::Malformed(format!("clientDataJSON: {e}")))?;

    // Ceremony checks, none of which needs the public key.
    if client.type_ != "webauthn.get" {
        return Err(E::WrongType);
    }
    let challenge = B64URL
        .decode(&client.challenge)
        .map_err(|e| E::Malformed(format!("clientDataJSON challenge: {e}")))?;
    match expected {
        ExpectedChallenge::Exact(want) => {
            if challenge != want {
                return Err(E::ChallengeMismatch);
            }
        }
    }
    let entry = policy
        .entry_for_rp_id_hash(auth_data.rp_id_hash)
        .ok_or(E::RpIdNotAllowed)?;
    if !entry.allows_origin(&client.origin) {
        return Err(E::OriginNotAllowed);
    }
    if client.cross_origin == Some(true) {
        return Err(E::CrossOrigin);
    }
    if client.top_origin {
        return Err(E::TopOriginPresent);
    }
    if auth_data.flags & FLAG_UP == 0 {
        return Err(E::UserPresenceMissing);
    }
    let user_verified = auth_data.flags & FLAG_UV != 0;
    if policy.require_uv() && !user_verified {
        return Err(E::UserVerificationMissing);
    }

    // Recovery: both y parities of R (x-reduced ids skipped: r >= n has
    // probability about 2^-128 for P-256). Negating s swaps the two keys, so
    // the candidate set does not depend on the signature's s form.
    let sig = Signature::from_der(&signature).map_err(|_| E::BadSignature)?;
    let sig = sig.normalize_s().unwrap_or(sig);
    let z = Sha256::digest(signed_payload(&auth_data_bytes, &client_data_json));
    let recover = |y_odd: bool| {
        VerifyingKey::recover_from_prehash(&z, &sig, RecoveryId::new(y_odd, false))
            .map_err(|_| E::BadSignature)
    };
    let candidates = [recover(false)?, recover(true)?];

    Ok(RecoveredAssertion {
        rp_id: entry.rp_id.clone(),
        origin: client.origin,
        user_verified,
        backup_eligible: auth_data.flags & FLAG_BE != 0,
        backup_state: auth_data.flags & FLAG_BS != 0,
        credential_id,
        user_handle,
        candidates,
    })
}

/// The clientDataJSON members the checks read. A typed struct rather than a
/// `serde_json::Value`, because serde refuses a duplicate known member here,
/// where a map keeps one of the two values silently. Unknown members are
/// ignored (browsers add some).
#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    type_: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: Option<bool>,
    /// Whether `topOrigin` is present at all (any value, `null` included).
    #[serde(rename = "topOrigin", default, deserialize_with = "present")]
    top_origin: bool,
}

fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    serde::de::IgnoredAny::deserialize(d).map(|_| true)
}

fn decode(member: &str, value: &str) -> Result<Vec<u8>, AssertionError> {
    B64URL
        .decode(value)
        .map_err(|e| AssertionError::Malformed(format!("{member}: {e}")))
}

/// Assertion builders shared by the unit tests of the store-free login
/// modules. A local P-256 signer, not an authenticator model.
#[cfg(test)]
pub(crate) mod test_support {
    use super::{empty_object, AssertionJson, AssertionResponseJson};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use rand::{rngs::StdRng, SeedableRng};
    use sha2::{Digest, Sha256};

    pub(crate) fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    pub(crate) fn key(seed: u64) -> SigningKey {
        SigningKey::random(&mut StdRng::seed_from_u64(seed))
    }

    pub(crate) fn auth_data(rp_id: &str, flags: u8) -> Vec<u8> {
        let mut ad = Sha256::digest(rp_id.as_bytes()).to_vec();
        ad.push(flags);
        ad.extend_from_slice(&[0, 0, 0, 0]); // signCount 0, as passkeys report
        ad
    }

    /// clientDataJSON in the browser's member order; `extra` is appended
    /// verbatim inside the object (e.g. `,"crossOrigin":false`).
    pub(crate) fn client_data(type_: &str, challenge: &[u8], origin: &str, extra: &str) -> Vec<u8> {
        format!(
            r#"{{"type":"{type_}","challenge":"{}","origin":"{origin}"{extra}}}"#,
            b64(challenge)
        )
        .into_bytes()
    }

    pub(crate) fn sign(key: &SigningKey, ad: &[u8], cdj: &[u8]) -> Signature {
        let mut msg = ad.to_vec();
        msg.extend_from_slice(&Sha256::digest(cdj));
        key.sign(&msg)
    }

    pub(crate) fn assertion_json(
        credential_id: &[u8],
        user_handle: Option<&[u8]>,
        ad: &[u8],
        cdj: &[u8],
        sig_der: &[u8],
    ) -> AssertionJson {
        AssertionJson {
            id: b64(credential_id),
            raw_id: b64(credential_id),
            type_: "public-key".into(),
            response: AssertionResponseJson {
                authenticator_data: b64(ad),
                client_data_json: b64(cdj),
                signature: b64(sig_der),
                user_handle: user_handle.map(b64),
            },
            client_extension_results: empty_object(),
        }
    }

    /// A `webauthn.get` assertion by `key` over `challenge` from `origin` for
    /// `rp_id`, flags UP|UV, no crossOrigin member.
    pub(crate) fn signed_get(
        key: &SigningKey,
        credential_id: &[u8],
        rp_id: &str,
        origin: &str,
        challenge: &[u8],
    ) -> AssertionJson {
        let ad = auth_data(rp_id, 0x05);
        let cdj = client_data("webauthn.get", challenge, origin, "");
        let sig = sign(key, &ad, &cdj);
        assertion_json(credential_id, None, &ad, &cdj, sig.to_der().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{assertion_json, auth_data, b64, client_data, key, sign};
    use super::*;
    use crate::webauthn::{verify_webauthn_assertion, WebAuthnAssertionParams};
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    const RP: &str = "inblock.io";
    const LEGACY_RP: &str = "siwx.inblock.io";
    const ORIGIN: &str = "https://aquafire.local.inblock.io:8443";
    const SIWX_ORIGIN: &str = "https://siwx.inblock.io";
    const CRED_ID: [u8; 16] = [7u8; 16];
    const USER_HANDLE: [u8; 32] = [9u8; 32];
    const CHALLENGE: &[u8] = b"0123456789abcdef0123456789abcdef";
    const UP_UV: u8 = 0x05;

    fn policy() -> AssertionPolicy {
        policy_uv(true)
    }

    fn policy_uv(require_uv: bool) -> AssertionPolicy {
        AssertionPolicy::builder()
            .require_uv(require_uv)
            .rp(RP, &[ORIGIN, SIWX_ORIGIN])
            .unwrap()
            .rp(LEGACY_RP, &[SIWX_ORIGIN])
            .unwrap()
            .build()
            .unwrap()
    }

    fn assertion_with_sig(ad: &[u8], cdj: &[u8], sig_der: &[u8]) -> AssertionJson {
        assertion_json(&CRED_ID, Some(&USER_HANDLE), ad, cdj, sig_der)
    }

    fn assertion(key: &SigningKey, ad: &[u8], cdj: &[u8]) -> AssertionJson {
        let sig = sign(key, ad, cdj);
        assertion_with_sig(ad, cdj, sig.to_der().as_bytes())
    }

    /// A browser-shaped assertion from `ORIGIN` for `RP` with UP|UV.
    fn good(key: &SigningKey) -> AssertionJson {
        let cdj = client_data("webauthn.get", CHALLENGE, ORIGIN, r#","crossOrigin":false"#);
        assertion(key, &auth_data(RP, UP_UV), &cdj)
    }

    fn verify(a: &AssertionJson) -> Result<RecoveredAssertion, AssertionError> {
        verify_and_recover(a, ExpectedChallenge::Exact(CHALLENGE), &policy())
    }

    fn holds(rec: &RecoveredAssertion, vk: &VerifyingKey) -> bool {
        rec.candidates.iter().any(|c| c == vk)
    }

    #[test]
    fn recover_property_signer_among_exactly_two_candidates() {
        let mut rng = StdRng::seed_from_u64(0x5eed_0002);
        for i in 0..256 {
            let sk = SigningKey::random(&mut rng);
            let mut challenge = [0u8; 32];
            rng.fill_bytes(&mut challenge);
            let cdj = client_data("webauthn.get", &challenge, ORIGIN, "");
            let a = assertion(&sk, &auth_data(RP, UP_UV), &cdj);
            let rec = verify_and_recover(&a, ExpectedChallenge::Exact(&challenge), &policy())
                .unwrap_or_else(|e| panic!("case {i}: {e}"));
            assert_ne!(rec.candidates[0], rec.candidates[1], "case {i}");
            assert!(holds(&rec, sk.verifying_key()), "case {i}: signer missing");
            let dids = rec.candidate_dids();
            assert_ne!(dids[0], dids[1], "case {i}");
            assert!(
                dids.iter().all(|d| d.starts_with("did:key:zDn")),
                "case {i}"
            );
            let signer = did_key_of(sk.verifying_key());
            assert_eq!(dids.iter().filter(|d| **d == signer).count(), 1, "case {i}");
            assert_eq!(rec.rp_id, RP);
            assert_eq!(rec.origin, ORIGIN);
            assert!(rec.user_verified);
            assert!(!rec.backup_eligible && !rec.backup_state);
            assert_eq!(rec.credential_id, CRED_ID.to_vec());
            assert_eq!(rec.user_handle.as_deref(), Some(&USER_HANDLE[..]));
        }
    }

    #[test]
    fn recover_candidate_set_invariant_under_s_negation() {
        let sk = key(11);
        let ad = auth_data(RP, UP_UV);
        let cdj = client_data("webauthn.get", CHALLENGE, ORIGIN, "");
        let sig = sign(&sk, &ad, &cdj);
        let (r, s) = sig.split_scalars();
        let negated = Signature::from_scalars(r.to_bytes(), (-*s).to_bytes()).unwrap();
        assert_ne!(sig, negated);
        let one = verify(&assertion_with_sig(&ad, &cdj, sig.to_der().as_bytes())).unwrap();
        let two = verify(&assertion_with_sig(&ad, &cdj, negated.to_der().as_bytes())).unwrap();
        let set = |rec: &RecoveredAssertion| {
            let mut v: Vec<Vec<u8>> = rec
                .candidates
                .iter()
                .map(|k| k.to_encoded_point(true).as_bytes().to_vec())
                .collect();
            v.sort();
            v
        };
        assert_eq!(set(&one), set(&two));
        assert!(holds(&one, sk.verifying_key()));
    }

    #[test]
    fn rejects_challenge_mismatch() {
        let a = good(&key(1));
        assert!(verify(&a).is_ok(), "control");
        let other = verify_and_recover(&a, ExpectedChallenge::Exact(b"another"), &policy());
        assert_eq!(other, Err(AssertionError::ChallengeMismatch));
        let empty = verify_and_recover(&a, ExpectedChallenge::Exact(b""), &policy());
        assert_eq!(empty, Err(AssertionError::ChallengeMismatch));
    }

    #[test]
    fn rejects_origin_not_listed() {
        let sk = key(2);
        for origin in [
            "https://evil.local.inblock.io:8443", // within the RP, not listed
            "https://aquafire.local.inblock.io",  // listed host, other port
            "https://aquafire.local.inblock.io:8443/",
            "https://evil.example",
        ] {
            let cdj = client_data("webauthn.get", CHALLENGE, origin, "");
            let a = assertion(&sk, &auth_data(RP, UP_UV), &cdj);
            assert_eq!(
                verify(&a),
                Err(AssertionError::OriginNotAllowed),
                "{origin}"
            );
        }
    }

    #[test]
    fn rejects_origin_listed_only_under_other_rp() {
        let sk = key(3);
        // Controls: each origin under an RP that lists it.
        let cdj = client_data("webauthn.get", CHALLENGE, SIWX_ORIGIN, "");
        let rec = verify(&assertion(&sk, &auth_data(LEGACY_RP, UP_UV), &cdj)).unwrap();
        assert_eq!(rec.rp_id, LEGACY_RP);
        let rec = verify(&assertion(&sk, &auth_data(RP, UP_UV), &cdj)).unwrap();
        assert_eq!(rec.rp_id, RP);
        // ORIGIN is listed under RP only, so the legacy RP refuses it.
        let cdj = client_data("webauthn.get", CHALLENGE, ORIGIN, "");
        let a = assertion(&sk, &auth_data(LEGACY_RP, UP_UV), &cdj);
        assert_eq!(verify(&a), Err(AssertionError::OriginNotAllowed));
    }

    #[test]
    fn rejects_rp_id_hash_not_allowed() {
        let sk = key(4);
        let cdj = client_data("webauthn.get", CHALLENGE, ORIGIN, "");
        for rp in ["evil.io", "local.inblock.io", "io", "INBLOCK.IO"] {
            let a = assertion(&sk, &auth_data(rp, UP_UV), &cdj);
            assert_eq!(verify(&a), Err(AssertionError::RpIdNotAllowed), "{rp}");
        }
    }

    #[test]
    fn rejects_uv_clear_when_required() {
        let sk = key(5);
        let cdj = client_data("webauthn.get", CHALLENGE, ORIGIN, "");
        let a = assertion(&sk, &auth_data(RP, 0x01), &cdj);
        assert_eq!(verify(&a), Err(AssertionError::UserVerificationMissing));
        let rec = verify_and_recover(&a, ExpectedChallenge::Exact(CHALLENGE), &policy_uv(false))
            .expect("UV waived by policy");
        assert!(!rec.user_verified);
        assert!(holds(&rec, sk.verifying_key()));
    }

    #[test]
    fn rejects_cross_origin_true() {
        let sk = key(6);
        let ad = auth_data(RP, UP_UV);
        let with = |extra: &str| {
            assertion(
                &sk,
                &ad,
                &client_data("webauthn.get", CHALLENGE, ORIGIN, extra),
            )
        };
        assert_eq!(
            verify(&with(r#","crossOrigin":true"#)),
            Err(AssertionError::CrossOrigin)
        );
        assert!(verify(&with(r#","crossOrigin":false"#)).is_ok());
        assert!(verify(&with("")).is_ok());
        // A non-boolean crossOrigin is not a browser's clientDataJSON.
        assert!(matches!(
            verify(&with(r#","crossOrigin":"false""#)),
            Err(AssertionError::Malformed(_))
        ));
    }

    #[test]
    fn rejects_top_origin_present() {
        let sk = key(7);
        let ad = auth_data(RP, UP_UV);
        let with = |extra: &str| {
            assertion(
                &sk,
                &ad,
                &client_data("webauthn.get", CHALLENGE, ORIGIN, extra),
            )
        };
        assert_eq!(
            verify(&with(
                r#","crossOrigin":false,"topOrigin":"https://evil.example""#
            )),
            Err(AssertionError::TopOriginPresent)
        );
        assert_eq!(
            verify(&with(r#","topOrigin":null"#)),
            Err(AssertionError::TopOriginPresent)
        );
        // Unknown members are allowed (browsers add them).
        assert!(verify(&with(r#","other_keys_can_be_added_here":"x""#)).is_ok());
    }

    #[test]
    fn rejects_type_webauthn_create() {
        let sk = key(8);
        let cdj = client_data("webauthn.create", CHALLENGE, ORIGIN, "");
        let a = assertion(&sk, &auth_data(RP, UP_UV), &cdj);
        assert_eq!(verify(&a), Err(AssertionError::WrongType));
        let cdj = client_data("payment.get", CHALLENGE, ORIGIN, "");
        let a = assertion(&sk, &auth_data(RP, UP_UV), &cdj);
        assert_eq!(verify(&a), Err(AssertionError::WrongType));
    }

    #[test]
    fn rejects_up_clear() {
        let sk = key(9);
        let cdj = client_data("webauthn.get", CHALLENGE, ORIGIN, "");
        let a = assertion(&sk, &auth_data(RP, 0x04), &cdj);
        assert_eq!(verify(&a), Err(AssertionError::UserPresenceMissing));
        let a = assertion(&sk, &auth_data(RP, 0x00), &cdj);
        let lax = verify_and_recover(&a, ExpectedChallenge::Exact(CHALLENGE), &policy_uv(false));
        assert_eq!(lax, Err(AssertionError::UserPresenceMissing));
    }

    #[test]
    fn rejects_duplicate_client_data_keys() {
        let sk = key(10);
        let ad = auth_data(RP, UP_UV);
        let good_c = b64(CHALLENGE);
        let bad_c = b64(b"another challenge");
        let control =
            format!(r#"{{"type":"webauthn.get","challenge":"{good_c}","origin":"{ORIGIN}"}}"#);
        assert!(
            verify(&assertion(&sk, &ad, control.as_bytes())).is_ok(),
            "control"
        );
        // A parser keeping either the first or the last duplicate would accept
        // one of each pair, so both orders must be refused.
        for cdj in [
            format!(
                r#"{{"type":"webauthn.get","challenge":"{good_c}","origin":"{ORIGIN}","origin":"https://evil.example"}}"#
            ),
            format!(
                r#"{{"type":"webauthn.get","challenge":"{good_c}","origin":"https://evil.example","origin":"{ORIGIN}"}}"#
            ),
            format!(
                r#"{{"type":"webauthn.get","challenge":"{bad_c}","challenge":"{good_c}","origin":"{ORIGIN}"}}"#
            ),
            format!(
                r#"{{"type":"webauthn.get","challenge":"{good_c}","challenge":"{bad_c}","origin":"{ORIGIN}"}}"#
            ),
            format!(
                r#"{{"type":"webauthn.create","type":"webauthn.get","challenge":"{good_c}","origin":"{ORIGIN}"}}"#
            ),
            format!(
                r#"{{"type":"webauthn.get","challenge":"{good_c}","origin":"{ORIGIN}","crossOrigin":true,"crossOrigin":false}}"#
            ),
        ] {
            let a = assertion(&sk, &ad, cdj.as_bytes());
            assert!(
                matches!(verify(&a), Err(AssertionError::Malformed(_))),
                "{cdj}"
            );
        }
    }

    #[test]
    fn rejects_non_p256_der_signature() {
        let sk = key(12);
        let ad = auth_data(RP, UP_UV);
        let cdj = client_data("webauthn.get", CHALLENGE, ORIGIN, "");
        let sig = sign(&sk, &ad, &cdj);
        let der = sig.to_der().as_bytes().to_vec();
        assert!(
            verify(&assertion_with_sig(&ad, &cdj, &der)).is_ok(),
            "control"
        );

        let mut trailing = der.clone();
        trailing.push(0);
        let order_n =
            hex::decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
                .unwrap();
        let mut r_is_n = vec![0x30, 0x26, 0x02, 0x21, 0x00];
        r_is_n.extend_from_slice(&order_n);
        r_is_n.extend_from_slice(&[0x02, 0x01, 0x01]);
        for (label, bytes) in [
            ("raw r||s", sig.to_bytes().to_vec()),
            ("empty", Vec::new()),
            ("truncated DER", der[..der.len() - 1].to_vec()),
            ("trailing byte", trailing),
            (
                "r = 0",
                vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01],
            ),
            ("r = n", r_is_n),
        ] {
            assert_eq!(
                verify(&assertion_with_sig(&ad, &cdj, &bytes)),
                Err(AssertionError::BadSignature),
                "{label}"
            );
        }
    }

    #[test]
    fn tampered_auth_data_does_not_recover_signer() {
        let sk = key(13);
        let ad = auth_data(RP, UP_UV);
        let cdj = client_data("webauthn.get", CHALLENGE, ORIGIN, "");
        let sig = sign(&sk, &ad, &cdj);
        // Flip the BE bit after signing: every check still passes, but the
        // signed bytes changed, so recovery yields two keys that are not the
        // signer's.
        let mut tampered = ad.clone();
        tampered[32] |= 0x08;
        let rec = verify(&assertion_with_sig(
            &tampered,
            &cdj,
            sig.to_der().as_bytes(),
        ))
        .expect("checks pass on the tampered bytes");
        assert!(rec.backup_eligible);
        assert_ne!(rec.candidates[0], rec.candidates[1]);
        assert!(!holds(&rec, sk.verifying_key()));
    }

    #[test]
    fn accepts_webauthn_rs_assertion_json_shape() {
        let sk = key(14);
        let ad = auth_data(RP, UP_UV);
        let cdj = client_data("webauthn.get", CHALLENGE, ORIGIN, r#","crossOrigin":false"#);
        let sig = sign(&sk, &ad, &cdj).to_der().as_bytes().to_vec();
        let padded = |b: &[u8]| {
            let s = b64(b);
            let pad = (4 - s.len() % 4) % 4;
            s + &"=".repeat(pad)
        };
        // webauthn-rs-proto 0.6.1-dev `PublicKeyCredential` as it serialises:
        // `extensions`, unpadded base64url, `userHandle: null`.
        let rs_shape = serde_json::json!({
            "id": b64(&CRED_ID),
            "rawId": b64(&CRED_ID),
            "response": {
                "authenticatorData": b64(&ad),
                "clientDataJSON": b64(&cdj),
                "signature": b64(&sig),
                "userHandle": null
            },
            "extensions": {},
            "type": "public-key"
        });
        // The browser's toJSON() shape, padded, with extra members.
        let browser_shape = serde_json::json!({
            "id": padded(&CRED_ID),
            "rawId": padded(&CRED_ID),
            "type": "public-key",
            "authenticatorAttachment": "platform",
            "response": {
                "authenticatorData": padded(&ad),
                "clientDataJSON": padded(&cdj),
                "signature": padded(&sig),
                "userHandle": padded(&USER_HANDLE)
            },
            "clientExtensionResults": {}
        });
        let a: AssertionJson = serde_json::from_value(rs_shape).unwrap();
        let rec = verify(&a).unwrap();
        assert_eq!(rec.user_handle, None);
        assert!(holds(&rec, sk.verifying_key()));
        let a: AssertionJson = serde_json::from_value(browser_shape).unwrap();
        let rec = verify(&a).unwrap();
        assert_eq!(rec.user_handle.as_deref(), Some(&USER_HANDLE[..]));
        assert_eq!(rec.credential_id, CRED_ID.to_vec());
        assert!(holds(&rec, sk.verifying_key()));

        // The complement: structure that is not an assertion is Malformed.
        let base = good(&sk);
        let mut mismatched_id = base.clone();
        mismatched_id.id = b64(b"some other credential");
        let mut wrong_cred_type = base.clone();
        wrong_cred_type.type_ = "password".into();
        let mut short_ad = base.clone();
        short_ad.response.authenticator_data = b64(&ad[..36]);
        let mut bad_b64 = base.clone();
        bad_b64.response.client_data_json = "not+base64url/".into();
        let mut not_json = base.clone();
        not_json.response.client_data_json = b64(b"not json");
        for (label, a) in [
            ("id disagrees with rawId", mismatched_id),
            ("credential type", wrong_cred_type),
            ("authenticatorData shorter than 37 bytes", short_ad),
            ("standard-alphabet base64", bad_b64),
            ("clientDataJSON not JSON", not_json),
        ] {
            assert!(
                matches!(verify(&a), Err(AssertionError::Malformed(_))),
                "{label}"
            );
        }
    }

    /// Characterization, stays green: the stored-key verifier does not check
    /// UV or crossOrigin. Store-free login must not inherit that gap.
    #[test]
    fn legacy_verify_accepts_uv0_and_cross_origin_true() {
        let sk = key(15);
        let ad = auth_data(RP, 0x01);
        let cdj = client_data("webauthn.get", CHALLENGE, ORIGIN, r#","crossOrigin":true"#);
        let sig = sign(&sk, &ad, &cdj);
        let pubkey = sk.verifying_key().to_encoded_point(true);
        let params = WebAuthnAssertionParams {
            credential_public_key: pubkey.as_bytes(),
            authenticator_data: &ad,
            client_data_json: &cdj,
            signature: &sig.to_bytes(),
            expected_challenge: CHALLENGE,
            expected_origin: ORIGIN,
            expected_rp_id: RP,
        };
        assert!(verify_webauthn_assertion(&params).unwrap());
    }
}
