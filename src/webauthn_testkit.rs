//! A software passkey for tests (feature `webauthn-testkit`).
//!
//! [`SoftPasskey`] plays browser and authenticator at once: it produces the
//! `PublicKeyCredential.toJSON()` shapes a server receives, an
//! [`AssertionJson`] from `get()` and a `RegistrationResponseJSON` from
//! `create()` with attestation `none`. [`AssertOpts`] carries one knob per
//! check [`crate::verify_and_recover`] makes (challenge, origin, flags,
//! `crossOrigin`, RP ID, ceremony type) plus the signature's s form, so a
//! consumer's negative tests need no hand-rolled assertion builder.
//!
//! It models only what login and registration tests need: `signCount` is
//! always 0, authenticator data carries no extensions, and attestation is
//! `none` (which proves nothing about the key, exactly like a real `none`
//! attestation). For dev-dependencies only: the keys come from small seeds
//! and are therefore public.

use crate::did::p256_did_key_from_pubkey;
use crate::webauthn::{signed_payload, FLAG_UP, FLAG_UV};
use crate::webauthn_recover::{AssertionJson, AssertionResponseJson, B64URL};
use base64::Engine as _;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};

/// Attested credential data included (WebAuthn section 6.1).
const FLAG_AT: u8 = 0x40;
/// COSE algorithm identifier for ES256.
const COSE_ES256: i64 = -7;

/// A seeded software passkey: one P-256 key, one credential ID, one RP ID.
///
/// All fields are public so a test can swap one of them, for example a
/// foreign credential ID over a victim's key:
/// `SoftPasskey { credential_id: other, ..SoftPasskey::new_seeded(1, rp) }`.
#[derive(Debug, Clone)]
pub struct SoftPasskey {
    /// The credential's private key.
    pub key: SigningKey,
    /// The credential ID (`rawId`).
    pub credential_id: Vec<u8>,
    /// The RP ID the credential is scoped to.
    pub rp_id: String,
    /// The user handle a discoverable credential returns on `get()`.
    pub user_handle: Option<Vec<u8>>,
}

/// How [`SoftPasskey::assert`] shapes one assertion. Start from
/// [`AssertOpts::new`] and change one field per negative test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssertOpts<'a> {
    /// The challenge bytes, base64url-encoded into clientDataJSON.
    pub challenge: &'a [u8],
    /// The origin clientDataJSON states.
    pub origin: &'a str,
    /// The authenticator data flags byte; default `0x05` (UP | UV).
    pub flags: u8,
    /// The `crossOrigin` member; default `Some(false)` (Chromium's shape),
    /// `None` omits it.
    pub cross_origin: Option<bool>,
    /// Hash this RP ID into the authenticator data instead of the passkey's.
    pub rp_id_override: Option<&'a str>,
    /// The clientDataJSON `type`; default `webauthn.get`.
    pub type_: &'a str,
    /// Emit the high-S form of the signature (default: low-S).
    pub high_s: bool,
}

impl<'a> AssertOpts<'a> {
    /// A well-formed `get()` over `challenge` from `origin`.
    pub fn new(challenge: &'a [u8], origin: &'a str) -> Self {
        AssertOpts {
            challenge,
            origin,
            flags: FLAG_UP | FLAG_UV,
            cross_origin: Some(false),
            rp_id_override: None,
            type_: "webauthn.get",
            high_s: false,
        }
    }
}

impl SoftPasskey {
    /// A passkey whose key, credential ID and user handle are drawn from
    /// `StdRng::seed_from_u64(seed)`, in that order.
    pub fn new_seeded(seed: u64, rp_id: &str) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let key = SigningKey::random(&mut rng);
        let mut credential_id = vec![0u8; 16];
        rng.fill_bytes(&mut credential_id);
        let mut user_handle = vec![0u8; 32];
        rng.fill_bytes(&mut user_handle);
        SoftPasskey {
            key,
            credential_id,
            rp_id: rp_id.to_owned(),
            user_handle: Some(user_handle),
        }
    }

    /// The credential's `did:key:zDn...`.
    pub fn did(&self) -> String {
        let point = self.key.verifying_key().to_encoded_point(true);
        let compressed: &[u8; 33] = point
            .as_bytes()
            .try_into()
            .expect("a compressed P-256 point is 33 bytes");
        p256_did_key_from_pubkey(compressed)
    }

    /// The public key as a DER SubjectPublicKeyInfo, as `getPublicKey()`
    /// returns it after `create()`.
    pub fn spki_der(&self) -> Vec<u8> {
        use p256::pkcs8::EncodePublicKey;
        self.key
            .verifying_key()
            .to_public_key_der()
            .expect("a P-256 key encodes as SubjectPublicKeyInfo")
            .into_vec()
    }

    /// A signed assertion shaped by `o`.
    pub fn assert(&self, o: &AssertOpts<'_>) -> AssertionJson {
        let rp_id = o.rp_id_override.unwrap_or(&self.rp_id);
        let authenticator_data = authenticator_data(rp_id, o.flags, &[]);
        let client_data_json = client_data_json(o.type_, o.challenge, o.origin, o.cross_origin);
        self.assert_raw(&authenticator_data, &client_data_json, o.high_s)
    }

    /// A signed assertion over exactly these authenticator data and
    /// clientDataJSON bytes (for structure tests the knobs cannot express).
    pub fn assert_raw(
        &self,
        authenticator_data: &[u8],
        client_data_json: &[u8],
        high_s: bool,
    ) -> AssertionJson {
        let low: Signature = self
            .key
            .sign(&signed_payload(authenticator_data, client_data_json));
        let low = low.normalize_s().unwrap_or(low);
        let signature = if high_s {
            let (r, s) = low.split_scalars();
            Signature::from_scalars(r.to_bytes(), (-*s).to_bytes())
                .expect("n - s is a valid nonzero scalar")
        } else {
            low
        };
        AssertionJson {
            id: b64(&self.credential_id),
            raw_id: b64(&self.credential_id),
            type_: "public-key".to_owned(),
            response: AssertionResponseJson {
                authenticator_data: b64(authenticator_data),
                client_data_json: b64(client_data_json),
                signature: b64(signature.to_der().as_bytes()),
                user_handle: self.user_handle.as_deref().map(b64),
            },
            client_extension_results: serde_json::json!({}),
        }
    }

    /// The `RegistrationResponseJSON` of a `create()` over `challenge` from
    /// `origin`, with attestation `none`.
    ///
    /// Nothing in it is signed: like a real `none` attestation, it would carry
    /// any public key and credential ID equally well. A server must take a
    /// principal only from a verified assertion.
    pub fn attestation_none(&self, challenge: &[u8], origin: &str) -> serde_json::Value {
        let point = self.key.verifying_key().to_encoded_point(false);
        // COSE_Key (RFC 9053): {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256),
        // -2: x, -3: y}, in CTAP2 canonical key order.
        let mut attested = vec![0u8; 16]; // AAGUID: none
        let id_len = u16::try_from(self.credential_id.len())
            .ok()
            .filter(|len| *len <= 1023)
            .expect("a WebAuthn credential ID is at most 1023 bytes");
        attested.extend_from_slice(&id_len.to_be_bytes());
        attested.extend_from_slice(&self.credential_id);
        attested.extend_from_slice(&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01]);
        attested.extend_from_slice(&[0x21]);
        cbor_bytes(&mut attested, point.x().expect("an uncompressed point has x"));
        attested.extend_from_slice(&[0x22]);
        cbor_bytes(&mut attested, point.y().expect("an uncompressed point has y"));
        let authenticator_data =
            authenticator_data(&self.rp_id, FLAG_UP | FLAG_UV | FLAG_AT, &attested);

        let mut attestation_object = vec![0xa3];
        cbor_text(&mut attestation_object, "fmt");
        cbor_text(&mut attestation_object, "none");
        cbor_text(&mut attestation_object, "attStmt");
        attestation_object.push(0xa0);
        cbor_text(&mut attestation_object, "authData");
        cbor_bytes(&mut attestation_object, &authenticator_data);

        let client_data_json = client_data_json("webauthn.create", challenge, origin, Some(false));
        serde_json::json!({
            "id": b64(&self.credential_id),
            "rawId": b64(&self.credential_id),
            "type": "public-key",
            "authenticatorAttachment": "platform",
            "response": {
                "clientDataJSON": b64(&client_data_json),
                "authenticatorData": b64(&authenticator_data),
                "transports": ["internal"],
                "publicKey": b64(&self.spki_der()),
                "publicKeyAlgorithm": COSE_ES256,
                "attestationObject": b64(&attestation_object),
            },
            "clientExtensionResults": {"credProps": {"rk": true}},
        })
    }
}

fn b64(bytes: &[u8]) -> String {
    B64URL.encode(bytes)
}

/// `SHA-256(rp_id) || flags || signCount 0 || attested`.
fn authenticator_data(rp_id: &str, flags: u8, attested: &[u8]) -> Vec<u8> {
    let mut ad = Sha256::digest(rp_id.as_bytes()).to_vec();
    ad.push(flags);
    ad.extend_from_slice(&[0, 0, 0, 0]);
    ad.extend_from_slice(attested);
    ad
}

/// clientDataJSON in the browser's member order.
fn client_data_json(
    type_: &str,
    challenge: &[u8],
    origin: &str,
    cross_origin: Option<bool>,
) -> Vec<u8> {
    let string = |s: &str| serde_json::to_string(s).expect("a str serialises");
    let cross_origin = cross_origin
        .map(|c| format!(r#","crossOrigin":{c}"#))
        .unwrap_or_default();
    format!(
        r#"{{"type":{},"challenge":"{}","origin":{}{cross_origin}}}"#,
        string(type_),
        b64(challenge),
        string(origin),
    )
    .into_bytes()
}

/// A CBOR text string (major type 3); short strings only.
fn cbor_text(out: &mut Vec<u8>, s: &str) {
    let len = u8::try_from(s.len())
        .ok()
        .filter(|len| *len < 24)
        .expect("short CBOR text");
    out.push(0x60 | len);
    out.extend_from_slice(s.as_bytes());
}

/// A CBOR byte string (major type 2) of up to 65535 bytes.
fn cbor_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    match bytes.len() {
        len @ 0..=23 => out.push(0x40 | len as u8),
        len @ 24..=0xff => out.extend_from_slice(&[0x58, len as u8]),
        len => {
            let len = u16::try_from(len).expect("CBOR byte string under 64 KiB");
            out.push(0x59);
            out.extend_from_slice(&len.to_be_bytes());
        }
    }
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webauthn_policy::AssertionPolicy;
    use crate::webauthn_recover::{
        verify_and_recover, AssertionError, ExpectedChallenge, RecoveredAssertion, B64URL,
    };
    use crate::webauthn_select::DidHint;
    use serde_json::{json, Value};

    const RP: &str = "inblock.io";
    const ORIGIN: &str = "https://aquafire.local.inblock.io:8443";
    const CHALLENGE: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn policy(require_uv: bool) -> AssertionPolicy {
        AssertionPolicy::builder()
            .require_uv(require_uv)
            .rp(RP, &[ORIGIN])
            .unwrap()
            .build()
            .unwrap()
    }

    fn unb64(s: &str) -> Vec<u8> {
        B64URL.decode(s).unwrap()
    }

    fn verify(a: &AssertionJson) -> Result<RecoveredAssertion, AssertionError> {
        verify_and_recover(a, ExpectedChallenge::Exact(CHALLENGE), &policy(true))
    }

    #[test]
    fn seeded_passkey_is_deterministic() {
        let a = SoftPasskey::new_seeded(1, RP);
        let b = SoftPasskey::new_seeded(1, RP);
        let c = SoftPasskey::new_seeded(2, RP);
        assert_eq!(a.key.verifying_key(), b.key.verifying_key());
        assert_eq!(
            (&a.did(), &a.credential_id, &a.user_handle),
            (&b.did(), &b.credential_id, &b.user_handle)
        );
        assert_ne!(a.did(), c.did());
        assert_ne!(a.credential_id, c.credential_id);
        assert_ne!(a.user_handle, c.user_handle);
        assert_eq!(a.credential_id.len(), 16);
        assert_eq!(a.user_handle.as_ref().map(Vec::len), Some(32));
        assert_eq!(a.rp_id, RP);
        assert!(a.did().starts_with("did:key:zDn"), "{}", a.did());
        // The key is the first draw from the seeded StdRng, the same key the
        // earlier tests of this crate built by hand from the same seed.
        let first_draw = SigningKey::random(&mut StdRng::seed_from_u64(1));
        assert_eq!(a.key.verifying_key(), first_draw.verifying_key());
    }

    #[test]
    fn default_assertion_is_browser_shaped_and_recovers_signer() {
        let pk = SoftPasskey::new_seeded(3, RP);
        let a = pk.assert(&AssertOpts::new(CHALLENGE, ORIGIN));
        assert_eq!(a.type_, "public-key");
        assert_eq!(a.id, a.raw_id);
        assert_eq!(unb64(&a.raw_id), pk.credential_id);
        let cdj = String::from_utf8(unb64(&a.response.client_data_json)).unwrap();
        assert_eq!(
            cdj,
            format!(
                r#"{{"type":"webauthn.get","challenge":"{}","origin":"{ORIGIN}","crossOrigin":false}}"#,
                B64URL.encode(CHALLENGE)
            )
        );
        let mut ad = Sha256::digest(RP.as_bytes()).to_vec();
        ad.extend_from_slice(&[0x05, 0, 0, 0, 0]); // UP|UV, signCount 0
        assert_eq!(unb64(&a.response.authenticator_data), ad);
        assert_eq!(
            a.response.user_handle.as_deref().map(unb64),
            pk.user_handle
        );
        let sig = Signature::from_der(&unb64(&a.response.signature)).unwrap();
        assert!(sig.normalize_s().is_none(), "low-S by default");
        let rec = verify(&a).unwrap();
        assert!(rec.candidate_dids().contains(&pk.did()));
        assert!(rec.user_verified);
        assert_eq!(rec.credential_id, pk.credential_id);
    }

    #[test]
    fn assert_knobs_each_trip_one_check() {
        use AssertionError as E;
        let pk = SoftPasskey::new_seeded(4, RP);
        let base = AssertOpts::new(CHALLENGE, ORIGIN);
        assert!(verify(&pk.assert(&base)).is_ok(), "control");
        for (label, o, want) in [
            ("UV clear", AssertOpts { flags: 0x01, ..base }, E::UserVerificationMissing),
            ("UP clear", AssertOpts { flags: 0x04, ..base }, E::UserPresenceMissing),
            ("crossOrigin true", AssertOpts { cross_origin: Some(true), ..base }, E::CrossOrigin),
            ("other RP", AssertOpts { rp_id_override: Some("evil.io"), ..base }, E::RpIdNotAllowed),
            ("create type", AssertOpts { type_: "webauthn.create", ..base }, E::WrongType),
            (
                "unlisted origin",
                AssertOpts { origin: "https://evil.local.inblock.io:8443", ..base },
                E::OriginNotAllowed,
            ),
            ("other challenge", AssertOpts { challenge: b"another", ..base }, E::ChallengeMismatch),
        ] {
            assert_eq!(verify(&pk.assert(&o)), Err(want), "{label}");
        }
        // crossOrigin omitted: absent from clientDataJSON and accepted.
        let a = pk.assert(&AssertOpts { cross_origin: None, ..base });
        let cdj = String::from_utf8(unb64(&a.response.client_data_json)).unwrap();
        assert!(!cdj.contains("crossOrigin"), "{cdj}");
        assert!(verify(&a).is_ok());
        // UV clear passes a policy that waives UV, and reports it.
        let a = pk.assert(&AssertOpts { flags: 0x01, ..base });
        let rec = verify_and_recover(&a, ExpectedChallenge::Exact(CHALLENGE), &policy(false))
            .unwrap();
        assert!(!rec.user_verified);
    }

    #[test]
    fn high_s_knob_flips_s_and_keeps_signer() {
        for seed in 0..32u64 {
            let pk = SoftPasskey::new_seeded(seed, RP);
            let challenge = Sha256::digest(seed.to_be_bytes());
            let low = pk.assert(&AssertOpts::new(&challenge, ORIGIN));
            let high = pk.assert(&AssertOpts {
                high_s: true,
                ..AssertOpts::new(&challenge, ORIGIN)
            });
            let low_sig = Signature::from_der(&unb64(&low.response.signature)).unwrap();
            let high_sig = Signature::from_der(&unb64(&high.response.signature)).unwrap();
            assert!(low_sig.normalize_s().is_none(), "seed {seed}: low-S");
            assert_eq!(high_sig.normalize_s(), Some(low_sig), "seed {seed}: twin");
            for a in [&low, &high] {
                let rec =
                    verify_and_recover(a, ExpectedChallenge::Exact(&challenge), &policy(true))
                        .unwrap();
                assert!(rec.candidate_dids().contains(&pk.did()), "seed {seed}");
            }
        }
    }

    #[test]
    fn spki_der_names_the_same_did() {
        let pk = SoftPasskey::new_seeded(5, RP);
        let spki = pk.spki_der();
        assert_eq!(spki.len(), 91);
        // RFC 5480 SubjectPublicKeyInfo head for id-ecPublicKey on
        // secp256r1, then an uncompressed point (0x04).
        assert_eq!(
            hex::encode(&spki[..27]),
            "3059301306072a8648ce3d020106082a8648ce3d03010703420004"
        );
        let point = pk.key.verifying_key().to_encoded_point(false);
        assert_eq!(&spki[26..], point.as_bytes());
        assert_eq!(DidHint::from_spki_der(&spki).unwrap().as_str(), pk.did());
    }

    #[test]
    fn attestation_none_has_registration_response_json_shape() {
        let pk = SoftPasskey::new_seeded(6, RP);
        let v = pk.attestation_none(CHALLENGE, ORIGIN);
        let s = |p: &str| {
            v.pointer(p)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{p}"))
                .to_owned()
        };
        assert_eq!(unb64(&s("/id")), pk.credential_id);
        assert_eq!(s("/rawId"), s("/id"));
        assert_eq!(s("/type"), "public-key");
        assert_eq!(v.pointer("/response/publicKeyAlgorithm"), Some(&json!(-7)));
        assert_eq!(unb64(&s("/response/publicKey")), pk.spki_der());
        let cdj: Value = serde_json::from_slice(&unb64(&s("/response/clientDataJSON"))).unwrap();
        assert_eq!(
            cdj,
            json!({"type": "webauthn.create", "challenge": B64URL.encode(CHALLENGE),
                   "origin": ORIGIN, "crossOrigin": false})
        );
        // Authenticator data (WebAuthn sections 6.1 and 6.5.1) with the
        // credential key as a COSE_Key (RFC 9053: kty EC2, alg ES256, crv
        // P-256), written out byte by byte from the specs.
        let point = pk.key.verifying_key().to_encoded_point(false);
        let mut ad = Sha256::digest(RP.as_bytes()).to_vec();
        ad.push(0x45); // UP | UV | AT
        ad.extend_from_slice(&[0; 4]); // signCount
        ad.extend_from_slice(&[0; 16]); // AAGUID
        ad.extend_from_slice(&[0, 16]); // credentialIdLength
        ad.extend_from_slice(&pk.credential_id);
        ad.extend_from_slice(&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
        ad.extend_from_slice(point.x().unwrap());
        ad.extend_from_slice(&[0x22, 0x58, 0x20]);
        ad.extend_from_slice(point.y().unwrap());
        assert_eq!(unb64(&s("/response/authenticatorData")), ad);
        // attestationObject: CBOR {"fmt": "none", "attStmt": {}, "authData":
        // bstr}, keys in CTAP2 canonical order.
        let mut ao = vec![0xa3, 0x63];
        ao.extend_from_slice(b"fmt");
        ao.push(0x64);
        ao.extend_from_slice(b"none");
        ao.push(0x67);
        ao.extend_from_slice(b"attStmt");
        ao.push(0xa0);
        ao.push(0x68);
        ao.extend_from_slice(b"authData");
        ao.extend_from_slice(&[0x58, u8::try_from(ad.len()).unwrap()]);
        ao.extend_from_slice(&ad);
        assert_eq!(unb64(&s("/response/attestationObject")), ao);
        assert_eq!(
            v.pointer("/clientExtensionResults/credProps/rk"),
            Some(&json!(true))
        );
        // A registration is not an assertion: there is no signature to
        // recover a principal from.
        assert!(serde_json::from_value::<AssertionJson>(v).is_err());
    }

    /// The independent oracle: webauthn-rs (the stack aquafier, aqua-node and
    /// siwx-oidc register with) accepts the attestation, binds the same
    /// did:key, and accepts low-S and high-S assertions from the passkey.
    #[cfg(feature = "ceremony")]
    #[test]
    fn webauthn_rs_accepts_soft_passkey_registration_and_login() {
        use crate::webauthn_ceremony::{
            build_webauthn, login_finish, login_start, passkey_from_blob, register_finish,
            register_start, RegisterMode, WebauthnAssertion, WebauthnAttestation, WebauthnConfig,
        };

        struct Rp(Vec<String>);
        impl WebauthnConfig for Rp {
            fn rp_id(&self) -> &str {
                RP
            }
            fn rp_name(&self) -> &str {
                RP
            }
            fn allowed_origins(&self) -> &[String] {
                &self.0
            }
        }
        let webauthn = build_webauthn(&Rp(vec![ORIGIN.to_owned()])).unwrap();
        let challenge_of = |options: Value| {
            unb64(
                options
                    .pointer("/publicKey/challenge")
                    .and_then(Value::as_str)
                    .expect("publicKey.challenge"),
            )
        };

        let pk = SoftPasskey::new_seeded(7, RP);
        let started = register_start(&webauthn, &RegisterMode::Anonymous).unwrap();
        let challenge = challenge_of(serde_json::to_value(&started.options).unwrap());
        let att: WebauthnAttestation =
            serde_json::from_value(pk.attestation_none(&challenge, ORIGIN)).unwrap();
        let reg = register_finish(&webauthn, &att, &started.state, None, None, None).unwrap();
        assert_eq!(reg.did, pk.did());
        assert_eq!(reg.credential.credential_id.0, pk.credential_id);
        let passkey = passkey_from_blob(&reg.credential.public_key).unwrap();

        for high_s in [false, true] {
            let (options, state) = login_start(&webauthn, std::slice::from_ref(&passkey)).unwrap();
            let challenge = challenge_of(serde_json::to_value(&options).unwrap());
            let a = pk.assert(&AssertOpts {
                high_s,
                ..AssertOpts::new(&challenge, ORIGIN)
            });
            let a: WebauthnAssertion =
                serde_json::from_value(serde_json::to_value(&a).unwrap()).unwrap();
            let done = login_finish(&webauthn, &a, &state)
                .unwrap_or_else(|e| panic!("high_s={high_s}: {e}"));
            assert_eq!(done.credential_id.0, pk.credential_id);
        }
    }
}
