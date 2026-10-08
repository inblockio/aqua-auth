//! Passkey creation and request options as plain serde JSON, in the shape
//! `PublicKeyCredential.parseCreationOptionsFromJSON` and
//! `parseRequestOptionsFromJSON` read (binary members as unpadded base64url).
//! No webauthn-rs and no server state: creation needs none, because no
//! service mints anything from a registration (a principal only ever comes
//! from a verified assertion).
//!
//! Every passkey is created alike, so it works at every service under the
//! same RP ID: ES256 only (the key a P-256 `did:key` names and recovery
//! needs), discoverable (resident), user verification required, attestation
//! `none`, `credProps` requested, and a random 32-byte `user.id` that ties the
//! credential to no account.

use crate::webauthn_recover::B64URL;
use base64::Engine as _;
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// The single user name every passkey is created with, so the browser's
/// account picker shows one entry per key, not per service.
pub const PASSKEY_USER_NAME: &str = "inblock.io";

/// COSE algorithm ES256 (ECDSA P-256 with SHA-256).
const COSE_ES256: i64 = -7;

const PUBLIC_KEY: &str = "public-key";
const REQUIRED: &str = "required";

/// `{"publicKey": {...}}` for `navigator.credentials.create()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreationOptionsJson {
    #[serde(rename = "publicKey")]
    public_key: PublicKeyCreationOptionsJson,
}

impl CreationOptionsJson {
    /// The inner `publicKey` object.
    pub fn public_key(&self) -> &PublicKeyCreationOptionsJson {
        &self.public_key
    }
}

/// `PublicKeyCredentialCreationOptionsJSON`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCreationOptionsJson {
    /// The relying party.
    pub rp: RelyingPartyJson,
    /// The user entity (random id, shared name).
    pub user: UserEntityJson,
    /// base64url challenge.
    pub challenge: String,
    /// `[{type: public-key, alg: -7}]`.
    pub pub_key_cred_params: Vec<CredentialParameterJson>,
    /// Resident key and user verification, both required.
    pub authenticator_selection: AuthenticatorSelectionJson,
    /// Always `none`.
    pub attestation: String,
    /// `{credProps: true}`.
    pub extensions: CreationExtensionsJson,
}

/// `PublicKeyCredentialRpEntity`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelyingPartyJson {
    /// The RP ID.
    pub id: String,
    /// The RP display name.
    pub name: String,
}

/// `PublicKeyCredentialUserEntityJSON`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserEntityJson {
    /// base64url of 32 random bytes, fresh per call.
    pub id: String,
    /// The user name.
    pub name: String,
    /// The display name (equal to `name`).
    pub display_name: String,
}

/// `PublicKeyCredentialParameters`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialParameterJson {
    /// Always `public-key`.
    #[serde(rename = "type")]
    pub type_: String,
    /// COSE algorithm identifier.
    pub alg: i64,
}

/// `AuthenticatorSelectionCriteria`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorSelectionJson {
    /// `required`.
    pub resident_key: String,
    /// `true` (the Level 1 spelling of `residentKey: required`).
    pub require_resident_key: bool,
    /// `required`.
    pub user_verification: String,
}

/// The creation extensions requested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreationExtensionsJson {
    /// Ask whether the credential is discoverable.
    pub cred_props: bool,
}

/// `{"publicKey": {...}}` for `navigator.credentials.get()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestOptionsJson {
    #[serde(rename = "publicKey")]
    public_key: PublicKeyRequestOptionsJson,
}

impl RequestOptionsJson {
    /// The inner `publicKey` object.
    pub fn public_key(&self) -> &PublicKeyRequestOptionsJson {
        &self.public_key
    }
}

/// `PublicKeyCredentialRequestOptionsJSON`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyRequestOptionsJson {
    /// base64url challenge.
    pub challenge: String,
    /// The RP ID.
    pub rp_id: String,
    /// Omitted when empty (a discoverable login).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_credentials: Vec<CredentialDescriptorJson>,
    /// `required`.
    pub user_verification: String,
}

/// `PublicKeyCredentialDescriptorJSON`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialDescriptorJson {
    /// Always `public-key`.
    #[serde(rename = "type")]
    pub type_: String,
    /// base64url credential id.
    pub id: String,
}

/// Options for `create()`; see the module docs for what is fixed. The
/// `user.id` is 32 fresh bytes from the OS RNG on every call.
pub fn creation_options(
    rp_id: &str,
    rp_name: &str,
    user_name: &str,
    challenge: &[u8; 32],
) -> CreationOptionsJson {
    let mut user_id = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut user_id);
    CreationOptionsJson {
        public_key: PublicKeyCreationOptionsJson {
            rp: RelyingPartyJson {
                id: rp_id.to_owned(),
                name: rp_name.to_owned(),
            },
            user: UserEntityJson {
                id: B64URL.encode(user_id),
                name: user_name.to_owned(),
                display_name: user_name.to_owned(),
            },
            challenge: B64URL.encode(challenge),
            pub_key_cred_params: vec![CredentialParameterJson {
                type_: PUBLIC_KEY.to_owned(),
                alg: COSE_ES256,
            }],
            authenticator_selection: AuthenticatorSelectionJson {
                resident_key: REQUIRED.to_owned(),
                require_resident_key: true,
                user_verification: REQUIRED.to_owned(),
            },
            attestation: "none".to_owned(),
            extensions: CreationExtensionsJson { cred_props: true },
        },
    }
}

/// Options for `get()` with user verification required. An empty `allow`
/// asks for a discoverable credential; a second prompt passes the first
/// assertion's `rawId`.
pub fn request_options(rp_id: &str, challenge: &[u8], allow: &[Vec<u8>]) -> RequestOptionsJson {
    RequestOptionsJson {
        public_key: PublicKeyRequestOptionsJson {
            challenge: B64URL.encode(challenge),
            rp_id: rp_id.to_owned(),
            allow_credentials: allow
                .iter()
                .map(|id| CredentialDescriptorJson {
                    type_: PUBLIC_KEY.to_owned(),
                    id: B64URL.encode(id),
                })
                .collect(),
            user_verification: REQUIRED.to_owned(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webauthn_recover::test_support::b64;
    use serde_json::{json, Value};
    use std::collections::HashSet;

    const RP: &str = "inblock.io";
    const CHALLENGE: [u8; 32] = [0xa5; 32];

    fn creation() -> CreationOptionsJson {
        creation_options(RP, "inblock.io", PASSKEY_USER_NAME, &CHALLENGE)
    }

    fn sorted_keys(v: &Value) -> Vec<&str> {
        let mut k: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        k.sort_unstable();
        k
    }

    fn is_b64url(s: &str) -> bool {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }

    #[test]
    fn creation_options_es256_only() {
        let v = serde_json::to_value(creation()).unwrap();
        assert_eq!(
            v["publicKey"]["pubKeyCredParams"],
            json!([{"type": "public-key", "alg": -7}])
        );
        let o = creation();
        assert_eq!(o.public_key().pub_key_cred_params.len(), 1);
        assert_eq!(o.public_key().pub_key_cred_params[0].alg, -7);
    }

    #[test]
    fn creation_options_resident_key_and_uv_required() {
        let v = serde_json::to_value(creation()).unwrap();
        let pk = &v["publicKey"];
        assert_eq!(
            pk["authenticatorSelection"],
            json!({"residentKey": "required", "requireResidentKey": true, "userVerification": "required"})
        );
        assert_eq!(pk["attestation"], "none");
        assert_eq!(pk["extensions"], json!({"credProps": true}));
    }

    #[test]
    fn creation_user_id_is_32_random_bytes_and_fresh_per_call() {
        let ids: Vec<Vec<u8>> = (0..16)
            .map(|_| B64URL.decode(&creation().public_key().user.id).unwrap())
            .collect();
        for id in &ids {
            assert_eq!(id.len(), 32);
            assert_ne!(id.as_slice(), &[0u8; 32]);
            assert_ne!(id.as_slice(), &CHALLENGE, "user.id is not the challenge");
        }
        let distinct: HashSet<&Vec<u8>> = ids.iter().collect();
        assert_eq!(distinct.len(), ids.len(), "fresh per call");
    }

    #[test]
    fn json_shape_is_public_key_envelope_with_base64url() {
        // The member names PublicKeyCredential.parseCreationOptionsFromJSON
        // and parseRequestOptionsFromJSON read, and nothing else.
        let o = creation();
        let v = serde_json::to_value(&o).unwrap();
        assert_eq!(sorted_keys(&v), ["publicKey"]);
        let pk = &v["publicKey"];
        assert_eq!(serde_json::to_value(o.public_key()).unwrap(), *pk);
        assert_eq!(
            sorted_keys(pk),
            [
                "attestation",
                "authenticatorSelection",
                "challenge",
                "extensions",
                "pubKeyCredParams",
                "rp",
                "user"
            ]
        );
        assert_eq!(pk["rp"], json!({"id": RP, "name": "inblock.io"}));
        assert_eq!(sorted_keys(&pk["user"]), ["displayName", "id", "name"]);
        assert_eq!(pk["user"]["name"], PASSKEY_USER_NAME);
        assert_eq!(pk["user"]["displayName"], PASSKEY_USER_NAME);
        let challenge = pk["challenge"].as_str().unwrap();
        assert!(is_b64url(challenge), "{challenge}");
        assert_eq!(B64URL.decode(challenge).unwrap(), CHALLENGE);
        assert!(is_b64url(pk["user"]["id"].as_str().unwrap()));

        let r = request_options(RP, &CHALLENGE, &[b"cred".to_vec()]);
        let rv = serde_json::to_value(&r).unwrap();
        assert_eq!(sorted_keys(&rv), ["publicKey"]);
        assert_eq!(
            serde_json::to_value(r.public_key()).unwrap(),
            rv["publicKey"]
        );
        assert_eq!(
            sorted_keys(&rv["publicKey"]),
            ["allowCredentials", "challenge", "rpId", "userVerification"]
        );
        // Both round-trip through their own type.
        let back: CreationOptionsJson = serde_json::from_value(v).unwrap();
        assert_eq!(back, o);
        let back: RequestOptionsJson = serde_json::from_value(rv).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn request_options_with_and_without_allow_credentials() {
        let none = request_options(RP, b"any length challenge", &[]);
        assert!(none.public_key().allow_credentials.is_empty());
        assert_eq!(
            serde_json::to_value(&none).unwrap(),
            json!({"publicKey": {
                "challenge": b64(b"any length challenge"),
                "rpId": RP,
                "userVerification": "required"
            }})
        );
        let two = request_options(RP, &CHALLENGE, &[vec![1, 2, 3], vec![0xff; 16]]);
        assert_eq!(
            serde_json::to_value(&two).unwrap(),
            json!({"publicKey": {
                "challenge": b64(&CHALLENGE),
                "rpId": RP,
                "allowCredentials": [
                    {"type": "public-key", "id": b64(&[1, 2, 3])},
                    {"type": "public-key", "id": b64(&[0xff; 16])}
                ],
                "userVerification": "required"
            }})
        );
    }
}
