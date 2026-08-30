//! Framework-agnostic renderers for the two well-known directory documents.
//!
//! Both renderers return a [`DirectoryDocument`], which is data: the path to
//! mount, the media type, the cache directive, and the serialized body. No
//! HTTP framework appears in any signature, so a service mounts these in
//! whatever router it already has instead of inheriting ours.
//!
//! # Pinned draft
//!
//! The JWKS view implements **draft-meunier-webbotauth-httpsig-directory-00**
//! (published 2026-06-26). That document replaced
//! draft-meunier-http-message-signatures-directory, whose final revision was
//! -05 (2026-03-02); the two agree on the well-known path, the media type and
//! the JWK member shape, so the rename does not change the wire format.
//!
//! From that draft, as implemented here:
//!
//! - path: `/.well-known/http-message-signatures-directory`
//! - media type: `application/http-message-signatures-directory+json`
//! - body: a JWKS, a top-level `keys` array whose members carry `kty` ("OKP"),
//!   `crv` ("Ed25519"), `kid`, `x`, `use` ("sig"), `nbf` and `exp`
//! - `kid`: "keyid MUST be a base64url JWK SHA-256 Thumbprint as defined in
//!   Section 3.2 of [JWK-THUMBPRINT]" (RFC 7638), which is
//!   [`crate::okp_thumbprint`]
//!
//! Known defect in the draft: its Appendix A.1 example prints a `kid` that is
//! not the RFC 7638 thumbprint of the `x` printed beside it. We implement the
//! normative rule, not the example, and pin our thumbprint to the RFC 8037
//! Appendix A.3 known-answer vector instead. See the test
//! `draft_appendix_a1_example_kid_does_not_match_its_own_x`.
//!
//! The draft is an expired Internet-Draft with no formal IETF standing, which
//! is exactly why this crate is versioned separately from `aqua-auth`.

use serde::Serialize;

use crate::{AdvertisedKey, DirectoryError, KeyRegistry, CRV_ED25519};

/// Well-known path for the JWKS directory.
pub const WELL_KNOWN_HTTP_MESSAGE_SIGNATURES: &str =
    "/.well-known/http-message-signatures-directory";

/// Well-known path for the Aqua-native identity document.
pub const WELL_KNOWN_AQUA_IDENTITY: &str = "/.well-known/aqua-identity";

/// Media type registered by the directory draft.
const MEDIA_TYPE_DIRECTORY: &str = "application/http-message-signatures-directory+json";

/// The Aqua-native document is ordinary JSON; it is ours, not a registered
/// interop format, so it claims no special media type.
const MEDIA_TYPE_JSON: &str = "application/json";

/// Lower bound on the advertised `max-age`.
///
/// Without a floor, a directory rendered moments before its soonest key
/// expires would tell clients to cache for a second or two, turning key
/// expiry into a refetch storm.
const MIN_CACHE_SECONDS: u64 = 60;

/// A rendered well-known document plus the HTTP metadata to serve it with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryDocument {
    /// The well-known path this document belongs at.
    pub path: &'static str,
    /// The `Content-Type` to serve it as.
    pub content_type: &'static str,
    /// The `Cache-Control` value, a `max-age` directive.
    pub cache_control: String,
    /// The serialized JSON body.
    pub body: String,
}

/// One JWK in the directory, member order matching the draft's example.
#[derive(Serialize)]
struct Jwk {
    kty: &'static str,
    crv: &'static str,
    kid: String,
    x: String,
    /// `use` is a Rust keyword, so the wire name is set explicitly.
    #[serde(rename = "use")]
    use_: &'static str,
    nbf: u64,
    exp: u64,
}

#[derive(Serialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

/// One entry in the Aqua-native identity document.
#[derive(Serialize)]
struct AquaKey {
    did: String,
    thumbprint: String,
    nbf: u64,
    exp: u64,
}

#[derive(Serialize)]
struct AquaIdentity {
    version: u32,
    dids: Vec<String>,
    keys: Vec<AquaKey>,
}

/// Cache lifetime for a set of active keys.
///
/// The directory stays accurate until its soonest-expiring key lapses, so
/// that instant is the natural expiry. A successor key in a rotation overlap
/// has an `nbf` earlier than its predecessor's `exp`, so a client that
/// refetches at that moment picks the successor up without a separate
/// staleness rule.
fn cache_seconds(active: &[&AdvertisedKey], now: u64) -> u64 {
    active
        .iter()
        .map(|k| k.exp.saturating_sub(now))
        .min()
        .unwrap_or(0)
        .max(MIN_CACHE_SECONDS)
}

fn serialize<T: Serialize>(value: &T) -> Result<String, DirectoryError> {
    serde_json::to_string(value).map_err(|e| DirectoryError::Serialization(e.to_string()))
}

/// Render the JWKS directory view for the keys active at `now`.
///
/// A registry with no active keys renders an empty `keys` array. That is a
/// truthful answer ("this service currently advertises nothing"), not an
/// error, and it keeps the endpoint's behaviour uniform for clients.
pub fn render_jwks(registry: &KeyRegistry, now: u64) -> Result<DirectoryDocument, DirectoryError> {
    let active = registry.active(now);
    let keys = active
        .iter()
        .map(|k| {
            let x = k.x_b64url()?;
            Ok(Jwk {
                kty: "OKP",
                crv: CRV_ED25519,
                kid: crate::okp_thumbprint(CRV_ED25519, &x),
                x,
                use_: "sig",
                nbf: k.nbf,
                exp: k.exp,
            })
        })
        .collect::<Result<Vec<_>, DirectoryError>>()?;

    Ok(DirectoryDocument {
        path: WELL_KNOWN_HTTP_MESSAGE_SIGNATURES,
        content_type: MEDIA_TYPE_DIRECTORY,
        cache_control: format!("max-age={}", cache_seconds(&active, now)),
        body: serialize(&Jwks { keys })?,
    })
}

/// Render the Aqua-native identity document for the keys active at `now`.
///
/// Shape: `{"version":1,"dids":[...],"keys":[{"did","thumbprint","nbf","exp"}]}`.
///
/// This view names keys by DID rather than by JWK. Aqua services already
/// resolve DIDs, so handing them a DID avoids a reverse lookup from a raw
/// key back to the principal it belongs to. `thumbprint` is carried too, so
/// a request whose signature keyid is a thumbprint (the web-bot-auth
/// spelling) can still be tied back to its DID from this one document.
pub fn render_aqua_identity(
    registry: &KeyRegistry,
    now: u64,
) -> Result<DirectoryDocument, DirectoryError> {
    let active = registry.active(now);
    let keys = active
        .iter()
        .map(|k| {
            Ok(AquaKey {
                did: k.did.clone(),
                thumbprint: k.thumbprint()?,
                nbf: k.nbf,
                exp: k.exp,
            })
        })
        .collect::<Result<Vec<_>, DirectoryError>>()?;

    Ok(DirectoryDocument {
        path: WELL_KNOWN_AQUA_IDENTITY,
        content_type: MEDIA_TYPE_JSON,
        cache_control: format!("max-age={}", cache_seconds(&active, now)),
        body: serialize(&AquaIdentity {
            version: 1,
            dids: active.iter().map(|k| k.did.clone()).collect(),
            keys,
        })?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{key, DID_A, DID_B, X_A, X_B};
    use crate::{okp_thumbprint, KeyRegistry};
    use serde_json::Value;

    fn registry(entries: &[(&str, u64, u64)]) -> KeyRegistry {
        let mut reg = KeyRegistry::new();
        for (did, nbf, exp) in entries {
            reg.add(key(did, *nbf, *exp)).unwrap();
        }
        reg
    }

    fn body(doc: &DirectoryDocument) -> Value {
        serde_json::from_str(&doc.body).expect("rendered body must be valid JSON")
    }

    /// max-age is parsed back out so the tests assert on the number, not on
    /// the exact header spelling.
    fn max_age(doc: &DirectoryDocument) -> u64 {
        doc.cache_control
            .strip_prefix("max-age=")
            .expect("cache_control must be a max-age directive")
            .parse()
            .expect("max-age must be a number")
    }

    #[test]
    fn well_known_paths_are_the_registered_ones() {
        assert_eq!(
            WELL_KNOWN_HTTP_MESSAGE_SIGNATURES,
            "/.well-known/http-message-signatures-directory"
        );
        assert_eq!(WELL_KNOWN_AQUA_IDENTITY, "/.well-known/aqua-identity");
    }

    #[test]
    fn jwks_carries_the_drafts_path_and_media_type() {
        let doc = render_jwks(&registry(&[(DID_A, 100, 200)]), 150).unwrap();
        assert_eq!(doc.path, WELL_KNOWN_HTTP_MESSAGE_SIGNATURES);
        assert_eq!(
            doc.content_type,
            "application/http-message-signatures-directory+json"
        );
    }

    #[test]
    fn jwks_body_has_the_drafts_member_shape() {
        let doc = render_jwks(&registry(&[(DID_A, 100, 200)]), 150).unwrap();
        let v = body(&doc);
        let jwk = &v["keys"][0];
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert_eq!(jwk["use"], "sig");
        assert_eq!(jwk["nbf"], 100);
        assert_eq!(jwk["exp"], 200);
        assert!(jwk["kid"].is_string());
        assert!(jwk["x"].is_string());
    }

    #[test]
    fn jwks_kid_is_the_computed_thumbprint() {
        let doc = render_jwks(&registry(&[(DID_A, 100, 200)]), 150).unwrap();
        assert_eq!(body(&doc)["keys"][0]["kid"], okp_thumbprint("Ed25519", X_A));
    }

    #[test]
    fn jwks_x_is_the_dids_raw_public_key() {
        let doc = render_jwks(&registry(&[(DID_A, 100, 200)]), 150).unwrap();
        assert_eq!(body(&doc)["keys"][0]["x"], X_A);
    }

    /// The draft's own Appendix A.1 example is internally inconsistent: the
    /// `kid` it prints is not the RFC 7638 thumbprint of the `x` it prints.
    ///
    /// We follow the draft's normative rule ("keyid MUST be a base64url JWK
    /// SHA-256 Thumbprint as defined in Section 3.2 of [JWK-THUMBPRINT]"),
    /// not its illustrative example, and our thumbprint is pinned by the
    /// RFC 8037 Appendix A.3 known-answer vector in `thumbprint.rs`.
    ///
    /// This test records the discrepancy so that a future draft revision
    /// which fixes the example forces a deliberate look rather than passing
    /// unnoticed.
    #[test]
    fn draft_appendix_a1_example_kid_does_not_match_its_own_x() {
        const DRAFT_X: &str = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs";
        const DRAFT_PRINTED_KID: &str = "NFcWBst6DXG-N35nHdzMrioWntdzNZghQSkjHNMMSjw";

        let computed = okp_thumbprint("Ed25519", DRAFT_X);
        assert_eq!(computed, "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U");
        assert_ne!(
            computed, DRAFT_PRINTED_KID,
            "draft example became self-consistent, re-check which value is right"
        );
    }

    #[test]
    fn jwks_lists_only_active_keys() {
        let reg = registry(&[(DID_A, 100, 200), (DID_B, 500, 600)]);
        let v = body(&render_jwks(&reg, 150).unwrap());
        assert_eq!(v["keys"].as_array().unwrap().len(), 1);
        assert_eq!(v["keys"][0]["x"], X_A);
    }

    #[test]
    fn jwks_lists_both_keys_during_a_rotation_overlap() {
        let reg = registry(&[(DID_A, 100, 200), (DID_B, 150, 300)]);
        let v = body(&render_jwks(&reg, 175).unwrap());
        let xs: Vec<&str> = v["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["x"].as_str().unwrap())
            .collect();
        assert_eq!(xs, vec![X_A, X_B]);
    }

    #[test]
    fn jwks_cache_control_expires_with_the_soonest_key() {
        // Soonest active exp is 200, now is 150, so 50s, lifted to the floor.
        assert_eq!(max_age(&render_jwks(&registry(&[(DID_A, 100, 200)]), 150).unwrap()), 60);
        // Soonest active exp is 10_000, now is 1_000, so 9_000s, above floor.
        let reg = registry(&[(DID_A, 0, 10_000), (DID_B, 0, 50_000)]);
        assert_eq!(max_age(&render_jwks(&reg, 1_000).unwrap()), 9_000);
    }

    #[test]
    fn jwks_cache_control_never_drops_below_the_floor() {
        // One second of validity left must not produce max-age=1.
        let reg = registry(&[(DID_A, 100, 200)]);
        assert_eq!(max_age(&render_jwks(&reg, 199).unwrap()), 60);
    }

    #[test]
    fn jwks_with_no_active_keys_renders_an_empty_list_not_an_error() {
        let reg = registry(&[(DID_A, 100, 200)]);
        let doc = render_jwks(&reg, 10_000).expect("an expired registry is still a valid document");
        assert_eq!(body(&doc)["keys"].as_array().unwrap().len(), 0);
        assert_eq!(max_age(&doc), 60);
    }

    #[test]
    fn jwks_of_an_empty_registry_renders_an_empty_list() {
        let doc = render_jwks(&KeyRegistry::new(), 100).unwrap();
        assert_eq!(body(&doc)["keys"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn aqua_identity_carries_its_path_and_plain_json_media_type() {
        let doc = render_aqua_identity(&registry(&[(DID_A, 100, 200)]), 150).unwrap();
        assert_eq!(doc.path, WELL_KNOWN_AQUA_IDENTITY);
        assert_eq!(doc.content_type, "application/json");
    }

    #[test]
    fn aqua_identity_has_the_specified_shape() {
        let reg = registry(&[(DID_A, 100, 200), (DID_B, 150, 300)]);
        let v = body(&render_aqua_identity(&reg, 175).unwrap());

        assert_eq!(v["version"], 1);
        assert_eq!(
            v["dids"].as_array().unwrap(),
            &vec![Value::from(DID_A), Value::from(DID_B)]
        );

        let entry = &v["keys"][0];
        assert_eq!(entry["did"], DID_A);
        assert_eq!(entry["thumbprint"], okp_thumbprint("Ed25519", X_A));
        assert_eq!(entry["nbf"], 100);
        assert_eq!(entry["exp"], 200);
    }

    #[test]
    fn aqua_identity_lists_only_active_keys() {
        let reg = registry(&[(DID_A, 100, 200), (DID_B, 500, 600)]);
        let v = body(&render_aqua_identity(&reg, 150).unwrap());
        assert_eq!(v["dids"].as_array().unwrap(), &vec![Value::from(DID_A)]);
        assert_eq!(v["keys"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn aqua_identity_with_no_active_keys_renders_empty_lists_not_an_error() {
        let reg = registry(&[(DID_A, 100, 200)]);
        let doc = render_aqua_identity(&reg, 10_000).expect("still a valid document");
        let v = body(&doc);
        assert_eq!(v["version"], 1);
        assert_eq!(v["dids"].as_array().unwrap().len(), 0);
        assert_eq!(v["keys"].as_array().unwrap().len(), 0);
        assert_eq!(max_age(&doc), 60);
    }

    #[test]
    fn both_views_agree_on_the_key_identity() {
        // The JWKS kid and the aqua-identity thumbprint name the same key.
        let reg = registry(&[(DID_A, 100, 200)]);
        let jwks = body(&render_jwks(&reg, 150).unwrap());
        let aqua = body(&render_aqua_identity(&reg, 150).unwrap());
        assert_eq!(jwks["keys"][0]["kid"], aqua["keys"][0]["thumbprint"]);
    }
}
