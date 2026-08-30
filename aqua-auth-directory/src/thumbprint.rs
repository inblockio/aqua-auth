//! RFC 7638 JWK thumbprints for OKP (Ed25519) keys.
//!
//! The thumbprint is the base64url (unpadded) SHA-256 digest of the JWK's
//! canonical form: only the members required to identify the key, sorted
//! lexicographically, serialized with no whitespace. For an OKP key those
//! members are `crv`, `kty` and `x` (RFC 8037 section 2), which is already
//! lexicographic order.
//!
//! SHA-256 is correct here and is not an oversight. The project's SHA3-256
//! rule is an aqua-tree invariant; RFC 7638 mandates SHA-256, and the
//! thumbprint has to match what other implementations compute or it is
//! useless as a `kid`.
//!
//! Known-answer vector: RFC 8037 Appendix A.3.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};

/// Serialize the canonical RFC 7638 JWK for an OKP public key.
///
/// Built by hand rather than through `serde_json` because the canonical form
/// is defined by the byte sequence, not by a JSON value: member order and the
/// absence of whitespace are load-bearing. A map-based serializer would leave
/// that to chance.
///
/// `x_b64url` is the raw public key already in base64url, which is how it
/// appears in the JWK itself.
pub(crate) fn canonical_okp_jwk(crv: &str, x_b64url: &str) -> String {
    format!(r#"{{"crv":"{crv}","kty":"OKP","x":"{x_b64url}"}}"#)
}

/// RFC 7638 thumbprint of an OKP public key, base64url encoded without padding.
///
/// This is the `kid` advertised in the JWKS directory and the `keyid` a
/// web-bot-auth signature carries.
pub fn okp_thumbprint(crv: &str, x_b64url: &str) -> String {
    let digest = Sha256::digest(canonical_okp_jwk(crv, x_b64url).as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8037 Appendix A.3 known-answer vector (fetched and confirmed
    /// against rfc-editor.org before being hardcoded).
    ///
    /// JWK:            {"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
    /// SHA-256 (hex):  90facafea9b1556698540f70c0117a22ea37bd5cf3ed3c47093c1707282b4b89
    /// Thumbprint:     kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k
    #[test]
    fn rfc8037_appendix_a3_vector() {
        assert_eq!(
            okp_thumbprint("Ed25519", "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }

    /// The hashed input must be the canonical form: the three required OKP
    /// members in lexicographic order, no whitespace, no other members.
    #[test]
    fn canonical_jwk_is_lexicographic_and_unspaced() {
        assert_eq!(
            canonical_okp_jwk("Ed25519", "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"),
            r#"{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#
        );
    }

    /// Thumbprints are base64url without padding, so no '=', '+' or '/'.
    #[test]
    fn thumbprint_is_unpadded_base64url() {
        let tp = okp_thumbprint("Ed25519", "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
        assert_eq!(tp.len(), 43, "SHA-256 in unpadded base64url is 43 chars");
        assert!(!tp.contains('='), "{tp}");
        assert!(!tp.contains('+'), "{tp}");
        assert!(!tp.contains('/'), "{tp}");
    }

    /// Distinct keys must not collide.
    #[test]
    fn different_x_yields_different_thumbprint() {
        let a = okp_thumbprint("Ed25519", "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
        let b = okp_thumbprint("Ed25519", "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs");
        assert_ne!(a, b);
    }
}
