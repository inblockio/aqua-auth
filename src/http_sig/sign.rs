//! Producing an RFC 9421 signature for an outbound request.
//!
//! Signing is deliberately thin: pick the profile's `keyid`, `alg`, and `tag`,
//! stamp a window and a fresh nonce, build the signature base, and hand the
//! base to a [`Signer`]. All key custody stays behind that trait, so the same
//! call works for an in-memory key, a KMS, an HSM, or a wallet prompt.

use super::base::{
    build_signature_base, covered_components, signature_header, signature_input_header,
    SignatureParams,
};
use super::{
    alg_for_did, unix_now, HttpSigError, Profile, RequestParts, SignedHeaders, ALG_ED25519,
    MAX_VALIDITY, NONCE_BYTES, SIGNATURE_LABEL, TAG_AQUA_INTERNAL, TAG_WEB_BOT_AUTH,
};
use crate::Signer;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::Rng;
use std::time::Duration;

/// Sign a request, returning the `Signature-Input` and `Signature` header
/// values to attach.
///
/// The covered components are `@authority`, plus `signature-agent` when
/// `parts` carries that header. `validity` sets `expires - created` and is
/// capped at [`MAX_VALIDITY`]; RFC 9421 timestamps are whole seconds, so a
/// sub-second `validity` is rejected rather than silently rounded to a window
/// that can never verify.
///
/// # Errors
///
/// Fails if the validity window is zero or over the cap, if the target URI has
/// no usable authority, if the profile's constraints are not met (see
/// [`Profile::WebBotAuth`]), or if the signing backend fails.
pub async fn sign_request(
    signer: &dyn Signer,
    parts: &RequestParts<'_>,
    profile: &Profile,
    validity: Duration,
) -> Result<SignedHeaders, HttpSigError> {
    sign_request_at(signer, parts, profile, validity, unix_now()).await
}

/// [`sign_request`] with an explicit `created` timestamp, so tests can pin a
/// window instead of racing the wall clock.
pub(crate) async fn sign_request_at(
    signer: &dyn Signer,
    parts: &RequestParts<'_>,
    profile: &Profile,
    validity: Duration,
    created: i64,
) -> Result<SignedHeaders, HttpSigError> {
    let window = validity_seconds(validity)?;
    let did = signer.signer_did();
    let (keyid, alg, tag) = profile_parameters(profile, did)?;

    let params = SignatureParams {
        covered: covered_components(parts),
        created,
        expires: created.saturating_add(window),
        keyid,
        alg: alg.to_string(),
        nonce: generate_nonce(),
        tag: tag.to_string(),
    };

    let base = build_signature_base(parts, &params)?;
    let signature = signer
        .sign(&base)
        .await
        .map_err(|e| HttpSigError::Sign(e.to_string()))?;

    Ok(SignedHeaders {
        signature_input: signature_input_header(SIGNATURE_LABEL, &params)?,
        signature: signature_header(SIGNATURE_LABEL, &signature)?,
    })
}

/// Validate the requested window and reduce it to whole seconds.
fn validity_seconds(validity: Duration) -> Result<i64, HttpSigError> {
    let seconds = validity.as_secs();
    if seconds == 0 {
        return Err(HttpSigError::ValidityZero);
    }
    if validity > MAX_VALIDITY {
        return Err(HttpSigError::ValidityTooLong {
            actual: seconds,
            max: MAX_VALIDITY.as_secs(),
        });
    }
    Ok(seconds as i64)
}

/// The `(keyid, alg, tag)` triple a profile dictates for this DID.
fn profile_parameters(
    profile: &Profile,
    did: &str,
) -> Result<(String, &'static str, &'static str), HttpSigError> {
    match profile {
        Profile::AquaInternal => Ok((did.to_string(), alg_for_did(did)?, TAG_AQUA_INTERNAL)),
        Profile::WebBotAuth { jwk_thumbprint } => {
            // draft-meunier-web-bot-auth-architecture-05 identifies keys by JWK
            // thumbprint, and the Aqua directory crate only advertises Ed25519
            // keys, so any other curve would produce a signature no web-bot-auth
            // verifier could resolve a key for.
            if alg_for_did(did)? != ALG_ED25519 {
                return Err(HttpSigError::ProfileRequiresEd25519(did.to_string()));
            }
            let thumbprint = jwk_thumbprint.trim();
            if thumbprint.is_empty() {
                return Err(HttpSigError::EmptyThumbprint);
            }
            Ok((thumbprint.to_string(), ALG_ED25519, TAG_WEB_BOT_AUTH))
        }
    }
}

/// A fresh nonce: [`NONCE_BYTES`] random bytes, base64url without padding.
fn generate_nonce() -> String {
    let mut bytes = [0u8; NONCE_BYTES];
    rand::thread_rng().fill(&mut bytes[..]);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::super::test_signers::{Ed25519TestSigner, Eip155TestSigner, P256TestSigner};
    use super::super::*;
    use super::sign_request_at;
    use crate::Signer as _;
    use std::time::Duration;

    fn parts() -> RequestParts<'static> {
        RequestParts::new("GET", "https://node.example.com/v1/trees")
    }

    #[tokio::test]
    async fn internal_profile_puts_the_did_in_keyid() {
        let signer = Ed25519TestSigner::generate();
        let headers = sign_request(
            &signer,
            &parts(),
            &Profile::AquaInternal,
            Duration::from_secs(300),
        )
        .await
        .unwrap();

        assert!(headers
            .signature_input
            .starts_with("sig1=(\"@authority\");created="));
        assert!(headers
            .signature_input
            .contains(&format!("keyid=\"{}\"", signer.signer_did())));
        assert!(headers.signature_input.contains("alg=\"ed25519\""));
        assert!(headers.signature_input.contains("tag=\"aqua-auth\""));
        assert!(headers.signature.starts_with("sig1=:"));
        assert!(headers.signature.ends_with(':'));
    }

    #[tokio::test]
    async fn signature_verifies_against_the_rebuilt_base() {
        let signer = Ed25519TestSigner::generate();
        let created = 1_700_000_000;
        let headers = sign_request_at(
            &signer,
            &parts(),
            &Profile::AquaInternal,
            Duration::from_secs(300),
            created,
        )
        .await
        .unwrap();

        // Rebuild the base from the emitted parameters and check the signature
        // through the ordinary CAIP-122 dispatcher: no new verifier code.
        let nonce = extract_quoted(&headers.signature_input, "nonce");
        let params = base::SignatureParams {
            covered: vec![base::COMPONENT_AUTHORITY],
            created,
            expires: created + 300,
            keyid: signer.signer_did().to_string(),
            alg: ALG_ED25519.to_string(),
            nonce,
            tag: TAG_AQUA_INTERNAL.to_string(),
        };
        let expected_base = base::build_signature_base(&parts(), &params).unwrap();
        assert_eq!(
            headers.signature_input,
            format!("sig1={}", base::serialize_signature_params(&params).unwrap())
        );

        let sig = decode_signature(&headers.signature);
        assert!(crate::verify_caip122(signer.signer_did(), &expected_base, &sig).unwrap());
    }

    #[tokio::test]
    async fn created_and_expires_bracket_the_validity_window() {
        let signer = Ed25519TestSigner::generate();
        let headers = sign_request_at(
            &signer,
            &parts(),
            &Profile::AquaInternal,
            Duration::from_secs(90),
            1_700_000_000,
        )
        .await
        .unwrap();
        assert!(headers.signature_input.contains(";created=1700000000;"));
        assert!(headers.signature_input.contains(";expires=1700000090;"));
    }

    #[tokio::test]
    async fn signature_agent_header_is_brought_under_the_signature() {
        let signer = Ed25519TestSigner::generate();
        let parts = parts().with_signature_agent("\"https://directory.example.com\"");
        let headers = sign_request(
            &signer,
            &parts,
            &Profile::AquaInternal,
            Duration::from_secs(300),
        )
        .await
        .unwrap();
        assert!(headers
            .signature_input
            .starts_with("sig1=(\"@authority\" \"signature-agent\");"));
    }

    #[tokio::test]
    async fn p256_and_eip155_get_their_own_alg_names() {
        let p256_signer = P256TestSigner::generate();
        let headers = sign_request(
            &p256_signer,
            &parts(),
            &Profile::AquaInternal,
            Duration::from_secs(300),
        )
        .await
        .unwrap();
        assert!(headers
            .signature_input
            .contains("alg=\"ecdsa-p256-sha256\""));

        let eip155_signer = Eip155TestSigner::generate();
        let headers = sign_request(
            &eip155_signer,
            &parts(),
            &Profile::AquaInternal,
            Duration::from_secs(300),
        )
        .await
        .unwrap();
        assert!(headers
            .signature_input
            .contains("alg=\"eip191-secp256k1\""));
    }

    // ── validity window bounds ──────────────────────────────────────────

    #[tokio::test]
    async fn validity_over_24h_is_rejected_at_sign_time() {
        let signer = Ed25519TestSigner::generate();
        let err = sign_request(
            &signer,
            &parts(),
            &Profile::AquaInternal,
            MAX_VALIDITY + Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, HttpSigError::ValidityTooLong { .. }));
    }

    #[tokio::test]
    async fn validity_of_exactly_24h_is_accepted() {
        let signer = Ed25519TestSigner::generate();
        assert!(sign_request(&signer, &parts(), &Profile::AquaInternal, MAX_VALIDITY)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn zero_validity_is_rejected() {
        let signer = Ed25519TestSigner::generate();
        let err = sign_request(
            &signer,
            &parts(),
            &Profile::AquaInternal,
            Duration::from_secs(0),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, HttpSigError::ValidityZero));
    }

    // ── nonce ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn nonce_is_64_random_bytes_base64url_unpadded() {
        let signer = Ed25519TestSigner::generate();
        let first = sign_request(
            &signer,
            &parts(),
            &Profile::AquaInternal,
            Duration::from_secs(300),
        )
        .await
        .unwrap();
        let second = sign_request(
            &signer,
            &parts(),
            &Profile::AquaInternal,
            Duration::from_secs(300),
        )
        .await
        .unwrap();

        let a = extract_quoted(&first.signature_input, "nonce");
        let b = extract_quoted(&second.signature_input, "nonce");
        assert_ne!(a, b, "nonces must not repeat");
        assert!(!a.contains('='), "base64url must be unpadded");
        assert!(!a.contains('+') && !a.contains('/'), "must be the URL alphabet");

        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        assert_eq!(URL_SAFE_NO_PAD.decode(&a).unwrap().len(), NONCE_BYTES);
    }

    // ── web-bot-auth profile ────────────────────────────────────────────

    #[tokio::test]
    async fn web_bot_auth_uses_the_supplied_thumbprint_and_tag() {
        let signer = Ed25519TestSigner::generate();
        let profile = Profile::WebBotAuth {
            jwk_thumbprint: "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U".to_string(),
        };
        let headers = sign_request(&signer, &parts(), &profile, Duration::from_secs(300))
            .await
            .unwrap();

        assert!(headers
            .signature_input
            .contains("keyid=\"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U\""));
        assert!(headers.signature_input.contains("tag=\"web-bot-auth\""));
        assert!(headers.signature_input.contains("alg=\"ed25519\""));
        // The DID must NOT leak into a web-bot-auth signature: the thumbprint
        // is the identifier the draft specifies.
        assert!(!headers.signature_input.contains(signer.signer_did()));
    }

    #[tokio::test]
    async fn web_bot_auth_rejects_a_p256_did() {
        let signer = P256TestSigner::generate();
        let profile = Profile::WebBotAuth {
            jwk_thumbprint: "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U".to_string(),
        };
        let err = sign_request(&signer, &parts(), &profile, Duration::from_secs(300))
            .await
            .unwrap_err();
        assert!(matches!(err, HttpSigError::ProfileRequiresEd25519(_)));
    }

    #[tokio::test]
    async fn web_bot_auth_rejects_an_eip155_did() {
        let signer = Eip155TestSigner::generate();
        let profile = Profile::WebBotAuth {
            jwk_thumbprint: "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U".to_string(),
        };
        let err = sign_request(&signer, &parts(), &profile, Duration::from_secs(300))
            .await
            .unwrap_err();
        assert!(matches!(err, HttpSigError::ProfileRequiresEd25519(_)));
    }

    #[tokio::test]
    async fn web_bot_auth_rejects_an_empty_thumbprint() {
        let signer = Ed25519TestSigner::generate();
        let profile = Profile::WebBotAuth {
            jwk_thumbprint: "   ".to_string(),
        };
        let err = sign_request(&signer, &parts(), &profile, Duration::from_secs(300))
            .await
            .unwrap_err();
        assert!(matches!(err, HttpSigError::EmptyThumbprint));
    }

    #[tokio::test]
    async fn a_failing_signer_surfaces_as_a_sign_error() {
        struct Broken;
        #[async_trait::async_trait]
        impl crate::Signer for Broken {
            fn signer_did(&self) -> &str {
                "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            }
            async fn sign(&self, _message: &str) -> Result<Vec<u8>, crate::signer::SignError> {
                Err(crate::signer::SignError("hsm offline".to_string()))
            }
        }
        let err = sign_request(
            &Broken,
            &parts(),
            &Profile::AquaInternal,
            Duration::from_secs(300),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, HttpSigError::Sign(_)));
    }

    // ── helpers ─────────────────────────────────────────────────────────

    fn extract_quoted(header: &str, param: &str) -> String {
        let needle = format!(";{param}=\"");
        let start = header.find(&needle).expect("parameter present") + needle.len();
        let rest = &header[start..];
        let end = rest.find('"').expect("closing quote");
        rest[..end].to_string()
    }

    fn decode_signature(header: &str) -> Vec<u8> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let body = header
            .trim_start_matches("sig1=:")
            .trim_end_matches(':')
            .to_string();
        STANDARD.decode(body).expect("base64 signature")
    }
}
