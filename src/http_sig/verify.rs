//! Verifying an RFC 9421 signature on an inbound request.
//!
//! The whole point of the profile: rebuild the signature base from the request
//! plus the declared parameters, read the signer's DID out of `keyid`, and
//! hand base and signature to [`crate::authenticate`]. That returns a
//! [`Principal`], so a verified request signature produces exactly the same
//! authenticated identity a CAIP-122 login does.
//!
//! Everything before that dispatch is validation, and it is strict on purpose.
//! Anything a caller can influence (which components are covered, which
//! parameters appear and in what order, how long the window is, which
//! application the signature was minted for) is checked against the fixed
//! profile before the signature is even looked at.

use super::base::{
    build_signature_base, check_signature_agent_coverage, signature_input_header,
    SignatureParams, ALLOWED_COMPONENTS, COMPONENT_AUTHORITY, PARAM_ORDER,
};
use super::{
    alg_for_did, unix_now, HttpSigError, RequestParts, DEFAULT_CLOCK_SKEW, MAX_VALIDITY,
    TAG_AQUA_INTERNAL, TAG_WEB_BOT_AUTH,
};
use crate::Principal;
use std::time::Duration;

/// Verification policy.
#[derive(Clone, Debug)]
pub struct VerifyOptions {
    /// The `tag` a signature must carry to be accepted here. A signature made
    /// for a different application is rejected even if it verifies
    /// cryptographically, which is what stops a signature minted for one
    /// protocol being presented to another.
    pub expected_tag: String,
    /// How far ahead of this verifier's clock a signer's `created` may be.
    pub clock_skew: Duration,
}

impl VerifyOptions {
    /// Options requiring the given `tag`, with [`DEFAULT_CLOCK_SKEW`].
    pub fn new(expected_tag: impl Into<String>) -> Self {
        Self {
            expected_tag: expected_tag.into(),
            clock_skew: DEFAULT_CLOCK_SKEW,
        }
    }

    /// Options for the Aqua-internal profile ([`TAG_AQUA_INTERNAL`]).
    pub fn aqua_internal() -> Self {
        Self::new(TAG_AQUA_INTERNAL)
    }

    /// Options for the web-bot-auth interop profile ([`TAG_WEB_BOT_AUTH`]).
    pub fn web_bot_auth() -> Self {
        Self::new(TAG_WEB_BOT_AUTH)
    }

    /// Override [`DEFAULT_CLOCK_SKEW`].
    pub fn with_clock_skew(mut self, skew: Duration) -> Self {
        self.clock_skew = skew;
        self
    }
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self::aqua_internal()
    }
}

/// Verify a request signature and return the authenticated [`Principal`].
///
/// `signature_input` and `signature` are the raw `Signature-Input` and
/// `Signature` header values. `parts` must describe the request as received,
/// since `@authority` and `signature-agent` are re-derived from it rather than
/// trusted from the headers.
///
/// # Errors
///
/// Fails if the headers are outside the profile (see the module docs), if the
/// validity window is closed or too wide, if `tag` or `alg` disagree with the
/// verifier's policy or with the DID, or if the signature does not verify.
pub fn verify_request(
    parts: &RequestParts<'_>,
    signature_input: &str,
    signature: &str,
    opts: &VerifyOptions,
) -> Result<Principal, HttpSigError> {
    verify_request_at(parts, signature_input, signature, opts, unix_now())
}

/// [`verify_request`] against an explicit clock, so tests can exercise the
/// window and skew boundaries deterministically.
pub(crate) fn verify_request_at(
    parts: &RequestParts<'_>,
    signature_input: &str,
    signature: &str,
    opts: &VerifyOptions,
    now: i64,
) -> Result<Principal, HttpSigError> {
    let (label, params) = parse_signature_input(signature_input)?;
    let signature_bytes = parse_signature(signature, &label)?;

    check_signature_agent_coverage(parts, &params.covered)?;
    check_tag(&params, opts)?;
    check_window(&params, opts, now)?;

    let alg = alg_for_did(&params.keyid)?;
    if alg != params.alg {
        return Err(HttpSigError::AlgMismatch {
            did: params.keyid.clone(),
            expected: alg.to_string(),
            actual: params.alg.clone(),
        });
    }

    // Re-serializing the parsed parameters must reproduce the header exactly.
    // If it does not, the sender used a shape this profile does not emit, and
    // the base we are about to build is not the base they signed.
    let canonical = signature_input_header(&label, &params)?;
    if canonical != signature_input.trim() {
        return Err(HttpSigError::MalformedSignatureInput(
            "Signature-Input is not in this profile's canonical form".to_string(),
        ));
    }

    let base = build_signature_base(parts, &params)?;
    Ok(crate::authenticate(&params.keyid, &base, &signature_bytes)?)
}

/// Parse `Signature-Input` into the one label and parameter set this profile
/// allows.
fn parse_signature_input(header: &str) -> Result<(String, SignatureParams), HttpSigError> {
    let dict: sfv::Dictionary = sfv::Parser::new(header)
        .parse()
        .map_err(|e| HttpSigError::MalformedSignatureInput(e.to_string()))?;

    if dict.len() != 1 {
        return Err(HttpSigError::MalformedSignatureInput(format!(
            "expected exactly one signature, found {}",
            dict.len()
        )));
    }
    let (label, entry) = dict.iter().next().expect("one member");
    let inner = match entry {
        sfv::ListEntry::InnerList(inner) => inner,
        sfv::ListEntry::Item(_) => {
            return Err(HttpSigError::MalformedSignatureInput(
                "signature parameters must be an inner list".to_string(),
            ))
        }
    };

    let mut covered = Vec::with_capacity(inner.items.len());
    for item in &inner.items {
        if !item.params.is_empty() {
            return Err(HttpSigError::MalformedSignatureInput(
                "covered components in this profile carry no parameters".to_string(),
            ));
        }
        let name = item.bare_item.as_string().ok_or_else(|| {
            HttpSigError::MalformedSignatureInput(
                "covered component names must be strings".to_string(),
            )
        })?;
        let known = ALLOWED_COMPONENTS
            .iter()
            .find(|allowed| **allowed == name.as_str())
            .ok_or_else(|| HttpSigError::UnsupportedComponent(name.as_str().to_string()))?;
        covered.push(*known);
    }
    if !covered.contains(&COMPONENT_AUTHORITY) {
        return Err(HttpSigError::MissingComponent(
            COMPONENT_AUTHORITY.to_string(),
        ));
    }

    // The parameter set and its order are fixed by the profile, so an exact
    // key sequence match is the cheapest way to reject anything else.
    let present: Vec<&str> = inner.params.keys().map(|k| k.as_str()).collect();
    if present != PARAM_ORDER {
        return Err(HttpSigError::MalformedSignatureInput(format!(
            "expected parameters {PARAM_ORDER:?} in that order, found {present:?}"
        )));
    }

    Ok((
        label.as_str().to_string(),
        SignatureParams {
            covered,
            created: integer_param(&inner.params, "created")?,
            expires: integer_param(&inner.params, "expires")?,
            keyid: string_param(&inner.params, "keyid")?,
            alg: string_param(&inner.params, "alg")?,
            nonce: string_param(&inner.params, "nonce")?,
            tag: string_param(&inner.params, "tag")?,
        },
    ))
}

fn integer_param(params: &sfv::Parameters, name: &str) -> Result<i64, HttpSigError> {
    params
        .get(name)
        .and_then(|value| value.as_integer())
        .map(i64::from)
        .ok_or_else(|| {
            HttpSigError::MalformedSignatureInput(format!("{name} must be an integer"))
        })
}

fn string_param(params: &sfv::Parameters, name: &str) -> Result<String, HttpSigError> {
    params
        .get(name)
        .and_then(|value| value.as_string())
        .map(|s| s.as_str().to_string())
        .ok_or_else(|| HttpSigError::MalformedSignatureInput(format!("{name} must be a string")))
}

/// Parse `Signature` and pull out the raw bytes stored under `label`.
fn parse_signature(header: &str, label: &str) -> Result<Vec<u8>, HttpSigError> {
    let dict: sfv::Dictionary = sfv::Parser::new(header)
        .parse()
        .map_err(|e| HttpSigError::MalformedSignature(e.to_string()))?;

    let entry = dict.get(label).ok_or_else(|| {
        HttpSigError::MalformedSignature(format!("no signature under the label {label}"))
    })?;
    match entry {
        sfv::ListEntry::Item(item) => item
            .bare_item
            .as_byte_sequence()
            .map(<[u8]>::to_vec)
            .ok_or_else(|| {
                HttpSigError::MalformedSignature("signature must be a byte sequence".to_string())
            }),
        sfv::ListEntry::InnerList(_) => Err(HttpSigError::MalformedSignature(
            "signature must be a single item".to_string(),
        )),
    }
}

fn check_tag(params: &SignatureParams, opts: &VerifyOptions) -> Result<(), HttpSigError> {
    if params.tag == opts.expected_tag {
        Ok(())
    } else {
        Err(HttpSigError::TagMismatch {
            expected: opts.expected_tag.clone(),
            actual: params.tag.clone(),
        })
    }
}

/// Enforce the validity window: `created` may not be further ahead than the
/// configured skew, `expires` is exclusive, and the window itself may not
/// exceed [`MAX_VALIDITY`].
fn check_window(
    params: &SignatureParams,
    opts: &VerifyOptions,
    now: i64,
) -> Result<(), HttpSigError> {
    if params.expires <= params.created {
        return Err(HttpSigError::InvalidWindow {
            created: params.created,
            expires: params.expires,
        });
    }

    let window = params.expires - params.created;
    let max = MAX_VALIDITY.as_secs() as i64;
    if window > max {
        return Err(HttpSigError::ValidityTooLong {
            actual: window as u64,
            max: max as u64,
        });
    }

    let skew = opts.clock_skew.as_secs() as i64;
    if params.created > now.saturating_add(skew) {
        return Err(HttpSigError::CreatedInFuture {
            created: params.created,
            now,
            skew: skew as u64,
        });
    }

    if now >= params.expires {
        return Err(HttpSigError::Expired {
            expires: params.expires,
            now,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::base::{
        build_signature_base, signature_header, signature_input_header, SignatureParams,
        COMPONENT_AUTHORITY,
    };
    use super::super::sign::sign_request_at;
    use super::super::test_signers::{Ed25519TestSigner, Eip155TestSigner, P256TestSigner};
    use super::super::*;
    use super::verify_request_at;
    use crate::Signer;
    use std::time::Duration;

    const NOW: i64 = 1_700_000_000;
    const NONCE: &str = "e4ZQMcuRoxHtRnCPFdCMlBunbNbYSWTiZOGyzP7DGwc";

    fn parts() -> RequestParts<'static> {
        RequestParts::new("GET", "https://node.example.com/v1/trees")
    }

    fn params_for(did: &str, alg: &str) -> SignatureParams {
        SignatureParams {
            covered: vec![COMPONENT_AUTHORITY],
            created: NOW,
            expires: NOW + 300,
            keyid: did.to_string(),
            alg: alg.to_string(),
            nonce: NONCE.to_string(),
            tag: TAG_AQUA_INTERNAL.to_string(),
        }
    }

    /// Sign an arbitrary `SignatureParams`, producing the two header values.
    /// Lets a test mint a signature the honest signer would refuse to make.
    async fn forge(
        signer: &dyn Signer,
        parts: &RequestParts<'_>,
        params: &SignatureParams,
    ) -> (String, String) {
        let base = build_signature_base(parts, params).unwrap();
        let sig = signer.sign(&base).await.unwrap();
        (
            signature_input_header(SIGNATURE_LABEL, params).unwrap(),
            signature_header(SIGNATURE_LABEL, &sig).unwrap(),
        )
    }

    /// Sign a hand-written signature base, for shapes the canonical builder
    /// cannot produce (reordered or extra parameters).
    async fn forge_raw(
        signer: &dyn Signer,
        authority: &str,
        params_value: &str,
    ) -> (String, String) {
        let base = format!("\"@authority\": {authority}\n\"@signature-params\": {params_value}");
        let sig = signer.sign(&base).await.unwrap();
        (
            format!("{SIGNATURE_LABEL}={params_value}"),
            signature_header(SIGNATURE_LABEL, &sig).unwrap(),
        )
    }

    // ── roundtrip ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn roundtrip_returns_the_signing_principal() {
        let signer = Ed25519TestSigner::generate();
        let headers = sign_request_at(
            &signer,
            &parts(),
            &Profile::AquaInternal,
            Duration::from_secs(300),
            NOW,
        )
        .await
        .unwrap();

        let principal = verify_request_at(
            &parts(),
            &headers.signature_input,
            &headers.signature,
            &VerifyOptions::aqua_internal(),
            NOW + 1,
        )
        .unwrap();
        assert_eq!(principal.did(), signer.signer_did());
    }

    #[tokio::test]
    async fn roundtrip_covers_the_signature_agent_header() {
        let signer = Ed25519TestSigner::generate();
        let parts = parts().with_signature_agent("\"https://directory.example.com\"");
        let headers = sign_request_at(
            &signer,
            &parts,
            &Profile::AquaInternal,
            Duration::from_secs(300),
            NOW,
        )
        .await
        .unwrap();

        let principal = verify_request_at(
            &parts,
            &headers.signature_input,
            &headers.signature,
            &VerifyOptions::aqua_internal(),
            NOW + 1,
        )
        .unwrap();
        assert_eq!(principal.did(), signer.signer_did());
    }

    #[tokio::test]
    async fn tampering_with_the_authority_fails() {
        let signer = Ed25519TestSigner::generate();
        let headers = sign_request_at(
            &signer,
            &parts(),
            &Profile::AquaInternal,
            Duration::from_secs(300),
            NOW,
        )
        .await
        .unwrap();

        let moved = RequestParts::new("GET", "https://evil.example.com/v1/trees");
        let err = verify_request_at(
            &moved,
            &headers.signature_input,
            &headers.signature,
            &VerifyOptions::aqua_internal(),
            NOW + 1,
        )
        .unwrap_err();
        assert!(matches!(err, HttpSigError::Crypto(_)));
    }

    // ── window enforcement ──────────────────────────────────────────────

    #[tokio::test]
    async fn created_beyond_the_clock_skew_is_rejected() {
        let signer = Ed25519TestSigner::generate();
        let headers = sign_request_at(
            &signer,
            &parts(),
            &Profile::AquaInternal,
            Duration::from_secs(300),
            NOW,
        )
        .await
        .unwrap();

        // Verifier's clock is 61s behind a 60s skew allowance.
        let err = verify_request_at(
            &parts(),
            &headers.signature_input,
            &headers.signature,
            &VerifyOptions::aqua_internal(),
            NOW - 61,
        )
        .unwrap_err();
        assert!(matches!(err, HttpSigError::CreatedInFuture { .. }));
    }

    #[tokio::test]
    async fn created_inside_the_clock_skew_is_accepted() {
        let signer = Ed25519TestSigner::generate();
        let headers = sign_request_at(
            &signer,
            &parts(),
            &Profile::AquaInternal,
            Duration::from_secs(300),
            NOW,
        )
        .await
        .unwrap();

        assert!(verify_request_at(
            &parts(),
            &headers.signature_input,
            &headers.signature,
            &VerifyOptions::aqua_internal(),
            NOW - 60,
        )
        .is_ok());
    }

    #[tokio::test]
    async fn an_expired_signature_is_rejected() {
        let signer = Ed25519TestSigner::generate();
        let headers = sign_request_at(
            &signer,
            &parts(),
            &Profile::AquaInternal,
            Duration::from_secs(300),
            NOW,
        )
        .await
        .unwrap();

        let err = verify_request_at(
            &parts(),
            &headers.signature_input,
            &headers.signature,
            &VerifyOptions::aqua_internal(),
            NOW + 300,
        )
        .unwrap_err();
        assert!(matches!(err, HttpSigError::Expired { .. }));
    }

    #[tokio::test]
    async fn expiry_is_exclusive_and_the_last_second_still_verifies() {
        let signer = Ed25519TestSigner::generate();
        let headers = sign_request_at(
            &signer,
            &parts(),
            &Profile::AquaInternal,
            Duration::from_secs(300),
            NOW,
        )
        .await
        .unwrap();

        assert!(verify_request_at(
            &parts(),
            &headers.signature_input,
            &headers.signature,
            &VerifyOptions::aqua_internal(),
            NOW + 299,
        )
        .is_ok());
    }

    #[tokio::test]
    async fn a_window_longer_than_24h_is_rejected_at_verify_time() {
        let signer = Ed25519TestSigner::generate();
        let mut params = params_for(signer.signer_did(), ALG_ED25519);
        params.expires = NOW + MAX_VALIDITY.as_secs() as i64 + 1;
        let (input, signature) = forge(&signer, &parts(), &params).await;

        let err = verify_request_at(
            &parts(),
            &input,
            &signature,
            &VerifyOptions::aqua_internal(),
            NOW + 1,
        )
        .unwrap_err();
        assert!(matches!(err, HttpSigError::ValidityTooLong { .. }));
    }

    #[tokio::test]
    async fn expires_not_after_created_is_rejected() {
        let signer = Ed25519TestSigner::generate();
        let mut params = params_for(signer.signer_did(), ALG_ED25519);
        params.expires = NOW;
        let (input, signature) = forge(&signer, &parts(), &params).await;

        let err = verify_request_at(
            &parts(),
            &input,
            &signature,
            &VerifyOptions::aqua_internal(),
            NOW,
        )
        .unwrap_err();
        assert!(matches!(err, HttpSigError::InvalidWindow { .. }));
    }

    // ── tag and alg ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn a_tag_for_another_application_is_rejected() {
        let signer = Ed25519TestSigner::generate();
        let mut params = params_for(signer.signer_did(), ALG_ED25519);
        params.tag = TAG_WEB_BOT_AUTH.to_string();
        let (input, signature) = forge(&signer, &parts(), &params).await;

        let err = verify_request_at(
            &parts(),
            &input,
            &signature,
            &VerifyOptions::aqua_internal(),
            NOW + 1,
        )
        .unwrap_err();
        assert!(matches!(err, HttpSigError::TagMismatch { .. }));
    }

    #[tokio::test]
    async fn an_alg_that_contradicts_the_did_is_rejected() {
        let signer = Ed25519TestSigner::generate();
        // Genuine Ed25519 signature, but the signature claims P-256.
        let params = params_for(signer.signer_did(), ALG_ECDSA_P256_SHA256);
        let (input, signature) = forge(&signer, &parts(), &params).await;

        let err = verify_request_at(
            &parts(),
            &input,
            &signature,
            &VerifyOptions::aqua_internal(),
            NOW + 1,
        )
        .unwrap_err();
        assert!(matches!(err, HttpSigError::AlgMismatch { .. }));
    }

    #[tokio::test]
    async fn a_keyid_that_is_not_a_known_did_is_rejected() {
        let signer = Ed25519TestSigner::generate();
        let params = params_for("did:example:not-a-real-method", ALG_ED25519);
        let (input, signature) = forge(&signer, &parts(), &params).await;

        let err = verify_request_at(
            &parts(),
            &input,
            &signature,
            &VerifyOptions::aqua_internal(),
            NOW + 1,
        )
        .unwrap_err();
        assert!(matches!(err, HttpSigError::Crypto(_)));
    }

    #[tokio::test]
    async fn swapping_the_keyid_to_another_did_fails() {
        let signer = Ed25519TestSigner::generate();
        let other = Ed25519TestSigner::generate();
        let params = params_for(signer.signer_did(), ALG_ED25519);
        let (_, signature) = forge(&signer, &parts(), &params).await;

        // Same signature, but the header now names a different key.
        let mut swapped = params.clone();
        swapped.keyid = other.signer_did().to_string();
        let input = signature_input_header(SIGNATURE_LABEL, &swapped).unwrap();

        let err = verify_request_at(
            &parts(),
            &input,
            &signature,
            &VerifyOptions::aqua_internal(),
            NOW + 1,
        )
        .unwrap_err();
        assert!(matches!(err, HttpSigError::Crypto(_)));
    }

    // ── the other two cipher suites ─────────────────────────────────────

    #[tokio::test]
    async fn p256_roundtrips() {
        let signer = P256TestSigner::generate();
        let headers = sign_request_at(
            &signer,
            &parts(),
            &Profile::AquaInternal,
            Duration::from_secs(300),
            NOW,
        )
        .await
        .unwrap();
        let principal = verify_request_at(
            &parts(),
            &headers.signature_input,
            &headers.signature,
            &VerifyOptions::aqua_internal(),
            NOW + 1,
        )
        .unwrap();
        assert_eq!(principal.did(), signer.signer_did());
    }

    #[tokio::test]
    async fn eip155_roundtrips() {
        let signer = Eip155TestSigner::generate();
        let headers = sign_request_at(
            &signer,
            &parts(),
            &Profile::AquaInternal,
            Duration::from_secs(300),
            NOW,
        )
        .await
        .unwrap();
        let principal = verify_request_at(
            &parts(),
            &headers.signature_input,
            &headers.signature,
            &VerifyOptions::aqua_internal(),
            NOW + 1,
        )
        .unwrap();
        assert_eq!(principal.did(), signer.signer_did());
    }

    // ── structural rejections ───────────────────────────────────────────

    #[tokio::test]
    async fn a_malformed_signature_length_is_rejected() {
        let signer = Ed25519TestSigner::generate();
        let headers = sign_request_at(
            &signer,
            &parts(),
            &Profile::AquaInternal,
            Duration::from_secs(300),
            NOW,
        )
        .await
        .unwrap();

        // 8 bytes is not a valid signature for any supported suite.
        let short = signature_header(SIGNATURE_LABEL, &[0u8; 8]).unwrap();
        let err = verify_request_at(
            &parts(),
            &headers.signature_input,
            &short,
            &VerifyOptions::aqua_internal(),
            NOW + 1,
        )
        .unwrap_err();
        assert!(matches!(err, HttpSigError::Crypto(_)));
    }

    #[test]
    fn unparsable_signature_input_is_rejected() {
        let err = verify_request_at(
            &parts(),
            "this is not a structured field ((((",
            "sig1=:AAAA:",
            &VerifyOptions::aqua_internal(),
            NOW,
        )
        .unwrap_err();
        assert!(matches!(err, HttpSigError::MalformedSignatureInput(_)));
    }

    #[tokio::test]
    async fn more_than_one_signature_is_rejected() {
        let signer = Ed25519TestSigner::generate();
        let headers = sign_request_at(
            &signer,
            &parts(),
            &Profile::AquaInternal,
            Duration::from_secs(300),
            NOW,
        )
        .await
        .unwrap();
        let doubled = format!(
            "{}, {}",
            headers.signature_input,
            headers.signature_input.replacen("sig1=", "sig2=", 1)
        );
        let err = verify_request_at(
            &parts(),
            &doubled,
            &headers.signature,
            &VerifyOptions::aqua_internal(),
            NOW + 1,
        )
        .unwrap_err();
        assert!(matches!(err, HttpSigError::MalformedSignatureInput(_)));
    }

    #[tokio::test]
    async fn a_signature_under_a_different_label_is_rejected() {
        let signer = Ed25519TestSigner::generate();
        let headers = sign_request_at(
            &signer,
            &parts(),
            &Profile::AquaInternal,
            Duration::from_secs(300),
            NOW,
        )
        .await
        .unwrap();
        let relabelled = headers.signature.replacen("sig1=", "other=", 1);
        let err = verify_request_at(
            &parts(),
            &headers.signature_input,
            &relabelled,
            &VerifyOptions::aqua_internal(),
            NOW + 1,
        )
        .unwrap_err();
        assert!(matches!(err, HttpSigError::MalformedSignature(_)));
    }

    #[tokio::test]
    async fn a_signature_that_is_not_a_byte_sequence_is_rejected() {
        let signer = Ed25519TestSigner::generate();
        let headers = sign_request_at(
            &signer,
            &parts(),
            &Profile::AquaInternal,
            Duration::from_secs(300),
            NOW,
        )
        .await
        .unwrap();
        let err = verify_request_at(
            &parts(),
            &headers.signature_input,
            "sig1=\"not-bytes\"",
            &VerifyOptions::aqua_internal(),
            NOW + 1,
        )
        .unwrap_err();
        assert!(matches!(err, HttpSigError::MalformedSignature(_)));
    }

    #[tokio::test]
    async fn a_covered_component_outside_the_profile_is_rejected() {
        let signer = Ed25519TestSigner::generate();
        let params_value = format!(
            "(\"@authority\" \"@method\");created={NOW};expires={};keyid=\"{}\";alg=\"ed25519\";nonce=\"{NONCE}\";tag=\"aqua-auth\"",
            NOW + 300,
            signer.signer_did()
        );
        let (input, signature) = forge_raw(&signer, "node.example.com", &params_value).await;

        let err = verify_request_at(
            &parts(),
            &input,
            &signature,
            &VerifyOptions::aqua_internal(),
            NOW + 1,
        )
        .unwrap_err();
        assert!(matches!(err, HttpSigError::UnsupportedComponent(_)));
    }

    #[tokio::test]
    async fn a_signature_that_does_not_cover_the_authority_is_rejected() {
        let signer = Ed25519TestSigner::generate();
        let params_value = format!(
            "();created={NOW};expires={};keyid=\"{}\";alg=\"ed25519\";nonce=\"{NONCE}\";tag=\"aqua-auth\"",
            NOW + 300,
            signer.signer_did()
        );
        let (input, signature) = forge_raw(&signer, "node.example.com", &params_value).await;

        let err = verify_request_at(
            &parts(),
            &input,
            &signature,
            &VerifyOptions::aqua_internal(),
            NOW + 1,
        )
        .unwrap_err();
        assert!(matches!(err, HttpSigError::MissingComponent(_)));
    }

    #[tokio::test]
    async fn parameters_out_of_canonical_order_are_rejected() {
        let signer = Ed25519TestSigner::generate();
        // keyid and expires swapped relative to the profile's fixed order.
        let params_value = format!(
            "(\"@authority\");created={NOW};keyid=\"{}\";expires={};alg=\"ed25519\";nonce=\"{NONCE}\";tag=\"aqua-auth\"",
            signer.signer_did(),
            NOW + 300
        );
        let (input, signature) = forge_raw(&signer, "node.example.com", &params_value).await;

        let err = verify_request_at(
            &parts(),
            &input,
            &signature,
            &VerifyOptions::aqua_internal(),
            NOW + 1,
        )
        .unwrap_err();
        assert!(matches!(err, HttpSigError::MalformedSignatureInput(_)));
    }

    #[tokio::test]
    async fn a_missing_parameter_is_rejected() {
        let signer = Ed25519TestSigner::generate();
        let params_value = format!(
            "(\"@authority\");created={NOW};expires={};keyid=\"{}\";alg=\"ed25519\";tag=\"aqua-auth\"",
            NOW + 300,
            signer.signer_did()
        );
        let (input, signature) = forge_raw(&signer, "node.example.com", &params_value).await;

        let err = verify_request_at(
            &parts(),
            &input,
            &signature,
            &VerifyOptions::aqua_internal(),
            NOW + 1,
        )
        .unwrap_err();
        assert!(matches!(err, HttpSigError::MalformedSignatureInput(_)));
    }

    #[tokio::test]
    async fn an_extra_parameter_is_rejected() {
        let signer = Ed25519TestSigner::generate();
        let params_value = format!(
            "(\"@authority\");created={NOW};expires={};keyid=\"{}\";alg=\"ed25519\";nonce=\"{NONCE}\";tag=\"aqua-auth\";extra=1",
            NOW + 300,
            signer.signer_did()
        );
        let (input, signature) = forge_raw(&signer, "node.example.com", &params_value).await;

        let err = verify_request_at(
            &parts(),
            &input,
            &signature,
            &VerifyOptions::aqua_internal(),
            NOW + 1,
        )
        .unwrap_err();
        assert!(matches!(err, HttpSigError::MalformedSignatureInput(_)));
    }

    #[tokio::test]
    async fn an_uncovered_signature_agent_header_is_rejected() {
        let signer = Ed25519TestSigner::generate();
        // Signed without the header, then the header is bolted on in transit.
        let headers = sign_request_at(
            &signer,
            &parts(),
            &Profile::AquaInternal,
            Duration::from_secs(300),
            NOW,
        )
        .await
        .unwrap();

        let smuggled = parts().with_signature_agent("\"https://evil.example\"");
        let err = verify_request_at(
            &smuggled,
            &headers.signature_input,
            &headers.signature,
            &VerifyOptions::aqua_internal(),
            NOW + 1,
        )
        .unwrap_err();
        assert!(matches!(err, HttpSigError::MalformedSignatureInput(_)));
    }

    #[tokio::test]
    async fn a_covered_signature_agent_that_is_absent_is_rejected() {
        let signer = Ed25519TestSigner::generate();
        let with_agent = parts().with_signature_agent("\"https://directory.example.com\"");
        let headers = sign_request_at(
            &signer,
            &with_agent,
            &Profile::AquaInternal,
            Duration::from_secs(300),
            NOW,
        )
        .await
        .unwrap();

        // Header stripped in transit; the signature still claims to cover it.
        let err = verify_request_at(
            &parts(),
            &headers.signature_input,
            &headers.signature,
            &VerifyOptions::aqua_internal(),
            NOW + 1,
        )
        .unwrap_err();
        assert!(matches!(err, HttpSigError::MissingComponent(_)));
    }

    #[tokio::test]
    async fn a_duplicate_covered_component_is_rejected() {
        let signer = Ed25519TestSigner::generate();
        let params_value = format!(
            "(\"@authority\" \"@authority\");created={NOW};expires={};keyid=\"{}\";alg=\"ed25519\";nonce=\"{NONCE}\";tag=\"aqua-auth\"",
            NOW + 300,
            signer.signer_did()
        );
        let (input, signature) = forge_raw(&signer, "node.example.com", &params_value).await;

        let err = verify_request_at(
            &parts(),
            &input,
            &signature,
            &VerifyOptions::aqua_internal(),
            NOW + 1,
        )
        .unwrap_err();
        assert!(matches!(err, HttpSigError::DuplicateComponent(_)));
    }

    // ── web-bot-auth tag acceptance ─────────────────────────────────────

    #[tokio::test]
    async fn web_bot_auth_tag_is_accepted_when_the_keyid_is_a_did() {
        // The interop profile normally carries a JWK thumbprint keyid, which
        // needs a directory to resolve. A DID keyid under the web-bot-auth tag
        // is still verifiable here, and VerifyOptions::web_bot_auth() is what
        // selects that tag.
        let signer = Ed25519TestSigner::generate();
        let mut params = params_for(signer.signer_did(), ALG_ED25519);
        params.tag = TAG_WEB_BOT_AUTH.to_string();
        let (input, signature) = forge(&signer, &parts(), &params).await;

        let principal = verify_request_at(
            &parts(),
            &input,
            &signature,
            &VerifyOptions::web_bot_auth(),
            NOW + 1,
        )
        .unwrap();
        assert_eq!(principal.did(), signer.signer_did());
    }

    #[tokio::test]
    async fn a_thumbprint_keyid_is_not_resolvable_without_a_directory() {
        let signer = Ed25519TestSigner::generate();
        let headers = sign_request_at(
            &signer,
            &parts(),
            &Profile::WebBotAuth {
                jwk_thumbprint: "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U".to_string(),
            },
            Duration::from_secs(300),
            NOW,
        )
        .await
        .unwrap();

        let err = verify_request_at(
            &parts(),
            &headers.signature_input,
            &headers.signature,
            &VerifyOptions::web_bot_auth(),
            NOW + 1,
        )
        .unwrap_err();
        assert!(matches!(err, HttpSigError::Crypto(_)));
    }

    // ── options plumbing ────────────────────────────────────────────────

    #[test]
    fn verify_options_defaults_to_the_internal_tag() {
        let opts = VerifyOptions::default();
        assert_eq!(opts.expected_tag, TAG_AQUA_INTERNAL);
        assert_eq!(opts.clock_skew, DEFAULT_CLOCK_SKEW);
    }

    #[tokio::test]
    async fn a_widened_clock_skew_admits_a_further_future_created() {
        let signer = Ed25519TestSigner::generate();
        let headers = sign_request_at(
            &signer,
            &parts(),
            &Profile::AquaInternal,
            Duration::from_secs(300),
            NOW,
        )
        .await
        .unwrap();

        let opts = VerifyOptions::aqua_internal().with_clock_skew(Duration::from_secs(600));
        assert!(verify_request_at(
            &parts(),
            &headers.signature_input,
            &headers.signature,
            &opts,
            NOW - 600,
        )
        .is_ok());
    }
}
