//! RFC 9421 request signatures, exercised through the public API only.
//!
//! The unit tests inside `src/http_sig/` reach for crate-private seams (a
//! pinned clock, the signature base builder). This suite deliberately does
//! not: it drives `sign_request` / `verify_request` exactly as a consumer
//! would, and where it needs a signature the honest signer would refuse to
//! make, it rebuilds the signature base from the RFC 9421 section 2.5 rules by
//! hand rather than borrowing the crate's builder. That keeps the base
//! construction independently checked from the outside.
//!
//! Per the project verifier test policy, each of the three suites gets the
//! full set: roundtrip, wrong DID, tampered message, malformed signature.

#![cfg(feature = "http-sig")]

use aqua_auth::http_sig::{
    sign_request, verify_request, HttpSigError, NonceReplayGuard, Profile, RequestParts,
    VerifyOptions, ALG_ECDSA_P256_SHA256, ALG_ED25519, ALG_EIP191_SECP256K1, MAX_VALIDITY,
    TAG_AQUA_INTERNAL, TAG_WEB_BOT_AUTH,
};
use aqua_auth::{SignError, Signer};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::rngs::OsRng;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TARGET_URI: &str = "https://node.example.com/v1/trees";
const AUTHORITY: &str = "node.example.com";
const THUMBPRINT: &str = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";

fn parts() -> RequestParts<'static> {
    RequestParts::new("GET", TARGET_URI)
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ── local signers ───────────────────────────────────────────────────────

struct Ed25519Local {
    key: ed25519_dalek::SigningKey,
    did: String,
}

impl Ed25519Local {
    fn generate() -> Self {
        let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let mut bytes: Vec<u8> = vec![0xed, 0x01];
        bytes.extend_from_slice(key.verifying_key().as_bytes());
        let did = format!("did:key:z{}", bs58::encode(&bytes).into_string());
        assert!(
            did.starts_with("did:key:z6Mk"),
            "expected a z6Mk DID: {did}"
        );
        Self { key, did }
    }
}

#[async_trait]
impl Signer for Ed25519Local {
    fn signer_did(&self) -> &str {
        &self.did
    }
    async fn sign(&self, message: &str) -> Result<Vec<u8>, SignError> {
        use ed25519_dalek::Signer as _;
        Ok(self.key.sign(message.as_bytes()).to_bytes().to_vec())
    }
}

struct P256Local {
    key: p256::ecdsa::SigningKey,
    did: String,
}

impl P256Local {
    fn generate() -> Self {
        let key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let compressed = key.verifying_key().to_encoded_point(true);
        let mut bytes: Vec<u8> = vec![0x80, 0x24];
        bytes.extend_from_slice(compressed.as_bytes());
        let did = format!("did:key:z{}", bs58::encode(&bytes).into_string());
        assert!(did.starts_with("did:key:zDn"), "expected a zDn DID: {did}");
        Self { key, did }
    }
}

#[async_trait]
impl Signer for P256Local {
    fn signer_did(&self) -> &str {
        &self.did
    }
    async fn sign(&self, message: &str) -> Result<Vec<u8>, SignError> {
        use p256::ecdsa::signature::Signer as _;
        let sig: p256::ecdsa::Signature = self.key.sign(message.as_bytes());
        Ok(sig.to_bytes().to_vec())
    }
}

struct Eip155Local {
    key: k256::ecdsa::SigningKey,
    did: String,
}

impl Eip155Local {
    fn generate() -> Self {
        let key = k256::ecdsa::SigningKey::from(&k256::SecretKey::random(&mut OsRng));
        let address = aqua_auth::address_from_verifying_key(key.verifying_key());
        let did = format!("did:pkh:eip155:1:0x{}", aqua_auth::eip55_checksum(&address));
        Self { key, did }
    }
}

#[async_trait]
impl Signer for Eip155Local {
    fn signer_did(&self) -> &str {
        &self.did
    }
    async fn sign(&self, message: &str) -> Result<Vec<u8>, SignError> {
        use sha3::{Digest, Keccak256};
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let prehash: [u8; 32] = {
            let mut hasher = Keccak256::new();
            hasher.update(prefix.as_bytes());
            hasher.update(message.as_bytes());
            hasher.finalize().into()
        };
        let (sig, rec_id) = self
            .key
            .sign_prehash_recoverable(&prehash)
            .map_err(|e| SignError(e.to_string()))?;
        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(&sig.to_bytes());
        out.push(u8::from(rec_id) + 27);
        Ok(out)
    }
}

// ── independent signature base construction (RFC 9421 section 2.5) ──────

/// The `@signature-params` inner list, written out longhand.
fn params_value(
    created: i64,
    expires: i64,
    keyid: &str,
    alg: &str,
    nonce: &str,
    tag: &str,
) -> String {
    format!(
        "(\"@authority\");created={created};expires={expires};keyid=\"{keyid}\";alg=\"{alg}\";nonce=\"{nonce}\";tag=\"{tag}\""
    )
}

/// One covered component line, then the params line, joined by a newline with
/// no trailing newline.
fn signature_base(authority: &str, params_value: &str) -> String {
    format!("\"@authority\": {authority}\n\"@signature-params\": {params_value}")
}

/// Mint the two header values for an arbitrary parameter set.
async fn forge(signer: &dyn Signer, params_value: &str) -> (String, String) {
    let base = signature_base(AUTHORITY, params_value);
    let signature = signer.sign(&base).await.unwrap();
    (
        format!("sig1={params_value}"),
        format!("sig1=:{}:", STANDARD.encode(signature)),
    )
}

fn signature_header(bytes: &[u8]) -> String {
    format!("sig1=:{}:", STANDARD.encode(bytes))
}

// ── per-suite matrix: roundtrip, wrong DID, tampered, malformed ─────────

/// Sign, verify, and assert the returned `Principal` names the signing DID.
async fn assert_roundtrip(signer: &dyn Signer, expected_alg: &str) {
    let headers = sign_request(
        signer,
        &parts(),
        &Profile::AquaInternal,
        Duration::from_secs(300),
    )
    .await
    .unwrap();
    assert!(
        headers
            .signature_input
            .contains(&format!("alg=\"{expected_alg}\"")),
        "expected alg {expected_alg} in {}",
        headers.signature_input
    );

    let principal = verify_request(
        &parts(),
        &headers.signature_input,
        &headers.signature,
        &VerifyOptions::aqua_internal(),
    )
    .unwrap();
    assert_eq!(principal.did(), signer.signer_did());
}

/// A valid signature presented under a different DID of the same method.
async fn assert_wrong_did_fails(signer: &dyn Signer, other: &dyn Signer) {
    let headers = sign_request(
        signer,
        &parts(),
        &Profile::AquaInternal,
        Duration::from_secs(300),
    )
    .await
    .unwrap();
    let swapped = headers
        .signature_input
        .replace(signer.signer_did(), other.signer_did());
    assert_ne!(swapped, headers.signature_input, "keyid was not swapped");

    let err = verify_request(
        &parts(),
        &swapped,
        &headers.signature,
        &VerifyOptions::aqua_internal(),
    )
    .unwrap_err();
    assert!(matches!(err, HttpSigError::Crypto(_)), "got {err:?}");
}

/// The same signature replayed against a different authority.
async fn assert_tampered_authority_fails(signer: &dyn Signer) {
    let headers = sign_request(
        signer,
        &parts(),
        &Profile::AquaInternal,
        Duration::from_secs(300),
    )
    .await
    .unwrap();

    let moved = RequestParts::new("GET", "https://evil.example.com/v1/trees");
    let err = verify_request(
        &moved,
        &headers.signature_input,
        &headers.signature,
        &VerifyOptions::aqua_internal(),
    )
    .unwrap_err();
    assert!(matches!(err, HttpSigError::Crypto(_)), "got {err:?}");
}

/// A signature of the wrong length for any supported suite.
async fn assert_malformed_signature_fails(signer: &dyn Signer) {
    let headers = sign_request(
        signer,
        &parts(),
        &Profile::AquaInternal,
        Duration::from_secs(300),
    )
    .await
    .unwrap();

    let err = verify_request(
        &parts(),
        &headers.signature_input,
        &signature_header(&[0u8; 8]),
        &VerifyOptions::aqua_internal(),
    )
    .unwrap_err();
    assert!(matches!(err, HttpSigError::Crypto(_)), "got {err:?}");
}

#[tokio::test]
async fn ed25519_did_key_full_matrix() {
    let signer = Ed25519Local::generate();
    let other = Ed25519Local::generate();
    assert_roundtrip(&signer, ALG_ED25519).await;
    assert_wrong_did_fails(&signer, &other).await;
    assert_tampered_authority_fails(&signer).await;
    assert_malformed_signature_fails(&signer).await;
}

#[tokio::test]
async fn p256_did_key_full_matrix() {
    let signer = P256Local::generate();
    let other = P256Local::generate();
    assert_roundtrip(&signer, ALG_ECDSA_P256_SHA256).await;
    assert_wrong_did_fails(&signer, &other).await;
    assert_tampered_authority_fails(&signer).await;
    assert_malformed_signature_fails(&signer).await;
}

#[tokio::test]
async fn eip155_did_pkh_full_matrix() {
    let signer = Eip155Local::generate();
    let other = Eip155Local::generate();
    assert_roundtrip(&signer, ALG_EIP191_SECP256K1).await;
    assert_wrong_did_fails(&signer, &other).await;
    assert_tampered_authority_fails(&signer).await;
    assert_malformed_signature_fails(&signer).await;
}

#[tokio::test]
async fn the_signature_agent_header_roundtrips_when_present() {
    let signer = Ed25519Local::generate();
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

    let principal = verify_request(
        &parts,
        &headers.signature_input,
        &headers.signature,
        &VerifyOptions::aqua_internal(),
    )
    .unwrap();
    assert_eq!(principal.did(), signer.signer_did());
}

// ── replay ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_same_nonce_is_refused_the_second_time() {
    let signer = Ed25519Local::generate();
    let headers = sign_request(
        &signer,
        &parts(),
        &Profile::AquaInternal,
        Duration::from_secs(300),
    )
    .await
    .unwrap();

    let opts = VerifyOptions::aqua_internal().with_replay_guard(Arc::new(NonceReplayGuard::new()));

    assert!(verify_request(
        &parts(),
        &headers.signature_input,
        &headers.signature,
        &opts
    )
    .is_ok());
    let err = verify_request(
        &parts(),
        &headers.signature_input,
        &headers.signature,
        &opts,
    )
    .unwrap_err();
    assert!(matches!(err, HttpSigError::NonceReplayed), "got {err:?}");
}

// ── validity window ─────────────────────────────────────────────────────

#[tokio::test]
async fn an_expired_window_fails() {
    let signer = Ed25519Local::generate();
    let created = now() - 3600;
    let value = params_value(
        created,
        created + 300,
        signer.signer_did(),
        ALG_ED25519,
        "expired-window-nonce",
        TAG_AQUA_INTERNAL,
    );
    let (input, signature) = forge(&signer, &value).await;

    let err = verify_request(
        &parts(),
        &input,
        &signature,
        &VerifyOptions::aqua_internal(),
    )
    .unwrap_err();
    assert!(matches!(err, HttpSigError::Expired { .. }), "got {err:?}");
}

#[tokio::test]
async fn a_created_beyond_the_clock_skew_fails() {
    let signer = Ed25519Local::generate();
    let created = now() + 3600;
    let value = params_value(
        created,
        created + 300,
        signer.signer_did(),
        ALG_ED25519,
        "future-created-nonce",
        TAG_AQUA_INTERNAL,
    );
    let (input, signature) = forge(&signer, &value).await;

    let err = verify_request(
        &parts(),
        &input,
        &signature,
        &VerifyOptions::aqua_internal(),
    )
    .unwrap_err();
    assert!(
        matches!(err, HttpSigError::CreatedInFuture { .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn a_validity_over_24h_is_rejected_at_sign_time() {
    let signer = Ed25519Local::generate();
    let err = sign_request(
        &signer,
        &parts(),
        &Profile::AquaInternal,
        MAX_VALIDITY + Duration::from_secs(1),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, HttpSigError::ValidityTooLong { .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn a_window_over_24h_is_also_rejected_at_verify_time() {
    // Signing caps the window, so a wide one can only arrive from a peer that
    // ignored the cap. The verifier must not take its word for it.
    let signer = Ed25519Local::generate();
    let created = now();
    let value = params_value(
        created,
        created + MAX_VALIDITY.as_secs() as i64 + 1,
        signer.signer_did(),
        ALG_ED25519,
        "wide-window-nonce",
        TAG_AQUA_INTERNAL,
    );
    let (input, signature) = forge(&signer, &value).await;

    let err = verify_request(
        &parts(),
        &input,
        &signature,
        &VerifyOptions::aqua_internal(),
    )
    .unwrap_err();
    assert!(
        matches!(err, HttpSigError::ValidityTooLong { .. }),
        "got {err:?}"
    );
}

// ── alg and tag ─────────────────────────────────────────────────────────

#[tokio::test]
async fn an_alg_that_contradicts_the_did_fails() {
    let signer = Ed25519Local::generate();
    let created = now();
    let value = params_value(
        created,
        created + 300,
        signer.signer_did(),
        ALG_ECDSA_P256_SHA256,
        "alg-mismatch-nonce",
        TAG_AQUA_INTERNAL,
    );
    let (input, signature) = forge(&signer, &value).await;

    let err = verify_request(
        &parts(),
        &input,
        &signature,
        &VerifyOptions::aqua_internal(),
    )
    .unwrap_err();
    assert!(
        matches!(err, HttpSigError::AlgMismatch { .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn a_signature_tagged_for_another_application_fails() {
    let signer = Ed25519Local::generate();
    let created = now();
    let value = params_value(
        created,
        created + 300,
        signer.signer_did(),
        ALG_ED25519,
        "tag-mismatch-nonce",
        TAG_WEB_BOT_AUTH,
    );
    let (input, signature) = forge(&signer, &value).await;

    let err = verify_request(
        &parts(),
        &input,
        &signature,
        &VerifyOptions::aqua_internal(),
    )
    .unwrap_err();
    assert!(
        matches!(err, HttpSigError::TagMismatch { .. }),
        "got {err:?}"
    );
}

// ── web-bot-auth interop profile ────────────────────────────────────────

#[tokio::test]
async fn web_bot_auth_ed25519_roundtrips() {
    let signer = Ed25519Local::generate();
    let headers = sign_request(
        &signer,
        &parts(),
        &Profile::WebBotAuth {
            jwk_thumbprint: THUMBPRINT.to_string(),
        },
        Duration::from_secs(300),
    )
    .await
    .unwrap();

    assert!(headers
        .signature_input
        .contains(&format!("keyid=\"{THUMBPRINT}\"")));
    assert!(headers
        .signature_input
        .contains(&format!("tag=\"{TAG_WEB_BOT_AUTH}\"")));
    assert!(headers.signature_input.contains("alg=\"ed25519\""));
    assert!(!headers.signature_input.contains(signer.signer_did()));

    // The crypto closes: rebuild the base independently and check the
    // signature with the ordinary CAIP-122 verifier. Resolving the thumbprint
    // back to a key is a directory's job, not this crate's, which is why
    // verify_request cannot complete this profile on its own.
    let value = headers.signature_input.trim_start_matches("sig1=");
    let base = signature_base(AUTHORITY, value);
    let bytes = STANDARD
        .decode(
            headers
                .signature
                .trim_start_matches("sig1=:")
                .trim_end_matches(':'),
        )
        .unwrap();
    assert!(aqua_auth::verify_caip122(signer.signer_did(), &base, &bytes).unwrap());
}

#[tokio::test]
async fn web_bot_auth_rejects_non_ed25519_dids() {
    let profile = Profile::WebBotAuth {
        jwk_thumbprint: THUMBPRINT.to_string(),
    };

    let p256 = P256Local::generate();
    let err = sign_request(&p256, &parts(), &profile, Duration::from_secs(300))
        .await
        .unwrap_err();
    assert!(
        matches!(err, HttpSigError::ProfileRequiresEd25519(_)),
        "got {err:?}"
    );

    let eip155 = Eip155Local::generate();
    let err = sign_request(&eip155, &parts(), &profile, Duration::from_secs(300))
        .await
        .unwrap_err();
    assert!(
        matches!(err, HttpSigError::ProfileRequiresEd25519(_)),
        "got {err:?}"
    );
}

#[tokio::test]
async fn a_thumbprint_keyid_needs_a_directory_to_verify() {
    // Documented limitation, pinned so it cannot regress into a silent accept.
    let signer = Ed25519Local::generate();
    let headers = sign_request(
        &signer,
        &parts(),
        &Profile::WebBotAuth {
            jwk_thumbprint: THUMBPRINT.to_string(),
        },
        Duration::from_secs(300),
    )
    .await
    .unwrap();

    let err = verify_request(
        &parts(),
        &headers.signature_input,
        &headers.signature,
        &VerifyOptions::web_bot_auth(),
    )
    .unwrap_err();
    assert!(matches!(err, HttpSigError::Crypto(_)), "got {err:?}");
}

// ── the signature base is what the RFC says it is ───────────────────────

#[tokio::test]
async fn the_signed_base_matches_an_independently_built_one() {
    // If this passes, the crate's base construction agrees with a base written
    // out longhand from RFC 9421 section 2.5 by a separate crate.
    let signer = Ed25519Local::generate();
    let headers = sign_request(
        &signer,
        &parts(),
        &Profile::AquaInternal,
        Duration::from_secs(300),
    )
    .await
    .unwrap();

    let value = headers.signature_input.trim_start_matches("sig1=");
    let base = signature_base(AUTHORITY, value);
    let bytes = STANDARD
        .decode(
            headers
                .signature
                .trim_start_matches("sig1=:")
                .trim_end_matches(':'),
        )
        .unwrap();
    assert!(aqua_auth::verify_caip122(signer.signer_did(), &base, &bytes).unwrap());
    assert!(
        !base.ends_with('\n'),
        "the base must not end with a newline"
    );
}
