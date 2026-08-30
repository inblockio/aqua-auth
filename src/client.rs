//! Client helpers for CAIP-122 authentication (behind `client` feature flag).
//!
//! Provides a simple `authenticate()` function that runs the full
//! challenge-response flow against an aqua-node endpoint.

use crate::auth_error::AuthError;
use crate::did::identifier_from_message;
use crate::did_method::find_did_method;
use crate::types::Session;
use crate::wire::{ChallengeEnvelope, SessionRequest, SessionResponse};

/// Run the full CAIP-122 challenge-response flow.
///
/// Wire contract: `GET /auth/challenge?did=<did>` returns [`ChallengeEnvelope`]
/// (no `did` field; the server omits it because the client supplied the DID in
/// the query string). `POST /auth/session` accepts [`SessionRequest`] and
/// returns [`SessionResponse`]. Both are defined in [`crate::wire`].
///
/// 1. `GET /auth/challenge?did=<did>` -- obtain a [`ChallengeEnvelope`]
/// 2. Sign the challenge message using the provided `sign_fn`
/// 3. `POST /auth/session` -- exchange signed challenge for a [`SessionResponse`],
///    translated into the internal [`Session`] type for callers
///
/// The `sign_fn` takes the canonical CAIP-122 message and returns
/// the hex-encoded signature (with or without `0x` prefix).
///
/// # Challenge binding
///
/// Before signing, the returned message is checked against what the client
/// asked for: its identifier line must match the identifier derived from
/// `did`, and its `URI:` line must have the same origin as `base_url` (scheme,
/// host, port; paths ignored). Either mismatch refuses to sign. This kills the
/// relay: a compromised endpoint that forwards a challenge minted for another
/// aqua service presents a message whose URI origin is that service's, not the
/// origin the client dialed, so the client never signs it. The `domain` line is
/// not enforced, because it is a free-form label (deployed servers use
/// non-hostnames such as `aqua-node`).
pub async fn authenticate<F>(
    http: &reqwest::Client,
    base_url: &str,
    did: &str,
    sign_fn: F,
) -> Result<Session, AuthClientError>
where
    F: FnOnce(&str) -> Result<String, Box<dyn std::error::Error + Send + Sync>>,
{
    // 1. Request challenge
    let challenge_url = format!("{base_url}/auth/challenge?did={}", urlencoded(did));
    let envelope: ChallengeEnvelope = http
        .get(&challenge_url)
        .send()
        .await
        .map_err(AuthClientError::Http)?
        .error_for_status()
        .map_err(AuthClientError::Http)?
        .json()
        .await
        .map_err(AuthClientError::Http)?;

    // 1a. Defense in depth: verify the identifier embedded in the SIWE
    //     message matches the identifier derived from the requested DID.
    let method = find_did_method(did).ok_or_else(|| {
        AuthClientError::Auth(
            crate::crypto_error::CryptoError::UnsupportedMethod(did.to_string()).into(),
        )
    })?;
    let expected = method
        .address_for_message(did)
        .map_err(|e| AuthClientError::Auth(e.into()))?;
    let actual = identifier_from_message(&envelope.message).ok_or_else(|| {
        AuthClientError::MessageIdentifierMismatch {
            expected: expected.clone(),
            actual: "<message missing identifier line>".to_string(),
        }
    })?;
    if actual != expected {
        return Err(AuthClientError::MessageIdentifierMismatch {
            expected,
            actual: actual.to_string(),
        });
    }

    // 1b. Bind the challenge to the endpoint we actually dialed: the message's
    //     URI origin must be ours, or a relayed challenge would get signed.
    verify_uri_binding(&envelope.message, base_url)?;

    // 2. Sign the message
    let signature = sign_fn(&envelope.message).map_err(|e| AuthClientError::Sign(e.to_string()))?;

    // 3. Exchange for session
    let session_url = format!("{base_url}/auth/session");
    let req = SessionRequest {
        did: did.to_string(),
        nonce: envelope.nonce,
        signature,
    };

    let resp: SessionResponse = http
        .post(&session_url)
        .json(&req)
        .send()
        .await
        .map_err(AuthClientError::Http)?
        .error_for_status()
        .map_err(AuthClientError::Http)?
        .json()
        .await
        .map_err(AuthClientError::Http)?;

    Ok(Session {
        did: resp.did,
        token: resp.token,
        valid_until: resp.valid_until,
        created_at: resp.created_at,
    })
}

/// Minimal URL encoding for the DID (colons are safe in query values but
/// let's be conservative).
fn urlencoded(s: &str) -> String {
    s.replace(':', "%3A")
}

/// Require the challenge message to be bound to the endpoint the client dialed.
///
/// Extracts the `URI:` line from the CAIP-122 message and compares its origin
/// (scheme, lowercased host, port with default-port normalization) against the
/// origin of `base_url`. Paths, query strings and fragments are ignored on both
/// sides: only the origin is load-bearing.
///
/// Fails closed. A missing `URI:` line, an empty value, a URI that does not
/// parse, a URI with no host (e.g. `file:///x`), or an unparsable `base_url`
/// all yield [`AuthClientError::UriOriginMismatch`] rather than a pass.
///
/// The free-form `domain` line (the first line of the message) is deliberately
/// NOT enforced: deployed servers set it to a service label such as
/// `aqua-node` rather than a hostname, so it carries no origin to compare.
fn verify_uri_binding(message: &str, base_url: &str) -> Result<(), AuthClientError> {
    let client_origin =
        origin_of(base_url).unwrap_or_else(|| format!("<unparsable base_url: {base_url}>"));

    let message_origin = match uri_line(message) {
        None => "<message missing URI line>".to_string(),
        Some(uri) => match origin_of(uri) {
            Some(origin) => origin,
            None => format!("<unparsable URI line: {uri}>"),
        },
    };

    // The placeholders are distinct from each other and from every real origin
    // (no origin starts with `<`), so any failure case above lands here as a
    // mismatch, even when both sides carry the same unparsable text. The check
    // fails closed by construction rather than by a separate branch.
    if message_origin == client_origin {
        Ok(())
    } else {
        Err(AuthClientError::UriOriginMismatch {
            message_origin,
            client_origin,
        })
    }
}

/// Value of the `URI: ` line of a CAIP-122 message, if present and non-empty.
///
/// The prefix must start the line, as CAIP-122 and SIWE specify. Matching an
/// indented occurrence would let the free-form statement block shadow the real
/// header line, so anything else fails closed.
fn uri_line(message: &str) -> Option<&str> {
    message
        .split('\n')
        .find_map(|line| line.trim_end_matches('\r').strip_prefix("URI:"))
        .map(str::trim)
        .filter(|uri| !uri.is_empty())
}

/// Canonical `scheme://host[:port]` origin, with the scheme's default port made
/// explicit so `https://x` and `https://x:443` compare equal.
fn origin_of(raw: &str) -> Option<String> {
    let url = url::Url::parse(raw).ok()?;
    let scheme = url.scheme().to_ascii_lowercase();
    let host = url.host_str()?.to_ascii_lowercase();
    match url.port_or_known_default() {
        Some(port) => Some(format!("{scheme}://{host}:{port}")),
        None => Some(format!("{scheme}://{host}")),
    }
}

/// Errors from the client authentication flow.
#[derive(Debug, thiserror::Error)]
pub enum AuthClientError {
    #[error("HTTP error: {0}")]
    Http(reqwest::Error),
    #[error("signing error: {0}")]
    Sign(String),
    #[error("auth error: {0}")]
    Auth(#[from] AuthError),
    #[error("server message identifier mismatch: expected {expected}, got {actual}")]
    MessageIdentifierMismatch { expected: String, actual: String },
    #[error("challenge URI origin mismatch: message says {message_origin}, client dialed {client_origin}")]
    UriOriginMismatch {
        message_origin: String,
        client_origin: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal CAIP-122 message carrying the given `URI:` line.
    fn message_with_uri(uri: &str) -> String {
        format!(
            "aqua-node wants you to sign in with your Ed25519 account:\n\
             0xaabb\n\
             \n\
             Sign in to Aqua Node\n\
             \n\
             URI: {uri}\n\
             Version: 1\n\
             Nonce: 0xdeadbeef\n\
             Issued At: 2026-08-30T12:00:00.000Z\n\
             Expiration Time: 2026-08-30T12:05:00.000Z"
        )
    }

    fn assert_mismatch(result: Result<(), AuthClientError>) {
        match result {
            Err(AuthClientError::UriOriginMismatch { .. }) => {}
            other => panic!("expected UriOriginMismatch, got {other:?}"),
        }
    }

    #[test]
    fn uri_binding_same_origin_passes() {
        let msg = message_with_uri("https://timestamp.inblock.io");
        assert!(verify_uri_binding(&msg, "https://timestamp.inblock.io").is_ok());
    }

    #[test]
    fn uri_binding_ignores_trailing_slash_and_path_on_base_url() {
        let msg = message_with_uri("http://127.0.0.1:3000");
        assert!(verify_uri_binding(&msg, "http://127.0.0.1:3000/").is_ok());
        assert!(verify_uri_binding(&msg, "http://127.0.0.1:3000/api/v1").is_ok());
        assert!(verify_uri_binding(&msg, "http://127.0.0.1:3000/api?x=1#frag").is_ok());
    }

    #[test]
    fn uri_binding_ignores_path_on_message_uri() {
        let msg = message_with_uri("http://127.0.0.1:3000/auth/challenge");
        assert!(verify_uri_binding(&msg, "http://127.0.0.1:3000").is_ok());
    }

    #[test]
    fn uri_binding_host_comparison_is_case_insensitive() {
        let msg = message_with_uri("https://Timestamp.INBLOCK.io");
        assert!(verify_uri_binding(&msg, "https://timestamp.inblock.io").is_ok());
    }

    #[test]
    fn uri_binding_tolerates_crlf_line_endings() {
        let msg = message_with_uri("https://timestamp.inblock.io").replace('\n', "\r\n");
        assert!(verify_uri_binding(&msg, "https://timestamp.inblock.io").is_ok());
    }

    #[test]
    fn uri_binding_different_host_fails() {
        // The relay case: a compromised endpoint hands back a challenge minted
        // for a different service.
        let msg = message_with_uri("https://victim.example");
        let err = verify_uri_binding(&msg, "https://relay.example").unwrap_err();
        match err {
            AuthClientError::UriOriginMismatch {
                message_origin,
                client_origin,
            } => {
                assert_eq!(message_origin, "https://victim.example:443");
                assert_eq!(client_origin, "https://relay.example:443");
            }
            other => panic!("expected UriOriginMismatch, got {other:?}"),
        }
    }

    #[test]
    fn uri_binding_different_port_fails() {
        let msg = message_with_uri("http://127.0.0.1:3000");
        assert_mismatch(verify_uri_binding(&msg, "http://127.0.0.1:3001"));
    }

    #[test]
    fn uri_binding_different_scheme_fails() {
        let msg = message_with_uri("https://example.com:8443");
        assert_mismatch(verify_uri_binding(&msg, "http://example.com:8443"));
    }

    #[test]
    fn uri_binding_explicit_https_port_equals_default() {
        let msg = message_with_uri("https://example.com:443");
        assert!(verify_uri_binding(&msg, "https://example.com").is_ok());

        let msg = message_with_uri("https://example.com");
        assert!(verify_uri_binding(&msg, "https://example.com:443/").is_ok());
    }

    #[test]
    fn uri_binding_explicit_http_port_equals_default() {
        let msg = message_with_uri("http://example.com:80");
        assert!(verify_uri_binding(&msg, "http://example.com").is_ok());
    }

    #[test]
    fn uri_binding_missing_uri_line_fails_closed() {
        let msg = "aqua-node wants you to sign in with your Ed25519 account:\n\
                   0xaabb\n\
                   \n\
                   Sign in to Aqua Node\n\
                   \n\
                   Version: 1\n\
                   Nonce: 0xdeadbeef";
        assert_mismatch(verify_uri_binding(msg, "https://example.com"));
    }

    #[test]
    fn uri_binding_empty_uri_value_fails_closed() {
        let msg = message_with_uri("");
        assert_mismatch(verify_uri_binding(&msg, "https://example.com"));
    }

    #[test]
    fn uri_binding_malformed_message_uri_fails_closed() {
        let msg = message_with_uri("not-a-url");
        assert_mismatch(verify_uri_binding(&msg, "https://example.com"));
    }

    #[test]
    fn uri_binding_message_uri_without_host_fails_closed() {
        let msg = message_with_uri("file:///etc/passwd");
        assert_mismatch(verify_uri_binding(&msg, "https://example.com"));
    }

    #[test]
    fn uri_binding_indented_uri_line_does_not_count() {
        // Only a line that starts with `URI:` is the header line; an indented
        // one lives in the free-form statement block and must not satisfy the
        // check.
        // Written on one line: a trailing `\` in a Rust string literal also
        // eats the next line's leading whitespace, which would defeat the test.
        let msg = "aqua-node wants you to sign in with your Ed25519 account:\n0xaabb\n\n  URI: https://example.com\n\nVersion: 1";
        assert_mismatch(verify_uri_binding(msg, "https://example.com"));
    }

    #[test]
    fn uri_binding_malformed_base_url_fails_closed() {
        let msg = message_with_uri("https://example.com");
        assert_mismatch(verify_uri_binding(&msg, "example.com:3000"));
    }

    #[test]
    fn uri_binding_identical_unparsable_values_still_fail_closed() {
        // Neither side reduces to an origin, and the two placeholders differ,
        // so equal garbage on both sides must not be read as a match.
        let msg = message_with_uri("not-a-url");
        assert_mismatch(verify_uri_binding(&msg, "not-a-url"));
    }

    #[test]
    fn uri_binding_ignores_free_form_domain_line() {
        // Deployed servers label the first line "aqua-node", not a hostname.
        // Only the URI origin is enforced, so this must pass.
        let msg = message_with_uri("https://timestamp.inblock.io");
        assert!(msg.starts_with("aqua-node wants you to sign in"));
        assert!(verify_uri_binding(&msg, "https://timestamp.inblock.io").is_ok());
    }

    // --- signed_session_request (the post-challenge seam) ---

    use crate::message::{build_message, MessageParams};
    use crate::signer::{SignError, Signer};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    const BASE_URL: &str = "https://timestamp.inblock.io";

    /// A local Ed25519 signer that genuinely suspends before producing bytes.
    ///
    /// The `sleep` is the point of the type: a synchronous `FnOnce` could not
    /// express a signer that waits on something external (a KMS round trip, a
    /// wallet prompt, a passkey touch), so a passing test proves the async path
    /// is really driven to completion. The call counter lets the refusal tests
    /// assert that a rejected challenge never reaches the key at all.
    struct SleepySigner {
        key: ed25519_dalek::SigningKey,
        did: String,
        calls: AtomicUsize,
    }

    impl SleepySigner {
        fn generate() -> Self {
            let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
            let mut bytes = crate::key::ED25519_PREFIX.to_vec();
            bytes.extend_from_slice(key.verifying_key().as_bytes());
            let did = format!("did:key:z{}", bs58::encode(&bytes).into_string());
            Self {
                key,
                did,
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl Signer for SleepySigner {
        fn signer_did(&self) -> &str {
            &self.did
        }

        async fn sign(&self, message: &str) -> Result<Vec<u8>, SignError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(10)).await;
            use ed25519_dalek::Signer as _;
            Ok(self.key.sign(message.as_bytes()).to_bytes().to_vec())
        }
    }

    /// A signer whose backend is down: proves the error mapping into
    /// [`AuthClientError::Sign`].
    struct FailingSigner {
        did: String,
    }

    #[async_trait]
    impl Signer for FailingSigner {
        fn signer_did(&self) -> &str {
            &self.did
        }

        async fn sign(&self, _message: &str) -> Result<Vec<u8>, SignError> {
            Err(SignError("hsm unreachable".to_string()))
        }
    }

    /// Build the envelope a well-behaved server would return for `did`.
    fn envelope_for(did: &str, uri: &str) -> ChallengeEnvelope {
        let now = chrono::Utc::now();
        let message = build_message(&MessageParams {
            did,
            domain: "aqua-node",
            uri,
            nonce: "0xdeadbeef",
            issued_at: now,
            expiration_time: now + chrono::Duration::minutes(5),
        })
        .expect("message builds for a supported DID");
        ChallengeEnvelope {
            nonce: "0xdeadbeef".to_string(),
            message,
            expires_at: 9999999999,
        }
    }

    #[tokio::test]
    async fn signed_session_request_awaits_the_signer_and_verifies() {
        let signer = SleepySigner::generate();
        let envelope = envelope_for(signer.signer_did(), BASE_URL);
        let message = envelope.message.clone();

        let req = signed_session_request(envelope, BASE_URL, &signer)
            .await
            .expect("a self-consistent challenge is signable");

        assert_eq!(signer.calls(), 1);
        assert_eq!(req.did, signer.signer_did());
        assert_eq!(req.nonce, "0xdeadbeef");

        // Hex with an `0x` prefix is the wire encoding the server decodes.
        let hex_body = req
            .signature
            .strip_prefix("0x")
            .expect("signature carries the 0x prefix");
        let sig_bytes = hex::decode(hex_body).expect("signature is hex");
        assert_eq!(sig_bytes.len(), 64, "raw ed25519 signature");
        assert!(crate::verify_caip122(signer.signer_did(), &message, &sig_bytes).unwrap());
    }

    #[tokio::test]
    async fn signed_session_request_refuses_a_relayed_challenge_unsigned() {
        // The relay case: the endpoint we dialed hands back a challenge minted
        // for another service. The key must never see it.
        let signer = SleepySigner::generate();
        let envelope = envelope_for(signer.signer_did(), "https://victim.example");

        let err = signed_session_request(envelope, BASE_URL, &signer)
            .await
            .unwrap_err();

        assert!(matches!(err, AuthClientError::UriOriginMismatch { .. }));
        assert_eq!(signer.calls(), 0, "refusal must precede signing");
    }

    #[tokio::test]
    async fn signed_session_request_refuses_a_foreign_identifier_unsigned() {
        // The message names someone else's key, so signing it would prove
        // possession of a message we did not ask for.
        let signer = SleepySigner::generate();
        let other = SleepySigner::generate();
        let envelope = envelope_for(other.signer_did(), BASE_URL);

        let err = signed_session_request(envelope, BASE_URL, &signer)
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            AuthClientError::MessageIdentifierMismatch { .. }
        ));
        assert_eq!(signer.calls(), 0, "refusal must precede signing");
    }

    #[tokio::test]
    async fn signed_session_request_maps_signer_failure_to_sign_error() {
        let good = SleepySigner::generate();
        let broken = FailingSigner {
            did: good.signer_did().to_string(),
        };
        let envelope = envelope_for(broken.signer_did(), BASE_URL);

        let err = signed_session_request(envelope, BASE_URL, &broken)
            .await
            .unwrap_err();

        match err {
            AuthClientError::Sign(msg) => assert!(msg.contains("hsm unreachable"), "got {msg}"),
            other => panic!("expected Sign, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn signed_session_request_rejects_an_unsupported_did_method() {
        let signer = FailingSigner {
            did: "did:pkh:solana:0xabc".to_string(),
        };
        // The identifier line is irrelevant here: the DID never resolves to a
        // method, so the check cannot even compute what to expect.
        let envelope = ChallengeEnvelope {
            nonce: "0xdeadbeef".to_string(),
            message: message_with_uri(BASE_URL),
            expires_at: 9999999999,
        };

        let err = signed_session_request(envelope, BASE_URL, &signer)
            .await
            .unwrap_err();

        assert!(matches!(err, AuthClientError::Auth(_)), "got {err:?}");
    }
}
