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
    fn uri_binding_malformed_base_url_fails_closed() {
        let msg = message_with_uri("https://example.com");
        assert_mismatch(verify_uri_binding(&msg, "example.com:3000"));
    }

    #[test]
    fn uri_binding_ignores_free_form_domain_line() {
        // Deployed servers label the first line "aqua-node", not a hostname.
        // Only the URI origin is enforced, so this must pass.
        let msg = message_with_uri("https://timestamp.inblock.io");
        assert!(msg.starts_with("aqua-node wants you to sign in"));
        assert!(verify_uri_binding(&msg, "https://timestamp.inblock.io").is_ok());
    }
}
