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
}
