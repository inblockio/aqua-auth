//! The derived passkey login challenge, for a front end that logs into a
//! backend it does not trust with its signing origin (aqua-explorer logging
//! into an aqua-node).
//!
//! The node issues a 32-byte nonce; the front end, never the node, computes
//! the challenge it passes to `get()`:
//!
//! ```text
//! challenge = SHA-256("aqua-auth/webauthn-login/v1" || nonce || origin(node base URL))
//! ```
//!
//! `origin` is the WHATWG serialization (`new URL(u).origin` in a browser):
//! lowercase scheme and host, ASCII (punycode) host, default port omitted,
//! path, query, fragment and user info dropped. The node checks the same
//! derivation through [`crate::ExpectedChallenge::DerivedLogin`]. Because the
//! challenge is a hash over a tagged input, a node cannot steer the passkey
//! into signing bytes of its choosing, such as an SDK revision challenge
//! (whose preimage is JSON and starts with `{`). Pinned vectors shared with
//! the TypeScript side: `tests/vectors/webauthn-derived-login-challenge.json`.

use sha2::{Digest, Sha256};

/// The domain-separation tag. Its first byte is not `{`, so it can never
/// prefix the SDK's JSON signing input.
pub const LOGIN_CHALLENGE_TAG: &[u8] = b"aqua-auth/webauthn-login/v1";

/// Why a node URL cannot anchor a derived login challenge.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LoginChallengeError {
    /// The node URL does not parse as an absolute URL.
    #[error("node URL does not parse: {0}")]
    InvalidUrl(String),
    /// The scheme is not `http` or `https` (a node URL is one of them; any
    /// other scheme has an opaque or ambiguous origin).
    #[error("node URL scheme {0:?} is not http or https")]
    UnsupportedScheme(String),
}

/// The login challenge for `nonce` at the node whose base URL is `node_url`.
pub fn derive_login_challenge(
    nonce: &[u8; 32],
    node_url: &str,
) -> Result<[u8; 32], LoginChallengeError> {
    let url =
        url::Url::parse(node_url).map_err(|e| LoginChallengeError::InvalidUrl(e.to_string()))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(LoginChallengeError::UnsupportedScheme(
            url.scheme().to_owned(),
        ));
    }
    let origin = url.origin().ascii_serialization();
    let mut h = Sha256::new();
    h.update(LOGIN_CHALLENGE_TAG);
    h.update(nonce);
    h.update(origin.as_bytes());
    Ok(h.finalize().into())
}
