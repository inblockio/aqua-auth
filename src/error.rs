//! Auth error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("unsupported DID method: {0}")]
    UnsupportedMethod(String),

    #[error("invalid DID format: {0}")]
    InvalidDid(String),

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("challenge not found or expired")]
    ChallengeNotFound,

    #[error("challenge expired")]
    ChallengeExpired,

    #[error("signature verification failed")]
    VerificationFailed,

    #[error("session not found or expired")]
    SessionNotFound,

    #[error("session expired")]
    SessionExpired,
}
