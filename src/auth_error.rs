use crate::crypto_error::CryptoError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    #[error("challenge not found or expired")]
    ChallengeNotFound,

    #[error("challenge expired")]
    ChallengeExpired,

    #[error("session not found or expired")]
    SessionNotFound,

    #[error("session expired")]
    SessionExpired,
}
