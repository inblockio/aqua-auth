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

    /// H2 hardening: the session store is at its hard capacity
    /// ([`crate::session::MAX_SESSIONS`] or an overridden value) and purging
    /// expired entries did not free a slot. The new session is rejected
    /// rather than evicting an active, authenticated session.
    #[error("session store at capacity ({max} sessions); new session rejected")]
    SessionStoreFull { max: usize },

    /// [`crate::redis_backend::RedisBackend`] (feature `redis`) failed to
    /// connect to or communicate with Redis.
    #[cfg(feature = "redis")]
    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),

    /// [`crate::redis_backend::RedisBackend`] (feature `redis`) failed to
    /// (de)serialize a [`crate::types::Session`] to/from JSON.
    #[cfg(feature = "redis")]
    #[error("session (de)serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}
