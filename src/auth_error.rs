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

    /// [`crate::session_backend::build_backend`] was asked for a
    /// [`crate::session_backend::SessionBackendKind`] whose implementation
    /// requires a cargo feature that is not compiled in (e.g.
    /// `SessionBackendKind::Redis` without the `redis` feature). Always
    /// available (not feature-gated) so `build_backend` compiles and returns
    /// this in both configurations.
    #[error("session backend unavailable: {0}")]
    BackendUnavailable(String),

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

    /// [`crate::redis_backend::RedisBackend`] (feature `redis`) found its
    /// internal connection mutex poisoned by a prior panic on another
    /// thread. Read methods degrade to their safe default instead of
    /// surfacing this (see the trait's infallible signatures); `insert` is
    /// the one fallible method, so it reports this explicitly.
    #[cfg(feature = "redis")]
    #[error("redis backend: connection lock poisoned by a prior panic")]
    LockPoisoned,
}
