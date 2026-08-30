use crate::crypto_error::CryptoError;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
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

    /// A [`crate::session_backend::SessionBackend`] could not serve a
    /// request: it could not reach its store, could not (de)serialize a
    /// [`crate::types::Session`], or was asked for a capability it does not
    /// have. This crate ships only
    /// [`crate::session_backend::InMemoryBackend`], which never returns it;
    /// it is the reporting channel for out-of-tree backends (Redis, SQL) so
    /// their storage-specific error types stay out of this crate's public
    /// API. Carries a human-readable description, not a typed cause.
    #[error("session backend unavailable: {0}")]
    BackendUnavailable(String),
}
