//! Protocol types for CAIP-122 authenticated sessions.

use serde::{Deserialize, Serialize};

/// Server-side stored record for an issued CAIP-122 challenge.
///
/// This is the **internal** representation held in [`crate::ChallengeStore`].
/// It is not the on-wire shape: the HTTP response body for
/// `GET /auth/challenge` omits `did` and uses [`crate::wire::ChallengeEnvelope`]
/// as the canonical wire type instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// The DID that requested this challenge.
    pub did: String,
    /// Random nonce (hex-encoded, 32 bytes).
    pub nonce: String,
    /// The canonical CAIP-122 message to sign.
    pub message: String,
    /// Unix timestamp (seconds) when this challenge expires.
    pub expires_at: u64,
}

/// Client request to create a session after signing a challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRequest {
    /// The DID that signed the challenge.
    pub did: String,
    /// The nonce from the challenge.
    pub nonce: String,
    /// The signature over the challenge message (hex-encoded).
    pub signature: String,
}

/// An active authenticated session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// The authenticated DID.
    pub did: String,
    /// Opaque session token (hex-encoded, 32 bytes).
    pub token: String,
    /// Unix timestamp (seconds) when this session expires.
    pub valid_until: u64,
    /// Unix timestamp (seconds) when this session was created.
    pub created_at: u64,
}

/// Represents a verified caller identity, injected into Axum request extensions.
#[derive(Debug, Clone)]
pub struct AuthenticatedDid(pub String);

/// Session info exposed via the management API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub did: String,
    pub created_at: u64,
    pub valid_until: u64,
}
