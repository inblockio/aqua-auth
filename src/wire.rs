//! Canonical on-wire types for the Aqua CAIP-122 authentication handshake.
//!
//! These are the JSON shapes that travel over HTTP between client and server.
//! They are intentionally distinct from the internal types in [`crate::types`]:
//!
//! - [`ChallengeEnvelope`] — what the server returns for `GET /auth/challenge`.
//!   Notably absent: `did`. The client supplied the DID in the query string;
//!   the message body already encodes the identifier. Including `did` in the
//!   response envelope creates an envelope/body mismatch surface and is omitted.
//! - [`SessionRequest`] — what the client posts to `POST /auth/session`.
//! - [`SessionResponse`] — what the server returns from `POST /auth/session`.

use serde::{Deserialize, Serialize};

/// Server -> client response body for `GET /auth/challenge?did=...`.
///
/// The `did` field is deliberately absent: the message body already
/// carries the identifier, the client supplied it in the query, and
/// returning it separately creates an envelope/body mismatch surface.
///
/// This is the canonical wire shape. See [`crate::types::Challenge`] for the
/// internal server-side stored record (which does carry `did`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeEnvelope {
    pub nonce: String,
    pub message: String,
    pub expires_at: u64,
}

/// Client -> server body for `POST /auth/session`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRequest {
    pub did: String,
    pub nonce: String,
    pub signature: String,
}

/// Server -> client response body for `POST /auth/session`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResponse {
    pub did: String,
    pub token: String,
    pub valid_until: u64,
    pub created_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_envelope_round_trip() {
        let env = ChallengeEnvelope {
            nonce: "0xabc".into(),
            message: "Sign in with Ethereum".into(),
            expires_at: 9999999999,
        };
        let json = serde_json::to_string(&env).unwrap();
        let decoded: ChallengeEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.nonce, env.nonce);
        assert_eq!(decoded.message, env.message);
        assert_eq!(decoded.expires_at, env.expires_at);
    }

    #[test]
    fn session_request_round_trip() {
        let req = SessionRequest {
            did: "did:pkh:eip155:1:0xABCD".into(),
            nonce: "0xdeadbeef".into(),
            signature: "0xsig".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let decoded: SessionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.did, req.did);
        assert_eq!(decoded.nonce, req.nonce);
        assert_eq!(decoded.signature, req.signature);
    }

    #[test]
    fn session_response_round_trip() {
        let resp = SessionResponse {
            did: "did:pkh:eip155:1:0xABCD".into(),
            token: "deadbeef".into(),
            valid_until: 9999999999,
            created_at: 1000000000,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let decoded: SessionResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.did, resp.did);
        assert_eq!(decoded.token, resp.token);
        assert_eq!(decoded.valid_until, resp.valid_until);
        assert_eq!(decoded.created_at, resp.created_at);
    }

    /// Exact shape emitted by the deployed `timestamp.inblock.io` server today.
    #[test]
    fn challenge_envelope_from_deployed_server_shape() {
        let raw = r#"{"nonce":"0xabc","message":"hi","expires_at":1}"#;
        let env: ChallengeEnvelope = serde_json::from_str(raw).unwrap();
        assert_eq!(env.nonce, "0xabc");
        assert_eq!(env.message, "hi");
        assert_eq!(env.expires_at, 1);
    }

    /// Forward-compat: servers that still emit `did` in the envelope must not
    /// break the client. Serde ignores unknown fields by default.
    #[test]
    fn challenge_envelope_tolerates_extra_did_field() {
        let raw = r#"{"did":"did:pkh:eip155:1:0xABCD","nonce":"0xabc","message":"hi","expires_at":1}"#;
        let env: ChallengeEnvelope = serde_json::from_str(raw).unwrap();
        assert_eq!(env.nonce, "0xabc");
        assert_eq!(env.expires_at, 1);
    }
}
