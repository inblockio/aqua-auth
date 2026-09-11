//! Canonical on-wire types for the Aqua CAIP-122 authentication handshake.
//!
//! These are the JSON shapes that travel over HTTP between client and server.
//! They are intentionally distinct from the internal types in [`crate::types`]:
//!
//! - [`ChallengeEnvelope`]: what the server returns for `GET /auth/challenge`.
//!   Notably absent: `did`. The client supplied the DID in the query string;
//!   the message body already encodes the identifier. Including `did` in the
//!   response envelope creates an envelope/body mismatch surface and is omitted.
//! - [`SessionRequest`]: what the client posts to `POST /auth/session`.
//! - [`SessionResponse`]: what the server returns from `POST /auth/session`.

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
///
/// `public_key` is the `did:aqua` transport and is absent for every other
/// namespace. Optional and skipped when `None`, so the shape a classical
/// client sends is byte-identical to what it sent before this field existed,
/// and a server that does not know the field ignores it per `SPEC.md`
/// Section 8's forward-compatibility rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRequest {
    pub did: String,
    pub nonce: String,
    pub signature: String,
    /// Hex-encoded raw public key, `0x` prefixed, for methods whose verifier
    /// can obtain it neither from the DID nor from the signature. Today that
    /// is `did:aqua` alone: a 2592-byte ML-DSA-87 key, so 5186 characters.
    ///
    /// The server MUST bind this back to the DID before trusting it (see
    /// `aqua::codec::aqua_did_binds_pubkey`). An unbound key proves
    /// possession of some identity, not of the one being claimed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
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
            public_key: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let decoded: SessionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.did, req.did);
        assert_eq!(decoded.nonce, req.nonce);
        assert_eq!(decoded.signature, req.signature);
        assert_eq!(decoded.public_key, None);
    }

    /// A classical request serializes to exactly the bytes it did before
    /// `public_key` existed. This is what makes the field a non-breaking
    /// addition rather than a wire change every consumer has to absorb.
    #[test]
    fn a_classical_request_omits_the_public_key_field_entirely() {
        let req = SessionRequest {
            did: "did:pkh:eip155:1:0xABCD".into(),
            nonce: "0xdeadbeef".into(),
            signature: "0xsig".into(),
            public_key: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("public_key"), "got: {json}");
        assert_eq!(
            json,
            r#"{"did":"did:pkh:eip155:1:0xABCD","nonce":"0xdeadbeef","signature":"0xsig"}"#
        );
    }

    /// A server built before this field existed still parses a request that
    /// carries it, and a server built after still parses one that does not.
    #[test]
    fn the_public_key_field_is_optional_in_both_directions() {
        let without = r#"{"did":"d","nonce":"n","signature":"s"}"#;
        let parsed: SessionRequest = serde_json::from_str(without).unwrap();
        assert_eq!(parsed.public_key, None);

        let with = r#"{"did":"d","nonce":"n","signature":"s","public_key":"0xab"}"#;
        let parsed: SessionRequest = serde_json::from_str(with).unwrap();
        assert_eq!(parsed.public_key.as_deref(), Some("0xab"));
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
        let raw =
            r#"{"did":"did:pkh:eip155:1:0xABCD","nonce":"0xabc","message":"hi","expires_at":1}"#;
        let env: ChallengeEnvelope = serde_json::from_str(raw).unwrap();
        assert_eq!(env.nonce, "0xabc");
        assert_eq!(env.expires_at, 1);
    }
}
