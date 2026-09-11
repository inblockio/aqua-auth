//! Canonical on-wire types for the Aqua CAIP-122 authentication handshake.
//!
//! These are the JSON shapes that travel over HTTP between client and server.
//! They are intentionally distinct from the internal types in [`crate::types`]:
//!
//! - [`ChallengeEnvelope`]: what the server returns for `GET /auth/challenge`.
//!   Notably absent: `did`. Servers emit it and this type ignores it.
//! - [`SessionRequest`]: what the client posts to `POST /auth/session`.
//! - [`SessionResponse`]: what the server returns from `POST /auth/session`.

use serde::{Deserialize, Serialize};

/// Server -> client response body for `GET /auth/challenge?did=...`.
///
/// `did` is deliberately not a field here, and this type is deliberately
/// tolerant of servers that send one.
///
/// The field was briefly added on 2026-09-11 to match `SPEC.md` Section 6.2,
/// then removed the same day once it was established that nothing needs it.
/// Nothing in this crate reads it; the client's binding check compares the
/// identifier inside `message` against the *signer's own* DID, never against
/// an envelope field, so a `did` here could only ever agree redundantly or
/// disagree dangerously. `did:aqua` carries its public key on
/// [`SessionRequest`], not here. A field no code reads is a second place for
/// an identity to be stated and therefore a second place for it to be wrong.
///
/// There is no `deny_unknown_fields`, so servers that emit `did` keep working
/// unchanged and serde discards it. Removing it from this type required no
/// server change, and it restores compatibility with servers that never sent
/// it. See `SPEC.md` Section 6.2.
///
/// See [`crate::types::Challenge`] for the internal server-side stored record,
/// which does carry the DID because a server must know who it minted for.
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

    /// The shape every current Aqua server emits: aqua-node
    /// (`aqua-rest/src/routes.rs`), aquafier-rs (`aquafier-auth/src/routes.rs`)
    /// and the testkit peer all serialize the stored `Challenge` verbatim,
    /// which includes `did`. This type ignores it, and must keep ignoring it:
    /// no server has to change for the field to be absent here.
    #[test]
    fn an_envelope_carrying_did_parses_and_the_field_is_ignored() {
        let raw =
            r#"{"did":"did:pkh:eip155:1:0xABCD","nonce":"0xabc","message":"hi","expires_at":1}"#;
        let env: ChallengeEnvelope = serde_json::from_str(raw).unwrap();
        assert_eq!(env.nonce, "0xabc");
        assert_eq!(env.message, "hi");
        assert_eq!(env.expires_at, 1);
    }

    /// A three-field envelope parses. This is why the tolerant shape matters
    /// rather than being merely tidy.
    ///
    /// One deployed server is known to emit exactly this:
    /// `timestamp.inblock.io`, the aqua-timestamps deployment. Requiring `did`
    /// would have made that endpoint unparseable for every client built on
    /// this crate. Its repo is separately recorded in `CONSUMERS.md` as
    /// orphaned, so the breakage would have been survivable, but it would have
    /// been a breakage taken in exchange for a field nothing reads.
    #[test]
    fn a_did_less_envelope_parses() {
        let raw = r#"{"nonce":"0xabc","message":"hi","expires_at":1}"#;
        let env: ChallengeEnvelope = serde_json::from_str(raw).unwrap();
        assert_eq!(env.nonce, "0xabc");
        assert_eq!(env.message, "hi");
        assert_eq!(env.expires_at, 1);
    }
}
