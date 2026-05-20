//! CAIP-122 canonical message construction (SIWE-compatible format).

use crate::auth_error::AuthError;
use crate::crypto_error::CryptoError;
use crate::did::{identifier_from_did, parse_did_namespace};
use chrono::{DateTime, Utc};

/// Parameters for constructing a CAIP-122 message.
pub struct MessageParams<'a> {
    /// The DID requesting authentication.
    pub did: &'a str,
    /// The domain (e.g. `"aqua-node"` or hostname).
    pub domain: &'a str,
    /// The URI of the resource being authenticated to (e.g. `"http://127.0.0.1:3000"`).
    pub uri: &'a str,
    /// Random nonce (hex-encoded).
    pub nonce: &'a str,
    /// When the message was issued (UTC).
    pub issued_at: DateTime<Utc>,
    /// When the message expires (UTC).
    pub expiration_time: DateTime<Utc>,
}

/// Construct a canonical CAIP-122 message string.
///
/// For `eip155` DIDs, produces a valid SIWE message (MetaMask native rendering).
/// For `ed25519`/`p256` DIDs, the structure is identical but programmatic.
pub fn build_message(params: &MessageParams) -> Result<String, AuthError> {
    let ns = parse_did_namespace(params.did)?;
    let identifier = identifier_from_did(params.did)?;

    let method_label = match ns {
        "eip155" => "Ethereum",
        "ed25519" => "Ed25519",
        "p256" => "P-256",
        other => Err(CryptoError::UnsupportedMethod(other.into()))?,
    };

    let issued_at = params.issued_at.format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let expiration_time = params.expiration_time.format("%Y-%m-%dT%H:%M:%S%.3fZ");

    let mut msg = format!(
        "{domain} wants you to sign in with your {method_label} account:\n\
         {identifier}\n\
         \n\
         Sign in to Aqua Node\n\
         \n\
         URI: {uri}\n\
         Version: 1\n\
         Nonce: {nonce}\n\
         Issued At: {issued_at}\n\
         Expiration Time: {expiration_time}",
        domain = params.domain,
        uri = params.uri,
        nonce = params.nonce,
    );

    // Add Chain ID for SIWE compatibility with eip155 DIDs.
    if ns == "eip155" {
        msg.push_str("\nChain ID: 1");
    }

    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn eip155_message_has_chain_id() {
        let addr_hex = hex::encode([0x11; 20]);
        let did = format!("did:pkh:eip155:1:0x{addr_hex}");
        let issued = Utc.with_ymd_and_hms(2026, 3, 17, 12, 0, 0).unwrap();
        let expires = Utc.with_ymd_and_hms(2026, 3, 17, 12, 5, 0).unwrap();

        let msg = build_message(&MessageParams {
            did: &did,
            domain: "aqua-node",
            uri: "http://127.0.0.1:3000",
            nonce: "0xdeadbeef",
            issued_at: issued,
            expiration_time: expires,
        })
        .unwrap();

        assert!(msg.contains("Ethereum account"));
        assert!(msg.contains("Chain ID: 1"));
        assert!(msg.contains("Sign in to Aqua Node"));
        assert!(msg.contains("Nonce: 0xdeadbeef"));
    }

    #[test]
    fn ed25519_message_no_chain_id() {
        let pk_hex = hex::encode([0xAA; 32]);
        let did = format!("did:pkh:ed25519:0x{pk_hex}");
        let issued = Utc.with_ymd_and_hms(2026, 3, 17, 12, 0, 0).unwrap();
        let expires = Utc.with_ymd_and_hms(2026, 3, 17, 12, 5, 0).unwrap();

        let msg = build_message(&MessageParams {
            did: &did,
            domain: "aqua-node",
            uri: "http://127.0.0.1:3000",
            nonce: "0xdeadbeef",
            issued_at: issued,
            expiration_time: expires,
        })
        .unwrap();

        assert!(msg.contains("Ed25519 account"));
        assert!(!msg.contains("Chain ID"));
    }

    #[test]
    fn p256_message_no_chain_id() {
        let pk_hex = hex::encode([0xBB; 33]);
        let did = format!("did:pkh:p256:0x{pk_hex}");
        let issued = Utc.with_ymd_and_hms(2026, 3, 17, 12, 0, 0).unwrap();
        let expires = Utc.with_ymd_and_hms(2026, 3, 17, 12, 5, 0).unwrap();

        let msg = build_message(&MessageParams {
            did: &did,
            domain: "aqua-node",
            uri: "http://127.0.0.1:3000",
            nonce: "0xdeadbeef",
            issued_at: issued,
            expiration_time: expires,
        })
        .unwrap();

        assert!(msg.contains("P-256 account"));
        assert!(!msg.contains("Chain ID"));
    }

    #[test]
    fn message_contains_all_fields() {
        let addr_hex = hex::encode([0x42; 20]);
        let did = format!("did:pkh:eip155:1:0x{addr_hex}");
        let issued = Utc.with_ymd_and_hms(2026, 1, 15, 10, 30, 0).unwrap();
        let expires = Utc.with_ymd_and_hms(2026, 1, 15, 10, 35, 0).unwrap();

        let msg = build_message(&MessageParams {
            did: &did,
            domain: "localhost",
            uri: "http://localhost:3000",
            nonce: "0xaabbccdd",
            issued_at: issued,
            expiration_time: expires,
        })
        .unwrap();

        assert!(msg.starts_with("localhost wants you to sign in"));
        assert!(msg.contains("URI: http://localhost:3000"));
        assert!(msg.contains("Version: 1"));
        assert!(msg.contains("Nonce: 0xaabbccdd"));
        assert!(msg.contains("Issued At: 2026-01-15T10:30:00.000Z"));
        assert!(msg.contains("Expiration Time: 2026-01-15T10:35:00.000Z"));
    }
}
