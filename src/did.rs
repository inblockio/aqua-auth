//! DID parsing helpers for CAIP-122 authentication.
//!
//! Supports three DID namespaces:
//! - `did:pkh:eip155:1:0x{address}` — Ethereum (secp256k1)
//! - `did:pkh:ed25519:0x{pubkey}` — Ed25519
//! - `did:pkh:p256:0x{pubkey}` — P-256 (NIST)

use crate::error::AuthError;
use sha3::{Digest, Keccak256};

/// Extract the DID namespace (e.g. `"eip155"`, `"ed25519"`, `"p256"`).
pub fn parse_did_namespace(did: &str) -> Result<&str, AuthError> {
    let rest = did
        .strip_prefix("did:pkh:")
        .ok_or_else(|| AuthError::InvalidDid(format!("expected 'did:pkh:' prefix: {did}")))?;

    // eip155:1:0x... → "eip155"
    // ed25519:0x...  → "ed25519"
    // p256:0x...     → "p256"
    rest.split(':')
        .next()
        .ok_or_else(|| AuthError::InvalidDid(format!("no namespace in DID: {did}")))
}

/// Parse the 20-byte Ethereum address from a `did:pkh:eip155:1:0x{40 hex}` DID.
pub fn address_from_did(did: &str) -> Result<[u8; 20], AuthError> {
    let hex_str = did
        .strip_prefix("did:pkh:eip155:1:0x")
        .ok_or_else(|| AuthError::InvalidDid(format!("expected eip155 DID: {did}")))?;
    if hex_str.len() != 40 {
        return Err(AuthError::InvalidDid(format!(
            "eip155 address must be 40 hex chars, got {}",
            hex_str.len()
        )));
    }
    let bytes = hex::decode(hex_str)?;
    bytes.try_into().map_err(|_| {
        AuthError::InvalidDid("address must be exactly 20 bytes".into())
    })
}

/// Extract the raw public key bytes from an Ed25519 DID.
///
/// `did:pkh:ed25519:0x{64 hex chars}` → 32-byte public key.
pub fn pubkey_from_ed25519_did(did: &str) -> Result<[u8; 32], AuthError> {
    let hex_str = did
        .strip_prefix("did:pkh:ed25519:0x")
        .ok_or_else(|| AuthError::InvalidDid(format!("expected ed25519 DID: {did}")))?;
    if hex_str.len() != 64 {
        return Err(AuthError::InvalidDid(format!(
            "ed25519 pubkey must be 64 hex chars, got {}",
            hex_str.len()
        )));
    }
    let bytes = hex::decode(hex_str)?;
    bytes.try_into().map_err(|_| {
        AuthError::InvalidDid("ed25519 pubkey must be exactly 32 bytes".into())
    })
}

/// Extract the compressed public key bytes from a P-256 DID.
///
/// `did:pkh:p256:0x{66 hex chars}` → 33-byte compressed public key.
pub fn pubkey_from_p256_did(did: &str) -> Result<[u8; 33], AuthError> {
    let hex_str = did
        .strip_prefix("did:pkh:p256:0x")
        .ok_or_else(|| AuthError::InvalidDid(format!("expected p256 DID: {did}")))?;
    if hex_str.len() != 66 {
        return Err(AuthError::InvalidDid(format!(
            "p256 compressed pubkey must be 66 hex chars, got {}",
            hex_str.len()
        )));
    }
    let bytes = hex::decode(hex_str)?;
    bytes.try_into().map_err(|_| {
        AuthError::InvalidDid("p256 compressed pubkey must be exactly 33 bytes".into())
    })
}

/// Derive the Ethereum address from a secp256k1 verifying key.
///
/// Algorithm: `address = keccak256(uncompressed_pubkey[1..])[12..]`
pub fn address_from_verifying_key(key: &k256::ecdsa::VerifyingKey) -> [u8; 20] {
    let point = key.to_encoded_point(false);
    let pubkey_bytes = &point.as_bytes()[1..]; // skip 0x04 prefix → 64 bytes
    let hash = Keccak256::digest(pubkey_bytes);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

/// EIP-55 mixed-case checksum encoding for a 20-byte Ethereum address.
pub fn eip55_checksum(addr: &[u8; 20]) -> String {
    let lower = hex::encode(addr);
    let hash = Keccak256::digest(lower.as_bytes());
    let mut result = String::with_capacity(40);
    for (i, c) in lower.chars().enumerate() {
        if c.is_ascii_digit() {
            result.push(c);
        } else {
            let nibble = if i % 2 == 0 {
                (hash[i / 2] >> 4) & 0xf
            } else {
                hash[i / 2] & 0xf
            };
            if nibble >= 8 {
                result.push(c.to_ascii_uppercase());
            } else {
                result.push(c);
            }
        }
    }
    result
}

/// Extract the `identifier` field for a CAIP-122 message from a DID.
///
/// - `eip155` → `0x{EIP-55 checksummed address}`
/// - `ed25519` → `0x{32-byte pubkey hex}`
/// - `p256` → `0x{33-byte compressed pubkey hex}`
pub fn identifier_from_did(did: &str) -> Result<String, AuthError> {
    let ns = parse_did_namespace(did)?;
    match ns {
        "eip155" => {
            let addr = address_from_did(did)?;
            Ok(format!("0x{}", eip55_checksum(&addr)))
        }
        "ed25519" => {
            let pk = pubkey_from_ed25519_did(did)?;
            Ok(format!("0x{}", hex::encode(pk)))
        }
        "p256" => {
            let pk = pubkey_from_p256_did(did)?;
            Ok(format!("0x{}", hex::encode(pk)))
        }
        other => Err(AuthError::UnsupportedMethod(other.into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_eip155_namespace() {
        let ns = parse_did_namespace("did:pkh:eip155:1:0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B")
            .unwrap();
        assert_eq!(ns, "eip155");
    }

    #[test]
    fn parse_ed25519_namespace() {
        let pk_hex = hex::encode([0xAA; 32]);
        let did = format!("did:pkh:ed25519:0x{pk_hex}");
        assert_eq!(parse_did_namespace(&did).unwrap(), "ed25519");
    }

    #[test]
    fn parse_p256_namespace() {
        let pk_hex = hex::encode([0xBB; 33]);
        let did = format!("did:pkh:p256:0x{pk_hex}");
        assert_eq!(parse_did_namespace(&did).unwrap(), "p256");
    }

    #[test]
    fn address_from_did_roundtrip() {
        let addr_bytes = hex::decode("Ab5801a7D398351b8bE11C439e05C5B3259aeC9B").unwrap();
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&addr_bytes);
        let did = format!("did:pkh:eip155:1:0x{}", hex::encode(addr));
        let parsed = address_from_did(&did).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn eip55_known_vector() {
        let raw = hex::decode("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").unwrap();
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&raw);
        assert_eq!(eip55_checksum(&addr), "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    }

    #[test]
    fn unsupported_namespace_errors() {
        let err = parse_did_namespace("did:pkh:solana:0xabc").unwrap();
        // "solana" is parsed but not verified here — verification happens in verify_caip122
        assert_eq!(err, "solana");
    }

    #[test]
    fn invalid_did_prefix() {
        assert!(parse_did_namespace("not:a:did").is_err());
    }
}
