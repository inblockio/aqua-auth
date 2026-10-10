//! DID parsing helpers for CAIP-122 verification.

use crate::crypto_error::CryptoError;
use sha3::{Digest, Keccak256};

/// Extract the DID namespace (e.g. `"eip155"`, `"ed25519"`, `"p256"`).
pub fn parse_did_namespace(did: &str) -> Result<&str, CryptoError> {
    let rest = did
        .strip_prefix("did:pkh:")
        .ok_or_else(|| CryptoError::InvalidDid(format!("expected 'did:pkh:' prefix: {did}")))?;
    rest.split(':')
        .next()
        .ok_or_else(|| CryptoError::InvalidDid(format!("no namespace in DID: {did}")))
}

/// Parse the 20-byte Ethereum address from a `did:pkh:eip155:{chain}:0x{hex}` DID.
pub fn address_from_did(did: &str) -> Result<[u8; 20], CryptoError> {
    let rest = did
        .strip_prefix("did:pkh:eip155:")
        .ok_or_else(|| CryptoError::InvalidDid(format!("expected eip155 DID: {did}")))?;
    let hex_str = rest
        .rsplit(':')
        .next()
        .and_then(|s| s.strip_prefix("0x"))
        .ok_or_else(|| {
            CryptoError::InvalidDid(format!("missing 0x address in eip155 DID: {did}"))
        })?;
    if hex_str.len() != 40 {
        return Err(CryptoError::InvalidDid(format!(
            "eip155 address must be 40 hex chars, got {}",
            hex_str.len()
        )));
    }
    let bytes = hex::decode(hex_str)?;
    bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidDid("address must be exactly 20 bytes".into()))
}

/// Extract the 32-byte Ed25519 public key from a `did:pkh:ed25519:0x{hex}` DID.
///
/// Refuses keys that are not points, are not canonically encoded, are weak,
/// or carry a torsion component.
pub fn pubkey_from_ed25519_did(did: &str) -> Result<[u8; 32], CryptoError> {
    let hex_str = did
        .strip_prefix("did:pkh:ed25519:0x")
        .ok_or_else(|| CryptoError::InvalidDid(format!("expected ed25519 DID: {did}")))?;
    if hex_str.len() != 64 {
        return Err(CryptoError::InvalidDid(format!(
            "ed25519 pubkey must be 64 hex chars, got {}",
            hex_str.len()
        )));
    }
    let bytes = hex::decode(hex_str)?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidDid("ed25519 pubkey must be 32 bytes".into()))?;
    crate::key::ed25519::strict_verifying_key(&key)?;
    Ok(key)
}

/// Extract the 33-byte compressed P-256 public key from a `did:pkh:p256:0x{hex}` DID.
pub fn pubkey_from_p256_did(did: &str) -> Result<[u8; 33], CryptoError> {
    let hex_str = did
        .strip_prefix("did:pkh:p256:0x")
        .ok_or_else(|| CryptoError::InvalidDid(format!("expected p256 DID: {did}")))?;
    if hex_str.len() != 66 {
        return Err(CryptoError::InvalidDid(format!(
            "p256 compressed pubkey must be 66 hex chars, got {}",
            hex_str.len()
        )));
    }
    let bytes = hex::decode(hex_str)?;
    bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidDid("p256 compressed pubkey must be 33 bytes".into()))
}

/// Derive the Ethereum address from a secp256k1 verifying key.
/// `address = keccak256(uncompressed_pubkey[1..])[12..]`
pub fn address_from_verifying_key(key: &k256::ecdsa::VerifyingKey) -> [u8; 20] {
    let point = key.to_encoded_point(false);
    let hash = Keccak256::digest(&point.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

/// EIP-55 mixed-case checksum encoding of a 20-byte Ethereum address.
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

/// Extract the identifier line from a CAIP-122 message body.
///
/// The Aqua CAIP-122 message format (see `crate::message::build_message`)
/// places the identifier on the second line, immediately after the
/// `{domain} wants you to sign in with your {method_label} account:` line.
/// This helper returns that line's trimmed content, or `None` if the
/// message is malformed (less than two lines, or empty second line).
pub fn identifier_from_message(message: &str) -> Option<&str> {
    let mut lines = message.split('\n');
    let _ = lines.next()?;
    let id = lines.next()?.trim_end_matches('\r').trim();
    if id.is_empty() {
        None
    } else {
        Some(id)
    }
}

/// EIP-55 checksummed address string from an eip155 DID.
pub fn checksummed_address(did: &str) -> Result<String, CryptoError> {
    let addr = address_from_did(did)?;
    Ok(format!("0x{}", eip55_checksum(&addr)))
}

/// Extract the human-readable identifier for a CAIP-122 message from a DID.
///
/// - `eip155` -> `0x{EIP-55 checksummed address}`
/// - `ed25519` -> `0x{32-byte pubkey hex}`
/// - `p256` -> `0x{33-byte compressed pubkey hex}`
pub fn identifier_from_did(did: &str) -> Result<String, CryptoError> {
    let ns = parse_did_namespace(did)?;
    match ns {
        "eip155" => checksummed_address(did),
        "ed25519" => {
            let pk = pubkey_from_ed25519_did(did)?;
            Ok(format!("0x{}", hex::encode(pk)))
        }
        "p256" => {
            let pk = pubkey_from_p256_did(did)?;
            Ok(format!("0x{}", hex::encode(pk)))
        }
        other => Err(CryptoError::UnsupportedMethod(other.into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eip55_known_vector() {
        let raw = hex::decode("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").unwrap();
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&raw);
        assert_eq!(
            eip55_checksum(&addr),
            "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        );
    }

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
    fn address_from_did_any_chain() {
        let did = "did:pkh:eip155:137:0xab5801a7d398351b8be11c439e05c5b3259aec9b";
        assert!(address_from_did(did).is_ok());
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
    fn invalid_did_prefix_errors() {
        assert!(parse_did_namespace("not:a:did").is_err());
    }

    #[test]
    fn identifier_from_message_extracts_eip155() {
        let msg = "timestamp.inblock.io wants you to sign in with your Ethereum account:\n\
                   0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed\n\
                   \n\
                   Sign in to Aqua Node\n";
        assert_eq!(
            identifier_from_message(msg),
            Some("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
        );
    }

    #[test]
    fn identifier_from_message_extracts_ed25519() {
        let pk_hex = hex::encode([0xAA; 32]);
        let msg = format!(
            "aqua-node wants you to sign in with your Ed25519 account:\n\
             0x{pk_hex}\n\
             \n\
             Sign in to Aqua Node"
        );
        assert_eq!(identifier_from_message(&msg), Some(&*format!("0x{pk_hex}")));
    }

    #[test]
    fn identifier_from_message_tolerates_crlf() {
        let msg = "domain wants you...\r\n0xABC\r\n\r\n";
        assert_eq!(identifier_from_message(msg), Some("0xABC"));
    }

    #[test]
    fn identifier_from_message_rejects_too_short() {
        assert!(identifier_from_message("").is_none());
        assert!(identifier_from_message("only one line").is_none());
    }

    #[test]
    fn identifier_from_message_rejects_empty_identifier() {
        let msg = "domain wants you...\n\n\nstatement\n";
        assert!(identifier_from_message(msg).is_none());
    }

    #[test]
    fn identifier_from_did_eip155() {
        let addr_hex = hex::encode([0x42; 20]);
        let did = format!("did:pkh:eip155:1:0x{addr_hex}");
        let id = identifier_from_did(&did).unwrap();
        assert!(id.starts_with("0x"));
        assert_eq!(id.len(), 42);
    }

    #[test]
    fn identifier_from_did_ed25519() {
        let pk_hex =
            hex::encode(curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED.to_bytes());
        let did = format!("did:pkh:ed25519:0x{pk_hex}");
        let id = identifier_from_did(&did).unwrap();
        assert_eq!(id, format!("0x{pk_hex}"));
    }

    #[test]
    fn identifier_from_did_p256() {
        let pk_hex = hex::encode([0xBB; 33]);
        let did = format!("did:pkh:p256:0x{pk_hex}");
        let id = identifier_from_did(&did).unwrap();
        assert_eq!(id, format!("0x{pk_hex}"));
    }

    #[test]
    fn identifier_from_did_unsupported() {
        assert!(identifier_from_did("did:pkh:solana:0xabc").is_err());
    }

    #[test]
    fn checksummed_address_eip155() {
        let did = "did:pkh:eip155:1:0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
        let addr = checksummed_address(did).unwrap();
        assert_eq!(addr, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    }
}

// ── did:key encoding ────────────────────────────────────────────────────────

/// Build a `did:key:z6Mk...` DID from a raw 32-byte Ed25519 public key.
///
/// The inverse of [`crate::key::ed25519_pubkey_from_did_key`]: `did:key:z` plus
/// base58btc over the Ed25519 multicodec prefix followed by the raw key bytes.
///
/// The name says `did_key` because the `did:key` and `did:pkh:ed25519` forms of
/// one key are **two distinct principals** (ruling #182), each with its own
/// grant bucket. A function named only for the curve would let a caller mint
/// the wrong one of the two without noticing.
///
/// Before this existed the encoding was open-coded at every producer, inside
/// this crate as well as outside it, and a DID string is an identity: two
/// producers that disagree mint two identities for one key.
pub fn ed25519_did_key_from_pubkey(pubkey: &[u8; 32]) -> String {
    encode_did_key(crate::key::ED25519_PREFIX, pubkey)
}

/// Build a `did:key:zDn...` DID from a compressed (SEC1, 33-byte) P-256 public key.
///
/// See [`ed25519_did_key_from_pubkey`] for why the spelling is in the name and
/// why the encoding lives in one place.
pub fn p256_did_key_from_pubkey(pubkey: &[u8; 33]) -> String {
    encode_did_key(crate::key::P256_PREFIX, pubkey)
}

/// `did:key:z` + base58btc(multicodec prefix || raw key bytes).
///
/// Private because a caller choosing its own prefix bytes is exactly the
/// divergence this module exists to prevent; add a typed wrapper above instead.
fn encode_did_key(prefix: &[u8], pubkey: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(prefix.len() + pubkey.len());
    bytes.extend_from_slice(prefix);
    bytes.extend_from_slice(pubkey);
    format!("did:key:z{}", bs58::encode(&bytes).into_string())
}

#[cfg(test)]
mod encode_tests {
    use super::*;

    /// Encode then decode returns the key unchanged. This is the property that
    /// makes the pair safe to use as an identity: a producer and a verifier
    /// that both route through this module cannot disagree.
    #[test]
    fn ed25519_encode_round_trips_through_the_did_key_decoder() {
        let ed = curve25519_dalek::constants::ED25519_BASEPOINT_COMPRESSED.to_bytes();
        let did = ed25519_did_key_from_pubkey(&ed);
        assert!(did.starts_with("did:key:z6Mk"), "unexpected prefix: {did}");
        assert_eq!(crate::key::ed25519_pubkey_from_did_key(&did).unwrap(), ed);
    }

    /// P-256 has no public `did:key` decoder, so the round trip goes through
    /// the method registry, which is what actually consumes these DIDs.
    #[test]
    fn p256_encode_produces_a_did_the_registry_accepts() {
        // A valid compressed SEC1 point starts with 0x02 or 0x03.
        let mut p = [9u8; 33];
        p[0] = 0x02;
        let did = p256_did_key_from_pubkey(&p);
        assert!(did.starts_with("did:key:zDn"), "unexpected prefix: {did}");
        assert!(
            crate::find_did_method(&did).is_some(),
            "the registry must recognise a did:key we mint"
        );
    }

    /// The two spellings of one key are different principals (#182), so the
    /// `did:key` encoder must not accidentally produce the `did:pkh` form.
    #[test]
    fn the_did_key_form_is_not_the_did_pkh_form() {
        let ed = [7u8; 32];
        assert_ne!(
            ed25519_did_key_from_pubkey(&ed),
            format!("did:pkh:ed25519:0x{}", hex::encode(ed))
        );
    }

    /// The ceremony helper predates this module and is part of the crate's
    /// public API, so it must keep producing byte-identical output.
    #[cfg(feature = "ceremony")]
    #[test]
    fn ceremony_helper_agrees_with_the_shared_encoder() {
        let mut p = [3u8; 33];
        p[0] = 0x03;
        assert_eq!(
            crate::webauthn_ceremony::did_key_from_p256_compressed(&p),
            p256_did_key_from_pubkey(&p)
        );
    }
}
