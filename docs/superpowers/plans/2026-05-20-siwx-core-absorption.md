# siwx-core Absorption into aqua-auth -- Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Absorb siwx-core's full public API into aqua-auth, feature-gate the HTTP/session layer behind `http`, and produce a 0.2.0 crate ready for `cargo publish --dry-run`.

**Architecture:** Copy siwx-core's source files into aqua-auth/src/, rename SiwxError to CryptoError, feature-gate the HTTP/session modules behind `http` and the client behind `client`. The crypto/DID layer (CipherSuite, DIDMethod, all impls) is always available under default features; the session management layer (ChallengeStore, SessionStore, build_message, types) is opt-in via `http`.

**Tech Stack:** Rust, k256 0.13, ed25519-dalek 2, p256 0.13, sha3 0.10, bs58 0.5, thiserror 2, serde 1, dashmap 6, tokio 1, chrono 0.4, reqwest 0.12.

**Spec:** `docs/superpowers/specs/2026-05-20-siwx-core-absorption-design.md`

**siwx-core source:** `/home/system-001/siwx-oidc/siwx-core/src/`

---

## Hypothesis Register

| ID | If | Then | Assumptions | Verification |
|----|-----|------|-------------|--------------|
| H1 | Copy siwx-core source files into aqua-auth/src/ and inline its deps in Cargo.toml | The crate compiles without the siwx-core path dependency | Dep versions compatible; no name collisions | `cargo check --no-default-features` |
| H2 | Rename SiwxError to CryptoError everywhere | All crypto code compiles with the new error type | Rename is mechanical; no dynamic dispatch on type name | `grep -r SiwxError src/` returns empty |
| H3 | Gate session/challenge/message/types/auth_error behind `#[cfg(feature = "http")]` | Default features compile only the crypto layer | No unconditional code path references gated types | `cargo check --no-default-features` and `cargo check --features http` both pass |
| H4 | Gate client.rs behind `#[cfg(feature = "client")]` with `client` implying `http` | Client feature activates the full stack | Feature implication wired correctly in Cargo.toml | `cargo check --features client` passes |
| H5 | Delete verify_eip191/ed25519/p256.rs and rewire verify_caip122 through DIDMethod dispatch | Signature verification still works for all 3 namespaces | siwx-core's CipherSuite impls are functionally equivalent | All dispatch tests pass |
| H6 | Update AuthError to wrap CryptoError via `#[from]` + `#[error(transparent)]` | Error messages preserved; consumers match CryptoError through AuthError::Crypto(_) | Breaking change accepted at 0.2.0 | Auth tests compile and pass |
| H7 | Promote identifier_from_did + checksummed_address into merged did.rs | Functions available under default features | The orphaned code in current did.rs is correct | Unit tests for identifier_from_did pass |
| H8 | Migrate all 57 siwx-core inline tests | Tests pass in new location | Tests don't depend on siwx-core-specific harness | `cargo test --no-default-features` count >= 57 |
| H9 | Adapt existing aqua-auth tests for new imports and error types | All auth tests pass | Changes are mechanical | `cargo test --features http` count >= 38 |
| H10 | Run cargo publish --dry-run | Crate is publishable | No path deps remain; metadata complete | Exit code 0 |

---

## File Map

### New files (from siwx-core, with SiwxError -> CryptoError rename)

| File | Source | Notes |
|------|--------|-------|
| `src/crypto_error.rs` | `siwx-core/src/error.rs` | Renamed enum SiwxError -> CryptoError |
| `src/cipher_suite.rs` | `siwx-core/src/cipher_suite.rs` | Import path fix |
| `src/did_method.rs` | `siwx-core/src/did_method.rs` | Import path fix |
| `src/pkh/mod.rs` | `siwx-core/src/pkh/mod.rs` | Unchanged |
| `src/pkh/method.rs` | `siwx-core/src/pkh/method.rs` | checksummed_address call -> crate::did |
| `src/pkh/eip155.rs` | `siwx-core/src/pkh/eip155.rs` | Remove checksummed_address (moved to did.rs) |
| `src/pkh/ed25519.rs` | `siwx-core/src/pkh/ed25519.rs` | Import path fix |
| `src/pkh/p256.rs` | `siwx-core/src/pkh/p256.rs` | Import path fix |
| `src/key/mod.rs` | `siwx-core/src/key/mod.rs` | Import path fix |
| `src/peer/mod.rs` | `siwx-core/src/peer/mod.rs` | Import path fix |

### Modified files

| File | Changes |
|------|---------|
| `Cargo.toml` | Complete rewrite: inline crypto deps, feature-gate http deps, bump 0.2.0 |
| `src/lib.rs` | Complete rewrite: feature-gated modules, new re-exports, verify_caip122 returns CryptoError |
| `src/did.rs` | Replace: merge siwx-core did.rs + identifier_from_did + checksummed_address + merged tests |
| `src/message.rs` | Update imports: siwx_core::did -> crate::did, use identifier_from_did |
| `src/challenge.rs` | Update import: crate::error -> crate::auth_error |
| `src/session.rs` | Update import: crate::error -> crate::auth_error |
| `src/client.rs` | Update import: crate::error -> crate::auth_error |

### New files (aqua-auth specific)

| File | Purpose |
|------|---------|
| `src/auth_error.rs` | AuthError wrapping CryptoError (replaces error.rs) |

### Deleted files

| File | Reason |
|------|--------|
| `src/error.rs` | Replaced by auth_error.rs |
| `src/verify_eip191.rs` | Dead file, logic in pkh/eip155.rs |
| `src/verify_ed25519.rs` | Dead file, logic in pkh/ed25519.rs |
| `src/verify_p256.rs` | Dead file, logic in pkh/p256.rs |

---

## Task 1: Cargo.toml + all source file operations

**Hypotheses:** H1, H2, H7

This task creates all new files, replaces modified files, and deletes dead files. The crate will NOT compile until Task 2 wires lib.rs.

**Files:**
- Create: `Cargo.toml` (rewrite)
- Create: `src/crypto_error.rs`
- Create: `src/cipher_suite.rs`
- Create: `src/did_method.rs`
- Create: `src/did.rs` (replace)
- Create: `src/pkh/mod.rs`, `src/pkh/method.rs`, `src/pkh/eip155.rs`, `src/pkh/ed25519.rs`, `src/pkh/p256.rs`
- Create: `src/key/mod.rs`
- Create: `src/peer/mod.rs`
- Delete: `src/verify_eip191.rs`, `src/verify_ed25519.rs`, `src/verify_p256.rs`, `src/error.rs`

### Step 1: Write new Cargo.toml

- [ ] Replace `Cargo.toml` with:

```toml
[package]
name = "aqua-auth"
version = "0.2.0"
edition = "2021"
license = "Apache-2.0"
repository = "https://github.com/inblockio/aqua-rs-auth"
description = "DID-based authentication for the Aqua Protocol. Crypto/DID primitives by default; challenge-response sessions behind the `http` feature."

[features]
default = []
http = ["dep:rand", "dep:serde_json", "dep:chrono", "dep:dashmap", "dep:tokio"]
client = ["http", "dep:reqwest"]

[dependencies]
# Always (crypto layer)
k256 = { version = "0.13", features = ["ecdsa"] }
ed25519-dalek = { version = "2", features = ["rand_core"] }
p256 = { version = "0.13", features = ["ecdsa"] }
sha3 = "0.10"
bs58 = "0.5"
hex = "0.4"
thiserror = "2"
serde = { version = "1", features = ["derive"] }

# Behind `http` feature
rand = { version = "0.8", optional = true }
serde_json = { version = "1", optional = true }
chrono = { version = "0.4", features = ["serde"], optional = true }
dashmap = { version = "6", optional = true }
tokio = { version = "1", features = ["time", "rt"], optional = true }

# Behind `client` feature
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"], optional = true }

[dev-dependencies]
tokio = { version = "1", features = ["full"] }
rand = "0.8"
```

### Step 2: Create src/crypto_error.rs

- [ ] Create `src/crypto_error.rs`:

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("unsupported DID method: {0}")]
    UnsupportedMethod(String),

    #[error("invalid DID: {0}")]
    InvalidDid(String),

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("signature verification failed")]
    VerificationFailed,

    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),
}
```

### Step 3: Copy siwx-core cipher_suite.rs

- [ ] Copy `/home/system-001/siwx-oidc/siwx-core/src/cipher_suite.rs` to `src/cipher_suite.rs`, then apply these changes:

Replace `use crate::error::SiwxError;` with `use crate::crypto_error::CryptoError;`

Replace all occurrences of `SiwxError` with `CryptoError` in the trait definition and function signatures.

The result should be the original file with every `SiwxError` replaced by `CryptoError` and the import path changed. No other changes.

### Step 4: Copy siwx-core did_method.rs

- [ ] Copy `/home/system-001/siwx-oidc/siwx-core/src/did_method.rs` to `src/did_method.rs`, then apply:

Replace `use crate::error::SiwxError;` with `use crate::crypto_error::CryptoError;`

Replace all `SiwxError` with `CryptoError`.

### Step 5: Create merged src/did.rs

- [ ] Replace `src/did.rs` with the merged version. Base: siwx-core's did.rs (handles any chain ID). Additions: `identifier_from_did` and `checksummed_address` from aqua-auth + siwx-core, plus merged test suite.

```rust
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
        .ok_or_else(|| CryptoError::InvalidDid(format!("missing 0x address in eip155 DID: {did}")))?;
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
    bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidDid("ed25519 pubkey must be 32 bytes".into()))
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
        let ns =
            parse_did_namespace("did:pkh:eip155:1:0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B")
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
    fn identifier_from_did_eip155() {
        let addr_hex = hex::encode([0x42; 20]);
        let did = format!("did:pkh:eip155:1:0x{addr_hex}");
        let id = identifier_from_did(&did).unwrap();
        assert!(id.starts_with("0x"));
        assert_eq!(id.len(), 42); // "0x" + 40 hex chars
    }

    #[test]
    fn identifier_from_did_ed25519() {
        let pk_hex = hex::encode([0xAA; 32]);
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
```

### Step 6: Create src/pkh/ directory and copy files

- [ ] Create `src/pkh/` directory.

- [ ] Copy `src/pkh/mod.rs` from siwx-core (unchanged):

```rust
pub mod ed25519;
pub mod eip155;
pub mod method;
pub mod p256;

pub use ed25519::Ed25519Suite;
pub use eip155::Eip155Suite;
pub use method::PkhMethod;
pub use p256::P256Suite;
```

- [ ] Copy `src/pkh/eip155.rs` from siwx-core with these changes:
  - `use crate::error::SiwxError;` -> `use crate::crypto_error::CryptoError;`
  - All `SiwxError` -> `CryptoError`
  - **Remove** the `checksummed_address` function (lines 76-79 in siwx-core) since it moved to `did.rs`

- [ ] Copy `src/pkh/method.rs` from siwx-core with these changes:
  - `use crate::error::SiwxError;` -> `use crate::crypto_error::CryptoError;`
  - All `SiwxError` -> `CryptoError`
  - In `address_for_message()`, change `crate::pkh::eip155::checksummed_address(did)` to `crate::did::checksummed_address(did)`

- [ ] Copy `src/pkh/ed25519.rs` from siwx-core with these changes:
  - `use crate::error::SiwxError;` -> `use crate::crypto_error::CryptoError;`
  - All `SiwxError` -> `CryptoError`

- [ ] Copy `src/pkh/p256.rs` from siwx-core with these changes:
  - `use crate::error::SiwxError;` -> `use crate::crypto_error::CryptoError;`
  - All `SiwxError` -> `CryptoError`

### Step 7: Create src/key/ directory and copy files

- [ ] Create `src/key/` directory.

- [ ] Copy `src/key/mod.rs` from siwx-core with these changes:
  - `use crate::{did_method::DIDMethod, error::SiwxError};` -> `use crate::{did_method::DIDMethod, crypto_error::CryptoError};`
  - All `SiwxError` -> `CryptoError`

### Step 8: Create src/peer/ directory and copy files

- [ ] Create `src/peer/` directory.

- [ ] Copy `src/peer/mod.rs` from siwx-core with these changes:
  - `use crate::{..., error::SiwxError, ...};` -> `use crate::{..., crypto_error::CryptoError, ...};`
  - All `SiwxError` -> `CryptoError`

### Step 9: Delete dead files

- [ ] Delete the following files:
  - `src/verify_eip191.rs`
  - `src/verify_ed25519.rs`
  - `src/verify_p256.rs`
  - `src/error.rs`

---

## Task 2: Module structure + feature gates + import fixups

**Hypotheses:** H3, H4, H5, H6

Wire the new module structure in lib.rs, create auth_error.rs, and fix imports in all HTTP-gated modules.

**Files:**
- Create: `src/auth_error.rs`
- Modify: `src/lib.rs` (rewrite)
- Modify: `src/message.rs` (imports)
- Modify: `src/challenge.rs` (imports)
- Modify: `src/session.rs` (imports)
- Modify: `src/client.rs` (imports)

### Step 1: Create src/auth_error.rs

- [ ] Create `src/auth_error.rs`:

```rust
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
}
```

### Step 2: Update src/message.rs imports

- [ ] In `src/message.rs`, replace the imports block (lines 1-11) with:

```rust
//! CAIP-122 canonical message construction (SIWE-compatible format).

use crate::auth_error::AuthError;
use crate::crypto_error::CryptoError;
use crate::did::{identifier_from_did, parse_did_namespace};
use chrono::{DateTime, Utc};
```

- [ ] Replace the `build_message` function body. The identifier computation simplifies to use `identifier_from_did`:

```rust
pub fn build_message(params: &MessageParams) -> Result<String, AuthError> {
    let ns = parse_did_namespace(params.did)?;
    let identifier = identifier_from_did(params.did)?;

    let method_label = match ns {
        "eip155"  => "Ethereum",
        "ed25519" => "Ed25519",
        "p256"    => "P-256",
        other     => Err(CryptoError::UnsupportedMethod(other.into()))?,
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

    if ns == "eip155" {
        msg.push_str("\nChain ID: 1");
    }

    Ok(msg)
}
```

- [ ] Remove the `hex` import if present (no longer needed in message.rs since identifier_from_did handles hex encoding).

### Step 3: Update src/challenge.rs imports

- [ ] In `src/challenge.rs`, change:

```rust
use crate::error::AuthError;
```

to:

```rust
use crate::auth_error::AuthError;
```

No other changes needed.

### Step 4: Update src/session.rs imports

- [ ] In `src/session.rs`, change:

```rust
use crate::error::AuthError;
```

to:

```rust
use crate::auth_error::AuthError;
```

No other changes needed.

### Step 5: Update src/client.rs imports

- [ ] In `src/client.rs`, change:

```rust
use crate::error::AuthError;
```

to:

```rust
use crate::auth_error::AuthError;
```

No other changes needed.

### Step 6: Rewrite src/lib.rs

- [ ] Replace `src/lib.rs` with:

```rust
//! # aqua-auth
//!
//! DID-based authentication for the Aqua Protocol.
//!
//! **Default features (crypto/DID layer):**
//! - CipherSuite and DIDMethod trait registries
//! - did:pkh (eip155, ed25519, p256), did:key, did:peer verification
//! - DID parsing, identifier extraction, EIP-55 checksumming
//! - `verify_caip122()` signature verification dispatch
//!
//! **`http` feature (session/auth layer):**
//! - CAIP-122 message construction
//! - ChallengeStore (in-memory, 5-min TTL, single-use nonces)
//! - SessionStore (in-memory, 1-hr TTL, background sweep)
//!
//! **`client` feature (implies `http`):**
//! - reqwest-based challenge-response authentication flow

// --- Always available (crypto/DID layer) ---
pub mod cipher_suite;
pub mod crypto_error;
pub mod did;
pub mod did_method;
pub mod key;
pub mod peer;
pub mod pkh;

pub use cipher_suite::{all_cipher_suites, find_cipher_suite, CipherSuite};
pub use crypto_error::CryptoError;
pub use did::{
    address_from_did, address_from_verifying_key, checksummed_address, eip55_checksum,
    identifier_from_did, parse_did_namespace, pubkey_from_ed25519_did, pubkey_from_p256_did,
};
pub use did_method::{all_did_methods, find_did_method, DIDMethod};
pub use key::KeyMethod;
pub use peer::PeerMethod;
pub use pkh::{Ed25519Suite, Eip155Suite, P256Suite, PkhMethod};

// --- Behind `http` feature (session/auth layer) ---
#[cfg(feature = "http")]
pub mod auth_error;
#[cfg(feature = "http")]
pub mod challenge;
#[cfg(feature = "http")]
pub mod message;
#[cfg(feature = "http")]
pub mod session;
#[cfg(feature = "http")]
pub mod types;

#[cfg(feature = "http")]
pub use auth_error::AuthError;
#[cfg(feature = "http")]
pub use challenge::ChallengeStore;
#[cfg(feature = "http")]
pub use message::{build_message, MessageParams};
#[cfg(feature = "http")]
pub use session::SessionStore;
#[cfg(feature = "http")]
pub use types::{AuthenticatedDid, Challenge, Session, SessionInfo, SessionRequest};

// --- Behind `client` feature ---
#[cfg(feature = "client")]
pub mod client;

/// Verify a CAIP-122 session signature.
///
/// Dispatches to the DIDMethod registry (did:pkh, did:key, did:peer).
pub fn verify_caip122(did: &str, message: &str, signature: &[u8]) -> Result<bool, CryptoError> {
    let method = find_did_method(did)
        .ok_or_else(|| CryptoError::UnsupportedMethod(did.to_string()))?;
    method.verify(did, message, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_eip155() {
        use k256::ecdsa::SigningKey;
        use rand::rngs::OsRng;
        use sha3::{Digest, Keccak256};

        let secret = k256::SecretKey::random(&mut OsRng);
        let signing_key = SigningKey::from(&secret);
        let addr = address_from_verifying_key(signing_key.verifying_key());
        let did_str = format!("did:pkh:eip155:1:0x{}", eip55_checksum(&addr));

        let msg = "test dispatch eip155";
        let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
        let prehash: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(prefix.as_bytes());
            h.update(msg.as_bytes());
            h.finalize().into()
        };
        let (sig, rec_id) = signing_key.sign_prehash_recoverable(&prehash).unwrap();
        let mut sig_bytes = [0u8; 65];
        sig_bytes[..64].copy_from_slice(&sig.to_bytes());
        sig_bytes[64] = u8::from(rec_id) + 27;

        assert!(verify_caip122(&did_str, msg, &sig_bytes).unwrap());
    }

    #[test]
    fn dispatch_ed25519() {
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let pubkey = signing_key.verifying_key();
        let did_str = format!("did:pkh:ed25519:0x{}", hex::encode(pubkey.as_bytes()));

        let msg = "test dispatch ed25519";
        let sig = signing_key.sign(msg.as_bytes());

        assert!(verify_caip122(&did_str, msg, &sig.to_bytes()).unwrap());
    }

    #[test]
    fn dispatch_p256() {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        use rand::rngs::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let compressed = verifying_key.to_encoded_point(true);
        let did_str = format!("did:pkh:p256:0x{}", hex::encode(compressed.as_bytes()));

        let msg = "test dispatch p256";
        let sig: Signature = signing_key.sign(msg.as_bytes());

        assert!(verify_caip122(&did_str, msg, &sig.to_bytes()).unwrap());
    }

    #[test]
    fn unsupported_namespace_returns_error() {
        let result = verify_caip122("did:pkh:solana:0xabc", "msg", &[0u8; 64]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, CryptoError::UnsupportedMethod(_)));
    }

    #[test]
    fn invalid_did_prefix_returns_error() {
        let result = verify_caip122("not:a:did", "msg", &[0u8; 64]);
        assert!(result.is_err());
    }

    #[test]
    fn did_key_dispatches() {
        assert!(find_did_method("did:key:z6MkiTBz1y").is_some());
    }
}
```

### Step 7: Verify compilation

- [ ] Run:

```bash
cargo check --no-default-features
```

Expected: compiles (crypto layer only).

- [ ] Run:

```bash
cargo check --features http
```

Expected: compiles (crypto + http layer).

- [ ] Run:

```bash
cargo check --features client
```

Expected: compiles (all features).

- [ ] Verify no SiwxError references remain:

```bash
grep -r 'SiwxError' src/
grep -r 'siwx_core' src/
```

Expected: no output from either command.

### Step 8: Commit

- [ ] Commit the restructuring:

```bash
git add -A
git commit -m "refactor!: absorb siwx-core into aqua-auth, feature-gate HTTP layer

BREAKING: SiwxError renamed to CryptoError, AuthError now wraps
CryptoError via From, verify_caip122 returns CryptoError.
HTTP/session types gated behind 'http' feature.
Bumped to 0.2.0."
```

---

## Task 3: Test suite + quality verification

**Hypotheses:** H8, H9, H10

Run all tests across all feature combinations, clippy, fmt, and publish dry-run.

### Step 1: Run crypto-only tests

- [ ] Run:

```bash
cargo test --no-default-features 2>&1
```

Expected: all crypto/DID tests pass (cipher_suite, did, did_method, pkh/*, key, peer, lib dispatch tests). Count should be >= 70.

### Step 2: Run HTTP tests

- [ ] Run:

```bash
cargo test --features http 2>&1
```

Expected: crypto tests + challenge, session, message tests pass. Count should be >= 85.

### Step 3: Run all tests

- [ ] Run:

```bash
cargo test --features client 2>&1
```

Expected: all tests pass. Count should be >= 85 (client has no inline tests).

### Step 4: Clippy

- [ ] Run:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: clean (exit 0).

### Step 5: Format check

- [ ] Run:

```bash
cargo fmt --check
```

Expected: clean (exit 0). If not, run `cargo fmt` and commit.

### Step 6: Publish dry-run

- [ ] Run:

```bash
cargo publish --dry-run 2>&1
```

Expected: completes without error. Verify no path dependencies remain in the output.

### Step 7: Final commit (if fmt or clippy needed fixes)

- [ ] If any changes were needed:

```bash
git add -A
git commit -m "chore: clippy + fmt cleanup after restructuring"
```

---

## Post-completion checklist

After all tasks complete, verify:

- [ ] `grep -r 'siwx.core' src/` returns nothing (no siwx-core references)
- [ ] `grep -r 'SiwxError' src/` returns nothing
- [ ] `grep -r 'path.*siwx' Cargo.toml` returns nothing (no path dependency)
- [ ] `cargo test --no-default-features` passes >= 70 tests
- [ ] `cargo test --features http` passes >= 85 tests
- [ ] `cargo publish --dry-run` succeeds
- [ ] Version is 0.2.0 in Cargo.toml
