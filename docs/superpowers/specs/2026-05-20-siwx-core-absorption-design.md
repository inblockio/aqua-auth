# Design: Absorb siwx-core into aqua-auth

**Date:** 2026-05-20
**Status:** Draft
**Goal:** Eliminate the siwx-oidc sibling-checkout build dependency by absorbing siwx-core into aqua-auth, feature-gating the HTTP/session layer, and publishing to crates.io.

## Problem

aqua-auth depends on `siwx-core` via `path = "../siwx-oidc/siwx-core"`. This means every project that uses aqua-auth must also clone the siwx-oidc repo as a sibling directory. This is undocumented, breaks Docker builds, and will break every new CI pipeline.

The fix the assessment recommended (promote `identifier_from_did`, delete orphaned files) is necessary but insufficient. The structural issue is the path dependency itself.

## Solution

Absorb siwx-core's full public API into aqua-auth behind the default feature set. Gate aqua-auth's HTTP/session layer behind an `http` feature. Publish to crates.io so all consumers use versioned dependencies.

After the merge, `siwx-core` as a standalone crate is deleted from the siwx-oidc repo. siwx-oidc switches to `aqua-auth = "0.1"` from crates.io.

## Feature gate structure

### `default` (crypto/DID layer)

Everything that was siwx-core, plus `identifier_from_did` and `verify_caip122`.

**Public API:**

| Item | Type | Description |
|---|---|---|
| `CryptoError` | enum | Renamed from `SiwxError`. Variants: `UnsupportedMethod`, `InvalidDid`, `InvalidSignature`, `VerificationFailed`, `HexDecode` |
| `CipherSuite` | trait | `namespace()`, `has_chain_id()`, `did_segments()`, `verify()`, `parse_did_parts()` |
| `DIDMethod` | trait | `method_name()`, `supports_did()`, `display_label()`, `address_for_message()`, `has_chain_id()`, `chain_id()`, `canonical_subject()`, `verify()` |
| `PkhMethod` | struct | `DIDMethod` impl for `did:pkh:*` |
| `KeyMethod` | struct | `DIDMethod` impl for `did:key:*` |
| `PeerMethod` | struct | `DIDMethod` impl for `did:peer:*` (v0 + v2) |
| `Eip155Suite` | struct | `CipherSuite` impl for `eip155` (secp256k1 + EIP-191) |
| `Ed25519Suite` | struct | `CipherSuite` impl for `ed25519` |
| `P256Suite` | struct | `CipherSuite` impl for `p256` (NIST) |
| `find_did_method(did) -> Option<Box<dyn DIDMethod>>` | fn | Registry lookup by DID string |
| `all_did_methods() -> Vec<Box<dyn DIDMethod>>` | fn | All registered methods |
| `find_cipher_suite(ns) -> Option<Box<dyn CipherSuite>>` | fn | Registry lookup by namespace |
| `all_cipher_suites() -> Vec<Box<dyn CipherSuite>>` | fn | All registered suites |
| `parse_did_namespace(did) -> Result<&str, CryptoError>` | fn | Extract namespace from `did:pkh:*` |
| `address_from_did(did) -> Result<[u8; 20], CryptoError>` | fn | Parse eip155 DID to raw address |
| `pubkey_from_ed25519_did(did) -> Result<[u8; 32], CryptoError>` | fn | Parse ed25519 DID to pubkey |
| `pubkey_from_p256_did(did) -> Result<[u8; 33], CryptoError>` | fn | Parse p256 DID to compressed pubkey |
| `address_from_verifying_key(key) -> [u8; 20]` | fn | Derive Ethereum address from secp256k1 key |
| `eip55_checksum(addr) -> String` | fn | EIP-55 mixed-case checksum encoding |
| `identifier_from_did(did) -> Result<String, CryptoError>` | fn | Human-readable identifier for CAIP-122 messages. Currently in orphaned `did.rs`, promoted here. |
| `verify_caip122(did, message, signature) -> Result<bool, CryptoError>` | fn | Signature verification dispatch. Currently returns `AuthError`, changed to `CryptoError` since it's pure crypto. |
| `checksummed_address(did) -> Result<String, CryptoError>` | fn | EIP-55 checksummed address from eip155 DID |

**Dependencies (always linked):**

- `k256` 0.13 (ecdsa)
- `ed25519-dalek` 2 (rand_core)
- `p256` 0.13 (ecdsa)
- `sha3` 0.10
- `bs58` 0.5
- `hex` 0.4
- `thiserror` 2
- `serde` 1 (derive)

### `http` feature (session/auth layer)

Implies `default`. Adds challenge/session management, message construction, and protocol types.

**Public API:**

| Item | Type | Description |
|---|---|---|
| `AuthError` | enum | Session/challenge errors + `From<CryptoError>`. Variants: `UnsupportedMethod`, `InvalidDid`, `InvalidSignature`, `HexDecode`, `ChallengeNotFound`, `ChallengeExpired`, `VerificationFailed`, `SessionNotFound`, `SessionExpired` |
| `ChallengeStore` | struct | In-memory nonce store. DashMap-backed, 5-min default TTL. |
| `SessionStore` | struct | In-memory session store. DashMap-backed, 1-hr default TTL, background cleanup task. |
| `build_message(params) -> Result<String, AuthError>` | fn | CAIP-122 message construction for eip155/ed25519/p256 |
| `MessageParams` | struct | Input to `build_message`: did, domain, uri, nonce, issued_at, expiration_time |
| `Challenge` | struct | did, nonce, message, expires_at |
| `Session` | struct | did, token, valid_until, created_at |
| `SessionRequest` | struct | did, nonce, signature |
| `AuthenticatedDid` | newtype | Wrapper for Axum request extensions |
| `SessionInfo` | struct | did, created_at, valid_until (no token, safe to expose) |
| `DEFAULT_CHALLENGE_TTL_SECS` | const | 300 |
| `DEFAULT_SESSION_TTL_SECS` | const | 3600 |
| `DEFAULT_CLEANUP_INTERVAL_SECS` | const | 60 |

**Additional dependencies (only with `http`):**

- `rand` 0.8
- `serde_json` 1
- `chrono` 0.4 (serde)
- `dashmap` 6
- `tokio` 1 (time, rt)

### `client` feature (HTTP auth client)

Implies `http`. Adds reqwest-based authentication flow.

**Public API:**

| Item | Type | Description |
|---|---|---|
| `authenticate(http, base_url, did, sign_fn) -> Result<Session, AuthClientError>` | async fn | Full SIWE auth flow: GET challenge, sign, POST session |
| `AuthClientError` | enum | Http, Sign, Auth variants |

**Additional dependencies (only with `client`):**

- `reqwest` 0.12 (json, rustls-tls)

## Module layout

```
src/
  lib.rs                     # conditional module declarations + re-exports
  crypto_error.rs            # CryptoError (renamed SiwxError)
  cipher_suite.rs            # CipherSuite trait + find/all registry
  did.rs                     # DID parsing + identifier_from_did (merged)
  did_method.rs              # DIDMethod trait + find/all registry
  pkh/
    mod.rs                   # re-exports PkhMethod + suites
    method.rs                # DIDMethod for did:pkh
    eip155.rs                # CipherSuite for eip155
    ed25519.rs               # CipherSuite for ed25519
    p256.rs                  # CipherSuite for p256
  key/
    mod.rs                   # DIDMethod for did:key
  peer/
    mod.rs                   # DIDMethod for did:peer (v0/v2)
  # --- gated on `http` feature ---
  auth_error.rs              # AuthError + From<CryptoError>
  message.rs                 # build_message (CAIP-122)
  challenge.rs               # ChallengeStore
  session.rs                 # SessionStore
  types.rs                   # Challenge, Session, SessionRequest, etc.
  # --- gated on `client` feature ---
  client.rs                  # authenticate()
```

## Error type design

### CryptoError (always available)

```rust
#[derive(Debug, thiserror::Error)]
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

### AuthError (behind `http` feature)

```rust
#[derive(Debug, thiserror::Error)]
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

This is a minor breaking change from the current `AuthError` which flattens crypto variants inline. The `#[error(transparent)]` delegation preserves error messages. Consumers matching on e.g. `AuthError::InvalidDid` would switch to `AuthError::Crypto(CryptoError::InvalidDid(...))`, or use `CryptoError` directly in crypto-only contexts.

## Migration path for each consumer

### aqua-timestamps

**Before:**
```toml
aqua-auth = { path = "../aqua-auth" }
# also needs ../siwx-oidc checked out as sibling
```

**After:**
```toml
aqua-auth = { version = "0.1", features = ["http"] }
```

Code changes:
- `use aqua_auth::verify_caip122` still works but now returns `CryptoError` instead of `AuthError`. Since aqua-timestamps maps auth errors to HTTP status codes, the match arms need updating (or use `AuthError::Crypto(e)` via the `http` feature).
- All other imports (`ChallengeStore`, `SessionStore`, types) unchanged.

### siwx-oidc

**Before:**
```toml
siwx-core = { path = "siwx-core" }
```

**After:**
```toml
aqua-auth = "0.1"
```

Code changes:
- `use siwx_core::` becomes `use aqua_auth::`
- `SiwxError` becomes `CryptoError`
- All trait and function names unchanged

### siwx-core directory

Deleted from `siwx-oidc/`. The subcrate no longer exists.

## What gets deleted from aqua-auth

| File | Reason |
|---|---|
| `src/verify_eip191.rs` | Logic lives in `pkh/eip155.rs` (from siwx-core) |
| `src/verify_ed25519.rs` | Logic lives in `pkh/ed25519.rs` (from siwx-core) |
| `src/verify_p256.rs` | Logic lives in `pkh/p256.rs` (from siwx-core) |
| Current `src/did.rs` | Replaced by siwx-core's `did.rs` + `identifier_from_did` added |

## Cargo.toml shape

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

## Test plan

### Before implementation

- `cargo test -p aqua-auth` passes (baseline, current state)
- `cargo test -p siwx-core` passes (baseline, siwx-core's 39 tests)

### After merge

- All 39 siwx-core tests pass inside aqua-auth (default features)
- All existing aqua-auth tests pass with `--features http`
- `cargo test --no-default-features` compiles and runs crypto tests only
- `cargo test --features http` runs crypto + session tests
- `cargo test --features client` runs all tests
- `cargo clippy --workspace --all-targets -- -D warnings` clean
- `cargo fmt --check` clean
- `identifier_from_did` has tests (migrated from orphaned `did.rs`)

### After publishing

- `cargo publish --dry-run` succeeds
- A scratch project can `cargo add aqua-auth` and `use aqua_auth::find_did_method`
- aqua-timestamps builds with `aqua-auth = { version = "0.2", features = ["http"] }` from crates.io (or path dep during development)
- siwx-oidc builds with `aqua-auth = "0.2"` from crates.io (or path dep during development)

## Versioning

Bump to `0.2.0` since this is a breaking change (new error types, new module paths). The `0.x` semver allows breaking changes at minor bumps.

## Out of scope

- Persistent session store (future, behind a separate feature flag)
- Per-DID rate limiting middleware (future, separate crate or feature)
- Axum extractors or middleware (belongs in consuming services, not the auth library)
- New DID method implementations (add later as needed)
