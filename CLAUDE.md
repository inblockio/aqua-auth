# aqua-rs-auth (crate: `aqua-auth`)

## Goal

Universal authentication library for the Aqua Protocol ecosystem. Implements CAIP-122 ("Sign In With X") challenge-response authentication, providing both client and server components for any two Aqua services to authenticate with each other: node-to-node, web-app-to-node, mobile-app-to-node, or any client-server pair.

Intended for publication on **crates.io** as the default auth crate for the Aqua ecosystem.

## Architecture

### Auth Flow

1. Client requests a challenge from the server (`ChallengeStore::create`)
2. Server returns a CAIP-122-compliant message with a nonce
3. Client signs the message with their DID's private key
4. Server verifies the signature (`verify_caip122`) and issues a session token (`SessionStore::create`)
5. Client uses the session token for subsequent requests

### Signature Schemes

Three DID namespaces via `CipherSuite` and `DIDMethod` trait registries:

| Namespace | Accepted login DID formats | Verifier |
|---|---|---|
| `eip155` | `did:pkh:eip155:1:0x{address}` | EIP-191 ecrecover (secp256k1) |
| `ed25519` | `did:key:z6Mk...` **and** `did:pkh:ed25519:0x{pubkey}` | ed25519-dalek |
| `p256` | `did:key:zDn...` **and** `did:pkh:p256:0x{compressed}` | P-256 ECDSA |

**Two spellings, two principals: deliberate (#182, ruled 2026-08-06).** An ed25519/P-256
key may log in as either its `did:key` form or its `did:pkh:{ed25519,p256}` form; **both are
accepted**, and they are **distinct principals**; `canonical_trust_key` keys them separately,
so each spelling has its own grant bucket. A key that uses both spellings therefore holds two
independent identities. This is intentional: they are NOT folded to one principal. (Considered
and rejected: A-strict, reject the did:pkh spelling; and B-fold, canonicalise it to did:key.
The ruling is to accept both as-is; see task #182 / `plans/backend-unification/25`.)

Additionally, `did:peer` (variants 0 and 2) is supported for DID resolution.

If aqua-rs-sdk adds a new signature scheme, this crate must add a corresponding verifier.

### WebAuthn Assertion Verification (feature: `webauthn`)

Standalone P-256 WebAuthn assertion verifier for login flows. Validates rpIdHash, UP flag, origin, challenge, and P-256 signature over `authenticatorData || SHA-256(clientDataJSON)`. No webauthn-rs dependency; uses only `sha2`, `base64`, `serde_json`.

### Module Layout

```
src/
  lib.rs              # Public API, verify_caip122 dispatcher
  cipher_suite.rs     # CipherSuite trait, registry
  crypto_error.rs     # CryptoError enum
  did.rs              # DID parsing, EIP-55, identifier extraction
  did_method.rs       # DIDMethod trait, registry
  pkh/
    mod.rs            # re-exports Eip155Suite, PkhMethod
    method.rs         # PkhMethod (DIDMethod for did:pkh)
    eip155.rs         # Eip155Suite (secp256k1 EIP-191)
  key/
    mod.rs            # KeyMethod (DIDMethod for did:key), multibase decode
    ed25519.rs        # Ed25519Suite
    p256.rs           # P256Suite
  peer/
    mod.rs            # PeerMethod (did:peer variants 0 and 2)
  --- behind feature "http" ---
  auth_error.rs       # AuthError (wraps CryptoError)
  message.rs          # build_message, MessageParams (CAIP-122)
  challenge.rs        # ChallengeStore (nonce + TTL)
  session.rs          # SessionStore (token + background sweep)
  types.rs            # Challenge, Session, SessionInfo, AuthenticatedDid
  wire.rs             # ChallengeEnvelope, SessionRequest, SessionResponse
  --- behind feature "client" ---
  client.rs           # authenticate() async helper
  --- behind feature "webauthn" ---
  webauthn.rs         # verify_webauthn_assertion(), WebAuthnAssertionParams
```

### Store Backend

Currently in-memory (`DashMap`). Non-persistent is acceptable, but the design should evolve toward:

- A pluggable store trait so backends can be swapped
- Redis as the default production backend

## Upstream Dependencies

- **aqua-rs-sdk** (`~/aqua-rs-sdk`): Defines which signature schemes exist in the protocol. This crate's namespace support must stay in sync.

## Consumers

- **aqua-node**: Primary server-side consumer
- **aqua-fire**: Aquafier service
- **Mobile apps**: Client-side auth via the `client` feature
- **Web apps and CLIs**: Any client connecting to an aqua-node

## Standards Compliance

### CAIP-122 Message Format (DO NOT MODIFY without discussion)

The message format in `message.rs` must remain CAIP-122 compliant. Changes to the message structure require review against the CAIP-122 specification. The format is also SIWE-compatible for `eip155` DIDs (renders correctly in MetaMask).

## Public API Surface (DO NOT MODIFY without discussion)

Since this crate is headed for crates.io, the public API is subject to semver. Breaking changes to exported types, traits, or function signatures require a major version bump and explicit discussion.

## Development

### Build & Test

```bash
cargo build                      # Build with default features (crypto/DID only)
cargo build --features http      # Build with session/auth layer
cargo build --features client    # Build with HTTP client (implies http)
cargo build --features webauthn  # Build with WebAuthn assertion verifier
cargo test                       # Run all 76 default tests
cargo test --features webauthn   # Run all 83 tests (includes WebAuthn)
cargo test --all-features        # Run everything
cargo doc --open                 # Generate and view docs
```

### Testing Requirements

Every signature verifier must include:

- **Roundtrip test**: Generate keypair, sign, verify succeeds
- **Wrong-DID test**: Valid signature, wrong DID, verify fails
- **Tampered-message test**: Modify message after signing, verify fails
- **Invalid-signature-length test**: Reject malformed signatures

Challenge and session stores must test: creation, validation, TTL expiration, and cleanup.

### Adding a New Signature Scheme

1. Add a `verify_{scheme}.rs` module with the verification function
2. Add a DID parser in `did.rs` for the new namespace
3. Add a message label/chain-id branch in `message.rs`
4. Wire the namespace into `verify_caip122` in `lib.rs`
5. Add the full test suite (roundtrip + negative tests as above)
6. Confirm the namespace matches what aqua-rs-sdk supports

## Roadmap

- [ ] Pluggable store trait with Redis as default backend
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] crates.io publication prep (README, license file, metadata)

<!-- gitnexus:start -->
# GitNexus: Code Intelligence

This project is indexed by GitNexus as **aqua-rs-auth** (243 symbols, 491 relationships, 21 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

> If any GitNexus tool warns the index is stale, run `npx gitnexus analyze` in terminal first.

## Always Do

- **MUST run impact analysis before editing any symbol.** Before modifying a function, class, or method, run `gitnexus_impact({target: "symbolName", direction: "upstream"})` and report the blast radius (direct callers, affected processes, risk level) to the user.
- **MUST run `gitnexus_detect_changes()` before committing** to verify your changes only affect expected symbols and execution flows.
- **MUST warn the user** if impact analysis returns HIGH or CRITICAL risk before proceeding with edits.
- When exploring unfamiliar code, use `gitnexus_query({query: "concept"})` to find execution flows instead of grepping. It returns process-grouped results ranked by relevance.
- When you need full context on a specific symbol (callers, callees, which execution flows it participates in), use `gitnexus_context({name: "symbolName"})`.

## Never Do

- NEVER edit a function, class, or method without first running `gitnexus_impact` on it.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis.
- NEVER rename symbols with find-and-replace; use `gitnexus_rename` which understands the call graph.
- NEVER commit changes without running `gitnexus_detect_changes()` to check affected scope.

## Resources

| Resource | Use for |
|----------|---------|
| `gitnexus://repo/aqua-rs-auth/context` | Codebase overview, check index freshness |
| `gitnexus://repo/aqua-rs-auth/clusters` | All functional areas |
| `gitnexus://repo/aqua-rs-auth/processes` | All execution flows |
| `gitnexus://repo/aqua-rs-auth/process/{name}` | Step-by-step execution trace |

## CLI

| Task | Read this skill file |
|------|---------------------|
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus/gitnexus-cli/SKILL.md` |

<!-- gitnexus:end -->
