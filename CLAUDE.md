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
  signer.rs           # async Signer trait + SignError (SDK-shape, raw sig bytes)
  principal.rs        # Principal type + authenticate() (scoped-self identity)
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
  session_backend.rs  # SessionBackend trait + InMemoryBackend (storage seam)
  types.rs            # Challenge, Session, SessionInfo, AuthenticatedDid
  wire.rs             # ChallengeEnvelope, SessionRequest, SessionResponse
  --- behind feature "client" ---
  client.rs           # authenticate(&dyn Signer) async client, URI-binding check
  --- behind feature "webauthn" ---
  webauthn.rs         # verify_webauthn_assertion(), WebAuthnAssertionParams
  webauthn_store.rs   # WebauthnCredentialBackend (async trait),
                      #   StoredCredential, InMemoryWebauthnStore
  --- behind features "webauthn" + "redis" ---
  redis_webauthn.rs   # RedisWebauthnStore (the shared production credential
                      #   store; the only thing `redis` still compiles)
  --- behind feature "ceremony" (implies "webauthn") ---
  webauthn_ceremony.rs # register/login over webauthn-rs, passkey -> did:key
  --- behind feature "http-sig" (EXPERIMENTAL, tracks IETF draft) ---
  http_sig/
    mod.rs            # RequestParts, Profile, SignedHeaders, HttpSigError
    base.rs           # RFC 9421 s2.5 signature base construction
    sign.rs           # sign_request() over the Signer trait
    verify.rs         # verify_request() -> Principal, VerifyOptions
    replay.rs         # bounded NonceReplayGuard
aqua-auth-directory/  # workspace member 0.x: public-key advertisement
  src/lib.rs          # KeyRegistry, AdvertisedKey (public keys ONLY, no custody)
  src/thumbprint.rs   # RFC 7638 JWK thumbprints (SHA-256 here is correct)
  src/render.rs       # JWKS + aqua-identity .well-known renderers
```

### Three Proof Surfaces (ruling, 2026-08-30)

Content is signed by aqua-trees (SDK), the connection by CAIP-122 sessions
(this crate), and individual requests by RFC 9421 (`http-sig` feature). Author
is not courier: tree signatures prove authorship, transport auth proves who
delivers now. All verification paths return the same `Principal`; one async
`Signer` drives all three surfaces. `http-sig` and `aqua-auth-directory` track
IETF drafts (web-bot-auth) and are exempt from the semver promise until the
IETF `webbotauth` WG adopts documents. Full rationale: SPEC.md section 11 and
`docs/superpowers/plans/2026-08-30-webbotauth-maturation.md`.

### Store Backend

`SessionStore` drives a pluggable `SessionBackend` (`session_backend.rs`).
`InMemoryBackend` (`DashMap`) is the only implementation this crate ships and
the one every consumer runs. `SessionStore::with_backend` takes any
`Arc<dyn SessionBackend>`, so a consumer needing durable or shared sessions
implements the trait in the crate that owns its connection pool.

A Redis `SessionBackend` lived here until 0.6.0 and was removed: it had no
users, blocked an async executor on a single `Mutex<redis::Connection>`, cost
two full keyspace `SCAN`s per login, and leaked `redis::RedisError` into a
crates.io-bound public API. The trait's two hot-path rules exist so a
replacement does not repeat that: `sessions_for_did` must be served from a
`did -> tokens` index (the login path calls it), and `all()` is cold-path
introspection only.

Passkey credentials are separate and *are* persisted: `WebauthnCredentialBackend`
(`webauthn_store.rs`) with `InMemoryWebauthnStore` and `RedisWebauthnStore`
(`redis_webauthn.rs`), the store aqua-node and aquafier share in production.

That trait is **async** as of 0.7.0, and every method returns `Result`. It was
sync in 0.6.0 on the grounds that it matched "this crate's blocking-Redis
pattern", but 0.6.0 is the release that deleted `RedisBackend`, so the
justification outlived its referent. `RedisWebauthnStore` now holds a
`redis::aio::MultiplexedConnection` (feature `redis/tokio-comp`) instead of a
`Mutex<redis::Connection>`, and `RedisWebauthnStore::connect` is `async`.

## Upstream Dependencies

- **aqua-rs-sdk** (`~/aqua-rs-sdk`): Defines which signature schemes exist in the protocol. This crate's namespace support must stay in sync.

## Consumers

Authoritative list, with each repo's pin, git URL spelling and feature set:
**`CONSUMERS.md`**. Read it before any change to the public API; all
consumers move together, and nothing in this repo verifies that they still
build.

- **aqua-node**: Primary server-side consumer
- **aquafier-rs** (aqua-fire): Aquafier service
- **aqua-state-viewer**: `client` feature
- **siwx-oidc**: `webauthn` feature, unpinned
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
cargo build                       # Default features (crypto/DID + Signer trait)
cargo build --features http       # Session/auth layer
cargo build --features client     # HTTP client (implies http)
cargo build --features webauthn   # WebAuthn assertion verifier
cargo build --features ceremony   # register/login ceremony (implies webauthn)
cargo build --features redis      # Redis credential store (implies webauthn)
cargo build --features http-sig   # RFC 9421 request signatures (experimental)
cargo test                        # Default-feature tests
cargo test --all-features         # Everything (264 lib + integration)
cargo test -p aqua-auth-directory # The directory workspace member
# E2E suites live in the testkit member (publish = false); no feature flags
# needed, the testkit pins the features its suites require:
cargo test -p aqua-auth-testkit                       # all three e2e suites
cargo test -p aqua-auth-testkit --test e2e_inmemory   # in-process harness matrix
cargo test -p aqua-auth-testkit --test e2e_loopback   # real reqwest client over sockets
cargo test -p aqua-auth-testkit --test dst_auth       # turmoil DST, fixed seeds
cargo doc --open                  # Generate and view docs
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

- [x] Pluggable store trait (`SessionBackend`, 0.6.0). Scoped to human web
      sessions: per-request `http-sig` removes SessionStore from pure S2S
      paths. A durable backend now belongs to the consumer that owns the pool,
      not to this crate.
- [ ] Accept-Signature server-issued nonces and RFC 9421 signed responses
      (mutual node-to-node auth); deferred, see SPEC.md section 11
- [ ] siwx-oidc ceremony consolidation: needs a passkey credential data
      migration, an async credential-store trait, and an account-linking API.
      Spec written, NOT executed:
      `docs/superpowers/specs/2026-08-30-siwx-oidc-ceremony-consolidation.md`
- [ ] Revisit the `webauthn-rs = "=0.6.1-dev"` exact prerelease pin before
      publishing. The pin is deliberate: the serialized `Passkey` blob
      (feature `danger-allow-state-serialisation`) must stay byte-compatible
      across aqua-node, aquafier and this crate, so do not relax it casually.
      It does not *block* publication (0.6.1-dev is published on crates.io and
      is not yanked, verified 2026-08-30), but an `=` requirement on a
      published library is a hard graph-wide lock: any downstream crate that
      needs a different `webauthn-rs` gets an unresolvable graph, and the
      pinned version carries no upstream stability promise. Publishing the
      `ceremony` feature means exporting that lock to every user.
- [ ] aqua-timestamps: orphaned consumer, `path = "../aqua-auth"` with no pin
      and a statically broken `client::authenticate` call. Needs a decision,
      see `CONSUMERS.md`.
- [ ] CI/CD pipeline (GitHub Actions). `cargo fmt --check` is clean as of
      0.6.0 and can be gated on.
- [ ] crates.io publication prep (workspace: aqua-auth + aqua-auth-directory)

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
