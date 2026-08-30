# Web Bot Auth Maturation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Mature aqua-auth for production service-to-service and agent authentication: fix the client challenge-binding gap, add an RFC 9421 per-request signature feature (`http-sig`) with DID keyid and web-bot-auth interop, split the repo into a workspace with an `aqua-auth-directory` key-advertisement crate, converge the client on an async `Signer` trait, and document the three-layer proof model. Version goes 0.4.0 to 0.5.0 (breaking OK, stays under 1.0).

**Architecture:** Three proof surfaces share one identity: aqua-trees sign content (SDK), CAIP-122 signs login (existing), RFC 9421 signs individual HTTP requests (new). The internal RFC 9421 profile reuses the existing `CipherSuite`/`DIDMethod` registries: construct the RFC 9421 signature base string, then verify it exactly like a CAIP-122 message via `verify_caip122(did, base, sig)`. No new cryptographic verifiers. The interop profile is draft-meunier-web-bot-auth compliant (Ed25519, JWK-thumbprint keyid, `tag="web-bot-auth"`). Key advertisement (public keys only, never custody) becomes a separate 0.x workspace crate so draft churn never breaks aqua-auth core semver.

**Tech Stack:** Rust 2021, existing deps (k256, ed25519-dalek, p256, sha3, dashmap, reqwest), new: `async-trait` (matches SDK Signer shape), `sfv` (RFC 8941 structured fields), `url` (origin comparison, already in reqwest's tree), `sha2` + `base64` (RFC 7638 thumbprints, already optional deps).

**Baseline (verified 2026-08-30):** v0.4.0, `cargo test --all-features` fully green (119 lib tests + integration suites + 4 principal tests). Memory verdict GREEN.

**Execution:** Wave 0 = orchestrator inline (Task 0). Wave 1 = three parallel opus subagents in worktrees (Tasks 1, 2, 3). Wave 2 = one opus subagent (Task 4). Wave 3 = docs and version bump (Task 5). Orchestrator merges each branch into local main after review and tests, then deletes the branch and removes the worktree (CLAUDE.md worktree hygiene). Replay policy (punch-list item 5) is folded into Task 2 acceptance criteria rather than being a separate task.

**Constraints (apply to every task):**
- No em dashes (U+2014) anywhere in code comments or docs. Use commas, colons, parentheses.
- Branch-per-change; commit incrementally in small coherent stages on the branch; never commit to main.
- TDD: write the failing test first, watch it fail, implement, watch it pass.
- SHA3-256 is an Aqua-tree invariant; it does NOT apply to RFC 7638 JWK thumbprints or RFC 9421, which mandate SHA-256. Do not "fix" SHA-256 usage in Tasks 2 and 3.
- Wire types in `src/wire.rs` intentionally tolerate unknown JSON fields (unlike the SDK's `deny_unknown_fields`). Preserve that.
- Public API is semver-relevant (crates.io-bound). Breaking changes are approved for this cycle only.
- If an assumption breaks (dep API mismatch, draft contradicts this plan, admission control denies a build), STOP and report; do not improvise around it.

---

## Hypothesis Register

| ID | If | Then | Assumptions | Verification |
|----|-----|------|-------------|--------------|
| H1 | The client enforces URI-origin equality between the challenge message and `base_url` before signing | A challenge relayed from another aqua service is refused client-side | Server-issued `URI:` line carries the service's own origin | `cargo test --features client binding` (mismatch test fails closed, match test passes) |
| H2 | We build RFC 9421 signature bases per section 2.5 with `sfv` for structured fields | Signatures roundtrip and verify for all three suites with no new verifier code | `sfv` crate API supports Dictionary/InnerList serialization | `cargo test --features http-sig` roundtrip + negative tests; base-construction unit tests |
| H3 | `keyid` carries the DID and verification dispatches through the existing registries | http-sig verification needs no directory fetch and yields a `Principal` | `CipherSuite::verify` treats the base string as an opaque message (same as CAIP-122) | verify test asserts returned `Principal::did()`; unknown-method DID rejected |
| H4 | Verification enforces created/expires window plus a nonce replay guard | A replayed request inside the window and a stale request outside it are both rejected | Server clock skew within configured tolerance | replay test (second verify of same nonce fails), expiry test, skew test |
| H5 | The repo becomes a two-member workspace with the root package retained in place | Existing consumers of aqua-auth are unaffected; the directory crate builds and tests independently | Cargo allows root `[package]` + `[workspace]` with members `[".", "aqua-auth-directory"]` | root `cargo test --all-features` matches baseline; `cargo test -p aqua-auth-directory` green |
| H6 | RFC 7638 thumbprint over the canonical `{crv,kty,x}` OKP JWK | Reproduces the RFC 8037 Appendix A.3 known-answer vector | none | vector test in aqua-auth-directory |
| H7 | The client takes an async `Signer` (async-trait, carries its own DID) | KMS/wallet-style async signing works and a DID/key mismatch is unrepresentable in the call | consumers can wrap keys in the trait | async-signer integration test (sign fn awaits); `grep -r "sign_fn" src/` empty |
| H8 | All branches merge | Full build matrix and tests pass; docs carry no em dashes | no cross-branch semantic conflicts beyond Cargo.toml | build matrix commands in Task 5 + `grep -rP '\x{2014}' *.md src/` empty |
| H9 | Memory verdict is GREEN before each wave | Three parallel worktree builds complete without admission-control denial | no other heavy load appears | `~/bin/resource-guard.sh verdict` before spawning; agents report denials |

---

## File Structure

```
Cargo.toml                          # gains [workspace], http-sig feature, async-trait, sfv, url deps, v0.5.0
src/signer.rs                       # NEW (Task 0): async Signer trait + SignError
src/client.rs                       # Task 1: binding check; Task 4: Signer-based API
src/http_sig/mod.rs                 # NEW (Task 2): public API, RequestParts, profiles
src/http_sig/base.rs                # NEW (Task 2): signature base construction (RFC 9421 s2.5)
src/http_sig/sign.rs                # NEW (Task 2): sign_request()
src/http_sig/verify.rs              # NEW (Task 2): verify_request(), VerifyOptions, replay guard
tests/http_sig.rs                   # NEW (Task 2)
aqua-auth-directory/Cargo.toml      # NEW (Task 3): v0.1.0
aqua-auth-directory/src/lib.rs      # NEW (Task 3): KeyRegistry, AdvertisedKey
aqua-auth-directory/src/thumbprint.rs # NEW (Task 3): RFC 7638
aqua-auth-directory/src/render.rs   # NEW (Task 3): JWKS + aqua-identity renderers
SPEC.md, README.md, CHANGELOG.md    # Task 5
```

---

## Task 0: Async Signer trait (orchestrator, inline, branch `feature/signer-trait`)

**Hypotheses:** H7 (contract half)
**Files:** Create `src/signer.rs`; Modify `src/lib.rs` (module + re-export), `Cargo.toml` (async-trait dep, always-on)

The contract both Task 2 and Task 4 build against. Mirrors the SDK `Signer` shape (async, carries DID) but returns raw signature bytes, not a `SignatureRevision`, because login and request signatures are not tree revisions.

```rust
//! src/signer.rs
use async_trait::async_trait;

/// Error from a signing backend (local key, KMS, HSM, wallet).
#[derive(Debug, thiserror::Error)]
#[error("signing failed: {0}")]
pub struct SignError(pub String);

/// An asynchronous signer bound to a DID.
///
/// Mirrors the Aqua SDK `Signer` shape (async sign + signer_did) so one key
/// custody point can drive tree signatures, CAIP-122 login signatures, and
/// RFC 9421 request signatures. Returns raw signature bytes in the format the
/// DID's cipher suite verifies (65-byte EIP-191 for eip155, 64-byte raw for
/// ed25519 and p256).
#[async_trait]
pub trait Signer: Send + Sync {
    /// The DID this signer proves possession for.
    fn signer_did(&self) -> &str;
    /// Sign an opaque message string (CAIP-122 message or RFC 9421 signature base).
    async fn sign(&self, message: &str) -> Result<Vec<u8>, SignError>;
}
```

- [ ] Write failing test in `src/signer.rs` `#[cfg(test)]`: implement a local Ed25519 test signer, sign a message, assert `verify_caip122(signer.signer_did(), msg, &sig)` is `Ok(true)`
- [ ] `cargo test signer` fails (module missing), implement, `cargo test signer` passes
- [ ] `cargo build --all-features` green; commit `feat: async Signer trait (SDK-shape, raw signature bytes)`

## Task 1: Client challenge binding (opus subagent, worktree, branch `fix/client-binding-check`)

**Hypotheses:** H1
**Files:** Modify `src/client.rs`, `Cargo.toml` (add `url = "2"` to `client` feature); Test in `src/client.rs` unit tests

The client currently verifies only the identifier line of the returned SIWE message (`client.rs` step 1a). Add step 1b: extract the `URI: ` line from `envelope.message` and require its origin (scheme, lowercased host, port with 80/443 defaulting) to equal `base_url`'s origin. Refuse to sign otherwise. Rationale: a compromised endpoint relaying a victim service's challenge presents a message whose URI origin is the victim's, not the endpoint the client dialed; failing closed kills the relay. The `domain` line is a free-form label (deployed servers use non-hostnames like `aqua-node`), so it is not enforced; document that in the function docs.

Contract:

```rust
/// New error variant on AuthClientError:
#[error("challenge URI origin mismatch: message says {message_origin}, client dialed {client_origin}")]
UriOriginMismatch { message_origin: String, client_origin: String },

/// Pure, unit-testable helper (private):
/// parse `URI: <value>` line from the message; parse both URLs with `url::Url`;
/// compare (scheme, host lowercased, port_or_known_default()).
fn verify_uri_binding(message: &str, base_url: &str) -> Result<(), AuthClientError>
```

- [ ] Failing tests first (unit tests on `verify_uri_binding`): same origin passes (incl. trailing-slash and path differences on base_url); different host fails; different port fails; different scheme fails; explicit `:443` equals default https; missing `URI:` line fails closed; malformed URI in message fails closed
- [ ] Run: `cargo test --features client uri_binding`, expect FAIL, then implement, expect PASS
- [ ] Wire into `authenticate()` after the existing identifier check; existing client tests still pass: `cargo test --features client`
- [ ] Commit stages: tests, then implementation, then wiring. Report branch name, worktree path, full test output.

## Task 2: `http-sig` feature: RFC 9421 request signatures (opus subagent, worktree, branch `feature/http-sig`)

**Hypotheses:** H2, H3, H4
**Files:** Create `src/http_sig/{mod,base,sign,verify}.rs`, `tests/http_sig.rs`; Modify `src/lib.rs` (feature-gated module + re-exports), `Cargo.toml` (feature `http-sig = ["dep:sfv", "dep:base64", "dep:rand"]`)

Framework-agnostic: no `http` crate types. Verify current `sfv` crate API on docs.rs before coding; if `sfv` cannot serialize the needed Dictionary/InnerList shapes, STOP and report.

Core types (public, feature-gated, marked experimental in rustdoc: tracks draft-meunier-web-bot-auth-architecture, exempt from stability promise):

```rust
/// The parts of an HTTP request that participate in signing.
pub struct RequestParts<'a> {
    pub method: &'a str,          // "GET"
    pub target_uri: &'a str,      // full URI, used to derive @authority
    pub signature_agent: Option<&'a str>, // Signature-Agent header value if present
}

pub enum Profile {
    /// keyid = DID, alg implied by DID method, tag = "aqua-auth".
    AquaInternal,
    /// draft-meunier compliant: Ed25519 only, keyid = RFC 7638 JWK thumbprint
    /// (supplied by caller), tag = "web-bot-auth".
    WebBotAuth { jwk_thumbprint: String },
}

/// Output of signing: header values to attach.
pub struct SignedHeaders {
    pub signature_input: String,  // `sig1=("@authority");created=...;expires=...;keyid="...";alg="...";nonce="...";tag="..."`
    pub signature: String,        // `sig1=:BASE64:`
}

pub async fn sign_request(
    signer: &dyn crate::Signer,
    parts: &RequestParts<'_>,
    profile: &Profile,
    validity: std::time::Duration,     // caps expires - created; cap at 24h per draft
) -> Result<SignedHeaders, HttpSigError>;

pub struct VerifyOptions {
    pub expected_tag: String,              // "aqua-auth" or "web-bot-auth"
    pub clock_skew: std::time::Duration,   // default 60s
    pub replay_guard: Option<std::sync::Arc<NonceReplayGuard>>,
}

/// DashMap-backed seen-nonce store with TTL sweep, same hygiene pattern as
/// ChallengeStore (bounded capacity, evict expired). ChallengeStore itself
/// stays the issuing store for the future Accept-Signature flow; note this
/// in the module docs, do not implement Accept-Signature now.
pub struct NonceReplayGuard { /* DashMap<String, Instant>, capacity bound */ }

/// Internal profile verification: parse Signature-Input + Signature,
/// rebuild the signature base, read the DID from keyid, then dispatch
/// through verify_caip122(did, base, sig). Returns the authenticated
/// Principal. Enforces: tag match, created <= now+skew, now < expires,
/// expires - created <= 24h, nonce unseen (when guard present), alg
/// consistent with the DID's method_label.
pub fn verify_request(
    parts: &RequestParts<'_>,
    signature_input: &str,
    signature: &str,
    opts: &VerifyOptions,
) -> Result<crate::Principal, HttpSigError>;
```

Signature base rules to implement in `base.rs` (RFC 9421 section 2.5; the agent MUST verify exact serialization details against RFC 9421 and pin the draft revision consulted in module docs):

```text
"@authority": <host[:port] from target_uri, port omitted when default>
"signature-agent": <value>              # only when covered
"@signature-params": <inner list serialization>
```

Covered components fixed per profile: `("@authority")`, plus `"signature-agent"` when the header is present. Base string joins lines with `\n`, no trailing newline. The `@signature-params` line value is the `sfv` InnerList serialization with params in order: created, expires, keyid, alg, nonce, tag. Nonce: 64 random bytes, base64url no padding.

- [ ] `base.rs` tests first: known-input base construction tests (fixed created/expires/keyid/nonce/tag, assert the exact multi-line string); authority derivation (default port elision, IPv6 host, explicit non-default port)
- [ ] `sign.rs` + `verify.rs` via `tests/http_sig.rs`, per CLAUDE.md verifier requirements, for EACH of ed25519 (did:key z6Mk), p256 (did:key zDn), eip155 (did:pkh): roundtrip (sign with local key via a test Signer impl, verify returns Principal with matching DID); wrong-DID (valid sig, keyid swapped to another DID, verify fails); tampered (flip authority after signing, fails); malformed signature length fails
- [ ] Replay/window tests: same nonce twice with guard fails second time; expired window fails; created in future beyond skew fails; validity > 24h rejected at sign time; alg/DID-method mismatch fails
- [ ] WebBotAuth profile test: ed25519 sign, headers carry `tag="web-bot-auth"` and the supplied thumbprint keyid; non-ed25519 DID with WebBotAuth profile errors
- [ ] `cargo test --features http-sig` green, `cargo build` (default features) untouched and green
- [ ] Commit stages: base + tests, sign, verify, replay guard, docs. Report branch, worktree path, test output, and which draft revision was pinned.

## Task 3: Workspace split + aqua-auth-directory crate (opus subagent, worktree, branch `feature/directory-crate`)

**Hypotheses:** H5, H6
**Files:** Modify root `Cargo.toml` (append `[workspace]` with `members = [".", "aqua-auth-directory"]`, `resolver = "2"`); Create `aqua-auth-directory/{Cargo.toml,src/lib.rs,src/thumbprint.rs,src/render.rs}`

Scope: public key advertisement only. If any API in this crate would touch a private key, STOP: the boundary is wrong. Crate v0.1.0, depends on aqua-auth by path+version for `pubkey_from_ed25519_did`. Deps: serde, serde_json, sha2, base64, thiserror. Framework-agnostic renderers return documents as data; services mount them in their own routers.

```rust
/// One advertised public key.
pub struct AdvertisedKey {
    pub did: String,           // did:key z6Mk form (Ed25519 only in v0.1)
    pub nbf: u64,              // unix seconds, inclusive
    pub exp: u64,              // unix seconds, exclusive
}

pub struct KeyRegistry { /* Vec<AdvertisedKey> */ }
impl KeyRegistry {
    pub fn add(&mut self, key: AdvertisedKey) -> Result<(), DirectoryError>; // rejects exp <= nbf, non-ed25519 did
    /// Keys valid at `now`, plus keys inside their rotation overlap
    /// (both predecessor and successor listed while windows overlap).
    pub fn active(&self, now: u64) -> Vec<&AdvertisedKey>;
}

/// A rendered .well-known document plus its HTTP metadata, as data.
pub struct DirectoryDocument {
    pub path: &'static str,       // the .well-known path constant
    pub content_type: &'static str,
    pub cache_control: String,    // max-age derived from soonest exp among active keys, floor 60s
    pub body: String,             // serialized JSON
}

pub const WELL_KNOWN_HTTP_MESSAGE_SIGNATURES: &str = "/.well-known/http-message-signatures-directory";
pub const WELL_KNOWN_AQUA_IDENTITY: &str = "/.well-known/aqua-identity";

/// draft-meunier-http-message-signatures-directory JWKS view. The agent MUST
/// fetch the current draft, pin the revision in module docs, and use its
/// exact media type and JWKS shape (kty OKP, crv Ed25519, x, kid = RFC 7638
/// thumbprint, use "sig", nbf, exp).
pub fn render_jwks(registry: &KeyRegistry, now: u64) -> Result<DirectoryDocument, DirectoryError>;

/// Aqua-native identity document, content type application/json:
/// {"version":1,"dids":[...],"keys":[{"did","thumbprint","nbf","exp"}]}
pub fn render_aqua_identity(registry: &KeyRegistry, now: u64) -> Result<DirectoryDocument, DirectoryError>;

/// thumbprint.rs: RFC 7638 over the canonical OKP JWK {"crv","kty","x"}
/// (lexicographic member order, no whitespace), SHA-256, base64url no pad.
pub fn okp_thumbprint(crv: &str, x_b64url: &str) -> String;
```

- [ ] Workspace first: append `[workspace]` to root Cargo.toml, `cargo test --all-features` at root must match baseline before any new code (H5 gate)
- [ ] `thumbprint.rs` test first: RFC 8037 Appendix A.3 known-answer vector (JWK `{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}` thumbprints to `kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k`); fetch RFC 8037 to confirm the vector before hardcoding, STOP if it differs
- [ ] Registry tests: add/reject invalid windows, reject non-ed25519 DIDs, `active()` at boundaries (nbf inclusive, exp exclusive), rotation overlap returns both keys
- [ ] Renderer tests: JWKS body parses as JSON, kid equals computed thumbprint, x matches the DID's raw pubkey b64url, nbf/exp present, cache_control floor respected; aqua-identity body shape as specified; expired-only registry renders empty key list (valid, not an error)
- [ ] `cargo test -p aqua-auth-directory` and root `cargo test --all-features` green
- [ ] Commit stages: workspace, thumbprint, registry, renderers. Report branch, worktree path, test output, pinned draft revision and media type used.

## Task 4: Client convergence on async Signer (opus subagent, worktree, branch `refactor/async-signer`, AFTER Task 1 merged)

**Hypotheses:** H7
**Files:** Modify `src/client.rs`, `src/lib.rs` (re-export unchanged), README example if it shows `sign_fn`

Replace the sync `sign_fn` parameter with the Task 0 trait. Breaking change, approved. New signature:

```rust
pub async fn authenticate(
    http: &reqwest::Client,
    base_url: &str,
    signer: &dyn crate::Signer,
) -> Result<Session, AuthClientError> {
    let did = signer.signer_did();
    // ... unchanged flow: challenge, identifier check, uri binding check (Task 1) ...
    let sig_bytes = signer.sign(&envelope.message).await
        .map_err(|e| AuthClientError::Sign(e.to_string()))?;
    let signature = format!("0x{}", hex::encode(sig_bytes));
    // ... unchanged: SessionRequest { did: did.to_string(), nonce, signature } ...
}
```

The `did` parameter is gone (read from the signer, making DID/key mismatch unrepresentable). `AuthClientError::Sign(String)` stays.

- [ ] Failing test first: local Ed25519 test `Signer` whose `sign` awaits `tokio::time::sleep(10ms)` before signing (proves the async path), used against a mocked flow (unit-test the signing + request-construction seam; do not add a mock HTTP dep, factor the post-challenge step into a testable function if needed)
- [ ] Migrate existing client tests from `sign_fn` closures to test Signer impls; `grep -rn "sign_fn" src/ tests/` must return nothing
- [ ] `cargo test --features client` and `cargo build --all-features` green
- [ ] Commit stages: trait adoption, test migration. Report branch, worktree path, test output.

## Task 5: Docs, CHANGELOG, version bump (orchestrator or single subagent, branch `docs/three-layer-spec`, AFTER all merges)

**Hypotheses:** H8
**Files:** Modify `SPEC.md`, `README.md`, root `Cargo.toml` (version = "0.5.0"), project `CLAUDE.md` (module layout, feature list, build commands); Create `CHANGELOG.md`

- [ ] SPEC.md: add "Three proof surfaces" section (content/aqua-trees, connection/CAIP-122, request/RFC 9421), the author-vs-courier distinction, the http-sig profiles (internal DID keyid, web-bot-auth interop), replay policy, and the directory crate boundary (public advertisement only, custody stays with Signer)
- [ ] README.md: feature table gains `http-sig`; client example updated to the Signer API; workspace layout note; explicit "experimental, tracks IETF draft" marker on http-sig and the directory crate
- [ ] CHANGELOG.md: 0.5.0 entry: breaking (authenticate signature, new AuthClientError variant), added (Signer trait, http-sig feature, aqua-auth-directory 0.1.0, URI binding check), rationale one-liners
- [ ] Bump root Cargo.toml to 0.5.0; `cargo build` green
- [ ] Verification sweep: `grep -rP '\x{2014}' README.md SPEC.md CHANGELOG.md CLAUDE.md docs/ src/ aqua-auth-directory/` returns nothing; full matrix: `cargo test` (default), `cargo test --features http`, `cargo test --features client`, `cargo test --features webauthn`, `cargo test --features http-sig`, `cargo test --all-features`, `cargo test -p aqua-auth-directory`
- [ ] Commit; orchestrator merges and runs the Phase 3 audit

---

## Self-Review Notes

- Spec coverage: punch-list items 1 through 6 map to Tasks 1, 5, 2, 3, 2 (folded), 0+4 respectively.
- Accept-Signature server-issued nonces and RFC 9421 signed responses (mutual auth) are explicitly deferred; noted in module docs, not implemented (YAGNI).
- Type consistency: `Signer`/`SignError` (Task 0) are the names used in Tasks 2 and 4; `Principal` return in Task 2 matches `src/principal.rs`.
- GitNexus MCP tools are not available in this session; mitigation is the full test matrix, baseline comparison, and orchestrator diff review at merge time.
