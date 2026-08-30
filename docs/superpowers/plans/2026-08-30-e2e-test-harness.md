# E2E Test Harness Implementation Plan (Phases 1 + 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give aqua-auth true end-to-end coverage without spawning full services: an in-process `AquaPeer` harness driven three ways (in-memory tower calls, loopback sockets for the real reqwest client, turmoil deterministic network simulation), covering the full login flow for all five DID spellings plus adversarial and network-hardship cases.

**Architecture:** One peer definition, three mounting modes. `tests/harness/mod.rs` defines `AquaPeer` (identity + ChallengeStore/SessionStore + NonceReplayGuard + KeyRegistry + axum Router over the real crate APIs). Mode 1 drives the Router in-memory via `tower::ServiceExt::oneshot` (no sockets). Mode 2 binds `127.0.0.1:0` so the real `client::authenticate()` (reqwest) runs end to end. Mode 3 mounts the same peer as turmoil hosts under injected latency, partitions, and duplication with fixed seeds. Elon-pass deletions (deliberate, do not add back): no containers, no testkit crate, no clock injection into `src/`, no transcript or agent-behavior layer (that framework belongs to the agentic-commerce effort, out of this repo).

**Tech Stack:** dev-dependencies ONLY: `axum` (0.8), `tower` (for `ServiceExt::oneshot`), `turmoil` (0.7), plus existing `tokio`/`rand` and workspace crates (`aqua-auth` with features, `aqua-auth-directory`). The published dependency surface of both crates must not change.

**Baseline (verified 2026-08-30, post-0.5.0):** `cargo test --all-features` = 247 lib + 15 http_sig + 4 principal + 1 doctest; `cargo test -p aqua-auth-directory` = 35; clippy clean; memory verdict GREEN.

**Execution:** Wave 1 = one opus subagent (Tasks A+B, the harness is the contract). Wave 2 = two parallel opus subagents (Task C, Task D) branching from merged main. Orchestrator merges, cleans worktrees, audits.

**Constraints (every task):**
- No em dashes (U+2014) anywhere. TDD (failing test first). Small staged commits on the branch, never on main. Stop and report on broken assumptions or admission-control denials (wait 60s, one retry). Ephemeral ports only; no network beyond loopback; no fixed sleeps for correctness (polling/retry loops with caps are fine).
- Integration-test crates cannot see `#[cfg(test)]` modules in `src/` (each `tests/*.rs` file is its own crate). The harness defines its own signers. Subdirectories of `tests/` are not compiled as test crates, so `tests/harness/mod.rs` is shared via `mod harness;` in each suite file.
- Do not modify anything under `src/` or `aqua-auth-directory/src/`. If a harness need seems to require it, STOP and report (that is a design signal, not a workaround target).

---

## Hypothesis Register

| ID | If | Then | Assumptions | Verification |
|----|-----|------|-------------|--------------|
| HA1 | An axum Router wired over the real stores/verifiers is driven via `oneshot` | The full login flow passes in-memory for all five DID spellings | axum 0.8 + tower dev-deps suffice | `cargo test --test e2e_inmemory` matrix tests |
| HA2 | The same router receives malformed/adversarial requests | Server rejects over the wire with correct 4xx (unknown nonce, consumed nonce, expired challenge, wrong DID, tampered signature, http-sig replay, tampered authority) | short TTLs make expiry testable without clock injection | negative tests in `e2e_inmemory` |
| HB1 | A peer is bound on `127.0.0.1:0` | The real `client::authenticate()` (reqwest) completes and the minted token validates server-side | base_url must be constructed after binding | `cargo test --test e2e_loopback` happy-path tests |
| HB2 | A relay peer returns a victim peer's challenge envelope | The client dies with `UriOriginMismatch` before its signer is invoked | client-side origin check (0.5.0) behaves identically over real HTTP | loopback relay test asserting variant + signer call count 0 |
| HC1 | The same peer serves as a turmoil host under injected latency and a partition-then-heal | Auth completes deterministically under a fixed seed | turmoil 0.7 axum glue works as in the upstream example; wall-clock TTLs do not expire because sim wall time is short | `cargo test --test dst_auth` scenario tests |
| HC2 | An identical session POST is delivered twice (duplication) | Exactly one session is minted; the duplicate gets 401 via single-use nonce | none beyond HC1 | dst duplicate test |
| HD1 | All harness work lands | Only `[dev-dependencies]` changed; the full existing matrix stays green | none | `git diff main -- Cargo.toml` + full matrix |
| HD2 | (Risk) turmoil API drift vs the docs consulted | Agent verifies the upstream axum example against the pinned turmoil version before writing scenarios | crates.io reachable | agent report pins the version + example commit |

Determinism scope note (pin in `dst_auth.rs` docs): fixed seeds make turmoil's scheduling and fault injection reproducible; nonce bytes still come from `OsRng` inside the crate, so assertions must never depend on nonce values, only on outcomes.

---

## Task A: `tests/harness/mod.rs`, the AquaPeer (wave 1, with Task B; branch `feature/e2e-harness`)

**Hypotheses:** HA1 (contract half), HD1
**Files:** Create `tests/harness/mod.rs`, `tests/harness/signers.rs`; Modify `Cargo.toml` (`[dev-dependencies]` only: axum, tower)

Contract (exact; Tasks C and D code against it):

```rust
// tests/harness/mod.rs
pub struct AquaPeer {
    pub name: String,               // used as the CAIP-122 domain label
    pub base_url: String,           // the uri baked into challenges
    pub signer: std::sync::Arc<dyn aqua_auth::Signer>, // this peer's own identity
    pub challenges: std::sync::Arc<aqua_auth::ChallengeStore>,
    pub sessions: std::sync::Arc<aqua_auth::SessionStore>,
    pub replay_guard: std::sync::Arc<aqua_auth::http_sig::NonceReplayGuard>,
    pub registry: std::sync::Arc<aqua_auth_directory::KeyRegistry>,
}

impl AquaPeer {
    /// In-memory peer; base_url is fictional (e.g. "http://peer-a.test").
    /// challenge_ttl_secs is configurable so expiry tests can use 1s.
    pub fn in_memory(name: &str, base_url: &str, challenge_ttl_secs: u64,
                     signer: std::sync::Arc<dyn aqua_auth::Signer>) -> Self;
    /// Bind 127.0.0.1:0 FIRST, then construct the peer with the real
    /// base_url ("http://127.0.0.1:{port}"), then serve. Returns the peer,
    /// the bound base_url, and the serve task handle (abort on drop is fine).
    pub async fn bind_loopback(name: &str, challenge_ttl_secs: u64,
                               signer: std::sync::Arc<dyn aqua_auth::Signer>)
        -> (Self, String, tokio::task::JoinHandle<()>);
    /// The axum Router (clones the Arcs into state). Same router in all modes.
    pub fn router(&self) -> axum::Router;
}
```

Routes (thin handlers over real crate APIs, mirroring the README server quick start):

| Route | Behavior |
|---|---|
| `GET /auth/challenge?did=` | `ChallengeStore::create(did)`, return `ChallengeEnvelope` JSON; 400 on missing/unsupported did |
| `POST /auth/session` | body `SessionRequest`; `challenges.validate(nonce)` (404/401 on unknown or expired), stored DID must equal body DID, hex-decode sig, `aqua_auth::authenticate(did, stored.message, sig)`, then `sessions.create()`; 401 on any failure, 200 `SessionResponse` on success |
| `GET /whoami` | `Authorization: Bearer <token>` validated in `SessionStore`; 200 `{"did": ...}` or 401 |
| `GET /sig/whoami` | read `Signature-Input`/`Signature` headers, build `RequestParts` from the real request (method, authority from Host header, path), `verify_request` with `VerifyOptions::aqua_internal().with_replay_guard(...)`; 200 `{"did": principal.did()}` or 401 |
| `GET /.well-known/http-message-signatures-directory` | `render_jwks(&registry, now)`, served with its content_type and cache_control |
| `GET /.well-known/aqua-identity` | `render_aqua_identity(&registry, now)`, same treatment |

`tests/harness/signers.rs`: local async `Signer` impls for the five spellings, mirroring the pattern of `src/http_sig/test_signers.rs` (unreachable from integration crates, hence the mirror): `ed25519_did_key()`, `ed25519_did_pkh()`, `p256_did_key()`, `p256_did_pkh()`, `eip155()`. Each generates a fresh key and produces the byte formats the suites verify (65-byte EIP-191 recoverable with +27 recovery byte for eip155; 64-byte raw for the others). Registry population: the peer's own key is advertised when it is an ed25519 did:key signer; otherwise the registry stays empty (directory endpoints still render, with an empty key list).

- [ ] Add dev-deps; write a failing smoke test in Task B's file first (see Task B step 1); implement `mod.rs` + `signers.rs` until it compiles and the smoke test passes
- [ ] Commit stages: dev-deps, signers, peer + router

## Task B: `tests/e2e_inmemory.rs`, matrix + adversarial suite (wave 1, same agent/branch as A)

**Hypotheses:** HA1, HA2
**Files:** Create `tests/e2e_inmemory.rs` (`mod harness;` at top)

All tests drive `peer.router().oneshot(request)` (import `tower::ServiceExt`). Client-side logic is hand-rolled in the test (build the GET, parse the envelope, sign with the harness signer, POST), since reqwest is out of scope for this suite; that hand-rolled path exercises the server half over real HTTP semantics.

- [ ] **Smoke test first (red):** `in_memory` peer, ed25519 did:key login flow end to end (challenge, sign, session, then `/whoami` with the token). Watch it fail to compile, then implement Task A until green
- [ ] **Matrix (5 tests):** the same flow for ed25519 did:key, ed25519 did:pkh, p256 did:key, p256 did:pkh, eip155; each asserts 200s, `SessionResponse.did` equals the signer DID, and `/whoami` returns it
- [ ] **Adversarial (7+ tests):** unknown nonce 401/404; nonce consumed by a successful login cannot be replayed (second POST 401); expired challenge (ttl 1s, `tokio::time::sleep` 1.2s real) 401; DID mismatch (challenge for A, session POST claims B) 401; tampered signature 401; `/whoami` with garbage token 401
- [ ] **http-sig over the wire (3+ tests):** `sign_request` for a GET to `/sig/whoami` (authority = the fictional host), attach headers, oneshot: 200 with the DID; replay the same signed request: 401 (guard); tamper the authority (different Host header than signed): 401
- [ ] **Directory (2 tests):** both `.well-known` routes return the rendered body, correct content type, and (for an ed25519 did:key peer) a kid equal to the registry thumbprint
- [ ] `cargo test --test e2e_inmemory` all green; full `cargo test --all-features` still green; commit stages: matrix, adversarial, http-sig, directory

## Task C: `tests/e2e_loopback.rs`, the real client (wave 2; branch `feature/e2e-loopback`)

**Hypotheses:** HB1, HB2
**Files:** Create `tests/e2e_loopback.rs` (`mod harness;`)

First step: `git merge main` in the worktree; confirm `tests/harness/mod.rs` exists, STOP if not. Keep the suite small (the in-memory suite owns breadth; this suite owns "the real reqwest path works"). Requires `--features client`; put `#![cfg(feature = "client")]` at the top so default builds skip it.

- [ ] **Happy path (3 tests):** `bind_loopback` peer; `aqua_auth::client::authenticate(&reqwest::Client::new(), &base_url, &*signer)` for ed25519 did:key, p256 did:pkh, eip155; assert the session DID and that `/whoami` accepts the token via reqwest
- [ ] **Relay defense (1 test):** bind victim peer A and a relay: a second router whose `/auth/challenge` returns a pre-fetched envelope from A verbatim (capture it with one reqwest GET in the test setup) and whose `/auth/session` would forward. Run `client::authenticate` against the relay's base_url with a call-counting signer: must fail with `AuthClientError::UriOriginMismatch` and the signer must never have been invoked
- [ ] **Failure mapping (2 tests):** server that returns 500 on `/auth/challenge` maps to `AuthClientError::Http`; tampered envelope message (identifier swapped to another DID) dies with `MessageIdentifierMismatch` before signing
- [ ] `cargo test --features client --test e2e_loopback` green; commit stages: happy path, relay, failure mapping

## Task D: `tests/dst_auth.rs`, turmoil DST scenarios (wave 2; branch `feature/e2e-dst`)

**Hypotheses:** HC1, HC2, HD2
**Files:** Create `tests/dst_auth.rs` (`mod harness;`); Modify `Cargo.toml` (`[dev-dependencies]`: turmoil)

First steps: `git merge main`; confirm the harness exists; then WebFetch the pinned turmoil version's axum example from the tokio-rs/turmoil repo and verify the listener/serve glue against the actual 0.x API before writing scenarios (HD2 gate; STOP and report if the glue does not exist for the pinned version). Client hosts speak hand-rolled HTTP/1.1 over `turmoil::net::TcpStream` (write request bytes, read to end of headers + content-length body, `serde_json` parse); reqwest is explicitly out of scope under simulation. Pin in the module docs: turmoil version, seed values, and the determinism scope note from the register.

- [ ] **Baseline under latency (1 test):** Builder with fixed seed and 50..200ms link latency; host `server.sim` runs the peer router; client host runs the full login flow (challenge, sign ed25519, session, `/whoami`); assert success
- [ ] **Partition then heal (1 test):** partition client/server before the challenge, client retries with a capped loop, heal the partition, flow completes; assert success after heal and failure count > 0
- [ ] **Duplicate delivery (1 test):** complete the challenge; send the identical signed session POST on two sequential connections; assert exactly one 200 and one 401, and `/whoami` works with the minted token (single-use nonce held under network-level duplication)
- [ ] **Seed stability (1 test):** run the baseline scenario body under two different fixed seeds; both succeed (outcome determinism, not byte determinism)
- [ ] `cargo test --test dst_auth` green; commit stages: glue + baseline, partition, duplicate

## Task E: Audit + docs touch (orchestrator, after merges)

**Hypotheses:** HD1
- [ ] `git diff <baseline>..HEAD -- Cargo.toml`: `[dev-dependencies]` only
- [ ] Full matrix: default, `--features client`, `--all-features`, `-p aqua-auth-directory`, plus the three new suites explicitly; clippy `--all-targets --all-features` zero warnings; em-dash grep zero
- [ ] README "Standards and stability" section gains one line pointing at the e2e suites; CLAUDE.md Build & Test gains the three suite commands; commit as docs

## Self-Review Notes

- Spec coverage: phases 1 (A+B+C) and 2 (D) in-repo; commerce framework explicitly excluded (elon deletion, owned by the agentic-commerce effort).
- The `/sig/whoami` authority detail is the known sharp edge: the signed `@authority` must equal what the server derives from the Host header; the in-memory suite controls the Host header explicitly, which is why the tampered-authority test lives there.
- Type consistency: harness names (`AquaPeer`, `in_memory`, `bind_loopback`, `router`) are used identically in B, C, D.

---

## Discovered During Execution (audit errata)

1. **Spent nonce reads as 404, not 401** (wave 1): `ChallengeStore::validate` removes the nonce, so "already used" and "never issued" are indistinguishable by design, and answering 401 would leak spent-versus-unknown. Task D's duplicate-delivery expectation was corrected to one 200 + one 404 before execution.
2. **turmoil 0.7.2 API drift vs docs**: the seed method is `Builder::rng_seed(u64)`; `fixed_seed` (mentioned in a docs.rs summary) does not exist. Glue pinned to the `v0.7.2` axum example; no hyper/hyper-util dev-dependency needed.
3. **Host-header requirement is narrower than assumed**: hyper serves the token routes without `Host`; only the authority-derived signature route 400s. The DST client still sends it (HTTP/1.1 conformance).
4. **One transient lib-test failure** was observed once during the Task C merge under parallel turmoil compilation load (246/247), did not reproduce across four subsequent runs, and its name was lost to an output pipe. Follow-up: CI should run `--no-fail-fast` with captured output; orchestrator pipelines must gate on `PIPESTATUS[0]`, not the pipe tail.
5. **Partition semantics**: turmoil partitions drop packets silently rather than refusing connections, so the heal scenario bounds each attempt with a simulated-time timeout instead of relying on connection errors.
