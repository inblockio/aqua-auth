# Orchestrator brief: finish the aqua-auth backend unification

You are the orchestrator for this work, running detached on NUC10-Office.
You have no prior context. Everything you need is here. Read it fully before acting.

**Machine:** 47 GB RAM, 12 cores, 411 GB free. Use `cargo` with `-j6` at most.
**Never** touch repos other than the ones named below.

---

## 1. Situation

`aqua-auth` (repo `github.com/inblockio/aqua-auth`, formerly `aqua-rs-auth`, the
old name still redirects) had **two heads**:

- `main` at v0.5.0: http-sig / RFC 9421, the `aqua-auth-directory` workspace
  member, an async `Signer` trait, e2e + DST test suites. **Zero consumers.**
- `feat/backend-unification`, whose tag `CheckPoint.20260817` is what
  **aqua-node and aquafier-rs actually run in production**. It adds a
  `SessionBackend` trait, a Redis session backend, a WebAuthn credential
  store, and a register/login ceremony over `webauthn-rs`.

The repo was running a fork where the head with all the tests had no users and
the head with all the users had none of the tests. That is the defect being
fixed.

**Already done on branch `feature/backend-unification-merge` (pushed):**

- `1d7aa97` merge of the branch into the main line. Only `Cargo.toml` and
  `Cargo.lock` conflicted; `lib.rs` and `session.rs` auto-merged.
  `cargo check --all-features` passed.
- `560822e` the `SessionBackend` trait fix (see T1). **Not yet test-verified.**

Your working copy is already checked out at `560822e` on that branch.

---

## 2. Consumer graph

| Repo | Pin | URL spelling | Features | On this machine |
|---|---|---|---|---|
| aqua-node | `tag CheckPoint.20260817` | `ssh://` | `http, redis, webauthn, ceremony` | `~/aqua-node`, on `main` |
| aquafier-rs | `tag CheckPoint.20260817` | `ssh://` | `http, webauthn, ceremony` | `~/aquafier-rs`, on `main` |
| aqua-state-viewer | `tag CheckPoint.20260521` | `ssh://` | `client` | `~/aqua-state-viewer`, on `main` |
| siwx-oidc (2 crates) | **unpinned** | `https://` | `webauthn`, default | `~/siwx-oidc`, on `main` |
| aqua-timestamps | `path = "../aqua-auth"` | n/a | `http`, `client` | **absent, see 6.4** |

`ssh://git@github.com/...` and `https://github.com/...` are two distinct Cargo
sources, so a graph containing both gets **two `aqua-auth` instances with
unmerged features**. Normalising this is part of the work.

**Verified API compatibility.** Fork point vs `main`, public surfaces diffed:
`ChallengeStore`, `types.rs`, `webauthn.rs`, `verify_caip122` are all
**identical**; `session.rs` differed only in doc punctuation. **Exactly one
symbol breaks: `client::authenticate`.** Old form
`authenticate(http, base_url, &did, closure)`, new form
`authenticate(http, base_url, &dyn Signer)`. Three call sites:

- `~/aqua-node/crates/aqua-analytics/src/client.rs:155`
- `~/aqua-state-viewer/src/auth.rs:93`
- `~/aqua-timestamps/crates/aqua-timestamp-client/src/auth.rs:102` (absent here)

---

## 3. Decisions already ruled by Tim. Do not relitigate these.

1. **Merge, do not close** the branch. Done.
2. **Cut `RedisBackend`.** Reasons: aqua-node defaults to
   `session_backend = "memory"` and no deployment manifest anywhere defines a
   Redis service; it is sync-blocking behind a single `Mutex<redis::Connection>`
   called from async axum handlers; `len()`/`all()` are `SCAN` so a login cost
   two full keyspace scans plus a GET per session; and `AuthError::Redis`
   leaks `redis::RedisError` into the public API of a crates.io-bound crate.
   The **capability** is not cut: the trait and `with_backend` stay public, so
   a consumer can implement Redis in ~100 lines in the repo that owns the pool.
3. **Fix the trait as part of the same change**, not after. Done in `560822e`.
4. **`FnSigner` adapter, no deprecated shim.**
5. **Consumers: prepare and verify, but do NOT change any pinned tag.** No new
   tag exists yet; cutting it is Tim's call. Commit and push consumer work on
   branches so nothing is stranded.
6. **siwx-oidc: scope corrected. Read section 6.3 before touching it.**

---

## 4. Tasks

### T1. Verify the trait fix (do this first)
`560822e` added to `SessionBackend`: `sessions_for_did(&str) -> Vec<Session>`
(required, hot path, replaces the `all()` call in `enforce_per_did_cap`) and
`purge_expired(now) -> usize` (defaulted over `all()`, overridden to a no-op
`0` in `RedisBackend` because `insert` already sets `SET ... EXAT`). `all()` is
retained but documented cold-path only.

Run `cargo test --all-features --lib`. Fix any fallout. There are existing
`session.rs` tests that may have assumed the old `all()`-based sweep.

### T2. Cut RedisBackend
Delete `src/redis_backend.rs`, `SessionBackendKind`, `build_backend`, and their
tests. Delete `AuthError::Redis` and `AuthError::LockPoisoned`. Change
`RedisWebauthnStore::connect` to return `Result<Self, WebauthnStoreError>`
(everything else in `redis_webauthn.rs` already stringifies through
`WebauthnStoreError::Backend(String)`, so this removes the last `redis` type
from the public API).

**Keep** `webauthn_store.rs`, `redis_webauthn.rs`, `session_backend.rs`
(trait + `InMemoryBackend`), and `SessionStore::with_backend`. The `redis`
cargo feature **survives**, because `RedisWebauthnStore` needs it. Check
whether `redis` still needs to imply `http` after the cut; simplify if not.

### T3. `FnSigner`
`main` has zero closure adapters and 14 hand-rolled `impl Signer` blocks, all
in tests. Add a public `FnSigner` so the three call sites in section 2 become a
one-line wrap instead of three bespoke impls. The trait is
`#[async_trait] pub trait Signer: Send + Sync { fn signer_did(&self) -> &str; async fn sign(&self, &str) -> Result<Vec<u8>, SignError>; }`.
Wrap a **sync** closure (all three call sites are sync today). Full test
coverage: round trip against `verify_caip122`, and error propagation.

### T4. Docs and version
Move `docs/REUSABILITY_HANDOFF.md` and `docs/WEBAUTHN_READINESS.md` into
`docs/superpowers/specs/`, each with a header noting it is **superseded**:
the readiness doc's 2026-05-22 "not ready" verdict describes a state this work
removed. Update `CLAUDE.md`'s module layout and roadmap. Write `CHANGELOG.md`.
Bump to **0.6.0**.

### T5. Full verification (hard gate)
```
cargo test --all-features
cargo test --all-features --test e2e_inmemory
cargo test --all-features --test e2e_loopback
cargo test --all-features --test dst_auth
cargo test -p aqua-auth-directory
```
**Assert the executed test count is non-zero for each.** A feature-gated suite
can compile empty under the wrong flags and report green while running nothing.
If you gate on a piped command, check `PIPESTATUS[0]`, not the pipe tail.

### T6. Consumer migrations
For each of aqua-node, aquafier-rs, aqua-state-viewer: create a branch, then
add an **uncommitted** `.cargo/config.toml` so it builds against your local
tree:
```toml
[patch."ssh://git@github.com/inblockio/aqua-rs-auth"]
aqua-auth = { path = "/home/waldknoten-01/aqua-auth" }
```
(match the patch key to the URL that repo actually declares). Then:
- **aqua-node:** migrate the `client::authenticate` call site to `FnSigner`;
  delete the now-dead `[auth] session_backend` / `redis_url` config in
  `crates/aqua-daemon/src/config.rs` and its boot wiring in
  `crates/aqua-daemon/src/main.rs`. The config struct has **no**
  `deny_unknown_fields`, so a stale TOML key will not crash a node.
- **aquafier-rs:** add `"redis"` to its `aqua-auth` feature list. It currently
  names `aqua_auth::RedisWebauthnStore` (gated `all(webauthn, redis)`) without
  declaring `redis`, and compiles only because Cargo unions features across the
  graph from aqua-node's declaration. That is an undeclared dependency on a
  sibling's feature choice.
- **aqua-state-viewer:** migrate its `client::authenticate` call site.
- Normalise every `aqua-auth` git URL to one spelling.
- `cargo check` each. Commit and push the branches. **Do not change the pinned
  tag**; leave a clear TODO comment where the tag bump will go.

### T7. siwx-oidc. Read 6.3 first.

### T8. `CONSUMERS.md` in aqua-auth
Table of every consumer, its pin, URL spelling, and feature set, plus the rule
that all consumers move together. Nothing in this repo verified that consumers
still built, which is how the fork survived six weeks unnoticed.

### T9. Integrate
Merge `feature/backend-unification-merge` into local `main`, delete the branch
with `git branch -d` (lowercase, never `-D`), push `main` and all consumer
branches.

---

## 5. Constraints

- **Never commit source changes directly to `main`** in any repo. Branch, then
  merge. Branch names: `type/kebab-slug`.
- **Commit incrementally** in coherent stages, not one batch at the end.
  Messages must accurately describe what changed. End each with:
  `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`
- **Never use em dashes** in any output: code, comments, docs, commit messages.
  Use commas, semicolons, colons, parentheses, or separate sentences.
- The public API is **semver-bound** (this crate is headed for crates.io).
- **Never claim something passes without running it.** Evidence before
  assertions.
- **Do not force-push. Do not rewrite published history.**
- **Do not touch `~/aqua-state-viewer`'s git stash.** It holds someone else's
  uncommitted work that was stashed to free the branch. Leave it.
- If an assumption in this brief turns out to be false, **stop and record it**
  in the report rather than improvising around it.

---

## 6. Known traps

**6.1 `webauthn-rs = "=0.6.1-dev"`** is an exact-pinned prerelease. The exact
pin is deliberate: the serialized `Passkey` blob must stay byte-compatible with
aqua-node and aquafier. Do not relax it. Do note in the report that an exact
prerelease pin blocks crates.io publication.

**6.2 Cargo feature unification** is what currently makes aquafier-rs compile.
Fixing it (T6) is a correctness fix, not cosmetic.

**6.3 siwx-oidc: the "551 duplicate lines" figure is wrong.** Measured
breakdown of `~/siwx-oidc/src/webauthn.rs`:

| Segment | Approx lines | Action |
|---|---|---|
| DID derivation helpers | ~50 | **DELETE.** Genuine duplicates of `aqua_auth::{did_key_from_p256_compressed, p256_compressed_from_passkey, passkey_from_blob}`. Pure functions, no data risk. |
| HTTP request/response types | ~25 | Keep. Correctly local. |
| Registration / authentication ceremony | ~230 | **DO NOT MIGRATE.** See below. |
| Account linking (`link_start`/`link_finish`, `LinkEntry`) | ~110 | Keep. **No aqua-auth equivalent exists.** |
| Config + `build_webauthn` | ~80 | Optional, low value. |

Do **not** migrate the ceremony core. Two blockers:
- **Incompatible storage.** siwx-oidc stores `webauthn:credential/{cred_id}` =
  raw `Passkey` JSON, no DID index, no sign-count tracking. aqua-auth stores
  `aqua:webauthn:cred:{id}` = `StoredCredential` JSON (did, credential_id,
  public_key blob, sign_count, transports, label, created_at) plus an
  `aqua:webauthn:did:{did}` index. Adopting aqua-auth's store means
  **rewriting every live passkey credential**. Passkeys are hardware-bound: a
  botched migration locks users out permanently, with no password fallback.
- **Sync/async mismatch.** siwx-oidc's `RedisClient` is async
  (`redis.get_raw(..).await`); aqua-auth's `RedisWebauthnStore` is
  sync/blocking.

So: do the ~50-line helper dedup only, verify siwx-oidc still builds, and write
`docs/superpowers/specs/2026-08-30-siwx-oidc-ceremony-consolidation.md` in the
**aqua-auth** repo describing what a real consolidation needs (a credential
data migration plan, an async credential-store trait, and an account-linking
API). Do not execute that spec.

**6.4 aqua-timestamps is orphaned.** It is absent here and unbuildable
anywhere: its workspace references `~/aqua-evm-provider`, which does not exist
locally and **does not exist on origin** (verified with `git ls-remote`). It
also uses `path = "../aqua-auth"`, so it tracks the working tree with no pin,
and its lockfile still says `aqua-auth 0.2.0`. Its `client::authenticate` call
site is statically broken already. **Do not clone it. Do not attempt to fix
it.** Record it in the report as needing a separate decision.

---

## 7. Report

Write `~/HANDOVER-REPORT.md` covering, for each task: what you did, the
verification command you ran and its actual output (test counts included), what
you did not do and why, every assumption from this brief that turned out false,
and every follow-up you are handing back. Be accurate about failures; do not
round a partial result up to success.
