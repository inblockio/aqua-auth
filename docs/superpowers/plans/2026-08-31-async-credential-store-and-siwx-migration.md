# Plan: async credential store (0.7.0) and the siwx-oidc credential migration

You are the orchestrator for this work, running detached on NUC10-Office.
You have no prior context. Read this file completely before acting.

**Machine:** 47 GB RAM, 12 cores. `cargo` with `-j6` at most.
**Repos in scope:** `~/aqua-auth`, `~/siwx-oidc`, `~/aqua-node`, `~/aquafier-rs`,
`~/aqua-state-viewer`. Touch nothing else.

---

## 0. Where things stand

`aqua-auth 0.6.0` is on `main` and pushed. It closed a long-running fork: the
`SessionBackend` trait and `InMemoryBackend` were kept, `RedisBackend` was cut,
`FnSigner` was added, and the WebAuthn credential store plus the `webauthn-rs`
ceremony were brought in from `feat/backend-unification`.

Three consumers have migration branches **staged, pushed, and deliberately
unmerged**, on `refactor/aqua-auth-0.6-migration`: aqua-node, aquafier-rs,
aqua-state-viewer. Their `aqua-auth` pins were **not** bumped, and each carries
an uncommitted `.cargo/config.toml` `[patch]` pointing at the local tree.

**No 0.6.0 tag has been cut and no consumer pin has moved.** That is why this
breaking change is cheap right now: one version bump and one pass over branches
that have not landed yet. After a tag lands it costs a second round trip through
four repos. Speed matters here for that reason and no other; do not trade
correctness for it.

---

## 1. The problem

`WebauthnCredentialBackend` in `src/webauthn_store.rs` is a **sync** trait. Its
own doc comment justifies this as matching "this crate's blocking-Redis
pattern", meaning `SessionBackend`/`RedisBackend`. **`RedisBackend` was deleted
in 0.6.0.** The justification's referent no longer exists.

Evidence that async is the correct shape, already gathered. Do not re-derive it:

1. **aqua-node already wrote the async version.**
   `~/aqua-node/crates/aqua-node-api/src/webauthn/store.rs:17` defines its own
   `WebauthnCredentialStore` with `async fn insert`, `async fn list_for_did`,
   using the **same method names and the same `NewCredential` /
   `StoredCredential` types**. The primary consumer received a sync trait and
   immediately mirrored it in async. Making aqua-auth's trait async should let
   aqua-node **delete that bridge**, which is the main win to look for.
2. **No consumer uses `spawn_blocking`.** Zero hits in aqua-node and
   aquafier-rs. The escape hatch the doc comment offers is not taken, so
   blocking Redis I/O runs on tokio worker threads today, behind a single
   `Mutex<redis::Connection>` that serialises every credential operation
   process-wide.
3. **The crate is already async.** `Signer` is `#[async_trait]`.
4. **Sync forecloses, async does not.** An async trait costs an in-memory
   backend nothing. A sync trait makes a correct async implementation
   impossible, because `block_on` inside a tokio worker deadlocks. siwx-oidc's
   `RedisClient` is async, which is exactly why siwx-oidc cannot adopt the
   store today.

---

## 2. Scope boundary. Read this twice.

**Account linking stays in siwx-oidc. Permanently. This is a ruling, not a
default.**

- Do **not** add an account-linking API to `aqua-auth`.
- Do **not** move, port, or reshape `LinkEntry`, `LinkChallengeState`,
  `link_start`, or `link_finish`.
- Do **not** migrate the `webauthn:link/*` Redis namespace. It stays where it
  is, owned and read by siwx-oidc.
- Your obligation is only that account linking **still works unchanged** after
  the credential migration. Prove it with a test, do not refactor it.

`aqua-auth` owns credential storage. siwx-oidc owns the relationship between a
credential and a primary DID. That line does not move in this work.

---

## 3. Phases. Each gate must pass before the next phase starts.

### Phase 1: align `webauthn-rs`

siwx-oidc declares `webauthn-rs = "0.6.0-dev"` and
`webauthn-rs-proto = "0.6.0-dev"` (`~/siwx-oidc/Cargo.toml:47,49`).
aqua-auth's `ceremony` feature pins `=0.6.1-dev`. These do not co-resolve: a
prerelease only satisfies a range that carries a prerelease on the same
version tuple, so `0.6.1-dev` does not match `^0.6.0-dev`. While they differ,
`Passkey` is a **different type** in each crate and no shared blob is possible.

Move siwx-oidc to `=0.6.1-dev` for both crates. Its API surface is small
(~11 distinct types, ~40 usages, dominated by `Passkey` and `Webauthn`).
De-risked: **aquafier-rs already runs `=0.6.1-dev` with the identical feature
pair** `["danger-allow-state-serialisation", "conditional-ui"]`.

**Gate 1.** siwx-oidc compiles and its full test suite passes at `=0.6.1-dev`.
Plus the blob-compatibility check below, which is the real risk surface:

> Take a serialized `Passkey` JSON blob as written by 0.6.0-dev (construct one
> from a fixture, or read one from a dev Redis if available) and deserialize it
> under 0.6.1-dev. It must round-trip. **If it does not, STOP.** Do not proceed
> to Phase 3; record the finding and report. Every later phase assumes blob
> compatibility.

### Phase 2: async credential store, `aqua-auth` 0.7.0

Convert `WebauthnCredentialBackend` to `#[async_trait]`. Convert
`InMemoryWebauthnStore` and `RedisWebauthnStore` with it.

For `RedisWebauthnStore`, the honest options are (a) move to the `redis`
crate's async API (`tokio-comp`, `MultiplexedConnection`), which also retires
the single-connection `Mutex` bottleneck, or (b) keep the blocking client and
wrap each call in `spawn_blocking`. **Prefer (a).** If you choose (b), justify
it in the commit message. Either way the single global `Mutex<Connection>`
should not survive.

Then update the three consumer branches, which are unmerged and therefore cheap
to amend. In aqua-node specifically, look to **delete** its
`WebauthnCredentialStore` bridge in favour of aqua-auth's trait directly. If
the bridge cannot be deleted, say precisely why.

Bump to **0.7.0** and write the CHANGELOG entry, including a migration note for
implementors of the trait.

**Gate 2.** Full verification, and assert non-zero executed test counts for
each command, not merely exit 0:
```
cargo test --all-features
cargo test -p aqua-auth-directory
cargo test -p aqua-auth-testkit          # confirm the real member name first
cargo fmt --check
cargo clippy --workspace --all-features --all-targets
```
Plus `cargo check` clean on all three consumer branches via their `.cargo`
patches.

### Phase 3: additive backfill migration

Write a migration that copies siwx-oidc's credentials into aqua-auth's layout.

| Target `StoredCredential` field | Source | Rule |
|---|---|---|
| `credential_id` | the key `webauthn:credential/{b64}` | decode the key itself |
| `public_key` | the value, raw `Passkey` JSON | copy **verbatim**; aqua-auth stores it opaquely and never parses it |
| `did` | derived from the `Passkey` | `p256_compressed_from_passkey` then `did_key_from_p256_compressed`. siwx-oidc computes the identical value today; assert they agree on every row |
| `sign_count` | absent upstream | `0`. This is the safe default: the next assertion's counter exceeds it and tracking resumes. It can under-detect a clone once; it cannot lock anyone out |
| `transports` | absent | empty |
| `label` | absent | `None`. Do **not** read `LinkEntry.label`; linking is out of scope |
| `created_at` | absent | migration timestamp |

**Non-negotiable safety properties:**

- **Additive only.** Write `aqua:webauthn:cred:*` and `aqua:webauthn:did:*`.
  **Never delete, rename, or mutate any `webauthn:credential/*` key.** The old
  namespace stays authoritative until siwx-oidc is flipped, so rollback is a
  flag flip and nothing is destroyed. There is no lockout path as long as this
  holds.
- **Idempotent and re-runnable.** Running it twice must equal running it once.
- **Dry-run by default.** Require an explicit flag to write. Report counts:
  read, would-write, written, skipped, failed.
- **Per-row failures do not abort the run.** Collect and report them; a single
  undecodable credential must not strand the rest.

**Gate 3.** Prove it against a disposable Redis instance seeded with fixture
credentials in siwx-oidc's layout: dry-run reports correct counts, a real run
produces correct `StoredCredential` rows, a second run changes nothing, and the
original keys are byte-identical afterwards.

### Phase 4: siwx-oidc adoption, on a branch

Only after Gates 1 to 3. Branch `refactor/aqua-auth-credential-store`.

- Point siwx-oidc's credential reads and writes at aqua-auth's async store,
  **behind a runtime flag**, defaulting to the existing Redis path.
- **Dual-write** while the flag is on: write both namespaces so a rollback
  loses nothing.
- Pin siwx-oidc's `aqua-auth` dependency. It is currently **unpinned and
  floating on the default branch**, which is the most dangerous thing in its
  Cargo.toml. Pin it and normalise the URL to the `ssh://` spelling the other
  consumers use, since `ssh://` and `https://` are two Cargo sources and
  produce two crate instances with unmerged features.
- Delete only the genuinely duplicated DID-derivation helpers, roughly 10
  lines, now that Phase 1 makes `Passkey` one type. Verify byte-identical DID
  output before and after.
- **Account linking untouched, and prove it still works.**

**Do NOT do step 5.** Deleting the old `webauthn:credential/*` namespace, or
removing the dual-write, requires a production soak and is explicitly out of
scope. Leave both in place.

**Gate 4.** siwx-oidc builds and its tests pass with the flag off and with the
flag on. Account-linking tests pass in both modes. Push the branch. Do not
merge it.

---

## 4. Constraints

- **Never commit source changes directly to `main`** in any repo. Branch, then
  merge. Branch names: `type/kebab-slug`.
- **Commit incrementally** in coherent stages with accurate messages. End each
  with `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`.
- **Never use em dashes** in code, comments, docs, or commit messages. Use
  commas, semicolons, colons, parentheses, or separate sentences.
- `aqua-auth`'s public API is semver-bound. Phase 2 is a deliberate major-ish
  break; everything else must not add one.
- **Never claim a gate passed without running it.** Evidence before assertions.
  If you gate on a piped command, check `PIPESTATUS[0]`, not the pipe tail.
- **Do not force-push. Do not rewrite published history. Do not cut tags.**
- **Do not touch `~/aqua-state-viewer`'s git stash.** It holds someone else's
  work.
- `~/siwx-oidc` is currently on branch `dev`. Establish its correct base branch
  before you start and record which you chose.
- If a gate fails, **stop at that gate and report**. Do not improvise past a
  failed safety check, and never weaken a gate to make it pass.

---

## 5. Report

Write `~/SIWX-MIGRATION-REPORT.md`: per phase, what you did, the exact
verification command and its real output including test counts, what you did
not do and why, every assumption in this document that proved false, and the
follow-ups you are handing back. Report failures as failures.
