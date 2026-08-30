# Handover: open items after the backend unification

**Date:** 2026-08-31
**Covers:** aqua-auth and its five consumers
**Status of this session:** closed. Work continues detached on NUC10-Office.

---

## 1. Live work, running unattended right now

A detached Opus orchestrator is executing
`docs/superpowers/plans/2026-08-31-async-credential-store-and-siwx-migration.md`
on NUC10-Office.

```
ssh nuc10 -t tmux attach -t siwx-migration
```

Detach with `Ctrl-b` then `d`. The session **persists after completion** (the
runner ends with `exec bash`), so a missing session means it crashed, not that
it succeeded. Output is buffered until the run ends; judge progress from git
history, not the log.

- Log: `~/siwx-migration.log`
- Report on completion: `~/SIWX-MIGRATION-REPORT.md`
- Prior phase's report: `~/HANDOVER-REPORT.md`

**Progress at handover:** Phase 1 complete and pushed (siwx-oidc
`chore/webauthn-rs-0.6.1-alignment`, `e7e7328`). Phase 2 in flight: aqua-auth is
on `refactor/async-credential-store`, already bumped to 0.7.0, branch not yet
pushed.

**First thing to check on reattach:** whether Gates 1 to 4 actually passed. The
plan requires it to stop at a failed gate rather than weaken it; verify it did.

---

## 2. What is done and closed

- The aqua-auth fork is closed. 0.6.0 shipped on `main`, verified at 285
  executed tests, 0 failures.
- `RedisBackend`, `build_backend`, `SessionBackendKind` cut. The
  `SessionBackend` seam, credential store, and ceremony kept.
- `SessionBackend` made index-aware (`sessions_for_did`, `purge_expired`),
  taking the login path off a full-store walk.
- `FnSigner` added, collapsing three bespoke `impl Signer` migrations into
  one-line wraps.
- Both merged remote branches deleted (`feat/backend-unification`,
  `feature/backend-unification-merge`). The `CheckPoint.20260817` tag still
  resolves, so existing consumer pins keep working.

---

## 3. Open items

### 3.1 Blocking a release

**Cut a version tag and bump all consumer pins in one batch.** Three consumer
branches are pushed and deliberately unmerged on
`refactor/aqua-auth-0.6-migration` (aqua-node, aquafier-rs, aqua-state-viewer),
each with a TODO marking where the pin bump goes. Note the in-flight work bumps
aqua-auth to **0.7.0**, so tag that rather than 0.6.0 if Phase 2 lands.

**Remove the three local `.cargo/config.toml` `[patch]` files** pointing at
`/home/waldknoten-01/aqua-auth` when the tag is cut.

> **Trap.** In `aqua-state-viewer` the whole `.cargo/` directory is **untracked
> and not gitignored**, so `git add -A` there would commit a local absolute
> path. The other two have `.cargo/config.toml` already tracked and merely
> modified.

### 3.2 Decisions needing an owner

**The `webauthn-rs` version question.** `=0.6.1-dev` is an exact-pinned
prerelease, deliberate so the serialized `Passkey` blob stays byte-compatible
across aqua-node, aquafier-rs, and now siwx-oidc. It is published on crates.io
and not yanked, so it does **not** block publication (an earlier note claiming
otherwise was wrong). The real cost is a graph-wide `=` lock. Decide whether to
carry it or move to a stable release.

**aqua-timestamps is orphaned.** Its workspace references
`~/aqua-evm-provider`, which exists neither locally nor on origin (verified with
`git ls-remote`), so it cannot build anywhere. It depends on aqua-auth by
`path = "../aqua-auth"` with no pin, its lockfile still says `aqua-auth 0.2.0`,
and its `client::authenticate` call site is already broken against `main`. It
needs an owner's decision: revive, pin, or retire.

### 3.3 Deferred by design, do not let these drift silently

**Do not delete the old `webauthn:credential/*` namespace, and do not remove
the dual-write**, until a production soak says otherwise. That is what keeps
rollback to a flag flip with no user-lockout path. Explicitly out of scope for
the running work.

**Post-migration consistency.** After the backfill, siwx-oidc's link table stays
authoritative while `StoredCredential.did` holds a snapshot of its effect, so a
later link or unlink makes the two disagree. Either siwx-oidc keeps resolving
through its own link table (the default while dual-write is on), or link/unlink
must write through to the credential store. Not designed yet, on purpose.

**Account linking stays in siwx-oidc.** Ruling, not a default. aqua-auth owns
credential storage; siwx-oidc owns the credential-to-primary-DID relationship.
The migration **reads** `webauthn:link/*` for correctness but never writes it.
If a second service ever needs linking, lift the *resolution* into aqua-auth
(something like `resolve_did(credential_id)` over a pluggable alias source);
do not copy the link table.

**siwx-oidc's aqua-auth dependency is unpinned** and floats on the default
branch, using the `https://` URL spelling while every other consumer uses
`ssh://` (two Cargo sources, so two crate instances with unmerged features).
Phase 4 of the running work is supposed to fix both. Verify it did.

### 3.4 Process gap that caused all of this

**There is no CI job building each consumer against aqua-auth `main`.** Nothing
verified that consumers still compiled, which is how a fork survived six weeks
with all the tests on the head that had no users and all the users on the head
that had no tests. This is the single highest-value follow-up. `CONSUMERS.md`
in this repo now records the consumer matrix; a CI job should enforce it.

### 3.5 Housekeeping

- Recover the stash in `~/aqua-state-viewer` **on nuc10**:
  `stash@{0}`, message `pre-backend-unification-handover 20260830225324`. It
  holds work that predates this effort and belongs to whoever left it.
- Check for em dashes reintroduced by the merge in `webauthn_store.rs` and
  `webauthn_ceremony.rs`; the first orchestrator counted 10 and may or may not
  have cleared them.

---

## 4. Where the reasoning lives

| Topic | Document |
|---|---|
| Why the branch was merged rather than closed | `docs/superpowers/handovers/2026-08-30-nuc10-orchestrator-brief.md` |
| The async store and migration plan, with the corrected field mapping | `docs/superpowers/plans/2026-08-31-async-credential-store-and-siwx-migration.md` |
| Consumer matrix and pins | `CONSUMERS.md` |
| What a full siwx-oidc consolidation would need | `docs/superpowers/specs/` |

Two corrections worth carrying forward, because both were caught late and both
would have shipped silently:

1. The migration must resolve `did` through the **link table**, not by deriving
   it from the Passkey. `verify_credential` treats a link as an override
   (`siwx-oidc/src/webauthn.rs:298-311`), so deriving unconditionally records
   the wrong principal for every linked credential.
2. The sign counter is **not absent** upstream. siwx-oidc keeps it inside the
   Passkey blob at `cred.counter` and rewrites it on every authentication
   (`src/webauthn.rs:316-332`), while aqua-auth uses a sidecar field.
   Defaulting it to `0` would silently reset clone detection.
