# Consumers of `aqua-auth`

Every repo that depends on this crate, with the exact pin, git URL spelling and
feature set it declares. **Keep this file current.** Nothing in this repo builds
its consumers, which is how `main` and `feat/backend-unification` drifted into
two heads for six weeks without anyone noticing: the head with all the tests had
no users, and the head with all the users had no tests.

Last verified: **2026-10-08**, from each consumer's `Cargo.toml` at the commit
named in the table (`git show <sha>:Cargo.toml`). The rows for aqua-agents and
aqua-timestamps were not re-checked and date from 2026-08-30.

> **0.9.0 is released and no consumer has moved yet.** Every pinned consumer is on
> `v0.7.0`; 0.8.0 (2026-09-11) is tagged at `553893e`, and consumers on `v0.7.0`
> move to `v0.9.0` in one step, since 0.9.0 carries 0.8.0's changes (see
> "Migrating to 0.9.0"). aqua-suite joins as a new consumer in that batch. The
> 0.8.0 companion PRs (`inblockio/aqua-node` #41 and #42, `inblockio/aquafier-rs`
> #192 and #193; #41 and #192 are hard prerequisites for `did:aqua`) still
> belong to the batch.

## Release tags

Releases are annotated `vX.Y.Z` tags. The version is semver for the **crate API**
and is separate from the wire/spec version; the tag message states the spec
version. `CheckPoint.*` tags are historical: no new ones are created, and the
existing ones are never moved or deleted, so consumers pinned to them stay valid
until they move. The crate is at 0.9.0, tagged `v0.9.0`; `v0.8.0` is tagged
at `553893e` and 0.9.0 carries its changes.

## The rule: all consumers move together

This crate is semver-bound and headed for crates.io, but today every consumer
takes it as a **git dependency pinned to a tag**. That means a breaking change
here is invisible until someone bumps a tag, and a bump that lands in one repo
while the others stay behind gives you two `aqua-auth` instances in a
multi-repo build.

So:

1. **Cut a `vX.Y.Z` release tag, then move every pinned consumer to it in the same batch.** Do
   not bump one repo and leave the rest. aqua-node and aquafier-rs in
   particular share a lockfile-adjacent build (aquafier-rs takes aqua-node
   crates as path dependencies); a mismatch there is a compile error, not a
   warning.
2. **Keep the URL string byte-identical everywhere.** Cargo keys a git source
   by the literal URL text, so `ssh://git@github.com/inblockio/aqua-rs-auth`
   and `https://github.com/inblockio/aqua-rs-auth` are two different sources.
   A dependency graph containing both gets two copies of this crate at the same
   commit with their features **unmerged**, which surfaces as missing items
   behind `#[cfg(feature = ...)]` rather than as a version conflict. The repo
   is named `aqua-auth`; `aqua-rs-auth` is the old name and now only a GitHub
   redirect (verified 2026-09-11: it answers `301` to `.../aqua-auth`). Every
   pinned consumer now spells it `https://github.com/inblockio/aqua-auth`,
   byte-identical (verified 2026-10-08). Keep it that way: a new consumer
   copies this exact string, and a spelling change moves every repo in one
   batch or none.
3. **Declare every feature you use.** Cargo unions features across a dependency
   graph, so a crate can compile against a feature a *sibling* declared. That
   compiles today and breaks the moment the sibling drops the feature. See
   aquafier-rs below.

## Consumers

| Repo | Pin | URL spelling | Features | Notes |
|---|---|---|---|---|
| aqua-node | `tag = "v0.7.0"` | `https://` | `http`, `redis`, `webauthn`, `ceremony`; `client` added in `aqua-analytics`; `aqua-node-client` takes `http`, `client` | Primary server-side consumer. Verified at `65c6e8b3da` (aqua-node v0.1.12). |
| aquafier-rs | `tag = "v0.7.0"` | `https://` | `http`, `webauthn`, `ceremony`, `redis` | Verified at `c9c35e9fdf`. `redis` declared explicitly since 2026-08-30, see below. |
| aqua-state-viewer | `tag = "v0.7.0"` | `https://` | `client` | Verified at `8af1e29`. |
| siwx-oidc (root) | `tag = "v0.7.0"` | `https://` | `webauthn`, `ceremony`, `redis` | Verified at `85df10c3e4`; pinned since 2026-09-11 (`5762aa0`). CI builds with `-Dwarnings`. |
| siwx-oidc-auth | `tag = "v0.7.0"` | `https://` | (default) | Same workspace as above, so it also sees the union. |
| aqua-suite | **not yet a consumer** (none at `e274a8b35a`) | `https://` (to be) | `webauthn` only | Joins with 0.9.0 for store-free passkey login. Keeps its own `webauthn-rs` 0.5; must not enable `ceremony` (pins `webauthn-rs =0.6.1-dev`). |
| aqua-agents | **transitive only**, via `siwx-oidc-auth` | `https://` (inherited) | (default; no `client`) | Not a direct consumer, but this crate is in its lock graph and it wants `client`. See below. |
| aqua-timestamps | `path = "../aqua-auth"` | n/a | `http`, `client` | **Orphaned.** See below. |

### aqua-node

`Cargo.toml` workspace dependency, re-exported to `aqua-node-api`,
`aqua-daemon`, `aqua-rest`, `aqua-mgmt`, and (with `client` added)
`aqua-analytics`. It is the only consumer that used the Redis *session*
backend, and it never enabled it: `[auth] session_backend` defaulted to
`"memory"` and no deployment manifest anywhere defines a Redis service. That
config key and its boot wiring were removed when the backend was cut in 0.6.0.

It keeps `redis` for `RedisWebauthnStore`, the passkey credential store, which
is genuinely deployed.

Until 0.7.0 it also carried a **duplicate of this crate's credential store**:
`WebauthnCredentialStore` in `crates/aqua-node-api/src/webauthn/store.rs`, an
async trait with the same method names over field-for-field copies of
`CredentialId`, `NewCredential` and `StoredCredential`, plus a
`RedisWebauthnCredentialStore` adapter converting between the two type families.
It existed because this crate's trait was sync and a sync trait cannot host an
async backend. 0.7.0 made the trait async, so aqua-node's trait and types are
now aliases for this crate's and the adapter is deleted. Anything that names
`aqua_node_api::webauthn::{StoredCredential, StoreError, ...}` still compiles;
those names now resolve here.

### aquafier-rs

`crates/aquafier-auth/src/webauthn.rs` names `aqua_auth::RedisWebauthnStore`
**unconditionally**, with no cfg gate, while the workspace declared only
`http`, `webauthn`, `ceremony`. It compiled solely because Cargo unions
features across the graph and aqua-node, whose crates are path dependencies of
this workspace, declares `redis`. That is an undeclared dependency on a sibling repo's feature
choice: the day aqua-node drops `redis`, aquafier-rs stops compiling for
reasons nothing in aquafier-rs explains. `redis` is now declared explicitly.

### aqua-state-viewer

Client-only. Its `client::authenticate` call site is the other one affected by
the 0.5.0 `Signer` migration.

### siwx-oidc

Pinned to `v0.7.0` since 2026-09-11 (`5762aa0`); before that it had no tag
and was held only by its `Cargo.lock`. Its CI builds with `-Dwarnings`; it
calls no deprecated item at `85df10c3e4`.

The analysis below dates from 2026-08-30. siwx-oidc has since enabled
`ceremony` (table above), so the version-resolution bullet no longer holds as
written; the storage bullet still does. Not re-audited for 0.9.0.

It uses `webauthn` (the standalone assertion verifier, already shared) and its
own local WebAuthn ceremony over `webauthn-rs`. Consolidating that ceremony
onto `aqua-auth`'s is **not** a refactor, and was deliberately not attempted:

- **Storage is incompatible, on live passkeys.** siwx-oidc stores raw
  `Passkey` JSON at `webauthn:credential/{cred_id}` with no DID index and no
  sign-count tracking; aqua-auth stores `StoredCredential` JSON at
  `aqua:webauthn:cred:{id}` plus a DID index. Adopting aqua-auth's store
  rewrites every live credential, and passkeys are hardware-bound: a botched
  migration is permanent lockout with no password fallback.
- **The `webauthn-rs` versions do not co-resolve.** siwx-oidc requires
  `^0.6.0-dev`; aqua-auth's `ceremony` feature requires `=0.6.1-dev`. Enabling
  `ceremony` on siwx-oidc fails at dependency resolution. Since
  `webauthn_rs::prelude::Passkey` differs between the two, every aqua-auth
  helper whose signature mentions `Passkey` is unusable there until the
  versions are unified, which is itself a stored-blob compatibility decision.
- **Sync/async mismatch.** siwx-oidc's Redis client is async; aqua-auth's
  credential store is sync and blocking.

Full analysis, including what a real consolidation would need:
`docs/superpowers/specs/2026-08-30-siwx-oidc-ceremony-consolidation.md`.

### aqua-agents: a transitive consumer that wants to become a direct one

`aqua-agents` never names this crate, but it has it: its `aqua-call-agent`
takes `aqua-matrix-agent`, which takes `siwx-oidc-auth`, which git-deps
`aqua-auth`. So the crate compiles into the Scribe transcript agent today with
default features and no `client`.

Meanwhile `aqua-agents/crates/aqua-node-client` hand-rolls the CAIP-122 login
this crate has shipped behind `client` since 0.2.0, including its own `did:key`
encoder and its own PKCS#8 loader. It cannot simply switch the feature on until
the URL spellings converged (rule 2 above). They have: every direct consumer
now uses the `https://` spelling it inherits from siwx-oidc-auth, so that
blocker is gone (not re-checked in aqua-agents itself).

Recorded so the next tag batch includes it. Nothing to do in this repo.

### aqua-timestamps: orphaned, needs a decision

Not present on the NUC10 working machine and **not buildable anywhere** as of
2026-08-30:

- Its workspace references `~/aqua-evm-provider`, which does not exist locally
  and does not exist on origin (`git ls-remote` finds nothing).
- It depends on `aqua-auth` by `path = "../aqua-auth"`, so it tracks whatever
  is in a sibling working tree with no pin at all. Its lockfile still records
  `aqua-auth 0.2.0`.
- Its `client::authenticate` call site
  (`crates/aqua-timestamp-client/src/auth.rs:102`) uses the pre-0.5.0
  four-argument form and is therefore already statically broken against any
  current `aqua-auth`.

It was deliberately not cloned or repaired during the 0.6.0 work. Someone with
authority over that repo needs to decide whether to revive it (which requires
recovering or replacing `aqua-evm-provider` first), archive it, or fold its
timestamping into another repo. Until then it is not a consumer this crate can
keep compatible.

## Migrating a consumer past 0.6.0

- **`client::authenticate`** changed in 0.5.0 from
  `authenticate(http, base_url, &did, sign_fn)` to
  `authenticate(http, base_url, &dyn Signer)`. Wrap an existing synchronous
  signing method with `aqua_auth::FnSigner`:

  ```rust
  let signer = aqua_auth::FnSigner::new(did.clone(), move |message: &str| {
      let hex = keypair
          .sign_message(message)
          .map_err(|e| aqua_auth::SignError(e.to_string()))?;
      // `FnSigner` returns raw bytes; the client hex-encodes for the wire.
      hex::decode(hex.strip_prefix("0x").unwrap_or(&hex))
          .map_err(|e| aqua_auth::SignError(e.to_string()))
  });
  let session = aqua_auth::client::authenticate(&http, &base_url, &signer).await?;
  ```

  Note the decode: the old closure returned a `0x`-prefixed hex **string**, the
  `Signer` trait returns raw **bytes**.

- **Redis sessions.** `SessionBackendKind`, `build_backend` and the Redis
  `SessionBackend` are gone in 0.6.0. If you actually need durable sessions,
  implement `SessionBackend` in the crate that owns your connection pool and
  pass it to `SessionStore::with_backend`. Note the trait's hot-path contract:
  `sessions_for_did` is called on every login and must be served from a
  `did -> tokens` index, and `all()` is cold-path introspection only.

- **`RedisWebauthnStore::connect`** now returns
  `Result<Self, WebauthnStoreError>`, not `Result<Self, AuthError>`.

- **The `redis` feature** no longer implies `http` and now implies `webauthn`.
  Declare `http` yourself if you use the session layer.

## Migrating to 0.7.0

One breaking change, in the WebAuthn credential store. A consumer that does not
enable `webauthn` is unaffected; `aqua-state-viewer` (feature `client`) needed
no source change at all.

- **`WebauthnCredentialBackend` is `#[async_trait]`.** Add
  `use async_trait::async_trait;`, put `#[async_trait]` on the `impl`, mark each
  method `async fn`. An in-memory or embedded-KV implementation needs nothing
  else, as long as no lock guard is held across an `.await`.

- **`list_for_did` and `get_by_id` return `Result`.** They were `Vec` and
  `Option`, so a backend failure looked exactly like "no credentials" and "no
  such credential". Callers that used to get a value now get `Result<value>`;
  handle the error rather than `unwrap_or_default()`, which reinstates the bug.

- **`delete` still returns `Result<bool, _>`**, unchanged, but note that
  aqua-node's alias inherits it: implementations that returned
  `Err(NotFound)` for a missing row must return `Ok(false)`.

- **`RedisWebauthnStore::connect` is `async`.** It stays eager, so an
  unreachable Redis still fails at boot. A sync lazy initialiser
  (`std::sync::OnceLock`) becomes `tokio::sync::OnceCell`; a sync builder that
  constructs the store at boot becomes `async fn` (aqua-node's
  `build_explorer_router` did).

- **The `redis` feature now enables `redis/tokio-comp` and
  `redis/connection-manager`.** If you also depend on the `redis` crate
  directly, both unify into your build.

## Migrating to 0.9.0

Additive: nothing in 0.9.0 changes an existing signature or wire shape. A
consumer that does not use passkeys moves by changing the tag alone. Because
consumers skip `v0.8.0`, the move from `v0.7.0` also brings 0.8.0's changes; the
one that shows is the `verify_caip122` deprecation warning, at the call sites in
aquafier-rs (`crates/aquafier-auth/src/routes.rs:82` at `c9c35e9fdf`) and
aqua-node (`crates/aqua-mgmt/src/routes.rs:207` at `65c6e8b3da`).

- **The batch.** Cut `v0.9.0`, then move aqua-node, aquafier-rs, siwx-oidc
  (root and `siwx-oidc-auth`) and aqua-state-viewer from `tag = "v0.7.0"` to
  `tag = "v0.9.0"` together, and add aqua-suite in the same batch (rule 1).
  aquafier-rs also takes aqua-node crates, so a mismatch between those two is
  a compile error.
- **Store-free passkey login** needs only `webauthn`. Read SPEC section 12
  before wiring it: a principal comes only from `verify_and_recover` plus
  `select` / `PendingRecovery::resolve`, never from a registration response.
- **aqua-suite** joins with exactly
  `aqua-auth = { git = "https://github.com/inblockio/aqua-auth", tag = "v0.9.0", features = ["webauthn"] }`.
  It keeps its own `webauthn-rs` 0.5 and must not enable `ceremony`.
- **Tests** use the software passkey as a dev-dependency feature:
  `aqua-auth = { git = "https://github.com/inblockio/aqua-auth", tag = "v0.9.0", features = ["webauthn", "webauthn-testkit"] }`.
  Never enable `webauthn-testkit` in a normal dependency: its keys are seeded
  and public.

### Building against an untagged checkout (local only)

Until the tag exists, point the git source at a local checkout with a cargo
config file passed on the command line, so no tracked file changes:

```toml
# e.g. ~/passkey-e2e/patches/<repo>.toml: never committed
[patch."https://github.com/inblockio/aqua-auth"]
aqua-auth = { path = "/absolute/path/to/an/aqua-auth/checkout" }
```

```sh
cargo --config /absolute/path/to/patch.toml test
cargo --config /absolute/path/to/patch.toml tree -i aqua-auth   # shows the path source
```

- The patch key is the dependency's URL string, byte for byte; one entry
  covers every crate in the graph that names that URL (aqua-node's crates
  inside aquafier-rs included).
- Patch from one checkout only. The committed dependency line keeps its
  existing spelling and tag; it builds only through the patch until the tag is
  cut, which blocks merging that branch.
- A patched build rewrites `Cargo.lock`. Before every commit run
  `git diff --quiet -- Cargo.lock || git checkout -- Cargo.lock`, and never
  commit a `[patch]` table, a patched lock or a vendored copy.
