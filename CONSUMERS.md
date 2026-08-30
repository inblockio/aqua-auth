# Consumers of `aqua-auth`

Every repo that depends on this crate, with the exact pin, git URL spelling and
feature set it declares. **Keep this file current.** Nothing in this repo builds
its consumers, which is how `main` and `feat/backend-unification` drifted into
two heads for six weeks without anyone noticing: the head with all the tests had
no users, and the head with all the users had no tests.

Last verified: **2026-08-30**, against `aqua-auth` 0.6.0.

## The rule: all consumers move together

This crate is semver-bound and headed for crates.io, but today every consumer
takes it as a **git dependency pinned to a tag**. That means a breaking change
here is invisible until someone bumps a tag, and a bump that lands in one repo
while the others stay behind gives you two `aqua-auth` instances in a
multi-repo build.

So:

1. **Cut a tag, then move every pinned consumer to it in the same batch.** Do
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
   is still named `aqua-rs-auth`; `aqua-auth` is only a GitHub rename redirect,
   so spelling the URL the new way also forks the source.
3. **Declare every feature you use.** Cargo unions features across a dependency
   graph, so a crate can compile against a feature a *sibling* declared. That
   compiles today and breaks the moment the sibling drops the feature. See
   aquafier-rs below.

## Consumers

| Repo | Pin | URL spelling | Features | Notes |
|---|---|---|---|---|
| aqua-node | `tag = "CheckPoint.20260817"` | `ssh://` | `http`, `redis`, `webauthn`, `ceremony` | Primary server-side consumer. Locked at `7d227b5` (0.4.0). |
| aquafier-rs | `tag = "CheckPoint.20260817"` | `ssh://` | `http`, `webauthn`, `ceremony`, `redis` | Locked at `7d227b5` (0.4.0). `redis` added 2026-08-30, see below. |
| aqua-state-viewer | `tag = "CheckPoint.20260521"` | `ssh://` | `client` | Locked at `056cb34` (0.2.0). Three tags behind. |
| siwx-oidc (root) | **unpinned** | `https://` | `webauthn` | Locked at `056cb34` (0.2.0) by `Cargo.lock` only. |
| siwx-oidc-auth | **unpinned** | `https://` | (default) | Same workspace as above, so it also sees `webauthn` by feature union. |
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

The only consumer on `https://` and the only one with **no tag**. It is held at
`056cb34` by its `Cargo.lock` alone, so a bare `cargo update` moves it from
0.2.0 to whatever `main` currently is, across four minor versions of breaking
changes, with no review step. It should be pinned to a tag like everyone else.

Its whole workspace does compile clean against 0.6.0 (verified 2026-08-30 via
a local `[patch]`), so the drift is source-compatible today. Pin it anyway.

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
