# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
semver, staying below 1.0 while the crate is in active development.

## [Unreleased]

## [0.6.0] - 2026-08-30

Fork-healing release. `main` (http-sig, the directory crate, the async
`Signer`, the e2e and DST suites) had zero consumers; the
`feat/backend-unification` branch, tag `CheckPoint.20260817`, was what
aqua-node and aquafier-rs actually ran. This release merges the two, keeps
the ceremony and credential store that production depends on, and drops the
one piece of the branch that had no users and a public-API cost.

### Breaking

- **Removed the Redis session backend.** `redis_backend.rs`,
  `SessionBackendKind`, `build_backend`, and `AuthError::{Redis, Serde,
  LockPoisoned}` are gone. It had no deployment anywhere (aqua-node defaults
  to `session_backend = "memory"` and no manifest defines a Redis service), it
  blocked an async executor on a single `Mutex<redis::Connection>`, one login
  cost two full keyspace `SCAN`s plus a GET per session, and
  `AuthError::Redis` leaked `redis::RedisError` into the public API. The
  *capability* is unchanged: `SessionBackend` and `SessionStore::with_backend`
  stay public, so a consumer implements Redis in the crate that owns its
  connection pool.
- `RedisWebauthnStore::connect` returns `Result<Self, WebauthnStoreError>`
  instead of `Result<Self, AuthError>`. No `redis` type remains in the public
  API.
- The `redis` cargo feature no longer implies `http`; it implies `webauthn`.
  Nothing under it touches the session layer any more, and the implication
  keeps `--features redis` from building the `redis` crate while exposing
  nothing. Every consumer already declares `http` explicitly where it needs
  it.
- `SessionBackend` gained a required method, `sessions_for_did(&str) ->
  Vec<Session>`. Any out-of-tree implementation must add it.

### Added

- `FnSigner`: a `Signer` built from a synchronous closure
  (`FnSigner::new(did, |message| -> Result<Vec<u8>, SignError>)`). Replaces
  the hand-rolled `impl Signer` block each consumer would otherwise write for
  its local keypair.
- `SessionBackend::sessions_for_did`, the indexed per-DID lookup
  `SessionStore::create` uses to enforce the per-DID cap. It replaced an
  `all()` call, which on a remote backend was a full keyspace walk on the
  login path.
- `SessionBackend::purge_expired(now_secs) -> usize`, defaulted over `all()`.
  A backend whose store expires entries itself overrides it with a no-op
  rather than walking the keyspace to delete rows that are already gone.
- `CONSUMERS.md`: every consumer, its pin, git URL spelling and feature set,
  plus the rule that all consumers move together.

### Changed

- `SessionBackend::all()` is now documented cold-path only (administrative
  introspection via `list_sessions`). Nothing on the login path calls it.
- `AuthError::BackendUnavailable` is re-documented as the reporting channel
  for out-of-tree `SessionBackend` implementations: it is now the only
  stringly variant an external backend can return, which is what keeps
  storage-specific error types out of this crate's API.
- The e2e harness (`AquaPeer`, test signers) and the three e2e suites moved
  from `tests/` into a new `aqua-auth-testkit` workspace member
  (`publish = false`), so other repos can reuse the harness by path or git
  dependency instead of copying it. No change to the published `aqua-auth`
  crate: its dependency surface, features, and test lanes are identical; the
  suites now run via `cargo test -p aqua-auth-testkit`.
- `docs/REUSABILITY_HANDOFF.md` (2026-05-20) and `docs/WEBAUTHN_READINESS.md`
  (2026-05-22) moved to `docs/superpowers/specs/` and are marked superseded.
  The readiness doc's "not ready for aquafier-rs" verdict described the 0.2.0
  crate; the ceremony and credential store it asked for are in this release.
- `aqua-auth-directory`'s path dependency requirement moved 0.5 -> 0.6.
- `cargo fmt --check` is clean across the workspace again.

### Merged in from `feat/backend-unification` (first appearance on the main line)

These shipped to production under tag `CheckPoint.20260817` and reach the main
line here:

- `SessionBackend` trait and `InMemoryBackend` (`session_backend.rs`),
  `SessionStore::with_backend`.
- `webauthn_store.rs`: `WebauthnCredentialBackend`, `StoredCredential`,
  `NewCredential`, `CredentialId`, `WebauthnStoreError`,
  `InMemoryWebauthnStore`.
- `redis_webauthn.rs`: `RedisWebauthnStore`, the shared production passkey
  credential store (features `webauthn` + `redis`).
- `ceremony` feature: `webauthn_ceremony.rs`, register/login over
  `webauthn-rs`, `Passkey` blob handling, and passkey to `did:key` derivation.

### Known issues

- `webauthn-rs = "=0.6.1-dev"` is an exact prerelease pin, deliberate so the
  serialized `Passkey` blob stays byte-compatible with aqua-node and aquafier.
  It does not block crates.io publication (0.6.1-dev is published there and
  not yanked), but an `=` requirement on a published library locks the whole
  downstream graph to that one version. Revisit before publishing.

## [0.5.0] - 2026-08-30

Service-to-service maturation release: per-request signatures, async signing,
client-side challenge binding, and a key-advertisement workspace crate. Design
record: `docs/superpowers/plans/2026-08-30-webbotauth-maturation.md`.

### Breaking

- `client::authenticate()` now takes `&dyn Signer` instead of a `did` string
  plus a synchronous `sign_fn` closure. The signer carries its own DID
  (`signer_did()`), so a DID/key mismatch is unrepresentable, and `sign` is
  async so KMS, HSM, wallet, and passkey backends fit without blocking.
- `AuthClientError` has a new variant, `UriOriginMismatch`; exhaustive matches
  on the enum must add an arm.

### Added

- `Signer` trait and `SignError` (always available): the async signing
  contract shared by CAIP-122 login and RFC 9421 request signatures, mirroring
  the Aqua SDK `Signer` shape.
- `http-sig` feature (experimental, tracks draft-meunier-web-bot-auth-architecture-05):
  RFC 9421 HTTP Message Signature signing and verification with two profiles.
  The Aqua-internal profile carries the DID in `keyid` and verifies through
  the existing `DIDMethod`/`CipherSuite` registries, returning a `Principal`;
  the `web-bot-auth` interop profile emits draft-compliant Ed25519 signatures
  with a JWK-thumbprint `keyid`. Includes a bounded `NonceReplayGuard`
  (created/expires window plus single-use nonces, recorded only after the
  signature verifies).
- Client challenge binding: before signing, the client now requires the
  challenge message's `URI:` line to have the same origin as the endpoint it
  dialed, killing cross-service challenge relay against headless clients.
- `ed25519_pubkey_from_did_key()`: public accessor for the raw Ed25519 key
  behind a `did:key:z6Mk` DID (the did:pkh spelling keeps its separate parser;
  the two-principal ruling from #182 is unchanged).
- New workspace member `aqua-auth-directory` 0.1.0: public-key advertisement
  for Aqua services. `KeyRegistry` with validity windows and rotation overlap,
  RFC 7638 JWK thumbprints (pinned to the RFC 8037 A.3 vector), and two
  framework-agnostic renderers: the JWKS directory per
  draft-meunier-webbotauth-httpsig-directory-00 at
  `/.well-known/http-message-signatures-directory`, and an Aqua-native
  identity document at `/.well-known/aqua-identity`. Public keys only, never
  custody.

### Changed

- SPEC.md documents the three proof surfaces (content via aqua-trees,
  connection via CAIP-122 sessions, request via RFC 9421) and the
  author-vs-courier distinction.
- House style sweep: em dashes removed repo-wide; clippy and rustdoc clean.

## [0.4.0] and earlier

Pre-changelog history; see the git log. Highlights: `Principal` +
`authenticate()` (scoped-self identity, #167), bounded challenge/session
stores with revocation, WebAuthn assertion verification (`webauthn` feature),
did:key and did:peer support, the two-spellings/two-principals ruling (#182).
