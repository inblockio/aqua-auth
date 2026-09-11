# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
semver, staying below 1.0 while the crate is in active development.

## [Unreleased]

### Fixed

- **SPEC section 7 rule 5 ("DID well-formed") now has an enforcement layer of
  its own.** It had none: the only thing that ever rejected a malformed
  identifier was the signature-verification path incidentally failing to
  parse a key out of it, so rule 5 held only to the extent that verification's
  own DID parsing happened to catch it. Measured 2026-09-11 against the
  conformance suite's seven malformed shapes (`spec_7_5_did_well_formed`),
  five reached `ChallengeStore::create` and were handed a real nonce for the
  full TTL: the four `did:pkh:ed25519` shapes (31-byte, 33-byte, missing
  `0x`, non-hex) and the 32-byte `did:pkh:p256` shape. The two refused early
  were refused by accident, not by design: `PkhMethod::address_for_message`
  special-cases eip155 to `checksummed_address`, which length-checks, and
  `build_message` calls `method_label`, which for `did:key` decodes the
  multibase body.

  The fix is a new public function, `validate_did_well_formed()`
  (`src/did_format.rs`). It is called at three independent points so that no
  single future change can remove rule 5 again: `ChallengeStore::create`,
  `authenticate_with_public_key`, and `Principal::from_trusted_did`. The
  per-method verifiers underneath all three are unchanged: this is defence in
  depth, not a relocation, and a relocated check would have left exactly the
  single point of failure it was meant to remove.

  **The one observable behaviour change:** `ChallengeStore::create` and
  `Principal::from_trusted_did` now refuse DIDs they used to accept. None of
  those DIDs could ever have produced a verifying signature, so no legitimate
  caller is affected, which is why this lands in 0.8.0 rather than needing a
  patch release of its own. The refusal set is also a strict subset of what
  verification already refused, by construction rather than by review: each
  arm of `validate_did_well_formed()` calls the same parser the corresponding
  verifier calls first, so the new check cannot reject anything the crate
  used to accept.

## [0.8.0] - 2026-09-11

What a consumer had to write for itself, and a way to tell whether a server is
right. Three surfaces that every consumer was reimplementing downstream now ship
here: `did:key` encoders, a local-key `Signer` over PKCS#8 PEM, and a session
that re-authenticates itself on 401. `aqua-agents` had built all three by hand,
plus a CAIP-122 login that skips the challenge binding checks, which is what
prompted the review.

Alongside them, the first post-quantum namespace (`did:aqua`, ML-DSA-87, behind
a feature and verification only), `authenticate()` promoted to the contract, the
client binding checks specified for the first time, and a conformance suite that
judges a server instead of this crate.

**Nothing here breaks the wire.** The minor bump is carried by the
`verify_caip122` deprecation and the new surfaces. One commit on the way here
(`1ef890f`) is marked `!` for a breaking change that the next commit
(`cf07f72`) reverts; a release-notes generator reading conventional commits will
claim a break that does not exist.

### Changed

- **`wire::ChallengeEnvelope` does not carry `did`**, and tolerates servers
  that send one. Earlier on 2026-09-11 the field was added to match `SPEC.md`
  Section 6.2; later the same day it was removed again and Section 6.2 amended
  to match, on the rule that a part you do not need is a part you should not
  have.

  Nothing consumed it. The client's binding check compares the identifier
  inside `message` against the **signer's own** DID, never an envelope field,
  so the one place the field could have mattered never read it. `did:aqua`
  carries its public key on `SessionRequest`. A field no code reads is a
  second place to state an identity and therefore a second place for it to
  disagree with the first.

  **This is not a breaking change and requires no server change.** There is no
  `deny_unknown_fields`, so servers keep emitting `did` and serde keeps
  discarding it. It also restores compatibility with `timestamp.inblock.io`,
  which has never sent the field; requiring it would have made that endpoint
  unparseable for every client built on this crate.

  Section 6.2 now also specifies the **URI origin binding check**, which was
  implemented and tested in `client::signed_session_request` but appeared in
  no specification text. It is what refuses a challenge relayed from another
  Aqua service, and with `did` gone the two client-side checks and their
  ordering are the entire mitigation, so they belong in the spec rather than
  only in the code.

### Deprecated

- **`verify_caip122` in favour of `authenticate`.** This deprecation, together
  with the new `local-key` and `AuthSession` surfaces, is what carries the
  0.8.0 bump; the wire format is unchanged in both directions. Ruled 2026-09-11: a `bool`
  is the wrong return type for proof of possession. Nothing in the type system
  stops a caller verifying one DID and creating a session for another, and
  `Ok(false)` is as easy to drop as any other boolean, whereas a `Principal`
  can only exist because a verification succeeded.

  **This is a warning, not a removal.** `verify_caip122` still works, is still
  supported for callers that genuinely only need the yes/no, and the
  deprecation note says so along with what changes at a call site. No consumer
  is required to move, and none has been moved: aqua-node and aquafier-rs are
  untouched by this release.

  The warning is the migration mechanism. Consumers that only want the boolean
  silence it with `#[allow(deprecated)]`; the crate's own tests do exactly
  that, since asserting "this signature verifies" is the question the boolean
  verifier exists to answer.

  `authenticate` itself no longer routes through `verify_caip122` at all: it
  delegates to `authenticate_with_public_key`, which calls
  `verify_caip122_with_public_key` and reaches the registry directly. The
  library therefore builds warning-free with no production-path `allow`.

### Added

- **`did:aqua`, the ML-DSA-87 post-quantum namespace (PCA-0017)**, behind the
  new `did-aqua` feature, off by default. A `did:aqua` identity can complete a
  CAIP-122 login and be issued a session.

  This is the first namespace whose verifier can obtain the public key neither
  from the DID nor from the signature. The other namespaces do one or the
  other: `did:key`, `did:pkh:{ed25519,p256}` and `did:peer` embed the key and
  decode it out, while `did:pkh:eip155` hashes it and recovers the key from
  the signature, which works only because secp256k1 ECDSA is recoverable.
  ML-DSA has no recovery, and `did:aqua` is a SHA3-256 commitment, so the key
  has to travel separately. It does so in a new optional `public_key` field on
  the session request (`SPEC.md` section 6.3), and the server binds it back to
  the DID before trusting it. See `SPEC.md` section 6.6 for the four
  transports evaluated and why this one was taken.

  **Read this before deploying it.** A `did:aqua` identity will authenticate
  and then fail at every authorization boundary. Both servers carry DID
  dispatch outside this crate's registry that predates the namespace:
  `aquafier-delegated-keys` hard-rejects any DID that is not `did:key` or
  `did:pkh`, and both `ceremony_signature_type` implementations silently
  label an unrecognised DID as an Ethereum signer. Enabling `did-aqua` gets
  you login, not a working agent identity. Tracked in
  `docs/did-aqua-phase-2.md`.

  The codec is reimplemented here rather than taken from `aqua-rs-sdk`, so
  this crate continues to depend on no Aqua crate and never inherits the SDK's
  pin. The two implementations are held together by the PCA-0017 section 5.1
  published vector, pinned as a test: if they ever diverge, that test fails
  here rather than a signature failing in production. `ml-dsa` is pinned to
  0.1.1, exactly the version the SDK uses, because the one thing that must not
  diverge is what actually verifies.

- **`DIDMethod::verify_with_public_key`**, `verify_caip122_with_public_key`
  and `authenticate_with_public_key`: the key-aware twins of the existing
  entry points. All additive, all with default bodies, so every existing
  `DIDMethod` implementation compiles unchanged.

  **Non-breaking for compilation, not for semantics.** A server that upgrades
  without plumbing the key through will 401 every `did:aqua` login rather than
  fail to build. That is the intended failure direction, but it is a runtime
  behaviour a deployment has to opt into rather than something the compiler
  will point at. Classical namespaces are entirely unaffected: they ignore the
  new argument.

  `CipherSuite` deliberately does **not** get the same change. It is internal
  to `PkhMethod`, and `did:aqua` is its own method rather than a `did:pkh`
  namespace.

- **`Signer::public_key()`**, defaulting to `None`. Only a `did:aqua` signer
  answers it. The key is public by definition and the private half never
  crosses the trait.

- **`aqua_auth_testkit::signers::did_aqua()`**, a sixth spelling for the e2e
  harness, with adversarial coverage of the key binding: a valid signature
  presented under a DID committing to another key, a substituted key, and a
  missing key are all refused.


- **`did::ed25519_did_key_from_pubkey` / `did::p256_did_key_from_pubkey`**: the
  encode direction for `did:key`, which the crate had never exported. Only the
  decoders existed, so every producer open-coded multicodec plus base58btc:
  six times inside this crate, plus the testkit, aqua-agents, the SDK and siwx.
  A DID string is an identity, and two producers that disagree mint two
  identities for one key. `webauthn_ceremony::did_key_from_p256_compressed` now
  delegates here and its duplicate multicodec constant is gone; its output is
  unchanged and covered by a test.

  Named for the `did:key` spelling rather than the curve because the `did:key`
  and `did:pkh` forms of one key are distinct principals (#182), and a
  curve-only name would let a caller mint the wrong one silently.

- **`LocalKeySigner`** behind the new `local-key` feature: a `Signer` over an
  Ed25519 or P-256 PKCS#8 PEM held in this process, deriving its own `did:key`
  through the encoders above so the key and the DID cannot drift apart. The
  crate shipped the `Signer` trait and `FnSigner` but nothing that loads a key,
  so every consumer wrote this. Opt-in because raw key material in process
  memory is what a production signer should avoid. `Debug` is implemented by
  hand and redacts the key.

- **`client::AuthSession`** behind `client`: an authenticated session that
  re-runs the CAIP-122 login once on a `401` and retries the request. `SPEC.md`
  section 6.5 makes sessions server-memory-resident and explicitly not durable
  across a restart, so a long-lived client's token can die at any time;
  `authenticate()` alone left every consumer writing the same retry. The token
  is handed to a caller-supplied request builder rather than attached here,
  because the Aqua node dialects accept it as a Bearer header, a `nonce` header
  or an `aqua_session` cookie. Covered by two loopback e2e tests, including one
  that counts signer invocations to prove the recovery re-runs the ceremony
  rather than replaying a cached signature.

### Changed

- `CONSUMERS.md` re-verified against 0.7.0: siwx-oidc is now tag-pinned
  (`v0.7.0`, 2026-09-11) rather than unpinned, and `aqua-agents` is recorded as
  a transitive consumer that wants `client` but is blocked on the URL-spelling
  rule.

## [0.7.0] - 2026-08-31

Async credential store. 0.6.0 removed the Redis *session* backend, which was
the "blocking-Redis pattern" that `WebauthnCredentialBackend` cited to justify
being sync. The justification outlived its referent by one release; this
release retires the sync trait.

### Breaking

- **`WebauthnCredentialBackend` is now `#[async_trait]`.** Every method is
  `async`. `InMemoryWebauthnStore` and `RedisWebauthnStore` move with it.

  Why: sync forecloses and async does not. An in-memory backend pays nothing
  to be async, whereas a sync trait makes a correct async implementation
  impossible, since `block_on` inside a tokio worker deadlocks. That is
  precisely why siwx-oidc (whose Redis client is async) could not adopt this
  store. Meanwhile the primary consumer, aqua-node, had already written the
  async version by hand: `WebauthnCredentialStore` in
  `crates/aqua-node-api/src/webauthn/store.rs`, same method names, same
  `NewCredential`/`StoredCredential` shape. No consumer used `spawn_blocking`,
  the escape hatch the old doc comment offered, so blocking Redis I/O was
  running on tokio worker threads in production.

  Migration for implementors: add `use async_trait::async_trait;`, put
  `#[async_trait]` on the `impl`, mark each method `async fn`. An in-memory
  implementation needs no other change, as long as no lock guard is held
  across an `.await`.

- **`list_for_did` and `get_by_id` now return `Result`.** They were
  `Vec<StoredCredential>` and `Option<StoredCredential>`, so a backend failure
  was indistinguishable from "this DID has no credentials" and "no such
  credential": a Redis blip silently degraded to an empty `allowCredentials`
  list or a failed login instead of a 5xx. Absent rows are still the cheap
  non-error path (`Ok(vec![])`, `Ok(None)`); only real backend failures are
  `Err`. This also makes the trait signature-compatible with aqua-node's
  hand-written async trait.

- **`RedisWebauthnStore::connect` is now `async`.** It stays eager, so an
  unreachable Redis still fails at boot rather than at first login. Callers
  doing lazy `std::sync::OnceLock` initialisation need `tokio::sync::OnceCell`
  (or equivalent) instead.

- **The `redis` cargo feature now enables `redis/tokio-comp` and
  `redis/connection-manager`.** A crate that depends on `aqua-auth`'s `redis`
  feature and also pins the `redis` crate itself will see both unified into its
  own build. (`connection-manager` does not imply `tokio-comp` in redis 0.27;
  both are needed or the `aio` module fails to compile.)

### Changed

- `RedisWebauthnStore` holds a `redis::aio::ConnectionManager` instead of a
  `Mutex<redis::Connection>`. The single global mutex serialised every
  credential operation process-wide; the manager is multiplexed, so concurrent
  commands pipeline over one socket and the bottleneck is retired rather than
  moved. It is also self-healing, which a bare `MultiplexedConnection` is not:
  that one never reconnects, so a single Redis restart would leave every later
  credential operation failing with a broken pipe until the process itself
  restarted. Found the hard way, by a test that shared one store across two
  tokio runtimes.
- `RedisWebauthnStore::list_for_did` now propagates a `SMEMBERS`/`GET` failure
  instead of returning an empty vec. Individual undecodable rows are still
  skipped, so one corrupt credential cannot strand the rest.

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
