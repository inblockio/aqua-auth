# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
semver, staying below 1.0 while the crate is in active development.

## [Unreleased]

### Changed

- The e2e harness (`AquaPeer`, test signers) and the three e2e suites moved
  from `tests/` into a new `aqua-auth-testkit` workspace member
  (`publish = false`), so other repos can reuse the harness by path or git
  dependency instead of copying it. No change to the published `aqua-auth`
  crate: its dependency surface, features, and test lanes are identical; the
  suites now run via `cargo test -p aqua-auth-testkit`.

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
