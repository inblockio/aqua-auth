# aqua-auth

Universal authentication for the [Aqua Protocol](https://github.com/inblockio) ecosystem. One identity (a DID and its key) drives three kinds of proof: interactive [CAIP-122](https://chainagnostic.org/CAIPs/caip-122) login sessions, per-request [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) HTTP Message Signatures for service-to-service and agent traffic, and public-key advertisement so third parties can verify you. Any two Aqua services, and any client (web app, mobile app, CLI, agent, or another node), authenticate through the same primitives regardless of which DID namespace either side uses.

## Repository layout

This is a two-member Cargo workspace:

| Crate | Version | Scope |
|---|---|---|
| **`aqua-auth`** (root) | 0.5.0 | Crypto/DID verification, CAIP-122 challenge-response sessions, the async `Signer` contract, the HTTP client, RFC 9421 request signatures, WebAuthn assertion verification |
| **[`aqua-auth-directory`](aqua-auth-directory/)** | 0.1.0 | Public-key advertisement: `.well-known` key-directory documents (JWKS and Aqua-native). Public keys only, never key custody |

The directory crate is versioned independently because it tracks an IETF draft; draft churn there never forces a version bump on `aqua-auth`.

## Three proof surfaces

Each surface answers a different question, and none subsumes the others (full rationale in [`SPEC.md`](SPEC.md) section 11):

| Surface | Mechanism | Question answered |
|---|---|---|
| Content | Aqua-tree Signature revisions ([`aqua-rs-sdk`](https://github.com/inblockio/aqua-rs-sdk)) | Who **authored** this data? |
| Connection | CAIP-122 challenge-response, then a bearer session token (this crate, `http`/`client`) | Who is on this **connection**? |
| Request | RFC 9421 HTTP Message Signatures (this crate, `http-sig`, experimental) | Who sent this specific **HTTP request**? |

Author is not courier: a signed aqua-tree proves who authored it, not who is delivering it now. The connection and request surfaces authenticate the courier. All verification paths converge on the same `Principal` type, and one async `Signer` implementation produces signatures for every surface from a single key custody point.

## Identity: DID namespaces

Three first-class namespaces, all on by default:

| Namespace | DID shape | Identifier | Signature |
|---|---|---|---|
| `eip155` | `did:pkh:eip155:<chain_id>:0x<eip55_address>` | EVM 20-byte address (EIP-55) | EIP-191 personal_sign over secp256k1 |
| `ed25519` | `did:key:z6Mk<multibase>` **or** `did:pkh:ed25519:0x<32-byte pubkey hex>` | Ed25519 public key | Ed25519 over canonical message bytes |
| `p256` | `did:key:zDn<multibase>` **or** `did:pkh:p256:0x<33-byte compressed pubkey hex>` | P-256 public key | P-256 ECDSA over canonical message bytes |

The two non-EVM namespaces are Aqua extensions to CAIP-122; `did:peer` (variants 0 and 2) is additionally supported for DID resolution. See [`SPEC.md`](SPEC.md) for the authoritative wire contract.

**Two spellings, two principals (#182, ruled 2026-08-06).** An ed25519/P-256 key has two accepted login DIDs: its `did:key` form and its `did:pkh:{ed25519,p256}` form. Both are valid, and they are **distinct principals**: the storage layer (`canonical_trust_key`) keys them separately, so each spelling has its own grant bucket. Logging in under one spelling then the other returns a **different set of resources**; this is intended, not a bug. If a user reports "my files disappeared" after switching login method, that is this behaviour (they authenticated as a different principal), not a regression; do **not** re-open #182.

## Feature flags

Only the crypto/DID primitives are unconditionally compiled: the `CipherSuite` and `DIDMethod` registries, the verifier modules, DID parsing, `verify_caip122()`, `Principal`/`authenticate()`, and the `Signer` trait. Everything else is opt-in:

| Flag | Default | What it gates |
|---|---|---|
| `http` | off | The session layer: CAIP-122 message construction, the on-wire JSON shapes, and the in-memory `ChallengeStore` / `SessionStore`. Pulls in `rand`, `serde_json`, `chrono`, `dashmap`, `tokio`, `tracing`. |
| `client` | off | Implies `http`. `client::authenticate()`: the full challenge-response flow over `reqwest`, with pre-sign challenge binding checks. |
| `http-sig` | off | **Experimental.** RFC 9421 request signatures: `sign_request` / `verify_request`, replay protection, two profiles (Aqua-internal and `web-bot-auth` interop). Pulls in `sfv`, `base64`, `rand`, `dashmap`. |
| `webauthn` | off | Standalone P-256 WebAuthn assertion verifier. Pulls in `sha2`, `base64`, `serde_json`. Independent of `http`. |

Per-namespace gating is deliberately not offered: a service that accepts Aqua CAIP-122 accepts all three namespaces, full stop.

## Quick start

### Implement `Signer` once

Everything that signs (login, request signatures) goes through the async `Signer` trait. Implement it for however you hold the key: a local keypair, a KMS or HSM client, a wallet prompt, a passkey. It carries its own DID, so a DID/key mismatch is unrepresentable.

```rust
use aqua_auth::{SignError, Signer};
use async_trait::async_trait;

struct MySigner { /* key handle + did */ }

#[async_trait]
impl Signer for MySigner {
    fn signer_did(&self) -> &str { "did:key:z6Mk..." }

    async fn sign(&self, message: &str) -> Result<Vec<u8>, SignError> {
        // Raw signature bytes: 65-byte EIP-191 for eip155, 64-byte raw for
        // ed25519 and p256.
        Ok(self.backend.sign(message).await?)
    }
}
```

### Log in from a client (`client` feature)

```rust
use aqua_auth::client::authenticate;

let session = authenticate(
    &reqwest::Client::new(),
    "https://timestamp.inblock.io",
    &MySigner::new(),
)
.await?;
// session.token is an opaque Bearer; attach it as Authorization: Bearer <token>
```

`authenticate()` runs the full handshake and refuses to sign anything it did not ask for:

1. `GET /auth/challenge?did=<did>` returns a `ChallengeEnvelope`.
2. Before signing, the identifier embedded in the SIWE message must match the signer's DID (`MessageIdentifierMismatch` otherwise), **and** the message's `URI:` line must have the same origin (scheme, host, port) as the dialed `base_url` (`UriOriginMismatch` otherwise). Both checks run before the signer is ever invoked, so a compromised endpoint cannot relay another service's challenge to a headless client.
3. `POST /auth/session` exchanges the signed challenge for a `SessionResponse`.

### Verify logins on a server (`http` feature)

```rust
use aqua_auth::{authenticate, ChallengeStore, SessionStore};

// At startup:
let challenges = ChallengeStore::new(300, "myhost.example".into(), "https://myhost.example".into());
let sessions = SessionStore::new(3600);

// GET /auth/challenge?did=...
let challenge = challenges.create(&did)?;
// Return ChallengeEnvelope { nonce, message, expires_at }

// POST /auth/session { did, nonce, signature }
let stored = challenges.validate(&nonce)?;
assert_eq!(stored.did, did);
let sig_bytes = hex::decode(signature.trim_start_matches("0x"))?;
let principal = authenticate(&did, &stored.message, &sig_bytes)?; // -> Principal
let session = sessions.create(principal.did())?; // may fail at capacity: map to 503
// return SessionResponse { did, token, valid_until, created_at }
```

`authenticate()` (crate root, always available) verifies the signature and returns a `Principal`, the scoped-self authenticated identity. aqua-auth says *who signed*; the consuming service owns session persistence and authorization.

### Sign and verify individual requests (`http-sig` feature, experimental)

Stateless per-request authentication: no challenge round trip, no bearer token to steal. The Aqua-internal profile puts the DID in `keyid`, so verification needs no key directory (Aqua DIDs are self-certifying) and returns the same `Principal` a login does.

```rust
use aqua_auth::http_sig::{
    sign_request, verify_request, NonceReplayGuard, Profile, RequestParts, VerifyOptions,
};
use std::{sync::Arc, time::Duration};

// Client side: produce the two headers.
let parts = RequestParts::new("POST", "https://node.example/api/trees");
let headers = sign_request(&signer, &parts, &Profile::AquaInternal, Duration::from_secs(300)).await?;
// attach headers.signature_input as `Signature-Input`, headers.signature as `Signature`

// Server side: verify, with single-use nonces.
let guard = Arc::new(NonceReplayGuard::new());
let opts = VerifyOptions::aqua_internal().with_replay_guard(guard);
let principal = verify_request(&parts, &signature_input_header, &signature_header, &opts)?;
```

Verification enforces the covered components (`"@authority"`, plus `"signature-agent"` when present), the `created`/`expires` window (24h cap, configurable clock skew), tag and algorithm consistency with the DID's method, and nonce single-use; a nonce is recorded only after the signature verifies. The `Profile::WebBotAuth { jwk_thumbprint }` variant emits [draft-meunier-web-bot-auth-architecture](https://datatracker.ietf.org/doc/draft-meunier-web-bot-auth-architecture/) compliant Ed25519 signatures (`tag="web-bot-auth"`), so an Aqua agent on the public web is verifiable by Cloudflare/Akamai/AWS-WAF-class infrastructure.

### Advertise your public keys (`aqua-auth-directory` crate)

For services and agents that need third parties to find their keys:

```rust
use aqua_auth_directory::{render_aqua_identity, render_jwks, AdvertisedKey, KeyRegistry};

let mut registry = KeyRegistry::new();
registry.add(AdvertisedKey { did: "did:key:z6Mk...".into(), nbf, exp })?;

let jwks = render_jwks(&registry, now)?;      // serve at jwks.path
let ident = render_aqua_identity(&registry, now)?; // serve at ident.path
// Each DirectoryDocument carries { path, content_type, cache_control, body };
// mount it in your own router (axum, actix, anything).
```

`render_jwks` produces the key directory per [draft-meunier-webbotauth-httpsig-directory](https://datatracker.ietf.org/doc/draft-meunier-webbotauth-httpsig-directory/) for `/.well-known/http-message-signatures-directory`; `render_aqua_identity` produces the Aqua-native `/.well-known/aqua-identity` document. Registry semantics: validity windows (`nbf` inclusive, `exp` exclusive), rotation overlap (predecessor and successor both listed while their windows overlap), RFC 7638 thumbprints as `kid`. The crate handles public keys only; private key custody stays with your `Signer`.

## Bounded stores and revocation

Both in-memory stores carry a hard capacity so neither grows without bound under a flood:

```rust
// Defaults: MAX_CHALLENGES = 8192, MAX_SESSIONS = 8192, MAX_SESSIONS_PER_DID = 32.
let sessions = SessionStore::with_capacity(3600, /* max_sessions */ 4096, /* max_sessions_per_did */ 16);
```

- `ChallengeStore::create` purges expired challenges first; at capacity it evicts the single oldest-issued challenge (pre-auth and short-TTL, so this only inconveniences whoever is flooding).
- `SessionStore::create` purges expired sessions first; at capacity it returns `Err(AuthError::SessionStoreFull)` rather than evicting an active session. A single DID exceeding its own per-DID quota has its own oldest session evicted, bounding session farming without touching other identities.
- `SessionStore::revoke(token)` and `revoke_all_for_did(did)` back a `/auth/logout` endpoint; revoked tokens fail `validate` immediately.

Stores are in-memory by default. For multi-instance deployments, plug in your own store; verification (`verify_caip122`, `verify_request`) is independent of state, and per-request signatures remove the session store from pure service-to-service paths entirely.

## WebAuthn assertion verification (`webauthn` feature)

For login flows that authenticate a passkey rather than a raw DID signature: a standalone P-256 verifier (`verify_webauthn_assertion`, `WebAuthnAssertionParams`) with no `webauthn-rs` dependency. It checks the rpIdHash, the user-present flag, the origin, the expected challenge, and the P-256 signature over `authenticatorData || SHA-256(clientDataJSON)`. Independent of the `http` session layer.

## Wire contract

The canonical on-wire shapes live in `aqua_auth::wire`:

```rust
pub struct ChallengeEnvelope { pub nonce: String, pub message: String, pub expires_at: u64 }
pub struct SessionRequest    { pub did: String, pub nonce: String, pub signature: String }
pub struct SessionResponse   { pub did: String, pub token: String, pub valid_until: u64, pub created_at: u64 }
```

Every Aqua service that exposes `/auth/challenge` + `/auth/session` MUST emit and accept these shapes. Consumers MAY ignore additional fields but MUST NOT depend on them. Full wire spec: [`SPEC.md`](SPEC.md) section 6.

## Threat model

Defense layers, weakest to strongest:

1. **TLS** authenticates the FQDN and prevents passive eavesdropping.
2. **Client-side challenge binding**: the identifier check and the URI-origin check refuse to sign challenges minted for another identity or another service, before the key is ever touched.
3. **SIWE message body** carries the DID's identifier; any tampering breaks the signature.
4. **`ChallengeStore`** ties each nonce to one DID at challenge time and cross-checks against the session POST.
5. **Signature verification** (`verify_caip122` / `verify_request`) is namespace-dispatched and is the cryptographic root.
6. **Replay protection** (`http-sig`): validity windows plus single-use nonces recorded only after successful verification, so unsigned traffic can neither burn nonces nor fill the bounded guard.

Session tokens are opaque bearers: anyone holding one can use it until expiry or revocation. Where that window is unacceptable (service-to-service, agents), use `http-sig` per-request signatures instead of session tokens.

## Standards and stability

- The CAIP-122 wire contract ([`SPEC.md`](SPEC.md) sections 2 to 10) is stable.
- `http-sig` and `aqua-auth-directory` track IETF drafts from the [`webbotauth`](https://datatracker.ietf.org/wg/webbotauth/about/) working group (no adopted documents yet) and are **explicitly experimental**: exempt from the semver stability promise until the WG adopts documents. Pinned draft revisions are recorded in the module docs.
- Versions stay below 1.0 deliberately while the crate family is in active development; minor bumps may break. See [`CHANGELOG.md`](CHANGELOG.md).

## Related projects

- [`aqua-rs-sdk`](https://github.com/inblockio/aqua-rs-sdk): Aqua Protocol Rust SDK (revisions, tree signing, verification). Its `Signer` signs tree revisions; this crate's `Signer` mirrors that shape for login and request signatures.
- [`siwx-oidc`](https://github.com/inblockio/siwx-oidc): CAIP-122 to OpenID Connect bridge. Layers a standard OIDC provider over the same three namespaces, so any OIDC relying party (Matrix, Keycloak, GitLab, etc.) can accept Aqua-keyed users.
- [`aqua-timestamp`](https://github.com/inblockio/aqua-timestamp): reference consumer; the deployed `timestamp.inblock.io` uses `aqua-auth` for its server-side handshake.

When to reach for which:

- **`aqua-auth` sessions** for interactive login and human-facing flows inside the Aqua ecosystem.
- **`aqua-auth` `http-sig`** for service-to-service and agent traffic, and for being verifiable as a signed agent on the public web.
- **`siwx-oidc`** for federated end-user identity via standard OIDC tokens.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
