# aqua-auth

Universal [CAIP-122](https://chainagnostic.org/CAIPs/caip-122) (Sign-In With X) session authentication for the Aqua Protocol ecosystem. Any two Aqua services can authenticate each other through the same challenge-response handshake, regardless of which DID namespace either side uses.

Three first-class DID namespaces, all on by default:

| Namespace | DID shape | Identifier | Signature |
|---|---|---|---|
| `eip155` | `did:pkh:eip155:<chain_id>:0x<eip55_address>` | EVM 20-byte address (EIP-55) | EIP-191 personal_sign over secp256k1 |
| `ed25519` | `did:pkh:ed25519:0x<32-byte pubkey hex>` | raw Ed25519 public key | Ed25519 over canonical message bytes |
| `p256` | `did:pkh:p256:0x<33-byte compressed pubkey hex>` | compressed P-256 public key | P-256 ECDSA over canonical message bytes |

The two non-EVM namespaces are Aqua extensions to CAIP-122. See [`SPEC.md`](SPEC.md) for the authoritative wire contract.

## Quick start

### Client (with the `client` feature)

```rust
use aqua_auth::client::authenticate;

let session = authenticate(
    &reqwest::Client::new(),
    "https://timestamp.inblock.io",
    "did:pkh:eip155:1:0x...",
    |message: &str| {
        // sign `message` with your CAIP-122 key, return hex
        Ok(my_signer.sign(message)?)
    },
)
.await?;

// session.token is an opaque Bearer; attach it as Authorization: Bearer <token>
```

`authenticate()` does the full two-roundtrip handshake:

1. `GET /auth/challenge?did=<did>` returns a [`ChallengeEnvelope`].
2. Before signing, the client checks that the identifier embedded in the SIWE message body matches the DID's expected identifier. A mismatch returns `AuthClientError::MessageIdentifierMismatch` without invoking the signer (defense in depth).
3. `POST /auth/session` exchanges the signed challenge for a [`SessionResponse`].

### Server (with the `http` feature)

```rust
use aqua_auth::{ChallengeStore, SessionStore, verify_caip122};

// At startup:
let challenges = ChallengeStore::new(300, "myhost.example".into(), "https://myhost.example".into());
let sessions = SessionStore::new(3600);

// GET /auth/challenge?did=...
let challenge = challenges.create(&did)?;
// Return ChallengeEnvelope { nonce: challenge.nonce, message: challenge.message, expires_at: challenge.expires_at }

// POST /auth/session { did, nonce, signature }
let stored = challenges.validate(&nonce)?;
assert_eq!(stored.did, did);
let sig_bytes = hex::decode(signature.trim_start_matches("0x"))?;
if verify_caip122(&did, &stored.message, &sig_bytes)? {
    let session = sessions.create(&did);
    // return SessionResponse { did, token, valid_until, created_at }
}
```

The `ChallengeStore` and `SessionStore` are in-memory by default with TTL-based cleanup. For multi-instance deployments, plug in your own store implementation; the verifier dispatch (`verify_caip122`) is independent of state.

## Wire contract

The canonical on-wire shapes live in `aqua_auth::wire`:

```rust
pub struct ChallengeEnvelope { pub nonce: String, pub message: String, pub expires_at: u64 }
pub struct SessionRequest    { pub did: String, pub nonce: String, pub signature: String }
pub struct SessionResponse   { pub did: String, pub token: String, pub valid_until: u64, pub created_at: u64 }
```

Every Aqua service that exposes `/auth/challenge` + `/auth/session` MUST emit these shapes and accept these shapes. Consumers MAY ignore additional fields they receive but MUST NOT depend on them. See [`SPEC.md`](SPEC.md) §6 for the full wire spec.

## Feature flags

| Flag | Default | What it gates |
|---|---|---|
| `http` | off | The session/auth layer: CAIP-122 message construction (`message`: `build_message`, `MessageParams`), the on-wire shapes (`wire`: `ChallengeEnvelope`, `SessionRequest`, `SessionResponse`), session/challenge types (`types`), and the in-memory `ChallengeStore` / `SessionStore`. Pulls in `rand`, `serde_json`, `chrono`, `dashmap`, `tokio`. |
| `client` | off | Implies `http`. Adds `aqua_auth::client::authenticate()` plus the `reqwest` transport dependency. |
| `webauthn` | off | Standalone P-256 WebAuthn assertion verifier (`verify_webauthn_assertion`, `WebAuthnAssertionParams`). Pulls in `sha2`, `base64`, `serde_json`. Independent of `http`. |

Only the crypto/DID primitives are unconditionally compiled: the `CipherSuite` and `DIDMethod` registries, the `did`/`did_method`/`key`/`peer`/`pkh` verifier modules, DID parsing and EIP-55 helpers in `did`, and `verify_caip122`. Everything else (`message`, `wire`, `ChallengeStore`, `SessionStore`) lives behind `http`. Per-namespace gating is deliberately not offered: a service that accepts Aqua CAIP-122 accepts all three namespaces, full stop.

## WebAuthn assertion verification (with the `webauthn` feature)

For login flows that authenticate a passkey rather than a raw DID signature, the `webauthn` feature ships a standalone P-256 WebAuthn assertion verifier. It has no `webauthn-rs` dependency and pulls in only `sha2`, `base64`, and `serde_json`.

```rust
use aqua_auth::{verify_webauthn_assertion, WebAuthnAssertionParams};

verify_webauthn_assertion(&WebAuthnAssertionParams { /* ... */ })?;
```

The verifier checks the rpIdHash, the user-present (UP) flag, the origin, the expected challenge, and the P-256 signature over `authenticatorData || SHA-256(clientDataJSON)`. It is independent of the `http` session layer.

## Threat model

Defense layers, weakest to strongest:

1. **TLS** authenticates the FQDN and prevents passive eavesdropping.
2. **SIWE message body** carries the DID's identifier. Any tampering breaks the signature.
3. **`ChallengeStore`** ties each nonce to one DID at challenge time and cross-checks against the session POST.
4. **Signature verification** (`verify_caip122`) is namespace-dispatched and is the cryptographic root.

The client's pre-sign identifier check (added in 0.1.x) prevents a hostile server from tricking a programmatic signer into producing a signature for a foreign account, even though the server-side check would already reject such a token.

## Related projects

- [`aqua-rs-sdk`](https://github.com/inblockio/aqua-rs-sdk): Aqua Protocol Rust SDK (revisions, signing, verification).
- [`siwx-oidc`](https://github.com/inblockio/siwx-oidc): CAIP-122 to OpenID Connect bridge. Layers a standard OIDC provider over the same three namespaces, so any OIDC relying party (Matrix, Keycloak, GitLab, etc.) can accept Aqua-keyed users.
- [`aqua-timestamp`](https://github.com/inblockio/aqua-timestamp): reference consumer of this crate. The deployed `timestamp.inblock.io` uses `aqua-auth` for its CAIP-122 server-side handshake.

When to reach for which:
- **`aqua-auth`** for service-to-service auth inside the Aqua ecosystem. No human in the loop. Opaque bearer tokens.
- **`siwx-oidc`** for federated end-user identity. Standard OIDC tokens. Browser or headless CLI client.

## Status

`0.2.0`. API stable enough to depend on; major version bump will signal a wire-format break (none planned).

## License

Apache-2.0. See [`LICENSE`](LICENSE).
