# aqua-rs-auth: Reusability, WebAuthn, and Inconsistencies Handoff

> **SUPERSEDED, 2026-08-30.** Historical record, kept for its rationale; do not
> read it as a description of the crate today. Written on 2026-05-20 against
> `aqua-auth` 0.2.0, when WebAuthn did not exist in this crate at all. Since
> then the `webauthn`, `ceremony`, `redis`, `http-sig` and `client` features
> shipped, `client::authenticate` moved to the `Signer` trait, and the
> backend-unification branch merged (0.6.0). Its Section 5/7 WebAuthn
> deliverable is closed except for the account-linking API and the credential
> data migration, which are tracked in
> `docs/superpowers/specs/2026-08-30-siwx-oidc-ceremony-consolidation.md`.
> Current state: `CLAUDE.md`, `SPEC.md`, `CHANGELOG.md`, `CONSUMERS.md`.
> Moved here from `docs/REUSABILITY_HANDOFF.md`.

**Date:** 2026-05-20
**Crate:** `aqua-auth` (repo `aqua-rs-auth`), version `0.2.0`, branch `main`
**Audience:** the engineer who will pick up this work
**Purpose:** make `aqua-rs-auth` the crate that every Aqua repo depends on for DID based authentication. That means three things: correct multi-chain `did:pkh:eip155:<chain_id>` support, a single shared WebAuthn (passkey) implementation that today is trapped inside `siwx-oidc`, and a docs and code base that does not contradict itself.

This document is an assessment and a plan. It does not change code. It lists what exists, what is wrong, what is missing, and what to do, in priority order.

---

## 1. Context in one paragraph

`aqua-rs-auth` is a CAIP-122 ("Sign In With X") verifier library. It recently absorbed the `siwx-core` crypto crate (commit `e2486cc`, design and plan docs under `docs/superpowers/`). The absorption shipped and the tests pass, but the older project docs (`CLAUDE.md`, `SPEC.md`, parts of `README.md`) were not updated to match the new code. Beyond the docs, two capabilities are needed before the crate can be the shared auth foundation for Aqua. First, correct multi-chain `did:pkh:eip155` message construction. Second, and the main subject of this revision, WebAuthn. `siwx-oidc` already has a complete, working, deployed passkey implementation, but it is locked inside that one binary. The decision recorded here is to move WebAuthn into `aqua-rs-auth` so every Aqua repo can use one implementation instead of copying the file.

---

## 2. What is implemented today

The crate has two layers. The crypto and DID layer is always compiled. The session layer is behind a Cargo feature. WebAuthn does not exist in the crate yet.

### 2.1 Crypto and DID layer (always compiled, no feature needed)

| Area | What works | Source |
|---|---|---|
| `CipherSuite` trait and registry | `all_cipher_suites()`, `find_cipher_suite(ns)` | `src/cipher_suite.rs` |
| eip155 cipher suite | secp256k1, EIP-191 `personal_sign`, ecrecover, 65 byte signature | `src/pkh/eip155.rs` |
| ed25519 cipher suite | Ed25519 raw verify, 64 byte signature | `src/key/ed25519.rs` |
| p256 cipher suite | P-256 ECDSA (ES256), accepts DER and fixed 64 byte forms | `src/key/p256.rs` |
| `DIDMethod` trait and registry | `all_did_methods()`, `find_did_method(did)` | `src/did_method.rs` |
| `did:pkh` method | dispatches to the cipher suite registry by namespace | `src/pkh/method.rs` |
| `did:key` method | decodes `z6Mk...` (Ed25519) and `zDn...` (P-256), multicodec plus base58btc | `src/key/mod.rs` |
| `did:peer` method | variant 0 (`0z...`) and variant 2 (`2.` elements, picks the first `V` key) | `src/peer/mod.rs` |
| DID parsing helpers | namespace parse, address parse, ed25519 and p256 pubkey parse, EIP-55 checksum, `identifier_from_did`, `identifier_from_message`, `checksummed_address`, `address_from_verifying_key` | `src/did.rs` |
| Dispatch entry point | `verify_caip122(did, message, signature)` | `src/lib.rs` |
| Error type | `CryptoError` | `src/crypto_error.rs` |

### 2.2 Session layer (Cargo feature `http`)

| Item | What works | Source |
|---|---|---|
| `build_message` and `MessageParams` | CAIP-122 SIWE message construction | `src/message.rs` |
| `ChallengeStore` | in-memory `DashMap`, 5 minute TTL, single use nonce | `src/challenge.rs` |
| `SessionStore` | in-memory `DashMap`, 1 hour TTL, background tokio sweep | `src/session.rs` |
| Internal types | `Challenge`, `Session`, `SessionInfo`, `AuthenticatedDid` | `src/types.rs` |
| Wire types | `ChallengeEnvelope`, `SessionRequest`, `SessionResponse` | `src/wire.rs` |
| `AuthError` | wraps `CryptoError` via `#[from]` | `src/auth_error.rs` |

### 2.3 Client layer (Cargo feature `client`, implies `http`)

| Item | What works | Source |
|---|---|---|
| `authenticate()` | full challenge then sign then session flow, with a pre-sign identifier check | `src/client.rs` |
| `AuthClientError` | error type for the client flow | `src/client.rs` |

### 2.4 WebAuthn

Nothing. The crate has the P-256 and Ed25519 verification math and the `did:key` representation, which are the floor a passkey verifier stands on, but it has no WebAuthn ceremony, no credential storage, and no passkey routes. See Section 5.

### 2.5 Build and test status

- Absorption of `siwx-core` is complete and committed (`e2486cc`).
- 94 inline `#[test]` functions in `src/`.
- Cargo features: `default = []`, `http`, `client` (implies `http`). The crypto and DID layer is not behind any feature.

---

## 3. Inconsistencies

Each item lists what is wrong, where, how bad it is, and the fix. Severity is one of: low (cosmetic or doc only), medium (misleads a consumer), high (wrong behavior in code).

### I1. CLAUDE.md module layout is stale. Severity: medium.

`CLAUDE.md` "Module Layout" lists `error.rs`, `verify_eip191.rs`, `verify_ed25519.rs`, `verify_p256.rs`. None of those files exist. The real layout is in Section 8 below. Cause: `CLAUDE.md` was written before the absorption. Fix: rewrite the module layout section.

### I2. CLAUDE.md "Adding a New Signature Scheme" is obsolete. Severity: medium.

`CLAUDE.md` tells the reader to add a `verify_{scheme}.rs` file and "wire the namespace into `verify_caip122` in `lib.rs`". That is not how the code works now. The real extension model is: implement `CipherSuite` (one file) and add one line to `all_cipher_suites()` in `src/cipher_suite.rs`, or implement `DIDMethod` and add one line to `all_did_methods()` in `src/did_method.rs`. Fix: rewrite that section to describe the registry model.

### I3. CLAUDE.md and SPEC.md claim "three DID namespaces" only. Severity: medium.

The code supports three `did:pkh` namespaces (eip155, ed25519, p256) plus the `did:key` method (Ed25519 and P-256) plus the `did:peer` method (variants 0 and 2). `SPEC.md` calls itself "the authoritative specification" yet sections 1, 3, and 10 do not mention `did:key` or `did:peer` at all. Fix: add `did:key` and `did:peer` sections to `SPEC.md`, and update `CLAUDE.md`.

### I4. SPEC.md says the eip155 parser is locked to chain ID 1. Severity: medium, and it is factually wrong.

`SPEC.md` section 3 says "The chain ID segment is currently fixed to `1` by the parser. DIDs with other chain IDs are not accepted by `address_from_did()`." Section 9 repeats it as an open question. This is false. `address_from_did` in `src/did.rs` uses `rsplit(':')` and accepts any chain ID. The test `address_from_did_any_chain` (`src/did.rs:190`) proves chain 137 parses. The test `chain_id_eip155` (`src/pkh/method.rs:155`) proves chain 137 yields `eip155:137`. Fix: correct `SPEC.md` sections 3 and 9.

### I5. build_message hardcodes "Chain ID: 1". Severity: high. This is the real multi-chain bug.

`src/message.rs:59-61`:

```rust
if ns == "eip155" {
    msg.push_str("\nChain ID: 1");
}
```

The CAIP-122 message always claims chain 1, even for a `did:pkh:eip155:137:0x...` (Polygon) DID. So while parsing and verification handle any chain, the message that the user signs asserts the wrong chain. The absorption plan (`docs/superpowers/plans/2026-05-20-siwx-core-absorption.md`, Task 2 Step 2) carried this hardcode forward unchanged, so it is a known carried-over bug. Fix: see Section 4.

### I6. SPEC.md section 6.2 challenge response shape is stale. Severity: medium.

`SPEC.md` section 6.2 says the challenge response JSON is `{did, nonce, message, expires_at}`. The canonical wire type `wire::ChallengeEnvelope` (`src/wire.rs:24-28`) is `{nonce, message, expires_at}`, with `did` deliberately removed (the file comment explains why). `SPEC.md` section 9 still lists "should the server echo the DID" as an open question, but `wire.rs` already answered it. `README.md` matches `wire.rs`. So `SPEC.md` is behind both. Fix: update `SPEC.md` section 6.2 and drop that section 9 open question.

### I7. SPEC.md describes the old dispatch model. Severity: medium.

`SPEC.md` section 5 says `verify_caip122` "dispatches on the namespace parsed from the DID." The real `lib.rs` dispatches on the DID method (pkh, key, peer) via `find_did_method`, and `PkhMethod` then dispatches on namespace. `SPEC.md` section 10 still lists `verify_eip191.rs`, `verify_ed25519.rs`, `verify_p256.rs`, and `error.rs` as source files. None exist. Fix: rewrite `SPEC.md` sections 5 and 10.

### I8. README version mismatch. Severity: low.

`README.md` says "Status: Pre-release (`0.1.0`)." `Cargo.toml` says `version = "0.2.0"`. Fix: set the README to match.

### I9. README feature flags section is wrong. Severity: medium.

`README.md` "Feature flags" lists only the `client` feature and states that "`message`, `wire`, `verify_caip122`, `ChallengeStore`, `SessionStore` are unconditionally compiled." In reality `Cargo.toml` has an `http` feature, and `lib.rs` gates `message`, `wire`, `challenge` (`ChallengeStore`), `session` (`SessionStore`), `types`, and `auth_error` behind `#[cfg(feature = "http")]`. Only the crypto and DID layer is unconditional. Fix: add an `http` row and correct the "unconditionally compiled" list.

### I10. README server quick start omits the http feature. Severity: low.

The `README.md` "Server" example uses `ChallengeStore` and `SessionStore` without noting that they require `features = ["http"]`. Fix: add the note.

### I11. ed25519 and p256 cipher suites live under key/, not pkh/. Severity: medium.

`Ed25519Suite` and `P256Suite` are `CipherSuite` implementations for the `did:pkh:ed25519` and `did:pkh:p256` namespaces, but they ship at `src/key/ed25519.rs` and `src/key/p256.rs`. The `key/` module is for the `did:key` method, so a `did:pkh` cipher suite living there is confusing. Worse, both the design doc and the plan doc place these files under `src/pkh/`. The shipped code does not match its own design and plan. Fix: move the two files to `src/pkh/` and update `pkh/mod.rs`, or update both docs to say `key/`. Moving to `pkh/` is recommended.

### I12. The plan doc lib.rs does not match the shipped lib.rs. Severity: low (the plan is historical).

`docs/superpowers/plans/2026-05-20-siwx-core-absorption.md` Task 2 Step 6 shows `pub use pkh::{Ed25519Suite, Eip155Suite, P256Suite, PkhMethod};`. That would not compile against the shipped `pkh/mod.rs`, which exports only `Eip155Suite` and `PkhMethod`. The shipped `lib.rs:36-38` uses `pub use key::{Ed25519Suite, KeyMethod, P256Suite};`. The plan also omits the `wire` module. Fix: mark the plan as superseded, or update it.

### I13. Design doc public API table is incomplete. Severity: low.

The design doc API table lists `identifier_from_did` but not `identifier_from_message`, which is implemented (`src/did.rs:115`) and exported (`src/lib.rs:30-34`). Fix: add it, or note that the design doc is historical.

### I14. wire.rs and types.rs both define SessionRequest. Severity: low (dead code).

`types::SessionRequest` (`src/types.rs:25`) and `wire::SessionRequest` (`src/wire.rs:32`) are two distinct structs with identical fields. Only `wire::SessionRequest` is re-exported at the crate root and used (`client.rs`). `types::SessionRequest` is never used. Fix: delete `types::SessionRequest`.

### I15. CryptoError::VerificationFailed is never constructed. Severity: low (dead code, public API).

`src/crypto_error.rs:14-15` declares the variant. A grep finds zero uses outside the definition. Verifiers return `Ok(false)` or `Err(InvalidSignature(...))` instead. Because it is a public enum variant, removing it is a breaking change. Fix: remove it as part of a batched breaking release, or start using it.

### I16. CipherSuite::did_segments() is never called. Severity: low (dead code).

`src/cipher_suite.rs:20-21` declares `did_segments()`. All three suites implement it. A grep finds zero call sites. Fix: remove it from the trait, or wire it into DID length validation.

### I17. CLAUDE.md test count is stale. Severity: low.

`CLAUDE.md` says "cargo test # Run all 37 tests." The real inline count is 94. Fix: update the number, or drop the hard count.

### I18. CLAUDE.md GitNexus block counts are stale. Severity: low.

The `CLAUDE.md` GitNexus block says "243 symbols, 491 relationships, 21 execution flows." Those counts predate the absorption, which roughly doubled the code. Fix: re-run the indexer, or drop the numbers.

### I19. The crate is told to be depended on and not depended on at the same time. Severity: high for reusability.

`README.md` says "API stable enough to depend on." But the crate is not published anywhere, so every consumer uses a path dependency. `siwx-oidc/CLAUDE.md` explicitly says of `aqua-rs-auth`: "Reference cipher suites, port files, do not add as dependency." `aquafier-rs` does not depend on it at all and reimplements SIWE with `k256` directly. So the same crypto is written three times across the ecosystem. This is the central reusability problem. Fix: see Section 6.

### I20. SPEC.md forbids WebAuthn, which contradicts the decision in this document. Severity: high.

`SPEC.md` Section 9 lists WebAuthn as a non-goal (quoted exactly in Section 5.6 below). The decision recorded in Section 5 is to make `aqua-rs-auth` the home of WebAuthn. As long as the non-goal stands, the spec and the plan disagree. Fix: amend `SPEC.md` Section 9, see Section 5.6.

---

## 4. What is missing for multi-chain did:pkh:eip155

**State:** parsing and verification already handle any chain ID. The only gap is message construction.

**Required change:** `build_message` in `src/message.rs` must read the chain ID from the DID and emit the real value, instead of the hardcoded `Chain ID: 1` (see I5).

How to get the chain ID: the eip155 cipher suite already extracts it. `Eip155Suite::parse_did_parts` returns `Some("eip155:137")` for a chain 137 DID, and `PkhMethod::chain_id` exposes that. The cleanest path is a small helper, for example `chain_id_from_eip155_did(did) -> Result<u64, CryptoError>`, used inside `build_message`.

The chain ID must come from the DID, not from `MessageParams`. The DID is what the signature binds to, so the message must agree with it. Do not add a chain field to `MessageParams`.

**Tests to add:** a `build_message` test that a `did:pkh:eip155:137:0x...` DID produces `Chain ID: 137`. There is no such test today.

**Minor robustness note:** `address_from_did` tolerates a missing chain segment (`did:pkh:eip155:0x...`), but `Eip155Suite::parse_did_parts` requires it. The two disagree on what a valid eip155 DID is. Pick one rule and apply it in both places.

**Out of scope unless asked:** non-eip155 CAIP-2 namespaces such as `solana`. The crate's chain ID concept is eip155 only.

---

## 5. WebAuthn and passkeys: bring the implementation into aqua-rs-auth

This section is the core of the handoff. It explains what passkey sign-in is, what `aqua-rs-auth` must do, and why the existing `siwx-oidc` implementation should move here.

### 5.1 What passkey sign-in is

WebAuthn, branded as passkeys, lets a user sign in from a browser with a fingerprint, a face scan, or a device PIN, instead of a password or a crypto wallet. The private key is generated and held inside the device's secure hardware (the TPM on a laptop, the Secure Enclave on Apple devices, or a security key such as a YubiKey). The private key never leaves the hardware. The server only ever sees the public key and signatures.

The browser side is the built-in `navigator.credentials` API. There is no extra library to install on the frontend, only a few lines of base64url encoding glue. The server side needs a WebAuthn library, and in Rust that is `webauthn-rs`, maintained by the Kanidm project. It does the CBOR and COSE parsing, the attestation and assertion validation, and the ceremony state machine.

### 5.2 The two ceremonies

WebAuthn has two ceremonies. Each one is a pair of HTTP requests against the server, a start and a finish.

**Registration, which means create a passkey.**

1. The browser calls the server's `register/start`. The server generates a random challenge and returns it together with options: who the relying party is, which signature algorithms are accepted, and which credentials the user already has so they are not registered twice.
2. The browser calls `navigator.credentials.create(options)`. The operating system shows a native prompt, "Create a passkey for this site?" The user confirms with a fingerprint, face, or PIN.
3. The device generates a new key pair inside secure hardware and returns a credential ID, the public key, and a signed attestation.
4. The browser sends that to the server's `register/finish`. The server validates the attestation and stores the credential, which is the public key, the credential ID, and a signature counter, against that user.

**Authentication, which means sign in with a passkey.**

1. The browser calls the server's `login/start`. The server generates a random challenge and returns it. In the usernameless or discoverable flow, the server does not need to know who the user is yet.
2. The browser calls `navigator.credentials.get(options)`. The operating system shows a native prompt, "Sign in?" and the user confirms with a fingerprint, face, or PIN. The browser only offers passkeys that were registered for this exact site.
3. The device signs the challenge with the stored private key and returns the credential ID, an assertion, and the authenticator data.
4. The browser sends that to the server's `login/finish`. The server looks up the stored public key by credential ID, verifies the signature, checks that the counter has increased since last time, and creates a session.

### 5.3 What actually gets signed, and why it matters here

This is the detail that decides what `aqua-rs-auth` must change. During authentication the authenticator does not sign the challenge as plain text. It signs the binary concatenation:

```
authenticatorData || SHA-256(clientDataJSON)
```

The challenge sits inside `clientDataJSON`, base64url encoded, next to the type and the origin. `authenticatorData` is a binary structure: a 32 byte hash of the relying party ID, a one byte flags field, a four byte counter, and optional extension data. None of that is guaranteed to be valid UTF-8.

So a WebAuthn signature is a signature over arbitrary binary bytes, not over a text string. That single fact is why the crate cannot verify a passkey today, and it drives the first prerequisite in Section 5.7.

### 5.4 Current state across Aqua

| Repo | WebAuthn state |
|---|---|
| `siwx-oidc` | Complete and deployed. `src/webauthn.rs`, `webauthn-rs 0.6.0-dev`, Redis backed. Covers registration, discoverable authentication, and account linking. Each passkey becomes a `did:key:zDn...`. Login only, no document signing. |
| `aquafier-rs` | Nothing. SIWE only auth. No passkey routes, no credential table, no frontend. |
| `aqua-rs-auth` | Nothing for the ceremony. It has the P-256 and Ed25519 verification math and the `did:key` representation, which is the floor a verifier needs, but no WebAuthn protocol layer. |

### 5.5 The decision: consolidate WebAuthn into aqua-rs-auth

`siwx-oidc` already solved WebAuthn once, well, in a single file, `siwx-oidc/src/webauthn.rs`. The problem is that the solution is trapped inside the `siwx-oidc` binary. `aquafier-rs` cannot use it. A new Aqua service cannot use it. The only way to reuse it today is to copy the file, which is exactly the copy-and-paste pattern that this whole handoff is trying to end (see I19).

The decision is to make `aqua-rs-auth` the shared home for WebAuthn. Concretely:

- Move the ceremony logic from `siwx-oidc/src/webauthn.rs` into `aqua-rs-auth` as a feature-gated module, behind a new `webauthn` Cargo feature.
- The module wraps `webauthn-rs` and exposes the ceremony functions: register start, register finish, login start, login finish, and the account link start and finish.
- Abstract the storage behind a trait. A WebAuthn ceremony spans two HTTP requests, so the in-flight challenge state has to survive between start and finish, and credentials have to be stored for the long term. `siwx-oidc` uses Redis. `aquafier-rs` uses Postgres. So `aqua-rs-auth` must not hardcode a backend. It defines a storage trait, for example `WebAuthnStore` with save, load, and delete for challenge state, and save, load, and counter update for credentials. Each consumer implements that trait against its own database. This is the same pattern Section 6 (R3) recommends for the existing `ChallengeStore` and `SessionStore`.
- Use one `did:key` derivation. The crate must first gain the public `did:key` build helpers from Section 5.7. Then the WebAuthn module derives `did:key:z6Mk...` and `did:key:zDn...` through that one shared helper, instead of the duplicated multicodec constant that `siwx-oidc` currently carries.
- After the move, `siwx-oidc` deletes its own `src/webauthn.rs` and depends on `aqua-auth` with the `webauthn` feature, the same way the `siwx-core` absorption already deletes `siwx-core`.

The result is one implementation and many consumers. `aquafier-rs` gets passkey sign-in by depending on `aqua-auth` and implementing the storage trait against Postgres, instead of writing the ceremony from scratch.

A note on layering. `siwx-oidc/CLAUDE.md` argues that ceremony verification belongs in the server layer, not in the crypto library, because the ceremony needs session state. That concern is real, and the storage trait is the answer to it. The ceremony logic is library code, the same way `webauthn-rs` itself is library code. The state stays in the server, because the server implements the storage trait. So hosting the ceremony in `aqua-rs-auth` and keeping the state in the consumer are not in conflict.

### 5.6 The SPEC.md non-goal that blocks this, quoted exactly

`aqua-rs-auth` currently forbids WebAuthn in writing. The statement is in `SPEC.md`, Section 9 "Open Questions and Non-Goals", under the heading "Non-goals", in the list introduced by the sentence "This specification does not cover:". The exact line is:

> WebAuthn integration beyond what P-256 ECDSA natively supports.

This non-goal must be amended. As long as it stands, the spec says the crate is not allowed to host WebAuthn, which directly contradicts the decision in Section 5.5. The amendment should replace the flat "no" with the real boundary: the crate hosts the WebAuthn ceremony logic that wraps `webauthn-rs`, the `did:key` derivation, and the storage trait. The consumer implements the storage trait and owns the HTTP routes and the browser frontend.

Two related doc points:

- `aqua-rs-auth/CLAUDE.md` does not mention WebAuthn at all, neither as a goal nor a non-goal. So the project doc is silent while the spec forbids it. Once the `webauthn` module lands, `CLAUDE.md` must be updated to add the `webauthn` feature to the module layout, the feature list, and the build and test commands.
- `SPEC.md` Section 9 also lists "The internal storage backend for challenges and sessions" as a non-goal. The storage trait in Section 5.5 changes that too. The trait is not a backend, it is the seam that lets a consumer plug a backend in, so the non-goal should be reworded rather than deleted: the crate does not ship a backend, but it does ship the trait.

### 5.7 What the crate needs before the WebAuthn module can land

These are prerequisites. The WebAuthn module depends on them.

**Prerequisite 1: a binary message verify path.** Every verify function in the crate takes `message: &str`:

- `verify_caip122(did, message: &str, signature: &[u8])` in `lib.rs`
- `DIDMethod::verify(did, canonical_msg: &str, signature)` in `did_method.rs`
- `CipherSuite::verify(did, message: &str, signature)` in `cipher_suite.rs`
- `verify_with_key(key, message: &str, signature)` in `key/mod.rs`

As Section 5.3 explains, a WebAuthn signature is over binary bytes, not text. There is no way to feed `authenticatorData || SHA-256(clientDataJSON)` to a `&str` API. The fix is to widen the trait methods and `verify_caip122` to take `message: &[u8]`, and add a thin convenience wrapper that accepts `&str` and calls `.as_bytes()`. One code path, no duplication. This is a breaking change to the public traits, so batch it into a `0.3.0` release. The verification math is already correct for both curves: the `p256` crate applies SHA-256 internally, which matches WebAuthn ES256, and Ed25519 is pure EdDSA, which matches WebAuthn EdDSA. Only the API type is wrong.

**Prerequisite 2: public did:key construction helpers.** The `z6Mk...` and `zDn...` encoding, which is a multicodec prefix plus base58btc, exists only as `#[cfg(test)]` helpers in `src/key/mod.rs` (`ed25519_did`, `p256_did`), and `decode_multibase_key` is `pub(crate)`. The WebAuthn module needs to turn a passkey public key into a `did:key`. So the crate needs public helpers, for example `did_key_from_ed25519(pubkey: &[u8; 32]) -> String`, `did_key_from_p256_compressed(pubkey: &[u8; 33]) -> String`, and a public decode that returns the raw key bytes and the key type. This is also what removes the duplicated constant in `siwx-oidc/src/webauthn.rs:28-36`.

**Prerequisite 3, a scope decision: COSE key parsing.** WebAuthn hands the public key as a COSE_Key CBOR map. `webauthn-rs` already parses that for the consumer, so the recommendation is that `aqua-rs-auth` accepts raw key bytes and does not take a CBOR dependency. State this in `SPEC.md` as a deliberate boundary, not a vague non-goal.

### 5.8 The Aqua specific extra: passkey document signing

`siwx-oidc`'s WebAuthn does login only. `aquafier-rs` also wants to sign aqua-tree revisions with a passkey, where the challenge is the revision hash instead of a random nonce. The authenticator signs `authenticatorData || SHA-256(clientDataJSON)` either way, and the revision hash rides inside `clientDataJSON`, so the signature ends up bound to the exact revision. This is genuinely new work, it does not exist in `siwx-oidc`, and it belongs in the consolidated `webauthn` module so that every Aqua service gets it. It can be a later milestone after login works.

---

## 6. What is required to make aqua-rs-auth fully reusable

Reusability is not only a code property. It needs the crate to be consumable, the consumers to actually consume it, and the docs to be correct.

### R1. Publish to crates.io, or commit to a stable git tag dependency story.

The absorption design's stated goal was a crate ready for `cargo publish`. It is not published. Until it is, every consumer uses a path dependency and a sibling checkout, which the design doc itself called the original problem. Reconcile the version (README says 0.1.0, Cargo.toml says 0.2.0), then publish.

### R2. Migrate the consumers, and delete the duplicate code.

Today `aquafier-rs` reimplements SIWE with `k256` directly, `siwx-oidc` ported the cipher suite files and is told not to depend on the crate, and `aqua-node` uses it through a path dependency. "Fully reusable" means these move to a real `aqua-auth = "0.x"` dependency. As part of this, `siwx-core` is deleted (the absorption design already specifies that), and `siwx-oidc/src/webauthn.rs` is deleted once the `webauthn` module lands (Section 5.5).

### R3. Make the http layer storage pluggable.

`ChallengeStore` and `SessionStore` are in-memory `DashMap` only. Different Aqua repos use different backends. The `http` layer, and the new `webauthn` module, both need a storage trait so each consumer plugs in its own backend. This is on the `CLAUDE.md` roadmap already, and Section 5.5 depends on it.

### R4. Widen the verify API to bytes.

The `&str` only verify API blocks any consumer that verifies a non-text payload: WebAuthn, SSH proofs, a raw revision hash. This is prerequisite 1 in Section 5.7 and it is also a general reusability item.

### R5. Add CI across the feature matrix.

There is no CI. With the feature combinations `--no-default-features`, `--features http`, `--features client`, and soon `--features webauthn`, plus `clippy` and `fmt`, a reusable crate needs a workflow that keeps every combination green.

### R6. Ship cross-language test vectors.

`SPEC.md` section 10 mentions a "cross-language test vector file (planned, not yet shipped)." Needed only if non-Rust Aqua services must interoperate. Lower priority if everything is Rust.

### R7. Fix the docs.

`CLAUDE.md` and `SPEC.md` are stale (Section 3). A consumer onboarding from these docs gets wrong file names, wrong instructions, a wrong namespace list, a wrong chain ID claim, and a non-goal that the project has decided to reverse. Correct docs are part of "reusable."

---

## 7. Suggested order of work

This is a recommendation. Small safe wins land first, breaking changes are batched.

1. **Docs correction pass.** Fix I1, I2, I3, I4, I6, I7, I8, I9, I10, I17, I18. No code risk, unblocks onboarding. Mark the absorption design and plan docs as historical (I12, I13).
2. **Multi-chain fix.** Section 4. Small and contained: a chain ID helper, a change in `build_message`, one new test. Ship as `0.2.1`.
3. **Structural cleanup.** Move `ed25519.rs` and `p256.rs` from `key/` to `pkh/` (I11). Delete `types::SessionRequest` (I14).
4. **Breaking release 0.3.0.** Batch the breaking changes: widen the verify API to `&[u8]` (Section 5.7 prerequisite 1), add public `did:key` helpers (prerequisite 2), remove the dead `CryptoError::VerificationFailed` (I15) and `CipherSuite::did_segments()` (I16). Amend `SPEC.md` Section 9 (I20, Section 5.6).
5. **Storage trait.** R3. A challenge and credential storage trait, used by both the `http` layer and the upcoming `webauthn` module.
6. **WebAuthn module.** Section 5. Add the `webauthn` feature. Move `siwx-oidc/src/webauthn.rs` in, rewrite its Redis calls against the storage trait from step 5, derive `did:key` through the step 4 helpers. Update `CLAUDE.md` and `SPEC.md`.
7. **Publish and CI.** R1 and R5.
8. **Migrate consumers.** R2. `aquafier-rs` and `siwx-oidc` move to the published crate. `siwx-core` is deleted. `siwx-oidc/src/webauthn.rs` is deleted.
9. **Passkey document signing.** Section 5.8. The Aqua specific ceremony for signing aqua-tree revisions. Later milestone.

The aquafier-rs side of WebAuthn, which is the HTTP routes, the Postgres storage trait implementation, and the browser frontend, is a separate project. It depends on steps 4, 5, and 6 here being done. Plan it on its own once `aqua-rs-auth` ships the `webauthn` feature.

---

## 8. Reference: actual source layout

```
src/
  lib.rs              verify_caip122 dispatch, module wiring, re-exports
  crypto_error.rs     CryptoError
  cipher_suite.rs     CipherSuite trait, all_cipher_suites, find_cipher_suite
  did_method.rs       DIDMethod trait, all_did_methods, find_did_method
  did.rs              DID parsing, EIP-55, identifier_from_did, identifier_from_message
  pkh/
    mod.rs            re-exports Eip155Suite, PkhMethod
    method.rs         PkhMethod (DIDMethod for did:pkh)
    eip155.rs         Eip155Suite (CipherSuite, secp256k1 EIP-191)
  key/
    mod.rs            KeyMethod (DIDMethod for did:key), shared multibase decode
    ed25519.rs        Ed25519Suite (CipherSuite for did:pkh:ed25519)
    p256.rs           P256Suite (CipherSuite for did:pkh:p256)
  peer/
    mod.rs            PeerMethod (DIDMethod for did:peer, variants 0 and 2)
  --- behind feature "http" ---
  auth_error.rs       AuthError, wraps CryptoError
  message.rs          build_message, MessageParams
  challenge.rs        ChallengeStore
  session.rs          SessionStore
  types.rs            Challenge, Session, SessionInfo, AuthenticatedDid
  wire.rs             ChallengeEnvelope, SessionRequest, SessionResponse
  --- behind feature "client" ---
  client.rs           authenticate, AuthClientError
  --- planned, behind feature "webauthn" (Section 5) ---
  webauthn/           ceremony wrapping webauthn-rs, plus a storage trait
```

Note that `key/ed25519.rs` and `key/p256.rs` are `did:pkh` cipher suites despite living under `key/`. See I11.

## 9. Reference: key code locations

| Topic | Location |
|---|---|
| The `Chain ID: 1` hardcode (I5) | `src/message.rs:59-61` |
| Multi-chain address parse that already works | `src/did.rs:17-38` |
| Proof that multi-chain parsing works | `src/did.rs:190`, `src/pkh/method.rs:155` |
| Text-only verify API (WebAuthn blocker) | `src/lib.rs:74`, `src/did_method.rs:45`, `src/cipher_suite.rs:27`, `src/key/mod.rs:42` |
| did:key encoding, test-only and pub(crate) | `src/key/mod.rs:25` (decode), `src/key/mod.rs:140-151` (test helpers) |
| The SPEC.md WebAuthn non-goal to amend (I20) | `SPEC.md` Section 9, "Non-goals" |
| siwx-oidc WebAuthn implementation to move here | `siwx-oidc/src/webauthn.rs` (whole file, 415 lines) |
| siwx-oidc reimplementing the did:key encoding | `siwx-oidc/src/webauthn.rs:28-36` |
| Dead `VerificationFailed` variant | `src/crypto_error.rs:14-15` |
| Dead `did_segments` method | `src/cipher_suite.rs:20-21` |
| Duplicate `SessionRequest` | `src/types.rs:25` and `src/wire.rs:32` |
