# WebAuthn Readiness Assessment

**Date:** 2026-05-22
**Crate:** `aqua-auth` (repo `aqua-rs-auth`), version `0.2.0`, branch `main`, HEAD `056cb34`
**Assessed against:** `docs/REUSABILITY_HANDOFF.md` (dated 2026-05-20)
**Question:** Is `aqua-rs-auth` ready to provide WebAuthn / passkey support for `aquafier-rs`?

This document is an assessment only. It does not change code. It measures what shipped
in the `webauthn` feature against what `REUSABILITY_HANDOFF.md` Section 5 and Section 7
defined as the WebAuthn deliverable.

---

## 1. Verdict

**No — `aqua-rs-auth` is not ready to provide WebAuthn to `aquafier-rs` by the bar
set in `REUSABILITY_HANDOFF.md`.**

What shipped (commit `5d97c4a`, "feat: add WebAuthn assertion verification behind
`webauthn` feature") is a small, self-contained, well-tested **P-256 login-assertion
verifier**. It is genuinely reusable, but it is roughly the cryptographic core of a
single `login/finish` step — about **one of ~seven pieces** of a passkey integration.

The handoff's actual deliverable — a *consolidated ceremony module* that absorbs
`siwx-oidc/src/webauthn.rs`, wraps `webauthn-rs`, exposes registration / login /
account-link ceremonies behind a pluggable storage trait, and derives `did:key`
through shared helpers — is essentially not started. None of the three prerequisites
in handoff Section 5.7 landed.

---

## 2. What actually shipped

| Item | Detail |
|---|---|
| File | `src/webauthn.rs`, 402 lines, gated by `#[cfg(feature = "webauthn")]` (`lib.rs:72-75`) |
| Public API | `verify_webauthn_assertion(&WebAuthnAssertionParams) -> Result<bool, CryptoError>` (`webauthn.rs:37`) and the `WebAuthnAssertionParams<'a>` input struct (`webauthn.rs:14`) |
| Feature deps | `webauthn = ["dep:sha2", "dep:base64", "dep:serde_json"]` — **no `webauthn-rs`, no `http`, no `DashMap`** |
| Tests | 7 inline tests: valid, wrong origin, wrong rpId, wrong challenge, bad signature length, malformed clientDataJSON, tampered signature |

**What the function does:** given a credential public key, raw `authenticatorData`,
raw `clientDataJSON`, a 64-byte signature, and the relying party's expected
`challenge` / `origin` / `rpId`, it validates `rpIdHash`, the User Present flag,
`clientDataJSON.type == "webauthn.get"`, the challenge, the origin, and the P-256
ECDSA signature over `authenticatorData || SHA-256(clientDataJSON)`.

**What it is not:** it is stateless and login-only. It does not generate or store
challenges, does not handle registration or attestation, does not parse COSE keys,
does not derive `did:key`, and does not track the signature counter.

---

## 3. Scorecard against REUSABILITY_HANDOFF.md

| Handoff requirement | Section | Status |
|---|---|---|
| Widen verify API to `&[u8]` (binary message path, `0.3.0` breaking) | §5.7 Prereq 1 | ❌ `verify_caip122` is still `message: &str` (`lib.rs:80`). The verifier sidesteps this by being a standalone island, not wired into the CAIP-122 / `CipherSuite` dispatch. |
| Public `did:key` construction helpers | §5.7 Prereq 2 | ❌ No public helpers in `src/key/mod.rs`; the verifier never produces a `did:key`. |
| COSE key parsing — explicit scope boundary | §5.7 Prereq 3 | ⚠️ Implicitly punted to the consumer. The function wants a 33-byte compressed SEC1 P-256 key; WebAuthn delivers the credential key as a COSE_Key CBOR map. With `webauthn-rs` dropped, COSE→SEC1 conversion is now the caller's problem and is not provided. |
| Move `siwx-oidc/src/webauthn.rs` into the crate | §5.5, §7.6 | ❌ `siwx-oidc/src/webauthn.rs` is still present (~414 lines) and still owns the full ceremony. `siwx-oidc` does not depend on `aqua-auth`. |
| Pluggable `WebAuthnStore` storage trait | §5.5, §R3 | ❌ No storage trait. The `webauthn` feature does not even pull in `http` / `DashMap`. |
| Registration + account-link ceremonies | §5.2, §5.5 | ❌ Login-assertion verification only. No registration, no attestation, no challenge issuance, no account linking. |
| Passkey document-signing ceremony (revision hash as challenge) | §5.8 | ❌ Not present. |
| Amend `SPEC.md` WebAuthn non-goal | §5.6, §I20 | ❌ `SPEC.md:427` still lists "WebAuthn integration beyond what P-256 ECDSA natively supports" as a non-goal — the spec still contradicts the shipped code. |
| Publish to crates.io | §7.7, §R1 | ❌ Still `0.2.0`, unpublished. |
| Migrate consumers off duplicated code | §7.8, §R2 | ❌ `aquafier-rs` does not depend on `aqua-auth` at all; `siwx-oidc` still carries its own copy. |
| Add a `webauthn` Cargo feature + module | §7.6 | ✅ Done, in reduced scope. |

---

## 4. What `aquafier-rs` would still have to build itself

Even to use only the shipped verifier, `aquafier-rs` must first add `aqua-auth`
as a dependency with `features = ["webauthn"]` — it currently does not depend on the
crate at all. Beyond that, a working passkey integration still requires:

1. **Registration ceremony** — create-passkey flow plus attestation validation. The crate provides none of it.
2. **Challenge issuance + storage** — the verifier takes `expected_challenge` as a parameter; the caller must generate it and persist it across the start/finish request pair.
3. **Credential storage** — the public key, credential ID, and signature counter. No schema and no storage trait are provided.
4. **COSE_Key → SEC1 conversion** — WebAuthn hands the public key as COSE CBOR; the verifier requires a raw 33-byte SEC1 key.
5. **Counter / replay tracking** — see Section 5.
6. **HTTP routes + browser frontend** — out of crate scope (the handoff agrees), but still unbuilt.
7. **The Aqua-specific document-signing ceremony** — signing aqua-tree revisions with a passkey (handoff §5.8) — genuinely new, not present anywhere.

---

## 5. Notable gaps in the shipped verifier

These are not bugs in what the function claims to do, but limits a consumer must know:

- **No replay protection.** The function reads the flags byte (`authenticatorData[32]`) but never reads, returns, or checks the signature counter (`authenticatorData[33..37]`). Detecting a cloned authenticator (counter must strictly increase) is left entirely to the caller, and the counter is not even surfaced for the caller to use.
- **P-256 / ES256 only.** There is no Ed25519 / EdDSA assertion path. Most platform authenticators use ES256, so this covers the common case, but it is narrower than "passkeys" in general.
- **User Verified (UV) flag is not enforced.** Only User Present (UP, bit 0) is checked. A consumer that needs UV (biometric/PIN actually performed) must check bit 2 itself.
- **Standalone, not integrated.** Because it bypasses `verify_caip122` / `CipherSuite::verify`, a passkey credential cannot currently flow through the crate's normal DID-based verification dispatch.

---

## 6. Bottom line

The `webauthn` feature delivers a clean, dependency-light, well-tested **P-256
login-assertion verifier**. That is a real, reusable primitive — but it is the
verification half of `login/finish` only, and it is the part that was always the
most contained.

The handoff's plan (Section 7, steps 4–9: the breaking `0.3.0` API release, the
storage trait, the ceremony consolidation, publication, and consumer migration) is
not started. The full WebAuthn ceremony still lives only inside the `siwx-oidc`
binary.

For passkey authentication in `aquafier-rs`, the architectural decision is therefore
still open — the three paths recorded in the wider planning (delegate to `siwx-oidc`
as an OIDC provider / federate `siwx-oidc` into the deployment / reimplement) are not
collapsed by what shipped here. The shipped verifier would be a building block for
the "reimplement" path, not a substitute for that decision.
