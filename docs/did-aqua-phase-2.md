# did:aqua Phase 2: authorization

**Status:** not started. Phase 1 (authentication) landed in `aqua-auth` on
2026-09-11 and is feature-gated behind `did-aqua`.

**Who this is for:** whoever picks up post-quantum identity support next. You
do not need to have been in the Phase 1 session. Everything needed is below.

---

## The one-sentence problem

A `did:aqua` identity can now log in and be issued a session, and it will then
be refused at every authorization boundary, because both servers carry DID
dispatch that never consults `aqua-auth`'s method registry and that predates
this namespace existing.

Phase 1 was necessary and is not sufficient. **Do not deploy `did-aqua`
expecting a working agent identity until this is done.**

## Why this was split out

The Phase 1 ruling (2026-09-11) scoped the work to `aqua-auth` only, on the
grounds that the server changes touch two shared repos with their own release
trains. That was a sequencing decision, not a judgement that Phase 2 is
optional.

## What is broken, precisely

Verified against `aqua-node` `origin/main` at `905d501` and `aquafier-rs`
`origin/dev` at `af2d8257`, both fetched 2026-09-11.

### 1. The delegated-keys allowlist. Hard reject.

`aquafier-rs`, `crates/aquafier-delegated-keys/src/routes.rs:17`

```rust
// did:key must not be lowercased; did:pkh is fine. Accept only these methods.
if !(did.starts_with("did:key:") || did.starts_with("did:pkh:")) {
    return Err(AppError::BadRequest("did must be a did:key or did:pkh".into()));
}
```

A `did:aqua` delegate cannot be granted any role. `POST /delegate-keys/prepare`
returns 400 before anything else runs.

**Fix:** add `did:aqua:` to the accepted set. Prefer routing through
`aqua_auth::find_did_method(did).is_some()` over extending the string list, so
the next namespace does not need this edit again. Note the existing comment is
a live hazard in its own right: it is a reminder that `did:key` must not be
lowercased, which is the same class as the 2026-09-09 incident, and `did:aqua`
is likewise case-sensitive by construction (PCA-0017 section 2.3).

**Effort:** one line, plus a test.

### 2. The ceremony signature-type fallthrough. Silent misroute.

Two independent implementations, same defect:

- `aquafier-rs`, `crates/aquafier-core/src/signing.rs:147-154`
- `aqua-node`, `crates/aqua-node-api/src/ceremony_sig.rs:38-96`

```rust
pub fn ceremony_signature_type(signer_did: &str) -> &'static str {
    if let Ok((algo, _)) = did_key::decode(signer_did) { ... }
    if signer_did.starts_with("did:pkh:ed25519:") { "ed25519" }
    else if signer_did.starts_with("did:pkh:p256:") { "ecdsa:p256" }
    else { EIP191_SIGNATURE_TYPE }          // <- a did:aqua lands here
}
```

An unrecognised DID is labelled an Ethereum signer. A `did:aqua` grant or
delegation ceremony is therefore classified as `eip191` and fails somewhere
downstream with a message about secp256k1, which is not a useful signal.

**Fix:** add an `aqua` arm returning the ML-DSA-87 scheme token, and replace
the `else` with an explicit error for unknown methods. The silent fallthrough
should go regardless of this workstream: it converts "I do not know this
identity" into "this is an Ethereum key", and that is the shape of the
`#118 / B5 grant-misroute` bug class that `aquafier-arch-guard` already has a
suite for.

**Effort:** small per site, but there are two sites and they must agree. The
scheme token must match what the SDK's `signature_ml_dsa_87` built-in template
uses (PCA-0017 Appendix A); do not invent a spelling.

### 3. Ceremony verification needs the public key too

Wherever those ceremonies verify a signature, the same constraint from Phase 1
applies: ML-DSA has no public-key recovery and the DID is only a hash, so the
key has to reach the verifier. Phase 1's answer for login was an optional
`public_key` field on the session request (`SPEC.md` section 6.3), and the
ceremony wire shapes will need the equivalent.

Before designing it, read `SPEC.md` section 6.6: four transports were
evaluated and the reasoning transfers. In particular the binding check is what
makes any transport safe, so whatever carries the key, recompute
`aqua_auth::aqua_did_from_pubkey(pk)` and compare against the presented DID
before trusting it.

**Effort:** this is the real work in Phase 2. Treat 1 and 2 as prerequisites.

### 4. Adjacent, not blocking: the case-folding comparison

`aquafier-rs`, `crates/aquafier-core/src/did_helpers.rs:250`

```rust
did == mine || (did.starts_with("did:pkh:") && did.eq_ignore_ascii_case(&mine))
```

Scoped to `did:pkh:`, so `did:aqua` is not affected today. Flagged because it
is one `starts_with` away from becoming affected, and case folding a
`did:aqua` would admit two distinct identities as one. PCA-0017 section 2.3
forbids it, base58btc is case-sensitive by construction, and this is exactly
the failure that cost a day on 2026-09-09.

## What Phase 1 gives you to build on

In `aqua-auth`, behind the `did-aqua` feature:

| Item | Use |
|---|---|
| `aqua_did_from_pubkey(pk) -> String` | mint the identity from a key |
| `aqua_did_binds_pubkey(did, pk) -> Result<bool>` | **the binding check.** Call this before trusting any supplied key |
| `multihash_from_aqua_did(did)` | grammar validation on its own |
| `AquaMethod` | registered in `all_did_methods()` when the feature is on |
| `verify_caip122_with_public_key(did, msg, sig, Some(pk))` | the verification entry point |
| `authenticate_with_public_key(...) -> Principal` | the typed entry point |
| `aqua_auth_testkit::signers::did_aqua()` | a working ML-DSA-87 test signer |

The verification trait method is **synchronous on purpose**. If a ceremony
needs to source the key from a store rather than the wire, do the lookup in
the handler and pass the result in. Keeping resolution outside the trait is
what lets the transport change without touching the trait or any
implementation.

## Suggested order

1. Item 1, the allowlist. One line, unblocks manual testing.
2. Item 2, both fallthroughs. Do them together so the two servers agree.
3. Item 3, the ceremony key transport. Design against `SPEC.md` section 6.6.
4. Item 4, opportunistically, whenever `did_helpers.rs` is next touched.

## Checks already done, so you do not repeat them

- **Body limits are not a problem.** `aqua-node` `/auth/session` inherits
  axum's 2 MB default; `aquafier-rs` sets a 300 MB global at
  `crates/aquafier-server/src/main.rs:2388`. A 14.3 KB request clears both.
- **PCA-0017 is silent on authentication.** It defines `did:aqua` for the
  content proof surface. Nothing in it covers CAIP-122, sessions or grants, so
  there is no existing ruling to conform to on the ceremony wire shapes. Its
  section 2.3 does defer W3C method registration until the method is used on a
  surface that resolves DIDs, which is worth re-reading if anyone proposes
  resolution rather than co-located keys.
