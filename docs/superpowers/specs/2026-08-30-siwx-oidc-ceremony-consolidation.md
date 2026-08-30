# Spec: consolidating siwx-oidc's WebAuthn ceremony onto aqua-auth

**Date:** 2026-08-30
**Status:** SPEC ONLY. Written, not executed, and deliberately so.
**Crate:** `aqua-auth` 0.6.0
**Subject repo:** `siwx-oidc` (`~/siwx-oidc`, `github.com/inblockio/siwx-oidc`)

This describes what a real consolidation of `siwx-oidc/src/webauthn.rs` onto
`aqua-auth`'s ceremony would require. It is not a task list to start on
Monday. It exists so that the next person who reads "siwx-oidc has a duplicate
WebAuthn implementation, delete it" understands why that sentence is wrong,
and what would actually have to be true first.

## 1. Why this is not a refactor

Two hard blockers, both verified on 2026-08-30, not inferred.

### 1.1 Incompatible credential storage, on live passkeys

siwx-oidc stores, per credential:

```
webauthn:credential/{b64url(cred_id)}  ->  raw webauthn-rs `Passkey` JSON
webauthn:link/{b64url(cred_id)}        ->  LinkEntry { primary_did, label }
```

There is no DID index and no sign-count tracking. `verify_credential`
deserializes the `Passkey` and derives the DID from its COSE key on every
authentication.

aqua-auth stores:

```
aqua:webauthn:cred:{b64url(cred_id)}  ->  StoredCredential JSON
                                          { did, credential_id, public_key,
                                            sign_count, transports, label,
                                            created_at }
aqua:webauthn:did:{did}               ->  Redis SET of credential ids
```

Different key namespace, different value schema, different derived fields.
Adopting aqua-auth's store therefore means **rewriting every live passkey
credential row**, not adding a compatibility shim.

That is the part that makes this dangerous rather than tedious. Passkeys are
hardware-bound. A user whose credential row is lost, mis-transcoded, or
written under a DID that does not match what the authenticator will assert
cannot recover by resetting a password, because there is no password. There is
no fallback in this system. A botched migration is permanent lockout.

### 1.2 A hard `webauthn-rs` version conflict

siwx-oidc depends on `webauthn-rs = "0.6.0-dev"` (locked at `0.6.0-dev`).
aqua-auth's `ceremony` feature depends on `webauthn-rs = "=0.6.1-dev"`, an
exact pin that exists so the serialized `Passkey` blob stays byte-compatible
across aqua-node, aquafier and this crate.

These do not co-resolve. Enabling `ceremony` on siwx-oidc's `aqua-auth`
dependency fails at resolution, before any code is compiled:

```
error: failed to select a version for `webauthn-rs`.
    ... required by package `aqua-auth v0.6.0`
versions that meet the requirements `=0.6.1-dev` are: 0.6.1-dev
all possible versions conflict with previously selected packages.
  previously selected package `webauthn-rs v0.6.0-dev`
    ... which satisfies dependency `webauthn-rs = "^0.6.0-dev"` of package `siwx-oidc v0.2.0`
```

The consequence is broader than it looks. `webauthn_rs::prelude::Passkey` from
0.6.0-dev and from 0.6.1-dev are **different types**. So every aqua-auth
ceremony helper whose signature mentions `Passkey`
(`p256_compressed_from_passkey`, `passkey_from_blob`, `register_finish`,
`login_finish`) is unusable from siwx-oidc, not merely inconvenient, until the
two repos agree on one `webauthn-rs` version. And agreeing on a version is
itself a decision about stored-blob compatibility, i.e. blocker 1.1 again,
approached from the other side.

### 1.3 Sync/async mismatch

siwx-oidc's `RedisClient` is async (`redis.get_raw(..).await`). aqua-auth's
`WebauthnCredentialBackend` and `RedisWebauthnStore` are sync and blocking.
aqua-node and aquafier both absorb this by calling the blocking store from
inside an async fn, which is defensible at authentication frequency but is a
choice siwx-oidc has not made and should not have forced on it silently.

## 2. What was actually duplicated, and what was not

The commonly quoted figure of "551 duplicate lines" in
`siwx-oidc/src/webauthn.rs` (876 lines total) is wrong. Measured:

| Segment | Approx lines | Reality |
|---|---|---|
| DID derivation from a P-256 key | ~10 | The only genuinely shareable code. `P256_MULTICODEC` plus `did_from_p256_compressed`: a multicodec prefix and a base58 encode. |
| `compressed_pubkey_from_passkey` / `did_from_passkey` | ~30 | Looks like a duplicate, is not shareable. Signatures mention `Passkey`, so blocker 1.2 applies. |
| HTTP request/response types | ~25 | Correctly local. |
| Registration / authentication ceremony | ~230 | Blocked by 1.1 and 1.2. |
| Account linking (`link_start`, `link_finish`, `LinkEntry`) | ~110 | **No aqua-auth equivalent exists.** Nothing to consolidate onto. |
| Config + `build_webauthn` | ~80 | Optional, low value. |

Note also that siwx-oidc already uses aqua-auth for the part that *is*
shareable today: `verify_credential` calls
`aqua_auth::verify_webauthn_assertion` with
`aqua_auth::WebAuthnAssertionParams`. The signature verification core is
already deduplicated. What remains is ceremony orchestration and storage,
which is exactly the part that is coupled to the stored data.

### 2.1 Why even the ~10 shareable lines were left alone

`aqua_auth::did_key_from_p256_compressed` sits behind the `ceremony` feature,
so using it from siwx-oidc runs straight into blocker 1.2. Making it reachable
would mean moving it out of `ceremony` in aqua-auth (it is pure, it needs no
`webauthn-rs`), and then siwx-oidc would have to move from aqua-auth 0.2.0 to
0.6.0 to see it.

That trade was rejected: a four-minor-version jump on a live OIDC bridge's
passkey path, to delete ten lines that have not drifted. If the multicodec
prefix ever *does* drift, revisit it; a wrong prefix yields a wrong DID and a
silent identity mismatch across services, which is the one reason this small
duplication is worth watching at all.

## 3. What a real consolidation needs

Three deliverables, in this order. Each is a prerequisite for the next.

### 3.1 A credential data migration plan

Not code: a plan, with a rollback. It must specify at minimum:

1. **A dual-read window.** siwx-oidc reads `aqua:webauthn:cred:{id}` first and
   falls back to `webauthn:credential/{id}`, so a partially migrated keyspace
   authenticates every user, both old and new. This must ship and bake
   *before* anything writes the new layout.
2. **A backfill that derives every new field from the old row**, with the
   derivation stated explicitly: `did` from the COSE key via the same
   multicodec path used at authentication time, `sign_count` seeded from 0 (or
   from the authenticator's next assertion, never from an invented value),
   `transports` and `label` from what is recorded or empty.
3. **A verification pass that re-derives the DID from every migrated row and
   compares it to the DID derived from the original row.** Any mismatch aborts
   the migration. This is the check that catches a wrong multicodec prefix or a
   y-coordinate parity bug before it locks anyone out.
4. **A rollback that is a no-op on the old keys.** The old rows are never
   deleted in the same operation that writes the new ones. Deletion is a
   separate, later, reversible step taken only after the dual-read window has
   run long enough to have seen the long tail of infrequent users.
5. **An explicit answer for credentials that fail to migrate**: an unparseable
   blob, a non-P-256 key, a row with no matching link entry. Silently dropping
   any of these is a lockout.

The sign-count question deserves its own paragraph in that plan. aqua-auth
tracks `sign_count` monotonically; siwx-oidc does not track it at all. Turning
on monotonic enforcement against credentials whose counters were never
observed can reject legitimate authenticators. aqua-node's model (a credential
blob plus a *separate* monotonic counter, never rewriting the blob) is the
precedent to follow.

### 3.2 An async credential-store trait in aqua-auth

`WebauthnCredentialBackend` is sync. Consolidating siwx-oidc onto it means
either blocking its async Redis client or adding an async twin.

The cheap version is an `async_trait` mirror of the existing trait, with the
sync implementations adapted through it, keeping `RedisWebauthnStore` as-is so
aqua-node and aquafier are untouched. Do not "just" make the existing trait
async: it would break both production consumers for the benefit of one that is
not yet migrated.

Prerequisite for this to be worth doing at all: 3.1 must have concluded that
siwx-oidc is moving to aqua-auth's storage layout. If it is not, an async
trait buys nothing.

### 3.3 An account-linking API

`link_start` / `link_finish` / `LinkEntry` map a passkey credential to a
*primary* DID, so a user can attach a passkey to an identity they already hold
rather than minting a new one from the passkey. aqua-auth has no equivalent
concept: its `StoredCredential.did` is the DID *derived from* the credential.

This is the genuinely new design work, and it is a protocol question before it
is an API question:

- Is a linked credential a second spelling of one principal, or a distinct
  principal that is *authorised to act for* the primary DID? The two-spellings
  ruling (#182) says aqua-auth does not fold distinct spellings into one
  principal, so the second reading is the one consistent with the rest of the
  crate.
- What proves the link at creation time? Today siwx-oidc's link ceremony runs
  inside an authenticated session for the primary DID. Any aqua-auth API needs
  that binding to be explicit in the type, not implicit in the caller's session
  handling.
- What revokes it, and what happens to sessions minted through the link when
  the link is revoked?

Until those are answered, siwx-oidc's linking code is not duplication. It is
the only implementation.

## 4. Recommended sequencing

1. **Pin siwx-oidc to a tag.** It is the only aqua-auth consumer with no pin;
   it is currently held at `056cb34` (0.2.0) by its `Cargo.lock` alone, so a
   bare `cargo update` moves it four minor versions with no review. Do this
   regardless of whether the rest of this spec ever happens. Verified
   2026-08-30: siwx-oidc's workspace does compile clean against aqua-auth
   0.6.0, so the pin can be set to a 0.6.0 tag rather than to 0.2.0.
2. **Decide the `webauthn-rs` version question** across siwx-oidc, aqua-node
   and aquafier together, as a stored-blob compatibility decision. Nothing in
   3.x is possible before this.
3. **Write and rehearse 3.1** against a copy of production keyspace data. The
   rehearsal is the deliverable, not the script.
4. Only then, 3.2 and 3.3.

## 5. What this spec deliberately does not authorise

- Rewriting, re-keying, or deleting any `webauthn:credential/*` row.
- Changing siwx-oidc's `webauthn-rs` version.
- Enabling aqua-auth's `ceremony` feature on siwx-oidc.
- Removing siwx-oidc's account-linking code.

None of these should happen as a side effect of a cleanup task. Each is a
decision with a user-lockout failure mode, and each needs an owner who is
prepared to be paged for it.
