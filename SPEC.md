# Aqua CAIP-122 Extension Specification

**Version:** 1.0 (2026-05-17)
**Status:** Draft
**Reference implementation:** this crate (`aqua-rs-auth`)

---

## 1. Purpose and Scope

This document is the authoritative specification for the Aqua extension of
CAIP-122 ("Sign In With X", SIWx). It describes:

- The three DID namespaces supported by the Aqua ecosystem (`eip155`,
  `ed25519`, `p256`), two of which are non-blockchain extensions beyond
  the CAIP-122 standard.
- The exact canonical message format for each namespace.
- The signature schemes and byte-level encoding for each namespace.
- The JSON wire envelope for the HTTP challenge-response flow (which CAIP-122
  leaves implementation-defined).
- Verification rules that any compliant implementation must enforce.

The Rust reference implementation is the `aqua-auth` crate in this
repository. Compatible implementations in other languages must produce
and accept the wire shapes defined here.

---

## 2. CAIP-122 Baseline

[CAIP-122](https://chainagnostic.org/CAIPs/caip-122) generalizes
[EIP-4361](https://eips.ethereum.org/EIPS/eip-4361) (Sign-In with Ethereum,
SIWE) to arbitrary blockchain namespaces. It specifies:

- A structured plaintext message format derived from SIWE, with fields for
  domain, account identifier, statement, URI, version, nonce, and timestamps.
- Namespace-dispatched signature verification: the `Chain ID` field and
  signature algorithm are determined by the CAIP-2 namespace of the account.
- That the message must be signed over its canonical string representation.

CAIP-122 explicitly leaves open: the HTTP wire format for challenge delivery
and session token issuance, session token type and lifetime, and how nonces
are generated and stored. The Aqua extension specifies all of these.

---

## 3. Supported DID Namespaces

EVM identities use the `did:pkh` method. ed25519/P-256 identities are accepted in
**both** their `did:key` form (W3C standard) **and** their `did:pkh:{ed25519,p256}`
form. The namespace/curve determines which signature algorithm applies.

| Namespace | Accepted login DID shapes | Identifier in message | Signature scheme | Status |
|---|---|---|---|---|
| `eip155` | `did:pkh:eip155:<chain_id>:0x<eip55_address>` | EIP-55 checksummed 20-byte address | EIP-191 `personal_sign` over canonical message string | CAIP-122 compliant |
| `ed25519` | `did:key:z6Mk<multibase>` or `did:pkh:ed25519:0x<32-byte pubkey hex>` | multibase key (`did:key`) or raw 32-byte pubkey hex (`did:pkh`) | Ed25519 over raw message bytes (no prefix) | Aqua extension |
| `p256` | `did:key:zDn<multibase>` or `did:pkh:p256:0x<33-byte compressed pubkey hex>` | multibase key (`did:key`) or compressed 33-byte pubkey hex (`did:pkh`) | P-256 ECDSA over raw message bytes (no prefix) | Aqua extension |
| `aqua` | `did:aqua:z<46 base58btc chars>` | the `z...` multibase body | ML-DSA-87 (FIPS 204) over raw message bytes | Aqua extension, **feature-gated** (`did-aqua`), **key supplied separately** |

> **`did:aqua` is the first namespace that hashes a non-recoverable key.** Every
> other namespace lets the verifier obtain the public key from something it
> already has: `did:key`, `did:pkh:{ed25519,p256}` and `did:peer` **embed** the
> key in the DID and decode it out, while `did:pkh:eip155` **hashes** it and
> recovers the key from the signature, which only works because secp256k1 ECDSA
> is recoverable. ML-DSA is Fiat-Shamir with Aborts over module lattices: the
> public key is an input to the verification relation, not an output of it, so
> there is no recovery and none is possible. `did:aqua` therefore commits to a
> key the verifier cannot reconstruct, and the key must travel separately
> (section 6.3). The reason to hash at all is size: an ML-DSA-87 public key is
> 2592 bytes, and embedding it `did:key`-style yields a ~3552-character DID
> (PCA-0017 section 1.4), against 56 characters content-addressed.

> **Two spellings, two principals (#182).** For ed25519/P-256, the `did:key` and
> `did:pkh` forms of one key are **both accepted** and are **distinct principals**;
> `canonical_trust_key` keys them into separate grant buckets. Switching login spelling
> returns a different resource set by design. A "my files disappeared" report after a
> login-method change is this behaviour (a different principal), not a defect; do not
> re-open #182.

**`eip155` DID parsing** (see `src/did.rs`):

- Expected exact form: `did:pkh:eip155:1:0x{40 hex chars}`.
- The chain ID segment is currently fixed to `1` by the parser. DIDs with
  other chain IDs are not accepted by `address_from_did()`.
- The address embedded in the DID is the EIP-55 checksummed form of the
  20-byte Ethereum address.

**`ed25519` DID parsing:**

- Expected form: `did:pkh:ed25519:0x{64 hex chars}` (32 bytes).

**`p256` DID parsing:**

- Expected form: `did:pkh:p256:0x{66 hex chars}` (33 bytes, compressed point
  with `02` or `03` prefix byte).

---

## 4. Message Format

The canonical message is constructed by `build_message()` in `src/message.rs`.
It follows the SIWE plaintext structure with three namespace-specific
differences described below.

### 4.1 Format Template

```
{domain} wants you to sign in with your {method_label} account:
{identifier}

Sign in to Aqua Node

URI: {uri}
Version: 1
Nonce: {nonce}
Issued At: {issued_at}
Expiration Time: {expiration_time}
```

For `eip155` only, one additional line is appended:

```
Chain ID: 1
```

### 4.2 Field Definitions

| Field | Value |
|---|---|
| `{domain}` | Caller-supplied domain string (e.g. `aqua-node`, `timestamp.inblock.io`) |
| `{method_label}` | `Ethereum` for `eip155`, `Ed25519` for `ed25519`, `P-256` for `p256`, `ML-DSA-87` for `aqua` |
| `{identifier}` | See namespace table in section 3 |
| `{uri}` | Caller-supplied URI (e.g. `http://127.0.0.1:3000`) |
| `{nonce}` | `0x` followed by 64 lowercase hex characters (32 random bytes) |
| `{issued_at}` | UTC timestamp formatted as `%Y-%m-%dT%H:%M:%S%.3fZ` (millisecond precision, zero-padded) |
| `{expiration_time}` | Same format as `{issued_at}` |

Datetime format example: `2026-05-17T12:00:00.000Z`.

### 4.3 Key Divergence from Baseline CAIP-122

**For `ed25519` and `p256`, the `Chain ID:` line is omitted.** These
namespaces have no chain context. Appending a fictional chain ID would be
misleading and create unnecessary coupling. This is the primary structural
deviation from baseline CAIP-122 and is intentional.

**The `Statement` field is fixed.** All messages contain `Sign in to Aqua Node`
as the statement. There is no mechanism to override this per-request. This
is a current implementation constraint, not a protocol requirement.

### 4.4 Concrete Examples

**`eip155` message:**

```
aqua-node wants you to sign in with your Ethereum account:
0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B

Sign in to Aqua Node

URI: http://127.0.0.1:3000
Version: 1
Nonce: 0x3f2a1b9c4e7d08a56b1c3e2f4d5a6078b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f
Issued At: 2026-05-17T12:00:00.000Z
Expiration Time: 2026-05-17T12:05:00.000Z
Chain ID: 1
```

**`ed25519` message (no `Chain ID` line):**

```
aqua-node wants you to sign in with your Ed25519 account:
0xaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd

Sign in to Aqua Node

URI: http://127.0.0.1:3000
Version: 1
Nonce: 0x3f2a1b9c4e7d08a56b1c3e2f4d5a6078b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f
Issued At: 2026-05-17T12:00:00.000Z
Expiration Time: 2026-05-17T12:05:00.000Z
```

**`p256` message (no `Chain ID` line):**

```
aqua-node wants you to sign in with your P-256 account:
0x02aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd

Sign in to Aqua Node

URI: http://127.0.0.1:3000
Version: 1
Nonce: 0x3f2a1b9c4e7d08a56b1c3e2f4d5a6078b9c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f
Issued At: 2026-05-17T12:00:00.000Z
Expiration Time: 2026-05-17T12:05:00.000Z
```

---

## 5. Signature Dispatch

Entry point: `verify_caip122(did, message, signature)` in `src/lib.rs`.
Dispatches on the namespace parsed from the DID. Signature bytes passed to
the verifier must be raw bytes (not hex-encoded).

For `did:aqua` the entry point is instead
`verify_caip122_with_public_key(did, message, signature, public_key)`, because
three arguments are not enough to verify that namespace (section 5.4).
`public_key` is ignored for every namespace below except 5.4, so a server that
accepts post-quantum identities MAY route every login through the four-argument
form. `verify_caip122` returns an error rather than a false for a `did:aqua`,
so a deployment that forgets to plumb the key through fails diagnosably.

### 5.1 `eip155` (EIP-191 `personal_sign`)

**Source:** `src/verify_eip191.rs`

**Signer:**

1. Compute the EIP-191 prefixed hash:
   `keccak256("\x19Ethereum Signed Message:\n{len}" || message_bytes)`
   where `{len}` is the byte length of the message string as a decimal integer.
2. Sign the 32-byte prehash with secp256k1 to produce a recoverable signature.
3. Encode as 65 bytes: `r (32) || s (32) || v (1)` where `v` is the recovery
   id plus 27, so `v ∈ {27, 28}`.

**Verifier:**

1. Recompute the EIP-191 prehash.
2. Extract `v` from byte 64; subtract 27 to get the recovery id (must be 0 or 1).
3. Recover the secp256k1 verifying key from `(prehash, r||s, recovery_id)`.
4. Derive the Ethereum address: `keccak256(uncompressed_pubkey[1..])[12..]`.
5. Compare the derived address with the address in the DID (case-insensitively
   via EIP-55 checksum normalization).

**Signature length:** exactly 65 bytes. Any other length is an error.

### 5.2 `ed25519`

**Source:** `src/verify_ed25519.rs`

**Signer:**

1. Sign the raw message bytes directly using Ed25519 (RFC 8032).
2. No prefix, no hashing step beyond what Ed25519 internally applies.

**Verifier:**

1. Extract the 32-byte public key from the DID.
2. Verify the signature over `message.as_bytes()` using the Ed25519 verifying
   key.

**Signature length:** exactly 64 bytes.

### 5.3 `p256`

**Source:** `src/verify_p256.rs`

**Signer:**

1. Sign the raw message bytes directly using P-256 ECDSA (NIST FIPS 186-4).
2. No prefix, no pre-hashing step beyond what P-256 ECDSA internally applies.
3. Signature may be encoded as either 64-byte fixed-size (`r || s`) or
   DER-encoded. Both are accepted by the verifier.

**Verifier:**

1. Extract the 33-byte compressed public key from the DID.
2. Decompress into a P-256 verifying key.
3. Parse the signature: attempt DER decoding first; if that fails, attempt
   fixed-size 64-byte `r || s` decoding.
4. Verify the signature over `message.as_bytes()`.

**Signature length:** 64 bytes (fixed) or variable (DER). The verifier accepts
both; signers should prefer fixed-size for interoperability.

### 5.4 `aqua` (ML-DSA-87, FIPS 204)

**Source:** `src/aqua/`. Gated behind the `did-aqua` feature.

**Signer:**

1. Sign the raw message bytes with ML-DSA-87 over the external interface with
   the empty context string, `ML-DSA.Sign(sk, M, ctx = "")`.
2. No prefix and no pre-hashing beyond what FIPS 204 applies internally.
3. Send the 2592-byte `pkEncode` public key alongside (section 6.3). The
   verifier cannot derive it.

**Verifier:**

1. **Bind first.** Recompute `did:aqua:` + `z` +
   `base58btc(0x16 || 0x20 || SHA3-256(varint(0x1212) || pk))` from the
   supplied key and compare byte-for-byte against the presented DID. A
   mismatch is a failed authentication, not a malformed request. Verifying
   before binding would prove possession of some key, which says nothing
   about the identity being claimed.
2. Length-check the key (2592) and the signature (4627).
3. Run the canonical hint-encoding gate (FIPS 204 Algorithm 21
   `HintBitUnpack`) over the trailing 83 hint bytes. Failures here are the
   **malformed** class.
4. Run `ML-DSA.Verify(pk, M, sig, ctx = "")`. A false here, including the `z`
   infinity-norm bound, is the **invalid** class.

The malformed/invalid split follows PCA-0017 section 2.5 and exists so that
monolithic and split implementations classify identically. It matters because
RustCrypto's `ml-dsa` folds the `z` bound into its decode step; implementations
MUST NOT use decode alone as the malformed gate.

**Signature length:** 4627 bytes, fixed. **Public key length:** 2592 bytes,
fixed. **Identity length:** 56 characters, fixed.

**Equality:** byte-for-byte and case-sensitive over the full DID string
(PCA-0017 section 2.3). base58btc is case-sensitive by construction, so any
case folding admits two distinct identities as one. No case folding, Unicode
normalization, percent-decoding or whitespace trimming, anywhere a `did:aqua`
is consumed.

---

## 6. Wire Format (JSON Envelope)

CAIP-122 does not specify the HTTP transport layer. This section defines the
canonical JSON shapes for the Aqua ecosystem. All Aqua services that speak
this protocol MUST use these shapes.

### 6.1 Challenge Request

```
GET /auth/challenge?did=<url-encoded-did>
```

The DID is URL-encoded in the query string (colons replaced with `%3A` by the
reference client in `src/client.rs`).

### 6.2 Challenge Response

```json
{
  "did": "<string>",
  "nonce": "<string>",
  "message": "<string>",
  "expires_at": <u64>
}
```

| Field | Type | Description |
|---|---|---|
| `did` | string | The DID that was passed in the query parameter |
| `nonce` | string | The random nonce (`0x` + 64 lowercase hex chars) |
| `message` | string | The full canonical CAIP-122 message to sign |
| `expires_at` | u64 | Unix timestamp (seconds) when the challenge expires (5-minute TTL by default) |

**Implementation note:** `did` is redundant with the message body, which
already encodes the identifier, and that redundancy is a mismatch surface: a
server can return an envelope naming one DID wrapped around a message naming
another.

Resolved 2026-09-11: the field **stays**, and the defence is the client check
below rather than removal. Every Aqua server emits it, and until this date
`wire::ChallengeEnvelope` omitted it, so the reference type and this section
disagreed and interop held only because serde ignores unknown fields. The type
now matches this table field for field.

Clients MUST verify that the identifier in `message` matches the DID they
requested, before signing. The reference client does this in
`client::signed_session_request`, alongside a second check this document does
not yet specify: the `URI:` line's origin must match the origin the client
dialled, which is what refuses a challenge relayed from another Aqua service.
Both run before the signer is invoked. A client that signs first and validates
afterwards has already produced a credential for whoever minted the challenge,
so the ordering is the defence and not the checks alone.

### 6.3 Session Request

```
POST /auth/session
Content-Type: application/json
```

```json
{
  "did": "<string>",
  "nonce": "<string>",
  "signature": "<string>",
  "public_key": "<string, optional>"
}
```

| Field | Type | Description |
|---|---|---|
| `did` | string | The DID that signed the challenge |
| `nonce` | string | The nonce from the challenge response |
| `signature` | string | Hex-encoded signature bytes, with or without `0x` prefix |
| `public_key` | string, optional | Hex-encoded raw public key, for namespaces whose verifier can obtain it neither from the DID nor from the signature. Present for `aqua` only |

The `signature` field carries the raw signature bytes hex-encoded. The server
strips an optional `0x` prefix before decoding. Clients MUST supply the full
signature bytes: 65 bytes for `eip155`, 64 bytes for `ed25519`, 64 bytes
(fixed) or DER-variable for `p256`, 4627 bytes for `aqua`.

**`public_key`** is a non-breaking addition under section 8's rule for new
optional fields. Clients MUST omit it entirely for every namespace but `aqua`,
where it carries the 2592-byte ML-DSA-87 `pkEncode` key (5184 hex characters,
5186 with the `0x` prefix). Servers that do not implement `aqua` MUST ignore
it, which section 8 already requires of any unknown field.

Servers MUST bind `public_key` to `did` before trusting it (section 5.4, step
1). A key that is accepted without being bound authenticates possession of
some identity rather than of the one presented, which is the whole attack this
field would otherwise open.

A session request carrying a `did:aqua` is about 14.3 KB. Deployments MUST NOT
set a body limit below that on `POST /auth/session`.

### 6.4 Session Response

```json
{
  "did": "<string>",
  "token": "<string>",
  "valid_until": <u64>,
  "created_at": <u64>
}
```

| Field | Type | Description |
|---|---|---|
| `did` | string | The authenticated DID |
| `token` | string | Opaque bearer token (64 lowercase hex chars, 32 random bytes) |
| `valid_until` | u64 | Unix timestamp (seconds) when the session expires (1-hour TTL by default) |
| `created_at` | u64 | Unix timestamp (seconds) when the session was created |

### 6.5 Bearer Token Usage

Clients attach the session token to subsequent requests:

```
Authorization: Bearer <token>
```

The token is opaque; clients must not parse or decode it. Sessions are
validated by the server against an in-memory `SessionStore`. Sessions do not
survive server restarts.

### 6.6 Key transport for `aqua`, and the alternatives not taken

Four transports were evaluated for getting the ML-DSA-87 public key to the
verifier (2026-09-11). The one specified above is **A**.

| | Wire, steady state | New state | First contact | Chosen |
|---|---|---|---|---|
| **A** key on the session request | 14.3 KB per login | none | works | **yes** |
| **B** key at challenge time | n/a | none | n/a | no |
| **C** register once, look up thereafter | ~200 B | key store + registration endpoint | fails until registered | no |
| **D** DID document resolution | ~200 B + resolver fetch | resolver service + W3C method registration | works | no |

**B is not implementable.** `GET /auth/challenge` carries its parameters in
the query string, and a 5184-character hex key exceeds the 4-8 KB header
buffer common to deployed proxies. It would also mean holding unauthenticated
caller-supplied key material across the round trip for no benefit.

**C and D were rejected on cost, not on security.** All four transports are
equally trustless: because the DID is a hash of the key, the binding check in
section 5.4 step 1 neutralises a lying client, a squatting registrant and a
malicious resolver alike. What separates them is operational weight. C buys a
14 KB saving and pays a key store, a registration endpoint, a first-contact
retry path, and a lockout mode if that store is cleared. D additionally puts
network I/O in the login path and requires the W3C method registration that
PCA-0017 section 2.3 explicitly defers "before the method is used on any
surface that resolves DIDs". At a one-hour session TTL, A costs a client
roughly 343 KB per day.

**C remains the documented future optimisation.** If login volume ever makes
14.3 KB per session matter, a key store is the answer, and adopting it is a
pure addition: `public_key` is already optional, and a stored key and a wire
key are validated by the same binding check. No trust model changes and no
existing client breaks.

---

## 7. Verification Rules

A compliant verifier MUST enforce all of the following checks when processing
a `POST /auth/session` request:

1. **Nonce exists:** the nonce was issued by this server's `ChallengeStore`
   and has not been consumed.
2. **Nonce not expired:** the current time is strictly before `expires_at`.
3. **Nonce consumed:** the challenge is removed from the store immediately
   upon validation (single-use). A second request with the same nonce MUST
   be rejected.
4. **Namespace supported:** the DID namespace is one of `eip155`, `ed25519`,
   `p256`. Any other namespace MUST return an error.
5. **DID well-formed:** the DID passes namespace-specific format checks (correct
   prefix, correct byte-length for the identifier).
6. **Signature valid:** the signature verifies against the DID's identifier
   under the namespace-appropriate algorithm (section 5).
7. **Message matches:** the canonical message in the challenge matches the
   message that was signed. (Enforced implicitly: the server signs the message
   it built and verifies against the same message.)

The reference implementation enforces rules 1-3 in `src/challenge.rs` and
rules 4-6 in `src/lib.rs` via `verify_caip122()`. Rule 7 holds by construction
because the client is given the exact message to sign in the challenge response
and the server verifies against the stored copy.

---

## 8. Versioning and Compatibility

The wire format defined in section 6 is the canonical contract between clients
and servers.

- Implementations MUST emit and accept the fields listed in section 6.
  Missing required fields on either side are a protocol error.
- Servers MAY emit additional fields in any response object. Clients MUST
  ignore unknown fields (forward compatibility).
- Clients MUST NOT depend on fields beyond those listed in section 6 (backward
  compatibility).
- A breaking change to field names, types, or the message format defined in
  section 4 requires a new version of this spec. Breaking changes will be
  signaled by incrementing the version number in the document header.
- Non-breaking additions (new optional fields) do not require a version bump.

The `Version: 1` line in the canonical message (section 4.1) identifies this
protocol version and is fixed. It is not currently negotiated dynamically.

---

## 9. Open Questions and Non-Goals

### Open questions

- **`did` field in challenge response:** should the server echo the DID back
  in the challenge response JSON, or rely on the client to retain the DID it
  supplied? Removing it eliminates an attack surface; keeping it simplifies
  stateless clients. Currently present in `Challenge` (see `src/types.rs`).
- **Nonce generation:** the current implementation generates nonces in the
  server's `ChallengeStore`. Should the abstract protocol allow client-supplied
  nonces (as EIP-4361 permits), or is server-generated the canonical approach?
  Currently server-generated only.
- **Fixed statement string:** `Sign in to Aqua Node` is hardcoded. Whether
  this should be parameterizable (e.g., per-service) is unresolved.
- **Chain ID for `eip155`:** the parser in `src/did.rs` accepts only chain ID
  `1`. Multi-chain support would require relaxing this constraint and
  propagating the chain ID into the message.

### Non-goals

This specification does not cover:

- Session refresh or token rotation.
- Session revocation before expiry.
- Multi-factor authentication layered on top of signature-based auth.
- Cross-service session sharing or federation.
- The internal storage backend for challenges and sessions (currently
  in-memory; persistence is out of scope).
- Key rotation for the DID's signing key (the DID commits to the current
  public key, by embedding it for `did:key` / `did:pkh` / `did:peer` or by
  hashing it for `aqua`; either way rotation requires a new DID).
- WebAuthn integration beyond what P-256 ECDSA natively supports.

---

## 10. Reference Implementation

The `aqua-auth` crate in this repository is the reference implementation for
Rust. It targets the wire shapes and verification rules defined here.

| Source file | Responsibility |
|---|---|
| `src/types.rs` | Wire-serializable types (`Challenge`, `SessionRequest`, `Session`) |
| `src/message.rs` | Canonical message construction (`build_message()`) |
| `src/did.rs` | DID parsing and identifier extraction |
| `src/challenge.rs` | `ChallengeStore`: nonce generation, single-use validation, TTL |
| `src/session.rs` | `SessionStore`: token generation, validation, background sweep |
| `src/verify_eip191.rs` | EIP-191 signature verification |
| `src/verify_ed25519.rs` | Ed25519 signature verification |
| `src/verify_p256.rs` | P-256 ECDSA signature verification |
| `src/lib.rs` | `verify_caip122()` dispatch entry point |
| `src/client.rs` | Client helper (feature-gated): `authenticate()` |

A cross-language test vector file (planned, not yet shipped) will provide
concrete inputs (DID, message, signature bytes) and expected verification
outcomes, enabling compatible implementations in other languages to validate
against this spec.

---

## 11. Three Proof Surfaces (Content, Connection, Request)

This spec so far defines the *connection* surface. Since 0.5.0 the crate
family spans three distinct proof surfaces. Each answers a different question,
and none subsumes the others:

| Surface | Mechanism | Question answered | Lifetime |
|---|---|---|---|
| Content | Aqua-tree Signature revisions (Aqua SDK; fork branches, SHA3-256 chain, `signer_did`) | Who **authored** this data? | Durable: travels with the data, verifiable offline, by anyone |
| Connection | CAIP-122 challenge-response (this spec, sections 2 to 10), then a bearer session token | Who is on this **connection**? | Ephemeral session |
| Request | RFC 9421 HTTP Message Signatures (`http-sig` feature, experimental) | Who sent this specific **HTTP request**? | Single request, stateless verification |

**Author is not courier.** The entity delivering an aqua-tree need not be any
of its signers; a signed tree is durable and can be re-delivered by anyone who
holds it. Tree signatures prove authorship; the connection or request surface
proves who is delivering *now*; authorization policy decides what that
delivery may effect. Conflating these surfaces is how credential-relay bugs
happen.

All three surfaces converge on the same identity types: verification of a
login (section 7) or of a request signature yields the same `Principal`, and
the same async `Signer` produces tree, login, and request signatures from one
key custody point.

### 11.1 The `http-sig` request profile (experimental)

Status: tracks `draft-meunier-web-bot-auth-architecture-05` and is exempt from
this crate's semver stability promise until the IETF `webbotauth` working
group adopts a document. Wire details live in the `http_sig` module rustdoc;
normative summary:

- Covered components: `"@authority"` always; `"signature-agent"` when the
  header is present (coverage must match presence in both directions).
- Signature parameters, fixed order: `created`, `expires`, `keyid`, `alg`,
  `nonce`, `tag`.
- **Aqua-internal profile:** `keyid` is the signer's DID, `tag` is
  `aqua-auth`, `alg` is implied by the DID method. Verification rebuilds the
  signature base and dispatches through the same registries as section 7,
  returning a `Principal`. No key directory is needed: Aqua DIDs are
  self-certifying.
- **Interop profile:** `tag` is `web-bot-auth`, Ed25519 only, `keyid` is an
  RFC 7638 JWK thumbprint resolved via a key directory (below). Used when an
  Aqua agent must be verifiable by third-party infrastructure (Cloudflare,
  Akamai, AWS WAF class verifiers).
- Replay policy: `created`/`expires` window (24h cap), clock-skew tolerance,
  and optional single-use nonces via a bounded replay guard; a nonce is
  recorded only after the signature verifies.

### 11.2 Key advertisement (`aqua-auth-directory`)

The workspace crate `aqua-auth-directory` renders public-key advertisement
documents for services: the JWKS directory per
`draft-meunier-webbotauth-httpsig-directory-00` at
`/.well-known/http-message-signatures-directory`, and an Aqua-native identity
document at `/.well-known/aqua-identity`. Boundary: public keys only, with
validity windows and rotation overlap; private key custody stays with each
service's `Signer`. The crate is versioned independently (0.x) so IETF draft
churn never forces a version bump on `aqua-auth` itself.
