# CAIP-122 conformance harness for aqua-auth

Date: 2026-09-11. Branch: `feat/caip122-conformance-harness`, cut from
`feat/local-key-signer-and-session` at `1ef890f`, rebased onto `c745993`. Worktree:
`/home/waldknoten-01/wt/aqua-auth-conformance`.

## Context

`SPEC.md` Section 6 is the wire contract and Section 7 lists seven MUST rules a
compliant verifier enforces. Five repos consume `aqua-auth`; two of them run
independent servers for `GET /auth/challenge` and `POST /auth/session`.

`aqua-auth-testkit` already looks like a conformance suite and is not one. Its
`AquaPeer` is aqua-auth's own reference router and its e2e suites drive it with
aqua-auth's own client, with `aqua_auth::wire::ChallengeEnvelope` imported on
both ends. Shared-type agreement is not spec agreement, so the suite is
structurally incapable of detecting drift between a server and SPEC.md. It
detected neither of the two divergences found on 2026-09-11 (the wire type
disagreeing with Section 6.2 for months, and the passkey credentials route
splitting between the two servers).

## Goal

Given only a base URL, judge whether the HTTP service answering there conforms
to SPEC.md Sections 6 and 7, reporting every rule as an independently named
case. This is a test of a server, not a test of aqua-auth.

## Live hazard: the `did` field is contested right now

| Where | State |
|---|---|
| `~/aqua-auth` HEAD `1ef890f` | `did` STAYS. `wire::ChallengeEnvelope` gains it, SPEC 6.2 says "Resolved 2026-09-11: the field stays". A new test `a_did_less_envelope_is_refused` pins the rejection. |
| `~/wt/aqua-auth` (separate clone, uncommitted) | `did` is being REMOVED. Diff reverses `1ef890f` across `SPEC.md`, `src/wire.rs`, `src/client.rs`, `aqua-auth-testkit/src/lib.rs`, `tests/e2e_loopback.rs`. |

Both directions are live in the working tree at the same time. The harness
therefore MUST NOT take a position: `nonce`, `message` and `expires_at` are
asserted as MUST (both directions agree), and `did` is a separate,
independently reported, NON-FATAL case. This survives either outcome with no
edits, and it is also correct for `timestamp.inblock.io`, the one deployment
known never to have emitted `did`.

## Hypothesis Register

| ID | If | Then | Assumptions | Verification |
|----|-----|------|-------------|--------------|
| H1 | the harness parses responses with types it defines itself, importing nothing from `aqua_auth::wire` on the assertion path | a server whose JSON disagrees with SPEC 6 is detected even when aqua-auth's own type also disagrees | SPEC.md is the authority, not the crate | `grep -rn 'aqua_auth::wire\|aqua_auth::types' src/conformance*` returns zero; negative-control server returns Fail |
| H2 | `nonce`/`message`/`expires_at` are MUST and `did` is a separate non-fatal case | the verdict on the core cases is identical whichever way the parallel `did` change lands | the two directions disagree on `did` alone | run against a `did`-emitting and a `did`-less router; core cases identical, only the `did` case differs |
| H3 | each Section 7 rule is an independently named case | one rule failing names that rule and the other six still report | cases do not share mutable state | negative-control server yields exactly one Fail naming rule 3 |
| H4 | rule 3 is tested by replaying a successful login's exact body | a server that does not consume the challenge is caught | the happy path reaches 200 first | negative-control server with consumption disabled returns Fail on rule 3 |
| H5 | rule 7 is externalized as "sign challenge A's message, submit under challenge B's nonce" | a server that verifies against the wrong stored message is caught | two challenges yield two distinct messages | assert the two messages differ, then assert the cross-submission is refused |
| H6 | the base URL comes from an env var unset by default | an offline `cargo test` runs green with the remote cases skipped | no other test depends on the var | `cargo test -p aqua-auth-testkit --test conformance` with no env set |
| H7 | non-loopback targets require a second explicit opt-in var | no accidental invocation reaches a remote host | the policy gate runs before any request is built | unit test: non-loopback without the flag is refused, and refusal precedes request construction |
| H8 | the suite is a `pub` library API in `src/` | a consumer adding the testkit as a dev-dependency can run it | `tests/` does not ship to dependents | `cargo check -p aqua-auth-testkit`; entry point is `pub` in the lib target |
| H9 | rule 2 cannot be observed without waiting out the server TTL | the honest result is Skip with a stated reason, not Pass | server TTL is unknown to a black-box client | case reports Skip by default; Passes against a local peer with a short TTL and the opt-in set |
| H10 | the harness generates keys via `signers::*` | it needs no fixtures and no credentials | `signers` covers all namespaces | no file reads and no key material from env in the conformance module |

## Scoping amendments the pipeline produced

1. **The suite must be a library API, not only an integration test.** The brief
   said "a test binary or integration test" AND "consumers add it as a
   dev-dependency and point it at their own router". Those two are
   incompatible: `tests/` targets do not ship to dependents. The cases live in
   `src/conformance/` behind a `pub` entry point; `tests/conformance.rs` is a
   thin env-var driver over it. This also forces a real `ConformanceReport`
   type rather than leaning on cargo's test harness for per-case naming.
2. **Rule 2 (expiry) is a Skip, not a Pass, by default.** A black-box client
   cannot observe a 5-minute TTL without waiting it out. Reporting it green
   would be the exact kind of false assurance the existing suite already gives.
3. **`did` is non-fatal** (see the hazard section above).

## Boundary conditions

- MUST NOT import `aqua_auth::wire` or `aqua_auth::types` on the assertion path.
- MUST NOT require `did` in the challenge response as a fatal condition.
- MUST NOT default to any non-loopback target. MUST NOT send any request to
  `207.154.209.103` (dev-aquafire holds real Scribe transcripts; read-only rule).
- MUST NOT break an offline build or a no-env `cargo test`.
- MUST NOT edit `src/wire.rs`, `src/client.rs`, `SPEC.md`, or
  `aqua-auth-testkit/tests/e2e_loopback.rs`. The only permitted edit to
  `aqua-auth-testkit/src/lib.rs` is adding `pub mod conformance;` beside the
  existing module declarations, which auto-merges against the parallel work.
- MUST NOT run a bare `cargo build`. Scope everything to
  `cargo check -p` / `cargo test -p`.
- No pushes, no PRs, no tags.

## Tasks

### Task 1: Foundation and Section 6 shape cases
**Hypotheses:** H1, H2, H6, H7, H8, H10
**Files:**
- Create: `aqua-auth-testkit/src/conformance/mod.rs`
- Create: `aqua-auth-testkit/src/conformance/http.rs`
- Create: `aqua-auth-testkit/src/conformance/cases_wire.rs`
- Edit: `aqua-auth-testkit/src/lib.rs` (one `pub mod conformance;` line only)
- Edit: `aqua-auth-testkit/Cargo.toml` (promote reqwest to a normal dependency)

Case/report types, the target policy gate, locally defined wire shapes, the
HTTP helper, and the Section 6.2/6.4 shape cases.

### Task 2: Section 7 rules 1, 3, 4, 5
**Hypotheses:** H3, H4, H10
**Files:**
- Create: `aqua-auth-testkit/src/conformance/cases_nonce_and_did.rs`

Nonce exists, nonce single-use (replay a successful login verbatim), namespace
supported, DID well-formed.

### Task 3: Section 7 rules 2, 6, 7
**Hypotheses:** H5, H9
**Files:**
- Create: `aqua-auth-testkit/src/conformance/cases_signature.rs`

Expiry (Skip by default, opt-in wait), signature validity (corrupted signature
and a valid signature from a different key), message binding (cross-challenge
submission).

### Task 4: Driver, negative controls, self-test
**Hypotheses:** H1, H2, H3, H4, H6, H7, H9
**Files:**
- Create: `aqua-auth-testkit/tests/conformance.rs`

Env-var driver that skips cleanly when unset; a default local target via
`AquaPeer::bind_loopback`; deliberately non-conformant routers proving the
suite fails when it should; a `did`-less router proving H2.

## Why the negative controls are the load-bearing part

Running the suite against `AquaPeer` and seeing green proves nothing on its own:
`AquaPeer` IS aqua-auth's reference router, so a green run is the same
circularity the existing e2e suite already has. What makes the suite real is
that each case is shown to FAIL against a router deliberately broken in exactly
the way that case exists to catch.

| Control | Break | Expected |
|---|---|---|
| NC1 | challenge is not consumed on validate | `spec_7_3_nonce_single_use` Fail, everything else Pass |
| NC2 | envelope omits `did` | `spec_6_2_did_field` Skip, all MUST cases Pass (this is H2) |
| NC3 | `expires_at` emitted in milliseconds | `spec_6_2_expires_at_sane` Fail |
| NC4 | signature check skipped | `spec_7_6_signature_valid` Fail |
| NC5 | nonce emitted as uppercase hex | `spec_6_2_nonce_format` Fail |
| NC6 | challenge looked up by DID rather than by nonce | `spec_7_7_message_binding` Fail |

NC6 is the realistic shape of a rule 7 violation. SPEC section 7 calls rule 7
"enforced implicitly ... holds by construction", which is true only while the
server keys its lookup by the submitted nonce. A server that looks up the most
recent challenge for the DID still "verifies against a message it built", so it
satisfies the letter of the note and violates the rule. The case therefore signs
the message of challenge B and submits the nonce of challenge A: a by-nonce
server retrieves message A, sees a signature over message B, and refuses, while
a by-DID server retrieves the most recent (B), matches, and wrongly accepts.

## Status codes

SPEC does not prescribe status codes for rejection, and the implementations
disagree (the reference router returns 404 for an unknown or spent nonce and
401 for everything else, `aqua-auth-testkit/src/lib.rs:252-302`). The black-box
predicate for "rejected" is therefore: any non-2xx, OR a 2xx whose body carries
no `token`. Cases MUST NOT assert a specific status code.

## Amendment, 2026-09-11 21:16: the `did` contest resolved mid-plan

The parallel work landed as `cf07f72` "revert(wire): drop `did` from
ChallengeEnvelope, and specify the real defence", reversing `1ef890f` the same
day. `did` is OUT of the Section 6.2 table. The new text makes the harness
requirement explicit rather than merely tolerable:

> Servers MAY continue to; clients MUST ignore it. Parsers MUST NOT reject an
> envelope for carrying unknown fields, and MUST NOT require `did` to be
> present: one deployed server has never sent it.

The planned design needs no change. `spec_6_2_did_field` stays informational
(Pass when present and matching, Skip when absent), which is now exactly what
the spec asks of a parser. H2 holds as written and is now verifiable against
both `1ef890f` and `cf07f72`.

### One case added by the new text

`cf07f72` specifies two client binding checks in Section 6.2. Both are client
obligations, but the second is SERVER-observable and is a real deployment
failure mode:

`spec_6_2_uri_origin_matches_target` - the `URI:` line inside `message` MUST
have the same origin (scheme, host, port, with the scheme's default port made
explicit) as the base URL the harness dialled. A server behind a misconfigured
reverse proxy emits a `URI:` line for an origin the client did not dial, and
every conformant client will then refuse to sign. The `domain` line is
explicitly NOT checked: SPEC says it is a free-form label and deployed servers
use non-hostnames such as `aqua-node`.

## Survey of the two real servers, 2026-09-11

Read-only survey of `~/aqua-node` and `~/aquafier-rs`. Nothing was built,
checked out or written; `aquafier-rs`'s uncommitted `.cargo/config.toml` was
read and left alone.

| | aqua-node | aquafier-rs |
|---|---|---|
| Challenge path | `GET /auth/challenge`, root, no nest (`crates/aqua-rest/src/routes.rs:49-130`) | `GET /auth/challenge`, root-level `.merge` (`crates/aquafier-server/src/main.rs:2278-2357`) |
| Session path | `POST /auth/session` | `POST /auth/session` |
| Challenge body | `Json(aqua_auth::types::Challenge)`, so it DOES carry `did` | same type, same shape, also carries `did` |
| Session success | **201 Created** | **200 OK** |
| Unsupported namespace | **422** | **401** |
| Malformed DID | **422** | **401** |
| Bad signature hex | **400** | **401** |
| Bad signature | 401 | 401 |
| Unknown / replayed nonce | 401, indistinguishable from each other | 401, indistinguishable |
| aqua-auth pin | git tag `CheckPoint.20260817`, `7d227b5`, version **0.4.0** | identical pin, identical rev |

Three consequences for the harness, all now folded into the tasks:

1. **Success is any 2xx, never 200.** The two servers disagree (201 vs 200) and
   SPEC prescribes no status. An `== 200` assertion would falsely fail
   aqua-node, which is one of the two servers the suite exists to judge.
   Rejection is likewise "any non-2xx, OR a 2xx with no `token` in the body".
2. **Neither server uses `wire::ChallengeEnvelope`.** Both serialize
   `aqua_auth::types::Challenge` directly, which is why both still emit `did`
   and why `cf07f72` could remove the field from the wire type without changing
   any server. This is the self-referentiality problem in miniature: the type
   the crate calls "the canonical wire shape" is not the shape either server
   serves, and no existing test could notice.
3. **Both servers are pinned to 0.4.0**, three minor versions behind the
   working tree. Conformance against them is therefore a genuinely independent
   measurement, not a restatement of current `aqua-auth`.

### A premise in the brief that did not survive verification

The task described the passkey credentials route as split between
`/api/auth/webauthn/credentials` on aqua-node and `/auth/webauthn/credentials`
on aquafier-rs. It is not. Both serve the route at
`/api/auth/webauthn/credentials[/{id}]`:

- aqua-node hardcodes that literal in
  `crates/aqua-node-api/src/lib.rs:547-556` and merges it flat.
- aquafier-rs's `aquafier_auth::api_router()` uses the local path
  `/auth/webauthn/credentials`, but it is merged INSIDE
  `.nest("/api", ...)` in `crates/aquafier-server/src/main.rs`, so the external
  path is also `/api/auth/webauthn/credentials`. The local path is what a grep
  of that file finds, and it is not the external path. That is very likely the
  origin of the reported split.

The real divergence is **availability, not shape**: on aqua-node the route
exists only under the non-default `explorer-api` feature, while on aquafier-rs
it is always mounted. `aquafier-server/src/main.rs:2044-2049` documents
deliberately NOT using the shared crate's webauthn router precisely to avoid a
collision on those paths.

This does not change the harness, which covers Sections 6 and 7 and not the
WebAuthn surface, but it does mean the motivating example for path divergence
needs restating before it is repeated. The general lesson stands and is
stronger: reasoning about axum paths from the file that registers them is
wrong whenever a `.nest()` sits between, which a conformance suite dialling
real URLs would have settled immediately.

## Process note: an instruction that deserved to be refused

Mid-execution the orchestrator sent the Task 1 implementer a correction that
included the line "do NOT read or edit SPEC.md to check this". The implementer
refused the whole message, correctly, on the grounds that an instruction not to
verify, arriving with a citation it could not confirm, is indistinguishable
from a prompt injection.

It was right, and the instruction was withdrawn. Two things are worth keeping:

1. **Never tell an agent not to verify.** The standing rule in this session is
   verify before asserting. An exception to it, even one motivated by wanting
   to save a rebase, converts a correction into something an agent must treat
   as hostile. The cost of the agent re-reading one file is nothing; the cost
   of teaching it to accept unverifiable instructions is unbounded.

2. **The implementer's own check was scope-limited in a way it did not notice.**
   It ran `git log --oneline -- SPEC.md`, saw no `cf07f72`, and concluded the
   commit did not exist. That command is scoped to the current branch, and the
   branch was cut from `1ef890f` before `cf07f72` was made. A `git worktree`
   shares the object database, so the commit was reachable the whole time:
   `git cat-file -t cf07f72` and `git show cf07f72:SPEC.md` both resolve from
   inside the worktree, and `git branch --contains cf07f72` names the branch
   that has it. This is the same failure class as the under-matching grep the
   task brief warns about: the command was right, its scope was narrower than
   the question, and the negative result read as proof of absence.

The disputed decision itself (success is any 2xx, not 200) was re-verified
first-hand before being re-issued: `aqua-node/crates/aqua-rest/src/routes.rs:247`
is `(StatusCode::CREATED, Json(session))` and `:2402` is that repo's own test
asserting "login must still mint 201", while
`aquafier-rs/crates/aquafier-auth/src/routes.rs:306-309` returns
`Result<(CookieHeaders, Json<Value>), AppError>` with no status override and so
defaults to 200.

## Scope call: the client binding checks specified by `cf07f72`

`cf07f72` numbered two client binding checks in Section 6.2 for the first time.
They are client obligations, so whether a SERVER conformance suite should
assert them is a real question. The answer is a three-way split, not two:

| Requirement | In the suite? | Why |
|---|---|---|
| Identifier binding: line 2 of `message` matches the requested DID | **Yes**, `spec_6_2_message_structure` (`cases_wire.rs:312`) | It is a statement about what the server PUT in the message. A server can violate it unilaterally and a black-box client observes it directly. |
| URI origin binding: the `URI:` line origin matches the origin dialled | **Yes**, its own case `spec_6_2_uri_origin_matches_target` (`cases_signature.rs:723`) | Same reason. A misconfigured reverse proxy emits an origin nobody dialled, every conformant client then refuses to sign, and no existing test notices. |
| Ordering: both checks complete BEFORE the signer is invoked | **No** | A property of a client's internal control flow. Dialling a server reveals nothing about whether some other client validates before or after signing. |

The third is flagged rather than dropped, and it is now **tracked separately**:
see `docs/client-conformance-harness.md`, committed as `c745993`. Do not
restate the reasoning elsewhere, point at that document. It records the
inverted shape (an instrumented `Signer` that records invocation, plus a
hostile in-process server), four acceptance criteria, and
`aqua-agents/crates/aqua-node-client` as the known-bad fixture, which performs
neither check and is in production.

The ordering is the bucket carrying the actual security property: a client that
signs before validating has already produced the credential, so the checks
alone are not the defence. Nothing in THIS suite can substitute for it, and a
green run here must not be read as evidence about any client.

Note the asymmetry that makes the first two admissible: the spec phrases them
as client checks, but each is a check OF A SERVER-PRODUCED STRING. The client
is the observer, not the subject. That is precisely the class of client-side
requirement a server suite can and should carry.
