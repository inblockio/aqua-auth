# Client conformance harness

Tracked follow-up, opened 2026-09-11. Not scheduled.

`SPEC.md` section 6 carries a MUST that nothing in this repo can verify, and the CAIP-122
conformance suite added alongside this document cannot close it. This is the artifact that
would.

## The gap

The client binding checks were specified for the first time in `cf07f72`. Two checks, plus
an ordering requirement:

| Requirement | Server-observable | Asserted by the server suite |
|---|---|---|
| The identifier in `message` matches the DID the client requested | yes, the server wrote the message | yes, `spec_6_2_message_structure` |
| The `URI:` line's origin matches the origin the client dialled | yes, same reason | yes, `spec_6_2_uri_origin_matches_target` |
| **Both checks complete BEFORE the signer is invoked** | **no** | **no, and it cannot be** |

The first two are statements about what a server put in a message, so a black box dialling
that server can catch a violation. The third is a statement about a client's internal
control flow. No sequence of requests to any server reveals whether some other client
validates before or after it signs.

## Why the ordering is the part that matters

The checks alone are not the defence. A client that signs first and validates afterwards has
already produced a credential for whoever minted the challenge, and discarding it afterwards
does not un-sign it. The relay attack the checks exist to stop is only stopped by the
ordering.

So the one requirement carrying the security property is the one requirement with no
mechanical enforcement anywhere in the ecosystem.

## This is not hypothetical

`aqua-agents/crates/aqua-node-client/src/session.rs` reimplements the CAIP-122 login rather
than using `client::authenticate`, and it performs neither binding check. It signs whatever
the challenge endpoint returns. That client is in production, holds the Scribe agent's
`did:key`, and would have been caught immediately by the harness described below.

It was found on 2026-09-11 by reading the code, which is exactly the review method a
conformance suite exists to replace.

## Shape of the solution

A harness that inverts the direction of the existing suite. Instead of dialling a server and
judging its responses, it stands up a **hostile server**, hands a candidate client a
challenge that should be refused, and observes whether the client's signer was invoked.

| Element | Note |
|---|---|
| Entry point | a candidate client, not a base URL. The suite drives the client; today's suite is driven by one |
| Signer | an instrumented `Signer` that records invocation. The observable is "was `sign` called", not "was a request sent", because a client that signs and then discards has already failed |
| Hostile cases | a challenge whose identifier line names a different DID; a challenge whose `URI:` line names another Aqua service; both together; and a well-formed control that MUST be signed, so the suite cannot pass by a client that refuses everything |
| Verdict | Fail if `sign` was invoked for any hostile case, Fail if it was not invoked for the control |

The instrumented signer is the whole trick, and it is why this cannot be folded into the
server suite: it requires the candidate to accept an injected `Signer`, which is a property
of the client's API rather than of the wire.

## Acceptance criteria

1. Detects a client that performs no binding checks. Use the `aqua-node-client` login as the
   known-bad fixture; it must Fail.
2. Passes `client::authenticate` in this repo, which does both checks before signing
   (`src/client.rs`, `signed_session_request`).
3. Detects a client that performs both checks but signs first. This is the case that
   distinguishes an ordering harness from a checks harness, and it needs a purpose-built
   fixture since no real client is known to do it.
4. Does not require network access. The hostile server is in-process.

## Relationship to the server suite

Independent artifacts, one shared vocabulary. The server suite asserts SPEC sections 6 and 7
against a deployment; this asserts the section 6 client obligations against an
implementation. Neither subsumes the other, and a deployment can be fully conformant while
every client talking to it is exploitable.

Both belong in `aqua-auth-testkit`, which is already `publish = false` and reached by path or
git.

## Provenance

Split out during the CAIP-122 conformance planning on 2026-09-11. The three-way split
between "asserted", "asserted in its server-observable projection", and "not assertable from
this direction" was made deliberately rather than by omission, and this document is the
record of the third bucket.
