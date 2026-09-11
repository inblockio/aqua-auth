//! SPEC.md section 7 rules 2, 6 and 7: expiry, signature validity, and
//! message binding across two challenges.
//!
//! Same rules as the rest of this crate: every response is parsed as
//! [`serde_json::Value`], never `aqua_auth::wire` or `aqua_auth::types`; every
//! case generates its own fresh signer(s) via [`crate::signers`] and shares no
//! mutable state with any other case; nothing here asserts a specific status
//! code, only [`super::HttpResponse::is_success`] plus a non-empty `token` in
//! the body (see [`accepted`]).
//!
//! Rule 6 (signature validity) is split into two cases on purpose:
//! [`spec_7_6_signature_invalid_refused`] covers "the bytes are wrong" and
//! [`spec_7_6_wrong_key_refused`] covers "the bytes are a perfectly valid
//! signature, just from the wrong key". A server could pass the first by
//! rejecting anything that fails to decode while still accepting any
//! well-formed signature regardless of whose key made it, which is a login
//! bypass. Keeping the impersonation shape as its own named case means a
//! report can never bury that failure inside a table of hex-corruption
//! variants.

use super::{fetch_challenge, post_session, sign_challenge, unix_now, CaseResult, HttpResponse};
use super::{Http, Target};
use serde_json::{json, Value};
use std::time::Duration;

/// Environment variable that opts [`spec_7_2_challenge_expiry`] into actually
/// waiting out a challenge's TTL rather than reporting [`super::Outcome::Skip`].
const EXPIRY_WAIT_ENV: &str = "AQUA_CONFORMANCE_EXPIRY_WAIT";

/// The longest this suite is willing to block a test run waiting for a
/// challenge to expire. SPEC 6.2's stated default TTL is 5 minutes, so this
/// comfortably covers the documented default while still refusing to hang a
/// CI run indefinitely against a deployment configured with a much longer
/// TTL.
const MAX_EXPIRY_WAIT: Duration = Duration::from_secs(600);

/// True exactly when a session response counts as a successful login:
/// any 2xx (never a specific code, servers disagree, see
/// [`super::HttpResponse::is_success`]) carrying a non-empty string `token`.
/// Everything else, including a 2xx with no token, counts as rejected. Every
/// case in this module funnels its verdict through this one predicate so the
/// definition of "accepted" cannot drift between cases.
fn accepted(response: &HttpResponse) -> bool {
    response.is_success()
        && response
            .json
            .as_ref()
            .and_then(|v| v.get("token"))
            .and_then(Value::as_str)
            .is_some_and(|t| !t.is_empty())
}

/// Pull `message` and `nonce` out of a challenge response as owned strings,
/// or a human-readable reason it could not be done. Owned rather than
/// borrowed so a case can hold on to two challenges' worth of these across an
/// `.await` (signing) without fighting the borrow checker over which
/// response they came from.
fn message_and_nonce(response: &HttpResponse) -> Result<(String, String), String> {
    if !response.is_success() {
        return Err(format!(
            "GET challenge returned {}, expected success: {}",
            response.status,
            response.excerpt()
        ));
    }
    let Some(body) = response.json.as_ref() else {
        return Err(format!(
            "challenge response was not JSON: {}",
            response.excerpt()
        ));
    };
    let Some(message) = body.get("message").and_then(Value::as_str) else {
        return Err(format!(
            "challenge response had no string `message` field: {}",
            response.excerpt()
        ));
    };
    let Some(nonce) = body.get("nonce").and_then(Value::as_str) else {
        return Err(format!(
            "challenge response had no string `nonce` field: {}",
            response.excerpt()
        ));
    };
    Ok((message.to_string(), nonce.to_string()))
}

// ── SPEC 7 rule 6, shape A: a well-formed-DID, wrong-bytes signature ───────

/// One way of corrupting an otherwise-valid `0x`-prefixed hex signature,
/// paired with a label for the failure detail.
type Corruption = (&'static str, fn(&str) -> String);

/// Every corruption [`spec_7_6_signature_invalid_refused`] tries. Each one
/// changes exactly one thing about an otherwise perfect signature.
const SIGNATURE_CORRUPTIONS: &[Corruption] = &[
    ("flipped one bit of the signature", flip_one_bit),
    ("truncated the signature by one byte", truncate_by_one_byte),
    ("appended one extra byte to the signature", append_one_byte),
    (
        "replaced the signature with all zero bytes of the correct length",
        zero_of_same_length,
    ),
    (
        "replaced the signature with a non-hex string",
        non_hex_garbage,
    ),
];

fn decode_hex_body(signature: &str) -> Vec<u8> {
    hex::decode(signature.strip_prefix("0x").unwrap_or(signature)).unwrap_or_default()
}

fn flip_one_bit(signature: &str) -> String {
    let mut bytes = decode_hex_body(signature);
    if let Some(first) = bytes.first_mut() {
        *first ^= 0x01;
    }
    format!("0x{}", hex::encode(bytes))
}

fn truncate_by_one_byte(signature: &str) -> String {
    let bytes = decode_hex_body(signature);
    let shorter = &bytes[..bytes.len().saturating_sub(1)];
    format!("0x{}", hex::encode(shorter))
}

fn append_one_byte(signature: &str) -> String {
    let mut bytes = decode_hex_body(signature);
    bytes.push(0xaa);
    format!("0x{}", hex::encode(bytes))
}

fn zero_of_same_length(signature: &str) -> String {
    let len = decode_hex_body(signature).len();
    format!("0x{}", hex::encode(vec![0u8; len]))
}

fn non_hex_garbage(_signature: &str) -> String {
    "0xthis-is-not-hex-at-all".to_string()
}

/// SPEC 7 rule 6: "the signature verifies against the DID's identifier under
/// the namespace-appropriate algorithm." This case tries several ways of
/// making an otherwise-perfect signature wrong: a flipped bit, a truncated or
/// extended byte string, an all-zero signature of the right length, and a
/// value that is not hex at all. Each is a distinct code path a verifier
/// could get wrong (decode failure vs. length check vs. the actual
/// cryptographic comparison), so a table of them catches more than any single
/// mutation would.
///
/// **The trap this case exists to avoid:** it would be easy to build one
/// valid session request and mutate its `signature` field five different
/// ways, reusing the same challenge for all five submissions. That reuses one
/// nonce five times. A server that correctly enforces rule 3 (single-use
/// nonce, `SPEC.md` section 7) consumes the nonce on the *first* submission
/// regardless of whether the signature was valid, so submissions two through
/// five would all be rejected for an unknown/spent nonce, rule 3, not rule 6.
/// The case would report every corruption as "rejected" and prove nothing
/// about rule 6 at all except for the very first row. Each corruption below
/// therefore runs against its own freshly fetched challenge and its own
/// freshly generated signer, so every submission is the *only* thing ever
/// sent for that nonce and a rejection can only be attributed to the
/// corrupted signature.
pub(crate) async fn spec_7_6_signature_invalid_refused(target: &Target, http: &Http) -> CaseResult {
    const ID: &str = "spec_7_6_signature_invalid_refused";
    const SPEC_REF: &str = "SPEC 7 rule 6";
    const TITLE: &str = "a corrupted signature is refused";

    let mut problems = Vec::new();

    for (label, corrupt) in SIGNATURE_CORRUPTIONS {
        let signer = crate::signers::ed25519_did_key();
        let challenge = match fetch_challenge(http, target, signer.signer_did()).await {
            Ok(r) => r,
            Err(e) => {
                problems.push(format!("{label}: could not fetch a fresh challenge: {e}"));
                continue;
            }
        };
        let mut body = match sign_challenge(&challenge, &signer).await {
            Ok(b) => b,
            Err(e) => {
                problems.push(format!(
                    "{label}: could not build a valid session request to corrupt: {e}"
                ));
                continue;
            }
        };
        let Some(original_signature) = body.get("signature").and_then(Value::as_str) else {
            problems.push(format!(
                "{label}: the harness's own signed body had no `signature` field, this is a \
                 harness bug"
            ));
            continue;
        };
        let corrupted = corrupt(original_signature);
        body["signature"] = Value::String(corrupted.clone());

        let response = match post_session(http, target, &body).await {
            Ok(r) => r,
            Err(e) => {
                problems.push(format!("{label}: request failed: {e}"));
                continue;
            }
        };

        if accepted(&response) {
            problems.push(format!(
                "{label}: WRONGLY ACCEPTED (sent signature {corrupted:?}, got {} with a token)",
                response.status
            ));
        }
    }

    if problems.is_empty() {
        CaseResult::pass(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "all {} corruptions were rejected, each against its own fresh challenge",
                SIGNATURE_CORRUPTIONS.len()
            ),
        )
    } else {
        CaseResult::fail(ID, SPEC_REF, TITLE, problems.join("; "))
    }
}

// ── SPEC 7 rule 6, shape B: a well-formed, validly-signed, wrong-key sig ───

/// SPEC 7 rule 6, the impersonation shape: a signature that is not corrupted
/// at all, just made by the wrong key. Generates two fresh ed25519 signers, A
/// and B; fetches a challenge naming A's DID; signs A's exact challenge
/// message with B's key; submits `{did: A, nonce: A's nonce, signature:
/// sig_B}`.
///
/// This is a different bug class from [`spec_7_6_signature_invalid_refused`]:
/// every byte here is a perfectly well-formed Ed25519 signature that a naive
/// verifier's length and encoding checks all pass. The only thing wrong with
/// it is which key produced it. A server that checks "is this a valid
/// signature over this message" without also checking "was it produced by
/// the key that DID A names" accepts this, and a server that does that lets
/// anyone log in as anyone: this is the single worst failure this suite can
/// find, which is why it gets its own named case rather than living as a row
/// in a table.
pub(crate) async fn spec_7_6_wrong_key_refused(target: &Target, http: &Http) -> CaseResult {
    const ID: &str = "spec_7_6_wrong_key_refused";
    const SPEC_REF: &str = "SPEC 7 rule 6";
    const TITLE: &str = "a valid signature from a different key than the claimed did is refused";

    let signer_a = crate::signers::ed25519_did_key();
    let signer_b = crate::signers::ed25519_did_key();

    let challenge = match fetch_challenge(http, target, signer_a.signer_did()).await {
        Ok(r) => r,
        Err(e) => {
            return CaseResult::fail(
                ID,
                SPEC_REF,
                TITLE,
                format!("could not fetch a challenge for signer A: {e}"),
            )
        }
    };
    let (message, nonce) = match message_and_nonce(&challenge) {
        Ok(pair) => pair,
        Err(reason) => {
            return CaseResult::fail(ID, SPEC_REF, TITLE, format!("A's challenge {reason}"))
        }
    };

    let signature_b = match signer_b.sign(&message).await {
        Ok(sig) => sig,
        Err(e) => {
            return CaseResult::fail(
                ID,
                SPEC_REF,
                TITLE,
                format!("signer B failed to sign A's message: {e}"),
            )
        }
    };

    let body = json!({
        "did": signer_a.signer_did(),
        "nonce": nonce,
        "signature": format!("0x{}", hex::encode(signature_b)),
    });

    let response = match post_session(http, target, &body).await {
        Ok(r) => r,
        Err(e) => return CaseResult::fail(ID, SPEC_REF, TITLE, format!("request failed: {e}")),
    };

    if accepted(&response) {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "the server logged in as {} using a well-formed signature made by an unrelated \
                 key B over A's own message; got {} with a token. Anyone who can produce any \
                 valid signature could log in as anyone else",
                signer_a.signer_did(),
                response.status
            ),
        );
    }
    CaseResult::pass(
        ID,
        SPEC_REF,
        TITLE,
        format!("rejected with {}: {}", response.status, response.excerpt()),
    )
}

// ── SPEC 7 rule 7 ───────────────────────────────────────────────────────

/// SPEC 7 rule 7: "the canonical message in the challenge matches the message
/// that was signed." `SPEC.md` calls this "enforced implicitly ... holds by
/// construction," which is true only while the server looks the challenge up
/// **by the submitted nonce**. A server that instead looks up the most recent
/// challenge issued for the DID still satisfies the letter of that note
/// (it "verifies against a message it built"), while violating the rule: it
/// will accept a signature over a message that is not the one named by the
/// submitted nonce, as long as some other, more recent challenge for the same
/// DID happens to have that message.
///
/// Construction: with one signer, fetch challenge A, then fetch challenge B
/// (two separate `GET`s for the same DID). Assert A's `message` and `nonce`
/// differ from B's; if they are identical the server is not minting fresh
/// challenges per request at all, which is a serious bug of its own (and
/// would make the rest of this probe meaningless, so it is reported as its
/// own [`super::Outcome::Fail`] rather than silently treated as a pass or a
/// skip). Then sign B's message and submit it under A's nonce:
/// `{did, nonce: nonce_a, signature: sign(message_b)}`. A by-nonce server
/// retrieves the message stored under `nonce_a` (message A), sees a signature
/// over a different message, and refuses. A by-DID server retrieves its most
/// recent challenge for the DID (challenge B, since it was issued after A),
/// finds the signature matches that message, and wrongly accepts.
///
/// The mirror direction is checked too (sign A's message, submit it under
/// B's nonce), since a server keyed by DID could plausibly retrieve
/// "the challenge matching this nonce" for either direction depending on
/// implementation details this suite cannot see from outside; both
/// directions must be refused for the rule to hold.
pub(crate) async fn spec_7_7_message_binding(target: &Target, http: &Http) -> CaseResult {
    const ID: &str = "spec_7_7_message_binding";
    const SPEC_REF: &str = "SPEC 7 rule 7";
    const TITLE: &str =
        "a signature is checked against the message stored under its own nonce, not the DID's \
         most recent challenge";

    let signer = crate::signers::ed25519_did_key();
    let did = signer.signer_did();

    let challenge_a = match fetch_challenge(http, target, did).await {
        Ok(r) => r,
        Err(e) => {
            return CaseResult::fail(
                ID,
                SPEC_REF,
                TITLE,
                format!("could not fetch challenge A: {e}"),
            )
        }
    };
    let challenge_b = match fetch_challenge(http, target, did).await {
        Ok(r) => r,
        Err(e) => {
            return CaseResult::fail(
                ID,
                SPEC_REF,
                TITLE,
                format!("could not fetch challenge B: {e}"),
            )
        }
    };

    let (message_a, nonce_a) = match message_and_nonce(&challenge_a) {
        Ok(pair) => pair,
        Err(reason) => {
            return CaseResult::fail(ID, SPEC_REF, TITLE, format!("challenge A {reason}"))
        }
    };
    let (message_b, nonce_b) = match message_and_nonce(&challenge_b) {
        Ok(pair) => pair,
        Err(reason) => {
            return CaseResult::fail(ID, SPEC_REF, TITLE, format!("challenge B {reason}"))
        }
    };

    if message_a == message_b || nonce_a == nonce_b {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "two separate GET /auth/challenge calls for the same DID returned identical \
                 message/nonce (nonce {nonce_a:?} both times); the server is not minting a \
                 fresh challenge per request, so this rule 7 probe cannot be exercised \
                 meaningfully and the identical-challenge behaviour is itself a bug"
            ),
        );
    }

    let mut wrongly_accepted = Vec::new();

    // Direction 1: sign B's message, submit under A's nonce.
    match signer.sign(&message_b).await {
        Ok(signature) => {
            let body = json!({
                "did": did,
                "nonce": nonce_a,
                "signature": format!("0x{}", hex::encode(signature)),
            });
            match post_session(http, target, &body).await {
                Ok(response) if accepted(&response) => wrongly_accepted.push(format!(
                    "nonce=A with a signature over message B was accepted ({} with a token); a \
                     by-DID lookup would retrieve the more recent challenge B and wrongly match",
                    response.status
                )),
                Ok(_) => {}
                Err(e) => wrongly_accepted
                    .push(format!("direction nonce=A/message=B: request failed: {e}")),
            }
        }
        Err(e) => wrongly_accepted.push(format!("could not sign message B: {e}")),
    }

    // Mirror direction: sign A's message, submit under B's nonce.
    match signer.sign(&message_a).await {
        Ok(signature) => {
            let body = json!({
                "did": did,
                "nonce": nonce_b,
                "signature": format!("0x{}", hex::encode(signature)),
            });
            match post_session(http, target, &body).await {
                Ok(response) if accepted(&response) => wrongly_accepted.push(format!(
                    "nonce=B with a signature over message A was accepted ({} with a token)",
                    response.status
                )),
                Ok(_) => {}
                Err(e) => wrongly_accepted
                    .push(format!("direction nonce=B/message=A: request failed: {e}")),
            }
        }
        Err(e) => wrongly_accepted.push(format!("could not sign message A: {e}")),
    }

    if wrongly_accepted.is_empty() {
        CaseResult::pass(
            ID,
            SPEC_REF,
            TITLE,
            "both cross-challenge submissions (nonce=A/message=B and nonce=B/message=A) were \
             rejected",
        )
    } else {
        CaseResult::fail(ID, SPEC_REF, TITLE, wrongly_accepted.join("; "))
    }
}

// ── SPEC 7 rule 2 ───────────────────────────────────────────────────────

/// SPEC 7 rule 2: "the current time is strictly before `expires_at`."
///
/// A black-box client cannot observe a multi-minute TTL without waiting it
/// out, and reporting this rule green without ever waiting would be exactly
/// the false assurance this whole suite exists to remove. So by default this
/// case reports [`super::Outcome::Skip`], stating the TTL it actually
/// observed (`expires_at - now` from a freshly fetched challenge) and naming
/// [`EXPIRY_WAIT_ENV`] as the way to make it run for real.
///
/// One check runs unconditionally, opt-in or not, because it costs nothing
/// and catches a real bug cheaply: if `expires_at` is already at or before
/// the moment the challenge was fetched, that is reported as
/// [`super::Outcome::Fail`] outright, no waiting required.
///
/// With `AQUA_CONFORMANCE_EXPIRY_WAIT=1` set, the case fetches a challenge,
/// signs it immediately (while it is still valid), sleeps past its
/// `expires_at` (capped at [`MAX_EXPIRY_WAIT`], reporting
/// [`super::Outcome::Skip`] instead of blocking indefinitely if the TTL
/// exceeds that cap), then submits the already-signed request. It must be
/// refused.
pub(crate) async fn spec_7_2_challenge_expiry(target: &Target, http: &Http) -> CaseResult {
    const ID: &str = "spec_7_2_challenge_expiry";
    const SPEC_REF: &str = "SPEC 7 rule 2";
    const TITLE: &str = "a session request signed after the challenge's expires_at is refused";

    let signer = crate::signers::ed25519_did_key();
    let challenge = match fetch_challenge(http, target, signer.signer_did()).await {
        Ok(r) => r,
        Err(e) => return CaseResult::fail(ID, SPEC_REF, TITLE, format!("request failed: {e}")),
    };
    if !challenge.is_success() {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "GET challenge returned {}, expected success: {}",
                challenge.status,
                challenge.excerpt()
            ),
        );
    }
    let Some(expires_at) = challenge
        .json
        .as_ref()
        .and_then(|v| v.get("expires_at"))
        .and_then(Value::as_u64)
    else {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "no unsigned-integer `expires_at` field in the response: {}",
                challenge.excerpt()
            ),
        );
    };

    let fetched_at = unix_now();

    // Cheap and unconditional: a challenge that is already expired the
    // moment it is issued is a real bug, and catching it needs no waiting.
    if expires_at <= fetched_at {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "expires_at ({expires_at}) is already at or before the moment the challenge was \
                 fetched (now {fetched_at}); the server minted a pre-expired challenge"
            ),
        );
    }

    let observed_ttl_secs = expires_at - fetched_at;

    let opt_in = std::env::var(EXPIRY_WAIT_ENV)
        .map(|v| v == "1")
        .unwrap_or(false);
    if !opt_in {
        return CaseResult::skip(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "observed TTL is {observed_ttl_secs}s (expires_at {expires_at}, fetched at \
                 {fetched_at}); a black-box client cannot prove expiry is enforced without \
                 waiting out the TTL, so this is not exercised by default. Set \
                 {EXPIRY_WAIT_ENV}=1 to actually wait and submit past expiry"
            ),
        );
    }

    if observed_ttl_secs > MAX_EXPIRY_WAIT.as_secs() {
        return CaseResult::skip(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "TTL is {observed_ttl_secs}s, more than the {}s this case is willing to wait; \
                 refusing to block the run for an impractically long TTL",
                MAX_EXPIRY_WAIT.as_secs()
            ),
        );
    }

    // Sign now, while the challenge is still valid, then wait it out.
    let body = match sign_challenge(&challenge, &signer).await {
        Ok(b) => b,
        Err(e) => {
            return CaseResult::fail(
                ID,
                SPEC_REF,
                TITLE,
                format!("could not sign the challenge before waiting out its TTL: {e}"),
            )
        }
    };

    let wait = Duration::from_secs(observed_ttl_secs.saturating_add(1));
    tokio::time::sleep(wait).await;

    let response = match post_session(http, target, &body).await {
        Ok(r) => r,
        Err(e) => {
            return CaseResult::fail(
                ID,
                SPEC_REF,
                TITLE,
                format!("request failed after waiting out the TTL: {e}"),
            )
        }
    };

    if accepted(&response) {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "a session request signed against a challenge {observed_ttl_secs}s past its \
                 stated expires_at ({expires_at}) was accepted: {} with a token",
                response.status
            ),
        );
    }
    CaseResult::pass(
        ID,
        SPEC_REF,
        TITLE,
        format!(
            "rejected {observed_ttl_secs}s past expiry with {}: {}",
            response.status,
            response.excerpt()
        ),
    )
}

// ── SPEC 6.2, client URI binding check (server-observable) ────────────────

/// SPEC 6.2's client binding check on the `URI:` line: "Clients MUST verify
/// ... the `URI:` line's origin must match the origin the client dialled...
/// which is what refuses a challenge relayed from another Aqua service." That
/// text describes an obligation on the *client*, but it is observable against
/// a server in isolation, and a mismatch here means every conformant client
/// will refuse to sign the challenge it just received: a misconfigured
/// reverse proxy or a wrong `PUBLIC_URL`-style setting that makes the server
/// emit a `URI:` line for an origin other than the one actually being dialled
/// is a real, server-side deployment failure, not merely a client's problem
/// to work around.
///
/// Compares scheme, host, and port, with the scheme's default port made
/// explicit via [`url::Url::port_or_known_default`], so `https://x` and
/// `https://x:443` compare equal.
///
/// **Deliberately does not check the `domain` line (message line 1).** SPEC
/// 4.2 says `{domain}` is a "caller-supplied domain string" and is explicit
/// elsewhere that it is a free-form label, not a hostname: deployed servers
/// use non-hostname values such as `aqua-node` there. Checking it against the
/// dialled host would fail every real deployment surveyed for this harness.
/// Do not "fix" this to also check `domain`; it is not a hostname and was
/// never meant to be one.
pub(crate) async fn spec_6_2_uri_origin_matches_target(target: &Target, http: &Http) -> CaseResult {
    const ID: &str = "spec_6_2_uri_origin_matches_target";
    const SPEC_REF: &str = "SPEC 6.2";
    const TITLE: &str = "the message's URI: line has the same origin as the base URL dialled";

    let signer = crate::signers::ed25519_did_key();
    let challenge = match fetch_challenge(http, target, signer.signer_did()).await {
        Ok(r) => r,
        Err(e) => return CaseResult::fail(ID, SPEC_REF, TITLE, format!("request failed: {e}")),
    };
    if !challenge.is_success() {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "GET challenge returned {}, expected success: {}",
                challenge.status,
                challenge.excerpt()
            ),
        );
    }
    let Some(message) = challenge
        .json
        .as_ref()
        .and_then(|v| v.get("message"))
        .and_then(Value::as_str)
    else {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "no string `message` field in the response: {}",
                challenge.excerpt()
            ),
        );
    };

    let Some(uri_line) = message.lines().find(|line| line.starts_with("URI: ")) else {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!("message has no 'URI: ' line at all: {message:?}"),
        );
    };
    let uri_value = uri_line.trim_start_matches("URI: ").trim();

    let Ok(message_uri) = url::Url::parse(uri_value) else {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!("the message's URI: line {uri_value:?} does not parse as a URL"),
        );
    };
    let Ok(dialled) = url::Url::parse(target.base_url()) else {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "the harness's own target base_url {:?} does not parse as a URL, this is a \
                 harness bug",
                target.base_url()
            ),
        );
    };

    let same_origin = message_uri.scheme() == dialled.scheme()
        && message_uri.host_str() == dialled.host_str()
        && message_uri.port_or_known_default() == dialled.port_or_known_default();

    if !same_origin {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "message's URI: line is {uri_value:?} (origin {}://{}:{}), the harness dialled \
                 {:?} (origin {}://{}:{}); a conformant client refuses to sign a challenge whose \
                 URI origin does not match the origin it dialled",
                message_uri.scheme(),
                message_uri.host_str().unwrap_or("<no host>"),
                message_uri
                    .port_or_known_default()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "<unknown>".to_string()),
                target.base_url(),
                dialled.scheme(),
                dialled.host_str().unwrap_or("<no host>"),
                dialled
                    .port_or_known_default()
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "<unknown>".to_string()),
            ),
        );
    }
    CaseResult::pass(ID, SPEC_REF, TITLE, "")
}

// ── SPEC 5.4 step 1 / 6.3, did:aqua public_key binding ─────────────────────

/// SPEC 6.3 / 5.4 step 1: "Servers MUST bind `public_key` to `did` before
/// trusting it ... A key that is accepted without being bound authenticates
/// possession of some identity rather than of the one presented."
///
/// Generates two fresh `did:aqua` signers, A and B. Fetches a challenge for
/// A's DID, signs A's message with A's own key (a perfectly valid signature),
/// then replaces the `public_key` field in the session request with **B's**
/// public key before submitting. A verifier that skips the binding check
/// (recomputing `did:aqua:` from the presented key and comparing it to the
/// claimed DID, `SPEC.md` 5.4 step 1) would verify the ML-DSA signature
/// successfully with A's key, if it even bothers reading `public_key` back
/// out correctly, or otherwise might key its lookup off `public_key` and
/// accept a proof of possession of B's key as authentication for A's
/// identity. Either way, the DID and the key backing the login have come
/// apart, which is exactly what binding exists to prevent.
///
/// `did:aqua` is `SPEC.md` section 3's one feature-gated, optional namespace.
/// If the challenge fetch for a `did:aqua` DID is itself refused, that means
/// the server does not implement the namespace at all, a supported
/// configuration, and this case reports [`super::Outcome::Skip`], never
/// [`super::Outcome::Fail`].
pub(crate) async fn spec_6_3_public_key_binding(target: &Target, http: &Http) -> CaseResult {
    const ID: &str = "spec_6_3_public_key_binding";
    const SPEC_REF: &str = "SPEC 5.4 step 1, 6.3";
    const TITLE: &str = "a did:aqua public_key is bound to the did before being trusted";

    let signer_a = crate::signers::did_aqua();
    let signer_b = crate::signers::did_aqua();

    let challenge = match fetch_challenge(http, target, signer_a.signer_did()).await {
        Ok(r) => r,
        Err(e) => {
            return CaseResult::skip(
                ID,
                SPEC_REF,
                TITLE,
                format!("could not even ask for a did:aqua challenge: {e}"),
            )
        }
    };
    if !challenge.is_success() {
        return CaseResult::skip(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "GET challenge for a did:aqua DID was refused ({}: {}); did:aqua is a \
                 feature-gated, optional namespace (SPEC section 3), so a server that does not \
                 implement it is a supported configuration, not a conformance failure",
                challenge.status,
                challenge.excerpt()
            ),
        );
    }

    let mut body = match sign_challenge(&challenge, &signer_a).await {
        Ok(b) => b,
        Err(e) => {
            return CaseResult::fail(
                ID,
                SPEC_REF,
                TITLE,
                format!("signer A could not sign its own challenge: {e}"),
            )
        }
    };

    let Some(public_key_b) = signer_b.public_key() else {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            "the harness's own did:aqua signer B returned no public_key, this is a harness bug",
        );
    };
    body["public_key"] = json!(format!("0x{}", hex::encode(public_key_b)));

    let response = match post_session(http, target, &body).await {
        Ok(r) => r,
        Err(e) => return CaseResult::fail(ID, SPEC_REF, TITLE, format!("request failed: {e}")),
    };

    if accepted(&response) {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "the server accepted a login as {} with a genuine signature from A's own key, \
                 but with B's public_key substituted into the request; got {} with a token. \
                 SPEC 5.4 step 1 requires binding public_key to did before trusting it",
                signer_a.signer_did(),
                response.status
            ),
        );
    }
    CaseResult::pass(
        ID,
        SPEC_REF,
        TITLE,
        format!("rejected with {}: {}", response.status, response.excerpt()),
    )
}

/// Every case this module implements, in the order they run.
pub(crate) async fn all(target: &Target, http: &Http) -> Vec<CaseResult> {
    vec![
        spec_7_6_signature_invalid_refused(target, http).await,
        spec_7_6_wrong_key_refused(target, http).await,
        spec_7_7_message_binding(target, http).await,
        spec_7_2_challenge_expiry(target, http).await,
        spec_6_2_uri_origin_matches_target(target, http).await,
        spec_6_3_public_key_binding(target, http).await,
    ]
}
