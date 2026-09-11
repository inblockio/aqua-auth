//! SPEC.md section 7 rules 1, 3, 4 and 5: nonce existence, nonce single-use,
//! namespace support and DID well-formedness.
//!
//! Every case below either performs its own fresh happy-path login or fetches
//! its own fresh challenge: no case shares a signer, a nonce or a challenge
//! with another, so one case's tampering can never leak into another case's
//! verdict (the plan's H3, "each Section 7 rule is an independently named
//! case ... cases do not share mutable state").
//!
//! # The accept/reject predicate
//!
//! SPEC.md prescribes no status code for either a successful or a rejected
//! `POST /auth/session`, and the two real Aqua servers surveyed for the plan
//! (`docs/superpowers/plans/2026-09-11-caip122-conformance-harness.md`,
//! "Survey of the two real servers") disagree with each other on every
//! failure mode this module exercises: aqua-node mints `201 Created` on
//! success and returns `422` for an unsupported namespace or a malformed
//! DID, while aquafier-rs mints `200 OK` on success and collapses every one
//! of those failures, indistinguishably, to `401`. A case that asserted a
//! specific status code, for success or for rejection, would therefore be
//! correct against at most one of the two servers this harness exists to
//! judge. See [`session_accepted`] for the predicate used instead.
//!
//! `did:aqua` is deliberately never used as an "unsupported" or "malformed"
//! probe below: it is a real, feature-gated namespace (SPEC 3), and a server
//! that supports it is conformant, not broken. Using it as a negative
//! example would manufacture a false failure against exactly the kind of
//! server this suite should praise.

use super::{
    fetch_challenge, login, post_session, sign_challenge, CaseResult, Http, HttpResponse, Target,
};
use serde_json::{json, Value};

/// `bytes` fresh random bytes, lowercase hex encoded. Every case below mints
/// its own nonces, signatures and DID identifiers this way rather than
/// hardcoding a fixture, so two runs of the same case never collide with
/// each other, and never collide with whatever a previous run may have left
/// behind on a real server (SPEC 7 rule 3 is exactly about state a previous
/// run could have left behind).
fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf);
    hex::encode(buf)
}

/// The one field a real SPEC 6.4 session response carries that this module
/// checks for: `token`, as a string.
fn extract_token(response: &HttpResponse) -> Option<&str> {
    response.json.as_ref()?.get("token")?.as_str()
}

/// **The rejection predicate for `POST /auth/session`, used by every case in
/// this module.**
///
/// Accepted = `is_success()` (any 2xx) AND the body carries a non-empty
/// string `token`. Rejected = anything else: any non-2xx status, or a 2xx
/// whose body has no usable `token`. See the module docs above for why no
/// status code, success or failure, is ever asserted directly: aqua-node and
/// aquafier-rs disagree on the status for every outcome this module tests,
/// and `token` is the one thing SPEC 6.4 says a real session carries that
/// neither server omits.
fn session_accepted(response: &HttpResponse) -> bool {
    response.is_success() && extract_token(response).is_some_and(|token| !token.is_empty())
}

/// The either-endpoint refusal check shared by SPEC 7 rules 4 and 5: a
/// conformant server may refuse a bad DID at `GET /auth/challenge` (the
/// cheaper place to do it) or, having handed out a challenge for it anyway,
/// at `POST /auth/session`. Only accepting at BOTH stages is nonconformant.
///
/// Returns `Ok(where)` describing where the DID was refused, or `Err(what)`
/// describing exactly what got accepted when it should not have: either
/// "both endpoints accepted it" (the real violation), or "the challenge
/// succeeded but with no usable nonce, so the session stage could not even
/// be attempted", which this treats as a violation too, since SPEC 6.2 makes
/// `nonce` a MUST on any 2xx challenge response, and a server that skips it
/// for exactly the DIDs that should have been refused is not meaningfully
/// different from accepting them outright.
async fn refused_at_either_endpoint(
    http: &Http,
    target: &Target,
    did: &str,
) -> Result<String, String> {
    let challenge = fetch_challenge(http, target, did)
        .await
        .map_err(|e| format!("challenge request itself failed: {e}"))?;

    if !challenge.is_success() {
        return Ok(format!(
            "refused at challenge time: {} {}",
            challenge.status,
            challenge.excerpt()
        ));
    }

    let Some(nonce) = challenge
        .json
        .as_ref()
        .and_then(|v| v.get("nonce"))
        .and_then(Value::as_str)
    else {
        return Err(format!(
            "challenge returned {} for this DID with no usable `nonce`, so the session-level \
             check could not be attempted: {}",
            challenge.status,
            challenge.excerpt()
        ));
    };

    let session_body = json!({
        "did": did,
        "nonce": nonce,
        "signature": format!("0x{}", random_hex(64)),
    });
    let session_response = post_session(http, target, &session_body)
        .await
        .map_err(|e| format!("session request itself failed: {e}"))?;

    if session_accepted(&session_response) {
        Err(format!(
            "accepted at BOTH endpoints: challenge {} then session {} {}",
            challenge.status,
            session_response.status,
            session_response.excerpt()
        ))
    } else {
        Ok(format!(
            "challenge accepted ({}) but session was refused: {} {}",
            challenge.status,
            session_response.status,
            session_response.excerpt()
        ))
    }
}

/// SPEC 7 rule 1: "the nonce was issued by this server's `ChallengeStore`".
///
/// Fetches a real challenge, signs it correctly, then swaps the `nonce` in
/// the outgoing session request for a fresh, well-formed, never-issued one
/// (`0x` + 64 random lowercase hex characters, SPEC 4.2's own nonce shape)
/// before submitting. This is the minimum adversarial shape that actually
/// distinguishes "the server consults its `ChallengeStore`" from "the server
/// trusts whatever nonce the client sends": a malformed nonce would only
/// prove the server validates shape, which SPEC 7 rule 1 does not ask for.
///
/// The signature on this request will also fail to verify, since it was
/// computed over a message binding the ORIGINAL nonce (SPEC 4.1's `Nonce:`
/// line), while the request now claims a different one. That is fine and
/// deliberate: rule 1 only requires the request be refused, not that it be
/// refused for a particular reason, and a server that accepts a nonce it
/// never minted is nonconforming no matter which of its checks let it
/// through.
pub(crate) async fn spec_7_1_unknown_nonce_refused(target: &Target, http: &Http) -> CaseResult {
    const ID: &str = "spec_7_1_unknown_nonce_refused";
    const SPEC_REF: &str = "SPEC 7 rule 1";
    const TITLE: &str = "a syntactically valid, never-issued nonce is refused";

    let signer = crate::signers::ed25519_did_key();
    let challenge = match fetch_challenge(http, target, signer.signer_did()).await {
        Ok(r) => r,
        Err(e) => {
            return CaseResult::fail(
                ID,
                SPEC_REF,
                TITLE,
                format!("challenge request failed: {e}"),
            )
        }
    };
    let mut body = match sign_challenge(&challenge, &signer).await {
        Ok(b) => b,
        Err(e) => {
            return CaseResult::fail(
                ID,
                SPEC_REF,
                TITLE,
                format!("could not build a session request to tamper with: {e}"),
            )
        }
    };

    let Value::Object(map) = &mut body else {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            "the session request this harness built was not a JSON object, a bug in this \
             harness, not the target",
        );
    };
    let unknown_nonce = format!("0x{}", random_hex(32));
    map.insert("nonce".to_string(), Value::String(unknown_nonce.clone()));

    let response = match post_session(http, target, &body).await {
        Ok(r) => r,
        Err(e) => {
            return CaseResult::fail(ID, SPEC_REF, TITLE, format!("session request failed: {e}"))
        }
    };

    if session_accepted(&response) {
        CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "a nonce this server never issued ({unknown_nonce}) was accepted: {} {}",
                response.status,
                response.excerpt()
            ),
        )
    } else {
        CaseResult::pass(
            ID,
            SPEC_REF,
            TITLE,
            format!("refused with {} {}", response.status, response.excerpt()),
        )
    }
}

/// SPEC 7 rule 3, the most important case in this module: "the challenge is
/// removed from the store immediately upon validation (single-use). A
/// second request with the same nonce MUST be rejected."
///
/// Performs one full, real login, then re-submits the exact same
/// byte-identical session request body a second time. A server that does
/// not consume the challenge on first use mints a second, independent
/// session token from it, which is a session-fixation-adjacent bug: anyone
/// who observes one session request in flight (a proxy log, a browser
/// history, a misconfigured CORS setup) can replay it and mint their own
/// session for that identity, repeatedly, until the nonce's TTL lapses
/// (SPEC 7 rule 2).
///
/// If the happy-path login itself is not accepted, this reports
/// [`super::Outcome::Skip`], never `Fail`: rule 3 is unobservable without a
/// working first login, and blaming rule 3 for a rule-6-or-earlier failure
/// would misdirect whoever reads the report. `spec_6_4_session_response_shape`
/// in `cases_wire` already owns reporting on the happy path itself.
pub(crate) async fn spec_7_3_nonce_single_use(target: &Target, http: &Http) -> CaseResult {
    const ID: &str = "spec_7_3_nonce_single_use";
    const SPEC_REF: &str = "SPEC 7 rule 3";
    const TITLE: &str = "a spent nonce cannot mint a second session";

    let signer = crate::signers::ed25519_did_key();
    let flow = match login(http, target, &signer).await {
        Ok(f) => f,
        Err(e) => {
            return CaseResult::skip(
                ID,
                SPEC_REF,
                TITLE,
                format!(
                    "the happy-path login did not even complete, so single-use could not be \
                     observed: {e}"
                ),
            )
        }
    };

    if !session_accepted(&flow.session_response) {
        return CaseResult::skip(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "the happy-path login was not accepted ({} {}), so single-use could not be \
                 observed; spec_6_4_session_response_shape already owns reporting on the happy \
                 path itself",
                flow.session_response.status,
                flow.session_response.excerpt()
            ),
        );
    }
    let first_token = extract_token(&flow.session_response)
        .unwrap_or("<accepted with no token, unexpected>")
        .to_string();

    let replay = match post_session(http, target, &flow.session_request).await {
        Ok(r) => r,
        Err(e) => {
            return CaseResult::fail(
                ID,
                SPEC_REF,
                TITLE,
                format!("replay request itself failed: {e}"),
            )
        }
    };

    if session_accepted(&replay) {
        let second_token = extract_token(&replay).unwrap_or("<accepted with no token, unexpected>");
        CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "the server minted a SECOND session from one already-spent challenge: first \
                 token {first_token:?}, replay token {second_token:?} ({} {})",
                replay.status,
                replay.excerpt()
            ),
        )
    } else {
        CaseResult::pass(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "byte-identical replay refused with {} {}",
                replay.status,
                replay.excerpt()
            ),
        )
    }
}

/// SPEC 7 rule 4: "the DID namespace is one of `eip155`, `ed25519`, `p256`.
/// Any other namespace MUST return an error."
///
/// Uses `did:pkh:solana:0x` plus 64 fresh random hex characters: a namespace
/// SPEC 3's table never lists, so there is no ambiguity about whether it
/// ought to be accepted. Deliberately not `did:aqua`, see the module docs.
///
/// A conformant server may refuse this at `GET /auth/challenge` or, having
/// handed out a challenge anyway, at `POST /auth/session` with a
/// syntactically plausible but meaningless signature (see
/// [`refused_at_either_endpoint`]); only accepting at both is a failure.
pub(crate) async fn spec_7_4_unsupported_namespace_refused(
    target: &Target,
    http: &Http,
) -> CaseResult {
    const ID: &str = "spec_7_4_unsupported_namespace_refused";
    const SPEC_REF: &str = "SPEC 7 rule 4";
    const TITLE: &str = "an unsupported DID namespace is refused at challenge or session";

    let did = format!("did:pkh:solana:0x{}", random_hex(32));
    match refused_at_either_endpoint(http, target, &did).await {
        Ok(where_refused) => CaseResult::pass(ID, SPEC_REF, TITLE, where_refused),
        Err(what_was_accepted) => CaseResult::fail(ID, SPEC_REF, TITLE, what_was_accepted),
    }
}

/// SPEC 7 rule 5: "the DID passes namespace-specific format checks (correct
/// prefix, correct byte-length for the identifier)", read against SPEC 3's
/// per-namespace length table.
///
/// Table-driven over seven malformed shapes, one per plausible off-by-one or
/// off-by-format mistake a hand-rolled parser makes: wrong byte length in
/// both directions, a missing `0x`, a non-hex character, the p256 case where
/// a "reasonable" 32-byte length is still wrong because p256 keys are
/// compressed points (33 bytes, SPEC 3), an eip155 address short by one
/// byte, and a `did:key` whose multibase body cannot decode at all (built
/// from `0`, `O`, `I`, `l`, all excluded from the base58btc alphabet). Reports
/// ONE [`CaseResult`] for the whole table: Pass only if every single input
/// was refused, otherwise Fail naming exactly which ones were not, since
/// "DID validation is loose" is not actionable and "it accepted a 31-byte
/// ed25519 key" is.
///
/// The Pass detail also reports WHERE each shape was refused, challenge time
/// versus session time, both as a count and per shape. [`refused_at_either_endpoint`]
/// already carries this in its `Ok` string (`"refused at challenge time: ..."` or
/// `"challenge accepted (...) but session was refused: ..."`); this case only
/// has to keep it instead of discarding it. Against a server this suite has
/// source access to, that distinction is a curiosity: `aqua-auth`'s own history
/// is the proof. Before 2026-09-11, five of these seven shapes reached
/// `ChallengeStore::create` and were only ever refused inside
/// `authenticate_with_public_key`'s signature-verification path, at session
/// time, purely because a display helper happened to parse the identifier on
/// the way past (`src/did_format.rs:9-26`). Against a third-party server this
/// suite has no source for, the per-shape location is the only way an
/// operator learns whether rule 5 is its own enforcement layer or a side
/// effect of something else, which is exactly the distinction that let the
/// finding above go unnoticed until someone went looking.
pub(crate) async fn spec_7_5_did_well_formed(target: &Target, http: &Http) -> CaseResult {
    const ID: &str = "spec_7_5_did_well_formed";
    const SPEC_REF: &str = "SPEC 7 rule 5, SPEC 3";
    const TITLE: &str = "malformed DIDs are refused at challenge or session";

    let too_short_ed25519 = format!("did:pkh:ed25519:0x{}", random_hex(31)); // 62 hex chars, needs 64
    let too_long_ed25519 = format!("did:pkh:ed25519:0x{}", random_hex(33)); // 66 hex chars, needs 64
    let missing_0x_ed25519 = format!("did:pkh:ed25519:{}", random_hex(32)); // 64 hex chars, no 0x
    let non_hex_ed25519 = {
        let mut chars: Vec<char> = random_hex(32).chars().collect();
        chars[0] = 'z';
        let corrupted: String = chars.into_iter().collect();
        format!("did:pkh:ed25519:0x{corrupted}")
    };
    let too_short_p256 = format!("did:pkh:p256:0x{}", random_hex(32)); // 32-byte key, needs 33 compressed
    let too_short_eip155 = format!("did:pkh:eip155:1:0x{}", random_hex(19)); // 38 hex chars, needs 40
    let corrupted_did_key = "did:key:z6Mk0OIl0000CORRUPTEDMULTIBASE0000".to_string();

    let table: Vec<(&str, String)> = vec![
        ("ed25519 did:pkh, 31-byte key (needs 32)", too_short_ed25519),
        ("ed25519 did:pkh, 33-byte key (needs 32)", too_long_ed25519),
        ("ed25519 did:pkh, missing 0x prefix", missing_0x_ed25519),
        (
            "ed25519 did:pkh, non-hex character present",
            non_hex_ed25519,
        ),
        (
            "p256 did:pkh, 32-byte key (needs 33, compressed point)",
            too_short_p256,
        ),
        (
            "eip155 did:pkh, 19-byte address (needs 20)",
            too_short_eip155,
        ),
        (
            "did:key with a corrupted multibase body (0/O/I/l chars)",
            corrupted_did_key,
        ),
    ];

    let mut violations = Vec::new();
    let mut refusals: Vec<(&str, String)> = Vec::new();
    for (label, did) in &table {
        match refused_at_either_endpoint(http, target, did).await {
            Ok(where_refused) => refusals.push((label, where_refused)),
            Err(what_was_accepted) => {
                violations.push(format!("{label} ({did:?}): {what_was_accepted}"));
            }
        }
    }

    if violations.is_empty() {
        // `refused_at_either_endpoint` only ever produces one of these two
        // prefixes on `Ok` (see its doc comment), so this is a classification
        // of the text it already returns, not a second definition of where
        // "challenge time" and "session time" mean.
        let at_challenge = refusals
            .iter()
            .filter(|(_, where_refused)| where_refused.starts_with("refused at challenge time"))
            .count();
        let at_session = refusals.len() - at_challenge;
        let per_shape = refusals
            .iter()
            .map(|(label, where_refused)| format!("{label}: {where_refused}"))
            .collect::<Vec<_>>()
            .join("; ");
        CaseResult::pass(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "all {} malformed DID shapes were refused ({at_challenge} at challenge, \
                 {at_session} at session): {per_shape}",
                table.len(),
            ),
        )
    } else {
        CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "{} of {} malformed DID shapes were not refused: {}",
                violations.len(),
                table.len(),
                violations.join("; ")
            ),
        )
    }
}

/// The other half of SPEC 7 rule 5 / SPEC 3: every DID spelling the spec
/// calls valid MUST be accepted, not merely rejected when invalid. A
/// verifier that refuses every login is trivially safe against rule 5's
/// malformed-DID table above and is exactly as nonconformant as one that
/// accepts everything: this is the case that catches, for example, a server
/// that implemented `did:pkh` and forgot `did:key` (SPEC 3's "two spellings,
/// two principals" note), or one that only wired up `eip155` and never
/// finished the two Aqua-extension namespaces.
///
/// Iterates the five non-`did:aqua` signers `crate::signers` provides and
/// asserts `GET /auth/challenge` succeeds for each. `did:aqua` is
/// deliberately excluded here (feature-gated per SPEC 3, see the module
/// docs); this case has nothing to say about it either way.
pub(crate) async fn spec_7_5_valid_did_spellings_accepted(
    target: &Target,
    http: &Http,
) -> CaseResult {
    const ID: &str = "spec_7_5_valid_did_spellings_accepted";
    const SPEC_REF: &str = "SPEC 7 rule 5, SPEC 3";
    const TITLE: &str = "every SPEC 3 valid DID spelling is accepted at the challenge endpoint";

    let entries = vec![
        ("ed25519 did:key", crate::signers::ed25519_did_key()),
        ("ed25519 did:pkh", crate::signers::ed25519_did_pkh()),
        ("p256 did:key", crate::signers::p256_did_key()),
        ("p256 did:pkh", crate::signers::p256_did_pkh()),
        ("eip155 did:pkh", crate::signers::eip155()),
    ];

    let mut failures = Vec::new();
    for (label, signer) in &entries {
        match fetch_challenge(http, target, signer.signer_did()).await {
            Ok(response) if response.is_success() => {}
            Ok(response) => failures.push(format!(
                "{label} ({}) was refused: {} {}",
                signer.signer_did(),
                response.status,
                response.excerpt()
            )),
            Err(e) => failures.push(format!(
                "{label} ({}) request failed: {e}",
                signer.signer_did()
            )),
        }
    }

    if failures.is_empty() {
        CaseResult::pass(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "all {} valid spellings accepted (did:aqua excluded, feature-gated per SPEC 3)",
                entries.len()
            ),
        )
    } else {
        CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "{} of {} valid spellings were wrongly refused: {}",
                failures.len(),
                entries.len(),
                failures.join("; ")
            ),
        )
    }
}

/// Every case this module implements, in the order they run.
pub(crate) async fn all(target: &Target, http: &Http) -> Vec<CaseResult> {
    vec![
        spec_7_1_unknown_nonce_refused(target, http).await,
        spec_7_3_nonce_single_use(target, http).await,
        spec_7_4_unsupported_namespace_refused(target, http).await,
        spec_7_5_did_well_formed(target, http).await,
        spec_7_5_valid_did_spellings_accepted(target, http).await,
    ]
}
