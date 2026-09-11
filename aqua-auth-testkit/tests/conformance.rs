//! Driver and negative controls for `aqua_auth_testkit::conformance`.
//!
//! Every test in this file except one needs nothing but loopback
//! (`suite_is_green_against_the_reference_router`, the six `nc*` tests below,
//! and the two policy-gate tests): they run in every offline
//! `cargo test -p aqua-auth-testkit`. The one exception,
//! `conformance_against_configured_target`, reads `AQUA_CONFORMANCE_URL` and
//! skips cleanly, never failing, when it is unset.
//!
//! # Why the negative controls are the point of this file
//!
//! `suite_is_green_against_the_reference_router` proves almost nothing by
//! itself: `AquaPeer` is aqua-auth's own reference router, so a green run
//! there is the exact circularity
//! `docs/superpowers/plans/2026-09-11-caip122-conformance-harness.md`
//! describes as the reason this harness exists (the pre-existing e2e suites
//! drive `AquaPeer` with aqua-auth's own client and both ends import the same
//! wire type, so neither can ever see a server whose JSON drifts from
//! `SPEC.md`). What actually proves the suite can detect anything is that
//! each negative control below stands up a deliberately broken copy of
//! `AquaPeer`'s handlers (`aqua-auth-testkit/src/lib.rs`) and the suite is
//! shown to FAIL, naming the right case, against it.
//!
//! Every negative-control server below is free to use `aqua_auth::wire`,
//! `aqua_auth::types`, `ChallengeStore`, `SessionStore`, and does: they are
//! servers, not the judge. Only `aqua-auth-testkit/src/conformance/` (not
//! touched by this file) is required to share no wire types with the thing
//! it judges.

use aqua_auth_testkit::conformance::{run_all, Outcome, Report, Target, TargetError};
use aqua_auth_testkit::{signers, AquaPeer};

use aqua_auth::types::{Challenge, Session};
use aqua_auth::wire::{ChallengeEnvelope, SessionRequest, SessionResponse};
use aqua_auth::{
    authenticate_with_public_key, find_did_method, AuthError, ChallengeStore, SessionStore,
};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// Challenge TTL for every server in this file. Long enough that no test
/// here trips over it; `spec_7_2_challenge_expiry` skips by default anyway
/// (see its rustdoc in `cases_signature.rs`) since none of these tests set
/// `AQUA_CONFORMANCE_EXPIRY_WAIT`.
const CHALLENGE_TTL_SECS: u64 = 300;

/// Session TTL for every server in this file.
const SESSION_TTL_SECS: u64 = 3600;

// ── shared loopback plumbing, same bind-then-build order as
//    `AquaPeer::bind_loopback` and `e2e_loopback.rs`'s `bind`/`serve` ────────
//
// The order matters here for the same reason it matters there: a challenge's
// `URI:` line has to name the address the harness will actually dial, or
// `spec_6_2_uri_origin_matches_target` fails for every single negative
// control below, masking each one's real, intended defect behind an
// unrelated one.

async fn bind_loopback() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binding an ephemeral loopback port must succeed");
    let address = listener
        .local_addr()
        .expect("a bound listener has a local address");
    (listener, format!("http://{address}"))
}

fn serve(listener: TcpListener, router: Router) -> JoinHandle<()> {
    tokio::spawn(async move {
        // A shut-down listener is the normal end of a test, not a failure.
        let _ = axum::serve(listener, router).await;
    })
}

fn build_target(base_url: &str) -> Target {
    Target::new(base_url).expect("a loopback base_url must always pass the policy gate")
}

/// Find one case by id in a rendered [`Report`], panicking with the whole
/// report if it never ran at all (a harness bug, not a server defect).
fn outcome_of<'a>(report: &'a Report, id: &str) -> &'a Outcome {
    &report
        .cases
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("case {id:?} did not run at all:\n{}", report.render()))
        .outcome
}

/// Every [`Outcome::Fail`] case id in a report, for asserting on the whole
/// failing set at once (used where one defect legitimately cascades to more
/// than one case).
fn failing_ids(report: &Report) -> Vec<&'static str> {
    let mut ids: Vec<&'static str> = report.failures().map(|c| c.id).collect();
    ids.sort_unstable();
    ids
}

/// Mirrors `aqua-auth-testkit/src/lib.rs`'s own private `ChallengeQuery`:
/// this file is a separate crate (an integration test), so it cannot reuse
/// that type and defines its own copy instead.
#[derive(serde::Deserialize)]
struct ChallengeQuery {
    did: Option<String>,
}

/// Build a [`SessionResponse`] the same way every conformant handler in this
/// file does.
fn session_json(session: Session) -> Json<SessionResponse> {
    Json(SessionResponse {
        did: session.did,
        token: session.token,
        valid_until: session.valid_until,
        created_at: session.created_at,
    })
}

/// Decode `signature` and the optional `public_key`, the same way
/// `aqua-auth-testkit/src/lib.rs`'s `session_handler` does. Shared by every
/// negative control below except NC4, which never reaches this call at all
/// (that omission is NC4's entire defect).
fn decode_signature_and_key(
    request: &SessionRequest,
) -> Result<(Vec<u8>, Option<Vec<u8>>), StatusCode> {
    let signature = hex::decode(request.signature.trim_start_matches("0x"))
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let public_key = match request.public_key.as_deref() {
        Some(hex_pk) => Some(
            hex::decode(hex_pk.trim_start_matches("0x")).map_err(|_| StatusCode::UNAUTHORIZED)?,
        ),
        None => None,
    };
    Ok((signature, public_key))
}

// ── the fully conformant building blocks, reused by whichever negative
//    controls do not touch a given endpoint ─────────────────────────────────

#[derive(Clone)]
struct ConformantSessionState {
    challenges: Arc<ChallengeStore>,
    sessions: Arc<SessionStore>,
}

fn conformant_state(base_url: &str, name: &str) -> ConformantSessionState {
    ConformantSessionState {
        challenges: Arc::new(ChallengeStore::new(
            CHALLENGE_TTL_SECS,
            name.to_string(),
            base_url.to_string(),
        )),
        sessions: Arc::new(SessionStore::new(SESSION_TTL_SECS)),
    }
}

/// Byte-for-byte what `aqua-auth-testkit/src/lib.rs`'s `challenge_handler`
/// does: reject a missing or unsupported DID before minting, otherwise mint
/// and echo the envelope. Since `cf07f72` that envelope is three fields:
/// `wire::ChallengeEnvelope` no longer carries `did`, so this handler no
/// longer emits one. `nc2b_challenge_handler` below covers the shape both
/// DEPLOYED servers still serve, which does carry it.
async fn conformant_challenge_handler(
    State(state): State<ConformantSessionState>,
    Query(query): Query<ChallengeQuery>,
) -> Result<Json<ChallengeEnvelope>, StatusCode> {
    let did = query.did.ok_or(StatusCode::BAD_REQUEST)?;
    if find_did_method(&did).is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let challenge = state
        .challenges
        .create(&did)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(ChallengeEnvelope {
        nonce: challenge.nonce,
        message: challenge.message,
        expires_at: challenge.expires_at,
    }))
}

/// Byte-for-byte what `aqua-auth-testkit/src/lib.rs`'s `session_handler`
/// does: consume the challenge by nonce (single-use), check the DID it was
/// issued to, verify the signature, mint a session.
async fn conformant_session_handler(
    State(state): State<ConformantSessionState>,
    Json(request): Json<SessionRequest>,
) -> Result<Json<SessionResponse>, StatusCode> {
    let stored = match state.challenges.validate(&request.nonce) {
        Ok(challenge) => challenge,
        Err(AuthError::ChallengeNotFound) => return Err(StatusCode::NOT_FOUND),
        Err(_) => return Err(StatusCode::UNAUTHORIZED),
    };
    if stored.did != request.did {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let (signature, public_key) = decode_signature_and_key(&request)?;
    let principal = authenticate_with_public_key(
        &request.did,
        &stored.message,
        &signature,
        public_key.as_deref(),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let session = state
        .sessions
        .create(principal.did())
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(session_json(session))
}

// ── the env-var driver (H6, H7) ──────────────────────────────────────────

/// Judge whatever server `AQUA_CONFORMANCE_URL` names.
///
/// MUST NOT fail when the variable is unset or empty: an offline
/// `cargo test -p aqua-auth-testkit` has to stay green with no server
/// running anywhere. Set `AQUA_CONFORMANCE_URL` (and, if the server nests its
/// routes under a prefix, `AQUA_CONFORMANCE_CHALLENGE_PATH` /
/// `AQUA_CONFORMANCE_SESSION_PATH`) to actually run this against a live
/// deployment; set `AQUA_CONFORMANCE_ALLOW_REMOTE=1` too if that URL is not
/// loopback.
#[tokio::test]
async fn conformance_against_configured_target() {
    let url = match std::env::var("AQUA_CONFORMANCE_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => {
            println!(
                "SKIP: AQUA_CONFORMANCE_URL is not set (or is empty), so there is no live \
                 server to judge. Set it to a base URL, e.g.\n\
                 \n    AQUA_CONFORMANCE_URL=http://127.0.0.1:3000 cargo test -p \
                 aqua-auth-testkit --test conformance -- --ignored\n\
                 \n\
                 to run this suite against a real Aqua server. Optional overrides:\n\
                 - AQUA_CONFORMANCE_CHALLENGE_PATH, AQUA_CONFORMANCE_SESSION_PATH (default \
                 /auth/challenge, /auth/session)\n\
                 - AQUA_CONFORMANCE_ALLOW_REMOTE=1, required if the URL is not loopback\n\
                 - AQUA_CONFORMANCE_EXPIRY_WAIT=1, to actually wait out a challenge's TTL for \
                 the SPEC 7 rule 2 case instead of skipping it"
            );
            return;
        }
    };

    let mut target = Target::new(&url).unwrap_or_else(|e| {
        panic!("AQUA_CONFORMANCE_URL={url:?} could not be used as a conformance target: {e}")
    });
    let challenge_path = std::env::var("AQUA_CONFORMANCE_CHALLENGE_PATH").ok();
    let session_path = std::env::var("AQUA_CONFORMANCE_SESSION_PATH").ok();
    if challenge_path.is_some() || session_path.is_some() {
        target = target.with_paths(
            challenge_path.as_deref().unwrap_or("/auth/challenge"),
            session_path.as_deref().unwrap_or("/auth/session"),
        );
    }

    let report = run_all(&target).await;
    // Printed on success too, not only on failure: a green run against a
    // real deployment is exactly the artifact worth keeping in CI output.
    println!("{}", report.render());
    assert!(
        report.passed(),
        "conformance run against {url:?} reported at least one Fail; full report:\n{}",
        report.render()
    );
}

// ── the local reference run (H1, H2, H8, H10) ────────────────────────────

/// The suite, against its own reference router, on loopback. This is the
/// suite's default target: no env var, no credentials, no network beyond
/// loopback, since every signer it uses is generated on the spot by
/// `crate::signers`.
///
/// A green run here is necessary but not sufficient, see the module docs:
/// `AquaPeer` is aqua-auth's own router, so this alone cannot prove the
/// suite can detect drift from `SPEC.md`. The `nc*` tests below are what
/// prove that.
#[tokio::test]
async fn suite_is_green_against_the_reference_router() {
    let (_peer, base_url, server) = AquaPeer::bind_loopback(
        "reference-peer",
        CHALLENGE_TTL_SECS,
        signers::ed25519_did_key(),
    )
    .await;
    let target = build_target(&base_url);

    let report = run_all(&target).await;
    println!("{}", report.render());

    let fails = failing_ids(&report);
    assert!(
        fails.is_empty(),
        "the suite must be green (Pass or Skip, never Fail) against its own reference router, \
         got failures {fails:?}:\n{}",
        report.render()
    );

    server.abort();
}

// ── NC1: challenge not consumed ──────────────────────────────────────────

/// NC1: the challenge is looked up without being removed, so the same nonce
/// authenticates twice.
///
/// Real-world shape this imitates: a `DashMap::remove` swapped for a
/// non-removing read (`.get`) during a refactor, for example adding a
/// read-through cache or moving to a store with a separate read replica,
/// where consumption was meant to move to a cleanup pass that never
/// shipped. Every other behaviour here matches
/// `aqua-auth-testkit/src/lib.rs`'s real handlers exactly (DID/namespace
/// validation, real signature verification, real DID matching): a suite
/// that could not catch this could not have caught the shipped bug either.
#[derive(Clone)]
struct Nc1State {
    challenges: Arc<ChallengeStore>,
    /// THE DEFECT lives in how this map is read at session time: every
    /// challenge is inserted here and NEVER removed, so a later `.get`
    /// (never `.remove`) always finds it again.
    issued: Arc<Mutex<HashMap<String, Challenge>>>,
    sessions: Arc<SessionStore>,
}

async fn nc1_challenge_handler(
    State(state): State<Nc1State>,
    Query(query): Query<ChallengeQuery>,
) -> Result<Json<ChallengeEnvelope>, StatusCode> {
    let did = query.did.ok_or(StatusCode::BAD_REQUEST)?;
    if find_did_method(&did).is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let challenge = state
        .challenges
        .create(&did)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    state
        .issued
        .lock()
        .unwrap()
        .insert(challenge.nonce.clone(), challenge.clone());
    Ok(Json(ChallengeEnvelope {
        nonce: challenge.nonce,
        message: challenge.message,
        expires_at: challenge.expires_at,
    }))
}

async fn nc1_session_handler(
    State(state): State<Nc1State>,
    Json(request): Json<SessionRequest>,
) -> Result<Json<SessionResponse>, StatusCode> {
    // THE DEFECT: `.get(...).cloned()` peeks without consuming. The
    // conforming handler this replaces is `conformant_session_handler`
    // above, which calls `state.challenges.validate(&nonce)`, and removal is
    // exactly what `validate` does that a peek does not.
    let stored = {
        let issued = state.issued.lock().unwrap();
        issued.get(&request.nonce).cloned()
    }
    .ok_or(StatusCode::NOT_FOUND)?;

    if stored.did != request.did {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let (signature, public_key) = decode_signature_and_key(&request)?;
    let principal = authenticate_with_public_key(
        &request.did,
        &stored.message,
        &signature,
        public_key.as_deref(),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let session = state
        .sessions
        .create(principal.did())
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(session_json(session))
}

fn nc1_router(base_url: &str) -> Router {
    let state = Nc1State {
        challenges: Arc::new(ChallengeStore::new(
            CHALLENGE_TTL_SECS,
            "nc1".to_string(),
            base_url.to_string(),
        )),
        issued: Arc::new(Mutex::new(HashMap::new())),
        sessions: Arc::new(SessionStore::new(SESSION_TTL_SECS)),
    };
    Router::new()
        .route("/auth/challenge", get(nc1_challenge_handler))
        .route("/auth/session", post(nc1_session_handler))
        .with_state(state)
}

#[tokio::test]
async fn nc1_challenge_not_consumed_fails_nonce_single_use_only() {
    let (listener, base_url) = bind_loopback().await;
    let server = serve(listener, nc1_router(&base_url));
    let target = build_target(&base_url);

    let report = run_all(&target).await;
    println!("{}", report.render());

    assert_eq!(
        *outcome_of(&report, "spec_7_3_nonce_single_use"),
        Outcome::Fail,
        "a non-consuming challenge lookup must fail the single-use case:\n{}",
        report.render()
    );
    assert_eq!(
        failing_ids(&report),
        vec!["spec_7_3_nonce_single_use"],
        "no other case should fail: nonce-to-message binding, DID matching and signature \
         verification are all untouched by this defect:\n{}",
        report.render()
    );

    server.abort();
}

// ── NC2: envelope omits `did` entirely (H2) ──────────────────────────────

/// NC2: the challenge envelope carries only `nonce`, `message` and
/// `expires_at`, no `did` field at all.
///
/// This is the single most important negative control in this file. On the
/// day this harness was written, `did` was simultaneously being ADDED to
/// `aqua_auth::wire::ChallengeEnvelope` on this branch's own history
/// (`1ef890f`) and REMOVED on a sibling worktree
/// (`docs/superpowers/plans/2026-09-11-caip122-conformance-harness.md`,
/// "Live hazard: the `did` field is contested right now"). A suite that
/// could not stay green against both directions at once would be actively
/// harmful: it would block whichever side it happened to disagree with, for
/// a field the plan's own hypothesis register (H2) says must never be
/// fatal. This test is the proof that omitting `did` fails NOTHING:
/// `spec_6_2_did_field` reports `Skip`, and `report.passed()` is `true`.
async fn nc2_challenge_handler(
    State(state): State<ConformantSessionState>,
    Query(query): Query<ChallengeQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let did = query.did.ok_or(StatusCode::BAD_REQUEST)?;
    if find_did_method(&did).is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let challenge = state
        .challenges
        .create(&did)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    // THE DEFECT: three fields only. No `did` key at all, not even `null`.
    Ok(Json(serde_json::json!({
        "nonce": challenge.nonce,
        "message": challenge.message,
        "expires_at": challenge.expires_at,
    })))
}

fn nc2_router(base_url: &str) -> Router {
    Router::new()
        .route("/auth/challenge", get(nc2_challenge_handler))
        .route("/auth/session", post(conformant_session_handler))
        .with_state(conformant_state(base_url, "nc2"))
}

#[tokio::test]
async fn nc2_did_less_envelope_fails_nothing() {
    let (listener, base_url) = bind_loopback().await;
    let server = serve(listener, nc2_router(&base_url));
    let target = build_target(&base_url);

    let report = run_all(&target).await;
    println!("{}", report.render());

    assert_eq!(
        *outcome_of(&report, "spec_6_2_did_field"),
        Outcome::Skip,
        "an absent `did` field must be Skip (honest 'cannot tell'), never Fail and never a false \
         Pass:\n{}",
        report.render()
    );
    assert!(
        report.passed(),
        "H2: dropping `did` from the envelope entirely must fail nothing at all, since both live \
         directions of the field's fate agree it must never be required:\n{}",
        report.render()
    );

    server.abort();
}

// ── NC2b: envelope CARRIES `did` (the other half of H2) ──────────────

/// NC2b: the challenge envelope carries `did` ALONGSIDE the three required
/// fields, which is what both deployed servers actually serve.
///
/// The mirror of NC2, and it exists because of what `cf07f72` did to this
/// file. Before that commit `wire::ChallengeEnvelope` had a `did` field, so
/// every conformant router here emitted one and the "extra field tolerated"
/// half of H2 was covered for free. `cf07f72` removed the field, all those
/// routers stopped emitting it, and that coverage silently vanished: after
/// the rebase, nothing in this file sent a `did` at all. A hypothesis that
/// says a field must be tolerated whether present or absent needs a control
/// on BOTH sides, so this restores the present side explicitly rather than
/// depending on the incidental shape of a type that just proved it can
/// change underneath us.
///
/// It is also the realistic case, not a hypothetical. Neither `aqua-node`
/// nor `aquafier-rs` serializes `wire::ChallengeEnvelope`: both do
/// `Json(challenge)` over `aqua_auth::types::Challenge`, which still has the
/// field. So every server this suite will actually be pointed at today
/// sends four fields, and `cf07f72` changed none of them. SPEC 6.2 is
/// explicit that this stays conformant: "Servers MAY continue to; clients
/// MUST ignore it."
async fn nc2b_challenge_handler(
    State(state): State<ConformantSessionState>,
    Query(query): Query<ChallengeQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let did = query.did.ok_or(StatusCode::BAD_REQUEST)?;
    if find_did_method(&did).is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let challenge = state
        .challenges
        .create(&did)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    // Four fields: the deployed shape, `did` included.
    Ok(Json(serde_json::json!({
        "did": challenge.did,
        "nonce": challenge.nonce,
        "message": challenge.message,
        "expires_at": challenge.expires_at,
    })))
}

fn nc2b_router(base_url: &str) -> Router {
    Router::new()
        .route("/auth/challenge", get(nc2b_challenge_handler))
        .route("/auth/session", post(conformant_session_handler))
        .with_state(conformant_state(base_url, "nc2b"))
}

#[tokio::test]
async fn nc2b_did_carrying_envelope_fails_nothing() {
    let (listener, base_url) = bind_loopback().await;
    let server = serve(listener, nc2b_router(&base_url));
    let target = build_target(&base_url);

    let report = run_all(&target).await;
    println!("{}", report.render());

    assert_eq!(
        *outcome_of(&report, "spec_6_2_did_field"),
        Outcome::Pass,
        "a `did` that is present AND matches the requested DID is the deployed shape and must \
         report Pass:\n{}",
        report.render()
    );
    assert!(
        report.passed(),
        "H2, present side: an envelope carrying `did` on top of the three required fields must \
         fail nothing. SPEC 8 requires unknown fields to be ignored, and SPEC 6.2 since cf07f72 \
         says servers MAY keep sending this one:\n{}",
        report.render()
    );

    server.abort();
}

// ── NC3: expires_at in milliseconds ──────────────────────────────────────

/// NC3: `expires_at` is emitted in milliseconds instead of the SPEC 6.2
/// Unix-seconds it must be.
///
/// Real-world shape: a duration computed as `Instant`/`SystemTime`
/// arithmetic that carries a stray `* 1000`, the classic seam where a
/// millisecond-based client convention (`Date.now()`) leaks into a
/// seconds-based wire contract. A millisecond value near "now" reads as
/// thousands of hours in the future, which is exactly what
/// `spec_6_2_expires_at_sane`'s 24h bound exists to catch.
async fn nc3_challenge_handler(
    State(state): State<ConformantSessionState>,
    Query(query): Query<ChallengeQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let did = query.did.ok_or(StatusCode::BAD_REQUEST)?;
    if find_did_method(&did).is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let challenge = state
        .challenges
        .create(&did)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(serde_json::json!({
        "did": challenge.did,
        "nonce": challenge.nonce,
        "message": challenge.message,
        // THE DEFECT: seconds multiplied by 1000, emitted as if they were
        // already milliseconds.
        "expires_at": challenge.expires_at * 1000,
    })))
}

fn nc3_router(base_url: &str) -> Router {
    Router::new()
        .route("/auth/challenge", get(nc3_challenge_handler))
        .route("/auth/session", post(conformant_session_handler))
        .with_state(conformant_state(base_url, "nc3"))
}

#[tokio::test]
async fn nc3_millisecond_expires_at_fails_expires_at_sane_only() {
    let (listener, base_url) = bind_loopback().await;
    let server = serve(listener, nc3_router(&base_url));
    let target = build_target(&base_url);

    let report = run_all(&target).await;
    println!("{}", report.render());

    assert_eq!(
        *outcome_of(&report, "spec_6_2_expires_at_sane"),
        Outcome::Fail,
        "a millisecond expires_at must fail the sanity case:\n{}",
        report.render()
    );
    assert_eq!(
        failing_ids(&report),
        vec!["spec_6_2_expires_at_sane"],
        "no other case should fail: the internal (seconds-based) ChallengeStore still enforces \
         real expiry and single-use correctly, only the wire value is wrong:\n{}",
        report.render()
    );

    server.abort();
}

// ── NC4: signature verification skipped entirely ─────────────────────────

/// NC4: `POST /auth/session` never looks at the challenge store, the nonce,
/// or the signature. It mints a session for whatever `did` the request
/// claims. This is a total login bypass: any string in `did` authenticates
/// as that identity.
///
/// Real-world shape: a verifier call short-circuited behind a debug flag
/// that shipped enabled, or a half-finished handler rewrite where the happy
/// path (mint a session) was wired up before its rejection path.
///
/// **This defect necessarily cascades past the two SPEC 7 rule 6 cases the
/// plan names it for.** Skipping verification also breaks nonce existence
/// (rule 1: an unknown nonce is accepted, since nothing checks it), single-use
/// (rule 3: a replay is accepted, since nothing is ever consumed) and message
/// binding (rule 7: a cross-challenge submission is accepted). That is not a
/// bug in this test; it is the correct diagnosis. Every one of those rules
/// is, in a conformant server, enforced by the same code path this server
/// removed, so a single defect that deletes that whole path fails every case
/// that depends on it. The assertion below is on the exact observed set, not
/// only the two named cases, precisely so a narrower, wrong failure set would
/// be caught as a finding rather than silently accepted.
///
/// `spec_7_5_did_well_formed` (SPEC 7 rule 5) is deliberately ABSENT from
/// that cascade, and its absence is itself the regression test for a finding
/// this negative control surfaced and `aqua-auth` has since fixed.
///
/// Confirmed empirically on 2026-09-11: before that date, this case DID join
/// the cascade. 5 of its 7 malformed-DID shapes were accepted by the real,
/// conformant `AquaPeer` handlers this crate ships
/// (`suite_is_green_against_the_reference_router` proves `AquaPeer` itself
/// passes rule 5 against a normal server), which meant `AquaPeer` was
/// refusing most of those shapes at SESSION time only, inside
/// `authenticate_with_public_key` noticing the malformed identifier while
/// verifying a signature, never at challenge time. Skip verification
/// entirely, as this server does, and that protection went with it: rule 5
/// held only as a side effect of rule 6 running.
///
/// That gap is closed. `aqua-auth`'s `validate_did_well_formed`
/// (`src/did_format.rs`) now enforces rule 5 at `ChallengeStore::create`
/// itself, so `conformant_challenge_handler`, which this server's router
/// still wires up unmodified for `GET /auth/challenge`
/// (`nc4_router`, above), refuses all seven shapes before a nonce is ever
/// minted, before `POST /auth/session` (this handler) is reachable at all.
/// A total verification bypass here can no longer take rule 5 down with it,
/// which is exactly the property `spec_7_5_did_well_formed` no longer
/// appearing in `expected_cascade` demonstrates.
///
/// **If `spec_7_5_did_well_formed` ever reappears in `expected_cascade`,
/// rule 5 has slid back into being a side effect of verification instead of
/// its own enforcement layer**, and that regression is exactly what this
/// test exists to catch. Treat a reappearance as the finding this rustdoc
/// once described, not as a test needing its expectation updated.
async fn nc4_session_handler(
    State(state): State<ConformantSessionState>,
    Json(request): Json<SessionRequest>,
) -> Result<Json<SessionResponse>, StatusCode> {
    // THE DEFECT: `state.challenges` is reachable (so the challenge endpoint
    // can still mint real challenges) but never consulted here. No nonce
    // lookup, no signature decode, no verification at all.
    let _ = &state.challenges;
    let session = state
        .sessions
        .create(&request.did)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(session_json(session))
}

fn nc4_router(base_url: &str) -> Router {
    Router::new()
        .route("/auth/challenge", get(conformant_challenge_handler))
        .route("/auth/session", post(nc4_session_handler))
        .with_state(conformant_state(base_url, "nc4"))
}

#[tokio::test]
async fn nc4_skipped_verification_fails_both_signature_cases_and_its_cascade() {
    let (listener, base_url) = bind_loopback().await;
    let server = serve(listener, nc4_router(&base_url));
    let target = build_target(&base_url);

    let report = run_all(&target).await;
    println!("{}", report.render());

    let fails = failing_ids(&report);

    assert_eq!(
        *outcome_of(&report, "spec_7_6_signature_invalid_refused"),
        Outcome::Fail,
        "a corrupted signature must be accepted (wrongly) when verification is skipped:\n{}",
        report.render()
    );
    assert_eq!(
        *outcome_of(&report, "spec_7_6_wrong_key_refused"),
        Outcome::Fail,
        "a signature from an unrelated key must be accepted (wrongly) when verification is \
         skipped:\n{}",
        report.render()
    );

    // The observed cascade, asserted on the whole set (see the rustdoc
    // above): every rule enforced by the removed code path fails alongside
    // the two named cases. If a future change to this server or to the case
    // set narrows or widens this set, this assertion is meant to catch that
    // as a finding, not silently pass.
    let mut expected_cascade = vec![
        "spec_6_3_public_key_binding",
        "spec_7_1_unknown_nonce_refused",
        "spec_7_3_nonce_single_use",
        "spec_7_6_signature_invalid_refused",
        "spec_7_6_wrong_key_refused",
        "spec_7_7_message_binding",
    ];
    expected_cascade.sort_unstable();
    assert_eq!(
        fails,
        expected_cascade,
        "the observed failing set for a total verification bypass must be exactly this cascade, \
         no more and no less (spec_7_5_did_well_formed's ABSENCE here is itself the regression \
         test, see the rustdoc above):\n{}",
        report.render()
    );

    server.abort();
}

// ── NC5: nonce emitted uppercase ──────────────────────────────────────────

/// NC5: the nonce is uppercased everywhere it appears on the wire, both the
/// envelope's top-level `nonce` field AND the `Nonce:` line inside `message`
/// (so the challenge stays internally self-consistent, a conformant client
/// signs exactly the `message` string it was handed). Session-time
/// verification still succeeds: the same uppercase nonce is used
/// consistently as the lookup key, and the signed message still matches
/// byte for byte. Only the wire-format case should notice.
///
/// Real-world shape: a `to_uppercase()` call, or a `{:X}` format specifier
/// used instead of `{:x}`, applied on the way out to the wire type.
#[derive(Clone)]
struct Nc5State {
    /// Keyed by the (uppercased) nonce actually handed to the client, since
    /// the real `ChallengeStore` this is built from always stores by the
    /// original lowercase nonce internally and exposes no way to relabel a
    /// key.
    issued: Arc<Mutex<HashMap<String, Challenge>>>,
    challenges: Arc<ChallengeStore>,
    sessions: Arc<SessionStore>,
}

async fn nc5_challenge_handler(
    State(state): State<Nc5State>,
    Query(query): Query<ChallengeQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let did = query.did.ok_or(StatusCode::BAD_REQUEST)?;
    if find_did_method(&did).is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let challenge = state
        .challenges
        .create(&did)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // THE DEFECT: uppercase the nonce, and rewrite the one line inside
    // `message` where it also appears, so the envelope's `nonce` field and
    // the message's own `Nonce:` line keep agreeing with each other (see
    // `cases_wire.rs`'s `spec_6_2_message_structure`, which checks exactly
    // that binding and would otherwise fail for an unrelated reason).
    let upper_nonce = challenge.nonce.to_uppercase();
    let rewritten_message = challenge.message.replacen(
        &format!("Nonce: {}", challenge.nonce),
        &format!("Nonce: {upper_nonce}"),
        1,
    );

    state.issued.lock().unwrap().insert(
        upper_nonce.clone(),
        Challenge {
            did: challenge.did.clone(),
            nonce: upper_nonce.clone(),
            message: rewritten_message.clone(),
            expires_at: challenge.expires_at,
        },
    );

    Ok(Json(serde_json::json!({
        "did": challenge.did,
        "nonce": upper_nonce,
        "message": rewritten_message,
        "expires_at": challenge.expires_at,
    })))
}

async fn nc5_session_handler(
    State(state): State<Nc5State>,
    Json(request): Json<SessionRequest>,
) -> Result<Json<SessionResponse>, StatusCode> {
    let stored = state
        .issued
        .lock()
        .unwrap()
        .remove(&request.nonce)
        .ok_or(StatusCode::NOT_FOUND)?;
    if stored.did != request.did {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let (signature, public_key) = decode_signature_and_key(&request)?;
    let principal = authenticate_with_public_key(
        &request.did,
        &stored.message,
        &signature,
        public_key.as_deref(),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let session = state
        .sessions
        .create(principal.did())
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(session_json(session))
}

fn nc5_router(base_url: &str) -> Router {
    let state = Nc5State {
        issued: Arc::new(Mutex::new(HashMap::new())),
        challenges: Arc::new(ChallengeStore::new(
            CHALLENGE_TTL_SECS,
            "nc5".to_string(),
            base_url.to_string(),
        )),
        sessions: Arc::new(SessionStore::new(SESSION_TTL_SECS)),
    };
    Router::new()
        .route("/auth/challenge", get(nc5_challenge_handler))
        .route("/auth/session", post(nc5_session_handler))
        .with_state(state)
}

#[tokio::test]
async fn nc5_uppercase_nonce_fails_nonce_format_only() {
    let (listener, base_url) = bind_loopback().await;
    let server = serve(listener, nc5_router(&base_url));
    let target = build_target(&base_url);

    let report = run_all(&target).await;
    println!("{}", report.render());

    assert_eq!(
        *outcome_of(&report, "spec_6_2_nonce_format"),
        Outcome::Fail,
        "an uppercase nonce must fail the lowercase-hex format case:\n{}",
        report.render()
    );
    assert_eq!(
        failing_ids(&report),
        vec!["spec_6_2_nonce_format"],
        "no other case should fail: the nonce is used consistently (as the same uppercase \
         string) everywhere it matters for verification, so single-use, message binding and \
         signature checks all still hold:\n{}",
        report.render()
    );

    server.abort();
}

// ── NC6: challenge looked up by DID, not by nonce ────────────────────────

/// NC6: session validation retrieves the MOST RECENTLY issued challenge for
/// the claimed DID and verifies the signature against that, ignoring
/// whatever `nonce` value the client actually submitted.
///
/// `SPEC.md` calls SPEC 7 rule 7 (message binding) "enforced implicitly...
/// holds by construction," which is true only while the server's lookup key
/// is the nonce (see the plan doc, "Why the negative controls are the
/// load-bearing part"). A server keyed by DID instead still "verifies
/// against a message it built," so it satisfies the letter of that note
/// while violating the rule: it accepts a signature over a message that is
/// not the one the submitted nonce actually names, as long as some other,
/// more recent challenge for the same DID happens to carry that message.
///
/// Real-world shape: a server that indexes challenges primarily by DID for
/// an operational reason (rate limiting logins, "only one pending login per
/// user," a "cancel my other pending logins" feature) and treats the nonce
/// as an opaque echo rather than as the actual lookup key.
///
/// **This also cascades to SPEC 7 rule 1**
/// (`spec_7_1_unknown_nonce_refused`): that case swaps in a nonce nobody
/// issued while leaving a genuinely valid signature and DID untouched, and a
/// DID-keyed lookup accepts it for the identical reason it accepts the
/// cross-challenge submission: it never looks at the submitted nonce at all.
/// Both failures share one root cause, asserted on the set below rather than
/// only on the case the plan names.
#[derive(Clone)]
struct Nc6State {
    /// Keyed by DID, overwritten by every fresh `create` for that DID,
    /// removed on the first successful validation. THE DEFECT is this map's
    /// key: a conformant lookup is keyed by nonce (see `Nc1State::issued` or
    /// the real `ChallengeStore`), never by DID.
    most_recent: Arc<Mutex<HashMap<String, Challenge>>>,
    challenges: Arc<ChallengeStore>,
    sessions: Arc<SessionStore>,
}

async fn nc6_challenge_handler(
    State(state): State<Nc6State>,
    Query(query): Query<ChallengeQuery>,
) -> Result<Json<ChallengeEnvelope>, StatusCode> {
    let did = query.did.ok_or(StatusCode::BAD_REQUEST)?;
    if find_did_method(&did).is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let challenge = state
        .challenges
        .create(&did)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    state
        .most_recent
        .lock()
        .unwrap()
        .insert(did.clone(), challenge.clone());
    Ok(Json(ChallengeEnvelope {
        nonce: challenge.nonce,
        message: challenge.message,
        expires_at: challenge.expires_at,
    }))
}

async fn nc6_session_handler(
    State(state): State<Nc6State>,
    Json(request): Json<SessionRequest>,
) -> Result<Json<SessionResponse>, StatusCode> {
    // THE DEFECT: looked up by `request.did`. `request.nonce` is never read
    // anywhere in this function.
    let stored = state
        .most_recent
        .lock()
        .unwrap()
        .remove(&request.did)
        .ok_or(StatusCode::NOT_FOUND)?;
    let (signature, public_key) = decode_signature_and_key(&request)?;
    let principal = authenticate_with_public_key(
        &request.did,
        &stored.message,
        &signature,
        public_key.as_deref(),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let session = state
        .sessions
        .create(principal.did())
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(session_json(session))
}

fn nc6_router(base_url: &str) -> Router {
    let state = Nc6State {
        most_recent: Arc::new(Mutex::new(HashMap::new())),
        challenges: Arc::new(ChallengeStore::new(
            CHALLENGE_TTL_SECS,
            "nc6".to_string(),
            base_url.to_string(),
        )),
        sessions: Arc::new(SessionStore::new(SESSION_TTL_SECS)),
    };
    Router::new()
        .route("/auth/challenge", get(nc6_challenge_handler))
        .route("/auth/session", post(nc6_session_handler))
        .with_state(state)
}

#[tokio::test]
async fn nc6_challenge_looked_up_by_did_fails_message_binding_and_its_cascade() {
    let (listener, base_url) = bind_loopback().await;
    let server = serve(listener, nc6_router(&base_url));
    let target = build_target(&base_url);

    let report = run_all(&target).await;
    println!("{}", report.render());

    assert_eq!(
        *outcome_of(&report, "spec_7_7_message_binding"),
        Outcome::Fail,
        "looking a challenge up by DID instead of by nonce must fail the message-binding case, \
         the realistic shape of a SPEC 7 rule 7 violation:\n{}",
        report.render()
    );

    // The observed cascade, asserted on the whole set (see the rustdoc
    // above): a lookup that ignores the submitted nonce necessarily also
    // accepts an unknown one.
    let mut expected_cascade = vec!["spec_7_1_unknown_nonce_refused", "spec_7_7_message_binding"];
    expected_cascade.sort_unstable();
    assert_eq!(
        failing_ids(&report),
        expected_cascade,
        "the observed failing set for a DID-keyed lookup must be exactly this cascade, no more \
         and no less; in particular spec_7_3_nonce_single_use must still Pass, since this \
         server does consume the DID's pending challenge on first successful use, just under \
         the wrong key:\n{}",
        report.render()
    );

    server.abort();
}

// ── the policy gate, end to end (H7) ──────────────────────────────────────

/// `Target::new` refuses a non-loopback host when `AQUA_CONFORMANCE_ALLOW_REMOTE`
/// is not set, and the refusal is a construction error, before any request
/// is ever built.
///
/// `aqua-auth-testkit/src/conformance/mod.rs` already unit-tests the gate's
/// entire boolean decision directly against `check_host`, without touching
/// process environment variables, specifically because Rust runs tests on
/// multiple threads and a test that mutates
/// `AQUA_CONFORMANCE_ALLOW_REMOTE` around an assertion would race every
/// other test in the process. That coverage stays where it is (`mod.rs`'s
/// `target_policy_gate_tests`); this test does not duplicate it or mutate
/// the environment at all. Instead it asserts the OBSERVABLE behaviour of
/// the public `Target::new` constructor under this test binary's ambient
/// environment: no test in this file ever sets
/// `AQUA_CONFORMANCE_ALLOW_REMOTE` (doing so would defeat the entire point
/// of every other test here staying on loopback), so it is absent in
/// practice, and this test only relies on that, never forces it.
#[test]
fn target_new_refuses_a_non_loopback_host_without_the_opt_in() {
    // 203.0.113.0/24 is TEST-NET-3 (RFC 5737): reserved for documentation
    // and guaranteed never to be a real, reachable service, so this test
    // does no DNS resolution and cannot flake on network state.
    let err = Target::new("http://203.0.113.7:9")
        .expect_err("a non-loopback host must be refused when the opt-in is not set");
    match err {
        TargetError::RemoteNotAllowed { host } => {
            assert_eq!(
                host, "203.0.113.7",
                "the refusal must name the exact host it refused"
            );
        }
        other => panic!("expected TargetError::RemoteNotAllowed, got {other:?}"),
    }
}

/// `with_paths` changes only the mount point, never the host, so it cannot
/// be used to route around the policy gate above.
///
/// `Target`'s `base_url`, `challenge_path` and `session_path` accessors are
/// `pub(crate)`: this file is compiled as its own external crate (an
/// integration test), so it has no way to read them directly and confirm
/// the host field is byte-for-byte unchanged after `with_paths`. The
/// observable proof instead: mount the real reference router under an
/// `/api` prefix, exactly the scenario `with_paths` exists for per its own
/// doc comment ("servers that nest the auth routes under a prefix"), and
/// run the full suite through it. `with_paths`'s signature,
/// `(mut self, challenge: &str, session: &str) -> Self`, takes no host,
/// port or scheme argument at all, so there is no argument through which it
/// could smuggle a different host past the gate that already ran inside
/// `Target::new`; this test is the outward, end-to-end confirmation that
/// requests still land on the SAME loopback address the gate already
/// approved; only the path changed.
#[tokio::test]
async fn with_paths_changes_only_the_mount_point_never_the_host() {
    let (listener, base_url) = bind_loopback().await;

    let peer = AquaPeer::in_memory(
        "nested-peer",
        &base_url,
        CHALLENGE_TTL_SECS,
        signers::ed25519_did_key(),
    );
    let nested = Router::new().nest("/api", peer.router());
    let server = serve(listener, nested);

    let target = build_target(&base_url).with_paths("/api/auth/challenge", "/api/auth/session");
    let report = run_all(&target).await;
    println!("{}", report.render());

    assert!(
        report.passed(),
        "with_paths must reach the nested mount at the SAME host the suite dialled (the gate \
         already approved that host inside build_target/Target::new above); a failure here \
         would mean the path override did not work, since with_paths's own signature makes a \
         host change impossible in principle:\n{}",
        report.render()
    );

    server.abort();
}
