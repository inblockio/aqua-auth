//! A CAIP-122 conformance harness: given only a base URL, judge whether the
//! HTTP service answering there conforms to `SPEC.md` sections 6 and 7.
//!
//! This is a test OF a server, not a test of aqua-auth. The e2e suites
//! elsewhere in this crate (`tests/e2e_inmemory.rs`, `tests/e2e_loopback.rs`)
//! drive `AquaPeer`, aqua-auth's own reference router, with aqua-auth's own
//! client, and both ends import `aqua_auth::wire::ChallengeEnvelope`. Shared-
//! type agreement is not spec agreement: those suites cannot see a server
//! whose JSON drifts from `SPEC.md` as long as the drift happens to match
//! what the crate's own type expects, which is exactly the class of bug that
//! motivated this module (two divergences found 2026-09-11, neither caught
//! by the existing suites). Every response here is therefore parsed with
//! [`serde_json::Value`] or a type local to this module, never with
//! `aqua_auth::wire` or `aqua_auth::types`. The only things imported from
//! aqua-auth on the assertion path are [`aqua_auth::signer::Signer`] and this
//! crate's own [`crate::signers`], which mint keys and are not wire shapes.
//!
//! # Layout
//!
//! - [`Target`]: the base URL under test, plus the policy gate that refuses a
//!   non-loopback host unless explicitly opted in.
//! - [`http`]: a thin reqwest wrapper that always keeps the raw response body
//!   text alongside whatever it parsed, because a case that fails on "the
//!   body was not JSON at all" is useless without a copy of what it got.
//! - [`cases_wire`]: the section 6 wire-shape cases.
//! - [`run_all`]: runs every case and collects a [`Report`].
//!
//! # Case naming
//!
//! Case ids are stable and name the rule they enforce (`spec_6_2_...`,
//! `spec_8_...`), never a generic counter, so a failure names the broken rule
//! without the reader cross-referencing anything.

use aqua_auth::signer::Signer;
use serde_json::{json, Value};
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

mod cases_nonce_and_did;
mod cases_signature;
mod cases_wire;
mod http;

pub(crate) use http::{Http, HttpError, HttpResponse};

/// The default SPEC section 6 challenge path.
const DEFAULT_CHALLENGE_PATH: &str = "/auth/challenge";
/// The default SPEC section 6 session path.
const DEFAULT_SESSION_PATH: &str = "/auth/session";

/// Environment variable that opts a run into targeting a non-loopback host.
/// Named so a `grep` for it in a shell history or a CI log is unambiguous
/// about what it does.
const ALLOW_REMOTE_ENV: &str = "AQUA_CONFORMANCE_ALLOW_REMOTE";

/// A server under test: a base URL plus the two paths SPEC section 6 mounts
/// its endpoints at.
///
/// Constructing one runs the loopback policy gate (see [`Target::new`]).
/// There is deliberately no way to build a `Target` that skips it: every
/// field is private, and the only entry points are `new` and `with_paths`,
/// the latter of which cannot change the host.
#[derive(Debug, Clone)]
pub struct Target {
    base_url: String,
    challenge_path: String,
    session_path: String,
}

/// Why a [`Target`] could not be constructed.
#[derive(Debug)]
pub enum TargetError {
    /// `base_url` did not parse as a URL at all.
    Parse(url::ParseError),
    /// The URL parsed but carries no host component (e.g. a `data:` URL).
    MissingHost,
    /// The host is not loopback and [`ALLOW_REMOTE_ENV`] is not set to `1`.
    ///
    /// This is the load-bearing safety rail: this suite signs real login
    /// attempts and posts them to whatever `base_url` names, and a
    /// misconfigured run must not be able to do that to a shared or
    /// production deployment by accident. `~/aquafire-rs`'s dev-aquafire box
    /// holds real Scribe transcripts behind this exact kind of URL; this gate
    /// is why pointing this suite at it takes a deliberate, separate action.
    RemoteNotAllowed {
        /// The refused host, exactly as parsed from `base_url`.
        host: String,
    },
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetError::Parse(e) => write!(f, "base_url did not parse as a URL: {e}"),
            TargetError::MissingHost => write!(f, "base_url has no host component"),
            TargetError::RemoteNotAllowed { host } => write!(
                f,
                "refusing non-loopback target host '{host}': this suite signs real login \
                 attempts and sends them to whatever base_url names, so pointing it at a \
                 shared or production deployment must be a deliberate act. Set the \
                 {ALLOW_REMOTE_ENV}=1 environment variable to opt in."
            ),
        }
    }
}

impl std::error::Error for TargetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TargetError::Parse(e) => Some(e),
            TargetError::MissingHost | TargetError::RemoteNotAllowed { .. } => None,
        }
    }
}

/// True if `host` (as returned by [`url::Url::host_str`], so an IPv6 address
/// still carries its `[...]` brackets) is loopback: `127.0.0.0/8`, `::1`, or
/// the literal string `localhost`.
///
/// Split out from [`check_host`] only to keep the IPv6-bracket handling in
/// one place; `check_host` is the function tests call, per the module's own
/// requirement that the gate be tested without mutating process environment
/// variables (Rust runs tests on multiple threads, so a test that sets and
/// unsets `ALLOW_REMOTE_ENV` around an assertion races every other test).
fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    unbracketed
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

/// The policy gate itself: loopback is always fine, anything else needs
/// `allow_remote`. Kept separate from [`Target::new`] so a unit test can
/// exercise both branches by passing a bool, rather than mutating
/// [`ALLOW_REMOTE_ENV`] and racing every other test in the process.
fn check_host(host: &str, allow_remote: bool) -> Result<(), TargetError> {
    if allow_remote || is_loopback_host(host) {
        Ok(())
    } else {
        Err(TargetError::RemoteNotAllowed {
            host: host.to_string(),
        })
    }
}

impl Target {
    /// Parse `base_url` and run the loopback policy gate.
    ///
    /// The gate runs here, inside `new`, before any [`http::Http`] value can
    /// exist and before any request is ever constructed: refusal is a
    /// property of construction, not of the first call. Defaults to SPEC
    /// section 6's paths, `/auth/challenge` and `/auth/session`; call
    /// [`Target::with_paths`] for a server that mounts them under a prefix.
    ///
    /// # Errors
    ///
    /// [`TargetError::Parse`] if `base_url` is not a URL,
    /// [`TargetError::MissingHost`] if it has no host, and
    /// [`TargetError::RemoteNotAllowed`] if the host is not loopback and
    /// [`ALLOW_REMOTE_ENV`] is not `"1"`.
    pub fn new(base_url: impl Into<String>) -> Result<Self, TargetError> {
        let base_url = base_url.into();
        let parsed = url::Url::parse(&base_url).map_err(TargetError::Parse)?;
        let host = parsed.host_str().ok_or(TargetError::MissingHost)?;

        let allow_remote = std::env::var(ALLOW_REMOTE_ENV)
            .map(|v| v == "1")
            .unwrap_or(false);
        check_host(host, allow_remote)?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            challenge_path: DEFAULT_CHALLENGE_PATH.to_string(),
            session_path: DEFAULT_SESSION_PATH.to_string(),
        })
    }

    /// Override the mount points for servers that nest the auth routes under
    /// a prefix. Cannot change the host, so it cannot be used to route around
    /// the policy gate.
    pub fn with_paths(mut self, challenge: &str, session: &str) -> Self {
        self.challenge_path = challenge.to_string();
        self.session_path = session.to_string();
        self
    }

    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
    }

    pub(crate) fn challenge_path(&self) -> &str {
        &self.challenge_path
    }

    pub(crate) fn session_path(&self) -> &str {
        &self.session_path
    }
}

/// The verdict on one case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The server does what the named rule requires.
    Pass,
    /// The server violates the named rule. Fails the run.
    Fail,
    /// The rule could not be exercised as a black box (e.g. it needs waiting
    /// out a TTL) or the field it covers is not yet settled spec-wide (the
    /// `did` field, see [`cases_wire::spec_6_2_did_field`]). Does not fail
    /// the run: a `Skip` is an honest "cannot tell", not a false pass.
    Skip,
}

/// The result of one case.
#[derive(Debug, Clone)]
pub struct CaseResult {
    /// Stable id naming the rule, e.g. `"spec_6_2_required_fields"`.
    pub id: &'static str,
    /// The `SPEC.md` section the rule comes from, e.g. `"SPEC 6.2"`.
    pub spec_ref: &'static str,
    /// One-line human description of the rule.
    pub title: &'static str,
    pub outcome: Outcome,
    /// Why: empty on an unremarkable pass, otherwise the specific field,
    /// value, or server response that drove the verdict. A `Fail` detail
    /// must be enough to act on without re-running the case by hand.
    pub detail: String,
}

impl CaseResult {
    pub(crate) fn pass(
        id: &'static str,
        spec_ref: &'static str,
        title: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id,
            spec_ref,
            title,
            outcome: Outcome::Pass,
            detail: detail.into(),
        }
    }

    pub(crate) fn fail(
        id: &'static str,
        spec_ref: &'static str,
        title: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id,
            spec_ref,
            title,
            outcome: Outcome::Fail,
            detail: detail.into(),
        }
    }

    pub(crate) fn skip(
        id: &'static str,
        spec_ref: &'static str,
        title: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id,
            spec_ref,
            title,
            outcome: Outcome::Skip,
            detail: detail.into(),
        }
    }
}

/// Every case's result from one [`run_all`].
pub struct Report {
    pub cases: Vec<CaseResult>,
}

impl Report {
    /// No case [`Outcome::Fail`]ed. A [`Outcome::Skip`] never fails a run:
    /// it means the rule could not be exercised, not that it was violated.
    pub fn passed(&self) -> bool {
        !self.cases.iter().any(|c| c.outcome == Outcome::Fail)
    }

    pub fn failures(&self) -> impl Iterator<Item = &CaseResult> {
        self.cases.iter().filter(|c| c.outcome == Outcome::Fail)
    }

    /// One line per case, id first, aligned into columns, for a human reading
    /// terminal output or a CI log.
    pub fn render(&self) -> String {
        use std::fmt::Write as _;

        let id_width = self.cases.iter().map(|c| c.id.len()).max().unwrap_or(0);
        let spec_ref_width = self
            .cases
            .iter()
            .map(|c| c.spec_ref.len())
            .max()
            .unwrap_or(0);

        let mut out = String::new();
        for case in &self.cases {
            let marker = match case.outcome {
                Outcome::Pass => "PASS",
                Outcome::Fail => "FAIL",
                Outcome::Skip => "SKIP",
            };
            let _ = write!(
                out,
                "{marker} {id:<id_width$}  {spec_ref:<spec_ref_width$}  {title}",
                id = case.id,
                spec_ref = case.spec_ref,
                title = case.title,
            );
            if !case.detail.is_empty() {
                let _ = write!(out, " : {}", case.detail);
            }
            out.push('\n');
        }
        out
    }
}

/// Run every implemented case against `target`.
pub async fn run_all(target: &Target) -> Report {
    let http = Http::new();
    let mut cases = cases_wire::all(target, &http).await;
    cases.extend(cases_nonce_and_did::all(target, &http).await);
    cases.extend(cases_signature::all(target, &http).await);
    Report { cases }
}

// ── the shared happy-path login, reused by every case that needs a working
//    session before it can assert anything, and by the adversarial cases in
//    later tasks that need to corrupt exactly one part of it ─────────────

/// Failure from the shared login helper below. Every variant carries enough
/// of the server's own response (or the reason there is none) that a case
/// can drop it straight into a [`CaseResult`] detail.
#[derive(Debug)]
pub(crate) enum LoginError {
    /// The GET or POST itself never got a response: DNS, connection refused,
    /// timeout.
    Http(HttpError),
    /// The challenge endpoint answered, but not with success.
    ChallengeStatus(HttpResponse),
    /// The challenge body could not be turned into something signable: not
    /// JSON, not an object, or missing `message` or `nonce`.
    ChallengeShape {
        response: HttpResponse,
        reason: &'static str,
    },
    /// The signer itself failed.
    Sign(String),
}

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoginError::Http(e) => write!(f, "{e}"),
            LoginError::ChallengeStatus(r) => {
                write!(
                    f,
                    "GET challenge returned {}, expected success: {}",
                    r.status,
                    r.excerpt()
                )
            }
            LoginError::ChallengeShape { response, reason } => {
                write!(f, "challenge response {reason}: {}", response.excerpt())
            }
            LoginError::Sign(e) => write!(f, "signer failed: {e}"),
        }
    }
}

/// Step 1 of the login: `GET` the challenge for `did`. Split out so a case
/// can inspect the raw response (every section 6.2 shape case does exactly
/// this) without running the rest of the login.
pub(crate) async fn fetch_challenge(
    http: &Http,
    target: &Target,
    did: &str,
) -> Result<HttpResponse, LoginError> {
    http.get_challenge(target, did)
        .await
        .map_err(LoginError::Http)
}

/// Step 2 of the login: sign a fetched challenge's `message`, embed its
/// `nonce`, and build the SPEC 6.3 session request body.
///
/// Takes the raw [`HttpResponse`] rather than a pre-validated envelope, so a
/// case handing this a 200 with a missing field gets back a descriptive
/// [`LoginError::ChallengeShape`] instead of a panic.
///
/// `public_key` is included only when `signer.public_key()` returns `Some`,
/// which per [`aqua_auth::signer::Signer`]'s own contract is `did:aqua` only:
/// every other namespace's verifier reaches the key through the DID or the
/// signature, so sending it would be an unknown field, not a required one.
pub(crate) async fn sign_challenge(
    challenge: &HttpResponse,
    signer: &Arc<dyn Signer>,
) -> Result<Value, LoginError> {
    if !challenge.is_success() {
        return Err(LoginError::ChallengeStatus(challenge.clone()));
    }
    let envelope = challenge.json.as_ref().ok_or(LoginError::ChallengeShape {
        response: challenge.clone(),
        reason: "was not valid JSON",
    })?;
    let message =
        envelope
            .get("message")
            .and_then(Value::as_str)
            .ok_or(LoginError::ChallengeShape {
                response: challenge.clone(),
                reason: "had no string `message` field",
            })?;
    let nonce =
        envelope
            .get("nonce")
            .and_then(Value::as_str)
            .ok_or(LoginError::ChallengeShape {
                response: challenge.clone(),
                reason: "had no string `nonce` field",
            })?;

    let signature = signer
        .sign(message)
        .await
        .map_err(|e| LoginError::Sign(e.to_string()))?;

    let mut body = json!({
        "did": signer.signer_did(),
        "nonce": nonce,
        "signature": format!("0x{}", hex::encode(signature)),
    });
    if let Some(public_key) = signer.public_key() {
        body["public_key"] = json!(format!("0x{}", hex::encode(public_key)));
    }
    Ok(body)
}

/// Step 3 of the login: `POST` a session request body, whether the exact one
/// [`sign_challenge`] built or a case's deliberately mutated copy of it.
///
/// Deliberately does not turn a non-2xx response into an `Err`: unlike the
/// challenge step, a rejected session submission is often the exact thing a
/// case is trying to observe (a tampered signature, a replayed nonce, a
/// cross-challenge submission, in later tasks), so the raw
/// [`HttpResponse`] is always handed back for the caller to judge. Only a
/// response that never arrived at all (`HttpError`, e.g. connection refused)
/// is a real error here.
pub(crate) async fn post_session(
    http: &Http,
    target: &Target,
    body: &Value,
) -> Result<HttpResponse, LoginError> {
    http.post_session(target, body)
        .await
        .map_err(LoginError::Http)
}

/// The full happy path: fetch, sign, submit, keeping every intermediate
/// value. Cases that only care about the end result call this; cases that
/// need to inspect or tamper with an intermediate value (the adversarial
/// cases in later tasks: nonce replay, signature corruption, cross-challenge
/// submission) call [`fetch_challenge`], [`sign_challenge`] and
/// [`post_session`] directly instead, exactly so they can get a valid body
/// and then corrupt one part of it before the final `POST`.
pub(crate) struct LoginFlow {
    /// The parsed challenge envelope (SPEC 6.2).
    ///
    /// Currently unread: no case needs the challenge back once the login has
    /// already completed, and the adversarial cases that DO inspect an
    /// envelope call [`fetch_challenge`] directly so they can act between
    /// the fetch and the signature. Kept because it costs a clone of a value
    /// this helper already holds, and a case that needs the pair is a
    /// plausible next addition.
    #[allow(dead_code)]
    pub challenge: Value,
    /// The session request body actually sent (SPEC 6.3).
    ///
    /// Read by `spec_7_3_nonce_single_use`
    /// (`cases_nonce_and_did.rs`), which re-POSTs this exact `Value` to
    /// prove a spent nonce cannot mint a second session. The replay has to
    /// be byte-identical to the body the server already accepted, which is
    /// why the sent body is kept rather than rebuilt.
    pub session_request: Value,
    /// The raw response to that request (SPEC 6.4 on success).
    pub session_response: HttpResponse,
}

pub(crate) async fn login(
    http: &Http,
    target: &Target,
    signer: &Arc<dyn Signer>,
) -> Result<LoginFlow, LoginError> {
    let challenge_response = fetch_challenge(http, target, signer.signer_did()).await?;
    let session_request = sign_challenge(&challenge_response, signer).await?;
    let session_response = post_session(http, target, &session_request).await?;

    // `sign_challenge` already proved this is `Some`, via the same
    // `ChallengeShape` check; re-deriving it here rather than threading the
    // parsed value through keeps the three steps independently callable with
    // their own simple signatures.
    let challenge = challenge_response
        .json
        .clone()
        .expect("sign_challenge succeeded, so the challenge body parsed as JSON");

    Ok(LoginFlow {
        challenge,
        session_request,
        session_response,
    })
}

/// Seconds since the Unix epoch. Saturates to 0 on a clock before 1970,
/// which has never been observed and would be a strange thing for a
/// conformance case to panic over.
pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod target_policy_gate_tests {
    use super::*;

    // Rust runs unit tests on multiple threads by default, so a test that
    // mutates `std::env` around an assertion races every other test in this
    // binary (including, on some platforms, tests in this same module run
    // concurrently). `check_host` is tested directly instead: it is the
    // entire policy decision, `Target::new` only adds URL parsing and an
    // `env::var` read around it.

    #[test]
    fn loopback_ipv4_is_accepted_without_the_opt_in() {
        assert!(check_host("127.0.0.1", false).is_ok());
        assert!(
            check_host("127.5.9.2", false).is_ok(),
            "the whole /8, not just .1"
        );
    }

    #[test]
    fn loopback_ipv6_is_accepted_without_the_opt_in() {
        assert!(check_host("::1", false).is_ok());
        // `url::Url::host_str` keeps the brackets for an IPv6 host.
        assert!(check_host("[::1]", false).is_ok());
    }

    #[test]
    fn localhost_is_accepted_without_the_opt_in() {
        assert!(check_host("localhost", false).is_ok());
        assert!(check_host("LOCALHOST", false).is_ok());
    }

    #[test]
    fn a_non_loopback_host_is_refused_without_the_opt_in() {
        let err = check_host("example.com", false).unwrap_err();
        match err {
            TargetError::RemoteNotAllowed { host } => assert_eq!(host, "example.com"),
            other => panic!("expected RemoteNotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn a_non_loopback_host_is_accepted_with_the_opt_in() {
        assert!(check_host("example.com", true).is_ok());
        // 203.0.113.0/24 is TEST-NET-3 (RFC 5737), reserved for
        // documentation and guaranteed never to be a real service. Test
        // literals here are deliberately unroutable: `check_host` is a pure
        // function that dials nothing, but a real host written into an
        // assertion that it IS permitted is one careless refactor away from
        // becoming a real request to someone's production box.
        assert!(check_host("203.0.113.7", true).is_ok());
    }

    #[test]
    fn target_new_rejects_an_unparseable_url() {
        let err = Target::new("not a url at all").unwrap_err();
        assert!(matches!(err, TargetError::Parse(_)));
    }

    #[test]
    fn target_new_accepts_loopback_regardless_of_the_environment() {
        // Deliberately does not touch `ALLOW_REMOTE_ENV`: loopback must be
        // fine whether or not the variable happens to be set in this process
        // by some other test or by the invoking shell.
        let target = Target::new("http://127.0.0.1:4000").expect("loopback must be accepted");
        assert_eq!(target.base_url(), "http://127.0.0.1:4000");
        assert_eq!(target.challenge_path(), DEFAULT_CHALLENGE_PATH);
        assert_eq!(target.session_path(), DEFAULT_SESSION_PATH);
    }

    #[test]
    fn with_paths_overrides_the_defaults_only() {
        let target = Target::new("http://127.0.0.1:4000")
            .unwrap()
            .with_paths("/api/auth/challenge", "/api/auth/session");
        assert_eq!(target.challenge_path(), "/api/auth/challenge");
        assert_eq!(target.session_path(), "/api/auth/session");
        assert_eq!(target.base_url(), "http://127.0.0.1:4000");
    }
}
