//! A thin reqwest wrapper for the conformance suite.
//!
//! Two properties this module exists to guarantee:
//!
//! - the raw response body text is always kept, even when it parses as JSON,
//!   because a case that fails on "the body was not JSON at all" or "the
//!   body was JSON but not an object" needs to quote what it actually got;
//! - a dead or hanging target fails in seconds, not by blocking a test run
//!   indefinitely.
//!
//! Nothing here imports `aqua_auth::wire` or `aqua_auth::types`: responses
//! are handed back as [`serde_json::Value`], which is the whole point of this
//! module existing separately from `aqua_auth::client`.

use super::Target;
use serde_json::Value;
use std::fmt;
use std::time::Duration;

/// A dead or misbehaving target must fail a case quickly rather than hang a
/// test run. 10s is generous for a loopback target and short enough that a
/// genuinely unreachable remote target does not stall the suite.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// One HTTP response, with the raw body text preserved alongside whatever
/// [`serde_json::from_str`] made of it.
#[derive(Debug, Clone)]
pub(crate) struct HttpResponse {
    pub status: reqwest::StatusCode,
    /// The exact bytes the server sent, as text. Kept even when `json` is
    /// `Some`, because a case asserting on `json` still wants to be able to
    /// quote the raw body in its failure detail.
    pub text: String,
    /// `None` when `text` did not parse as JSON at all, which is itself a
    /// fact worth a case reporting rather than a reason to error out here.
    pub json: Option<Value>,
}

impl HttpResponse {
    /// A bounded excerpt of the raw body, for embedding in a [`super::CaseResult`]
    /// detail without dumping an entire body (an HTML error page, a huge JSON
    /// blob) into a one-line report.
    pub(crate) fn excerpt(&self) -> String {
        const MAX_CHARS: usize = 300;
        if self.text.chars().count() > MAX_CHARS {
            let truncated: String = self.text.chars().take(MAX_CHARS).collect();
            format!("{truncated}... [{} bytes total]", self.text.len())
        } else if self.text.is_empty() {
            "<empty body>".to_string()
        } else {
            self.text.clone()
        }
    }

    /// True for any 2xx.
    ///
    /// `SPEC.md` prescribes no status code for a successful `GET
    /// /auth/challenge` or `POST /auth/session`, and the two real Aqua
    /// servers surveyed for this task disagree with each other on session
    /// creation: aqua-node mints `201 Created`
    /// (`aqua-rest/src/routes.rs:247`, `(StatusCode::CREATED,
    /// Json(session)).into_response()`, pinned by its own test asserting
    /// "login must still mint 201"), while aquafier-rs's handler returns
    /// `Json<serde_json::Value>` with no status override, so axum's default
    /// `200 OK` applies. A conformance suite that hardcoded `== 200` would
    /// report a false `Fail` against aqua-node, which is exactly the kind of
    /// one-implementation self-reference this harness exists to eliminate:
    /// this crate's own reference router (`AquaPeer`) also happens to return
    /// 200 for both endpoints, so self-testing against it alone would never
    /// have caught this. Do not narrow this back to `== StatusCode::OK`.
    pub(crate) fn is_success(&self) -> bool {
        self.status.is_success()
    }
}

/// A request that never got a response at all: DNS failure, connection
/// refused, timeout, or a body that could not even be read as text. There is
/// no status and no body to quote, which is exactly why this is a distinct
/// variant from a case's own "unexpected status" failure: the latter has a
/// [`HttpResponse`] to describe, this does not.
#[derive(Debug)]
pub(crate) struct HttpError(String);

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "no usable response from the target: {}", self.0)
    }
}

impl std::error::Error for HttpError {}

/// The reqwest client, held once so connection pooling and the timeout
/// configuration apply across every case in a run.
pub(crate) struct Http {
    client: reqwest::Client,
}

impl Http {
    pub(crate) fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .expect("a reqwest client configured with only a timeout always builds");
        Self { client }
    }

    /// `GET {base}{challenge_path}?did=<did>` (SPEC 6.1).
    ///
    /// The DID is passed through reqwest's own query-parameter encoding
    /// rather than hand-built, so it goes through the same
    /// `application/x-www-form-urlencoded` percent-encoding SPEC 6.1
    /// describes for the reference client (colons become `%3A`) without this
    /// module having to reimplement it.
    pub(crate) async fn get_challenge(
        &self,
        target: &Target,
        did: &str,
    ) -> Result<HttpResponse, HttpError> {
        let url = format!("{}{}", target.base_url(), target.challenge_path());
        let response = self
            .client
            .get(&url)
            .query(&[("did", did)])
            .send()
            .await
            .map_err(|e| HttpError(e.to_string()))?;
        Self::into_http_response(response).await
    }

    /// `POST {base}{session_path}` with `body` as the JSON payload (SPEC 6.3).
    ///
    /// Takes a [`Value`] rather than a typed session-request struct on
    /// purpose: the adversarial cases (later tasks) build a valid body via
    /// [`super::sign_challenge`] and then mutate one field of the raw JSON
    /// before calling this, which a typed request body would make far more
    /// awkward to express.
    pub(crate) async fn post_session(
        &self,
        target: &Target,
        body: &Value,
    ) -> Result<HttpResponse, HttpError> {
        let url = format!("{}{}", target.base_url(), target.session_path());
        let response = self
            .client
            .post(&url)
            .json(body)
            .send()
            .await
            .map_err(|e| HttpError(e.to_string()))?;
        Self::into_http_response(response).await
    }

    async fn into_http_response(response: reqwest::Response) -> Result<HttpResponse, HttpError> {
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| HttpError(format!("could not read the response body: {e}")))?;
        let json = serde_json::from_str(&text).ok();
        Ok(HttpResponse { status, text, json })
    }
}
