//! SPEC.md section 6 wire-shape cases, plus one section 8 case that is wire-
//! adjacent enough to belong here rather than in a rules module of its own.
//!
//! Every case below fetches its own fresh challenge (or runs its own fresh
//! login): cases share no mutable state, so one case's failure can never
//! cause another to report a false result. Each case also generates its own
//! signer via [`crate::signers`] rather than accepting one as a parameter,
//! since section 6 shape rules apply identically regardless of which
//! namespace exercises them and an ed25519 `did:key` signer is the cheapest
//! to generate.
//!
//! Status codes: every check below accepts any 2xx via
//! [`super::HttpResponse::is_success`], never a specific code. See that
//! method's rustdoc for why: SPEC.md prescribes no status code here, and the
//! two real Aqua servers surveyed for this task disagree with each other
//! (201 vs 200).

use super::{
    fetch_challenge, login, post_session, sign_challenge, unix_now, CaseResult, Http, Target,
};
use serde_json::Value;

/// SPEC 6.2: the challenge response MUST be a JSON object carrying `nonce`
/// (string), `message` (string) and `expires_at` (unsigned integer). These
/// three are asserted as MUST, unlike `did` below, because both live
/// directions of the in-flight `did` debate (see
/// [`spec_6_2_did_field`]'s rustdoc) agree on them.
pub(crate) async fn spec_6_2_required_fields(target: &Target, http: &Http) -> CaseResult {
    const ID: &str = "spec_6_2_required_fields";
    const SPEC_REF: &str = "SPEC 6.2";
    const TITLE: &str = "challenge response carries nonce, message, expires_at";

    let signer = crate::signers::ed25519_did_key();
    let response = match fetch_challenge(http, target, signer.signer_did()).await {
        Ok(r) => r,
        Err(e) => return CaseResult::fail(ID, SPEC_REF, TITLE, format!("request failed: {e}")),
    };
    if !response.is_success() {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "expected a 2xx, got {}: {}",
                response.status,
                response.excerpt()
            ),
        );
    }
    let Some(body) = response.json.as_ref() else {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!("response body was not JSON at all: {}", response.excerpt()),
        );
    };
    let Some(obj) = body.as_object() else {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "response body was JSON but not an object: {}",
                response.excerpt()
            ),
        );
    };

    match obj.get("nonce") {
        Some(Value::String(_)) => {}
        Some(other) => {
            return CaseResult::fail(
                ID,
                SPEC_REF,
                TITLE,
                format!("`nonce` is present but not a string: {other}"),
            )
        }
        None => return CaseResult::fail(ID, SPEC_REF, TITLE, "`nonce` field is missing"),
    }
    match obj.get("message") {
        Some(Value::String(_)) => {}
        Some(other) => {
            return CaseResult::fail(
                ID,
                SPEC_REF,
                TITLE,
                format!("`message` is present but not a string: {other}"),
            )
        }
        None => return CaseResult::fail(ID, SPEC_REF, TITLE, "`message` field is missing"),
    }
    match obj.get("expires_at") {
        Some(v) if v.is_u64() => {}
        Some(other) => {
            return CaseResult::fail(
                ID,
                SPEC_REF,
                TITLE,
                format!("`expires_at` is present but not an unsigned integer: {other}"),
            )
        }
        None => return CaseResult::fail(ID, SPEC_REF, TITLE, "`expires_at` field is missing"),
    }

    CaseResult::pass(ID, SPEC_REF, TITLE, "")
}

/// SPEC 6.2's `did` field: the server echoing the requested DID back in the
/// challenge response.
///
/// **This case never returns [`super::Outcome::Fail`].** The field's status
/// is unsettled in this repository's own history as of 2026-09-11: commit
/// `1ef890f` (this branch's base) makes `wire::ChallengeEnvelope` carry it
/// and states in `SPEC.md` 6.2 that "the field stays"; a same-day follow-up,
/// `cf07f72` on `feat/local-key-signer-and-session`, reverts that and drops
/// `did` from the section 6.2 table entirely, on the grounds that nothing
/// reads it (the client's identifier-binding check compares against the
/// *signer's own DID*, never an envelope field). Both directions agree the
/// field must never be REQUIRED: `cf07f72`'s SPEC text says so explicitly
/// ("MUST NOT require `did` to be present: one deployed server has never
/// sent it"), and `timestamp.inblock.io` is that deployed server. A
/// conformance suite has no business hard-failing a server for landing on
/// one side of a fight the spec itself had not settled network-wide at the
/// time this case was written. Absence, or a mismatch, is reported as
/// [`super::Outcome::Skip`] with the reason spelled out, so the report still
/// surfaces the fact without treating it as nonconformance.
pub(crate) async fn spec_6_2_did_field(target: &Target, http: &Http) -> CaseResult {
    const ID: &str = "spec_6_2_did_field";
    const SPEC_REF: &str = "SPEC 6.2";
    const TITLE: &str = "challenge response echoes the requested did (non-fatal, contested field)";

    let signer = crate::signers::ed25519_did_key();
    let requested_did = signer.signer_did();
    let response = match fetch_challenge(http, target, requested_did).await {
        Ok(r) => r,
        Err(e) => return CaseResult::skip(ID, SPEC_REF, TITLE, format!("could not even ask: {e}")),
    };

    let returned = response
        .json
        .as_ref()
        .and_then(|v| v.get("did"))
        .and_then(Value::as_str);

    match returned {
        Some(did) if did == requested_did => CaseResult::pass(ID, SPEC_REF, TITLE, ""),
        Some(did) => CaseResult::skip(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "server echoed a `did` field but it does not match the requested DID \
                 (requested {requested_did}, got {did}); reported, not failed, because \
                 SPEC 6.2 since cf07f72 says clients MUST ignore this field, so a wrong \
                 value cannot break a conformant client. The integrity property it hints \
                 at is enforced as a hard MUST elsewhere: spec_6_2_message_structure \
                 FAILS if the identifier inside `message`, which is the part that gets \
                 signed, disagrees with the requested DID"
            ),
        ),
        None => CaseResult::skip(
            ID,
            SPEC_REF,
            TITLE,
            "server did not echo a `did` field; contested field as of 2026-09-11, absence is \
             the spec-compliant choice under the newer of the two live revisions, not a \
             failure under either",
        ),
    }
}

/// SPEC 4.2 / 6.2: `nonce` is `0x` followed by exactly 64 lowercase hex
/// characters. Uppercase hex is explicitly a `Fail`, not a lenient pass: the
/// wire format is a fixed string shape, not "anything `hex::decode` would
/// accept case-insensitively".
pub(crate) async fn spec_6_2_nonce_format(target: &Target, http: &Http) -> CaseResult {
    const ID: &str = "spec_6_2_nonce_format";
    const SPEC_REF: &str = "SPEC 4.2, 6.2";
    const TITLE: &str = "nonce is 0x followed by exactly 64 lowercase hex chars";

    let signer = crate::signers::ed25519_did_key();
    let response = match fetch_challenge(http, target, signer.signer_did()).await {
        Ok(r) => r,
        Err(e) => return CaseResult::fail(ID, SPEC_REF, TITLE, format!("request failed: {e}")),
    };
    let Some(nonce) = response
        .json
        .as_ref()
        .and_then(|v| v.get("nonce"))
        .and_then(Value::as_str)
    else {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "no string `nonce` field in the response: {}",
                response.excerpt()
            ),
        );
    };

    if !is_well_formed_nonce(nonce) {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!("nonce {nonce:?} is not `0x` + exactly 64 lowercase hex characters"),
        );
    }
    CaseResult::pass(ID, SPEC_REF, TITLE, "")
}

fn is_well_formed_nonce(nonce: &str) -> bool {
    match nonce.strip_prefix("0x") {
        Some(hex_part) => {
            hex_part.len() == 64
                && hex_part
                    .chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        }
        None => false,
    }
}

/// SPEC 4.1-4.3: the `message` field matches the CAIP-122 template exactly,
/// line for line, and binds the envelope's own `nonce`.
///
/// The identifier on line 2 is computed independently of aqua-auth's own DID
/// parser (`src/key/mod.rs`'s `KeyMethod::address_for_message` strips the
/// `did:key:` prefix and nothing else): this case hardcodes that same rule
/// from SPEC section 3's table rather than calling into the crate, because
/// reusing the crate's own parser to check the crate's own output would
/// prove nothing about spec agreement, which is the entire defect this
/// module exists to not repeat.
///
/// Asserts `Version: 1` exactly and asserts the `Nonce:` line equals the
/// envelope's own `nonce` field: that binding is what stops a server from
/// handing out a message signed against one nonce while filing it under
/// another. For an ed25519 `did:key` DID, also asserts there is NO `Chain
/// ID:` line (SPEC 4.3: that line exists for `eip155` only).
pub(crate) async fn spec_6_2_message_structure(target: &Target, http: &Http) -> CaseResult {
    const ID: &str = "spec_6_2_message_structure";
    const SPEC_REF: &str = "SPEC 4.1, 4.2, 4.3";
    const TITLE: &str = "message matches the CAIP-122 template and binds the envelope's nonce";

    let signer = crate::signers::ed25519_did_key();
    let did = signer.signer_did();
    let Some(expected_identifier) = did.strip_prefix("did:key:") else {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!("harness signer DID {did:?} unexpectedly has no did:key: prefix"),
        );
    };

    let response = match fetch_challenge(http, target, did).await {
        Ok(r) => r,
        Err(e) => return CaseResult::fail(ID, SPEC_REF, TITLE, format!("request failed: {e}")),
    };
    let Some(json_body) = response.json.as_ref() else {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!("response body was not JSON: {}", response.excerpt()),
        );
    };
    let Some(message) = json_body.get("message").and_then(Value::as_str) else {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            "no string `message` field in the response",
        );
    };
    let Some(nonce) = json_body.get("nonce").and_then(Value::as_str) else {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            "no string `nonce` field in the response, cannot check the message binds it",
        );
    };

    let lines: Vec<&str> = message
        .split('\n')
        .map(|l| l.trim_end_matches('\r'))
        .collect();
    if lines.len() < 10 {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "message has only {} lines, the SPEC 4.1 template needs at least 10:\n{message}",
                lines.len()
            ),
        );
    }

    if !lines[0].ends_with("wants you to sign in with your Ed25519 account:") {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "line 1 must end with the fixed suffix for the Ed25519 method label, got {:?}",
                lines[0]
            ),
        );
    }
    if lines[1] != expected_identifier {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "line 2 identifier is {:?}, expected {:?} (the DID's did:key body, SPEC \
                 section 3)",
                lines[1], expected_identifier
            ),
        );
    }
    if !lines[2].is_empty() {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!("line 3 must be blank, got {:?}", lines[2]),
        );
    }
    if lines[3] != "Sign in to Aqua Node" {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "line 4 must be the fixed statement 'Sign in to Aqua Node', got {:?}",
                lines[3]
            ),
        );
    }
    if !lines[4].is_empty() {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!("line 5 must be blank, got {:?}", lines[4]),
        );
    }
    if !lines[5].starts_with("URI: ") {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!("line 6 must start with 'URI: ', got {:?}", lines[5]),
        );
    }
    if lines[6] != "Version: 1" {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!("line 7 must be exactly 'Version: 1', got {:?}", lines[6]),
        );
    }
    let expected_nonce_line = format!("Nonce: {nonce}");
    if lines[7] != expected_nonce_line {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "line 8 must bind the envelope's own nonce ({expected_nonce_line:?}), got {:?}; \
                 a message signed against one nonce while the envelope names another is the \
                 SPEC 7 rule 7 hole this line closes",
                lines[7]
            ),
        );
    }
    if !lines[8].starts_with("Issued At: ") {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!("line 9 must start with 'Issued At: ', got {:?}", lines[8]),
        );
    }
    if !lines[9].starts_with("Expiration Time: ") {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "line 10 must start with 'Expiration Time: ', got {:?}",
                lines[9]
            ),
        );
    }

    if lines.iter().any(|l| l.starts_with("Chain ID:")) {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            "message carries a 'Chain ID:' line for an ed25519 identity; SPEC 4.3 reserves \
             that line for eip155 only",
        );
    }

    CaseResult::pass(ID, SPEC_REF, TITLE, "")
}

/// SPEC 6.2: `expires_at` is a Unix-seconds timestamp strictly in the future
/// and within 24h of now.
///
/// The default TTL is 5 minutes (SPEC 6.2), so 24h is a deliberately wide
/// bound that tolerates a generous server-side TTL while still catching the
/// classic drift of a server emitting milliseconds instead of seconds: a
/// millisecond timestamp near "now" is roughly 1000x the correct value,
/// landing thousands of hours in the future, far outside this bound.
pub(crate) async fn spec_6_2_expires_at_sane(target: &Target, http: &Http) -> CaseResult {
    const ID: &str = "spec_6_2_expires_at_sane";
    const SPEC_REF: &str = "SPEC 6.2";
    const TITLE: &str = "expires_at is a future unix-seconds timestamp within 24h";
    const ONE_DAY_SECS: u64 = 24 * 60 * 60;

    let signer = crate::signers::ed25519_did_key();
    let response = match fetch_challenge(http, target, signer.signer_did()).await {
        Ok(r) => r,
        Err(e) => return CaseResult::fail(ID, SPEC_REF, TITLE, format!("request failed: {e}")),
    };
    let Some(expires_at) = response
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
                "no unsigned-integer `expires_at` field: {}",
                response.excerpt()
            ),
        );
    };

    let now = unix_now();
    if expires_at <= now {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!("expires_at ({expires_at}) is not strictly in the future (now is {now})"),
        );
    }
    if expires_at - now > ONE_DAY_SECS {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "expires_at ({expires_at}) is more than 24h ahead of now ({now}); a server \
                 emitting milliseconds instead of seconds is the classic cause of a drift this \
                 large"
            ),
        );
    }
    CaseResult::pass(ID, SPEC_REF, TITLE, "")
}

/// SPEC 6.4: a successful session response carries `did` (matching the login
/// DID), `token` (64 lowercase hex characters, no `0x` prefix), `valid_until`
/// (unsigned integer, in the future) and `created_at` (unsigned integer, no
/// later than `valid_until`).
pub(crate) async fn spec_6_4_session_response_shape(target: &Target, http: &Http) -> CaseResult {
    const ID: &str = "spec_6_4_session_response_shape";
    const SPEC_REF: &str = "SPEC 6.4";
    const TITLE: &str = "session response carries did, token, valid_until, created_at";

    let signer = crate::signers::ed25519_did_key();
    let flow = match login(http, target, &signer).await {
        Ok(f) => f,
        Err(e) => {
            return CaseResult::fail(
                ID,
                SPEC_REF,
                TITLE,
                format!("the happy-path login did not complete: {e}"),
            )
        }
    };

    if !flow.session_response.is_success() {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "expected a 2xx from a valid login, got {}: {}",
                flow.session_response.status,
                flow.session_response.excerpt()
            ),
        );
    }
    let Some(body) = flow.session_response.json.as_ref() else {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "session response was not JSON: {}",
                flow.session_response.excerpt()
            ),
        );
    };

    match body.get("did").and_then(Value::as_str) {
        Some(did) if did == signer.signer_did() => {}
        Some(other) => {
            return CaseResult::fail(
                ID,
                SPEC_REF,
                TITLE,
                format!(
                    "`did` is {other:?}, expected the login DID {:?}",
                    signer.signer_did()
                ),
            )
        }
        None => {
            return CaseResult::fail(ID, SPEC_REF, TITLE, "`did` field missing or not a string")
        }
    }

    let token = match body.get("token").and_then(Value::as_str) {
        Some(t) => t,
        None => {
            return CaseResult::fail(ID, SPEC_REF, TITLE, "`token` field missing or not a string")
        }
    };
    let token_well_formed = token.len() == 64
        && token
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c));
    if !token_well_formed {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "`token` must be exactly 64 lowercase hex chars with no 0x prefix, got {token:?} \
                 ({} chars)",
                token.chars().count()
            ),
        );
    }

    let valid_until = match body.get("valid_until").and_then(Value::as_u64) {
        Some(v) => v,
        None => {
            return CaseResult::fail(
                ID,
                SPEC_REF,
                TITLE,
                "`valid_until` field missing or not an unsigned integer",
            )
        }
    };
    let created_at = match body.get("created_at").and_then(Value::as_u64) {
        Some(v) => v,
        None => {
            return CaseResult::fail(
                ID,
                SPEC_REF,
                TITLE,
                "`created_at` field missing or not an unsigned integer",
            )
        }
    };

    let now = unix_now();
    if valid_until <= now {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!("`valid_until` ({valid_until}) is not strictly in the future (now is {now})"),
        );
    }
    if created_at > valid_until {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!("`created_at` ({created_at}) is after `valid_until` ({valid_until})"),
        );
    }

    CaseResult::pass(ID, SPEC_REF, TITLE, "")
}

/// SPEC 8: "Servers MAY emit additional fields in any response object.
/// Clients MUST ignore unknown fields." The reciprocal requirement on a
/// server receiving a request follows from the same forward-compatibility
/// goal: a server that rejects a request for carrying one field it does not
/// recognise can never grow its own request shape without breaking every
/// existing client at once. This case builds an otherwise-valid session
/// request, adds one field SPEC.md never defines, and asserts the login
/// still succeeds.
pub(crate) async fn spec_8_unknown_request_fields_ignored(
    target: &Target,
    http: &Http,
) -> CaseResult {
    const ID: &str = "spec_8_unknown_request_fields_ignored";
    const SPEC_REF: &str = "SPEC 8";
    const TITLE: &str = "an unrecognised top-level field on the session request is ignored";

    let signer = crate::signers::ed25519_did_key();
    let challenge = match fetch_challenge(http, target, signer.signer_did()).await {
        Ok(r) => r,
        Err(e) => {
            return CaseResult::fail(ID, SPEC_REF, TITLE, format!("challenge setup failed: {e}"))
        }
    };
    let mut body = match sign_challenge(&challenge, &signer).await {
        Ok(b) => b,
        Err(e) => {
            return CaseResult::fail(
                ID,
                SPEC_REF,
                TITLE,
                format!("could not build a valid session request to mutate: {e}"),
            )
        }
    };

    let Value::Object(map) = &mut body else {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            "the session request this suite builds was not a JSON object, which is a bug in \
             this harness, not the target",
        );
    };
    map.insert(
        "an_unrecognised_field_the_spec_never_defined".to_string(),
        Value::String("conformance-probe".to_string()),
    );

    let response = match post_session(http, target, &body).await {
        Ok(r) => r,
        Err(e) => return CaseResult::fail(ID, SPEC_REF, TITLE, format!("request failed: {e}")),
    };

    if !response.is_success() {
        return CaseResult::fail(
            ID,
            SPEC_REF,
            TITLE,
            format!(
                "a request that is valid except for one added, unrecognised field was refused: \
                 {} {}",
                response.status,
                response.excerpt()
            ),
        );
    }
    CaseResult::pass(ID, SPEC_REF, TITLE, "")
}

/// Every case this module implements, in the order they run.
pub(crate) async fn all(target: &Target, http: &Http) -> Vec<CaseResult> {
    vec![
        spec_6_2_required_fields(target, http).await,
        spec_6_2_did_field(target, http).await,
        spec_6_2_nonce_format(target, http).await,
        spec_6_2_message_structure(target, http).await,
        spec_6_2_expires_at_sane(target, http).await,
        spec_6_4_session_response_shape(target, http).await,
        spec_8_unknown_request_fields_ignored(target, http).await,
    ]
}
