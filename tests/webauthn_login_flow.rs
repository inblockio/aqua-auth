//! Store-free passkey login flows end to end, through the public API only.
//! `SoftPasskey` stands in for browser and authenticator; each test makes the
//! calls a consumer's server makes, in order (SPEC section 12). Origins are
//! the three signing origins every app lists (explorer, aquafire, suite) under
//! RP ID `inblock.io`.

use aqua_auth::{
    creation_options, derive_login_challenge, hint_set_cookie, hints_from_cookie_header,
    request_options, verify_and_recover, AssertOpts, AssertionError, AssertionJson,
    AssertionPolicy, DidHint, ExpectedChallenge, HintCookieConfig, PendingRecovery, Principal,
    RequestOptionsJson, SelectedBy, Selection, SelectionError, SoftPasskey, PASSKEY_USER_NAME,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

const RP: &str = "inblock.io";
const EXPLORER: &str = "https://explorer.local.inblock.io:8443";
const AQUAFIRE: &str = "https://aquafire.local.inblock.io:8443";
const SUITE: &str = "https://suite.local.inblock.io:8443";
const NODE: &str = "https://node.local.inblock.io:8443";

fn policy() -> AssertionPolicy {
    AssertionPolicy::builder()
        .rp(RP, &[EXPLORER, AQUAFIRE, SUITE])
        .unwrap()
        .build()
        .unwrap()
}

fn unb64(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s).unwrap()
}

/// The challenge bytes a server put into its `get()` options.
fn challenge_of(options: &RequestOptionsJson) -> Vec<u8> {
    unb64(&options.public_key().challenge)
}

/// The browser answers `options` from `origin` with `pk`; the server
/// verifies against the challenge it issued.
fn login(
    pk: &SoftPasskey,
    options: &RequestOptionsJson,
    origin: &str,
) -> aqua_auth::RecoveredAssertion {
    let challenge = challenge_of(options);
    let a = pk.assert(&AssertOpts::new(&challenge, origin));
    verify_and_recover(&a, ExpectedChallenge::Exact(&challenge), &policy())
        .expect("a well-formed assertion verifies")
}

fn selected(s: Selection) -> (Principal, SelectedBy) {
    match s {
        Selection::Selected { principal, by } => (principal, by),
        other => panic!("expected a selection, got {other:?}"),
    }
}

/// The `name=value` pair a browser sends back for a `Set-Cookie` value.
fn cookie_pair(set_cookie: &str) -> &str {
    set_cookie.split(';').next().unwrap()
}

#[test]
fn first_visit_two_prompts_resolve_to_signer() {
    // Registered elsewhere; this app has no record of the key and the
    // browser carries no hint cookie.
    let pk = SoftPasskey::new_seeded(101, RP);
    let first = request_options(RP, b"first prompt challenge, 32 bytes", &[]);
    assert!(
        first.public_key().allow_credentials.is_empty(),
        "discoverable"
    );
    let rec = login(&pk, &first, SUITE);
    let pending = match rec.select(&[], [false, false]) {
        Selection::NeedSecondAssertion(p) => p,
        other => panic!("nothing to choose by, got {other:?}"),
    };
    // The server keeps the pending state next to the second challenge.
    let stored = serde_json::to_string(&pending).unwrap();

    let second = request_options(
        RP,
        b"second prompt, fresh challenge..",
        &[pending.credential_id().to_vec()],
    );
    let allow = &second.public_key().allow_credentials;
    assert_eq!(allow.len(), 1);
    assert_eq!(unb64(&allow[0].id), pk.credential_id);
    let rec2 = login(&pk, &second, SUITE);

    let pending: PendingRecovery = serde_json::from_str(&stored).unwrap();
    let principal = pending
        .resolve(&rec2)
        .expect("one key both assertions recover");
    assert_eq!(principal.did(), pk.did());
    // The first assertion again is not a second proof.
    assert_eq!(pending.resolve(&rec), Err(SelectionError::Ambiguous));
    // Another passkey's assertion cannot complete this login.
    let other = SoftPasskey {
        credential_id: pk.credential_id.clone(),
        ..SoftPasskey::new_seeded(199, RP)
    };
    assert_eq!(
        pending.resolve(&login(&other, &second, SUITE)),
        Err(SelectionError::NoCommonCandidate)
    );
    // Then the hint cookie names the principal for the next login.
    let set = hint_set_cookie(&principal, &HintCookieConfig::for_rp_id(RP));
    assert_eq!(cookie_pair(&set), format!("aqua_did_hint={}", pk.did()));
}

#[test]
fn hinted_login_one_prompt() {
    let pk = SoftPasskey::new_seeded(102, RP);
    let stale = SoftPasskey::new_seeded(103, RP);
    // Cookies earlier logins set (another passkey's too) come back in the
    // Cookie header next to unrelated ones.
    let cfg = HintCookieConfig::for_rp_id(RP);
    let set_for =
        |p: &SoftPasskey| hint_set_cookie(&Principal::from_trusted_did(&p.did()).unwrap(), &cfg);
    let (mine, theirs) = (set_for(&pk), set_for(&stale));
    let header = format!(
        "session=abc; {}; {}",
        cookie_pair(&theirs),
        cookie_pair(&mine)
    );
    let hints = hints_from_cookie_header(&header);
    assert_eq!(hints.len(), 2);

    let options = request_options(RP, b"one prompt only, 32 bytes long..", &[]);
    let rec = login(&pk, &options, AQUAFIRE);
    let (p, by) = selected(rec.select(&hints, [false, false]));
    assert_eq!((p.did(), by), (pk.did().as_str(), SelectedBy::Hint));
    // Only the stale hint: it names no candidate, so nothing is selected.
    let only_stale = hints_from_cookie_header(cookie_pair(&theirs));
    assert!(matches!(
        rec.select(&only_stale, [false, false]),
        Selection::NeedSecondAssertion(_)
    ));
}

#[test]
fn signup_spki_hint_then_login_selects_it() {
    let pk = SoftPasskey::new_seeded(104, RP);
    // Sign-up is options only: create(), no verifier, no session.
    let create = creation_options(RP, RP, PASSKEY_USER_NAME, &[0x11; 32]);
    let params = &create.public_key().pub_key_cred_params;
    assert_eq!((params.len(), params[0].alg), (1, -7));
    let attestation = pk.attestation_none(&unb64(&create.public_key().challenge), AQUAFIRE);
    assert!(
        serde_json::from_value::<AssertionJson>(attestation.clone()).is_err(),
        "a registration carries no assertion to take a principal from"
    );
    // Then login: the start request carries getPublicKey() as the key hint
    // and the get() is pinned to the new credential.
    let spki = unb64(attestation["response"]["publicKey"].as_str().unwrap());
    let raw_id = unb64(attestation["rawId"].as_str().unwrap());
    let key_hint = DidHint::from_spki_der(&spki).unwrap();
    let options = request_options(RP, b"login right after sign-up.......", &[raw_id]);
    let rec = login(&pk, &options, AQUAFIRE);
    let (p, by) = selected(rec.select(&[key_hint], [false, false]));
    assert_eq!((p.did(), by), (pk.did().as_str(), SelectedBy::Hint));
    // A client that sends another key's SPKI selects nothing.
    let lie = DidHint::from_spki_der(&SoftPasskey::new_seeded(105, RP).spki_der()).unwrap();
    assert!(matches!(
        rec.select(&[lie], [false, false]),
        Selection::NeedSecondAssertion(_)
    ));
}

#[test]
fn derived_challenge_flow_end_to_end() {
    // aqua-explorer logs into aqua-node: the node issues a nonce, the
    // explorer derives the challenge itself and sends its DID as the hint.
    let pk = SoftPasskey::new_seeded(106, RP);
    let nonce = [0x5a; 32];
    let expected = ExpectedChallenge::DerivedLogin {
        nonce: &nonce,
        node_url: NODE,
    };
    let challenge = derive_login_challenge(&nonce, NODE).unwrap();
    let a = pk.assert(&AssertOpts::new(&challenge, EXPLORER));
    let rec = verify_and_recover(&a, expected, &policy()).unwrap();
    let hint = DidHint::parse(&pk.did()).unwrap();
    let (p, by) = selected(rec.select(&[hint], [false, false]));
    assert_eq!((p.did(), by), (pk.did().as_str(), SelectedBy::Hint));
    // The raw nonce as the challenge (bytes the node chose) is refused, and
    // so is a challenge derived for another node.
    let elsewhere = derive_login_challenge(&nonce, "https://evil.local.inblock.io:8443").unwrap();
    for wrong in [&nonce[..], &elsewhere[..]] {
        let a = pk.assert(&AssertOpts::new(wrong, EXPLORER));
        assert_eq!(
            verify_and_recover(&a, expected, &policy()),
            Err(AssertionError::ChallengeMismatch)
        );
    }
}

#[test]
fn assertion_from_unlisted_origin_refused() {
    let pk = SoftPasskey::new_seeded(107, RP);
    let challenge = b"origin check challenge, 32 bytes";
    let verify = |origin: &str| {
        let a = pk.assert(&AssertOpts::new(challenge, origin));
        verify_and_recover(&a, ExpectedChallenge::Exact(challenge), &policy())
    };
    assert!(verify(SUITE).is_ok(), "control");
    for origin in [
        "https://siwx.local.inblock.io:8443", // within the RP, never a signing origin
        "https://evil.local.inblock.io:8443",
        "https://suite.local.inblock.io",
        "http://suite.local.inblock.io:8443",
        "https://evil.example",
    ] {
        assert_eq!(
            verify(origin).map(|_| ()),
            Err(AssertionError::OriginNotAllowed),
            "{origin}"
        );
    }
}
