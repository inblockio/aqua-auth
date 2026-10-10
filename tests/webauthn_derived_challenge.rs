//! The derived passkey login challenge (aqua-explorer logging into
//! aqua-node), through the public API only, against pinned vectors that were
//! computed outside this crate (origins with Node's WHATWG `URL`, hashes with
//! Python's hashlib). aqua-explorer consumes the same vectors file.
//! Assertions come from the testkit's `SoftPasskey`.

use aqua_auth::{
    derive_login_challenge, verify_and_recover, AssertOpts, AssertionError, AssertionJson,
    AssertionPolicy, ExpectedChallenge, LoginChallengeError, SoftPasskey, LOGIN_CHALLENGE_TAG,
};
use sha2::{Digest, Sha256};

const VECTORS: &str = include_str!("vectors/webauthn-derived-login-challenge.json");
const RP: &str = "inblock.io";
const EXPLORER: &str = "https://explorer.local.inblock.io:8443";
const NODE: &str = "https://node.local.inblock.io:8443";

#[derive(serde::Deserialize)]
struct Vectors {
    tag_utf8: String,
    cases: Vec<Case>,
    rejected_node_urls: Vec<String>,
}

#[derive(serde::Deserialize)]
struct Case {
    name: String,
    nonce_hex: String,
    node_url: String,
    origin: String,
    challenge_hex: String,
}

fn vectors() -> Vectors {
    serde_json::from_str(VECTORS).expect("vectors file parses")
}

fn derive(nonce: &[u8; 32], node_url: &str) -> [u8; 32] {
    derive_login_challenge(nonce, node_url).unwrap_or_else(|e| panic!("{node_url}: {e}"))
}

fn policy() -> AssertionPolicy {
    AssertionPolicy::builder()
        .rp(RP, &[EXPLORER])
        .unwrap()
        .build()
        .unwrap()
}

/// A browser-shaped assertion (UP|UV, `crossOrigin: false`) from the
/// explorer origin over `challenge`.
fn assertion(pk: &SoftPasskey, challenge: &[u8]) -> AssertionJson {
    pk.assert(&AssertOpts::new(challenge, EXPLORER))
}

#[test]
fn pinned_vectors_match() {
    let v = vectors();
    assert_eq!(v.tag_utf8.as_bytes(), LOGIN_CHALLENGE_TAG);
    assert!(v.cases.len() >= 6, "at least six cases");
    for c in &v.cases {
        let nonce: [u8; 32] = hex::decode(&c.nonce_hex).unwrap().try_into().unwrap();
        let want = hex::decode(&c.challenge_hex).unwrap();
        // The vector agrees with its own stated origin...
        let mut h = Sha256::new();
        h.update(LOGIN_CHALLENGE_TAG);
        h.update(nonce);
        h.update(c.origin.as_bytes());
        assert_eq!(h.finalize().as_slice(), want, "{}: vector", c.name);
        // ...and the crate derives it from the URL as given.
        assert_eq!(derive(&nonce, &c.node_url).as_slice(), want, "{}", c.name);
    }
}

#[test]
fn tag_cannot_prefix_sdk_signing_input() {
    // The SDK's WebAuthn signing input M is canonical JSON (it starts with
    // `{"hash_codec"`) and its challenge is SHA-256(M). A derived login
    // challenge equals one only if TAG || nonce || origin == M, which the
    // first byte already rules out: a node cannot obtain a revision
    // signature through explorer login.
    assert_ne!(LOGIN_CHALLENGE_TAG[0], b'{');
    assert_eq!(LOGIN_CHALLENGE_TAG, b"aqua-auth/webauthn-login/v1");
}

#[test]
fn different_origin_gives_different_challenge() {
    let nonce = [7u8; 32];
    let base = derive(&nonce, NODE);
    let mut all = vec![base];
    for other in [
        "https://evil.local.inblock.io:8443",
        "http://node.local.inblock.io:8443",
        "https://node.local.inblock.io",
        "https://node.local.inblock.io:8444",
        "https://node.inblock.io:8443",
    ] {
        all.push(derive(&nonce, other));
    }
    let mut distinct = all.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(distinct.len(), all.len());
    // Only the origin is bound: path, query and fragment are not.
    assert_eq!(
        derive(&nonce, "https://node.local.inblock.io:8443/api/x?y=1#z"),
        base
    );
    // The nonce is bound.
    assert_ne!(derive(&[8u8; 32], NODE), base);
}

#[test]
fn verify_and_recover_accepts_derived_and_rejects_raw_nonce_as_challenge() {
    let pk = SoftPasskey::new_seeded(0x0de1_17ed, RP);
    let nonce = [0x42u8; 32];
    let expected = ExpectedChallenge::DerivedLogin {
        nonce: &nonce,
        node_url: NODE,
    };
    let derived = derive(&nonce, NODE);
    let rec = verify_and_recover(&assertion(&pk, &derived), expected, &policy())
        .expect("the derived challenge is accepted");
    assert!(rec.candidate_dids().contains(&pk.did()));
    // Another spelling of the same node origin derives the same bytes.
    let respelled = ExpectedChallenge::DerivedLogin {
        nonce: &nonce,
        node_url: "https://NODE.local.inblock.io:8443/",
    };
    assert!(verify_and_recover(&assertion(&pk, &derived), respelled, &policy()).is_ok());

    // The raw node nonce as the challenge (a node-chosen get()) is refused.
    assert_eq!(
        verify_and_recover(&assertion(&pk, &nonce), expected, &policy()),
        Err(AssertionError::ChallengeMismatch)
    );
    // Derived for another node, or from another nonce: refused.
    for wrong in [
        derive(&nonce, "https://evil.local.inblock.io:8443"),
        derive(&[0x43u8; 32], NODE),
    ] {
        assert_eq!(
            verify_and_recover(&assertion(&pk, &wrong), expected, &policy()),
            Err(AssertionError::ChallengeMismatch)
        );
    }
}

#[test]
fn opaque_or_unparsable_origin_rejected() {
    let v = vectors();
    assert!(!v.rejected_node_urls.is_empty());
    for url in &v.rejected_node_urls {
        assert!(
            derive_login_challenge(&[0u8; 32], url).is_err(),
            "{url:?} must be refused"
        );
    }
    assert!(matches!(
        derive_login_challenge(&[0u8; 32], "not a url"),
        Err(LoginChallengeError::InvalidUrl(_))
    ));
    assert!(matches!(
        derive_login_challenge(&[0u8; 32], "data:text/plain,x"),
        Err(LoginChallengeError::UnsupportedScheme(_))
    ));
    // verify_and_recover reports an unusable expected node URL as such,
    // not as a challenge mismatch.
    let pk = SoftPasskey::new_seeded(7, RP);
    let nonce = [1u8; 32];
    let a = assertion(&pk, &derive(&nonce, NODE));
    let broken = ExpectedChallenge::DerivedLogin {
        nonce: &nonce,
        node_url: "file:///etc/hosts",
    };
    assert!(matches!(
        verify_and_recover(&a, broken, &policy()),
        Err(AssertionError::InvalidNodeUrl(
            LoginChallengeError::UnsupportedScheme(_)
        ))
    ));
}
