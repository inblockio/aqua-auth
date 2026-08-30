//! End-to-end login flows driven in-memory, with no sockets.
//!
//! Every test here drives `AquaPeer::router()` through
//! [`tower::ServiceExt::oneshot`], so the whole server half runs (routing,
//! extractors, the real `ChallengeStore` / `SessionStore` / `NonceReplayGuard`
//! / `KeyRegistry`, the real verifiers) without a listener, a port, or a
//! runtime reactor. The client half is hand-rolled: build the GET, parse the
//! envelope, sign with a harness signer, POST the signature. Driving the real
//! reqwest client is `tests/e2e_loopback.rs`'s job, not this suite's.
//!
//! **Feature gate.** The harness needs `http` (the stores and the wire types)
//! and `http-sig` (`verify_request` for `/sig/whoami`). `http-sig` does *not*
//! imply `http` in `Cargo.toml`, so both are named explicitly. Run with
//! `cargo test --all-features` or `cargo test --features http,http-sig`.

#![cfg(all(feature = "http", feature = "http-sig"))]

mod harness;

use aqua_auth::wire::{ChallengeEnvelope, SessionRequest, SessionResponse};
use aqua_auth::Signer;
use axum::body::Body;
use axum::http::{header, Request, Response, StatusCode};
use harness::{signers, AquaPeer};
use std::sync::Arc;
use tower::ServiceExt;

const BASE_URL: &str = "http://peer-a.test";
const AUTHORITY: &str = "peer-a.test";
const TTL_SECS: u64 = 300;

fn peer(signer: Arc<dyn Signer>) -> AquaPeer {
    AquaPeer::in_memory("peer-a", BASE_URL, TTL_SECS, signer)
}

/// A fresh `Router` per call, sharing the peer's stores through its `Arc`s, so
/// state carries across requests exactly as it would across connections.
async fn send(peer: &AquaPeer, request: Request<Body>) -> Response<Body> {
    peer.router()
        .oneshot(request)
        .await
        .expect("the router is infallible")
}

fn get(path: &str) -> axum::http::request::Builder {
    Request::builder()
        .method("GET")
        .uri(path)
        .header(header::HOST, AUTHORITY)
}

async fn body_bytes(response: Response<Body>) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body must be readable")
        .to_vec()
}

async fn body_json<T: serde::de::DeserializeOwned>(response: Response<Body>) -> T {
    let bytes = body_bytes(response).await;
    serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!(
            "body was not the expected JSON shape ({e}): {}",
            String::from_utf8_lossy(&bytes)
        )
    })
}

/// `GET /auth/challenge?did=...`, asserting 200 and returning the envelope.
async fn fetch_challenge(peer: &AquaPeer, did: &str) -> ChallengeEnvelope {
    let response = send(
        peer,
        get(&format!("/auth/challenge?did={did}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "challenge request failed");
    body_json(response).await
}

/// `POST /auth/session` with an already-built body, returning the raw response
/// so negative tests can assert on the status.
async fn post_session(peer: &AquaPeer, request: &SessionRequest) -> Response<Body> {
    send(
        peer,
        Request::builder()
            .method("POST")
            .uri("/auth/session")
            .header(header::HOST, AUTHORITY)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(request).unwrap()))
            .unwrap(),
    )
    .await
}

/// `GET /whoami` with a bearer token.
async fn whoami(peer: &AquaPeer, token: &str) -> Response<Body> {
    send(
        peer,
        get("/whoami")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

/// The full login flow for one signer: challenge, sign, session, `/whoami`.
async fn login(peer: &AquaPeer, signer: &dyn Signer) -> SessionResponse {
    let envelope = fetch_challenge(peer, signer.signer_did()).await;
    let signature = signer.sign(&envelope.message).await.expect("signing failed");

    let response = post_session(
        peer,
        &SessionRequest {
            did: signer.signer_did().to_string(),
            nonce: envelope.nonce,
            signature: hex::encode(signature),
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "session request failed");
    body_json(response).await
}

// ── the five-spelling login matrix ──────────────────────────────────────
//
// One key type can be spelled two ways (did:key and did:pkh) and those are two
// distinct principals, not one folded identity (#182). Both spellings must log
// in, and each must come back as the DID it presented, never normalised to the
// other.

/// Log in, then prove the token names the same DID at `/whoami`.
async fn assert_login_matrix(signer: Arc<dyn Signer>) {
    let peer = peer(signer.clone());

    let session = login(&peer, &*signer).await;
    assert_eq!(
        session.did,
        signer.signer_did(),
        "the session must name the DID that signed, unmodified"
    );
    assert!(!session.token.is_empty());

    let response = whoami(&peer, &session.token).await;
    assert_eq!(response.status(), StatusCode::OK);
    let who: serde_json::Value = body_json(response).await;
    assert_eq!(who["did"], signer.signer_did());
}

#[tokio::test]
async fn ed25519_did_key_logs_in_end_to_end() {
    assert_login_matrix(signers::ed25519_did_key()).await;
}

#[tokio::test]
async fn ed25519_did_pkh_logs_in_end_to_end() {
    assert_login_matrix(signers::ed25519_did_pkh()).await;
}

#[tokio::test]
async fn p256_did_key_logs_in_end_to_end() {
    assert_login_matrix(signers::p256_did_key()).await;
}

#[tokio::test]
async fn p256_did_pkh_logs_in_end_to_end() {
    assert_login_matrix(signers::p256_did_pkh()).await;
}

#[tokio::test]
async fn eip155_did_pkh_logs_in_end_to_end() {
    assert_login_matrix(signers::eip155()).await;
}

// ── adversarial: the server half refuses over the wire ──────────────────
//
// Status contract (the plan's route table): a nonce the store does not hold is
// 404, every other credential failure is 401. A *spent* nonce is 404 rather
// than 401 because `ChallengeStore::validate` removes it, which makes "already
// used" and "never issued" the same observation. That indistinguishability is
// the point: it denies an attacker a nonce-existence oracle.

#[tokio::test]
async fn a_nonce_this_server_never_issued_is_refused() {
    let signer = signers::ed25519_did_key();
    let peer = peer(signer.clone());

    let response = post_session(
        &peer,
        &SessionRequest {
            did: signer.signer_did().to_string(),
            nonce: format!("0x{}", "11".repeat(32)),
            signature: hex::encode([0u8; 64]),
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_nonce_spent_by_a_successful_login_cannot_be_reused() {
    let signer = signers::ed25519_did_key();
    let peer = peer(signer.clone());

    let envelope = fetch_challenge(&peer, signer.signer_did()).await;
    let signature = hex::encode(signer.sign(&envelope.message).await.unwrap());
    let request = SessionRequest {
        did: signer.signer_did().to_string(),
        nonce: envelope.nonce,
        signature,
    };

    let first = post_session(&peer, &request).await;
    assert_eq!(first.status(), StatusCode::OK);

    // Byte-identical replay of a request that just succeeded.
    let second = post_session(&peer, &request).await;
    assert_eq!(
        second.status(),
        StatusCode::NOT_FOUND,
        "a spent nonce is gone from the store, so it reads as never-issued"
    );
}

#[tokio::test]
async fn a_challenge_past_its_ttl_is_refused() {
    // The one place real time is unavoidable: the TTL lives inside
    // ChallengeStore and the plan forbids injecting a clock into src/. A 1s TTL
    // outlived by 1.2s is the shortest honest way to cross that boundary.
    let signer = signers::ed25519_did_key();
    let peer = AquaPeer::in_memory("peer-a", BASE_URL, 1, signer.clone());

    let envelope = fetch_challenge(&peer, signer.signer_did()).await;
    let signature = hex::encode(signer.sign(&envelope.message).await.unwrap());
    tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;

    let response = post_session(
        &peer,
        &SessionRequest {
            did: signer.signer_did().to_string(),
            nonce: envelope.nonce,
            signature,
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_challenge_issued_to_one_did_cannot_be_claimed_by_another() {
    // Both signatures are genuine; only the pairing is wrong. The store ties
    // each nonce to the DID it was minted for, so this fails before any
    // cryptography runs.
    let alice = signers::ed25519_did_key();
    let mallory = signers::ed25519_did_key();
    let peer = peer(alice.clone());

    let envelope = fetch_challenge(&peer, alice.signer_did()).await;
    let signature = hex::encode(mallory.sign(&envelope.message).await.unwrap());

    let response = post_session(
        &peer,
        &SessionRequest {
            did: mallory.signer_did().to_string(),
            nonce: envelope.nonce,
            signature,
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_tampered_signature_is_refused() {
    let signer = signers::ed25519_did_key();
    let peer = peer(signer.clone());

    let envelope = fetch_challenge(&peer, signer.signer_did()).await;
    let mut signature = signer.sign(&envelope.message).await.unwrap();
    signature[0] ^= 0xff;

    let response = post_session(
        &peer,
        &SessionRequest {
            did: signer.signer_did().to_string(),
            nonce: envelope.nonce,
            signature: hex::encode(signature),
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_signature_that_is_not_hex_is_refused() {
    let signer = signers::ed25519_did_key();
    let peer = peer(signer.clone());

    let envelope = fetch_challenge(&peer, signer.signer_did()).await;
    let response = post_session(
        &peer,
        &SessionRequest {
            did: signer.signer_did().to_string(),
            nonce: envelope.nonce,
            signature: "not-hex-at-all".to_string(),
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn whoami_refuses_a_token_it_never_minted() {
    let peer = peer(signers::ed25519_did_key());

    let response = whoami(&peer, "deadbeef-not-a-token").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn whoami_refuses_a_request_with_no_authorization_header() {
    let peer = peer(signers::ed25519_did_key());

    let response = send(&peer, get("/whoami").body(Body::empty()).unwrap()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_challenge_is_not_minted_for_an_unsupported_did() {
    let peer = peer(signers::ed25519_did_key());

    for did in ["did:pkh:solana:0xabc", "not-a-did", ""] {
        let response = send(
            &peer,
            get(&format!("/auth/challenge?did={did}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "unsupported DID {did:?} must not get a challenge"
        );
    }
}

#[tokio::test]
async fn a_challenge_request_with_no_did_is_refused() {
    let peer = peer(signers::ed25519_did_key());

    let response = send(&peer, get("/auth/challenge").body(Body::empty()).unwrap()).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
