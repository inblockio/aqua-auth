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

#[tokio::test]
async fn ed25519_did_key_logs_in_end_to_end() {
    let signer = signers::ed25519_did_key();
    let peer = peer(signer.clone());

    let session = login(&peer, &*signer).await;
    assert_eq!(session.did, signer.signer_did());
    assert!(!session.token.is_empty());

    let response = whoami(&peer, &session.token).await;
    assert_eq!(response.status(), StatusCode::OK);
    let who: serde_json::Value = body_json(response).await;
    assert_eq!(who["did"], signer.signer_did());
}
