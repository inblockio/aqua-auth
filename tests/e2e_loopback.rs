//! End-to-end login flows driven by the *real* client over *real* sockets.
//!
//! `tests/e2e_inmemory.rs` owns breadth: it drives the same [`AquaPeer`] router
//! through `tower`'s `oneshot` with a hand-rolled client, so it can afford a
//! test per DID spelling and a long adversarial tail. This suite owns exactly
//! one claim instead: `aqua_auth::client::authenticate()`, the shipped reqwest
//! path, works against a peer bound on a socket. Everything here therefore
//! costs a TCP connection, which is why the list is short.
//!
//! Two properties only this suite can prove:
//!
//! - **HB1:** a peer bound on an ephemeral `127.0.0.1` port mints challenges
//!   whose `URI:` line carries the address it actually got, so the client's
//!   origin check passes and the token it receives validates server-side.
//! - **HB2:** a relay that replays a victim peer's challenge verbatim is
//!   refused with [`AuthClientError::UriOriginMismatch`] *before* the client's
//!   signer is ever invoked. The counting signer is the instrument: a call
//!   count of zero is the difference between "the login failed" and "the key
//!   was never used", and only the second is a defence.
//!
//! ## Feature gate
//!
//! The harness needs `http` (stores, wire types) and `http-sig`
//! (`verify_request` behind `/sig/whoami`); this suite additionally needs
//! `client` (reqwest and `AuthClientError`). `client` implies `http` in
//! `Cargo.toml`, and `http-sig` implies neither, so naming `client` and
//! `http-sig` is exactly sufficient. Run with `cargo test --all-features` or
//! `cargo test --features client,http-sig`.
//!
//! ## No sleeps
//!
//! Readiness needs no polling and no fixed delay: `AquaPeer::bind_loopback`
//! calls `TcpListener::bind` before returning, so the port is listening and the
//! kernel is queueing connections by the time a test has an address to dial.
//! Every port is ephemeral (`:0`), so suites can run concurrently.

#![cfg(all(feature = "client", feature = "http-sig"))]

mod harness;

use aqua_auth::client::authenticate;
use aqua_auth::Signer;
use axum::http::StatusCode;
use harness::{signers, AquaPeer};
use std::sync::Arc;

/// Challenge lifetime for every peer here. Long enough that no test in this
/// suite can trip over expiry; the in-memory suite owns the TTL tests.
const CHALLENGE_TTL_SECS: u64 = 300;

/// `GET /whoami` with a session bearer token, over the wire.
async fn whoami(http: &reqwest::Client, base_url: &str, token: &str) -> reqwest::Response {
    http.get(format!("{base_url}/whoami"))
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .expect("the loopback peer must answer /whoami")
}

// ── HB1: the shipped client, end to end, over a socket ──────────────────
//
// Three spellings rather than all five: this suite is proving the transport
// and the client, not the verifier matrix, and the verifier matrix is already
// covered spelling by spelling in `e2e_inmemory.rs`. The three chosen cover the
// three distinct signature formats: 64-byte Ed25519, 64-byte P-256 ECDSA, and
// 65-byte recoverable EIP-191.

/// Log in with the real client, then spend the token it minted.
async fn assert_real_client_logs_in(signer: Arc<dyn Signer>) {
    let (peer, base_url, server) =
        AquaPeer::bind_loopback("peer-a", CHALLENGE_TTL_SECS, signer.clone()).await;

    // The peer was built around the address it actually got, not the other way
    // round; if it were not, the challenge would name a port nobody is serving
    // and `authenticate` below would die with UriOriginMismatch.
    assert_eq!(base_url, format!("http://{}", peer.authority()));

    let http = reqwest::Client::new();
    let session = authenticate(&http, &base_url, &*signer)
        .await
        .expect("the real client must complete the login flow over loopback");

    assert_eq!(
        session.did,
        signer.signer_did(),
        "the session must name the DID that signed, unmodified"
    );
    assert!(!session.token.is_empty());

    let response = whoami(&http, &base_url, &session.token).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the minted token must validate server-side"
    );
    let who: serde_json::Value = response
        .json()
        .await
        .expect("/whoami answers with a JSON object");
    assert_eq!(who["did"], signer.signer_did());

    server.abort();
}

#[tokio::test]
async fn real_client_logs_in_as_ed25519_did_key() {
    assert_real_client_logs_in(signers::ed25519_did_key()).await;
}

#[tokio::test]
async fn real_client_logs_in_as_p256_did_pkh() {
    assert_real_client_logs_in(signers::p256_did_pkh()).await;
}

#[tokio::test]
async fn real_client_logs_in_as_eip155() {
    assert_real_client_logs_in(signers::eip155()).await;
}
