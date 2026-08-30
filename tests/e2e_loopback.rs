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

use aqua_auth::client::{authenticate, AuthClientError};
use aqua_auth::wire::ChallengeEnvelope;
use aqua_auth::{build_message, MessageParams, SignError, Signer};
use async_trait::async_trait;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use harness::{signers, AquaPeer};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// Challenge lifetime for every peer here. Long enough that no test in this
/// suite can trip over expiry; the in-memory suite owns the TTL tests.
const CHALLENGE_TTL_SECS: u64 = 300;

/// Bind an ephemeral loopback port and report the URL it will be reachable at,
/// *before* anything is served on it.
///
/// Split from [`serve_on`] so a hostile router can be built around the address
/// it is about to serve on, which is the same bind-then-build ordering
/// `AquaPeer::bind_loopback` uses and for the same reason: a challenge that
/// names a port nobody serves is not a useful forgery.
async fn bind() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binding an ephemeral loopback port must succeed");
    let address = listener
        .local_addr()
        .expect("a bound listener has a local address");
    (listener, format!("http://{address}"))
}

/// Serve `router` on an already-bound listener.
fn serve_on(listener: TcpListener, router: Router) -> JoinHandle<()> {
    tokio::spawn(async move {
        // A shut-down listener is the normal end of a test, not a failure.
        let _ = axum::serve(listener, router).await;
    })
}

/// Bind and serve in one step, for routers that do not need their own address.
async fn serve(router: Router) -> (String, JoinHandle<()>) {
    let (listener, base_url) = bind().await;
    (base_url, serve_on(listener, router))
}

/// `GET /auth/challenge?did=...`, asserting 200 and returning the envelope.
async fn fetch_challenge(http: &reqwest::Client, base_url: &str, did: &str) -> ChallengeEnvelope {
    let response = http
        .get(format!("{base_url}/auth/challenge"))
        .query(&[("did", did)])
        .send()
        .await
        .expect("the peer must answer /auth/challenge");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "challenge request failed"
    );
    response.json().await.expect("the envelope is JSON")
}

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

    let http = reqwest::Client::new();

    // HB1's load-bearing half, asserted directly rather than inferred from the
    // login succeeding: the peer was built around the address it actually got,
    // so its challenges name that authority. Were the order reversed, the
    // challenge would name a port nobody serves, `authenticate` would refuse to
    // sign it, and the failure would read as a client bug rather than a binding
    // bug. This probe challenge is simply abandoned; nonces are cheap and it
    // expires on its own.
    let probe = fetch_challenge(&http, &base_url, signer.signer_did()).await;
    let expected_uri = format!("URI: http://{}", peer.authority());
    assert!(
        probe.message.lines().any(|line| line == expected_uri),
        "the challenge must carry the bound origin ({expected_uri}), got:\n{}",
        probe.message
    );

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

// ── HB2: the relay is refused before the key is touched ─────────────────

/// A [`Signer`] that delegates to a real one and counts how often the key was
/// actually asked to sign.
///
/// The count is the instrument of HB2. "The login failed" and "the key was
/// never used" are different claims, and only the second one says the relay
/// came away with nothing: a signature over a foreign challenge is a credential
/// for the victim, so a client that signs first and fails afterwards has
/// already lost. An `AtomicUsize` rather than a `Cell` because `Signer` is
/// `Send + Sync`.
struct CountingSigner {
    inner: Arc<dyn Signer>,
    calls: AtomicUsize,
}

impl CountingSigner {
    fn wrapping(inner: Arc<dyn Signer>) -> Self {
        Self {
            inner,
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Signer for CountingSigner {
    fn signer_did(&self) -> &str {
        self.inner.signer_did()
    }

    async fn sign(&self, message: &str) -> Result<Vec<u8>, SignError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.sign(message).await
    }
}

/// A hostile server: it hands back one fixed challenge whatever DID is asked
/// for, and stands ready to forward whatever signature it hopes to collect.
///
/// One router covers both attacks in this file, because the attack lives
/// entirely in the envelope it is fed: a challenge minted by another origin is
/// a relay, a challenge naming another DID is a tampered message. The server
/// behaviour is identical either way.
///
/// `forwards` counts arrivals at `/auth/session`. Zero is a second, independent
/// witness to the refusal: the client not only never signed, it never even
/// spoke to the attacker again.
fn hostile_router(envelope: ChallengeEnvelope, forwards: Arc<AtomicUsize>) -> Router {
    Router::new()
        .route(
            "/auth/challenge",
            get(move || {
                let envelope = envelope.clone();
                async move { Json(envelope) }
            }),
        )
        .route(
            "/auth/session",
            post(move || {
                let forwards = forwards.clone();
                async move {
                    forwards.fetch_add(1, Ordering::SeqCst);
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            }),
        )
}

#[tokio::test]
async fn a_relayed_challenge_is_refused_before_the_key_is_touched() {
    let (_victim, victim_url, victim_server) =
        AquaPeer::bind_loopback("victim", CHALLENGE_TTL_SECS, signers::ed25519_did_key()).await;

    let client = CountingSigner::wrapping(signers::ed25519_did_key());
    let http = reqwest::Client::new();

    // The relay's stock in trade: a challenge the victim genuinely minted, for
    // this client's own DID. Nonce, identifier, expiry and signature format are
    // all beyond reproach; only the origin betrays it.
    let stolen = fetch_challenge(&http, &victim_url, client.signer_did()).await;

    let forwards = Arc::new(AtomicUsize::new(0));
    let (relay_url, relay_server) = serve(hostile_router(stolen, forwards.clone())).await;
    assert_ne!(relay_url, victim_url, "the relay must be its own origin");

    let err = authenticate(&http, &relay_url, &client)
        .await
        .expect_err("a challenge minted for another origin must not authenticate");

    match err {
        // Both origins are asserted, not just the variant: the error has to
        // name the victim as the origin it was handed and the relay as the one
        // that was dialed, which is the exact shape of a relay and not merely
        // "two URLs differed".
        AuthClientError::UriOriginMismatch {
            message_origin,
            client_origin,
        } => {
            assert_eq!(message_origin, victim_url);
            assert_eq!(client_origin, relay_url);
        }
        other => panic!("expected UriOriginMismatch, got {other:?}"),
    }

    assert_eq!(client.calls(), 0, "the refusal must precede signing");
    assert_eq!(
        forwards.load(Ordering::SeqCst),
        0,
        "the client must never come back to the relay with a signature"
    );

    relay_server.abort();
    victim_server.abort();
}

// ── error mapping: what the caller can actually branch on ───────────────
//
// A client is only as useful as the distinctions its error type preserves. A
// server that is merely broken and a server that is lying must not arrive as
// the same variant, because the first deserves a retry and the second deserves
// an alarm. These two tests pin that boundary over real HTTP.

/// Build the challenge envelope a server would mint for `did` at `uri`.
///
/// Hand-built rather than fetched, so a hostile server can be handed a message
/// that is well formed in every respect except the single one under test.
fn envelope_for(did: &str, uri: &str) -> ChallengeEnvelope {
    let now = chrono::Utc::now();
    let nonce = format!("0x{}", "ab".repeat(32));
    let message = build_message(&MessageParams {
        did,
        domain: "hostile",
        uri,
        nonce: &nonce,
        issued_at: now,
        expiration_time: now + chrono::Duration::minutes(5),
    })
    .expect("a supported DID yields a CAIP-122 message");

    ChallengeEnvelope {
        nonce,
        message,
        expires_at: 9_999_999_999,
    }
}

/// The identifier line a CAIP-122 message carries for `did`: the EIP-55 address
/// for `eip155`, the hex public key for the key-based namespaces.
fn identifier_of(did: &str) -> String {
    aqua_auth::find_did_method(did)
        .expect("a harness signer's DID resolves to a DID method")
        .address_for_message(did)
        .expect("a harness signer's DID is well formed")
}

#[tokio::test]
async fn a_server_that_fails_the_challenge_maps_to_the_http_variant() {
    let (base_url, server) = serve(Router::new().route(
        "/auth/challenge",
        get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
    ))
    .await;

    let err = authenticate(
        &reqwest::Client::new(),
        &base_url,
        &*signers::ed25519_did_key(),
    )
    .await
    .expect_err("a 500 on the challenge cannot yield a session");

    match err {
        // The status is asserted, not just the variant: a transport failure
        // (refused connection, closed socket) also lands in `Http`, and this
        // test is about a server that answered and answered badly.
        AuthClientError::Http(e) => assert_eq!(
            e.status(),
            Some(StatusCode::INTERNAL_SERVER_ERROR),
            "the mapped error must carry the status the server actually sent"
        ),
        other => panic!("expected Http, got {other:?}"),
    }

    server.abort();
}

#[tokio::test]
async fn an_envelope_naming_another_did_dies_before_signing() {
    let client = CountingSigner::wrapping(signers::ed25519_did_key());
    let stranger = signers::p256_did_key();

    // Bind first, then build the message around the address this server will
    // actually answer on. That makes the `URI:` line honest, so the origin
    // check passes and the identifier check is the only thing left that can
    // fail: the test isolates one variable instead of relying on the client
    // happening to check the identifier first.
    let (listener, base_url) = bind().await;
    let forwards = Arc::new(AtomicUsize::new(0));
    let envelope = envelope_for(stranger.signer_did(), &base_url);
    let server = serve_on(listener, hostile_router(envelope, forwards.clone()));

    let err = authenticate(&reqwest::Client::new(), &base_url, &client)
        .await
        .expect_err("a message naming another DID must not be signed");

    match err {
        AuthClientError::MessageIdentifierMismatch { expected, actual } => {
            assert_eq!(expected, identifier_of(client.signer_did()));
            assert_eq!(
                actual,
                identifier_of(stranger.signer_did()),
                "the error must report the identifier the server actually sent"
            );
        }
        other => panic!("expected MessageIdentifierMismatch, got {other:?}"),
    }

    assert_eq!(client.calls(), 0, "the refusal must precede signing");
    assert_eq!(forwards.load(Ordering::SeqCst), 0);

    server.abort();
}
