//! `AquaPeer`: one Aqua service definition, mountable three ways.
//!
//! A peer is an identity (its own [`Signer`]) plus the real server-side state
//! aqua-auth ships (a [`ChallengeStore`], a [`SessionStore`], a
//! [`NonceReplayGuard`], a [`KeyRegistry`]) plus an axum [`Router`] of thin
//! handlers over the real crate APIs. Nothing here reimplements verification;
//! the handlers do exactly what the aqua-auth README's server quick start does.
//!
//! The same `router()` serves every mode:
//!
//! - **in-memory** ([`AquaPeer::in_memory`]): driven by `tower`'s
//!   `ServiceExt::oneshot`, no listener and no port, in `tests/e2e_inmemory.rs`
//! - **loopback** ([`AquaPeer::bind_loopback`]): bound on an ephemeral
//!   `127.0.0.1` port so the real reqwest client runs against it
//! - **simulated**: the same `Router` mounted as a host under a deterministic
//!   network simulator
//!
//! This crate is the promoted form of aqua-auth's former `tests/harness/`
//! module (promotion trigger: a second repo needed `AquaPeer`). It is
//! `publish = false` by ruling: consumers reach it by path or git, and its
//! API carries no stability promise. The e2e suites live in this crate's
//! `tests/` so they always compile with the features they need; aqua-auth's
//! own feature-lane matrix is unaffected by this crate.

pub mod signers;

use aqua_auth::http_sig::{NonceReplayGuard, RequestParts, VerifyOptions};
use aqua_auth::wire::{ChallengeEnvelope, SessionRequest, SessionResponse};
use aqua_auth::{authenticate, AuthError, ChallengeStore, SessionStore, Signer};
use aqua_auth_directory::{
    render_aqua_identity, render_jwks, AdvertisedKey, DirectoryDocument, DirectoryError,
    KeyRegistry, WELL_KNOWN_AQUA_IDENTITY, WELL_KNOWN_HTTP_MESSAGE_SIGNATURES,
};
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Session lifetime for every harness peer. Long enough that no test can trip
/// over it; challenge TTL is the knob expiry tests turn instead.
pub const SESSION_TTL_SECS: u64 = 3600;

/// `nbf` of the peer's self-advertised key: live since the epoch.
pub const ADVERTISED_NBF: u64 = 0;

/// `exp` of the peer's self-advertised key (2100-01-01T00:00:00Z). A fixed
/// constant rather than `now + something`, so the rendered directory is
/// identical between runs.
pub const ADVERTISED_EXP: u64 = 4_102_444_800;

/// One Aqua service: an identity, the real server-side stores, and a router.
pub struct AquaPeer {
    /// The CAIP-122 domain label this peer signs challenges under.
    pub name: String,
    /// The origin baked into every challenge's `URI:` line. Fictional in
    /// in-memory mode, the actual bound address in loopback mode.
    pub base_url: String,
    /// This peer's own identity, for when it acts as a client.
    pub signer: Arc<dyn Signer>,
    /// Pending challenges, keyed by nonce, single-use.
    pub challenges: Arc<ChallengeStore>,
    /// Issued session tokens.
    pub sessions: Arc<SessionStore>,
    /// RFC 9421 nonces already spent, for `/sig/whoami`.
    pub replay_guard: Arc<NonceReplayGuard>,
    /// The public keys this peer advertises at its two well-known paths.
    pub registry: Arc<KeyRegistry>,
}

impl AquaPeer {
    /// A peer with a fictional `base_url` (e.g. `"http://peer-a.test"`), for
    /// suites that never open a socket.
    ///
    /// `challenge_ttl_secs` is a parameter rather than a constant so an expiry
    /// test can ask for a 1-second TTL and then outlive it, which is the one
    /// place real time is unavoidable without injecting a clock into `src/`.
    pub fn in_memory(
        name: &str,
        base_url: &str,
        challenge_ttl_secs: u64,
        signer: Arc<dyn Signer>,
    ) -> Self {
        let challenges = Arc::new(ChallengeStore::new(
            challenge_ttl_secs,
            name.to_string(),
            base_url.to_string(),
        ));

        // Advertise the peer's own key when it is an Ed25519 did:key; the
        // directory crate accepts nothing else in v0.1, so any other spelling
        // simply leaves the registry empty and the well-known documents render
        // an empty key list. That is a truthful answer, not an error.
        let mut registry = KeyRegistry::new();
        let _ = registry.add(AdvertisedKey {
            did: signer.signer_did().to_string(),
            nbf: ADVERTISED_NBF,
            exp: ADVERTISED_EXP,
        });

        Self {
            name: name.to_string(),
            base_url: base_url.to_string(),
            signer,
            challenges,
            sessions: Arc::new(SessionStore::new(SESSION_TTL_SECS)),
            replay_guard: Arc::new(NonceReplayGuard::new()),
            registry: Arc::new(registry),
        }
    }

    /// Bind an ephemeral loopback port, then build the peer around the address
    /// it actually got, then serve.
    ///
    /// The order matters: the challenge `URI:` line has to carry the real
    /// origin, because the client's URI-binding check compares it against the
    /// `base_url` it dialed. Constructing the peer before binding would bake in
    /// a port that is not the one being served.
    ///
    /// Returns the peer, its `base_url`, and the serve task's handle. Dropping
    /// the handle detaches the task; aborting it stops the listener.
    pub async fn bind_loopback(
        name: &str,
        challenge_ttl_secs: u64,
        signer: Arc<dyn Signer>,
    ) -> (Self, String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binding an ephemeral loopback port must succeed");
        let address = listener
            .local_addr()
            .expect("a bound listener has a local address");
        let base_url = format!("http://{address}");

        let peer = Self::in_memory(name, &base_url, challenge_ttl_secs, signer);
        let router = peer.router();
        let handle = tokio::spawn(async move {
            // A shut-down listener is the normal end of a test, not a failure.
            let _ = axum::serve(listener, router).await;
        });

        (peer, base_url, handle)
    }

    /// The authority (`host[:port]`) of this peer's `base_url`, i.e. what a
    /// client puts in the `Host` header and what `@authority` must equal.
    pub fn authority(&self) -> String {
        let after_scheme = self
            .base_url
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(&self.base_url);
        after_scheme
            .split(['/', '?', '#'])
            .next()
            .unwrap_or(after_scheme)
            .to_string()
    }

    /// The router, with the peer's `Arc`s cloned into its state.
    ///
    /// Cheap enough to call per request: every clone shares the same stores, so
    /// a nonce issued through one router is spent through the next.
    pub fn router(&self) -> Router {
        let state = PeerState {
            challenges: self.challenges.clone(),
            sessions: self.sessions.clone(),
            replay_guard: self.replay_guard.clone(),
            registry: self.registry.clone(),
            scheme: scheme_of(&self.base_url),
        };

        Router::new()
            .route("/auth/challenge", get(challenge_handler))
            .route("/auth/session", post(session_handler))
            .route("/whoami", get(whoami_handler))
            .route("/sig/whoami", get(sig_whoami_handler))
            .route(WELL_KNOWN_HTTP_MESSAGE_SIGNATURES, get(jwks_handler))
            .route(WELL_KNOWN_AQUA_IDENTITY, get(aqua_identity_handler))
            .with_state(state)
    }
}

/// What the handlers see: the peer's shared state, no `&self`.
#[derive(Clone)]
struct PeerState {
    challenges: Arc<ChallengeStore>,
    sessions: Arc<SessionStore>,
    replay_guard: Arc<NonceReplayGuard>,
    registry: Arc<KeyRegistry>,
    /// The scheme half of `base_url`, needed to rebuild a target URI from the
    /// `Host` header (an HTTP/1.1 request line carries no scheme).
    scheme: String,
}

fn scheme_of(base_url: &str) -> String {
    base_url
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
        .unwrap_or_else(|| "http".to_string())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Deserialize)]
struct ChallengeQuery {
    did: Option<String>,
}

/// `GET /auth/challenge?did=...`
///
/// 400 for a missing DID or one no `DIDMethod` recognises, so an unsupported
/// namespace is refused before a challenge is ever minted for it.
async fn challenge_handler(
    State(state): State<PeerState>,
    Query(query): Query<ChallengeQuery>,
) -> Result<Json<ChallengeEnvelope>, StatusCode> {
    let did = query.did.ok_or(StatusCode::BAD_REQUEST)?;
    if aqua_auth::find_did_method(&did).is_none() {
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

/// `POST /auth/session`
///
/// 404 for a nonce this server never issued (or has already spent), 401 for
/// everything else that fails: an expired challenge, a DID that is not the one
/// the nonce was issued to, an unparseable signature, a signature that does not
/// verify. 503 when the session store is at capacity, which is a server
/// condition rather than a client one.
async fn session_handler(
    State(state): State<PeerState>,
    Json(request): Json<SessionRequest>,
) -> Result<Json<SessionResponse>, StatusCode> {
    let stored = match state.challenges.validate(&request.nonce) {
        Ok(challenge) => challenge,
        Err(AuthError::ChallengeNotFound) => return Err(StatusCode::NOT_FOUND),
        Err(_) => return Err(StatusCode::UNAUTHORIZED),
    };

    // The nonce was issued to one DID. Anyone else presenting it is refused
    // even before the signature is looked at.
    if stored.did != request.did {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let signature = hex::decode(request.signature.trim_start_matches("0x"))
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let principal = authenticate(&request.did, &stored.message, &signature)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let session = state
        .sessions
        .create(principal.did())
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    Ok(Json(SessionResponse {
        did: session.did,
        token: session.token,
        valid_until: session.valid_until,
        created_at: session.created_at,
    }))
}

/// `GET /whoami`, authenticated by a session bearer token.
async fn whoami_handler(
    State(state): State<PeerState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let token = bearer_token(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let did = state
        .sessions
        .validate(token)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(Json(json!({ "did": did })))
}

/// `GET /sig/whoami`, authenticated by an RFC 9421 request signature.
///
/// The request parts are rebuilt from the request *as received*, never from the
/// signature parameters: `@authority` comes from the `Host` header, so a
/// signature made for one host and presented to another rebuilds a different
/// signature base and fails to verify. That is the whole point of covering
/// `@authority`.
async fn sig_whoami_handler(
    State(state): State<PeerState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let authority = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        .or_else(|| uri.authority().map(ToString::to_string))
        .ok_or(StatusCode::BAD_REQUEST)?;
    let target_uri = format!("{}://{}{}", state.scheme, authority, uri.path());

    let signature_input =
        header_str(&headers, "signature-input").ok_or(StatusCode::UNAUTHORIZED)?;
    let signature = header_str(&headers, "signature").ok_or(StatusCode::UNAUTHORIZED)?;

    // `signature-agent` is covered by the signature whenever the request
    // carries it, so it has to be fed in from the request too, not assumed
    // absent.
    let mut parts = RequestParts::new(method.as_str(), &target_uri);
    if let Some(agent) = header_str(&headers, "signature-agent") {
        parts = parts.with_signature_agent(agent);
    }

    let options = VerifyOptions::aqua_internal().with_replay_guard(state.replay_guard.clone());
    let principal = aqua_auth::verify_request(&parts, signature_input, signature, &options)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    Ok(Json(json!({ "did": principal.did() })))
}

/// `GET /.well-known/http-message-signatures-directory`
async fn jwks_handler(State(state): State<PeerState>) -> Result<Response, StatusCode> {
    serve_document(render_jwks(&state.registry, unix_now()))
}

/// `GET /.well-known/aqua-identity`
async fn aqua_identity_handler(State(state): State<PeerState>) -> Result<Response, StatusCode> {
    serve_document(render_aqua_identity(&state.registry, unix_now()))
}

/// Serve a rendered directory document with the content type and cache
/// directive the renderer chose. The renderer owns those, not the router.
fn serve_document(
    document: Result<DirectoryDocument, DirectoryError>,
) -> Result<Response, StatusCode> {
    let document = document.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((
        [
            (header::CONTENT_TYPE, document.content_type.to_string()),
            (header::CACHE_CONTROL, document.cache_control),
        ],
        document.body,
    )
        .into_response())
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    header_str(headers, header::AUTHORIZATION.as_str())?.strip_prefix("Bearer ")
}
