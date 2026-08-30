//! Deterministic simulation tests: the login flow under a hostile network.
//!
//! The same [`AquaPeer`] the other end-to-end suites mount is served here as a
//! [`turmoil`] host, and a simulated client speaks HTTP/1.1 to it over a
//! simulated network that adds latency, partitions, and duplicate delivery.
//! One process, one thread, one seed: every scheduling decision and every
//! injected fault is reproducible.
//!
//! ## Pinned facts
//!
//! - **turmoil version:** `0.7` (`0.7.2` in `Cargo.lock`).
//! - **Serve glue followed:** `examples/axum/src/main.rs` at tag `v0.7.2` of
//!   <https://github.com/tokio-rs/turmoil> (byte-identical to `main` as of
//!   2026-08-30). The example implements [`axum::serve::Listener`] for a
//!   newtype over `turmoil::net::TcpListener` with
//!   `type Io = turmoil::net::TcpStream`, which works because that stream
//!   implements tokio's `AsyncRead`/`AsyncWrite` unconditionally. The
//!   example's second half, a `hyper_util` connector so a hyper client can
//!   dial the simulated network, is deliberately **not** copied: this suite
//!   hand-rolls HTTP/1.1 instead, and reqwest is out of scope under
//!   simulation.
//! - **Seeds:** [`BASELINE_SEED`], [`PARTITION_SEED`].
//!
//! ## Determinism scope
//!
//! A fixed seed pins turmoil's scheduling and fault injection, and nothing
//! else. Challenge nonces still come from `OsRng` inside the crate, session
//! tokens likewise, the harness signers generate a fresh key per test, and the
//! challenge TTL is measured against the real wall clock rather than simulated
//! time. So assertions here are **outcome-based only**: a flow succeeds, a
//! duplicate is refused, a partition is survived. Never assert on a nonce, a
//! token, a timestamp, or a byte-for-byte transcript; those are not, and are
//! not meant to be, reproducible across runs.
//!
//! Real wall time is never waited on. Any waiting below goes through
//! `tokio::time`, which turmoil drives from simulated time, so a "1 second"
//! timeout costs microseconds of real time.
//!
//! ## Feature gate
//!
//! Same gate as `tests/e2e_inmemory.rs`: the harness needs `http` (the stores
//! and wire types) and `http-sig` (`verify_request`), and `http-sig` does not
//! imply `http`. Run with `cargo test --all-features --test dst_auth`.

#![cfg(all(feature = "http", feature = "http-sig"))]

mod harness;

use aqua_auth::wire::{ChallengeEnvelope, SessionRequest, SessionResponse};
use aqua_auth::Signer;
use axum::serve::Listener;
use axum::Router;
use harness::{signers, AquaPeer};
use std::io::{Error, ErrorKind, Result as IoResult};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use turmoil::net::{TcpListener, TcpStream};

/// The simulated hostname the peer answers on. turmoil resolves it for both
/// `TcpStream::connect` and the partition API.
const SERVER_HOST: &str = "server";

/// The simulated hostname the login flow runs from.
const CLIENT_HOST: &str = "client";

/// The port the peer listens on. Fixed rather than ephemeral because the
/// challenge `URI:` line has to be built before the sim starts.
const SERVER_PORT: u16 = 9999;

/// `host:port`, i.e. the `Host` header every request carries and the authority
/// baked into `base_url`.
const AUTHORITY: &str = "server:9999";

/// The peer's origin, and therefore the `URI:` line of every challenge.
const BASE_URL: &str = "http://server:9999";

/// The CAIP-122 domain label.
const PEER_NAME: &str = "peer-sim";

/// Long enough that the real wall clock cannot expire a challenge mid-flow.
/// Simulated latency costs no wall time, so this is generous by a wide margin.
const CHALLENGE_TTL_SECS: u64 = 300;

/// Seed for the plain latency scenario.
const BASELINE_SEED: u64 = 0x5EED_0001;

/// Seed for the partition-then-heal scenario.
const PARTITION_SEED: u64 = 0x5EED_0002;

/// Lower bound on per-message latency.
const MIN_LATENCY: Duration = Duration::from_millis(50);

/// Upper bound on per-message latency.
const MAX_LATENCY: Duration = Duration::from_millis(200);

/// How long one attempt may take before the client abandons it and counts a
/// failure. A partition drops packets silently rather than refusing them, so
/// without a bound an attempt would never fail at all. Simulated time.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(1);

/// Simulated pause between retries.
const RETRY_BACKOFF: Duration = Duration::from_millis(250);

/// Hard cap on retries, so a scenario that never heals fails fast and names
/// itself instead of spinning until the simulation duration runs out.
const MAX_ATTEMPTS: usize = 20;

/// Simulated time to hold the partition before repairing it. Several attempt
/// cycles long, so the client is guaranteed to have failed before the heal.
const HEAL_AFTER: Duration = Duration::from_secs(3);

// ---------------------------------------------------------------------------
// The serve glue
// ---------------------------------------------------------------------------

/// A simulated listener wearing axum's [`Listener`] trait.
///
/// This is the whole adapter. `axum::serve` needs a listener that yields
/// something tokio can read and write, and `turmoil::net::TcpStream` is
/// exactly that, so the newtype only has to forward two methods. Nothing about
/// HTTP or hyper is reimplemented here.
struct TurmoilListener(TcpListener);

impl Listener for TurmoilListener {
    type Io = TcpStream;
    type Addr = SocketAddr;

    fn accept(&mut self) -> impl std::future::Future<Output = (Self::Io, Self::Addr)> + Send {
        async move {
            self.0
                .accept()
                .await
                .expect("the simulated listener stays bound for the life of the host")
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.0.local_addr()
    }
}

/// Serve `router` on the simulated network until the host is torn down.
async fn serve(router: Router) -> turmoil::Result {
    let listener = TcpListener::bind((IpAddr::from(Ipv4Addr::UNSPECIFIED), SERVER_PORT)).await?;
    axum::serve(TurmoilListener(listener), router)
        .await
        .map_err(Into::into)
}

// ---------------------------------------------------------------------------
// A hand-rolled HTTP/1.1 client
// ---------------------------------------------------------------------------

/// The parts of a response this suite reasons about.
#[derive(Debug)]
struct HttpReply {
    status: u16,
    body: Vec<u8>,
}

impl HttpReply {
    /// The body, or a descriptive error naming the status that was returned
    /// instead of `expected`.
    fn expect_status(self, expected: u16, what: &str) -> IoResult<Vec<u8>> {
        if self.status != expected {
            return Err(Error::other(format!(
                "{what}: expected HTTP {expected}, got HTTP {} with body {}",
                self.status,
                String::from_utf8_lossy(&self.body)
            )));
        }
        Ok(self.body)
    }
}

/// One request on one fresh simulated connection.
///
/// `Host` is always sent: without it the peer's `/sig/whoami` handler has no
/// authority to rebuild, and HTTP/1.1 requires it regardless. `Connection:
/// close` keeps every exchange to exactly one connection, which is what makes
/// "two sequential connections" in the duplicate scenario literally true.
async fn request(
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> IoResult<HttpReply> {
    let mut stream = TcpStream::connect(AUTHORITY).await?;

    let mut head = String::new();
    head.push_str(&format!("{method} {path} HTTP/1.1\r\n"));
    head.push_str(&format!("Host: {AUTHORITY}\r\n"));
    head.push_str("Connection: close\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(bytes) = body {
        head.push_str(&format!("Content-Length: {}\r\n", bytes.len()));
    }
    head.push_str("\r\n");

    stream.write_all(head.as_bytes()).await?;
    if let Some(bytes) = body {
        stream.write_all(bytes).await?;
    }
    stream.flush().await?;

    read_reply(&mut stream).await
}

/// Read one response: everything up to the blank line, then exactly as many
/// body bytes as `Content-Length` promises (or to end of stream when the
/// server sent no length, which `Connection: close` makes unambiguous).
async fn read_reply(stream: &mut TcpStream) -> IoResult<HttpReply> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 512];

    let head_end = loop {
        if let Some(at) = find(&raw, b"\r\n\r\n") {
            break at;
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "the connection closed before the response headers were complete",
            ));
        }
        raw.extend_from_slice(&chunk[..read]);
    };

    let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
    let status = parse_status(&head)?;
    let body_start = head_end + 4;

    match content_length(&head) {
        Some(length) => {
            while raw.len() < body_start + length {
                let read = stream.read(&mut chunk).await?;
                if read == 0 {
                    return Err(Error::new(
                        ErrorKind::UnexpectedEof,
                        "the response body was shorter than its Content-Length",
                    ));
                }
                raw.extend_from_slice(&chunk[..read]);
            }
            raw.truncate(body_start + length);
        }
        None => loop {
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            raw.extend_from_slice(&chunk[..read]);
        },
    }

    let body = raw.split_off(body_start);
    Ok(HttpReply { status, body })
}

/// Index of the first occurrence of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// The three-digit code out of a `HTTP/1.1 200 OK` status line.
fn parse_status(head: &str) -> IoResult<u16> {
    head.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                format!("no HTTP status line in response head: {head:?}"),
            )
        })
}

/// `Content-Length`, matched case-insensitively as HTTP requires.
fn content_length(head: &str) -> Option<usize> {
    head.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().ok())
            .flatten()
    })
}

// ---------------------------------------------------------------------------
// The login flow, one step per function
// ---------------------------------------------------------------------------

/// `GET /auth/challenge?did=...`. DIDs contain colons, which RFC 3986 allows
/// in a query unescaped, so the DID goes in verbatim.
async fn fetch_challenge(did: &str) -> IoResult<ChallengeEnvelope> {
    let reply = request("GET", &format!("/auth/challenge?did={did}"), &[], None).await?;
    let body = reply.expect_status(200, "challenge")?;
    serde_json::from_slice(&body).map_err(|e| Error::new(ErrorKind::InvalidData, e))
}

/// Fetch a challenge, retrying while the network refuses to carry it.
///
/// Returns the envelope and the number of attempts that failed first. The loop
/// is bounded twice over: each attempt by [`ATTEMPT_TIMEOUT`], the whole loop
/// by [`MAX_ATTEMPTS`], so a network that never heals produces a named failure
/// rather than a hang.
async fn fetch_challenge_with_retries(did: &str) -> IoResult<(ChallengeEnvelope, usize)> {
    let mut failed_attempts = 0;
    for _ in 0..MAX_ATTEMPTS {
        if let Ok(Ok(envelope)) = tokio::time::timeout(ATTEMPT_TIMEOUT, fetch_challenge(did)).await
        {
            return Ok((envelope, failed_attempts));
        }
        failed_attempts += 1;
        tokio::time::sleep(RETRY_BACKOFF).await;
    }

    Err(Error::other(format!(
        "the challenge never arrived: all {MAX_ATTEMPTS} attempts failed"
    )))
}

/// Sign the challenge message and build the body to post.
async fn sign_challenge(signer: &dyn Signer, envelope: ChallengeEnvelope) -> IoResult<SessionRequest> {
    let signature = signer
        .sign(&envelope.message)
        .await
        .map_err(|e| Error::other(e.to_string()))?;
    Ok(SessionRequest {
        did: signer.signer_did().to_string(),
        nonce: envelope.nonce,
        signature: hex::encode(signature),
    })
}

/// `POST /auth/session`, returning the raw reply so a scenario can assert on
/// the status rather than only on success.
async fn post_session(session_request: &SessionRequest) -> IoResult<HttpReply> {
    let body = serde_json::to_vec(session_request)
        .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
    request(
        "POST",
        "/auth/session",
        &[("Content-Type", "application/json")],
        Some(&body),
    )
    .await
}

/// `GET /whoami` with a session bearer token, returning the DID it reports.
async fn whoami(token: &str) -> IoResult<String> {
    let reply = request(
        "GET",
        "/whoami",
        &[("Authorization", &format!("Bearer {token}"))],
        None,
    )
    .await?;
    let body = reply.expect_status(200, "whoami")?;
    let value: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
    value
        .get("did")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "whoami returned no did field"))
}

/// What a simulated client proved, handed back to the test body to assert on
/// once `Sim::run` has returned.
#[derive(Debug, Default, Clone)]
struct Recorded {
    /// The DID the session was minted for.
    session_did: String,
    /// The DID `/whoami` reported for the minted token.
    whoami_did: String,
    /// Attempts that failed before the flow got through. Zero unless the
    /// scenario broke the network first.
    failed_attempts: usize,
}

/// A slot the client writes its outcome into. Single-threaded under the sim,
/// but a `Mutex` keeps the future `Send`-agnostic and the intent obvious.
type Sink = Arc<Mutex<Option<Recorded>>>;

fn sink() -> Sink {
    Arc::new(Mutex::new(None))
}

/// Read back what the client recorded, failing the test with a useful message
/// if it never got that far.
fn recorded(sink: &Sink) -> Recorded {
    sink.lock()
        .expect("the sink mutex is never poisoned in a single-threaded sim")
        .clone()
        .expect("the simulated client must have recorded an outcome")
}

/// Sign an already-fetched challenge, exchange it for a session, and prove the
/// token authenticates. Returns the session DID and the DID `/whoami` reports.
///
/// Split from [`login`] so the partition scenario can retry only the part that
/// runs on a broken link and then share the rest verbatim.
async fn finish_login(
    signer: &dyn Signer,
    envelope: ChallengeEnvelope,
) -> IoResult<(String, String)> {
    let session_request = sign_challenge(signer, envelope).await?;
    let body = post_session(&session_request)
        .await?
        .expect_status(200, "session")?;
    let session: SessionResponse =
        serde_json::from_slice(&body).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;
    let whoami_did = whoami(&session.token).await?;
    Ok((session.did, whoami_did))
}

/// Challenge, sign, session, `/whoami`: the whole flow, no retries.
async fn login(signer: &dyn Signer) -> IoResult<Recorded> {
    let envelope = fetch_challenge(signer.signer_did()).await?;
    let (session_did, whoami_did) = finish_login(signer, envelope).await?;

    Ok(Recorded {
        session_did,
        whoami_did,
        failed_attempts: 0,
    })
}

// ---------------------------------------------------------------------------
// Simulation setup
// ---------------------------------------------------------------------------

/// A simulation with the seed pinned and latency injected on every message.
fn simulation(seed: u64) -> turmoil::Sim<'static> {
    turmoil::Builder::new()
        .rng_seed(seed)
        .min_message_latency(MIN_LATENCY)
        .max_message_latency(MAX_LATENCY)
        .simulation_duration(Duration::from_secs(120))
        .build()
}

/// Mount `peer`'s router as the `server` host. The closure is called again on
/// every host restart, so the `Router` is cloned per invocation.
fn host_peer(sim: &mut turmoil::Sim<'static>, peer: &AquaPeer) {
    let router = peer.router();
    sim.host(SERVER_HOST, move || serve(router.clone()));
}

/// A peer whose challenges name the simulated origin.
fn simulated_peer(signer: Arc<dyn Signer>) -> AquaPeer {
    AquaPeer::in_memory(PEER_NAME, BASE_URL, CHALLENGE_TTL_SECS, signer)
}

/// The baseline scenario body, parameterised by seed so the stability test can
/// replay it under a different schedule.
fn run_baseline(seed: u64, signer: Arc<dyn Signer>) -> Recorded {
    let peer = simulated_peer(signer.clone());
    let mut sim = simulation(seed);
    host_peer(&mut sim, &peer);

    let sink = sink();
    let client_sink = sink.clone();
    sim.client(CLIENT_HOST, async move {
        let outcome = login(signer.as_ref()).await?;
        *client_sink.lock().unwrap() = Some(outcome);
        Ok(())
    });

    sim.run()
        .unwrap_or_else(|e| panic!("simulation with seed {seed:#x} failed: {e}"));
    recorded(&sink)
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

/// Every message spends 50 to 200 simulated milliseconds on the wire. The flow
/// is challenge-response over four round trips, so this is the scenario that
/// says latency alone breaks nothing.
#[test]
fn login_completes_under_injected_latency() {
    let signer = signers::ed25519_did_key();
    let outcome = run_baseline(BASELINE_SEED, signer.clone());

    assert_eq!(
        outcome.session_did,
        signer.signer_did(),
        "the session must be minted for the DID that signed"
    );
    assert_eq!(
        outcome.whoami_did,
        signer.signer_did(),
        "the minted token must authenticate the same principal"
    );
}

/// The link is cut before the client says a word, then repaired part way
/// through its retry loop. Stepping the simulation by hand keeps the fault
/// injection in the test rather than in the client: the client only knows that
/// attempts fail, never why or when they will stop failing.
#[test]
fn login_survives_a_partition_that_heals() {
    let signer = signers::ed25519_did_key();
    let peer = simulated_peer(signer.clone());
    let mut sim = simulation(PARTITION_SEED);
    host_peer(&mut sim, &peer);

    let sink = sink();
    let client_sink = sink.clone();
    let client_signer = signer.clone();
    sim.client(CLIENT_HOST, async move {
        let signer = client_signer.as_ref();
        let (envelope, failed_attempts) =
            fetch_challenge_with_retries(signer.signer_did()).await?;
        let (session_did, whoami_did) = finish_login(signer, envelope).await?;
        *client_sink.lock().unwrap() = Some(Recorded {
            session_did,
            whoami_did,
            failed_attempts,
        });
        Ok(())
    });

    sim.partition(CLIENT_HOST, SERVER_HOST);

    let mut healed = false;
    loop {
        if !healed && sim.elapsed() >= HEAL_AFTER {
            sim.repair(CLIENT_HOST, SERVER_HOST);
            healed = true;
        }
        if sim.step().expect("the simulation must not fault") {
            break;
        }
    }

    assert!(
        healed,
        "the client finished before the heal, so the partition proved nothing"
    );

    let outcome = recorded(&sink);
    assert!(
        outcome.failed_attempts > 0,
        "the partition must have cost the client at least one attempt"
    );
    assert_eq!(
        outcome.session_did,
        signer.signer_did(),
        "the flow must complete once the link is repaired"
    );
    assert_eq!(
        outcome.whoami_did,
        signer.signer_did(),
        "the token minted after the heal must authenticate"
    );
}
