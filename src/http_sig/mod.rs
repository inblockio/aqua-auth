//! RFC 9421 HTTP Message Signatures: per-request proof of possession.
//!
//! **EXPERIMENTAL.** This module tracks an IETF Internet-Draft and is exempt
//! from the crate's semver stability promise until that draft settles. Pinned
//! revisions consulted while writing it:
//!
//! | Document | Revision consulted |
//! |---|---|
//! | RFC 9421, HTTP Message Signatures | February 2024 (final RFC) |
//! | RFC 8941, Structured Field Values for HTTP | February 2021 (final RFC) |
//! | draft-meunier-web-bot-auth-architecture | **-05**, 2 March 2026 (expires 3 September 2026) |
//!
//! ## Where this sits among the three proof surfaces
//!
//! Aqua has three places a key proves something, all keyed to one identity:
//! aqua-trees sign *content* (the SDK), CAIP-122 signs a *login*
//! ([`crate::authenticate`]), and RFC 9421 signs an *individual HTTP request*
//! (this module). A session token says "this connection was authenticated
//! once"; an RFC 9421 signature says "this exact request came from this key,
//! now".
//!
//! ## The narrow profile
//!
//! RFC 9421 is a large toolkit. This module implements a deliberately small,
//! fixed slice of it so that the signature base is fully determined by a
//! handful of inputs and cannot be negotiated by an attacker:
//!
//! - Covered components are always `"@authority"`, plus `"signature-agent"`
//!   when that header is present on the request. Nothing else is accepted.
//! - Signature parameters are always present, always exactly six, and always
//!   in this order: `created`, `expires`, `keyid`, `alg`, `nonce`, `tag`.
//! - One signature per message, under the label [`SIGNATURE_LABEL`].
//!
//! Verification rejects anything outside that shape rather than trying to
//! accommodate it. That is a profile restriction, not an RFC 9421 defect: a
//! verifier that accepts an attacker-chosen covered-component set is a
//! verifier that can be talked into signing over nothing.
//!
//! ## The key insight: no new cryptographic code
//!
//! RFC 9421 verification reduces to "rebuild a string, then check a signature
//! over it". The string is the *signature base* (RFC 9421 section 2.5). Once
//! it is rebuilt, [`crate::verify_caip122`] verifies it exactly as it verifies
//! a CAIP-122 login message, dispatching through the existing `DIDMethod` and
//! `CipherSuite` registries. This module therefore contains signature-base
//! construction, structured-field handling, parameter validation, and a replay
//! guard, and **zero** cryptographic verifier code.
//!
//! ## Two profiles
//!
//! [`Profile::AquaInternal`] puts the signer's DID directly in `keyid`, so a
//! verifier needs no directory fetch: the key is recoverable from the
//! identifier itself. [`Profile::WebBotAuth`] is the interop shape from
//! draft-meunier: Ed25519 only, `keyid` is a caller-supplied RFC 7638 JWK
//! thumbprint, and `tag` is `web-bot-auth`. Resolving a thumbprint back to a
//! key requires a key directory, which is the `aqua-auth-directory` crate's
//! job, not this module's.
//!
//! ## Deliberately not implemented
//!
//! Server-issued nonces via `Accept-Signature` and RFC 9421 signed *responses*
//! (mutual authentication) are out of scope for now. When `Accept-Signature`
//! arrives, [`crate::ChallengeStore`] is the store that should issue those
//! nonces; the replay guard in this module only remembers nonces it has
//! already seen, it never issues them.

mod base;
mod sign;
#[cfg(test)]
mod test_signers;

pub use sign::sign_request;

use crate::crypto_error::CryptoError;
use crate::did_method::find_did_method;
use std::time::Duration;

/// The signature label this profile uses in `Signature-Input` and `Signature`.
pub const SIGNATURE_LABEL: &str = "sig1";

/// `tag` value for the Aqua-internal profile ([`Profile::AquaInternal`]).
pub const TAG_AQUA_INTERNAL: &str = "aqua-auth";

/// `tag` value mandated by draft-meunier-web-bot-auth-architecture-05.
pub const TAG_WEB_BOT_AUTH: &str = "web-bot-auth";

/// Hard cap on `expires - created`. draft-meunier-web-bot-auth-architecture-05
/// only RECOMMENDS an expiry of no more than 24 hours; this profile makes it a
/// hard limit, at signing and at verification, because a long-lived request
/// signature is a bearer token with extra steps.
pub const MAX_VALIDITY: Duration = Duration::from_secs(24 * 60 * 60);

/// Default tolerance for a signer's clock running ahead of the verifier's.
pub const DEFAULT_CLOCK_SKEW: Duration = Duration::from_secs(60);

/// Nonce length in raw bytes before base64url encoding. draft-meunier
/// RECOMMENDS a 64-byte array.
pub const NONCE_BYTES: usize = 64;

/// `alg` for Ed25519 (RFC 9421 section 3.3.6, IANA-registered).
pub const ALG_ED25519: &str = "ed25519";

/// `alg` for P-256 ECDSA with SHA-256 (RFC 9421 section 3.3.4, IANA-registered).
pub const ALG_ECDSA_P256_SHA256: &str = "ecdsa-p256-sha256";

/// `alg` for EIP-191 `personal_sign` over secp256k1.
///
/// **Not IANA-registered.** There is no registry entry for EIP-191, so this is
/// an Aqua-internal name. It is therefore only meaningful under
/// [`Profile::AquaInternal`]; a `web-bot-auth` peer will not understand it,
/// which is one reason that profile is Ed25519-only.
pub const ALG_EIP191_SECP256K1: &str = "eip191-secp256k1";

/// Everything about an HTTP request that this profile can sign over.
///
/// Framework-agnostic on purpose: no `http` crate types, so axum, hyper,
/// reqwest, and a hand-rolled client all feed the same three strings in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestParts<'a> {
    /// The request method, e.g. `"GET"`.
    ///
    /// Carried for forward compatibility and for callers that want it in their
    /// own logs. This profile does not currently cover `@method`; adding it
    /// would change every signature base, so it is a profile revision, not a
    /// runtime option.
    pub method: &'a str,
    /// The full request target URI, e.g. `"https://node.example.com/v1/trees"`.
    /// `@authority` is derived from this.
    pub target_uri: &'a str,
    /// The `Signature-Agent` header value, if the request carries one. When
    /// present it is always covered by the signature.
    pub signature_agent: Option<&'a str>,
}

impl<'a> RequestParts<'a> {
    /// A request with no `Signature-Agent` header.
    pub fn new(method: &'a str, target_uri: &'a str) -> Self {
        Self {
            method,
            target_uri,
            signature_agent: None,
        }
    }

    /// Attach a `Signature-Agent` header value, bringing it under the signature.
    pub fn with_signature_agent(mut self, value: &'a str) -> Self {
        self.signature_agent = Some(value);
        self
    }
}

/// Which signature profile to produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Profile {
    /// Aqua-internal: `keyid` is the signer's DID, `alg` is implied by the
    /// DID's method, `tag` is [`TAG_AQUA_INTERNAL`]. Self-describing, so a
    /// verifier needs no key directory.
    AquaInternal,
    /// draft-meunier-web-bot-auth-architecture-05 interop: Ed25519 only,
    /// `keyid` is the caller-supplied RFC 7638 JWK thumbprint (base64url,
    /// unpadded), `tag` is [`TAG_WEB_BOT_AUTH`].
    WebBotAuth {
        /// RFC 7638 JWK SHA-256 thumbprint of the Ed25519 public key.
        jwk_thumbprint: String,
    },
}

/// The two header values produced by signing, ready to attach to a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHeaders {
    /// `Signature-Input` header value, e.g.
    /// `sig1=("@authority");created=...;expires=...;keyid="...";alg="...";nonce="...";tag="..."`.
    pub signature_input: String,
    /// `Signature` header value, e.g. `sig1=:BASE64:`.
    pub signature: String,
}

/// Everything that can go wrong signing or verifying a request signature.
#[derive(Debug, thiserror::Error)]
pub enum HttpSigError {
    /// The target URI could not be parsed into an authority.
    #[error("invalid target URI: {0}")]
    InvalidTargetUri(String),

    /// The target URI used a scheme this profile does not sign for.
    #[error("unsupported URI scheme (expected http or https): {0}")]
    UnsupportedScheme(String),

    /// A covered component outside this profile's allowlist was requested.
    #[error("covered component outside this profile: {0}")]
    UnsupportedComponent(String),

    /// A covered component has no value in the request being signed or verified.
    #[error("covered component {0} has no value in this request")]
    MissingComponent(String),

    /// The same component was covered twice (RFC 9421 section 2.5 step 2.1).
    #[error("duplicate covered component: {0}")]
    DuplicateComponent(String),

    /// A component value cannot appear in a signature base.
    #[error("invalid value for covered component {name}: {reason}")]
    InvalidComponentValue {
        /// The component name.
        name: String,
        /// Why the value was rejected.
        reason: String,
    },

    /// The signature base contained non-ASCII bytes (RFC 9421 section 2.5 step 4).
    #[error("signature base contains non-ASCII characters")]
    NonAsciiBase,

    /// A structured field could not be built or parsed (RFC 8941).
    #[error("structured field error: {0}")]
    StructuredField(String),

    /// `Signature-Input` was absent, malformed, or outside this profile.
    #[error("malformed Signature-Input: {0}")]
    MalformedSignatureInput(String),

    /// `Signature` was absent, malformed, or did not match `Signature-Input`.
    #[error("malformed Signature: {0}")]
    MalformedSignature(String),

    /// `expires - created` exceeded [`MAX_VALIDITY`].
    #[error("validity window of {actual}s exceeds the {max}s maximum")]
    ValidityTooLong {
        /// Requested window, in seconds.
        actual: u64,
        /// The cap, in seconds.
        max: u64,
    },

    /// A zero-length validity window was requested, which can never verify.
    #[error("validity window must be non-zero")]
    ValidityZero,

    /// `expires` was not strictly after `created`.
    #[error("invalid validity window: expires {expires} is not after created {created}")]
    InvalidWindow {
        /// The `created` parameter.
        created: i64,
        /// The `expires` parameter.
        expires: i64,
    },

    /// [`Profile::WebBotAuth`] was used with a non-Ed25519 DID.
    #[error("the web-bot-auth profile requires an Ed25519 DID, got {0}")]
    ProfileRequiresEd25519(String),

    /// [`Profile::WebBotAuth`] was given an empty thumbprint.
    #[error("the web-bot-auth profile requires a non-empty JWK thumbprint keyid")]
    EmptyThumbprint,

    /// The signature's `tag` is not the one this verifier accepts.
    #[error("tag mismatch: expected {expected}, signature carries {actual}")]
    TagMismatch {
        /// The tag the verifier requires.
        expected: String,
        /// The tag the signature carries.
        actual: String,
    },

    /// The declared `alg` disagrees with the DID in `keyid`.
    #[error("alg mismatch: {did} implies {expected}, signature declares {actual}")]
    AlgMismatch {
        /// The DID from `keyid`.
        did: String,
        /// The algorithm that DID's method implies.
        expected: String,
        /// The algorithm the signature declares.
        actual: String,
    },

    /// `created` is further in the future than the configured clock skew allows.
    #[error("signature created at {created} is beyond the accepted skew (now {now}, skew {skew}s)")]
    CreatedInFuture {
        /// The `created` parameter.
        created: i64,
        /// The verifier's clock.
        now: i64,
        /// The configured tolerance, in seconds.
        skew: u64,
    },

    /// The signature's validity window has closed.
    #[error("signature expired at {expires} (now {now})")]
    Expired {
        /// The `expires` parameter.
        expires: i64,
        /// The verifier's clock.
        now: i64,
    },

    /// This nonce has already been accepted inside its validity window.
    #[error("nonce replayed")]
    NonceReplayed,

    /// The signing backend failed.
    #[error("signing failed: {0}")]
    Sign(String),

    /// The signature did not verify, or the DID was not usable.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

impl From<sfv::Error> for HttpSigError {
    fn from(e: sfv::Error) -> Self {
        HttpSigError::StructuredField(e.to_string())
    }
}

/// The RFC 9421 `alg` implied by a DID's method.
///
/// The `DIDMethod` registry is the single authority on which curve a DID uses,
/// so the mapping is taken from [`crate::DIDMethod::method_label`] rather than
/// re-parsing the DID here. Note that `method_label` returns the human-facing
/// CAIP-122 label (`"Ethereum"`, `"Ed25519"`, `"P-256"`), not the `did:pkh`
/// namespace, so those are the strings matched below.
pub(crate) fn alg_for_did(did: &str) -> Result<&'static str, HttpSigError> {
    let method =
        find_did_method(did).ok_or_else(|| CryptoError::UnsupportedMethod(did.to_string()))?;
    match method.method_label(did)? {
        "Ed25519" => Ok(ALG_ED25519),
        "P-256" => Ok(ALG_ECDSA_P256_SHA256),
        "Ethereum" => Ok(ALG_EIP191_SECP256K1),
        other => Err(CryptoError::UnsupportedMethod(other.to_string()).into()),
    }
}

/// Seconds since the UNIX epoch.
///
/// A clock before the epoch yields 0, which makes every signature look either
/// expired (when verifying) or created far in the past (when signing). Both
/// fail closed, which is the right behaviour for a broken clock.
#[allow(dead_code)]
pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alg_for_ed25519_did_key() {
        let did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        assert_eq!(alg_for_did(did).unwrap(), ALG_ED25519);
    }

    #[test]
    fn alg_for_eip155_did_pkh() {
        let did = "did:pkh:eip155:1:0x0000000000000000000000000000000000000001";
        assert_eq!(alg_for_did(did).unwrap(), ALG_EIP191_SECP256K1);
    }

    #[test]
    fn alg_for_unknown_method_errors() {
        assert!(alg_for_did("did:example:nope").is_err());
    }
}
