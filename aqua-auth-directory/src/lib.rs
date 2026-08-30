//! Public-key advertisement for Aqua services.
//!
//! A service registers the Ed25519 keys it signs with and serves them at two
//! well-known paths: a JWKS view for interoperability with the web-bot-auth
//! ecosystem, and an Aqua-native identity document that speaks in DIDs.
//!
//! # Boundary
//!
//! This crate handles public keys only. It never takes, stores, derives or
//! returns private key material, and no API here accepts a signing key.
//! Custody belongs to the `Signer` implementation in `aqua-auth`. Advertising
//! a key and being able to use it are separate concerns, and separating them
//! is the entire point of this crate being its own compilation unit.
//!
//! # Stability
//!
//! Experimental. This crate tracks an IETF Internet-Draft (see [`render`]),
//! so it is versioned 0.x separately from `aqua-auth`: draft churn must never
//! force a semver bump on the authentication crate.
//!
//! # Scope in v0.1
//!
//! Ed25519 `did:key` (`z6Mk...`) only. The JWKS view is defined over OKP keys,
//! and web-bot-auth is Ed25519-only, so there is nothing to gain from
//! advertising key types the consuming profile cannot use. The
//! `did:pkh:ed25519` spelling is a distinct principal (see the two-principal
//! ruling in the project CLAUDE.md) and is not accepted here.

pub mod render;
pub mod thumbprint;

pub use render::{
    render_aqua_identity, render_jwks, DirectoryDocument, WELL_KNOWN_AQUA_IDENTITY,
    WELL_KNOWN_HTTP_MESSAGE_SIGNATURES,
};
pub use thumbprint::okp_thumbprint;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};

/// The curve name advertised for every key in v0.1.
pub(crate) const CRV_ED25519: &str = "Ed25519";

/// Something went wrong building or rendering an advertisement.
#[derive(Debug, thiserror::Error)]
pub enum DirectoryError {
    /// The validity window is empty or inverted. `exp` is exclusive, so a key
    /// with `exp <= nbf` is never active and advertising it is meaningless.
    #[error("invalid validity window: exp ({exp}) must be greater than nbf ({nbf})")]
    InvalidWindow { nbf: u64, exp: u64 },

    /// The DID is not an Ed25519 `did:key`, the only form advertised in v0.1.
    #[error("unsupported DID for advertisement, expected an Ed25519 did:key: {0}")]
    UnsupportedDid(String),

    /// Serializing a rendered document failed.
    #[error("failed to serialize directory document: {0}")]
    Serialization(String),
}

/// One advertised public key and the window it is valid for.
///
/// `nbf` is inclusive and `exp` is exclusive, both in unix seconds, so a key
/// is live exactly when `nbf <= now < exp`. Windows are allowed to overlap:
/// that overlap is how key rotation stays seamless, since a verifier that
/// fetched the directory at any point during the overlap holds both the
/// outgoing and the incoming key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvertisedKey {
    /// Ed25519 `did:key` (`z6Mk...` form). Ed25519 only in v0.1.
    pub did: String,
    /// Not-before, unix seconds, inclusive.
    pub nbf: u64,
    /// Expiry, unix seconds, exclusive.
    pub exp: u64,
}

impl AdvertisedKey {
    /// The JWK `x` member: the DID's raw 32-byte public key, base64url
    /// unpadded.
    ///
    /// Fallible because the public fields let a caller build a key that never
    /// went through [`KeyRegistry::add`]; keys that did are always valid here.
    pub fn x_b64url(&self) -> Result<String, DirectoryError> {
        let raw = aqua_auth::ed25519_pubkey_from_did_key(&self.did)
            .map_err(|e| DirectoryError::UnsupportedDid(e.to_string()))?;
        Ok(URL_SAFE_NO_PAD.encode(raw))
    }

    /// The RFC 7638 thumbprint of this key's JWK, used as the JWKS `kid` and
    /// as the web-bot-auth `keyid`.
    pub fn thumbprint(&self) -> Result<String, DirectoryError> {
        Ok(okp_thumbprint(CRV_ED25519, &self.x_b64url()?))
    }

    /// Whether this key is live at `now` (`nbf` inclusive, `exp` exclusive).
    pub fn is_active_at(&self, now: u64) -> bool {
        self.nbf <= now && now < self.exp
    }
}

/// The set of public keys a service advertises.
///
/// Insertion-ordered, and rendering preserves that order so a directory
/// response is stable between fetches when the registry has not changed.
#[derive(Debug, Clone, Default)]
pub struct KeyRegistry {
    keys: Vec<AdvertisedKey>,
}

impl KeyRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a key, rejecting anything that could not be meaningfully
    /// advertised: an empty or inverted window, or a DID that is not an
    /// Ed25519 `did:key`.
    ///
    /// Validating on the way in is what lets rendering treat every stored key
    /// as well-formed instead of having to skip or report bad entries while
    /// serving a request.
    pub fn add(&mut self, key: AdvertisedKey) -> Result<(), DirectoryError> {
        if key.exp <= key.nbf {
            return Err(DirectoryError::InvalidWindow {
                nbf: key.nbf,
                exp: key.exp,
            });
        }
        // Parse for effect: this is the did:key well-formedness check, and it
        // rejects both non-Ed25519 key types and the did:pkh spelling.
        aqua_auth::ed25519_pubkey_from_did_key(&key.did)
            .map_err(|e| DirectoryError::UnsupportedDid(e.to_string()))?;
        self.keys.push(key);
        Ok(())
    }

    /// The keys live at `now`.
    ///
    /// Rotation overlap needs no special case: when a predecessor and its
    /// successor have overlapping windows, both satisfy the same predicate
    /// and both are returned.
    pub fn active(&self, now: u64) -> Vec<&AdvertisedKey> {
        self.keys.iter().filter(|k| k.is_active_at(now)).collect()
    }

    /// Every registered key, live or not.
    pub fn keys(&self) -> &[AdvertisedKey] {
        &self.keys
    }

    /// How many keys are registered.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether no keys are registered.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Valid Ed25519 `did:key` fixtures, with the base64url encoding of the
    /// raw public key each one carries. Confirmed to decode to a 0xED01
    /// multicodec prefix followed by 32 bytes.
    pub(crate) const DID_A: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    pub(crate) const X_A: &str = "Lm_M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY";
    pub(crate) const DID_B: &str = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";
    pub(crate) const X_B: &str = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik";
    /// A P-256 `did:key`, which is well-formed but out of scope in v0.1.
    pub(crate) const DID_P256: &str =
        "did:key:zDnaeQVuEURtDUXbSTyTUdJpYzELcVW3bTUyvU2rzNRQWuQEb";

    pub(crate) fn key(did: &str, nbf: u64, exp: u64) -> AdvertisedKey {
        AdvertisedKey {
            did: did.to_string(),
            nbf,
            exp,
        }
    }

    #[test]
    fn add_accepts_a_valid_ed25519_did_key() {
        let mut reg = KeyRegistry::new();
        assert!(reg.add(key(DID_A, 100, 200)).is_ok());
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn add_rejects_exp_equal_to_nbf() {
        // The window is half-open, so exp == nbf can never be active.
        let mut reg = KeyRegistry::new();
        assert!(matches!(
            reg.add(key(DID_A, 100, 100)),
            Err(DirectoryError::InvalidWindow { .. })
        ));
        assert_eq!(reg.len(), 0, "a rejected key must not be stored");
    }

    #[test]
    fn add_rejects_exp_before_nbf() {
        let mut reg = KeyRegistry::new();
        assert!(matches!(
            reg.add(key(DID_A, 200, 100)),
            Err(DirectoryError::InvalidWindow { .. })
        ));
    }

    #[test]
    fn add_rejects_p256_did_key() {
        let mut reg = KeyRegistry::new();
        assert!(matches!(
            reg.add(key(DID_P256, 100, 200)),
            Err(DirectoryError::UnsupportedDid(_))
        ));
    }

    #[test]
    fn add_rejects_the_pkh_ed25519_spelling() {
        // Same underlying key type, different principal, out of scope in v0.1.
        let mut reg = KeyRegistry::new();
        let did = format!("did:pkh:ed25519:0x{}", "aa".repeat(32));
        assert!(matches!(
            reg.add(key(&did, 100, 200)),
            Err(DirectoryError::UnsupportedDid(_))
        ));
    }

    #[test]
    fn add_rejects_a_malformed_did() {
        let mut reg = KeyRegistry::new();
        assert!(reg.add(key("not-a-did", 100, 200)).is_err());
        assert!(reg.add(key("did:key:zzzz!!!", 100, 200)).is_err());
    }

    #[test]
    fn active_includes_a_key_exactly_at_nbf() {
        // nbf is inclusive.
        let mut reg = KeyRegistry::new();
        reg.add(key(DID_A, 100, 200)).unwrap();
        assert_eq!(reg.active(100).len(), 1);
    }

    #[test]
    fn active_excludes_a_key_exactly_at_exp() {
        // exp is exclusive.
        let mut reg = KeyRegistry::new();
        reg.add(key(DID_A, 100, 200)).unwrap();
        assert_eq!(reg.active(199).len(), 1);
        assert_eq!(reg.active(200).len(), 0);
    }

    #[test]
    fn active_excludes_a_key_before_nbf() {
        let mut reg = KeyRegistry::new();
        reg.add(key(DID_A, 100, 200)).unwrap();
        assert_eq!(reg.active(99).len(), 0);
    }

    #[test]
    fn active_is_empty_when_every_key_has_expired() {
        let mut reg = KeyRegistry::new();
        reg.add(key(DID_A, 100, 200)).unwrap();
        reg.add(key(DID_B, 150, 250)).unwrap();
        assert!(reg.active(1_000).is_empty());
    }

    #[test]
    fn rotation_overlap_returns_both_keys() {
        // Predecessor and successor windows overlap on [150, 200); a verifier
        // fetching mid-rotation must see both, or requests signed by whichever
        // key it did not receive fail.
        let mut reg = KeyRegistry::new();
        reg.add(key(DID_A, 100, 200)).unwrap();
        reg.add(key(DID_B, 150, 300)).unwrap();

        let dids: Vec<&str> = reg.active(175).iter().map(|k| k.did.as_str()).collect();
        assert_eq!(dids.len(), 2, "both keys are live during the overlap");
        assert!(dids.contains(&DID_A));
        assert!(dids.contains(&DID_B));

        // Outside the overlap only the successor remains.
        let after: Vec<&str> = reg.active(250).iter().map(|k| k.did.as_str()).collect();
        assert_eq!(after, vec![DID_B]);
    }

    #[test]
    fn x_b64url_is_the_dids_raw_public_key() {
        assert_eq!(key(DID_A, 0, 1).x_b64url().unwrap(), X_A);
        assert_eq!(key(DID_B, 0, 1).x_b64url().unwrap(), X_B);
    }

    #[test]
    fn thumbprint_is_the_rfc7638_thumbprint_of_the_advertised_jwk() {
        let k = key(DID_A, 0, 1);
        assert_eq!(k.thumbprint().unwrap(), okp_thumbprint("Ed25519", X_A));
    }

    #[test]
    fn derivation_fails_for_a_did_that_never_passed_add() {
        // The fields are public, so an unvalidated key is constructible; the
        // derivations must refuse it rather than panic.
        let k = key(DID_P256, 0, 1);
        assert!(k.x_b64url().is_err());
        assert!(k.thumbprint().is_err());
    }
}
