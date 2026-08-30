//! The scoped-self authenticated identity (#167 item #10).
//!
//! aqua-auth's job is to say *who signed*, not to remember them: [`authenticate`]
//! verifies a CAIP-122 signature and returns a [`Principal`]; aqua-node takes
//! that `Principal` and creates/stores the session. aqua-auth persists nothing;
//! its `SessionStore` is a reusable helper, not the owner of sessions (Dalmas
//! ownership ruling; doc 01 §2 / doc 04 §2.1).
//!
//! A `Principal` can only be constructed by successful [`authenticate`] or by
//! [`Principal::from_trusted_did`] (explicit validation), so an unauthenticated
//! string is not a `Principal`. It holds only the DID that signed; there is
//! deliberately **no `actor_did` / `delegated_role`**, so an impersonated or
//! delegated identity is *unrepresentable* rather than merely discouraged
//! (Dalmas scoped-self ruling, via #164): a delegate logs in as its own DID and
//! is authorized downstream by grants.
//!
//! Spec: `docs/superpowers/specs/2026-08-05-principal-and-auth-consolidation-design.md`.
//! Deviation from that spec: it typed the identity as `Principal { did, curve:
//! DidCurve }`, but the merged did:key work never introduced a `DidCurve` enum;
//! the `DIDMethod` registry is the single source of the method/curve. `Principal`
//! therefore stores the DID and defers method/subject questions to the registry
//! (`method_label`, `canonical_subject`), rather than duplicating that knowledge.

use crate::crypto_error::CryptoError;
use crate::did_method::{find_did_method, DIDMethod};

/// A verified, scoped-self authenticated identity: the DID that signed.
///
/// Construct only via [`authenticate`] (proof of possession) or
/// [`Principal::from_trusted_did`] (explicit validation of an already-trusted
/// DID). No delegation state exists on the type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    did: String,
}

impl Principal {
    /// Validate a DID string into a `Principal` **without** proof of possession.
    ///
    /// Use only where the DID is already trusted, e.g. re-hydrating a
    /// `Principal` from an aqua-node-owned session record. Fails with
    /// [`CryptoError::UnsupportedMethod`] if no `DIDMethod` recognises it, so an
    /// unknown or malformed method cannot become a `Principal`.
    pub fn from_trusted_did(did: &str) -> Result<Self, CryptoError> {
        find_did_method(did).ok_or_else(|| CryptoError::UnsupportedMethod(did.to_string()))?;
        Ok(Self { did: did.to_string() })
    }

    /// The complete DID that signed: the identity of record.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The registry's machine label for this DID's method (e.g. `eip155`,
    /// `ed25519`, `p256`). The stand-in for the spec's `curve`, sourced from the
    /// one authority, the `DIDMethod` registry.
    pub fn method_label(&self) -> Result<&'static str, CryptoError> {
        self.method()?.method_label(&self.did)
    }

    /// The registry's canonical subject (the OIDC `sub`); for did:pkh/did:key the
    /// full DID string.
    pub fn canonical_subject(&self) -> Result<String, CryptoError> {
        self.method()?.canonical_subject(&self.did)
    }

    fn method(&self) -> Result<Box<dyn DIDMethod>, CryptoError> {
        find_did_method(&self.did).ok_or_else(|| CryptoError::UnsupportedMethod(self.did.clone()))
    }
}

/// Log a user in: verify a CAIP-122 signature and return the authenticated
/// [`Principal`].
///
/// This is the proof-of-possession entry point; the returned `Principal` has
/// demonstrably signed `message`. aqua-node then creates a session from it;
/// aqua-auth stores nothing. A thin, typed wrapper over [`crate::verify_caip122`]:
/// verify → build the `Principal` on success, [`CryptoError::InvalidSignature`]
/// on failure. `verify_caip122` (returning `bool`) remains for callers that only
/// need the yes/no.
pub fn authenticate(did: &str, message: &str, signature: &[u8]) -> Result<Principal, CryptoError> {
    if crate::verify_caip122(did, message, signature)? {
        Principal::from_trusted_did(did)
    } else {
        Err(CryptoError::InvalidSignature(
            "CAIP-122 signature did not verify for this DID".to_string(),
        ))
    }
}
