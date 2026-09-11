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
    /// [`CryptoError::UnsupportedMethod`] if no `DIDMethod` recognises the
    /// method (SPEC section 7 rule 4), and with [`CryptoError::InvalidDid`] or
    /// [`CryptoError::HexDecode`] if the identifier is the wrong shape for that
    /// namespace (rule 5), so neither an unknown method nor a malformed
    /// identifier can become a `Principal`.
    ///
    /// **Rule 5 is checked here as of 0.8.0.** This is the one path into a
    /// `Principal` that verifies nothing, so before
    /// [`crate::validate_did_well_formed`] existed it was also the one place
    /// where the rule had no enforcement at all: the method was checked, the
    /// identifier was not, and `did:pkh:ed25519:0xdeadbeef` became a
    /// `Principal`. Tightening it cannot invalidate a session that was ever
    /// legitimately issued, because a DID this now refuses could never have
    /// produced a verifying signature in the first place; a stored record
    /// holding one was already unusable.
    pub fn from_trusted_did(did: &str) -> Result<Self, CryptoError> {
        crate::validate_did_well_formed(did)?;
        Ok(Self {
            did: did.to_string(),
        })
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
    authenticate_with_public_key(did, message, signature, None)
}

/// Log a user in when the method needs the signer's public key supplied
/// separately.
///
/// The key-aware twin of [`authenticate`], and the entry point a deployment
/// that accepts `did:aqua` should call. `public_key` is ignored for every
/// classical namespace, so a server can route every login through this one
/// function and pass whatever the request carried.
///
/// The returned [`Principal`] means the same thing either way: this DID
/// demonstrably signed this message. For `did:aqua` that involves one extra
/// step, binding the supplied key back to the DID's hash commitment before
/// the signature is checked at all, so a `Principal` can never be minted for
/// an identity whose key the caller did not actually hold.
///
/// # SPEC section 7 rule 5 is enforced here in its own right
///
/// [`crate::validate_did_well_formed`] runs before verification is attempted,
/// rather than rule 5 being left to whichever parser the verifier happens to
/// reach first. The verifiers underneath still perform their own checks and
/// are unchanged; this is a second layer, not a relocation. The practical
/// difference is that removing, stubbing or short-circuiting the verification
/// path no longer removes rule 5 along with it, which is exactly what the
/// negative control `nc4_skipped_verification_fails_both_signature_cases_and_its_cascade`
/// demonstrated on 2026-09-11.
///
/// For every classical namespace the observable error is unchanged, because
/// the early check calls the same parser the verifier called. The one
/// improvement is `did:aqua`: a malformed `did:aqua` used to report the
/// missing public key first, and now reports the malformed DID.
pub fn authenticate_with_public_key(
    did: &str,
    message: &str,
    signature: &[u8],
    public_key: Option<&[u8]>,
) -> Result<Principal, CryptoError> {
    crate::validate_did_well_formed(did)?;

    if crate::verify_caip122_with_public_key(did, message, signature, public_key)? {
        Principal::from_trusted_did(did)
    } else {
        Err(CryptoError::InvalidSignature(
            "CAIP-122 signature did not verify for this DID".to_string(),
        ))
    }
}
