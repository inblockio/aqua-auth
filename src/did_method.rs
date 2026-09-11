//! `DIDMethod` -- the primary extensibility trait.
//!
//! The server dispatches exclusively on this trait. `CipherSuite` is an
//! implementation detail hidden inside `PkhMethod`.

use crate::crypto_error::CryptoError;

/// Handles DID interpretation, CAIP-122 field extraction, and verification
/// for one DID method (e.g. "pkh", "key", "peer").
///
/// Implementations must be `Send + Sync` (used behind `Arc` in axum state).
pub trait DIDMethod: Send + Sync {
    /// The method name, e.g. `"pkh"`, `"key"`, `"peer"`.
    fn method_name(&self) -> &str;

    /// Returns true if this method should handle `did`.
    fn supports_did(&self, did: &str) -> bool {
        let prefix = format!("did:{}:", self.method_name());
        did.starts_with(&prefix)
    }

    /// Short label for the CAIP-122 sign-in message, e.g. `"Ethereum"`, `"Ed25519"`.
    fn method_label(&self, did: &str) -> Result<&'static str, CryptoError>;

    /// Human-readable label for UI display, e.g. `"0x1234...5678 (Ethereum)"`.
    fn display_label(&self, did: &str) -> Result<String, CryptoError>;

    /// The address string embedded in the CAIP-122 canonical message.
    /// For eip155 this is the EIP-55 checksummed address; for ed25519/p256
    /// it is the hex-encoded public key.
    fn address_for_message(&self, did: &str) -> Result<String, CryptoError>;

    /// True if this DID encodes a CAIP-2 chain ID (only eip155 does).
    fn has_chain_id(&self, did: &str) -> bool;

    /// The CAIP-2 chain ID if present, e.g. `Some("eip155:1")`.
    fn chain_id(&self, did: &str) -> Result<Option<String>, CryptoError>;

    /// The `sub` claim value for OIDC tokens.
    /// For did:pkh this is the full DID string, e.g. `"did:pkh:eip155:1:0x..."`.
    fn canonical_subject(&self, did: &str) -> Result<String, CryptoError>;

    /// Verify a CAIP-122 signature.
    ///
    /// - `did` -- the signer's full DID string
    /// - `canonical_msg` -- the canonical CAIP-122 message that was signed
    /// - `signature` -- raw signature bytes (caller hex-decodes from cookie)
    ///
    /// Methods whose DID does not carry the public key and whose scheme has
    /// no key recovery cannot be served by this signature; they return an
    /// error here and implement [`Self::verify_with_public_key`] instead.
    fn verify(&self, did: &str, canonical_msg: &str, signature: &[u8])
        -> Result<bool, CryptoError>;

    /// Verify a CAIP-122 signature, with the signer's public key supplied
    /// separately when the method needs it.
    ///
    /// Every method that embeds its key in the DID (`did:key`,
    /// `did:pkh:{ed25519,p256}`, `did:peer`) or recovers it from the
    /// signature (`did:pkh:eip155`) ignores `public_key` entirely, which is
    /// what the default implementation does. Only `did:aqua` needs it: it
    /// commits to an ML-DSA-87 key by hash, and ML-DSA has no public-key
    /// recovery, so the key can come from neither place.
    ///
    /// **Where the key comes from is the caller's problem, deliberately.**
    /// This method is synchronous, so a handler that sources the key from a
    /// store or a resolver does that lookup first and passes the result in.
    /// Keeping resolution outside the trait is what lets the wire transport
    /// change later without touching this signature or any implementation.
    ///
    /// Added in 0.8.0 with a default body, so existing implementations
    /// compile unchanged.
    fn verify_with_public_key(
        &self,
        did: &str,
        canonical_msg: &str,
        signature: &[u8],
        public_key: Option<&[u8]>,
    ) -> Result<bool, CryptoError> {
        let _ = public_key;
        self.verify(did, canonical_msg, signature)
    }
}

/// All registered DID method handlers, in priority order.
///
/// Add one line here when a new `DIDMethod` implementation is ready.
pub fn all_did_methods() -> Vec<Box<dyn DIDMethod>> {
    use crate::key::KeyMethod;
    use crate::peer::PeerMethod;
    use crate::pkh::PkhMethod;
    #[allow(unused_mut)]
    let mut methods: Vec<Box<dyn DIDMethod>> = vec![
        Box::new(PkhMethod),
        Box::new(KeyMethod),
        Box::new(PeerMethod),
    ];
    // `did:aqua` is the one gated namespace: it pulls the `ml-dsa` stack,
    // which a deployment with no post-quantum identities should not have to
    // build or audit. See README "Feature flags" for why this one is an
    // exception to the otherwise-universal namespace rule.
    #[cfg(feature = "did-aqua")]
    methods.push(Box::new(crate::aqua::AquaMethod));
    methods
}

/// Find the handler for `did`, or `None` if no registered method matches.
pub fn find_did_method(did: &str) -> Option<Box<dyn DIDMethod>> {
    all_did_methods().into_iter().find(|m| m.supports_did(did))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_unknown_did_returns_none() {
        assert!(find_did_method("did:unknown:foo").is_none());
    }

    #[test]
    fn all_did_methods_has_pkh_key_peer() {
        let methods = all_did_methods();
        let names: Vec<&str> = methods.iter().map(|m| m.method_name()).collect();
        assert!(names.contains(&"pkh"));
        assert!(names.contains(&"key"));
        assert!(names.contains(&"peer"));
    }

    #[test]
    fn find_pkh_did_returns_some() {
        assert!(find_did_method("did:pkh:eip155:1:0xAbc").is_some());
    }

    #[test]
    fn find_key_did_returns_some() {
        assert!(find_did_method("did:key:z6MkiTBz1y").is_some());
    }

    #[test]
    fn find_peer_v0_returns_some() {
        assert!(find_did_method("did:peer:0z6Mkfoo").is_some());
    }

    #[test]
    fn find_peer_v1_returns_none() {
        // variant 1 is not supported
        assert!(find_did_method("did:peer:1zQm").is_none());
    }
}
