//! The async signing contract shared by every proof surface.
//!
//! Mirrors the Aqua SDK `Signer` shape (async `sign` plus `signer_did`) so one
//! key custody point can drive tree signatures, CAIP-122 login signatures, and
//! RFC 9421 request signatures. Unlike the SDK trait it returns raw signature
//! bytes, not a `SignatureRevision`: login and request signatures are not tree
//! revisions.
//!
//! `sign` is async because production signers wait on something external: a
//! cloud KMS or HSM round trip, a wallet prompt, a passkey touch. A local
//! in-memory key simply returns immediately.

use async_trait::async_trait;

/// Error from a signing backend (local key, KMS, HSM, wallet).
#[derive(Debug, thiserror::Error)]
#[error("signing failed: {0}")]
pub struct SignError(pub String);

/// An asynchronous signer bound to a DID.
///
/// The signature bytes must be in the format the DID's cipher suite verifies:
/// 65-byte EIP-191 recoverable for `eip155`, 64-byte raw for `ed25519` and
/// `p256`. A signer carries its own DID so callers can never pair a message
/// with the wrong identity.
#[async_trait]
pub trait Signer: Send + Sync {
    /// The DID this signer proves possession for.
    fn signer_did(&self) -> &str;

    /// Sign an opaque message string (CAIP-122 message or RFC 9421 signature
    /// base). Awaitable so remote and interactive backends fit.
    async fn sign(&self, message: &str) -> Result<Vec<u8>, SignError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_caip122;
    use ed25519_dalek::{Signer as DalekSigner, SigningKey};
    use rand::rngs::OsRng;

    struct LocalEd25519 {
        key: SigningKey,
        did: String,
    }

    impl LocalEd25519 {
        fn generate() -> Self {
            let key = SigningKey::generate(&mut OsRng);
            let mut bytes = crate::key::ED25519_PREFIX.to_vec();
            bytes.extend_from_slice(key.verifying_key().as_bytes());
            let did = format!("did:key:z{}", bs58::encode(&bytes).into_string());
            Self { key, did }
        }
    }

    #[async_trait]
    impl Signer for LocalEd25519 {
        fn signer_did(&self) -> &str {
            &self.did
        }

        async fn sign(&self, message: &str) -> Result<Vec<u8>, SignError> {
            Ok(self.key.sign(message.as_bytes()).to_bytes().to_vec())
        }
    }

    #[tokio::test]
    async fn local_ed25519_signer_roundtrips_through_verify_caip122() {
        let signer = LocalEd25519::generate();
        let msg = "signer trait roundtrip";
        let sig = signer.sign(msg).await.unwrap();
        assert!(verify_caip122(signer.signer_did(), msg, &sig).unwrap());
    }

    #[tokio::test]
    async fn signer_is_object_safe_behind_dyn() {
        let signer = LocalEd25519::generate();
        let dyn_signer: &dyn Signer = &signer;
        let msg = "dyn signer";
        let sig = dyn_signer.sign(msg).await.unwrap();
        assert!(verify_caip122(dyn_signer.signer_did(), msg, &sig).unwrap());
    }

    #[tokio::test]
    async fn tampered_message_fails_verification() {
        let signer = LocalEd25519::generate();
        let sig = signer.sign("original").await.unwrap();
        assert!(!verify_caip122(signer.signer_did(), "tampered", &sig).unwrap());
    }
}
