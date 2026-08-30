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

/// A [`Signer`] built from a plain synchronous closure.
///
/// Most callers already have a key object with a synchronous `sign` method
/// (a local keypair, an in-process wallet). Without this adapter each one has
/// to hand-roll an `impl Signer` block: a struct, an `#[async_trait]` impl,
/// and two method bodies, for what is really one line of glue.
///
/// The closure returns the raw signature bytes in the format the DID's cipher
/// suite verifies (65-byte EIP-191 recoverable for `eip155`, 64-byte raw for
/// `ed25519` and `p256`). A caller whose key returns hex decodes it inside the
/// closure.
///
/// Signing runs inline on the calling task, so this is for signers that return
/// immediately. A backend that blocks (a KMS or HSM round trip, a wallet
/// prompt) should implement [`Signer`] directly and actually await, rather
/// than stalling the executor thread from inside this closure.
///
/// ```
/// use aqua_auth::{FnSigner, SignError, Signer};
///
/// # async fn run() -> Result<(), SignError> {
/// let signer = FnSigner::new("did:key:z6MkExample", |message: &str| {
///     Ok(message.as_bytes().to_vec()) // a real signer signs here
/// });
/// let _signature = signer.sign("hello").await?;
/// # Ok(())
/// # }
/// ```
pub struct FnSigner<F> {
    did: String,
    sign: F,
}

impl<F> FnSigner<F>
where
    F: Fn(&str) -> Result<Vec<u8>, SignError> + Send + Sync,
{
    /// Bind `did` to a synchronous signing closure.
    ///
    /// The DID is carried by the signer, so the message and the identity it
    /// is signed under can never be paired up wrongly at the call site.
    pub fn new(did: impl Into<String>, sign: F) -> Self {
        Self {
            did: did.into(),
            sign,
        }
    }
}

#[async_trait]
impl<F> Signer for FnSigner<F>
where
    F: Fn(&str) -> Result<Vec<u8>, SignError> + Send + Sync,
{
    fn signer_did(&self) -> &str {
        &self.did
    }

    async fn sign(&self, message: &str) -> Result<Vec<u8>, SignError> {
        (self.sign)(message)
    }
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

    // ── FnSigner ────────────────────────────────────────────────────────

    /// Build a `(did, sign_fn)` pair over a fresh ed25519 key, the shape a
    /// consumer has before it wraps its own keypair in `FnSigner`.
    fn ed25519_key() -> (String, SigningKey) {
        let key = SigningKey::generate(&mut OsRng);
        let mut bytes = crate::key::ED25519_PREFIX.to_vec();
        bytes.extend_from_slice(key.verifying_key().as_bytes());
        let did = format!("did:key:z{}", bs58::encode(&bytes).into_string());
        (did, key)
    }

    #[tokio::test]
    async fn fn_signer_roundtrips_through_verify_caip122() {
        let (did, key) = ed25519_key();
        let signer = FnSigner::new(did.clone(), move |message: &str| {
            Ok(key.sign(message.as_bytes()).to_bytes().to_vec())
        });

        assert_eq!(signer.signer_did(), did);
        let msg = "fn signer roundtrip";
        let sig = signer.sign(msg).await.unwrap();
        assert!(verify_caip122(signer.signer_did(), msg, &sig).unwrap());
    }

    #[tokio::test]
    async fn fn_signer_is_usable_behind_dyn() {
        let (did, key) = ed25519_key();
        let signer = FnSigner::new(did, move |message: &str| {
            Ok(key.sign(message.as_bytes()).to_bytes().to_vec())
        });
        // `client::authenticate` takes `&dyn Signer`, so this coercion is the
        // property that makes the adapter usable at the real call sites.
        let dyn_signer: &dyn Signer = &signer;
        let sig = dyn_signer.sign("dyn fn signer").await.unwrap();
        assert!(verify_caip122(dyn_signer.signer_did(), "dyn fn signer", &sig).unwrap());
    }

    #[tokio::test]
    async fn fn_signer_propagates_the_closures_error() {
        let signer = FnSigner::new("did:key:z6MkFailing", |_: &str| {
            Err(SignError("hardware wallet said no".into()))
        });
        let err = signer.sign("anything").await.unwrap_err();
        assert_eq!(err.to_string(), "signing failed: hardware wallet said no");
    }

    #[tokio::test]
    async fn fn_signer_sees_the_exact_message_it_was_given() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let recorder = std::sync::Arc::clone(&seen);
        let signer = FnSigner::new("did:key:z6MkRecorder", move |message: &str| {
            *recorder.lock().unwrap() = message.to_string();
            Ok(vec![1, 2, 3])
        });

        let sig = signer
            .sign("the exact\nmultiline CAIP-122 message")
            .await
            .unwrap();
        assert_eq!(sig, vec![1, 2, 3]);
        assert_eq!(
            &*seen.lock().unwrap(),
            "the exact\nmultiline CAIP-122 message"
        );
    }

    #[tokio::test]
    async fn fn_signer_tampered_message_fails_verification() {
        let (did, key) = ed25519_key();
        let signer = FnSigner::new(did, move |message: &str| {
            Ok(key.sign(message.as_bytes()).to_bytes().to_vec())
        });
        let sig = signer.sign("original").await.unwrap();
        assert!(!verify_caip122(signer.signer_did(), "tampered", &sig).unwrap());
    }

    #[tokio::test]
    async fn fn_signer_wrong_did_fails_verification() {
        let (_did, key) = ed25519_key();
        let (other_did, _other_key) = ed25519_key();
        // A valid signature presented under a different DID must not verify.
        let signer = FnSigner::new(other_did, move |message: &str| {
            Ok(key.sign(message.as_bytes()).to_bytes().to_vec())
        });
        let sig = signer.sign("wrong did").await.unwrap();
        assert!(!verify_caip122(signer.signer_did(), "wrong did", &sig).unwrap());
    }
}
