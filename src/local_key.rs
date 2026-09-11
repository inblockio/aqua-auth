//! [`LocalKeySigner`]: a [`Signer`] over a private key held in this process.
//!
//! Every consumer that keeps a key on disk was writing this: load a PKCS#8 PEM,
//! derive the `did:key`, implement the trait. aqua-agents wrote a whole
//! `signer.rs` for it, aqua-analytics wraps its key in [`crate::FnSigner`] at
//! the call site, and the testkit has a generate-only variant. Three solutions
//! to the default case argues the default case belongs here.
//!
//! Re-deriving the DID at each site is the part that actually bites: a DID
//! string is an identity, so two producers that encode differently mint two
//! identities for one key. This type derives it once, through
//! [`crate::did::ed25519_did_key_from_pubkey`] and
//! [`crate::did::p256_did_key_from_pubkey`], so the DID and the key cannot drift
//! apart.
//!
//! Behind the `local-key` feature: holding raw private key material in process
//! memory is exactly what a production signer should not do, so it is opt-in.
//! A KMS, HSM, wallet or passkey backend implements [`Signer`] directly and
//! actually awaits.

use std::path::Path;

use async_trait::async_trait;

use crate::signer::{SignError, Signer};

/// Failure loading a local key.
#[derive(Debug, thiserror::Error)]
pub enum LocalKeyError {
    /// The file could not be read.
    #[error("read key file {path}: {source}")]
    Io {
        /// The path that failed.
        path: String,
        /// The underlying IO error.
        source: std::io::Error,
    },
    /// The PEM did not parse as a PKCS#8 private key of the expected curve.
    #[error("not a PKCS#8 {curve} private key: {detail}")]
    Pkcs8 {
        /// The curve that was expected.
        curve: &'static str,
        /// The decoder's message.
        detail: String,
    },
}

/// The curve a [`LocalKeySigner`] holds.
enum Key {
    Ed25519(Box<ed25519_dalek::SigningKey>),
    P256(Box<p256::ecdsa::SigningKey>),
}

/// A [`Signer`] over an in-process private key, carrying its own `did:key`.
///
/// ```no_run
/// use aqua_auth::{LocalKeySigner, Signer};
///
/// # fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let signer = LocalKeySigner::ed25519_from_pem_file("agent.pem")?;
/// println!("{}", signer.signer_did()); // did:key:z6Mk...
/// # Ok(())
/// # }
/// ```
pub struct LocalKeySigner {
    key: Key,
    did: String,
}

impl LocalKeySigner {
    /// Load an Ed25519 key from a PKCS#8 PEM string and derive its `did:key`.
    pub fn ed25519_from_pem(pem: &str) -> Result<Self, LocalKeyError> {
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        let key =
            ed25519_dalek::SigningKey::from_pkcs8_pem(pem).map_err(|e| LocalKeyError::Pkcs8 {
                curve: "Ed25519",
                detail: e.to_string(),
            })?;
        let did = crate::did::ed25519_did_key_from_pubkey(&key.verifying_key().to_bytes());
        Ok(Self {
            key: Key::Ed25519(Box::new(key)),
            did,
        })
    }

    /// Load a P-256 key from a PKCS#8 PEM string and derive its `did:key`.
    pub fn p256_from_pem(pem: &str) -> Result<Self, LocalKeyError> {
        use p256::pkcs8::DecodePrivateKey;
        let key =
            p256::ecdsa::SigningKey::from_pkcs8_pem(pem).map_err(|e| LocalKeyError::Pkcs8 {
                curve: "P-256",
                detail: e.to_string(),
            })?;
        let point = key.verifying_key().to_encoded_point(true);
        let mut compressed = [0u8; 33];
        compressed.copy_from_slice(point.as_bytes());
        let did = crate::did::p256_did_key_from_pubkey(&compressed);
        Ok(Self {
            key: Key::P256(Box::new(key)),
            did,
        })
    }

    /// Load an Ed25519 key from a PKCS#8 PEM file.
    pub fn ed25519_from_pem_file(path: impl AsRef<Path>) -> Result<Self, LocalKeyError> {
        Self::ed25519_from_pem(&read_pem(path.as_ref())?)
    }

    /// Load a P-256 key from a PKCS#8 PEM file.
    pub fn p256_from_pem_file(path: impl AsRef<Path>) -> Result<Self, LocalKeyError> {
        Self::p256_from_pem(&read_pem(path.as_ref())?)
    }
}

/// Redacted on purpose. A derived `Debug` would print the private scalar into
/// whatever log or panic message formatted the signer, which is the classic way
/// key material escapes a process. Only the DID, which is public, is shown.
impl std::fmt::Debug for LocalKeySigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let curve = match self.key {
            Key::Ed25519(_) => "Ed25519",
            Key::P256(_) => "P-256",
        };
        f.debug_struct("LocalKeySigner")
            .field("did", &self.did)
            .field("curve", &curve)
            .field("key", &"<redacted>")
            .finish()
    }
}

fn read_pem(path: &Path) -> Result<String, LocalKeyError> {
    std::fs::read_to_string(path).map_err(|source| LocalKeyError::Io {
        path: path.display().to_string(),
        source,
    })
}

#[async_trait]
impl Signer for LocalKeySigner {
    fn signer_did(&self) -> &str {
        &self.did
    }

    async fn sign(&self, message: &str) -> Result<Vec<u8>, SignError> {
        Ok(match &self.key {
            Key::Ed25519(k) => {
                use ed25519_dalek::Signer as _;
                k.sign(message.as_bytes()).to_bytes().to_vec()
            }
            Key::P256(k) => {
                use p256::ecdsa::signature::Signer as _;
                let sig: p256::ecdsa::Signature = k.sign(message.as_bytes());
                sig.to_bytes().to_vec()
            }
        })
    }
}

// These tests use the boolean verifier deliberately: they assert that a
// signature does or does not verify, which is exactly the yes/no question
// `verify_caip122` still exists to answer. Not a pending migration.
#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::verify_caip122;

    fn ed25519_pem() -> String {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng)
            .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
            .unwrap()
            .to_string()
    }

    fn p256_pem() -> String {
        use p256::pkcs8::EncodePrivateKey;
        p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng)
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string()
    }

    /// The whole point of the type: the DID it advertises verifies the
    /// signatures it produces. If the derivation and the key ever drift apart,
    /// this fails.
    #[tokio::test]
    async fn ed25519_did_verifies_its_own_signature() {
        let signer = LocalKeySigner::ed25519_from_pem(&ed25519_pem()).unwrap();
        assert!(signer.signer_did().starts_with("did:key:z6Mk"));
        let sig = signer.sign("hello").await.unwrap();
        assert!(verify_caip122(signer.signer_did(), "hello", &sig).unwrap());
    }

    #[tokio::test]
    async fn p256_did_verifies_its_own_signature() {
        let signer = LocalKeySigner::p256_from_pem(&p256_pem()).unwrap();
        assert!(signer.signer_did().starts_with("did:key:zDn"));
        let sig = signer.sign("hello").await.unwrap();
        assert!(verify_caip122(signer.signer_did(), "hello", &sig).unwrap());
    }

    /// A signature must not verify under a different key's DID.
    #[tokio::test]
    async fn a_signature_does_not_verify_under_another_did() {
        let a = LocalKeySigner::ed25519_from_pem(&ed25519_pem()).unwrap();
        let b = LocalKeySigner::ed25519_from_pem(&ed25519_pem()).unwrap();
        let sig = a.sign("hello").await.unwrap();
        assert!(!verify_caip122(b.signer_did(), "hello", &sig).unwrap());
    }

    #[test]
    fn a_p256_pem_is_refused_by_the_ed25519_loader() {
        assert!(matches!(
            LocalKeySigner::ed25519_from_pem(&p256_pem()),
            Err(LocalKeyError::Pkcs8 { .. })
        ));
    }

    /// A signer must never format its key material. Guards the manual `Debug`
    /// against someone later replacing it with a derive.
    #[test]
    fn debug_redacts_the_private_key() {
        let pem = ed25519_pem();
        let signer = LocalKeySigner::ed25519_from_pem(&pem).unwrap();
        let rendered = format!("{signer:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains(signer.signer_did()));
        for byte in signer_scalar_hex(&signer)
            .chars()
            .collect::<Vec<_>>()
            .chunks(16)
        {
            let probe: String = byte.iter().collect();
            assert!(!rendered.contains(&probe), "key material leaked into Debug");
        }
    }

    fn signer_scalar_hex(signer: &LocalKeySigner) -> String {
        match &signer.key {
            Key::Ed25519(k) => hex::encode(k.to_bytes()),
            Key::P256(k) => hex::encode(k.to_bytes()),
        }
    }

    #[test]
    fn a_missing_file_names_the_path() {
        let err = LocalKeySigner::ed25519_from_pem_file("/nonexistent/agent.pem").unwrap_err();
        assert!(err.to_string().contains("/nonexistent/agent.pem"));
    }
}
