//! In-memory [`Signer`] implementations for the `http_sig` unit tests.
//!
//! One per cipher suite, each carrying the DID spelling the tests exercise:
//! `did:key` for ed25519 and p256, `did:pkh` for eip155. They hold a raw key
//! in memory, which is exactly what a production signer must not do; that is
//! the point of the `Signer` trait being async and pluggable.

use crate::signer::{SignError, Signer};
use async_trait::async_trait;
use rand::rngs::OsRng;

/// Ed25519, advertised as `did:key:z6Mk...`.
pub(crate) struct Ed25519TestSigner {
    key: ed25519_dalek::SigningKey,
    did: String,
}

impl Ed25519TestSigner {
    pub(crate) fn generate() -> Self {
        let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let mut bytes = crate::key::ED25519_PREFIX.to_vec();
        bytes.extend_from_slice(key.verifying_key().as_bytes());
        let did = format!("did:key:z{}", bs58::encode(&bytes).into_string());
        Self { key, did }
    }
}

#[async_trait]
impl Signer for Ed25519TestSigner {
    fn signer_did(&self) -> &str {
        &self.did
    }

    async fn sign(&self, message: &str) -> Result<Vec<u8>, SignError> {
        use ed25519_dalek::Signer as _;
        Ok(self.key.sign(message.as_bytes()).to_bytes().to_vec())
    }
}

/// P-256 ECDSA, advertised as `did:key:zDn...`.
pub(crate) struct P256TestSigner {
    key: p256::ecdsa::SigningKey,
    did: String,
}

impl P256TestSigner {
    pub(crate) fn generate() -> Self {
        let key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let compressed = key.verifying_key().to_encoded_point(true);
        let mut bytes = crate::key::P256_PREFIX.to_vec();
        bytes.extend_from_slice(compressed.as_bytes());
        let did = format!("did:key:z{}", bs58::encode(&bytes).into_string());
        Self { key, did }
    }
}

#[async_trait]
impl Signer for P256TestSigner {
    fn signer_did(&self) -> &str {
        &self.did
    }

    async fn sign(&self, message: &str) -> Result<Vec<u8>, SignError> {
        use p256::ecdsa::signature::Signer as _;
        let sig: p256::ecdsa::Signature = self.key.sign(message.as_bytes());
        Ok(sig.to_bytes().to_vec())
    }
}

/// secp256k1 via EIP-191 `personal_sign`, advertised as `did:pkh:eip155:1:0x...`.
pub(crate) struct Eip155TestSigner {
    key: k256::ecdsa::SigningKey,
    did: String,
}

impl Eip155TestSigner {
    pub(crate) fn generate() -> Self {
        let key = k256::ecdsa::SigningKey::from(&k256::SecretKey::random(&mut OsRng));
        let address = crate::did::address_from_verifying_key(key.verifying_key());
        let did = format!(
            "did:pkh:eip155:1:0x{}",
            crate::did::eip55_checksum(&address)
        );
        Self { key, did }
    }
}

#[async_trait]
impl Signer for Eip155TestSigner {
    fn signer_did(&self) -> &str {
        &self.did
    }

    async fn sign(&self, message: &str) -> Result<Vec<u8>, SignError> {
        use sha3::{Digest, Keccak256};
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let prehash: [u8; 32] = {
            let mut hasher = Keccak256::new();
            hasher.update(prefix.as_bytes());
            hasher.update(message.as_bytes());
            hasher.finalize().into()
        };
        let (sig, rec_id) = self
            .key
            .sign_prehash_recoverable(&prehash)
            .map_err(|e| SignError(e.to_string()))?;
        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(&sig.to_bytes());
        out.push(u8::from(rec_id) + 27);
        Ok(out)
    }
}
