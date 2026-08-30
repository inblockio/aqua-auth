//! In-memory [`Signer`] implementations, one per accepted DID spelling.
//!
//! `src/http_sig/test_signers.rs` holds the same pattern for the crate's own
//! unit tests, but a `#[cfg(test)]` module is invisible from an integration
//! test crate, so the pattern is mirrored here rather than shared. The mirror
//! also has to inline the multicodec prefixes (`crate::key::ED25519_PREFIX`
//! and friends are `pub(crate)`), which is why the byte literals appear below
//! with their provenance in a comment.
//!
//! Five spellings, five signers. Ed25519 and P-256 keys each get both a
//! `did:key` and a `did:pkh` identity, which are two *distinct principals* per
//! the two-principal ruling (#182): the same key logging in under the other
//! spelling is a different subject, not the same one.
//!
//! Every signer holds a raw private key in process memory, which is exactly
//! what a production signer must not do. That is the point of `Signer` being
//! async and pluggable: a KMS, an HSM, a wallet prompt, or a passkey touch
//! slots in behind the same trait.

use aqua_auth::{SignError, Signer};
use async_trait::async_trait;
use rand::rngs::OsRng;
use std::sync::Arc;

/// Multicodec prefix for an Ed25519 public key (0xED 0x01), the `z6Mk` form.
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// Multicodec prefix for a P-256 public key (0x80 0x24), the `zDn` form.
const P256_MULTICODEC: [u8; 2] = [0x80, 0x24];

/// Which of the two spellings an ed25519 or p256 key advertises itself under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spelling {
    /// `did:key:z6Mk...` (ed25519) or `did:key:zDn...` (p256).
    DidKey,
    /// `did:pkh:ed25519:0x...` or `did:pkh:p256:0x...`.
    DidPkh,
}

/// Ed25519 under either spelling.
pub struct Ed25519Local {
    key: ed25519_dalek::SigningKey,
    did: String,
}

impl Ed25519Local {
    /// Generate a fresh key advertised under `spelling`.
    pub fn generate(spelling: Spelling) -> Self {
        let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let raw = key.verifying_key().to_bytes();
        let did = match spelling {
            Spelling::DidKey => {
                let mut bytes = ED25519_MULTICODEC.to_vec();
                bytes.extend_from_slice(&raw);
                format!("did:key:z{}", bs58::encode(&bytes).into_string())
            }
            Spelling::DidPkh => format!("did:pkh:ed25519:0x{}", hex::encode(raw)),
        };
        Self { key, did }
    }
}

#[async_trait]
impl Signer for Ed25519Local {
    fn signer_did(&self) -> &str {
        &self.did
    }

    async fn sign(&self, message: &str) -> Result<Vec<u8>, SignError> {
        use ed25519_dalek::Signer as _;
        Ok(self.key.sign(message.as_bytes()).to_bytes().to_vec())
    }
}

/// P-256 ECDSA under either spelling.
pub struct P256Local {
    key: p256::ecdsa::SigningKey,
    did: String,
}

impl P256Local {
    /// Generate a fresh key advertised under `spelling`.
    pub fn generate(spelling: Spelling) -> Self {
        let key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let compressed = key.verifying_key().to_encoded_point(true);
        let did = match spelling {
            Spelling::DidKey => {
                let mut bytes = P256_MULTICODEC.to_vec();
                bytes.extend_from_slice(compressed.as_bytes());
                format!("did:key:z{}", bs58::encode(&bytes).into_string())
            }
            Spelling::DidPkh => format!("did:pkh:p256:0x{}", hex::encode(compressed.as_bytes())),
        };
        Self { key, did }
    }
}

#[async_trait]
impl Signer for P256Local {
    fn signer_did(&self) -> &str {
        &self.did
    }

    async fn sign(&self, message: &str) -> Result<Vec<u8>, SignError> {
        use p256::ecdsa::signature::Signer as _;
        let signature: p256::ecdsa::Signature = self.key.sign(message.as_bytes());
        Ok(signature.to_bytes().to_vec())
    }
}

/// secp256k1 via EIP-191 `personal_sign`, advertised as `did:pkh:eip155:1:0x...`.
///
/// The only spelling for this namespace: there is no `did:key` form for an
/// Ethereum address, because the DID names the address, not the key.
pub struct Eip155Local {
    key: k256::ecdsa::SigningKey,
    did: String,
}

impl Eip155Local {
    /// Generate a fresh key on chain 1.
    pub fn generate() -> Self {
        let key = k256::ecdsa::SigningKey::from(&k256::SecretKey::random(&mut OsRng));
        let address = aqua_auth::address_from_verifying_key(key.verifying_key());
        let did = format!("did:pkh:eip155:1:0x{}", aqua_auth::eip55_checksum(&address));
        Self { key, did }
    }
}

#[async_trait]
impl Signer for Eip155Local {
    fn signer_did(&self) -> &str {
        &self.did
    }

    /// 65 bytes: `r || s || v`, where `v` is the recovery id plus 27, over the
    /// EIP-191 `personal_sign` prehash.
    async fn sign(&self, message: &str) -> Result<Vec<u8>, SignError> {
        use sha3::{Digest, Keccak256};
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let prehash: [u8; 32] = {
            let mut hasher = Keccak256::new();
            hasher.update(prefix.as_bytes());
            hasher.update(message.as_bytes());
            hasher.finalize().into()
        };
        let (signature, recovery_id) = self
            .key
            .sign_prehash_recoverable(&prehash)
            .map_err(|e| SignError(e.to_string()))?;
        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(&signature.to_bytes());
        out.push(u8::from(recovery_id) + 27);
        Ok(out)
    }
}

/// A fresh Ed25519 key spelled `did:key:z6Mk...`.
pub fn ed25519_did_key() -> Arc<dyn Signer> {
    Arc::new(Ed25519Local::generate(Spelling::DidKey))
}

/// A fresh Ed25519 key spelled `did:pkh:ed25519:0x...` (a distinct principal
/// from the same key's `did:key` form).
pub fn ed25519_did_pkh() -> Arc<dyn Signer> {
    Arc::new(Ed25519Local::generate(Spelling::DidPkh))
}

/// A fresh P-256 key spelled `did:key:zDn...`.
pub fn p256_did_key() -> Arc<dyn Signer> {
    Arc::new(P256Local::generate(Spelling::DidKey))
}

/// A fresh P-256 key spelled `did:pkh:p256:0x...` (a distinct principal from
/// the same key's `did:key` form).
pub fn p256_did_pkh() -> Arc<dyn Signer> {
    Arc::new(P256Local::generate(Spelling::DidPkh))
}

/// A fresh secp256k1 key spelled `did:pkh:eip155:1:0x...`.
pub fn eip155() -> Arc<dyn Signer> {
    Arc::new(Eip155Local::generate())
}
