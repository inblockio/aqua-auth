//! # aqua-auth
//!
//! CAIP-122 ("Sign In With X") session authentication for the Aqua Protocol.
//!
//! Provides:
//! - **CAIP-122 message construction** — SIWE-compatible format, generalized for
//!   Ed25519 and P-256 signers.
//! - **Chain-dispatching signature verification** — `verify_caip122()` dispatches
//!   on DID namespace to the appropriate verifier.
//! - **ChallengeStore** — in-memory, 5-min TTL, single-use nonces.
//! - **SessionStore** — in-memory, 1-hr TTL, background sweep.
//! - **Client helpers** — (behind `client` feature flag) reqwest-based auth flow.
//!
//! # Supported DID methods
//!
//! | Server Verifier | DID Namespace | Signature Format |
//! |---|---|---|
//! | EIP-191 ecrecover | `eip155` | 65-byte `r‖s‖v` (v ∈ {27,28}) |
//! | Ed25519 verify | `ed25519` | 64-byte Ed25519 signature |
//! | P-256 ECDSA verify | `p256` | 64-byte fixed or DER-encoded |

pub mod challenge;
#[cfg(feature = "client")]
pub mod client;
pub mod did;
pub mod error;
pub mod message;
pub mod session;
pub mod types;
mod verify_ed25519;
mod verify_eip191;
mod verify_p256;

pub use challenge::ChallengeStore;
pub use error::AuthError;
pub use session::SessionStore;
pub use types::{AuthenticatedDid, Challenge, Session, SessionInfo, SessionRequest};

/// Verify a CAIP-122 session signature. Dispatches on DID namespace.
///
/// - `did` — the full DID string (e.g. `did:pkh:eip155:1:0x...`)
/// - `message` — the canonical CAIP-122 message that was signed
/// - `signature` — raw signature bytes (not hex-encoded)
///
/// Returns `Ok(true)` if the signature is valid for the DID, `Ok(false)` if
/// the signature is well-formed but doesn't match, and `Err` on malformed inputs.
pub fn verify_caip122(did: &str, message: &str, signature: &[u8]) -> Result<bool, AuthError> {
    let ns = did::parse_did_namespace(did)?;
    match ns {
        "eip155"  => verify_eip191::verify(did, message, signature),
        "ed25519" => verify_ed25519::verify(did, message, signature),
        "p256"    => verify_p256::verify(did, message, signature),
        other     => Err(AuthError::UnsupportedMethod(other.into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_eip155() {
        // Generate a secp256k1 key, sign, and verify via dispatch
        use k256::ecdsa::SigningKey;
        use rand::rngs::OsRng;
        use sha3::{Digest, Keccak256};

        let secret = k256::SecretKey::random(&mut OsRng);
        let signing_key = SigningKey::from(&secret);
        let addr = did::address_from_verifying_key(signing_key.verifying_key());
        let did_str = format!("did:pkh:eip155:1:0x{}", did::eip55_checksum(&addr));

        let msg = "test dispatch eip155";
        let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
        let prehash: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update(prefix.as_bytes());
            h.update(msg.as_bytes());
            h.finalize().into()
        };
        let (sig, rec_id) = signing_key.sign_prehash_recoverable(&prehash).unwrap();
        let mut sig_bytes = [0u8; 65];
        sig_bytes[..64].copy_from_slice(&sig.to_bytes());
        sig_bytes[64] = u8::from(rec_id) + 27;

        assert!(verify_caip122(&did_str, msg, &sig_bytes).unwrap());
    }

    #[test]
    fn dispatch_ed25519() {
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let pubkey = signing_key.verifying_key();
        let did_str = format!("did:pkh:ed25519:0x{}", hex::encode(pubkey.as_bytes()));

        let msg = "test dispatch ed25519";
        let sig = signing_key.sign(msg.as_bytes());

        assert!(verify_caip122(&did_str, msg, &sig.to_bytes()).unwrap());
    }

    #[test]
    fn dispatch_p256() {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        use rand::rngs::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let compressed = verifying_key.to_encoded_point(true);
        let did_str = format!("did:pkh:p256:0x{}", hex::encode(compressed.as_bytes()));

        let msg = "test dispatch p256";
        let sig: Signature = signing_key.sign(msg.as_bytes());

        assert!(verify_caip122(&did_str, msg, &sig.to_bytes()).unwrap());
    }

    #[test]
    fn unsupported_namespace_returns_error() {
        let result = verify_caip122("did:pkh:solana:0xabc", "msg", &[0u8; 64]);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, AuthError::UnsupportedMethod(_)));
    }

    #[test]
    fn invalid_did_prefix_returns_error() {
        let result = verify_caip122("not:a:did", "msg", &[0u8; 64]);
        assert!(result.is_err());
    }
}
