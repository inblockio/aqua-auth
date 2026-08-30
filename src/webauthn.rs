//! WebAuthn assertion verification for CAIP-122 login flows.
//!
//! Provides a standalone verifier that validates a passkey assertion against
//! a relying party's expectations (origin, rpId, challenge) and verifies the
//! P-256 ECDSA signature over the signed payload.

use crate::CryptoError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::EncodedPoint;
use sha2::{Digest, Sha256};

/// Parameters for verifying a WebAuthn assertion.
pub struct WebAuthnAssertionParams<'a> {
    /// 33-byte compressed SEC1 P-256 public key
    pub credential_public_key: &'a [u8],
    /// Raw authenticator data bytes from the assertion response
    pub authenticator_data: &'a [u8],
    /// Raw UTF-8 bytes of the clientDataJSON
    pub client_data_json: &'a [u8],
    /// 64-byte r||s ECDSA signature
    pub signature: &'a [u8],
    /// The expected challenge bytes (arbitrary length)
    pub expected_challenge: &'a [u8],
    /// The expected origin (e.g. `https://auth.example.com`)
    pub expected_origin: &'a str,
    /// The expected relying party ID (e.g. "auth.example.com")
    pub expected_rp_id: &'a str,
}

/// Verify a WebAuthn assertion (passkey authentication response).
///
/// Returns:
/// - `Ok(true)` if the assertion is valid
/// - `Ok(false)` if the P-256 signature is invalid but inputs are well-formed
/// - `Err(CryptoError::InvalidSignature(...))` for structural problems
pub fn verify_webauthn_assertion(params: &WebAuthnAssertionParams) -> Result<bool, CryptoError> {
    // 1. Validate authenticatorData length (minimum 37 bytes: 32 rpIdHash + 1 flags + 4 signCount)
    if params.authenticator_data.len() < 37 {
        return Err(CryptoError::InvalidSignature(format!(
            "authenticatorData too short: {} bytes, need at least 37",
            params.authenticator_data.len()
        )));
    }

    // 2. Verify rpIdHash matches SHA-256(expected_rp_id)
    let expected_rp_id_hash = Sha256::digest(params.expected_rp_id.as_bytes());
    if params.authenticator_data[0..32] != expected_rp_id_hash[..] {
        return Err(CryptoError::InvalidSignature(
            "rpIdHash mismatch: authenticatorData does not match expected rpId".to_string(),
        ));
    }

    // 3. Verify User Present flag (bit 0 of flags byte at offset 32)
    let flags = params.authenticator_data[32];
    if flags & 0x01 == 0 {
        return Err(CryptoError::InvalidSignature(
            "User Present flag not set in authenticatorData".to_string(),
        ));
    }

    // 4. Parse clientDataJSON
    let client_data: serde_json::Value = serde_json::from_slice(params.client_data_json)
        .map_err(|e| CryptoError::InvalidSignature(format!("invalid clientDataJSON: {}", e)))?;

    // 5. Verify type == "webauthn.get"
    let cd_type = client_data
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CryptoError::InvalidSignature("clientDataJSON missing 'type' field".to_string())
        })?;
    if cd_type != "webauthn.get" {
        return Err(CryptoError::InvalidSignature(format!(
            "clientDataJSON type mismatch: expected 'webauthn.get', got '{}'",
            cd_type
        )));
    }

    // 6. base64url-decode challenge field, compare to expected_challenge
    let cd_challenge = client_data
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CryptoError::InvalidSignature("clientDataJSON missing 'challenge' field".to_string())
        })?;
    let decoded_challenge = URL_SAFE_NO_PAD.decode(cd_challenge).map_err(|e| {
        CryptoError::InvalidSignature(format!("invalid base64url challenge: {}", e))
    })?;
    if decoded_challenge != params.expected_challenge {
        return Err(CryptoError::InvalidSignature(
            "challenge mismatch".to_string(),
        ));
    }

    // 7. Verify origin matches expected_origin
    let cd_origin = client_data
        .get("origin")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CryptoError::InvalidSignature("clientDataJSON missing 'origin' field".to_string())
        })?;
    if cd_origin != params.expected_origin {
        return Err(CryptoError::InvalidSignature(format!(
            "origin mismatch: expected '{}', got '{}'",
            params.expected_origin, cd_origin
        )));
    }

    // 8. Compute signed_payload = authenticatorData || SHA-256(clientDataJSON)
    let client_data_hash = Sha256::digest(params.client_data_json);
    let mut signed_payload =
        Vec::with_capacity(params.authenticator_data.len() + client_data_hash.len());
    signed_payload.extend_from_slice(params.authenticator_data);
    signed_payload.extend_from_slice(&client_data_hash);

    // 9. Verify P-256 ECDSA signature over signed_payload
    if params.signature.len() != 64 {
        return Err(CryptoError::InvalidSignature(format!(
            "signature must be 64 bytes (r||s), got {}",
            params.signature.len()
        )));
    }

    let encoded_point = EncodedPoint::from_bytes(params.credential_public_key).map_err(|e| {
        CryptoError::InvalidSignature(format!("invalid public key encoding: {}", e))
    })?;
    let verifying_key = VerifyingKey::from_encoded_point(&encoded_point)
        .map_err(|e| CryptoError::InvalidSignature(format!("invalid P-256 public key: {}", e)))?;

    let signature = Signature::from_bytes(params.signature.into())
        .map_err(|e| CryptoError::InvalidSignature(format!("invalid signature encoding: {}", e)))?;

    match verifying_key.verify(&signed_payload, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};
    use rand::rngs::OsRng;

    const TEST_RP_ID: &str = "auth.example.com";
    const TEST_ORIGIN: &str = "https://auth.example.com";

    /// Build a synthetic WebAuthn assertion for testing.
    fn build_assertion(
        signing_key: &SigningKey,
        challenge: &[u8],
        origin: &str,
        rp_id: &str,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        // authenticatorData: rpIdHash (32) + flags (1) + signCount (4)
        let rp_id_hash = Sha256::digest(rp_id.as_bytes());
        let mut authenticator_data = Vec::with_capacity(37);
        authenticator_data.extend_from_slice(&rp_id_hash);
        authenticator_data.push(0x05); // flags: UP=1, UV=1
        authenticator_data.extend_from_slice(&[0, 0, 0, 1]); // signCount = 1

        // clientDataJSON
        let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge);
        let client_data_json = serde_json::json!({
            "type": "webauthn.get",
            "challenge": challenge_b64,
            "origin": origin,
            "crossOrigin": false
        });
        let client_data_bytes = serde_json::to_vec(&client_data_json).unwrap();

        // Compute signature over authenticatorData || SHA-256(clientDataJSON)
        let client_data_hash = Sha256::digest(&client_data_bytes);
        let mut signed_payload =
            Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
        signed_payload.extend_from_slice(&authenticator_data);
        signed_payload.extend_from_slice(&client_data_hash);

        let sig: Signature = signing_key.sign(&signed_payload);
        let sig_bytes = sig.to_bytes().to_vec();

        (authenticator_data, client_data_bytes, sig_bytes)
    }

    #[test]
    fn valid_assertion_passes() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let pubkey = verifying_key.to_encoded_point(true);
        let challenge = b"random-challenge-bytes-1234";

        let (auth_data, client_data, sig) =
            build_assertion(&signing_key, challenge, TEST_ORIGIN, TEST_RP_ID);

        let params = WebAuthnAssertionParams {
            credential_public_key: pubkey.as_bytes(),
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &sig,
            expected_challenge: challenge,
            expected_origin: TEST_ORIGIN,
            expected_rp_id: TEST_RP_ID,
        };

        let result = verify_webauthn_assertion(&params).unwrap();
        assert!(result, "valid assertion should pass verification");
    }

    #[test]
    fn wrong_origin_rejected() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let pubkey = verifying_key.to_encoded_point(true);
        let challenge = b"test-challenge";

        let (auth_data, client_data, sig) =
            build_assertion(&signing_key, challenge, TEST_ORIGIN, TEST_RP_ID);

        let params = WebAuthnAssertionParams {
            credential_public_key: pubkey.as_bytes(),
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &sig,
            expected_challenge: challenge,
            expected_origin: "https://evil.example.com",
            expected_rp_id: TEST_RP_ID,
        };

        let result = verify_webauthn_assertion(&params);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("origin mismatch"),
            "expected origin mismatch error, got: {}",
            err
        );
    }

    #[test]
    fn wrong_rp_id_rejected() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let pubkey = verifying_key.to_encoded_point(true);
        let challenge = b"test-challenge";

        let (auth_data, client_data, sig) =
            build_assertion(&signing_key, challenge, TEST_ORIGIN, TEST_RP_ID);

        let params = WebAuthnAssertionParams {
            credential_public_key: pubkey.as_bytes(),
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &sig,
            expected_challenge: challenge,
            expected_origin: TEST_ORIGIN,
            expected_rp_id: "evil.example.com",
        };

        let result = verify_webauthn_assertion(&params);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("rpIdHash mismatch"),
            "expected rpIdHash mismatch error, got: {}",
            err
        );
    }

    #[test]
    fn wrong_challenge_rejected() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let pubkey = verifying_key.to_encoded_point(true);
        let challenge = b"correct-challenge";

        let (auth_data, client_data, sig) =
            build_assertion(&signing_key, challenge, TEST_ORIGIN, TEST_RP_ID);

        let params = WebAuthnAssertionParams {
            credential_public_key: pubkey.as_bytes(),
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &sig,
            expected_challenge: b"wrong-challenge",
            expected_origin: TEST_ORIGIN,
            expected_rp_id: TEST_RP_ID,
        };

        let result = verify_webauthn_assertion(&params);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("challenge mismatch"),
            "expected challenge mismatch error, got: {}",
            err
        );
    }

    #[test]
    fn invalid_signature_length_rejected() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let pubkey = verifying_key.to_encoded_point(true);
        let challenge = b"test-challenge";

        let (auth_data, client_data, _sig) =
            build_assertion(&signing_key, challenge, TEST_ORIGIN, TEST_RP_ID);

        let params = WebAuthnAssertionParams {
            credential_public_key: pubkey.as_bytes(),
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &[0u8; 63], // wrong length
            expected_challenge: challenge,
            expected_origin: TEST_ORIGIN,
            expected_rp_id: TEST_RP_ID,
        };

        let result = verify_webauthn_assertion(&params);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("signature must be 64 bytes"),
            "expected signature length error, got: {}",
            err
        );
    }

    #[test]
    fn malformed_client_data_json_rejected() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let pubkey = verifying_key.to_encoded_point(true);
        let challenge = b"test-challenge";

        let (auth_data, _client_data, sig) =
            build_assertion(&signing_key, challenge, TEST_ORIGIN, TEST_RP_ID);

        let params = WebAuthnAssertionParams {
            credential_public_key: pubkey.as_bytes(),
            authenticator_data: &auth_data,
            client_data_json: b"this is not valid json{{{",
            signature: &sig,
            expected_challenge: challenge,
            expected_origin: TEST_ORIGIN,
            expected_rp_id: TEST_RP_ID,
        };

        let result = verify_webauthn_assertion(&params);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("invalid clientDataJSON"),
            "expected JSON parse error, got: {}",
            err
        );
    }

    #[test]
    fn tampered_signature_returns_false() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let pubkey = verifying_key.to_encoded_point(true);
        let challenge = b"test-challenge";

        let (auth_data, client_data, mut sig) =
            build_assertion(&signing_key, challenge, TEST_ORIGIN, TEST_RP_ID);

        // Flip a byte in the signature
        sig[0] ^= 0xFF;

        let params = WebAuthnAssertionParams {
            credential_public_key: pubkey.as_bytes(),
            authenticator_data: &auth_data,
            client_data_json: &client_data,
            signature: &sig,
            expected_challenge: challenge,
            expected_origin: TEST_ORIGIN,
            expected_rp_id: TEST_RP_ID,
        };

        // Tampered signature may result in either Ok(false) or Err depending on
        // whether the flipped bytes still form a valid curve point encoding.
        // Both outcomes are acceptable - the key point is it must NOT return Ok(true).
        // An Err is also acceptable (structural invalidity); only Ok(true) fails.
        if let Ok(valid) = verify_webauthn_assertion(&params) {
            assert!(!valid, "tampered signature must not verify as valid");
        }
    }
}
