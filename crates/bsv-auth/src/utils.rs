//! Utility functions: nonce creation/verification, random base64, certificate helpers.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bsv_wallet::types::*;
use rand::RngCore;

use crate::error::AuthError;

/// Generate random bytes of specified length and return as base64.
pub fn random_base64(length: usize) -> String {
    let mut bytes = vec![0u8; length];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    BASE64.encode(&bytes)
}

/// Create a cryptographic nonce derived from the wallet.
/// The nonce = base64(random_16_bytes || HMAC(random_16_bytes)).
pub fn create_nonce(
    wallet: &dyn bsv_wallet::wallet_trait::WalletInterface,
    counterparty: Counterparty,
) -> Result<String, AuthError> {
    let mut random_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut random_bytes);

    let args = CreateHmacArgs {
        encryption_args: EncryptionArgs {
            protocol_id: Protocol {
                security_level: SECURITY_LEVEL_EVERY_APP,
                protocol: "server hmac".to_string(),
            },
            key_id: hex::encode(&random_bytes),
            counterparty: counterparty.clone(),
            privileged: false,
            privileged_reason: String::new(),
            seek_permission: false,
        },
        data: random_bytes.to_vec(),
    };

    let hmac_result = wallet.create_hmac(args)?;

    let mut combined = Vec::with_capacity(16 + 32);
    combined.extend_from_slice(&random_bytes);
    combined.extend_from_slice(&hmac_result.hmac);

    Ok(BASE64.encode(&combined))
}

/// Verify that a nonce was derived from the given wallet.
pub fn verify_nonce(
    nonce: &str,
    wallet: &dyn bsv_wallet::wallet_trait::WalletInterface,
    counterparty: Counterparty,
) -> Result<bool, AuthError> {
    let nonce_bytes = BASE64.decode(nonce)?;

    if nonce_bytes.len() <= 16 {
        return Err(AuthError::InvalidNonce);
    }

    let data = &nonce_bytes[..16];
    let hmac = &nonce_bytes[16..];

    if hmac.len() != 32 {
        return Err(AuthError::InvalidNonce);
    }

    let mut hmac_array = [0u8; 32];
    hmac_array.copy_from_slice(hmac);

    let args = VerifyHmacArgs {
        encryption_args: EncryptionArgs {
            protocol_id: Protocol {
                security_level: SECURITY_LEVEL_EVERY_APP,
                protocol: "server hmac".to_string(),
            },
            key_id: hex::encode(data),
            counterparty,
            privileged: false,
            privileged_reason: String::new(),
            seek_permission: false,
        },
        data: data.to_vec(),
        hmac: hmac_array,
    };

    let result = wallet.verify_hmac(args)?;
    Ok(result.valid)
}

/// Validate that a RequestedCertificateSet is properly formatted.
pub fn validate_requested_certificate_set(
    req: &crate::types::RequestedCertificateSet,
) -> Result<(), AuthError> {
    if req.certifiers.is_empty() {
        return Err(AuthError::General("certifiers list is empty".into()));
    }

    if req.certificate_types.is_empty() {
        return Err(AuthError::General("certificate types map is empty".into()));
    }

    for (cert_type, fields) in &req.certificate_types {
        if *cert_type == [0u8; 32] {
            return Err(AuthError::General(
                "empty certificate type specified".into(),
            ));
        }
        if fields.is_empty() {
            return Err(AuthError::General(format!(
                "no fields specified for certificate type: {:?}",
                cert_type
            )));
        }
    }

    Ok(())
}

/// Check if a certifier public key is in the list.
pub fn certifier_in_slice(
    certifiers: &[bsv_primitives::ec::public_key::PublicKey],
    certifier: &bsv_primitives::ec::public_key::PublicKey,
) -> bool {
    certifiers.iter().any(|c| c == certifier)
}
