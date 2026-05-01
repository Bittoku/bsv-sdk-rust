//! VerifiableCertificate — extends Certificate with a verifier-specific keyring.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bsv_primitives::ec::symmetric::SymmetricKey;
use bsv_wallet::types::*;
use std::collections::HashMap;

use super::Certificate;
use crate::error::AuthError;

/// A certificate with a verifier-specific keyring for selective field decryption.
#[derive(Debug, Clone)]
pub struct VerifiableCertificate {
    /// The underlying certificate.
    pub certificate: Certificate,
    /// Encrypted field revelation keys for the verifier (field_name -> base64 encrypted key).
    pub keyring: HashMap<String, String>,
    /// Decrypted field values (populated after decrypt_fields).
    pub decrypted_fields: HashMap<String, String>,
}

impl VerifiableCertificate {
    /// Create a new VerifiableCertificate from a certificate and a verifier-specific keyring.
    pub fn new(cert: Certificate, keyring: HashMap<String, String>) -> Self {
        Self {
            certificate: cert,
            keyring,
            decrypted_fields: HashMap::new(),
        }
    }

    /// Decrypt the fields using the verifier wallet and the keyring.
    pub fn decrypt_fields(
        &mut self,
        verifier_wallet: &dyn bsv_wallet::wallet_trait::WalletInterface,
    ) -> Result<HashMap<String, String>, AuthError> {
        if self.keyring.is_empty() {
            return Err(AuthError::FieldDecryption(
                "a keyring is required to decrypt certificate fields for the verifier".into(),
            ));
        }

        let mut decrypted = HashMap::new();

        let subject_counterparty = Counterparty {
            r#type: CounterpartyType::Other,
            counterparty: Some(self.certificate.subject.clone()),
        };

        for (field_name, encrypted_key_base64) in &self.keyring {
            // 1. Decrypt the field revelation key
            let encrypted_key_bytes = BASE64.decode(encrypted_key_base64).map_err(|e| {
                AuthError::FieldDecryption(format!(
                    "failed to decode base64 key for field '{}': {}",
                    field_name, e
                ))
            })?;

            let (protocol_id, key_id) =
                Certificate::get_encryption_details(field_name, &self.certificate.serial_number);

            let decrypt_result = verifier_wallet
                .decrypt(DecryptArgs {
                    encryption_args: EncryptionArgs {
                        protocol_id,
                        key_id,
                        counterparty: subject_counterparty.clone(),
                        privileged: false,
                        privileged_reason: String::new(),
                        seek_permission: false,
                    },
                    ciphertext: encrypted_key_bytes,
                })
                .map_err(|e| {
                    AuthError::FieldDecryption(format!(
                        "wallet decryption failed for field '{}': {}",
                        field_name, e
                    ))
                })?;

            let field_revelation_key = decrypt_result.plaintext;

            // 2. Decrypt the actual field value
            let encrypted_field_value =
                self.certificate.fields.get(field_name).ok_or_else(|| {
                    AuthError::FieldDecryption(format!(
                        "field '{}' not found in certificate fields",
                        field_name
                    ))
                })?;

            let encrypted_field_bytes = BASE64.decode(encrypted_field_value).map_err(|e| {
                AuthError::FieldDecryption(format!(
                    "failed to decode base64 field value for '{}': {}",
                    field_name, e
                ))
            })?;

            if field_revelation_key.len() != 32 {
                return Err(AuthError::FieldDecryption(format!(
                    "field revelation key for '{}' is not 32 bytes",
                    field_name
                )));
            }
            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(&field_revelation_key);
            let symmetric_key = SymmetricKey::new(&key_array);

            let plaintext_bytes = symmetric_key.decrypt(&encrypted_field_bytes).map_err(|e| {
                AuthError::FieldDecryption(format!(
                    "symmetric decryption failed for field '{}': {}",
                    field_name, e
                ))
            })?;

            decrypted.insert(
                field_name.clone(),
                String::from_utf8_lossy(&plaintext_bytes).to_string(),
            );
        }

        self.decrypted_fields = decrypted.clone();
        Ok(decrypted)
    }

    /// Verify the certificate signature (delegates to Certificate::verify).
    pub fn verify(&self) -> Result<(), AuthError> {
        self.certificate.verify()
    }
}
