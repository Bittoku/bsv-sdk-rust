//! MasterCertificate — extends Certificate with a master keyring for key management.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bsv_primitives::ec::symmetric::SymmetricKey;
use bsv_wallet::types::*;
use rand::RngCore;
use std::collections::HashMap;

use super::Certificate;
use crate::error::AuthError;
use crate::utils::random_base64;

/// A master certificate with encrypted symmetric keys for each field.
#[derive(Debug, Clone)]
pub struct MasterCertificate {
    /// The underlying certificate.
    pub certificate: Certificate,
    /// Encrypted symmetric keys for each field (field_name -> base64 encrypted key).
    pub master_keyring: HashMap<String, String>,
}

impl MasterCertificate {
    /// Create a new MasterCertificate.
    pub fn new(
        cert: Certificate,
        master_keyring: HashMap<String, String>,
    ) -> Result<Self, AuthError> {
        if master_keyring.is_empty() {
            return Err(AuthError::MissingMasterKeyring);
        }

        for field_name in cert.fields.keys() {
            if !master_keyring.contains_key(field_name) {
                return Err(AuthError::General(format!(
                    "master keyring must contain a value for every field. Missing key for field: {}",
                    field_name
                )));
            }
        }

        Ok(MasterCertificate {
            certificate: cert,
            master_keyring,
        })
    }
}

/// Result of creating encrypted certificate fields.
pub struct CertificateFieldsResult {
    /// Encrypted field values (field_name -> base64 ciphertext).
    pub certificate_fields: HashMap<String, String>,
    /// Encrypted symmetric keys for each field (field_name -> base64 encrypted key).
    pub master_keyring: HashMap<String, String>,
}

/// Encrypt certificate fields for a subject and generate a master keyring.
pub fn create_certificate_fields(
    creator_wallet: &dyn bsv_wallet::wallet_trait::WalletInterface,
    certifier_or_subject: &Counterparty,
    fields: &HashMap<String, String>, // plaintext field values
) -> Result<CertificateFieldsResult, AuthError> {
    let mut certificate_fields = HashMap::new();
    let mut master_keyring = HashMap::new();

    for (field_name, field_value) in fields {
        // 1. Generate a random symmetric key (32 bytes)
        let mut key_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let symmetric_key = SymmetricKey::new(&key_bytes);

        // 2. Encrypt the field value with this key
        let encrypted_value = symmetric_key
            .encrypt(field_value.as_bytes())
            .map_err(|e| AuthError::EncryptionFailed(format!("field {}: {}", field_name, e)))?;
        certificate_fields.insert(field_name.clone(), BASE64.encode(&encrypted_value));

        // 3. Encrypt the symmetric key for the certifier/subject
        let (protocol_id, key_id) = Certificate::get_encryption_details(field_name, "");
        let encrypted_key = creator_wallet.encrypt(EncryptArgs {
            encryption_args: EncryptionArgs {
                protocol_id,
                key_id,
                counterparty: certifier_or_subject.clone(),
                privileged: false,
                privileged_reason: String::new(),
                seek_permission: false,
            },
            plaintext: key_bytes.to_vec(),
        })?;
        master_keyring.insert(field_name.clone(), BASE64.encode(&encrypted_key.ciphertext));
    }

    Ok(CertificateFieldsResult {
        certificate_fields,
        master_keyring,
    })
}

/// Issue a certificate for a subject.
pub fn issue_certificate_for_subject(
    certifier_wallet: &dyn bsv_wallet::wallet_trait::WalletInterface,
    subject: &Counterparty,
    plain_fields: &HashMap<String, String>,
    certificate_type: &str,
    revocation_outpoint: Option<String>,
    serial_number: Option<String>,
) -> Result<MasterCertificate, AuthError> {
    // 1. Generate serial number if not provided
    let serial_number = serial_number.unwrap_or_else(|| random_base64(32));

    // 2. Create encrypted fields and master keyring
    let field_result = create_certificate_fields(certifier_wallet, subject, plain_fields)?;

    // 3. Get certifier identity key
    let certifier_pub_key = certifier_wallet.get_public_key(GetPublicKeyArgs {
        identity_key: true,
        encryption_args: EncryptionArgs {
            protocol_id: Protocol {
                security_level: 0,
                protocol: String::new(),
            },
            key_id: String::new(),
            counterparty: Counterparty::default(),
            privileged: false,
            privileged_reason: String::new(),
            seek_permission: false,
        },
        for_self: None,
    })?;

    // 4. Determine subject key
    let subject_key = match subject.r#type {
        CounterpartyType::Other => subject.counterparty.clone().ok_or(AuthError::General(
            "subject counterparty is Other but has no public key".into(),
        ))?,
        _ => certifier_pub_key.public_key.clone(),
    };

    // 5. Create the base certificate
    let mut cert = Certificate::new(
        certificate_type.to_string(),
        serial_number,
        subject_key,
        certifier_pub_key.public_key,
        revocation_outpoint.unwrap_or_else(|| format!("{}.0", "0".repeat(64))),
        field_result.certificate_fields,
    );

    // 6. Sign the certificate
    cert.sign(certifier_wallet)?;

    // 7. Create the master certificate
    MasterCertificate::new(cert, field_result.master_keyring)
}

/// Decrypt a single field using the master keyring.
pub fn decrypt_field(
    wallet: &dyn bsv_wallet::wallet_trait::WalletInterface,
    master_keyring: &HashMap<String, String>,
    field_name: &str,
    encrypted_field_value: &str,
    counterparty: &Counterparty,
) -> Result<(Vec<u8>, String), AuthError> {
    let encrypted_key_base64 = master_keyring
        .get(field_name)
        .ok_or_else(|| AuthError::KeyNotFoundInKeyring(field_name.to_string()))?;

    let encrypted_key_bytes = BASE64.decode(encrypted_key_base64)?;

    // Decrypt the field revelation key
    let (protocol_id, key_id) = Certificate::get_encryption_details(field_name, "");
    let decrypted = wallet.decrypt(DecryptArgs {
        encryption_args: EncryptionArgs {
            protocol_id,
            key_id,
            counterparty: counterparty.clone(),
            privileged: false,
            privileged_reason: String::new(),
            seek_permission: false,
        },
        ciphertext: encrypted_key_bytes,
    })?;
    let field_revelation_key = decrypted.plaintext;

    // Decrypt the field value
    let encrypted_field_bytes = BASE64.decode(encrypted_field_value)?;
    let mut key_array = [0u8; 32];
    if field_revelation_key.len() != 32 {
        return Err(AuthError::DecryptionFailed(format!(
            "field revelation key for {} is not 32 bytes",
            field_name
        )));
    }
    key_array.copy_from_slice(&field_revelation_key);
    let symmetric_key = SymmetricKey::new(&key_array);
    let plaintext = symmetric_key
        .decrypt(&encrypted_field_bytes)
        .map_err(|e| AuthError::DecryptionFailed(format!("field {}: {}", field_name, e)))?;

    Ok((
        field_revelation_key,
        String::from_utf8_lossy(&plaintext).to_string(),
    ))
}

/// Decrypt multiple fields using the master keyring.
pub fn decrypt_fields(
    wallet: &dyn bsv_wallet::wallet_trait::WalletInterface,
    master_keyring: &HashMap<String, String>,
    fields: &HashMap<String, String>,
    counterparty: &Counterparty,
) -> Result<HashMap<String, String>, AuthError> {
    if master_keyring.is_empty() {
        return Err(AuthError::MissingMasterKeyring);
    }

    let mut decrypted = HashMap::new();
    for (field_name, encrypted_value) in fields {
        let (_, plaintext) = decrypt_field(
            wallet,
            master_keyring,
            field_name,
            encrypted_value,
            counterparty,
        )?;
        decrypted.insert(field_name.clone(), plaintext);
    }

    Ok(decrypted)
}

/// Create a keyring for a verifier that allows them to decrypt specific fields.
pub fn create_keyring_for_verifier(
    subject_wallet: &dyn bsv_wallet::wallet_trait::WalletInterface,
    certifier: &Counterparty,
    verifier: &Counterparty,
    fields: &HashMap<String, String>,
    fields_to_reveal: &[String],
    master_keyring: &HashMap<String, String>,
    serial_number: &str,
) -> Result<HashMap<String, String>, AuthError> {
    if master_keyring.is_empty() {
        return Err(AuthError::MissingMasterKeyring);
    }

    let mut keyring_for_verifier = HashMap::new();

    for field_name in fields_to_reveal {
        if !fields.contains_key(field_name) {
            return Err(AuthError::FieldNotFound(field_name.clone()));
        }

        // Decrypt the master key
        let (field_revelation_key, _) = decrypt_field(
            subject_wallet,
            master_keyring,
            field_name,
            fields.get(field_name).unwrap(),
            certifier,
        )?;

        // Re-encrypt for the verifier
        let (protocol_id, key_id) = Certificate::get_encryption_details(field_name, serial_number);
        let encrypted_for_verifier = subject_wallet.encrypt(EncryptArgs {
            encryption_args: EncryptionArgs {
                protocol_id,
                key_id,
                counterparty: verifier.clone(),
                privileged: false,
                privileged_reason: String::new(),
                seek_permission: false,
            },
            plaintext: field_revelation_key,
        })?;

        keyring_for_verifier.insert(
            field_name.clone(),
            BASE64.encode(&encrypted_for_verifier.ciphertext),
        );
    }

    Ok(keyring_for_verifier)
}
