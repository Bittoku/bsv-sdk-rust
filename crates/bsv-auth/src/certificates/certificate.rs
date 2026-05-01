//! Base Certificate type with signing and verification.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bsv_primitives::ec::public_key::PublicKey;
use bsv_primitives::ec::signature::Signature;
use bsv_primitives::util::{BsvReader, BsvWriter, VarInt};
use bsv_wallet::types::*;
use bsv_wallet::wallet_trait::WalletInterface;
use std::collections::HashMap;

use crate::error::AuthError;

/// A BRC-31 identity certificate.
#[derive(Debug, Clone)]
pub struct Certificate {
    /// Type identifier (base64 encoded, 32 bytes decoded).
    pub cert_type: String,
    /// Unique serial number (base64 encoded, 32 bytes decoded).
    pub serial_number: String,
    /// Subject's public key.
    pub subject: PublicKey,
    /// Certifier's public key.
    pub certifier: PublicKey,
    /// Revocation outpoint (txid_hex.index).
    pub revocation_outpoint: String,
    /// Encrypted fields: field_name -> base64_encrypted_value.
    pub fields: HashMap<String, String>,
    /// DER-encoded signature bytes.
    pub signature: Vec<u8>,
}

impl Certificate {
    /// Create a new unsigned certificate.
    pub fn new(
        cert_type: String,
        serial_number: String,
        subject: PublicKey,
        certifier: PublicKey,
        revocation_outpoint: String,
        fields: HashMap<String, String>,
    ) -> Self {
        Self {
            cert_type,
            serial_number,
            subject,
            certifier,
            revocation_outpoint,
            fields,
            signature: Vec::new(),
        }
    }

    /// Serialize the certificate to binary format.
    pub fn to_binary(&self, include_signature: bool) -> Result<Vec<u8>, AuthError> {
        let mut w = BsvWriter::new();

        // Type (base64 -> 32 bytes)
        let type_bytes = BASE64
            .decode(&self.cert_type)
            .map_err(|e| AuthError::General(format!("invalid cert type base64: {}", e)))?;
        w.write_bytes(&type_bytes);

        // Serial number (base64 -> 32 bytes)
        let serial_bytes = BASE64
            .decode(&self.serial_number)
            .map_err(|e| AuthError::General(format!("invalid serial number base64: {}", e)))?;
        w.write_bytes(&serial_bytes);

        // Subject (33 bytes compressed)
        w.write_bytes(&self.subject.to_compressed());

        // Certifier (33 bytes compressed)
        w.write_bytes(&self.certifier.to_compressed());

        // Revocation outpoint
        let outpoint_bytes = encode_outpoint(&self.revocation_outpoint)?;
        w.write_bytes(&outpoint_bytes);

        // Fields count + field data
        w.write_varint(VarInt(self.fields.len() as u64));
        // Sort fields by key for deterministic serialization
        let mut sorted_fields: Vec<_> = self.fields.iter().collect();
        sorted_fields.sort_by_key(|(k, _)| k.as_str());
        for (name, value) in sorted_fields {
            let name_bytes = name.as_bytes();
            w.write_varint(VarInt(name_bytes.len() as u64));
            w.write_bytes(name_bytes);
            let value_bytes = value.as_bytes();
            w.write_varint(VarInt(value_bytes.len() as u64));
            w.write_bytes(value_bytes);
        }

        // Signature
        if include_signature && !self.signature.is_empty() {
            w.write_varint(VarInt(self.signature.len() as u64));
            w.write_bytes(&self.signature);
        }

        Ok(w.into_bytes())
    }

    /// Deserialize a certificate from binary format.
    pub fn from_binary(data: &[u8]) -> Result<Self, AuthError> {
        let mut r = BsvReader::new(data);

        // Type (32 bytes)
        let type_bytes = r
            .read_bytes(32)
            .map_err(|e| AuthError::General(format!("read cert type: {}", e)))?;
        let cert_type = BASE64.encode(type_bytes);

        // Serial number (32 bytes)
        let serial_bytes = r
            .read_bytes(32)
            .map_err(|e| AuthError::General(format!("read serial: {}", e)))?;
        let serial_number = BASE64.encode(serial_bytes);

        // Subject (33 bytes)
        let subject_bytes = r
            .read_bytes(33)
            .map_err(|e| AuthError::General(format!("read subject: {}", e)))?;
        let subject = PublicKey::from_bytes(subject_bytes)
            .map_err(|e| AuthError::General(format!("parse subject: {}", e)))?;

        // Certifier (33 bytes)
        let certifier_bytes = r
            .read_bytes(33)
            .map_err(|e| AuthError::General(format!("read certifier: {}", e)))?;
        let certifier = PublicKey::from_bytes(certifier_bytes)
            .map_err(|e| AuthError::General(format!("parse certifier: {}", e)))?;

        // Revocation outpoint (36 bytes: 32 txid + 4 index)
        let outpoint_bytes = r
            .read_bytes(36)
            .map_err(|e| AuthError::General(format!("read outpoint: {}", e)))?;
        let revocation_outpoint = decode_outpoint(outpoint_bytes)?;

        // Fields
        let field_count = r
            .read_varint()
            .map_err(|e| AuthError::General(format!("read field count: {}", e)))?
            .0 as usize;
        let mut fields = HashMap::new();
        for _ in 0..field_count {
            let name_len = r
                .read_varint()
                .map_err(|e| AuthError::General(format!("read field name len: {}", e)))?
                .0 as usize;
            let name_bytes = r
                .read_bytes(name_len)
                .map_err(|e| AuthError::General(format!("read field name: {}", e)))?;
            let name = String::from_utf8(name_bytes.to_vec())
                .map_err(|e| AuthError::General(format!("invalid field name: {}", e)))?;

            let value_len = r
                .read_varint()
                .map_err(|e| AuthError::General(format!("read field value len: {}", e)))?
                .0 as usize;
            let value_bytes = r
                .read_bytes(value_len)
                .map_err(|e| AuthError::General(format!("read field value: {}", e)))?;
            let value = String::from_utf8(value_bytes.to_vec())
                .map_err(|e| AuthError::General(format!("invalid field value: {}", e)))?;

            fields.insert(name, value);
        }

        // Signature (optional, rest of data)
        let mut signature = Vec::new();
        if r.remaining() > 0 {
            let sig_len = r
                .read_varint()
                .map_err(|e| AuthError::General(format!("read sig len: {}", e)))?
                .0 as usize;
            if sig_len > 0 {
                let sig_bytes = r
                    .read_bytes(sig_len)
                    .map_err(|e| AuthError::General(format!("read sig: {}", e)))?;
                signature = sig_bytes.to_vec();
            }
        }

        Ok(Certificate {
            cert_type,
            serial_number,
            subject,
            certifier,
            revocation_outpoint,
            fields,
            signature,
        })
    }

    /// Sign the certificate using the certifier's wallet.
    pub fn sign(
        &mut self,
        certifier_wallet: &dyn bsv_wallet::wallet_trait::WalletInterface,
    ) -> Result<(), AuthError> {
        if !self.signature.is_empty() {
            return Err(AuthError::AlreadySigned);
        }

        // Update certifier to wallet's identity key
        let pub_key_result = certifier_wallet.get_public_key(GetPublicKeyArgs {
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
        self.certifier = pub_key_result.public_key;

        let data_to_sign = self.to_binary(false)?;

        let sig_result = certifier_wallet.create_signature(CreateSignatureArgs {
            encryption_args: EncryptionArgs {
                protocol_id: Protocol {
                    security_level: SECURITY_LEVEL_EVERY_APP_AND_COUNTERPARTY,
                    protocol: "certificate signature".to_string(),
                },
                key_id: format!("{} {}", self.cert_type, self.serial_number),
                counterparty: Counterparty {
                    r#type: CounterpartyType::Anyone,
                    counterparty: None,
                },
                privileged: false,
                privileged_reason: String::new(),
                seek_permission: false,
            },
            data: data_to_sign,
            hash_to_directly_sign: Vec::new(),
        })?;

        self.signature = sig_result.signature.to_der();

        Ok(())
    }

    /// Verify the certificate signature.
    pub fn verify(&self) -> Result<(), AuthError> {
        if self.signature.is_empty() {
            return Err(AuthError::NotSigned);
        }

        // Create an anyone wallet for verification
        let verifier = bsv_wallet::ProtoWallet::new(bsv_wallet::ProtoWalletArgs::Anyone)?;

        let data = self.to_binary(false)?;

        let signature = Signature::from_der(&self.signature)
            .map_err(|e| AuthError::General(format!("failed to parse signature: {}", e)))?;

        let verify_result = verifier.verify_signature(VerifySignatureArgs {
            encryption_args: EncryptionArgs {
                protocol_id: Protocol {
                    security_level: SECURITY_LEVEL_EVERY_APP_AND_COUNTERPARTY,
                    protocol: "certificate signature".to_string(),
                },
                key_id: format!("{} {}", self.cert_type, self.serial_number),
                counterparty: Counterparty {
                    r#type: CounterpartyType::Other,
                    counterparty: Some(self.certifier.clone()),
                },
                privileged: false,
                privileged_reason: String::new(),
                seek_permission: false,
            },
            data,
            hash_to_directly_verify: Vec::new(),
            signature: Some(signature),
            for_self: None,
        })?;

        if !verify_result.valid {
            return Err(AuthError::InvalidSignature);
        }

        Ok(())
    }

    /// Get encryption protocol and key ID for certificate fields.
    pub fn get_encryption_details(field_name: &str, serial_number: &str) -> (Protocol, String) {
        let protocol_id = Protocol {
            security_level: SECURITY_LEVEL_EVERY_APP_AND_COUNTERPARTY,
            protocol: "certificate field encryption".to_string(),
        };

        let key_id = if !serial_number.is_empty() {
            format!("{} {}", serial_number, field_name)
        } else {
            field_name.to_string()
        };

        (protocol_id, key_id)
    }
}

fn encode_outpoint(outpoint: &str) -> Result<Vec<u8>, AuthError> {
    let mut result = vec![0u8; 36];
    if outpoint.is_empty() {
        return Ok(result);
    }
    let parts: Vec<&str> = outpoint.split('.').collect();
    if parts.len() != 2 {
        return Err(AuthError::General(format!(
            "invalid outpoint format: {}",
            outpoint
        )));
    }
    let txid_hex = parts[0];
    let index: u32 = parts[1]
        .parse()
        .map_err(|e| AuthError::General(format!("invalid outpoint index: {}", e)))?;
    let txid_bytes = hex::decode(txid_hex)
        .map_err(|e| AuthError::General(format!("invalid outpoint txid: {}", e)))?;
    if txid_bytes.len() != 32 {
        return Err(AuthError::General("txid must be 32 bytes".into()));
    }
    result[..32].copy_from_slice(&txid_bytes);
    result[32..36].copy_from_slice(&index.to_le_bytes());
    Ok(result)
}

fn decode_outpoint(data: &[u8]) -> Result<String, AuthError> {
    if data.len() != 36 {
        return Err(AuthError::General("outpoint must be 36 bytes".into()));
    }
    let txid_hex = hex::encode(&data[..32]);
    let index = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
    Ok(format!("{}.{}", txid_hex, index))
}
