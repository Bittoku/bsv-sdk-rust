//! Wallet wire protocol serializer.
//!
//! Binary serialization for wallet request/response frames, matching the
//! Go SDK's `wallet/serializer` package and the TypeScript SDK wire format.

use bsv_primitives::ec::public_key::PublicKey;
use bsv_primitives::ec::signature::Signature;
use bsv_primitives::util::{BsvReader, BsvWriter, VarInt};

use crate::error::WalletError;
use crate::types::*;

// === Wire constants ===

const COUNTERPARTY_UNINITIALIZED: u8 = 0;
const COUNTERPARTY_SELF: u8 = 11;
const COUNTERPARTY_ANYONE: u8 = 12;
const NEGATIVE_ONE_BYTE: u8 = 0xFF;
const IDENTITY_KEY_FLAG: u8 = 1;

// === Request/Result Frames ===

/// A request frame in the wallet wire protocol.
#[derive(Debug, Clone)]
pub struct RequestFrame {
    /// The method call identifier byte.
    pub call: u8,
    /// The originator application identifier.
    pub originator: String,
    /// The serialized method parameters.
    pub params: Vec<u8>,
}

/// Serialize a request frame.
pub fn write_request_frame(frame: &RequestFrame) -> Vec<u8> {
    let mut w = BsvWriter::new();
    w.write_u8(frame.call);
    let orig_bytes = frame.originator.as_bytes();
    w.write_u8(orig_bytes.len() as u8);
    w.write_bytes(orig_bytes);
    if !frame.params.is_empty() {
        w.write_bytes(&frame.params);
    }
    w.into_bytes()
}

/// Deserialize a request frame.
pub fn read_request_frame(data: &[u8]) -> Result<RequestFrame, WalletError> {
    let mut r = BsvReader::new(data);
    let call = r
        .read_u8()
        .map_err(|e| WalletError::General(format!("read call: {}", e)))?;
    let orig_len =
        r.read_u8()
            .map_err(|e| WalletError::General(format!("read orig len: {}", e)))? as usize;
    let orig_bytes = r
        .read_bytes(orig_len)
        .map_err(|e| WalletError::General(format!("read orig: {}", e)))?;
    let originator = String::from_utf8(orig_bytes.to_vec())
        .map_err(|e| WalletError::General(format!("invalid originator utf8: {}", e)))?;
    let remaining = r.remaining();
    let params = if remaining > 0 {
        r.read_bytes(remaining)
            .map_err(|e| WalletError::General(format!("read params: {}", e)))?
            .to_vec()
    } else {
        vec![]
    };
    Ok(RequestFrame {
        call,
        originator,
        params,
    })
}

/// Serialize a result frame (success).
pub fn write_result_frame_ok(result: &[u8]) -> Vec<u8> {
    let mut w = BsvWriter::new();
    w.write_u8(0); // success
    w.write_bytes(result);
    w.into_bytes()
}

/// Serialize a result frame (error).
pub fn write_result_frame_err(code: u8, message: &str, stack: &str) -> Vec<u8> {
    let mut w = BsvWriter::new();
    w.write_u8(code);
    let msg_bytes = message.as_bytes();
    w.write_varint(VarInt(msg_bytes.len() as u64));
    w.write_bytes(msg_bytes);
    let stack_bytes = stack.as_bytes();
    w.write_varint(VarInt(stack_bytes.len() as u64));
    w.write_bytes(stack_bytes);
    w.into_bytes()
}

/// Read a result frame. Returns Ok(data) or Err with the error message.
pub fn read_result_frame(data: &[u8]) -> Result<Vec<u8>, WalletError> {
    let mut r = BsvReader::new(data);
    let error_byte = r
        .read_u8()
        .map_err(|e| WalletError::General(format!("read error byte: {}", e)))?;

    if error_byte != 0 {
        let msg_len = r
            .read_varint()
            .map_err(|e| WalletError::General(format!("read err msg len: {}", e)))?
            .0 as usize;
        let msg_bytes = r
            .read_bytes(msg_len)
            .map_err(|e| WalletError::General(format!("read err msg: {}", e)))?;
        let msg = String::from_utf8_lossy(msg_bytes).to_string();
        let stack_len = r
            .read_varint()
            .map_err(|e| WalletError::General(format!("read stack len: {}", e)))?
            .0 as usize;
        let _stack = r.read_bytes(stack_len).ok();
        return Err(WalletError::General(format!(
            "wire error (code {}): {}",
            error_byte, msg
        )));
    }

    let remaining = r.remaining();
    if remaining > 0 {
        Ok(r.read_bytes(remaining).unwrap().to_vec())
    } else {
        Ok(vec![])
    }
}

// === Encoding Helpers ===

fn write_string(w: &mut BsvWriter, s: &str) {
    let b = s.as_bytes();
    w.write_varint(VarInt(b.len() as u64));
    w.write_bytes(b);
}

fn read_string(r: &mut BsvReader) -> Result<String, WalletError> {
    let len = r
        .read_varint()
        .map_err(|e| WalletError::General(format!("read string len: {}", e)))?
        .0;
    if len == u64::MAX || len == 0 {
        return Ok(String::new());
    }
    let bytes = r
        .read_bytes(len as usize)
        .map_err(|e| WalletError::General(format!("read string: {}", e)))?;
    String::from_utf8(bytes.to_vec())
        .map_err(|e| WalletError::General(format!("invalid utf8: {}", e)))
}

fn write_optional_bool(w: &mut BsvWriter, b: Option<bool>) {
    match b {
        Some(true) => w.write_u8(1),
        Some(false) => w.write_u8(0),
        None => w.write_u8(NEGATIVE_ONE_BYTE),
    }
}

fn read_optional_bool(r: &mut BsvReader) -> Result<Option<bool>, WalletError> {
    let b = r
        .read_u8()
        .map_err(|e| WalletError::General(format!("read optional bool: {}", e)))?;
    match b {
        0xFF => Ok(None),
        1 => Ok(Some(true)),
        _ => Ok(Some(false)),
    }
}

fn encode_counterparty(w: &mut BsvWriter, cp: &Counterparty) -> Result<(), WalletError> {
    match cp.r#type {
        CounterpartyType::Uninitialized => w.write_u8(COUNTERPARTY_UNINITIALIZED),
        CounterpartyType::Self_ => w.write_u8(COUNTERPARTY_SELF),
        CounterpartyType::Anyone => w.write_u8(COUNTERPARTY_ANYONE),
        CounterpartyType::Other => {
            let pubkey = cp.counterparty.as_ref().ok_or_else(|| {
                WalletError::InvalidCounterparty(
                    "counterparty pubkey required for type other".into(),
                )
            })?;
            w.write_bytes(&pubkey.to_compressed());
        }
    }
    Ok(())
}

fn decode_counterparty(r: &mut BsvReader) -> Result<Counterparty, WalletError> {
    let flag = r
        .read_u8()
        .map_err(|e| WalletError::General(format!("read counterparty flag: {}", e)))?;
    match flag {
        COUNTERPARTY_UNINITIALIZED => Ok(Counterparty {
            r#type: CounterpartyType::Uninitialized,
            counterparty: None,
        }),
        COUNTERPARTY_SELF => Ok(Counterparty {
            r#type: CounterpartyType::Self_,
            counterparty: None,
        }),
        COUNTERPARTY_ANYONE => Ok(Counterparty {
            r#type: CounterpartyType::Anyone,
            counterparty: None,
        }),
        _ => {
            // flag is first byte of 33-byte compressed pubkey, read remaining 32
            let rest = r
                .read_bytes(32)
                .map_err(|e| WalletError::General(format!("read counterparty pubkey: {}", e)))?;
            let mut full = vec![flag];
            full.extend_from_slice(rest);
            let pubkey = PublicKey::from_bytes(&full)
                .map_err(|e| WalletError::General(format!("invalid counterparty pubkey: {}", e)))?;
            Ok(Counterparty {
                r#type: CounterpartyType::Other,
                counterparty: Some(pubkey),
            })
        }
    }
}

fn encode_protocol(w: &mut BsvWriter, protocol: &Protocol) {
    w.write_u8(protocol.security_level as u8);
    write_string(w, &protocol.protocol);
}

fn decode_protocol(r: &mut BsvReader) -> Result<Protocol, WalletError> {
    let level = r
        .read_u8()
        .map_err(|e| WalletError::General(format!("read security level: {}", e)))?;
    let name = read_string(r)?;
    Ok(Protocol {
        security_level: level as i32,
        protocol: name,
    })
}

fn encode_privileged_params(w: &mut BsvWriter, privileged: Option<bool>, reason: &str) {
    write_optional_bool(w, privileged);
    if !reason.is_empty() {
        write_string(w, reason);
    } else {
        w.write_u8(NEGATIVE_ONE_BYTE);
    }
}

fn decode_privileged_params(r: &mut BsvReader) -> Result<(Option<bool>, String), WalletError> {
    let privileged = read_optional_bool(r)?;
    let b = r
        .read_u8()
        .map_err(|e| WalletError::General(format!("read priv reason flag: {}", e)))?;
    if b == NEGATIVE_ONE_BYTE {
        return Ok((privileged, String::new()));
    }
    // Put byte back by creating a sub-reader... we can't easily do this with BsvReader.
    // Instead, we know this byte is the first byte of a VarInt for the string length.
    // Reconstruct: prepend it and read.
    // Simple approach: the byte IS the varint length (for lengths < 253).
    if b < 253 {
        let s_bytes = r
            .read_bytes(b as usize)
            .map_err(|e| WalletError::General(format!("read priv reason: {}", e)))?;
        let s = String::from_utf8(s_bytes.to_vec()).unwrap_or_default();
        Ok((privileged, s))
    } else {
        // For longer strings, reconstruct the varint
        let mut buf = vec![b];
        let extra = match b {
            253 => 2,
            254 => 4,
            255 => 8,
            _ => unreachable!(),
        };
        let extra_bytes = r
            .read_bytes(extra)
            .map_err(|e| WalletError::General(format!("read priv reason varint: {}", e)))?;
        buf.extend_from_slice(extra_bytes);
        let (vi, _) = VarInt::from_bytes(&buf)
            .map_err(|e| WalletError::General(format!("varint decode: {}", e)))?;
        let s_bytes = r
            .read_bytes(vi.0 as usize)
            .map_err(|e| WalletError::General(format!("read priv reason str: {}", e)))?;
        let s = String::from_utf8(s_bytes.to_vec()).unwrap_or_default();
        Ok((privileged, s))
    }
}

/// Shared key-related parameters (protocol, keyID, counterparty, privileged).
#[derive(Debug, Clone)]
pub struct KeyRelatedParams {
    /// The protocol under which the key is derived.
    pub protocol_id: Protocol,
    /// The application-specific key identifier.
    pub key_id: String,
    /// The counterparty for the operation.
    pub counterparty: Counterparty,
    /// Whether this is a privileged operation.
    pub privileged: Option<bool>,
    /// Human-readable reason for privileged access.
    pub privileged_reason: String,
}

/// Encode key-related parameters to wire format bytes.
pub fn encode_key_related_params(params: &KeyRelatedParams) -> Result<Vec<u8>, WalletError> {
    let mut w = BsvWriter::new();
    encode_protocol(&mut w, &params.protocol_id);
    write_string(&mut w, &params.key_id);
    encode_counterparty(&mut w, &params.counterparty)?;
    encode_privileged_params(&mut w, params.privileged, &params.privileged_reason);
    Ok(w.into_bytes())
}

/// Decode key-related parameters from wire format bytes.
pub fn decode_key_related_params(r: &mut BsvReader) -> Result<KeyRelatedParams, WalletError> {
    let protocol_id = decode_protocol(r)?;
    let key_id = read_string(r)?;
    let counterparty = decode_counterparty(r)?;
    let (privileged, privileged_reason) = decode_privileged_params(r)?;
    Ok(KeyRelatedParams {
        protocol_id,
        key_id,
        counterparty,
        privileged,
        privileged_reason,
    })
}

// === Encrypt/Decrypt ===

/// Serialize encrypt arguments to wire format bytes.
pub fn serialize_encrypt_args(args: &EncryptArgs) -> Result<Vec<u8>, WalletError> {
    let mut w = BsvWriter::new();
    let params = encode_key_related_params(&KeyRelatedParams {
        protocol_id: args.encryption_args.protocol_id.clone(),
        key_id: args.encryption_args.key_id.clone(),
        counterparty: args.encryption_args.counterparty.clone(),
        privileged: Some(args.encryption_args.privileged),
        privileged_reason: args.encryption_args.privileged_reason.clone(),
    })?;
    w.write_bytes(&params);
    w.write_varint(VarInt(args.plaintext.len() as u64));
    w.write_bytes(&args.plaintext);
    write_optional_bool(&mut w, Some(args.encryption_args.seek_permission));
    Ok(w.into_bytes())
}

/// Deserialize encrypt arguments from wire format bytes.
pub fn deserialize_encrypt_args(data: &[u8]) -> Result<EncryptArgs, WalletError> {
    let mut r = BsvReader::new(data);
    let params = decode_key_related_params(&mut r)?;
    let pt_len = r
        .read_varint()
        .map_err(|e| WalletError::General(format!("read pt len: {}", e)))?
        .0 as usize;
    let plaintext = r
        .read_bytes(pt_len)
        .map_err(|e| WalletError::General(format!("read pt: {}", e)))?
        .to_vec();
    let seek = read_optional_bool(&mut r)?.unwrap_or(false);

    Ok(EncryptArgs {
        encryption_args: EncryptionArgs {
            protocol_id: params.protocol_id,
            key_id: params.key_id,
            counterparty: params.counterparty,
            privileged: params.privileged.unwrap_or(false),
            privileged_reason: params.privileged_reason,
            seek_permission: seek,
        },
        plaintext,
    })
}

/// Serialize an encrypt result to wire format bytes.
pub fn serialize_encrypt_result(result: &EncryptResult) -> Vec<u8> {
    result.ciphertext.clone()
}

/// Deserialize an encrypt result from wire format bytes.
pub fn deserialize_encrypt_result(data: &[u8]) -> EncryptResult {
    EncryptResult {
        ciphertext: data.to_vec(),
    }
}

/// Serialize decrypt arguments to wire format bytes.
pub fn serialize_decrypt_args(args: &DecryptArgs) -> Result<Vec<u8>, WalletError> {
    let mut w = BsvWriter::new();
    let params = encode_key_related_params(&KeyRelatedParams {
        protocol_id: args.encryption_args.protocol_id.clone(),
        key_id: args.encryption_args.key_id.clone(),
        counterparty: args.encryption_args.counterparty.clone(),
        privileged: Some(args.encryption_args.privileged),
        privileged_reason: args.encryption_args.privileged_reason.clone(),
    })?;
    w.write_bytes(&params);
    w.write_varint(VarInt(args.ciphertext.len() as u64));
    w.write_bytes(&args.ciphertext);
    write_optional_bool(&mut w, Some(args.encryption_args.seek_permission));
    Ok(w.into_bytes())
}

/// Deserialize decrypt arguments from wire format bytes.
pub fn deserialize_decrypt_args(data: &[u8]) -> Result<DecryptArgs, WalletError> {
    let mut r = BsvReader::new(data);
    let params = decode_key_related_params(&mut r)?;
    let ct_len = r
        .read_varint()
        .map_err(|e| WalletError::General(format!("read ct len: {}", e)))?
        .0 as usize;
    let ciphertext = r
        .read_bytes(ct_len)
        .map_err(|e| WalletError::General(format!("read ct: {}", e)))?
        .to_vec();
    let seek = read_optional_bool(&mut r)?.unwrap_or(false);

    Ok(DecryptArgs {
        encryption_args: EncryptionArgs {
            protocol_id: params.protocol_id,
            key_id: params.key_id,
            counterparty: params.counterparty,
            privileged: params.privileged.unwrap_or(false),
            privileged_reason: params.privileged_reason,
            seek_permission: seek,
        },
        ciphertext,
    })
}

/// Serialize a decrypt result to wire format bytes.
pub fn serialize_decrypt_result(result: &DecryptResult) -> Vec<u8> {
    result.plaintext.clone()
}

/// Deserialize a decrypt result from wire format bytes.
pub fn deserialize_decrypt_result(data: &[u8]) -> DecryptResult {
    DecryptResult {
        plaintext: data.to_vec(),
    }
}

// === GetPublicKey ===

/// Serialize get-public-key arguments to wire format bytes.
pub fn serialize_get_public_key_args(args: &GetPublicKeyArgs) -> Result<Vec<u8>, WalletError> {
    let mut w = BsvWriter::new();
    if args.identity_key {
        w.write_u8(IDENTITY_KEY_FLAG);
        encode_privileged_params(
            &mut w,
            Some(args.encryption_args.privileged),
            &args.encryption_args.privileged_reason,
        );
    } else {
        w.write_u8(0);
        let params = encode_key_related_params(&KeyRelatedParams {
            protocol_id: args.encryption_args.protocol_id.clone(),
            key_id: args.encryption_args.key_id.clone(),
            counterparty: args.encryption_args.counterparty.clone(),
            privileged: Some(args.encryption_args.privileged),
            privileged_reason: args.encryption_args.privileged_reason.clone(),
        })?;
        w.write_bytes(&params);
        write_optional_bool(&mut w, args.for_self);
    }
    write_optional_bool(&mut w, Some(args.encryption_args.seek_permission));
    Ok(w.into_bytes())
}

/// Deserialize get-public-key arguments from wire format bytes.
pub fn deserialize_get_public_key_args(data: &[u8]) -> Result<GetPublicKeyArgs, WalletError> {
    let mut r = BsvReader::new(data);
    let ik_flag = r
        .read_u8()
        .map_err(|e| WalletError::General(format!("read ik flag: {}", e)))?;
    let identity_key = ik_flag == IDENTITY_KEY_FLAG;

    if identity_key {
        let (privileged, privileged_reason) = decode_privileged_params(&mut r)?;
        let seek = read_optional_bool(&mut r)?.unwrap_or(false);
        Ok(GetPublicKeyArgs {
            encryption_args: EncryptionArgs {
                protocol_id: Protocol {
                    security_level: 0,
                    protocol: String::new(),
                },
                key_id: String::new(),
                counterparty: Counterparty::default(),
                privileged: privileged.unwrap_or(false),
                privileged_reason,
                seek_permission: seek,
            },
            identity_key: true,
            for_self: None,
        })
    } else {
        let params = decode_key_related_params(&mut r)?;
        let for_self = read_optional_bool(&mut r)?;
        let seek = read_optional_bool(&mut r)?.unwrap_or(false);
        Ok(GetPublicKeyArgs {
            encryption_args: EncryptionArgs {
                protocol_id: params.protocol_id,
                key_id: params.key_id,
                counterparty: params.counterparty,
                privileged: params.privileged.unwrap_or(false),
                privileged_reason: params.privileged_reason,
                seek_permission: seek,
            },
            identity_key: false,
            for_self,
        })
    }
}

/// Serialize a get-public-key result to wire format bytes.
pub fn serialize_get_public_key_result(result: &GetPublicKeyResult) -> Vec<u8> {
    result.public_key.to_compressed().to_vec()
}

/// Deserialize a get-public-key result from wire format bytes.
pub fn deserialize_get_public_key_result(data: &[u8]) -> Result<GetPublicKeyResult, WalletError> {
    let pubkey = PublicKey::from_bytes(data)
        .map_err(|e| WalletError::General(format!("invalid pubkey: {}", e)))?;
    Ok(GetPublicKeyResult { public_key: pubkey })
}

// === CreateSignature ===

/// Serialize create-signature arguments to wire format bytes.
pub fn serialize_create_signature_args(args: &CreateSignatureArgs) -> Result<Vec<u8>, WalletError> {
    let mut w = BsvWriter::new();
    let params = encode_key_related_params(&KeyRelatedParams {
        protocol_id: args.encryption_args.protocol_id.clone(),
        key_id: args.encryption_args.key_id.clone(),
        counterparty: args.encryption_args.counterparty.clone(),
        privileged: Some(args.encryption_args.privileged),
        privileged_reason: args.encryption_args.privileged_reason.clone(),
    })?;
    w.write_bytes(&params);

    if !args.data.is_empty() {
        w.write_u8(1);
        w.write_varint(VarInt(args.data.len() as u64));
        w.write_bytes(&args.data);
    } else {
        w.write_u8(2);
        w.write_bytes(&args.hash_to_directly_sign);
    }

    write_optional_bool(&mut w, Some(args.encryption_args.seek_permission));
    Ok(w.into_bytes())
}

/// Deserialize create-signature arguments from wire format bytes.
pub fn deserialize_create_signature_args(data: &[u8]) -> Result<CreateSignatureArgs, WalletError> {
    let mut r = BsvReader::new(data);
    let params = decode_key_related_params(&mut r)?;

    let flag = r
        .read_u8()
        .map_err(|e| WalletError::General(format!("read data flag: {}", e)))?;
    let (sig_data, hash) = match flag {
        1 => {
            let len = r
                .read_varint()
                .map_err(|e| WalletError::General(format!("read data len: {}", e)))?
                .0 as usize;
            let d = r
                .read_bytes(len)
                .map_err(|e| WalletError::General(format!("read data: {}", e)))?
                .to_vec();
            (d, vec![])
        }
        2 => {
            let h = r
                .read_bytes(32)
                .map_err(|e| WalletError::General(format!("read hash: {}", e)))?
                .to_vec();
            (vec![], h)
        }
        _ => {
            return Err(WalletError::General(format!(
                "invalid data type flag: {}",
                flag
            )))
        }
    };

    let seek = read_optional_bool(&mut r)?.unwrap_or(false);

    Ok(CreateSignatureArgs {
        encryption_args: EncryptionArgs {
            protocol_id: params.protocol_id,
            key_id: params.key_id,
            counterparty: params.counterparty,
            privileged: params.privileged.unwrap_or(false),
            privileged_reason: params.privileged_reason,
            seek_permission: seek,
        },
        data: sig_data,
        hash_to_directly_sign: hash,
    })
}

/// Serialize a create-signature result to DER-encoded bytes.
pub fn serialize_create_signature_result(result: &CreateSignatureResult) -> Vec<u8> {
    result.signature.to_der()
}

/// Deserialize a create-signature result from DER-encoded bytes.
pub fn deserialize_create_signature_result(
    data: &[u8],
) -> Result<CreateSignatureResult, WalletError> {
    let sig = Signature::from_der(data)
        .map_err(|e| WalletError::General(format!("invalid signature: {}", e)))?;
    Ok(CreateSignatureResult { signature: sig })
}

// === HMAC ===

/// Serialize create-HMAC arguments to wire format bytes.
pub fn serialize_create_hmac_args(args: &CreateHmacArgs) -> Result<Vec<u8>, WalletError> {
    let mut w = BsvWriter::new();
    let params = encode_key_related_params(&KeyRelatedParams {
        protocol_id: args.encryption_args.protocol_id.clone(),
        key_id: args.encryption_args.key_id.clone(),
        counterparty: args.encryption_args.counterparty.clone(),
        privileged: Some(args.encryption_args.privileged),
        privileged_reason: args.encryption_args.privileged_reason.clone(),
    })?;
    w.write_bytes(&params);
    w.write_varint(VarInt(args.data.len() as u64));
    w.write_bytes(&args.data);
    write_optional_bool(&mut w, Some(args.encryption_args.seek_permission));
    Ok(w.into_bytes())
}

/// Deserialize create-HMAC arguments from wire format bytes.
pub fn deserialize_create_hmac_args(data: &[u8]) -> Result<CreateHmacArgs, WalletError> {
    let mut r = BsvReader::new(data);
    let params = decode_key_related_params(&mut r)?;
    let data_len = r
        .read_varint()
        .map_err(|e| WalletError::General(format!("read data len: {}", e)))?
        .0 as usize;
    let hmac_data = r
        .read_bytes(data_len)
        .map_err(|e| WalletError::General(format!("read data: {}", e)))?
        .to_vec();
    let seek = read_optional_bool(&mut r)?.unwrap_or(false);

    Ok(CreateHmacArgs {
        encryption_args: EncryptionArgs {
            protocol_id: params.protocol_id,
            key_id: params.key_id,
            counterparty: params.counterparty,
            privileged: params.privileged.unwrap_or(false),
            privileged_reason: params.privileged_reason,
            seek_permission: seek,
        },
        data: hmac_data,
    })
}

/// Serialize a create-HMAC result to raw 32-byte output.
pub fn serialize_create_hmac_result(result: &CreateHmacResult) -> Vec<u8> {
    result.hmac.to_vec()
}

/// Deserialize a create-HMAC result from raw 32-byte input.
pub fn deserialize_create_hmac_result(data: &[u8]) -> Result<CreateHmacResult, WalletError> {
    if data.len() < 32 {
        return Err(WalletError::General(format!(
            "HMAC too short: expected 32, got {}",
            data.len()
        )));
    }
    let mut hmac = [0u8; 32];
    hmac.copy_from_slice(&data[..32]);
    Ok(CreateHmacResult { hmac })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_protocol() -> Protocol {
        Protocol {
            security_level: 2,
            protocol: "test-protocol".into(),
        }
    }

    fn test_counterparty_self() -> Counterparty {
        Counterparty {
            r#type: CounterpartyType::Self_,
            counterparty: None,
        }
    }

    fn test_counterparty_anyone() -> Counterparty {
        Counterparty {
            r#type: CounterpartyType::Anyone,
            counterparty: None,
        }
    }

    fn test_counterparty_other() -> Counterparty {
        use bsv_primitives::ec::private_key::PrivateKey;
        let mut bytes = [0u8; 32];
        bytes[31] = 69;
        let pk = PrivateKey::from_bytes(&bytes).unwrap();
        Counterparty {
            r#type: CounterpartyType::Other,
            counterparty: Some(pk.pub_key()),
        }
    }

    // === Request/Result frame round-trips ===

    #[test]
    fn test_request_frame_roundtrip() {
        let frame = RequestFrame {
            call: 42,
            originator: "test-app".into(),
            params: vec![1, 2, 3, 4],
        };
        let bytes = write_request_frame(&frame);
        let decoded = read_request_frame(&bytes).unwrap();
        assert_eq!(decoded.call, 42);
        assert_eq!(decoded.originator, "test-app");
        assert_eq!(decoded.params, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_result_frame_ok_roundtrip() {
        let data = vec![10, 20, 30];
        let bytes = write_result_frame_ok(&data);
        let decoded = read_result_frame(&bytes).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_result_frame_err() {
        let bytes = write_result_frame_err(1, "something broke", "at line 42");
        let err = read_result_frame(&bytes).unwrap_err();
        assert!(err.to_string().contains("something broke"));
    }

    // === Key related params round-trips ===

    #[test]
    fn test_key_related_params_full_roundtrip() {
        let params = KeyRelatedParams {
            protocol_id: test_protocol(),
            key_id: "test-key-id".into(),
            counterparty: test_counterparty_other(),
            privileged: Some(true),
            privileged_reason: "test-reason".into(),
        };
        let bytes = encode_key_related_params(&params).unwrap();
        let mut r = BsvReader::new(&bytes);
        let decoded = decode_key_related_params(&mut r).unwrap();

        assert_eq!(
            decoded.protocol_id.security_level,
            params.protocol_id.security_level
        );
        assert_eq!(decoded.protocol_id.protocol, params.protocol_id.protocol);
        assert_eq!(decoded.key_id, params.key_id);
        assert_eq!(decoded.counterparty.r#type, CounterpartyType::Other);
        assert!(decoded.counterparty.counterparty.is_some());
        assert_eq!(
            decoded.counterparty.counterparty.unwrap().to_compressed(),
            params.counterparty.counterparty.unwrap().to_compressed()
        );
        assert_eq!(decoded.privileged, Some(true));
        assert_eq!(decoded.privileged_reason, "test-reason");
    }

    #[test]
    fn test_key_related_params_minimal_roundtrip() {
        let params = KeyRelatedParams {
            protocol_id: Protocol {
                security_level: 0,
                protocol: "default".into(),
            },
            key_id: String::new(),
            counterparty: Counterparty::default(),
            privileged: None,
            privileged_reason: String::new(),
        };
        let bytes = encode_key_related_params(&params).unwrap();
        let mut r = BsvReader::new(&bytes);
        let decoded = decode_key_related_params(&mut r).unwrap();

        assert_eq!(decoded.protocol_id.security_level, 0);
        assert_eq!(decoded.counterparty.r#type, CounterpartyType::Uninitialized);
        assert!(decoded.privileged.is_none());
    }

    #[test]
    fn test_counterparty_self_roundtrip() {
        let cp = test_counterparty_self();
        let mut w = BsvWriter::new();
        encode_counterparty(&mut w, &cp).unwrap();
        let bytes = w.into_bytes();
        let mut r = BsvReader::new(&bytes);
        let decoded = decode_counterparty(&mut r).unwrap();
        assert_eq!(decoded.r#type, CounterpartyType::Self_);
        assert!(decoded.counterparty.is_none());
    }

    #[test]
    fn test_counterparty_anyone_roundtrip() {
        let cp = test_counterparty_anyone();
        let mut w = BsvWriter::new();
        encode_counterparty(&mut w, &cp).unwrap();
        let bytes = w.into_bytes();
        let mut r = BsvReader::new(&bytes);
        let decoded = decode_counterparty(&mut r).unwrap();
        assert_eq!(decoded.r#type, CounterpartyType::Anyone);
    }

    #[test]
    fn test_counterparty_other_roundtrip() {
        let cp = test_counterparty_other();
        let orig_pub = cp.counterparty.clone().unwrap();
        let mut w = BsvWriter::new();
        encode_counterparty(&mut w, &cp).unwrap();
        let bytes = w.into_bytes();
        let mut r = BsvReader::new(&bytes);
        let decoded = decode_counterparty(&mut r).unwrap();
        assert_eq!(decoded.r#type, CounterpartyType::Other);
        assert_eq!(
            decoded.counterparty.unwrap().to_compressed(),
            orig_pub.to_compressed()
        );
    }

    // === Encrypt round-trip ===

    #[test]
    fn test_encrypt_args_roundtrip() {
        let args = EncryptArgs {
            encryption_args: EncryptionArgs {
                protocol_id: test_protocol(),
                key_id: "enc-key".into(),
                counterparty: test_counterparty_self(),
                privileged: true,
                privileged_reason: "need access".into(),
                seek_permission: false,
            },
            plaintext: b"hello world".to_vec(),
        };
        let bytes = serialize_encrypt_args(&args).unwrap();
        let decoded = deserialize_encrypt_args(&bytes).unwrap();
        assert_eq!(decoded.plaintext, b"hello world");
        assert_eq!(decoded.encryption_args.key_id, "enc-key");
        assert_eq!(
            decoded.encryption_args.counterparty.r#type,
            CounterpartyType::Self_
        );
    }

    // === GetPublicKey round-trip ===

    #[test]
    fn test_get_public_key_identity_roundtrip() {
        let args = GetPublicKeyArgs {
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
            identity_key: true,
            for_self: None,
        };
        let bytes = serialize_get_public_key_args(&args).unwrap();
        let decoded = deserialize_get_public_key_args(&bytes).unwrap();
        assert!(decoded.identity_key);
    }

    #[test]
    fn test_get_public_key_derived_roundtrip() {
        let args = GetPublicKeyArgs {
            encryption_args: EncryptionArgs {
                protocol_id: test_protocol(),
                key_id: "derived-key".into(),
                counterparty: test_counterparty_other(),
                privileged: false,
                privileged_reason: String::new(),
                seek_permission: true,
            },
            identity_key: false,
            for_self: Some(true),
        };
        let bytes = serialize_get_public_key_args(&args).unwrap();
        let decoded = deserialize_get_public_key_args(&bytes).unwrap();
        assert!(!decoded.identity_key);
        assert_eq!(decoded.for_self, Some(true));
        assert_eq!(decoded.encryption_args.key_id, "derived-key");
    }

    // === CreateSignature round-trip ===

    #[test]
    fn test_create_signature_args_data_roundtrip() {
        let args = CreateSignatureArgs {
            encryption_args: EncryptionArgs {
                protocol_id: test_protocol(),
                key_id: "sig-key".into(),
                counterparty: test_counterparty_anyone(),
                privileged: false,
                privileged_reason: String::new(),
                seek_permission: false,
            },
            data: b"sign this".to_vec(),
            hash_to_directly_sign: vec![],
        };
        let bytes = serialize_create_signature_args(&args).unwrap();
        let decoded = deserialize_create_signature_args(&bytes).unwrap();
        assert_eq!(decoded.data, b"sign this");
        assert!(decoded.hash_to_directly_sign.is_empty());
    }

    #[test]
    fn test_create_signature_args_hash_roundtrip() {
        let hash = [42u8; 32];
        let args = CreateSignatureArgs {
            encryption_args: EncryptionArgs {
                protocol_id: test_protocol(),
                key_id: "sig-key".into(),
                counterparty: test_counterparty_anyone(),
                privileged: false,
                privileged_reason: String::new(),
                seek_permission: false,
            },
            data: vec![],
            hash_to_directly_sign: hash.to_vec(),
        };
        let bytes = serialize_create_signature_args(&args).unwrap();
        let decoded = deserialize_create_signature_args(&bytes).unwrap();
        assert!(decoded.data.is_empty());
        assert_eq!(decoded.hash_to_directly_sign, hash.to_vec());
    }

    // === HMAC round-trip ===

    #[test]
    fn test_create_hmac_args_roundtrip() {
        let args = CreateHmacArgs {
            encryption_args: EncryptionArgs {
                protocol_id: test_protocol(),
                key_id: "hmac-key".into(),
                counterparty: test_counterparty_self(),
                privileged: false,
                privileged_reason: String::new(),
                seek_permission: false,
            },
            data: b"hmac this".to_vec(),
        };
        let bytes = serialize_create_hmac_args(&args).unwrap();
        let decoded = deserialize_create_hmac_args(&bytes).unwrap();
        assert_eq!(decoded.data, b"hmac this");
        assert_eq!(decoded.encryption_args.key_id, "hmac-key");
    }

    #[test]
    fn test_create_hmac_result_roundtrip() {
        let result = CreateHmacResult { hmac: [7u8; 32] };
        let bytes = serialize_create_hmac_result(&result);
        let decoded = deserialize_create_hmac_result(&bytes).unwrap();
        assert_eq!(decoded.hmac, [7u8; 32]);
    }
}
