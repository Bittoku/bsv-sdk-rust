//! Script chunk parsing and encoding.
//!
//! A script chunk is either an opcode or a data push with its associated bytes.
//! This module handles decoding raw script bytes into structured chunks and
//! encoding push data with the correct OP_PUSHDATA prefix.

use crate::opcodes::*;
use crate::ScriptError;

/// A single parsed element of a Bitcoin script.
///
/// Each chunk is either a standalone opcode (like OP_DUP) or a data push
/// that carries the opcode byte and the pushed data bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptChunk {
    /// The opcode byte. For direct pushes (1-75 bytes), this is the length.
    pub op: u8,
    /// The data payload, if this chunk is a push operation.
    pub data: Option<Vec<u8>>,
}

impl ScriptChunk {
    /// Convert this chunk to its ASM string representation.
    ///
    /// Data push chunks are rendered as hex strings; non-push opcodes use
    /// their canonical OP_xxx name.
    ///
    /// # Returns
    /// A string suitable for inclusion in a space-separated ASM output.
    pub fn to_asm_string(&self) -> String {
        if self.op > OP_0 && self.op <= OP_PUSHDATA4 {
            if let Some(ref data) = self.data {
                return hex::encode(data);
            }
        }
        opcode_to_string(self.op).to_string()
    }
}

/// Decode raw script bytes into a vector of `ScriptChunk` values.
///
/// Handles OP_DATA_1..OP_DATA_75 (direct push), OP_PUSHDATA1/2/4
/// (extended push), and OP_RETURN (consumes remaining bytes as data
/// unless inside a conditional block).
///
/// # Arguments
/// * `bytes` - The raw script bytes to decode.
///
/// # Returns
/// A vector of parsed chunks, or a `ScriptError` if the data is truncated.
pub fn decode_script(bytes: &[u8]) -> Result<Vec<ScriptChunk>, ScriptError> {
    let mut chunks = Vec::new();
    let mut pos = 0;
    let mut conditional_block: i32 = 0;

    while pos < bytes.len() {
        let op = bytes[pos];

        match op {
            OP_IF | OP_NOTIF | OP_VERIF | OP_VERNOTIF => {
                conditional_block += 1;
                chunks.push(ScriptChunk { op, data: None });
                pos += 1;
            }
            OP_ENDIF => {
                conditional_block -= 1;
                chunks.push(ScriptChunk { op, data: None });
                pos += 1;
            }
            OP_RETURN => {
                if conditional_block > 0 {
                    chunks.push(ScriptChunk { op, data: None });
                    pos += 1;
                } else {
                    // Consume the rest of the script as data attached to OP_RETURN.
                    let data = bytes[pos..].to_vec();
                    chunks.push(ScriptChunk {
                        op,
                        data: Some(data),
                    });
                    pos = bytes.len();
                }
            }
            OP_PUSHDATA1 => {
                if bytes.len() < pos + 2 {
                    return Err(ScriptError::DataTooSmall);
                }
                let length = bytes[pos + 1] as usize;
                pos += 2;
                if bytes.len() < pos + length {
                    return Err(ScriptError::DataTooSmall);
                }
                let data = bytes[pos..pos + length].to_vec();
                chunks.push(ScriptChunk {
                    op,
                    data: Some(data),
                });
                pos += length;
            }
            OP_PUSHDATA2 => {
                if bytes.len() < pos + 3 {
                    return Err(ScriptError::DataTooSmall);
                }
                let length = u16::from_le_bytes([bytes[pos + 1], bytes[pos + 2]]) as usize;
                pos += 3;
                if bytes.len() < pos + length {
                    return Err(ScriptError::DataTooSmall);
                }
                let data = bytes[pos..pos + length].to_vec();
                chunks.push(ScriptChunk {
                    op,
                    data: Some(data),
                });
                pos += length;
            }
            OP_PUSHDATA4 => {
                if bytes.len() < pos + 5 {
                    return Err(ScriptError::DataTooSmall);
                }
                let length = u32::from_le_bytes([
                    bytes[pos + 1],
                    bytes[pos + 2],
                    bytes[pos + 3],
                    bytes[pos + 4],
                ]) as usize;
                pos += 5;
                if bytes.len() < pos + length {
                    return Err(ScriptError::DataTooSmall);
                }
                let data = bytes[pos..pos + length].to_vec();
                chunks.push(ScriptChunk {
                    op,
                    data: Some(data),
                });
                pos += length;
            }
            0x01..=0x4b => {
                // Direct push: op byte is the number of bytes to push.
                let length = op as usize;
                if bytes.len() < pos + 1 + length {
                    return Err(ScriptError::DataTooSmall);
                }
                let data = bytes[pos + 1..pos + 1 + length].to_vec();
                chunks.push(ScriptChunk {
                    op,
                    data: Some(data),
                });
                pos += 1 + length;
            }
            _ => {
                chunks.push(ScriptChunk { op, data: None });
                pos += 1;
            }
        }
    }

    Ok(chunks)
}

/// Compute the OP_PUSHDATA prefix bytes for a data payload of the given length.
///
/// Returns the prefix that should be prepended to the data when encoding
/// a push operation into raw script bytes.
///
/// # Arguments
/// * `data_len` - The length of the data to be pushed.
///
/// # Returns
/// A byte vector containing the appropriate prefix, or an error if the data
/// is too large for the protocol.
pub fn push_data_prefix(data_len: usize) -> Result<Vec<u8>, ScriptError> {
    if data_len <= 75 {
        Ok(vec![data_len as u8])
    } else if data_len <= 0xFF {
        Ok(vec![OP_PUSHDATA1, data_len as u8])
    } else if data_len <= 0xFFFF {
        let mut buf = vec![OP_PUSHDATA2];
        buf.extend_from_slice(&(data_len as u16).to_le_bytes());
        Ok(buf)
    } else if data_len <= 0xFFFFFFFF {
        let mut buf = vec![OP_PUSHDATA4];
        buf.extend_from_slice(&(data_len as u32).to_le_bytes());
        Ok(buf)
    } else {
        Err(ScriptError::DataTooBig)
    }
}

/// Encode multiple data payloads into a single byte vector with push prefixes.
///
/// Each element in `parts` gets its own OP_PUSHDATA prefix based on length.
///
/// # Arguments
/// * `parts` - Slice of data byte slices to encode.
///
/// # Returns
/// A byte vector containing all pushes concatenated, or an error if any
/// part is too large.
pub fn encode_push_datas(parts: &[&[u8]]) -> Result<Vec<u8>, ScriptError> {
    let mut result = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        let prefix = push_data_prefix(part.len()).map_err(|_| ScriptError::PartTooBig(i))?;
        result.extend_from_slice(&prefix);
        result.extend_from_slice(part);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    //! Tests for script chunk decoding and push data encoding.
    //!
    //! Covers decode_script with simple, complex, and malformed inputs,
    //! push_data_prefix boundary sizes, encode_push_datas roundtrips,
    //! and OP_PUSHDATA1/2/4 error cases. Test vectors are derived from
    //! the Go SDK reference implementation.

    use super::*;

    // -----------------------------------------------------------------------
    // decode_script - basic cases
    // -----------------------------------------------------------------------

    /// Decode a script with three simple push chunks and verify count.
    #[test]
    fn test_decode_script_simple() {
        let script_hex = "05000102030401FF02ABCD";
        let bytes = hex::decode(script_hex).expect("valid hex");
        let parts = decode_script(&bytes).expect("should decode");
        assert_eq!(parts.len(), 3);
    }

    /// Decode and re-encode a simple script to verify roundtrip fidelity.
    #[test]
    fn test_decode_and_encode_roundtrip() {
        let script_hex = "05000102030401FF02ABCD";
        let bytes = hex::decode(script_hex).expect("valid hex");
        let parts = decode_script(&bytes).expect("should decode");
        assert_eq!(parts.len(), 3);

        // Re-encode: gather the data from each chunk
        let data_parts: Vec<&[u8]> = parts.iter().filter_map(|p| p.data.as_deref()).collect();
        let encoded = encode_push_datas(&data_parts).expect("should encode");
        assert_eq!(hex::encode(&encoded), script_hex.to_lowercase());
    }

    /// Decode an empty byte slice returns an empty chunk vector.
    #[test]
    fn test_decode_script_empty() {
        let parts = decode_script(&[]).expect("should decode");
        assert!(parts.is_empty());
    }

    /// Decode a complex multisig-like script with OP_PUSHDATA1 chunks.
    #[test]
    fn test_decode_script_complex() {
        let script_hex = "524c53ff0488b21e000000000000000000362f7a9030543db8751401c387d6a71e870f1895b3a62569d455e8ee5f5f5e5f03036624c6df96984db6b4e625b6707c017eb0e0d137cd13a0c989bfa77a4473fd000000004c53ff0488b21e0000000000000000008b20425398995f3c866ea6ce5c1828a516b007379cf97b136bffbdc86f75df14036454bad23b019eae34f10aff8b8d6d8deb18cb31354e5a169ee09d8a4560e8250000000052ae";
        let bytes = hex::decode(script_hex).expect("valid hex");
        let parts = decode_script(&bytes).expect("should decode");
        assert_eq!(parts.len(), 5);
    }

    // -----------------------------------------------------------------------
    // decode_script - error / truncation cases
    // -----------------------------------------------------------------------

    /// Verify that a truncated direct-push script returns DataTooSmall.
    #[test]
    fn test_decode_script_bad_parts() {
        // 0x05 says "push 5 bytes" but only 3 bytes follow
        let bytes = hex::decode("05000000").expect("valid hex");
        let result = decode_script(&bytes);
        assert!(result.is_err());
    }

    /// Verify that a truncated OP_PUSHDATA1 script returns DataTooSmall.
    #[test]
    fn test_decode_script_invalid_pushdata1() {
        // OP_PUSHDATA1 = 0x4c, claims 5 bytes but only 4 follow
        let bytes = hex::decode("4c05000000").expect("valid hex");
        let result = decode_script(&bytes);
        assert!(result.is_err());
    }

    /// Verify OP_PUSHDATA1 with a valid data payload decodes correctly.
    #[test]
    fn test_decode_script_pushdata1_valid() {
        let data = b"testing";
        let mut script_bytes = vec![OP_PUSHDATA1, data.len() as u8];
        script_bytes.extend_from_slice(data);
        let parts = decode_script(&script_bytes).expect("should decode");
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].op, OP_PUSHDATA1);
        assert_eq!(parts[0].data.as_ref().unwrap(), data);
    }

    /// Verify OP_PUSHDATA1 alone (no length byte) returns an error.
    #[test]
    fn test_decode_script_pushdata1_missing_payload() {
        let result = decode_script(&[OP_PUSHDATA1]);
        assert!(result.is_err());
    }

    /// Verify OP_PUSHDATA2 alone returns an error.
    #[test]
    fn test_decode_script_pushdata2_missing_payload() {
        let result = decode_script(&[OP_PUSHDATA2]);
        assert!(result.is_err());
    }

    /// Verify OP_PUSHDATA2 with insufficient data returns an error.
    #[test]
    fn test_decode_script_pushdata2_too_small() {
        let data = b"testing PUSHDATA2";
        let mut script_bytes = vec![OP_PUSHDATA2, data.len() as u8];
        script_bytes.extend_from_slice(data);
        // Only 1 length byte instead of 2 -- OP_PUSHDATA2 needs 2 bytes for length
        let result = decode_script(&script_bytes);
        assert!(result.is_err());
    }

    /// Verify OP_PUSHDATA4 alone returns an error.
    #[test]
    fn test_decode_script_pushdata4_missing_payload() {
        let result = decode_script(&[OP_PUSHDATA4]);
        assert!(result.is_err());
    }

    /// Verify OP_PUSHDATA4 with insufficient data returns an error.
    #[test]
    fn test_decode_script_pushdata4_too_small() {
        let data = b"testing PUSHDATA4";
        let mut script_bytes = vec![OP_PUSHDATA4, data.len() as u8];
        script_bytes.extend_from_slice(data);
        // Only 1 length byte instead of 4 -- will fail
        let result = decode_script(&script_bytes);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // push_data_prefix boundary tests
    // -----------------------------------------------------------------------

    /// Verify push_data_prefix returns a 1-byte prefix for data <= 75 bytes.
    #[test]
    fn test_push_data_prefix_small() {
        let prefix = push_data_prefix(20).expect("should succeed");
        assert_eq!(prefix, vec![20u8]);
    }

    /// Verify push_data_prefix returns a 1-byte prefix at the 75-byte boundary.
    #[test]
    fn test_push_data_prefix_75() {
        let prefix = push_data_prefix(75).expect("should succeed");
        assert_eq!(prefix, vec![75u8]);
    }

    /// Verify push_data_prefix returns OP_PUSHDATA1 prefix for 76..=255 bytes.
    #[test]
    fn test_push_data_prefix_pushdata1() {
        let prefix = push_data_prefix(76).expect("should succeed");
        assert_eq!(prefix, vec![OP_PUSHDATA1, 76]);
    }

    /// Verify push_data_prefix returns OP_PUSHDATA1 prefix at the 255-byte boundary.
    #[test]
    fn test_push_data_prefix_255() {
        let prefix = push_data_prefix(255).expect("should succeed");
        assert_eq!(prefix, vec![OP_PUSHDATA1, 255]);
    }

    /// Verify push_data_prefix returns OP_PUSHDATA2 prefix for 256..=65535 bytes.
    #[test]
    fn test_push_data_prefix_pushdata2() {
        let prefix = push_data_prefix(256).expect("should succeed");
        assert_eq!(prefix, vec![OP_PUSHDATA2, 0x00, 0x01]);
    }

    /// Verify push_data_prefix returns OP_PUSHDATA2 prefix at the 65535-byte boundary.
    #[test]
    fn test_push_data_prefix_65535() {
        let prefix = push_data_prefix(65535).expect("should succeed");
        assert_eq!(prefix, vec![OP_PUSHDATA2, 0xFF, 0xFF]);
    }

    /// Verify push_data_prefix returns OP_PUSHDATA4 prefix for 65536+ bytes.
    #[test]
    fn test_push_data_prefix_pushdata4() {
        let prefix = push_data_prefix(65536).expect("should succeed");
        assert_eq!(prefix, vec![OP_PUSHDATA4, 0x00, 0x00, 0x01, 0x00]);
    }

    // -----------------------------------------------------------------------
    // encode_push_datas
    // -----------------------------------------------------------------------

    /// Verify encode_push_datas concatenates multiple pushes correctly.
    #[test]
    fn test_encode_push_datas_multiple() {
        let parts: Vec<&[u8]> = vec![b"hello", b"world"];
        let encoded = encode_push_datas(&parts).expect("should encode");
        // "hello" is 5 bytes -> prefix 0x05, "world" is 5 bytes -> prefix 0x05
        let expected = hex::decode("0568656c6c6f05776f726c64").expect("valid hex");
        assert_eq!(encoded, expected);
    }

    /// Verify encode_push_datas with an empty parts list returns empty bytes.
    #[test]
    fn test_encode_push_datas_empty() {
        let parts: Vec<&[u8]> = vec![];
        let encoded = encode_push_datas(&parts).expect("should encode");
        assert!(encoded.is_empty());
    }

    // -----------------------------------------------------------------------
    // ScriptChunk::to_asm_string
    // -----------------------------------------------------------------------

    /// Verify that a data-push chunk renders as hex in ASM output.
    #[test]
    fn test_chunk_to_asm_string_data() {
        let chunk = ScriptChunk {
            op: OP_DATA_20,
            data: Some(vec![0xAB; 20]),
        };
        let asm = chunk.to_asm_string();
        assert_eq!(asm, "ab".repeat(20));
    }

    /// Verify that a non-push opcode chunk renders as its OP_xxx name.
    #[test]
    fn test_chunk_to_asm_string_opcode() {
        let chunk = ScriptChunk {
            op: OP_DUP,
            data: None,
        };
        assert_eq!(chunk.to_asm_string(), "OP_DUP");
    }
}
