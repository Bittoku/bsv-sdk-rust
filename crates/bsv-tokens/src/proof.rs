//! Prev-TX split utility for Back-to-Genesis (BTG) proof system.
//!
//! Provides [`split_tx_around_output`], which splits a raw serialized transaction
//! into three byte segments around a specified output index. The spender pushes
//! these three segments in the unlocking script so that the BTG locking script
//! can reconstruct the previous transaction, verify its hash against the outpoint
//! txid, and inspect the output's locking script for legitimacy.

use bsv_primitives::hash::sha256d;

use crate::error::TokenError;

/// Split a raw serialized transaction into three byte segments around the output
/// at index `vout`.
///
/// Returns `(prefix, output_bytes, suffix)` where:
///   `hash256(prefix || output_bytes || suffix) == txid`
///
/// The `output_bytes` segment contains the serialized output at `vout` in wire
/// format: `satoshis(8 LE) + varint(script_len) + script_bytes`.
///
/// # Arguments
/// * `raw_tx` - The complete raw transaction bytes (wire format).
/// * `vout` - The output index to split around.
///
/// # Errors
/// Returns [`TokenError::InvalidScript`] if the raw bytes are malformed or
/// `vout` is out of range.
pub fn split_tx_around_output(
    raw_tx: &[u8],
    vout: u32,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), TokenError> {
    let vout_idx = vout as usize;
    let tx_len = raw_tx.len();

    if tx_len < 10 {
        return Err(TokenError::InvalidScript("raw TX too short".into()));
    }

    // Skip version (4 bytes)
    let mut cursor = 4usize;

    // Read varint for input count
    let (input_count, bytes_read) = read_varint(raw_tx, cursor)?;
    cursor += bytes_read;

    // Skip all inputs
    for _ in 0..input_count {
        // prev_txid (32) + prev_vout (4)
        if cursor + 36 > tx_len {
            return Err(TokenError::InvalidScript("truncated input".into()));
        }
        cursor += 36;

        // script_len varint + script + sequence (4)
        let (script_len, varint_bytes) = read_varint(raw_tx, cursor)?;
        cursor += varint_bytes;
        let script_len_usize = script_len as usize;
        if cursor + script_len_usize + 4 > tx_len {
            return Err(TokenError::InvalidScript("truncated input script".into()));
        }
        cursor += script_len_usize + 4; // script + sequence
    }

    // Read varint for output count
    let (output_count, varint_bytes) = read_varint(raw_tx, cursor)?;
    cursor += varint_bytes;

    if vout_idx >= output_count as usize {
        return Err(TokenError::InvalidScript(format!(
            "vout {} out of range (tx has {} outputs)",
            vout_idx, output_count
        )));
    }

    // Walk outputs to find byte boundaries of output[vout]
    let mut output_start = 0usize;
    let mut output_end = 0usize;

    for output_idx in 0..output_count as usize {
        let this_output_start = cursor;

        // satoshis (8 bytes)
        if cursor + 8 > tx_len {
            return Err(TokenError::InvalidScript(
                "truncated output satoshis".into(),
            ));
        }
        cursor += 8;

        // script_len varint + script
        let (script_len, varint_bytes) = read_varint(raw_tx, cursor)?;
        cursor += varint_bytes;
        let script_len_usize = script_len as usize;
        if cursor + script_len_usize > tx_len {
            return Err(TokenError::InvalidScript("truncated output script".into()));
        }
        cursor += script_len_usize;

        if output_idx == vout_idx {
            output_start = this_output_start;
            output_end = cursor;
        }
    }

    // Sanity: the remaining bytes should be the 4-byte locktime
    // (We don't enforce this strictly — just split at the boundaries we found.)

    let prefix = raw_tx[..output_start].to_vec();
    let output_bytes = raw_tx[output_start..output_end].to_vec();
    let suffix = raw_tx[output_end..].to_vec();

    // Sanity check: hash256(prefix || output || suffix) == hash256(raw_tx)
    let mut reconstructed = Vec::with_capacity(tx_len);
    reconstructed.extend_from_slice(&prefix);
    reconstructed.extend_from_slice(&output_bytes);
    reconstructed.extend_from_slice(&suffix);

    let original_hash = sha256d(raw_tx);
    let reconstructed_hash = sha256d(&reconstructed);
    if original_hash != reconstructed_hash {
        return Err(TokenError::InvalidScript(
            "internal error: reconstructed TX hash mismatch".into(),
        ));
    }

    Ok((prefix, output_bytes, suffix))
}

/// Read a Bitcoin varint from `data` at the given `offset`.
///
/// # Returns
/// `(value, bytes_consumed)` on success.
///
/// # Errors
/// Returns [`TokenError::InvalidScript`] if the data is truncated.
fn read_varint(data: &[u8], offset: usize) -> Result<(u64, usize), TokenError> {
    if offset >= data.len() {
        return Err(TokenError::InvalidScript("truncated varint".into()));
    }

    let first_byte = data[offset];
    match first_byte {
        0..=0xfc => Ok((first_byte as u64, 1)),
        0xfd => {
            if offset + 3 > data.len() {
                return Err(TokenError::InvalidScript("truncated varint (fd)".into()));
            }
            let value = u16::from_le_bytes([data[offset + 1], data[offset + 2]]) as u64;
            Ok((value, 3))
        }
        0xfe => {
            if offset + 5 > data.len() {
                return Err(TokenError::InvalidScript("truncated varint (fe)".into()));
            }
            let value = u32::from_le_bytes([
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
            ]) as u64;
            Ok((value, 5))
        }
        0xff => {
            if offset + 9 > data.len() {
                return Err(TokenError::InvalidScript("truncated varint (ff)".into()));
            }
            let value = u64::from_le_bytes([
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
                data[offset + 8],
            ]);
            Ok((value, 9))
        }
    }
}

/// Encode a `u64` value as a Bitcoin varint byte sequence.
///
/// # Arguments
/// * `value` - The integer value to encode.
///
/// # Returns
/// A `Vec<u8>` containing the varint-encoded bytes (1, 3, 5, or 9 bytes).
pub fn encode_varint(value: u64) -> Vec<u8> {
    if value < 0xfd {
        vec![value as u8]
    } else if value <= 0xffff {
        let mut buf = vec![0xfd];
        buf.extend_from_slice(&(value as u16).to_le_bytes());
        buf
    } else if value <= 0xffff_ffff {
        let mut buf = vec![0xfe];
        buf.extend_from_slice(&(value as u32).to_le_bytes());
        buf
    } else {
        let mut buf = vec![0xff];
        buf.extend_from_slice(&value.to_le_bytes());
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_transaction::transaction::Transaction;

    /// Build a simple test transaction with known structure and return its raw bytes.
    fn build_test_tx() -> (Transaction, Vec<u8>) {
        use bsv_primitives::ec::PrivateKey;
        use bsv_script::Script;
        use bsv_transaction::input::TransactionInput;
        use bsv_transaction::output::TransactionOutput;

        let mut tx = Transaction::new();

        // Add a dummy input
        let mut input = TransactionInput::new();
        input.source_txid = [0xaa; 32];
        input.source_tx_out_index = 0;
        input.unlocking_script = Some(Script::new());
        input.sequence_number = 0xffffffff;
        tx.add_input(input);

        // Add two outputs
        let key = PrivateKey::new();
        let pubkey = key.pub_key().to_compressed();
        let pkh = bsv_primitives::hash::hash160(&pubkey);
        let addr = bsv_script::Address::from_public_key_hash(&pkh, bsv_script::Network::Mainnet);

        let locking_script = bsv_transaction::template::p2pkh::lock(&addr).unwrap();

        tx.add_output(TransactionOutput {
            satoshis: 5000,
            locking_script: locking_script.clone(),
            change: false,
        });
        tx.add_output(TransactionOutput {
            satoshis: 3000,
            locking_script,
            change: false,
        });

        let raw = tx.to_bytes();
        (tx, raw)
    }

    #[test]
    fn split_and_reconstruct_vout_0() {
        let (_tx, raw) = build_test_tx();
        let (prefix, output, suffix) = split_tx_around_output(&raw, 0).unwrap();

        // Verify reconstruction hashes to the same txid
        let mut reconstructed = Vec::new();
        reconstructed.extend_from_slice(&prefix);
        reconstructed.extend_from_slice(&output);
        reconstructed.extend_from_slice(&suffix);

        assert_eq!(sha256d(&reconstructed), sha256d(&raw));
    }

    #[test]
    fn split_and_reconstruct_vout_1() {
        let (_tx, raw) = build_test_tx();
        let (prefix, output, suffix) = split_tx_around_output(&raw, 1).unwrap();

        let mut reconstructed = Vec::new();
        reconstructed.extend_from_slice(&prefix);
        reconstructed.extend_from_slice(&output);
        reconstructed.extend_from_slice(&suffix);

        assert_eq!(sha256d(&reconstructed), sha256d(&raw));
    }

    #[test]
    fn split_vout_out_of_range() {
        let (_tx, raw) = build_test_tx();
        let result = split_tx_around_output(&raw, 5);
        assert!(result.is_err());
    }

    #[test]
    fn split_empty_tx() {
        let result = split_tx_around_output(&[], 0);
        assert!(result.is_err());
    }

    #[test]
    fn output_bytes_contain_correct_satoshis() {
        let (_tx, raw) = build_test_tx();

        // Check vout 0: should have 5000 satoshis (0x1388 LE)
        let (_prefix, output, _suffix) = split_tx_around_output(&raw, 0).unwrap();
        let satoshis = u64::from_le_bytes(output[..8].try_into().unwrap());
        assert_eq!(satoshis, 5000);

        // Check vout 1: should have 3000 satoshis (0x0BB8 LE)
        let (_prefix, output, _suffix) = split_tx_around_output(&raw, 1).unwrap();
        let satoshis = u64::from_le_bytes(output[..8].try_into().unwrap());
        assert_eq!(satoshis, 3000);
    }

    #[test]
    fn varint_roundtrip() {
        for &val in &[
            0u64,
            1,
            0xfc,
            0xfd,
            0xfffe,
            0xffff,
            0x1_0000,
            0xffff_ffff,
            0x1_0000_0000,
        ] {
            let encoded = encode_varint(val);
            let (decoded, len) = read_varint(&encoded, 0).unwrap();
            assert_eq!(decoded, val, "failed for value {val}");
            assert_eq!(len, encoded.len(), "length mismatch for value {val}");
        }
    }
}
