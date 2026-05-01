//! Signature hash computation for transaction signing.
//!
//! Computes the hash that is signed by ECDSA to authorize spending a
//! transaction input.  BSV uses BIP-143-style sighash with FORKID after
//! the UAHF fork for replay protection.
//!
//! See <https://github.com/bitcoin-sv/bitcoin-sv/blob/master/doc/abc/replay-protected-sighash.md#digest-algorithm>

use bsv_primitives::hash::sha256d;
use bsv_primitives::util::{BsvWriter, VarInt};

use crate::transaction::Transaction;
use crate::TransactionError;

// -----------------------------------------------------------------------
// Sighash flag constants
// -----------------------------------------------------------------------

/// Sign all inputs and all outputs (the default).
pub const SIGHASH_ALL: u32 = 0x01;

/// Sign all inputs but no outputs, allowing outputs to be modified.
pub const SIGHASH_NONE: u32 = 0x02;

/// Sign all inputs and only the output with the same index as the signed input.
pub const SIGHASH_SINGLE: u32 = 0x03;

/// Combined with another flag: only sign the current input, allowing other
/// inputs to be added later.
pub const SIGHASH_ANYONECANPAY: u32 = 0x80;

/// Replay-protection flag required on all BSV transactions after the UAHF fork.
pub const SIGHASH_FORKID: u32 = 0x40;

/// The standard BSV sighash type: ALL | FORKID.
pub const SIGHASH_ALL_FORKID: u32 = SIGHASH_ALL | SIGHASH_FORKID;

/// Mask applied to extract the base sighash type (ALL, NONE, SINGLE).
pub const SIGHASH_MASK: u32 = 0x1f;

// -----------------------------------------------------------------------
// BIP-143 (FORKID) signature hash
// -----------------------------------------------------------------------

/// Compute the BIP-143-style signature hash for a given input.
///
/// This is the hash algorithm used by BSV after the UAHF fork (when
/// `sighash_type` includes `SIGHASH_FORKID`).  It commits to the value
/// being spent and uses a different serialization order than legacy sighash.
///
/// # Arguments
/// * `tx`                  - The transaction being signed.
/// * `input_index`         - Index of the input being signed.
/// * `prev_output_script`  - The locking script (scriptCode) of the output being spent.
/// * `sighash_type`        - The combined sighash flags (e.g. `SIGHASH_ALL | SIGHASH_FORKID`).
/// * `satoshis`            - The satoshi value of the output being spent.
///
/// # Returns
/// A 32-byte double-SHA256 hash to be signed by ECDSA.
pub fn signature_hash(
    tx: &Transaction,
    input_index: usize,
    prev_output_script: &[u8],
    sighash_type: u32,
    satoshis: u64,
) -> Result<[u8; 32], TransactionError> {
    if input_index >= tx.inputs.len() {
        return Err(TransactionError::InvalidTransaction(format!(
            "input index {} out of range (tx has {} inputs)",
            input_index,
            tx.inputs.len()
        )));
    }

    let preimage = calc_preimage(tx, input_index, prev_output_script, sighash_type, satoshis)?;
    Ok(sha256d(&preimage))
}

/// Compute the pre-image bytes for BIP-143-style sighash before double-hashing.
///
/// The preimage consists of:
/// 1. nVersion (4 bytes LE)
/// 2. hashPrevouts (32 bytes) - sha256d of all outpoints unless ANYONECANPAY
/// 3. hashSequence (32 bytes) - sha256d of all sequences unless ANYONECANPAY/SINGLE/NONE
/// 4. outpoint (32+4 bytes) - txid + vout of the input being signed
/// 5. scriptCode (varint + script) - the locking script being satisfied
/// 6. value (8 bytes LE) - satoshis of the output being spent
/// 7. nSequence (4 bytes LE) - sequence of the input being signed
/// 8. hashOutputs (32 bytes) - sha256d of all outputs or one output
/// 9. nLocktime (4 bytes LE)
/// 10. sighashType (4 bytes LE)
///
/// # Arguments
/// * `tx`                  - The transaction being signed.
/// * `input_index`         - Index of the input being signed.
/// * `prev_output_script`  - The locking script of the output being spent.
/// * `sighash_type`        - The combined sighash flags.
/// * `satoshis`            - The satoshi value of the output being spent.
///
/// # Returns
/// The raw preimage bytes (not yet hashed).
pub fn calc_preimage(
    tx: &Transaction,
    input_index: usize,
    prev_output_script: &[u8],
    sighash_type: u32,
    satoshis: u64,
) -> Result<Vec<u8>, TransactionError> {
    if input_index >= tx.inputs.len() {
        return Err(TransactionError::InvalidTransaction(format!(
            "input index {} out of range (tx has {} inputs)",
            input_index,
            tx.inputs.len()
        )));
    }

    let input = &tx.inputs[input_index];
    let base_type = sighash_type & SIGHASH_MASK;

    // hashPrevouts
    let hash_prevouts = if sighash_type & SIGHASH_ANYONECANPAY == 0 {
        source_out_hash(tx)
    } else {
        [0u8; 32]
    };

    // hashSequence
    let hash_sequence = if sighash_type & SIGHASH_ANYONECANPAY == 0
        && base_type != SIGHASH_SINGLE
        && base_type != SIGHASH_NONE
    {
        sequence_hash(tx)
    } else {
        [0u8; 32]
    };

    // hashOutputs
    let hash_outputs = if base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE {
        outputs_hash(tx, -1)
    } else if base_type == SIGHASH_SINGLE && input_index < tx.outputs.len() {
        outputs_hash(tx, input_index as i32)
    } else {
        [0u8; 32]
    };

    // Build the preimage
    let mut writer = BsvWriter::with_capacity(256);

    // Version
    writer.write_u32_le(tx.version);

    // hashPrevouts
    writer.write_bytes(&hash_prevouts);

    // hashSequence
    writer.write_bytes(&hash_sequence);

    // Outpoint (txid + vout)
    writer.write_bytes(&input.source_txid);
    writer.write_u32_le(input.source_tx_out_index);

    // scriptCode
    writer.write_varint(VarInt::from(prev_output_script.len()));
    writer.write_bytes(prev_output_script);

    // Value of the output being spent
    writer.write_u64_le(satoshis);

    // nSequence
    writer.write_u32_le(input.sequence_number);

    // hashOutputs
    writer.write_bytes(&hash_outputs);

    // nLocktime
    writer.write_u32_le(tx.lock_time);

    // Sighash type
    writer.write_u32_le(sighash_type);

    Ok(writer.into_bytes())
}

// -----------------------------------------------------------------------
// Internal helper functions
// -----------------------------------------------------------------------

/// Compute the double-SHA256 of all input outpoints concatenated.
///
/// Each outpoint is txid (32 bytes) + vout (4 bytes LE).
///
/// # Arguments
/// * `tx` - The transaction whose inputs to hash.
///
/// # Returns
/// A 32-byte sha256d hash of the concatenated outpoints.
fn source_out_hash(tx: &Transaction) -> [u8; 32] {
    let mut writer = BsvWriter::with_capacity(tx.inputs.len() * 36);
    for input in &tx.inputs {
        writer.write_bytes(&input.source_txid);
        writer.write_u32_le(input.source_tx_out_index);
    }
    sha256d(writer.as_bytes())
}

/// Compute the double-SHA256 of all input sequence numbers concatenated.
///
/// Each sequence number is 4 bytes LE.
///
/// # Arguments
/// * `tx` - The transaction whose input sequences to hash.
///
/// # Returns
/// A 32-byte sha256d hash of the concatenated sequences.
fn sequence_hash(tx: &Transaction) -> [u8; 32] {
    let mut writer = BsvWriter::with_capacity(tx.inputs.len() * 4);
    for input in &tx.inputs {
        writer.write_u32_le(input.sequence_number);
    }
    sha256d(writer.as_bytes())
}

/// Compute the double-SHA256 of serialized outputs.
///
/// If `n` is -1, all outputs are included.  If `n >= 0`, only the output
/// at that index is included (used for SIGHASH_SINGLE).
///
/// # Arguments
/// * `tx` - The transaction whose outputs to hash.
/// * `n`  - Output index, or -1 for all outputs.
///
/// # Returns
/// A 32-byte sha256d hash of the serialized output(s).
fn outputs_hash(tx: &Transaction, n: i32) -> [u8; 32] {
    let mut writer = BsvWriter::new();
    if n == -1 {
        for output in &tx.outputs {
            writer.write_bytes(&output.bytes_for_sig_hash());
        }
    } else {
        writer.write_bytes(&tx.outputs[n as usize].bytes_for_sig_hash());
    }
    sha256d(writer.as_bytes())
}
