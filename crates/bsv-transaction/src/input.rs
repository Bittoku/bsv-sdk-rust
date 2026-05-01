//! Transaction input referencing a previous output.
//!
//! Contains the source transaction ID, output index, unlocking script,
//! sequence number, and an optional back-reference to the full source
//! transaction or a direct source output.  Provides binary
//! serialization/deserialization following the Bitcoin wire format.

use bsv_primitives::util::{BsvReader, BsvWriter, VarInt};
use bsv_script::Script;

use crate::output::TransactionOutput;
use crate::TransactionError;

/// Default sequence number indicating a finalized input (no relative lock-time).
pub const DEFAULT_SEQUENCE_NUMBER: u32 = 0xFFFF_FFFF;

/// A single input in a BSV transaction.
///
/// Each input references an output from a previous transaction by its
/// transaction ID (`source_txid`) and output index (`source_tx_out_index`).
/// The `unlocking_script` (scriptSig) supplies the data required to satisfy
/// the referenced output's locking script.
///
/// Source output information can be provided either via `source_transaction`
/// (full previous tx) or `set_source_output` (just the relevant output).
/// The direct source output takes priority when both are present.
///
/// # Wire format (standard)
///
/// | Field              | Size             |
/// |--------------------|------------------|
/// | source_txid        | 32 bytes (LE)    |
/// | source_tx_out_index| 4 bytes (LE)     |
/// | script length      | VarInt           |
/// | unlocking_script   | variable         |
/// | sequence_number    | 4 bytes (LE)     |
#[derive(Clone, Debug)]
pub struct TransactionInput {
    /// The 32-byte transaction ID of the output being spent, in internal
    /// (little-endian) byte order.
    pub source_txid: [u8; 32],

    /// Index of the output within the source transaction.
    pub source_tx_out_index: u32,

    /// Sequence number. Defaults to `0xFFFFFFFF` (finalized).
    pub sequence_number: u32,

    /// The unlocking script (scriptSig) that proves authorization.
    /// `None` when the input has not yet been signed.
    pub unlocking_script: Option<Script>,

    /// Optional reference to the full source transaction.
    /// Used during signing to look up the previous output's locking script
    /// and satoshi value.
    pub source_transaction: Option<Box<crate::transaction::Transaction>>,

    /// Optional direct reference to the source output being spent.
    /// This is an alternative to `source_transaction` when only the
    /// specific output information (satoshis and locking script) is known.
    /// Takes priority over `source_transaction` when both are set.
    source_output: Option<TransactionOutput>,
}

impl TransactionInput {
    /// Create a new `TransactionInput` with default values.
    ///
    /// The source txid is zeroed, output index is 0, sequence is finalized,
    /// and no unlocking script or source transaction is set.
    ///
    /// # Returns
    /// A default `TransactionInput`.
    pub fn new() -> Self {
        TransactionInput {
            source_txid: [0u8; 32],
            source_tx_out_index: 0,
            sequence_number: DEFAULT_SEQUENCE_NUMBER,
            unlocking_script: None,
            source_transaction: None,
            source_output: None,
        }
    }

    /// Deserialize a `TransactionInput` from a `BsvReader`.
    ///
    /// Reads the standard wire format: 32-byte txid, 4-byte output index,
    /// varint-prefixed unlocking script, and 4-byte sequence number.
    ///
    /// # Arguments
    /// * `reader` - The reader positioned at the start of an encoded input.
    ///
    /// # Returns
    /// `Ok(TransactionInput)` on success, or a `TransactionError` if the
    /// data is truncated or malformed.
    pub fn read_from(reader: &mut BsvReader) -> Result<Self, TransactionError> {
        let txid_bytes = reader.read_bytes(32).map_err(|e| {
            TransactionError::SerializationError(format!("reading source txid: {}", e))
        })?;
        let mut source_txid = [0u8; 32];
        source_txid.copy_from_slice(txid_bytes);

        let source_tx_out_index = reader.read_u32_le().map_err(|e| {
            TransactionError::SerializationError(format!("reading output index: {}", e))
        })?;

        let script_len = reader.read_varint().map_err(|e| {
            TransactionError::SerializationError(format!("reading script length: {}", e))
        })?;

        let script_bytes = reader
            .read_bytes(script_len.value() as usize)
            .map_err(|e| {
                TransactionError::SerializationError(format!("reading unlocking script: {}", e))
            })?;

        let sequence_number = reader.read_u32_le().map_err(|e| {
            TransactionError::SerializationError(format!("reading sequence number: {}", e))
        })?;

        let unlocking_script = if script_bytes.is_empty() {
            None
        } else {
            Some(Script::from_bytes(script_bytes))
        };

        Ok(TransactionInput {
            source_txid,
            source_tx_out_index,
            sequence_number,
            unlocking_script,
            source_transaction: None,
            source_output: None,
        })
    }

    /// Serialize this `TransactionInput` into a `BsvWriter`.
    ///
    /// Writes the standard wire format: txid, output index, varint script
    /// length, script bytes, and sequence number.
    ///
    /// # Arguments
    /// * `writer` - The writer to append serialized bytes to.
    pub fn write_to(&self, writer: &mut BsvWriter) {
        writer.write_bytes(&self.source_txid);
        writer.write_u32_le(self.source_tx_out_index);

        match &self.unlocking_script {
            Some(script) => {
                let script_bytes = script.to_bytes();
                writer.write_varint(VarInt::from(script_bytes.len()));
                writer.write_bytes(script_bytes);
            }
            None => {
                writer.write_varint(VarInt::from(0u64));
            }
        }

        writer.write_u32_le(self.sequence_number);
    }

    /// Serialize this input to a byte vector.
    ///
    /// If `clear` is true, the unlocking script is omitted (written as
    /// zero-length). This is used when constructing signature preimages.
    ///
    /// # Arguments
    /// * `clear` - If `true`, omit the unlocking script from the output.
    ///
    /// # Returns
    /// A `Vec<u8>` containing the serialized input.
    pub fn to_bytes_cleared(&self, clear: bool) -> Vec<u8> {
        let mut writer = BsvWriter::new();
        writer.write_bytes(&self.source_txid);
        writer.write_u32_le(self.source_tx_out_index);

        if clear {
            writer.write_varint(VarInt::from(0u64));
        } else if let Some(script) = self.unlocking_script.as_ref() {
            let script_bytes = script.to_bytes();
            writer.write_varint(VarInt::from(script_bytes.len()));
            writer.write_bytes(script_bytes);
        } else {
            writer.write_varint(VarInt::from(0u64));
        }

        writer.write_u32_le(self.sequence_number);
        writer.into_bytes()
    }

    /// Set a direct source output on this input.
    ///
    /// This provides the satoshi value and locking script of the output
    /// being spent, without needing the full source transaction.
    /// Takes priority over `source_transaction` for lookups.
    ///
    /// # Arguments
    /// * `output` - The source output, or `None` to clear.
    pub fn set_source_output(&mut self, output: Option<TransactionOutput>) {
        self.source_output = output;
    }

    /// Look up the source transaction output, if available.
    ///
    /// First checks the direct `source_output` field, then falls back
    /// to looking up the output by index in `source_transaction`.
    ///
    /// # Returns
    /// `Some(&TransactionOutput)` if source info is available, otherwise `None`.
    pub fn source_tx_output(&self) -> Option<&TransactionOutput> {
        if let Some(ref output) = self.source_output {
            return Some(output);
        }
        if let Some(ref source_tx) = self.source_transaction {
            source_tx.outputs.get(self.source_tx_out_index as usize)
        } else {
            None
        }
    }

    /// Return the satoshi value of the source output, if available.
    ///
    /// # Returns
    /// `Some(satoshis)` if the source output info is available,
    /// otherwise `None`.
    pub fn source_tx_satoshis(&self) -> Option<u64> {
        self.source_tx_output().map(|o| o.satoshis)
    }

    /// Return the locking script of the source output, if available.
    ///
    /// # Returns
    /// `Some(&Script)` if the source output info is available,
    /// otherwise `None`.
    pub fn source_tx_script(&self) -> Option<&Script> {
        self.source_tx_output().map(|o| &o.locking_script)
    }
}

impl Default for TransactionInput {
    fn default() -> Self {
        Self::new()
    }
}
