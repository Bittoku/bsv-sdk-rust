//! Transaction output with satoshi value and locking script.
//!
//! Defines the spending conditions for the output's value.  Provides
//! binary serialization/deserialization following the Bitcoin wire format.

use bsv_primitives::util::{BsvReader, BsvWriter, VarInt};
use bsv_script::Script;

use crate::TransactionError;

/// Maximum satoshi value: 21 million BSV = 2.1 × 10^15 satoshis.
const MAX_SATOSHIS: u64 = 21_000_000 * 100_000_000;

/// A single output in a BSV transaction.
///
/// Each output specifies a satoshi `value` and a `locking_script`
/// (scriptPubKey) that defines the conditions under which the funds
/// may be spent.  The `change` flag is a local-only annotation used
/// during fee calculation to identify outputs that should receive any
/// leftover satoshis; it is not serialized.
///
/// # Wire format
///
/// | Field            | Size           |
/// |------------------|----------------|
/// | satoshis         | 8 bytes (LE)   |
/// | script length    | VarInt         |
/// | locking_script   | variable       |
#[derive(Clone, Debug)]
pub struct TransactionOutput {
    /// The number of satoshis (1 satoshi = 10^-8 BSV) locked by this output.
    pub satoshis: u64,

    /// The locking script (scriptPubKey) that defines spending conditions.
    pub locking_script: Script,

    /// Local-only flag marking this output as a change output.
    /// Used by fee calculation; not serialized on the wire.
    pub change: bool,
}

impl TransactionOutput {
    /// Create a new `TransactionOutput` with zero satoshis and an empty script.
    ///
    /// # Returns
    /// A default `TransactionOutput`.
    pub fn new() -> Self {
        TransactionOutput {
            satoshis: 0,
            locking_script: Script::new(),
            change: false,
        }
    }

    /// Deserialize a `TransactionOutput` from a `BsvReader`.
    ///
    /// Reads 8-byte LE satoshis, a varint script length, and the script bytes.
    ///
    /// # Arguments
    /// * `reader` - The reader positioned at the start of an encoded output.
    ///
    /// # Returns
    /// `Ok(TransactionOutput)` on success, or a `TransactionError` if the
    /// data is truncated or malformed.
    pub fn read_from(reader: &mut BsvReader) -> Result<Self, TransactionError> {
        let satoshis = reader.read_u64_le().map_err(|e| {
            TransactionError::SerializationError(format!("reading satoshis: {}", e))
        })?;

        let script_len = reader.read_varint().map_err(|e| {
            TransactionError::SerializationError(format!("reading script length: {}", e))
        })?;

        let script_bytes = reader
            .read_bytes(script_len.value() as usize)
            .map_err(|e| {
                TransactionError::SerializationError(format!("reading locking script: {}", e))
            })?;

        if satoshis > MAX_SATOSHIS {
            return Err(TransactionError::SerializationError(format!(
                "satoshi value {} exceeds maximum supply ({})",
                satoshis, MAX_SATOSHIS
            )));
        }

        Ok(TransactionOutput {
            satoshis,
            locking_script: Script::from_bytes(script_bytes),
            change: false,
        })
    }

    /// Serialize this `TransactionOutput` into a `BsvWriter`.
    ///
    /// Writes 8-byte LE satoshis, a varint script length, and the script.
    ///
    /// # Arguments
    /// * `writer` - The writer to append serialized bytes to.
    pub fn write_to(&self, writer: &mut BsvWriter) {
        writer.write_u64_le(self.satoshis);
        let script_bytes = self.locking_script.to_bytes();
        writer.write_varint(VarInt::from(script_bytes.len()));
        writer.write_bytes(script_bytes);
    }

    /// Serialize this output to a byte vector.
    ///
    /// # Returns
    /// A `Vec<u8>` containing the wire-format bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = BsvWriter::new();
        self.write_to(&mut writer);
        writer.into_bytes()
    }

    /// Serialize this output for use in signature hash computation.
    ///
    /// The format is identical to `to_bytes`: satoshis(8) + varint(script_len) + script.
    ///
    /// # Returns
    /// A `Vec<u8>` containing the serialized output suitable for sighash.
    pub fn bytes_for_sig_hash(&self) -> Vec<u8> {
        self.to_bytes()
    }

    /// Return the locking script as a hex-encoded string.
    ///
    /// # Returns
    /// A lowercase hex string of the locking script bytes.
    pub fn locking_script_hex(&self) -> String {
        self.locking_script.to_hex()
    }
}

impl Default for TransactionOutput {
    fn default() -> Self {
        Self::new()
    }
}
