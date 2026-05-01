//! Core transaction type for the BSV blockchain.
//!
//! Represents a complete transaction with version, inputs, outputs, and locktime.
//! Supports binary and hex serialization, transaction ID computation, coinbase
//! detection, and various builder-pattern methods for adding inputs and outputs.
//! Ported from the Go BSV SDK (`transaction` package).

use bsv_primitives::chainhash::Hash;
use bsv_primitives::hash::sha256d;
use bsv_primitives::util::{BsvReader, BsvWriter, VarInt};

use crate::input::{TransactionInput, DEFAULT_SEQUENCE_NUMBER};
use crate::output::TransactionOutput;
use crate::sighash;
use crate::TransactionError;

/// A BSV transaction consisting of a version, a set of inputs, a set of
/// outputs, and a lock time.
///
/// # Wire format
///
/// | Field        | Size                      |
/// |--------------|---------------------------|
/// | version      | 4 bytes (LE)              |
/// | input count  | VarInt                    |
/// | inputs       | variable (per input)      |
/// | output count | VarInt                    |
/// | outputs      | variable (per output)     |
/// | lock_time    | 4 bytes (LE)              |
#[derive(Clone, Debug)]
pub struct Transaction {
    /// Transaction format version. Currently 1 or 2.
    pub version: u32,

    /// Ordered list of transaction inputs.
    pub inputs: Vec<TransactionInput>,

    /// Ordered list of transaction outputs.
    pub outputs: Vec<TransactionOutput>,

    /// Lock time. If non-zero, the transaction is not valid until the
    /// specified block height or Unix timestamp.
    pub lock_time: u32,
}

impl Transaction {
    /// Create a new empty transaction with version 1 and lock time 0.
    ///
    /// # Returns
    /// A `Transaction` with no inputs or outputs.
    pub fn new() -> Self {
        Transaction {
            version: 1,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
        }
    }

    // -----------------------------------------------------------------
    // Deserialization
    // -----------------------------------------------------------------

    /// Parse a transaction from a hex-encoded string.
    ///
    /// # Arguments
    /// * `hex_str` - A hex string of the raw transaction bytes.
    ///
    /// # Returns
    /// `Ok(Transaction)` on success, or a `TransactionError` if the hex is
    /// invalid or the bytes do not form a valid transaction.
    pub fn from_hex(hex_str: &str) -> Result<Self, TransactionError> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| TransactionError::SerializationError(format!("invalid hex: {}", e)))?;
        Self::from_bytes(&bytes)
    }

    /// Parse a transaction from raw bytes.
    ///
    /// This method requires the byte slice to contain exactly one complete
    /// transaction with no trailing data.
    ///
    /// # Arguments
    /// * `bytes` - The raw transaction bytes.
    ///
    /// # Returns
    /// `Ok(Transaction)` on success, or a `TransactionError` if the data
    /// is truncated, malformed, or has trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TransactionError> {
        let mut reader = BsvReader::new(bytes);
        let tx = Self::read_from(&mut reader)?;
        if reader.remaining() != 0 {
            return Err(TransactionError::SerializationError(format!(
                "trailing {} bytes after transaction",
                reader.remaining()
            )));
        }
        Ok(tx)
    }

    /// Deserialize a transaction from a `BsvReader`.
    ///
    /// Reads the version, input count, inputs, output count, outputs, and
    /// lock time in standard Bitcoin wire format.
    ///
    /// # Arguments
    /// * `reader` - The reader positioned at the start of a serialized transaction.
    ///
    /// # Returns
    /// `Ok(Transaction)` on success, or a `TransactionError` on I/O or
    /// format errors.
    pub fn read_from(reader: &mut BsvReader) -> Result<Self, TransactionError> {
        let version = reader
            .read_u32_le()
            .map_err(|e| TransactionError::SerializationError(format!("reading version: {}", e)))?;

        let input_count = reader.read_varint().map_err(|e| {
            TransactionError::SerializationError(format!("reading input count: {}", e))
        })?;

        let mut inputs = Vec::with_capacity(input_count.value() as usize);
        for _ in 0..input_count.value() {
            inputs.push(TransactionInput::read_from(reader)?);
        }

        let output_count = reader.read_varint().map_err(|e| {
            TransactionError::SerializationError(format!("reading output count: {}", e))
        })?;

        let mut outputs = Vec::with_capacity(output_count.value() as usize);
        for _ in 0..output_count.value() {
            outputs.push(TransactionOutput::read_from(reader)?);
        }

        let lock_time = reader.read_u32_le().map_err(|e| {
            TransactionError::SerializationError(format!("reading lock time: {}", e))
        })?;

        Ok(Transaction {
            version,
            inputs,
            outputs,
            lock_time,
        })
    }

    // -----------------------------------------------------------------
    // Serialization
    // -----------------------------------------------------------------

    /// Serialize this transaction to raw bytes.
    ///
    /// # Returns
    /// A `Vec<u8>` containing the standard wire-format bytes:
    /// version(4) + varint(n_in) + inputs + varint(n_out) + outputs + locktime(4).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = BsvWriter::with_capacity(256);
        writer.write_u32_le(self.version);

        writer.write_varint(VarInt::from(self.inputs.len()));
        for input in &self.inputs {
            input.write_to(&mut writer);
        }

        writer.write_varint(VarInt::from(self.outputs.len()));
        for output in &self.outputs {
            output.write_to(&mut writer);
        }

        writer.write_u32_le(self.lock_time);
        writer.into_bytes()
    }

    /// Serialize this transaction to a hex string.
    ///
    /// # Returns
    /// A lowercase hex-encoded string of the raw bytes.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    // -----------------------------------------------------------------
    // Transaction ID
    // -----------------------------------------------------------------

    /// Compute the transaction ID (double SHA-256 of serialized bytes).
    ///
    /// The txid bytes are in internal (little-endian) order. To get the
    /// conventional display string, use `tx_id_hex()`.
    ///
    /// # Returns
    /// A 32-byte array containing the txid in internal byte order.
    pub fn tx_id(&self) -> [u8; 32] {
        sha256d(&self.to_bytes())
    }

    /// Compute the transaction ID as a human-readable hex string.
    ///
    /// The hex string is byte-reversed from the internal hash, following
    /// Bitcoin's convention where txids are displayed in big-endian order.
    ///
    /// # Returns
    /// A 64-character hex string of the txid.
    pub fn tx_id_hex(&self) -> String {
        let mut id = self.tx_id();
        id.reverse();
        hex::encode(id)
    }

    // -----------------------------------------------------------------
    // Inputs
    // -----------------------------------------------------------------

    /// Append a `TransactionInput` to this transaction.
    ///
    /// # Arguments
    /// * `input` - The input to add.
    pub fn add_input(&mut self, input: TransactionInput) {
        self.inputs.push(input);
    }

    /// Return the number of inputs in the transaction.
    ///
    /// # Returns
    /// The input count.
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }

    // -----------------------------------------------------------------
    // Outputs
    // -----------------------------------------------------------------

    /// Append a `TransactionOutput` to this transaction.
    ///
    /// # Arguments
    /// * `output` - The output to add.
    pub fn add_output(&mut self, output: TransactionOutput) {
        self.outputs.push(output);
    }

    /// Return the number of outputs in the transaction.
    ///
    /// # Returns
    /// The output count.
    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }

    /// Compute the sum of all output satoshi values.
    ///
    /// # Returns
    /// The total satoshis across all outputs.
    pub fn total_output_satoshis(&self) -> u64 {
        self.outputs.iter().map(|o| o.satoshis).sum()
    }

    /// Compute the sum of all input satoshi values from their source outputs.
    ///
    /// Returns an error if any input does not have its source transaction set.
    ///
    /// # Returns
    /// `Ok(total)` with the sum of input satoshis, or an error if a source
    /// transaction is missing.
    pub fn total_input_satoshis(&self) -> Result<u64, TransactionError> {
        let mut total = 0u64;
        for input in &self.inputs {
            let sats = input.source_tx_satoshis().ok_or_else(|| {
                TransactionError::InvalidTransaction(
                    "missing source transaction on input".to_string(),
                )
            })?;
            total += sats;
        }
        Ok(total)
    }

    // -----------------------------------------------------------------
    // Coinbase detection
    // -----------------------------------------------------------------

    /// Determine whether this transaction is a coinbase transaction.
    ///
    /// A coinbase transaction has exactly one input with an all-zero txid
    /// and either `source_tx_out_index == 0xFFFFFFFF` or
    /// `sequence_number == 0xFFFFFFFF`.
    ///
    /// # Returns
    /// `true` if this is a coinbase transaction.
    pub fn is_coinbase(&self) -> bool {
        if self.inputs.len() != 1 {
            return false;
        }

        let input = &self.inputs[0];

        // Check that the source txid is all zeros.
        if input.source_txid != [0u8; 32] {
            return false;
        }

        // Either the output index or the sequence must be 0xFFFFFFFF.
        input.source_tx_out_index == 0xFFFF_FFFF || input.sequence_number == 0xFFFF_FFFF
    }

    /// Return the size of this transaction in bytes.
    ///
    /// # Returns
    /// The byte length of the serialized transaction.
    pub fn size(&self) -> usize {
        self.to_bytes().len()
    }

    // -----------------------------------------------------------------
    // Input helpers
    // -----------------------------------------------------------------

    /// Add an input from UTXO information.
    ///
    /// Creates a new input referencing the given previous transaction
    /// output and stores the locking script and satoshi value for
    /// sighash computation during signing.
    ///
    /// Matches the Go SDK's `Transaction.AddInputFrom(prevTxID, vout,
    /// prevTxLockingScript, satoshis, ...)`.
    ///
    /// # Arguments
    /// * `prev_tx_id` - The hex txid of the previous transaction (display order).
    /// * `vout` - The output index being spent.
    /// * `prev_locking_script_hex` - Hex-encoded locking script of the previous output.
    /// * `satoshis` - The satoshi value of the previous output.
    ///
    /// # Returns
    /// `Ok(())` on success, or a `TransactionError` if any hex is invalid.
    pub fn add_input_from(
        &mut self,
        prev_tx_id: &str,
        vout: u32,
        prev_locking_script_hex: &str,
        satoshis: u64,
    ) -> Result<(), TransactionError> {
        let hash = Hash::from_hex(prev_tx_id)?;

        let locking_script = if prev_locking_script_hex.is_empty() {
            bsv_script::Script::new()
        } else {
            bsv_script::Script::from_hex(prev_locking_script_hex)?
        };

        let mut input = TransactionInput::new();
        input.source_txid = *hash.as_bytes();
        input.source_tx_out_index = vout;
        input.sequence_number = DEFAULT_SEQUENCE_NUMBER;
        input.set_source_output(Some(TransactionOutput {
            satoshis,
            locking_script,
            change: false,
        }));

        self.inputs.push(input);
        Ok(())
    }

    // -----------------------------------------------------------------
    // Signature hash
    // -----------------------------------------------------------------

    /// Compute the BIP-143-style signature hash for a given input.
    ///
    /// Looks up the source output's locking script and satoshi value
    /// from the input's stored source info, then delegates to
    /// `sighash::signature_hash`.
    ///
    /// Matches the Go SDK's `Transaction.CalcInputSignatureHash(inputNumber, sigHashFlag)`.
    ///
    /// # Arguments
    /// * `input_index` - Index of the input being signed.
    /// * `sighash_flag` - The combined sighash flags (e.g. `SIGHASH_ALL_FORKID`).
    ///
    /// # Returns
    /// A 32-byte double-SHA256 hash to be signed by ECDSA.
    pub fn calc_input_signature_hash(
        &self,
        input_index: usize,
        sighash_flag: u32,
    ) -> Result<[u8; 32], TransactionError> {
        if input_index >= self.inputs.len() {
            return Err(TransactionError::InvalidTransaction(format!(
                "input index {} out of range (tx has {} inputs)",
                input_index,
                self.inputs.len()
            )));
        }

        let input = &self.inputs[input_index];
        let source_output = input.source_tx_output().ok_or_else(|| {
            TransactionError::SigningError(
                "missing source output on input (no previous tx info)".to_string(),
            )
        })?;

        let script_bytes = source_output.locking_script.to_bytes();
        let satoshis = source_output.satoshis;

        sighash::signature_hash(self, input_index, script_bytes, sighash_flag, satoshis)
    }
}

impl Default for Transaction {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for Transaction {
    /// Display the transaction as its hex-encoded serialization.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}
