//! Script templates for common transaction types.
//!
//! Provides the `UnlockingScriptTemplate` trait and a P2PKH implementation
//! for creating locking and unlocking scripts during transaction signing.
//! Ported from the Go BSV SDK (`transaction/template/p2pkh`).

pub mod p2mpkh;
pub mod p2pkh;

use crate::transaction::Transaction;
use crate::TransactionError;
use bsv_script::Script;

/// Trait for script templates that produce unlocking scripts.
///
/// Any signing strategy (P2PKH, P2SH, custom scripts) should implement this
/// trait.  The `sign` method receives the full transaction and the input index,
/// computes the appropriate signature hash, signs it, and returns the
/// unlocking script.
pub trait UnlockingScriptTemplate {
    /// Produce an unlocking script for the given input.
    ///
    /// # Arguments
    /// * `tx` - The transaction being signed.
    /// * `input_index` - The index of the input to sign.
    ///
    /// # Returns
    /// `Ok(Script)` containing the unlocking script, or an error on failure.
    fn sign(&self, tx: &Transaction, input_index: u32) -> Result<Script, TransactionError>;

    /// Estimate the byte length of the unlocking script.
    ///
    /// Used for fee calculation before the actual signature is computed.
    ///
    /// # Arguments
    /// * `tx` - The transaction being signed.
    /// * `input_index` - The index of the input.
    ///
    /// # Returns
    /// The estimated byte length of the unlocking script.
    fn estimate_length(&self, tx: &Transaction, input_index: u32) -> u32;
}
