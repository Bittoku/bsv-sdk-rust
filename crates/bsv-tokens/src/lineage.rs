//! Off-chain lineage validator for STAS tokens.
//!
//! Provides [`LineageValidator`] which walks the ancestor chain of a token
//! UTXO back to the genesis (contract) transaction, verifying that every hop
//! is a legitimate STAS token transfer or issuance.
//!
//! This is the "belt-and-suspenders" complement to the on-chain BTG proof
//! system. It can also validate legacy (non-BTG) STAS tokens that lack
//! on-chain prev-TX verification.
//!
//! # Usage
//!
//! ```ignore
//! use bsv_tokens::lineage::{LineageValidator, TxFetcher};
//!
//! let mut validator = LineageValidator::new(contract_txid, redemption_pkh);
//! validator.validate(&utxo_txid, vout, &my_fetcher)?;
//! ```

use std::collections::HashSet;

use bsv_primitives::hash::sha256d;
use bsv_transaction::transaction::Transaction;

use crate::error::TokenError;
use crate::script::reader::read_locking_script;
use crate::ScriptType;

/// Trait for fetching raw transactions by txid.
///
/// Implementors provide access to a transaction source — whether a local
/// cache, a BSV node RPC, a JungleBus/WhatsOnChain API, or an overlay
/// network.
pub trait TxFetcher {
    /// Fetch the raw serialized bytes of the transaction with the given txid.
    ///
    /// The `txid` is in internal byte order (the double-SHA256 hash of the
    /// raw transaction, NOT reversed).
    ///
    /// # Errors
    /// Returns [`TokenError`] if the transaction cannot be found or fetched.
    fn fetch_raw_tx(&self, txid: &[u8; 32]) -> Result<Vec<u8>, TokenError>;
}

/// Maximum ancestor chain depth to prevent infinite loops or excessive traversal.
const MAX_CHAIN_DEPTH: usize = 10_000;

/// Off-chain lineage validator that walks a token's ancestor chain back to
/// the genesis (contract) transaction.
///
/// Caches validated txids to avoid redundant work when validating multiple
/// UTXOs from the same token issuance.
pub struct LineageValidator {
    /// Set of txids that have already been validated as legitimate.
    validated: HashSet<[u8; 32]>,
    /// The contract (genesis) transaction ID. This is the trust anchor —
    /// when the chain reaches this txid, validation succeeds.
    contract_txid: [u8; 32],
    /// The expected 20-byte redemption public key hash that should appear
    /// in every STAS token script in the lineage.
    redemption_pkh: [u8; 20],
}

impl LineageValidator {
    /// Create a new lineage validator.
    ///
    /// # Arguments
    /// * `contract_txid` - The txid of the contract (genesis) transaction
    ///   (internal byte order, i.e., the raw sha256d hash).
    /// * `redemption_pkh` - The 20-byte redemption PKH that all tokens in
    ///   this lineage should contain.
    pub fn new(contract_txid: [u8; 32], redemption_pkh: [u8; 20]) -> Self {
        let mut validated = HashSet::new();
        // The contract TX itself is always considered valid
        validated.insert(contract_txid);

        Self {
            validated,
            contract_txid,
            redemption_pkh,
        }
    }

    /// Validate a token UTXO's lineage back to the genesis transaction.
    ///
    /// Walks the ancestor chain by fetching each previous transaction and
    /// checking that the spent output contains a valid STAS locking script
    /// (or a P2PKH script for the issuance boundary).
    ///
    /// # Arguments
    /// * `utxo_txid` - The txid of the UTXO to validate (internal byte order).
    /// * `vout` - The output index within the transaction.
    /// * `tx_fetcher` - An implementation of [`TxFetcher`] for retrieving
    ///   ancestor transactions.
    ///
    /// # Errors
    /// Returns [`TokenError`] if any hop in the lineage is invalid or if
    /// the chain exceeds `MAX_CHAIN_DEPTH`.
    pub fn validate(
        &mut self,
        utxo_txid: &[u8; 32],
        vout: u32,
        tx_fetcher: &dyn TxFetcher,
    ) -> Result<(), TokenError> {
        let mut current_txid = *utxo_txid;
        let mut current_vout = vout;
        let mut depth = 0usize;

        loop {
            // Check if already validated
            if self.validated.contains(&current_txid) {
                return Ok(());
            }

            // Depth guard
            depth += 1;
            if depth > MAX_CHAIN_DEPTH {
                return Err(TokenError::InvalidScript(format!(
                    "lineage chain exceeds maximum depth ({MAX_CHAIN_DEPTH})"
                )));
            }

            // Fetch the transaction
            let raw_tx = tx_fetcher.fetch_raw_tx(&current_txid)?;

            // Verify the hash matches
            let computed_txid = sha256d(&raw_tx);
            if computed_txid != current_txid {
                return Err(TokenError::InvalidScript(format!(
                    "fetched TX hash mismatch: expected {}, got {}",
                    hex::encode(current_txid),
                    hex::encode(computed_txid)
                )));
            }

            // Parse the transaction
            let tx = Transaction::from_bytes(&raw_tx)?;

            // Check the output at current_vout
            let output = tx.outputs.get(current_vout as usize).ok_or_else(|| {
                TokenError::InvalidScript(format!(
                    "vout {} out of range in tx {}",
                    current_vout,
                    hex::encode(current_txid)
                ))
            })?;

            let script_bytes = output.locking_script.to_bytes();
            let parsed = read_locking_script(&script_bytes);

            match parsed.script_type {
                ScriptType::Stas => {
                    // Verify the redemption PKH matches
                    let stas_fields = parsed
                        .stas
                        .ok_or_else(|| TokenError::InvalidScript("STAS fields missing".into()))?;

                    if stas_fields.redemption_hash != self.redemption_pkh {
                        return Err(TokenError::InvalidScript(format!(
                            "redemption PKH mismatch in tx {}: expected {}, got {}",
                            hex::encode(current_txid),
                            hex::encode(self.redemption_pkh),
                            hex::encode(stas_fields.redemption_hash)
                        )));
                    }

                    // Mark this TX as validated
                    self.validated.insert(current_txid);

                    // Walk backwards: the token input is at index 0
                    // (by STAS convention, token input is always input 0)
                    if tx.inputs.is_empty() {
                        return Err(TokenError::InvalidScript(
                            "transaction has no inputs".into(),
                        ));
                    }

                    let prev_input = &tx.inputs[0];
                    current_txid = prev_input.source_txid;
                    current_vout = prev_input.source_tx_out_index;
                }
                ScriptType::P2pkh => {
                    // P2PKH output — this should be the issuance boundary.
                    // The P2PKH script's PKH should match the redemption address
                    // (i.e., this is the contract TX output being spent for issuance).
                    //
                    // For the issuance boundary, we check if the parent TX is
                    // the contract TX.
                    if tx.inputs.is_empty() {
                        return Err(TokenError::InvalidScript(
                            "transaction has no inputs".into(),
                        ));
                    }

                    // The current TX should have been issued from the contract TX.
                    // Check if any input references the contract txid.
                    let references_contract = tx
                        .inputs
                        .iter()
                        .any(|input| input.source_txid == self.contract_txid);

                    if references_contract {
                        // Valid issuance — chain is anchored at contract TX
                        self.validated.insert(current_txid);
                        return Ok(());
                    }

                    // If it's P2PKH but doesn't reference the contract TX,
                    // the chain hasn't reached genesis yet. Continue walking.
                    self.validated.insert(current_txid);
                    let prev_input = &tx.inputs[0];
                    current_txid = prev_input.source_txid;
                    current_vout = prev_input.source_tx_out_index;
                }
                _ => {
                    return Err(TokenError::InvalidScript(format!(
                        "unexpected script type {:?} at vout {} in tx {}",
                        parsed.script_type,
                        current_vout,
                        hex::encode(current_txid)
                    )));
                }
            }
        }
    }

    /// Check whether a specific txid has already been validated.
    pub fn is_validated(&self, txid: &[u8; 32]) -> bool {
        self.validated.contains(txid)
    }

    /// Return the number of txids that have been validated so far.
    pub fn validated_count(&self) -> usize {
        self.validated.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Simple in-memory TxFetcher for testing.
    struct MockFetcher {
        txs: HashMap<[u8; 32], Vec<u8>>,
    }

    impl MockFetcher {
        fn new() -> Self {
            Self {
                txs: HashMap::new(),
            }
        }

        #[allow(dead_code)]
        fn add_tx(&mut self, raw_tx: Vec<u8>) -> [u8; 32] {
            let txid = sha256d(&raw_tx);
            self.txs.insert(txid, raw_tx);
            txid
        }
    }

    impl TxFetcher for MockFetcher {
        fn fetch_raw_tx(&self, txid: &[u8; 32]) -> Result<Vec<u8>, TokenError> {
            self.txs.get(txid).cloned().ok_or_else(|| {
                TokenError::InvalidScript(format!("tx not found: {}", hex::encode(txid)))
            })
        }
    }

    #[test]
    fn validator_creation() {
        let contract_txid = [0x01; 32];
        let redemption_pkh = [0xaa; 20];
        let validator = LineageValidator::new(contract_txid, redemption_pkh);

        // Contract TX should be pre-validated
        assert!(validator.is_validated(&contract_txid));
        assert_eq!(validator.validated_count(), 1);
    }

    #[test]
    fn validate_unknown_tx_fails() {
        let contract_txid = [0x01; 32];
        let redemption_pkh = [0xaa; 20];
        let mut validator = LineageValidator::new(contract_txid, redemption_pkh);

        let fetcher = MockFetcher::new();
        let unknown_txid = [0x99; 32];

        let result = validator.validate(&unknown_txid, 0, &fetcher);
        assert!(result.is_err());
    }

    #[test]
    fn contract_txid_validates_immediately() {
        let contract_txid = [0x01; 32];
        let redemption_pkh = [0xaa; 20];
        let mut validator = LineageValidator::new(contract_txid, redemption_pkh);

        let fetcher = MockFetcher::new();

        // The contract TX itself is pre-validated, so this should succeed
        let result = validator.validate(&contract_txid, 0, &fetcher);
        assert!(result.is_ok());
    }
}
