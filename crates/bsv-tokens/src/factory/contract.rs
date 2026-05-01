//! Contract transaction builder.
//!
//! Builds the initial contract transaction that establishes the token scheme
//! on-chain. The contract TX has a funding input (P2PKH), a contract output
//! (P2PKH to the issuer), and an OP_RETURN output with the scheme JSON.

use bsv_primitives::chainhash::Hash;
use bsv_primitives::ec::PrivateKey;
use bsv_script::opcodes::{OP_FALSE, OP_RETURN};
use bsv_script::Script;
use bsv_transaction::input::TransactionInput;
use bsv_transaction::output::TransactionOutput;
use bsv_transaction::template::p2pkh;
use bsv_transaction::template::UnlockingScriptTemplate;
use bsv_transaction::transaction::Transaction;

use crate::error::TokenError;
use crate::scheme::TokenScheme;

/// Configuration for building a contract transaction.
pub struct ContractConfig {
    /// The token scheme to embed in the contract.
    pub scheme: TokenScheme,
    /// Transaction ID of the funding UTXO.
    pub funding_txid: Hash,
    /// Output index of the funding UTXO.
    pub funding_vout: u32,
    /// Satoshi value of the funding UTXO.
    pub funding_satoshis: u64,
    /// Locking script of the funding UTXO.
    pub funding_locking_script: Script,
    /// Private key to sign the funding input.
    pub funding_private_key: PrivateKey,
    /// Satoshi amount for the contract output.
    pub contract_satoshis: u64,
    /// Fee rate in satoshis per kilobyte.
    pub fee_rate: u64,
}

/// Build a contract transaction.
///
/// # Transaction structure
/// - Input 0: Funding UTXO (P2PKH)
/// - Output 0: Contract output (P2PKH to issuer address)
/// - Output 1: OP_RETURN with scheme JSON
/// - Output 2: Change (if any)
pub fn build_contract_tx(config: &ContractConfig) -> Result<Transaction, TokenError> {
    let mut tx = Transaction::new();

    // Add funding input
    let mut input = TransactionInput::new();
    input.source_txid = *config.funding_txid.as_bytes();
    input.source_tx_out_index = config.funding_vout;
    input.set_source_output(Some(TransactionOutput {
        satoshis: config.funding_satoshis,
        locking_script: config.funding_locking_script.clone(),
        change: false,
    }));
    tx.add_input(input);

    // Contract output: P2PKH to the issuer (derived from funding key)
    let issuer_address = bsv_script::Address::from_public_key_hash(
        &bsv_primitives::hash::hash160(&config.funding_private_key.pub_key().to_compressed()),
        bsv_script::Network::Mainnet,
    );
    let contract_script = p2pkh::lock(&issuer_address)?;
    tx.add_output(TransactionOutput {
        satoshis: config.contract_satoshis,
        locking_script: contract_script,
        change: false,
    });

    // OP_RETURN output with scheme JSON
    let scheme_bytes = config.scheme.to_bytes()?;
    let mut op_return_script = Script::new();
    op_return_script.append_opcodes(&[OP_FALSE, OP_RETURN])?;
    op_return_script.append_push_data(&scheme_bytes)?;
    tx.add_output(TransactionOutput {
        satoshis: 0,
        locking_script: op_return_script,
        change: false,
    });

    // Estimate fee (with 106-byte unlocking script estimate + change output)
    let estimated_size = estimate_tx_size(&tx, 1) + 34; // +34 for potential change output
    let fee = (estimated_size as u64 * config.fee_rate).div_ceil(1000);

    let total_out = config.contract_satoshis + fee;
    if config.funding_satoshis < total_out {
        return Err(TokenError::InsufficientFunds {
            needed: total_out,
            available: config.funding_satoshis,
        });
    }

    let change = config.funding_satoshis - total_out;
    if change > 0 {
        let change_script = p2pkh::lock(&issuer_address)?;
        tx.add_output(TransactionOutput {
            satoshis: change,
            locking_script: change_script,
            change: true,
        });
    }

    // Sign funding input with P2PKH
    let unlocker = p2pkh::unlock(config.funding_private_key.clone(), None);
    let unlocking_script = unlocker.sign(&tx, 0)?;
    tx.inputs[0].unlocking_script = Some(unlocking_script);

    Ok(tx)
}

/// Estimate transaction size with unsigned inputs (106 bytes per P2PKH input).
fn estimate_tx_size(tx: &Transaction, num_p2pkh_inputs: usize) -> usize {
    // version(4) + varint(inputs) + varint(outputs) + locktime(4)
    let mut size = 4 + 1 + 1 + 4;
    // Each input: txid(32) + vout(4) + varint(script_len) + script + seq(4)
    size += num_p2pkh_inputs * (32 + 4 + 1 + 106 + 4);
    // Outputs
    for output in &tx.outputs {
        size += 8 + 1 + output.locking_script.len(); // satoshis + varint + script
    }
    size
}
