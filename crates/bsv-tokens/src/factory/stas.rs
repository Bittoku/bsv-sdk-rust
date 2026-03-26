//! STAS transaction factories.
//!
//! Pure functions that build complete, signed transactions for STAS token
//! operations: issue, transfer, split, merge, and redeem.
//!
//! Also includes BTG (Back-to-Genesis) variants that produce STAS-BTG token
//! outputs and require prev-TX proof data in the unlocking scripts.

use bsv_primitives::ec::PrivateKey;
use bsv_script::opcodes::{OP_FALSE, OP_RETURN};
use bsv_script::Script;
use bsv_transaction::input::TransactionInput;
use bsv_transaction::output::TransactionOutput;
use bsv_transaction::template::p2pkh;
use bsv_transaction::template::UnlockingScriptTemplate;
use bsv_transaction::transaction::Transaction;

use crate::error::TokenError;
use crate::script::stas_builder::build_stas_locking_script;
use crate::script::stas_btg_builder::build_stas_btg_locking_script;
use crate::template::stas as stas_template;
use crate::template::stas_btg as stas_btg_template;
use crate::types::{Destination, Payment, SigningKey};

// -----------------------------------------------------------------------
// Config structs
// -----------------------------------------------------------------------

/// Configuration for issuing new STAS tokens.
pub struct IssueConfig {
    /// The contract UTXO (output from the contract TX).
    pub contract_utxo: Payment,
    /// Destinations for the issued tokens.
    pub destinations: Vec<Destination>,
    /// The 20-byte redemption public key hash.
    pub redemption_pkh: [u8; 20],
    /// Whether tokens are splittable.
    pub splittable: bool,
    /// Funding UTXO for fees.
    pub funding: Payment,
    /// Fee rate in satoshis per kilobyte.
    pub fee_rate: u64,
}

/// Configuration for transferring a STAS token.
pub struct TransferConfig {
    /// The token UTXO being transferred.
    pub token_utxo: Payment,
    /// The recipient destination.
    pub destination: Destination,
    /// The 20-byte redemption public key hash.
    pub redemption_pkh: [u8; 20],
    /// Whether the token is splittable.
    pub splittable: bool,
    /// Funding UTXO for fees.
    pub funding: Payment,
    /// Fee rate in satoshis per kilobyte.
    pub fee_rate: u64,
}

/// Configuration for splitting a STAS token.
pub struct SplitConfig {
    /// The token UTXO being split.
    pub token_utxo: Payment,
    /// The split destinations (must sum to token_utxo satoshis).
    pub destinations: Vec<Destination>,
    /// The 20-byte redemption public key hash.
    pub redemption_pkh: [u8; 20],
    /// Funding UTXO for fees.
    pub funding: Payment,
    /// Fee rate in satoshis per kilobyte.
    pub fee_rate: u64,
}

/// Configuration for merging multiple STAS tokens.
pub struct MergeConfig {
    /// The token UTXOs being merged.
    pub token_utxos: Vec<Payment>,
    /// The recipient destination.
    pub destination: Destination,
    /// The 20-byte redemption public key hash.
    pub redemption_pkh: [u8; 20],
    /// Whether the merged token is splittable.
    pub splittable: bool,
    /// Funding UTXO for fees.
    pub funding: Payment,
    /// Fee rate in satoshis per kilobyte.
    pub fee_rate: u64,
}

/// Configuration for redeeming (burning) a STAS token.
pub struct RedeemConfig {
    /// The token UTXO being redeemed.
    pub token_utxo: Payment,
    /// Funding UTXO for fees.
    pub funding: Payment,
    /// Fee rate in satoshis per kilobyte.
    pub fee_rate: u64,
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

/// Add a funding input to the transaction.
fn add_funding_input(tx: &mut Transaction, funding: &Payment) {
    let mut input = TransactionInput::new();
    input.source_txid = *funding.txid.as_bytes();
    input.source_tx_out_index = funding.vout;
    input.set_source_output(Some(TransactionOutput {
        satoshis: funding.satoshis,
        locking_script: funding.locking_script.clone(),
        change: false,
    }));
    tx.add_input(input);
}

/// Add a token input to the transaction.
fn add_token_input(tx: &mut Transaction, utxo: &Payment) {
    let mut input = TransactionInput::new();
    input.source_txid = *utxo.txid.as_bytes();
    input.source_tx_out_index = utxo.vout;
    input.set_source_output(Some(TransactionOutput {
        satoshis: utxo.satoshis,
        locking_script: utxo.locking_script.clone(),
        change: false,
    }));
    tx.add_input(input);
}

/// Estimate transaction size.
fn estimate_size(num_inputs: usize, outputs: &[TransactionOutput]) -> usize {
    let mut size = 4 + 1 + 1 + 4; // version + varint(in) + varint(out) + locktime
    size += num_inputs * (32 + 4 + 1 + 106 + 4); // each input with ~106 byte script
    for output in outputs {
        size += 8 + 1 + output.locking_script.len();
    }
    size
}

/// Calculate fee and add change output if needed. Returns error if insufficient funds.
fn add_change_output(
    tx: &mut Transaction,
    funding: &Payment,
    fee_rate: u64,
) -> Result<(), TokenError> {
    let num_inputs = tx.inputs.len();
    // Estimate with a potential change output (+34 bytes)
    let est_size = estimate_size(num_inputs, &tx.outputs) + 34;
    let fee = (est_size as u64 * fee_rate).div_ceil(1000);

    let total_in_sats = funding.satoshis;
    // Token inputs are accounted for in token outputs, so only funding pays fees
    // Simple approach: funding must cover fee
    if total_in_sats < fee {
        return Err(TokenError::InsufficientFunds {
            needed: fee,
            available: total_in_sats,
        });
    }

    let change = total_in_sats - fee;
    if change > 0 {
        let change_address = bsv_script::Address::from_public_key_hash(
            &funding.signing_key.hash160(),
            bsv_script::Network::Mainnet,
        );
        let change_script = p2pkh::lock(&change_address)?;
        tx.add_output(TransactionOutput {
            satoshis: change,
            locking_script: change_script,
            change: true,
        });
    }

    Ok(())
}

/// Sign all inputs. Token inputs use STAS template (P2PKH or P2MPKH),
/// funding input uses P2PKH or P2MPKH depending on its `SigningKey`.
fn sign_inputs(
    tx: &mut Transaction,
    token_keys: &[&SigningKey],
    funding_key: &SigningKey,
    funding_index: u32,
) -> Result<(), TokenError> {
    // Sign token inputs with STAS template (dispatches P2PKH vs P2MPKH).
    for (i, key) in token_keys.iter().enumerate() {
        let unlocker = stas_template::unlock_from_signing_key(key, None)?;
        let script = unlocker.sign(tx, i as u32)?;
        tx.inputs[i].unlocking_script = Some(script);
    }

    // Sign funding input with P2PKH (funding is always P2PKH).
    match funding_key {
        SigningKey::Single(pk) => {
            let p2pkh_unlocker = p2pkh::unlock(pk.clone(), None);
            let script = p2pkh_unlocker.sign(tx, funding_index)?;
            tx.inputs[funding_index as usize].unlocking_script = Some(script);
        }
        SigningKey::Multi { .. } => {
            // Funding with multisig — use standalone P2MPKH bare multisig unlock.
            let unlocker = stas_template::unlock_from_signing_key(funding_key, None)?;
            let script = unlocker.sign(tx, funding_index)?;
            tx.inputs[funding_index as usize].unlocking_script = Some(script);
        }
    }

    Ok(())
}

// -----------------------------------------------------------------------
// Factory functions
// -----------------------------------------------------------------------

/// Build an issue transaction.
///
/// # Transaction structure
/// - Input 0: Contract UTXO (P2PKH, signed with contract key)
/// - Input 1: Funding UTXO (P2PKH)
/// - Outputs 0..N-1: STAS token outputs to destinations
/// - Output N: Change
pub fn build_issue_tx(config: &IssueConfig) -> Result<Transaction, TokenError> {
    if config.destinations.is_empty() {
        return Err(TokenError::InvalidDestination(
            "at least one destination required".into(),
        ));
    }

    let total_tokens: u64 = config.destinations.iter().map(|d| d.satoshis).sum();
    if total_tokens != config.contract_utxo.satoshis {
        return Err(TokenError::AmountMismatch {
            expected: config.contract_utxo.satoshis,
            actual: total_tokens,
        });
    }

    let mut tx = Transaction::new();

    // Input 0: contract UTXO
    add_token_input(&mut tx, &config.contract_utxo);
    // Input 1: funding
    add_funding_input(&mut tx, &config.funding);

    // STAS token outputs
    for dest in &config.destinations {
        let locking_script = build_stas_locking_script(
            &dest.address,
            &config.redemption_pkh,
            config.splittable,
        )?;
        tx.add_output(TransactionOutput {
            satoshis: dest.satoshis,
            locking_script,
            change: false,
        });
    }

    // Change output
    add_change_output(&mut tx, &config.funding, config.fee_rate)?;

    // Sign: input 0 with contract key, input 1 with funding key.
    let unlocker0 = stas_template::unlock_from_signing_key(&config.contract_utxo.signing_key, None)?;
    let script0 = unlocker0.sign(&tx, 0)?;
    tx.inputs[0].unlocking_script = Some(script0);

    let unlocker1 = stas_template::unlock_from_signing_key(&config.funding.signing_key, None)?;
    let script1 = unlocker1.sign(&tx, 1)?;
    tx.inputs[1].unlocking_script = Some(script1);

    Ok(tx)
}

/// Build a transfer transaction.
///
/// # Transaction structure
/// - Input 0: Token UTXO (STAS)
/// - Input 1: Funding UTXO (P2PKH)
/// - Output 0: STAS token to destination
/// - Output 1: Change
pub fn build_transfer_tx(config: &TransferConfig) -> Result<Transaction, TokenError> {
    if config.destination.satoshis != config.token_utxo.satoshis {
        return Err(TokenError::AmountMismatch {
            expected: config.token_utxo.satoshis,
            actual: config.destination.satoshis,
        });
    }

    let mut tx = Transaction::new();

    add_token_input(&mut tx, &config.token_utxo);
    add_funding_input(&mut tx, &config.funding);

    let locking_script = build_stas_locking_script(
        &config.destination.address,
        &config.redemption_pkh,
        config.splittable,
    )?;
    tx.add_output(TransactionOutput {
        satoshis: config.destination.satoshis,
        locking_script,
        change: false,
    });

    add_change_output(&mut tx, &config.funding, config.fee_rate)?;

    sign_inputs(
        &mut tx,
        &[&config.token_utxo.signing_key],
        &config.funding.signing_key,
        1,
    )?;

    Ok(tx)
}

/// Build a split transaction.
///
/// # Transaction structure
/// - Input 0: Token UTXO (STAS)
/// - Input 1: Funding UTXO (P2PKH)
/// - Outputs 0..N-1: STAS token outputs to destinations
/// - Output N: Change
pub fn build_split_tx(config: &SplitConfig) -> Result<Transaction, TokenError> {
    if config.destinations.is_empty() {
        return Err(TokenError::InvalidDestination(
            "at least one destination required".into(),
        ));
    }

    if config.destinations.len() > 4 {
        return Err(TokenError::InvalidDestination(
            "maximum 4 split destinations allowed".into(),
        ));
    }

    let total: u64 = config.destinations.iter().map(|d| d.satoshis).sum();
    if total != config.token_utxo.satoshis {
        return Err(TokenError::AmountMismatch {
            expected: config.token_utxo.satoshis,
            actual: total,
        });
    }

    let mut tx = Transaction::new();

    add_token_input(&mut tx, &config.token_utxo);
    add_funding_input(&mut tx, &config.funding);

    for dest in &config.destinations {
        let locking_script = build_stas_locking_script(
            &dest.address,
            &config.redemption_pkh,
            true, // splittable tokens only
        )?;
        tx.add_output(TransactionOutput {
            satoshis: dest.satoshis,
            locking_script,
            change: false,
        });
    }

    add_change_output(&mut tx, &config.funding, config.fee_rate)?;

    sign_inputs(
        &mut tx,
        &[&config.token_utxo.signing_key],
        &config.funding.signing_key,
        1,
    )?;

    Ok(tx)
}

/// Build a merge transaction.
///
/// # Transaction structure
/// - Inputs 0..N-1: Token UTXOs (STAS)
/// - Input N: Funding UTXO (P2PKH)
/// - Output 0: Merged STAS token
/// - Output 1: Change
pub fn build_merge_tx(config: &MergeConfig) -> Result<Transaction, TokenError> {
    if config.token_utxos.len() < 2 {
        return Err(TokenError::InvalidDestination(
            "at least 2 token UTXOs required for merge".into(),
        ));
    }

    let total_tokens: u64 = config.token_utxos.iter().map(|u| u.satoshis).sum();
    if total_tokens != config.destination.satoshis {
        return Err(TokenError::AmountMismatch {
            expected: total_tokens,
            actual: config.destination.satoshis,
        });
    }

    let mut tx = Transaction::new();

    for utxo in &config.token_utxos {
        add_token_input(&mut tx, utxo);
    }
    add_funding_input(&mut tx, &config.funding);

    let locking_script = build_stas_locking_script(
        &config.destination.address,
        &config.redemption_pkh,
        config.splittable,
    )?;
    tx.add_output(TransactionOutput {
        satoshis: config.destination.satoshis,
        locking_script,
        change: false,
    });

    add_change_output(&mut tx, &config.funding, config.fee_rate)?;

    let token_keys: Vec<&SigningKey> = config.token_utxos.iter().map(|u| &u.signing_key).collect();
    let funding_index = config.token_utxos.len() as u32;
    sign_inputs(&mut tx, &token_keys, &config.funding.signing_key, funding_index)?;

    Ok(tx)
}

/// Build a redeem (burn) transaction.
///
/// # Transaction structure
/// - Input 0: Token UTXO (STAS)
/// - Input 1: Funding UTXO (P2PKH)
/// - Output 0: OP_RETURN (burn marker, 0 satoshis)
/// - Output 1: Change (token satoshis + funding - fee returned to funder)
pub fn build_redeem_tx(config: &RedeemConfig) -> Result<Transaction, TokenError> {
    let mut tx = Transaction::new();

    add_token_input(&mut tx, &config.token_utxo);
    add_funding_input(&mut tx, &config.funding);

    // OP_RETURN burn marker
    let mut op_return_script = Script::new();
    op_return_script.append_opcodes(&[OP_FALSE, OP_RETURN])?;
    tx.add_output(TransactionOutput {
        satoshis: 0,
        locking_script: op_return_script,
        change: false,
    });

    // Estimate fee
    let est_size = estimate_size(2, &tx.outputs) + 34;
    let fee = (est_size as u64 * config.fee_rate).div_ceil(1000);

    let total_in = config.token_utxo.satoshis + config.funding.satoshis;
    if total_in < fee {
        return Err(TokenError::InsufficientFunds {
            needed: fee,
            available: total_in,
        });
    }

    let change = total_in - fee;
    if change > 0 {
        let change_address = bsv_script::Address::from_public_key_hash(
            &config.funding.signing_key.hash160(),
            bsv_script::Network::Mainnet,
        );
        let change_script = p2pkh::lock(&change_address)?;
        tx.add_output(TransactionOutput {
            satoshis: change,
            locking_script: change_script,
            change: true,
        });
    }

    sign_inputs(
        &mut tx,
        &[&config.token_utxo.signing_key],
        &config.funding.signing_key,
        1,
    )?;

    Ok(tx)
}

// =======================================================================
// BTG (Back-to-Genesis) factory functions
// =======================================================================

/// A UTXO payment input that includes the raw previous transaction for BTG proof.
///
/// Extends [`Payment`] with the raw bytes of the previous transaction, which
/// the BTG unlocking template splits into three proof segments.
pub struct BtgPayment {
    /// Standard payment fields (txid, vout, satoshis, locking_script, private_key).
    pub payment: Payment,
    /// Raw bytes of the previous transaction (wire format).
    /// Used to construct the BTG prev-TX proof in the unlocking script.
    pub prev_raw_tx: Vec<u8>,
}

/// Configuration for transferring a STAS-BTG token.
pub struct BtgTransferConfig {
    /// The token UTXO being transferred, with raw prev TX for proof.
    pub token_utxo: BtgPayment,
    /// The recipient destination.
    pub destination: Destination,
    /// The 20-byte redemption public key hash.
    pub redemption_pkh: [u8; 20],
    /// Whether the token is splittable.
    pub splittable: bool,
    /// Funding UTXO for fees.
    pub funding: Payment,
    /// Fee rate in satoshis per kilobyte.
    pub fee_rate: u64,
}

/// Configuration for splitting a STAS-BTG token.
pub struct BtgSplitConfig {
    /// The token UTXO being split, with raw prev TX for proof.
    pub token_utxo: BtgPayment,
    /// The split destinations (must sum to token_utxo satoshis).
    pub destinations: Vec<Destination>,
    /// The 20-byte redemption public key hash.
    pub redemption_pkh: [u8; 20],
    /// Funding UTXO for fees.
    pub funding: Payment,
    /// Fee rate in satoshis per kilobyte.
    pub fee_rate: u64,
}

/// Configuration for merging multiple STAS-BTG tokens.
pub struct BtgMergeConfig {
    /// The token UTXOs being merged, each with raw prev TX for proof.
    pub token_utxos: Vec<BtgPayment>,
    /// The recipient destination.
    pub destination: Destination,
    /// The 20-byte redemption public key hash.
    pub redemption_pkh: [u8; 20],
    /// Whether the merged token is splittable.
    pub splittable: bool,
    /// Funding UTXO for fees.
    pub funding: Payment,
    /// Fee rate in satoshis per kilobyte.
    pub fee_rate: u64,
}

/// Sign token inputs using BTG unlocking templates and funding input with P2PKH.
///
/// Each token input gets a STAS-BTG unlocker that includes the prev-TX proof.
/// The funding input (at `funding_index`) uses a standard P2PKH unlocker.
fn sign_btg_inputs(
    tx: &mut Transaction,
    token_btg_data: &[(&SigningKey, &[u8], u32)], // (key, prev_raw_tx, prev_vout)
    funding_key: &SigningKey,
    funding_index: u32,
) -> Result<(), TokenError> {
    // Sign token inputs with BTG unlocking templates.
    // BTG currently only supports P2PKH signing — extract the single key.
    for (i, (key, prev_raw, prev_vout)) in token_btg_data.iter().enumerate() {
        match key {
            SigningKey::Single(pk) => {
                let unlocker = stas_btg_template::unlock_btg(
                    pk.clone(),
                    None,
                    prev_raw.to_vec(),
                    *prev_vout,
                );
                let script = unlocker.sign(tx, i as u32)?;
                tx.inputs[i].unlocking_script = Some(script);
            }
            SigningKey::Multi { .. } => {
                return Err(TokenError::SigningFailed(
                    "BTG templates do not yet support P2MPKH signing".to_string(),
                ));
            }
        }
    }

    // Sign funding input.
    match funding_key {
        SigningKey::Single(pk) => {
            let p2pkh_unlocker = p2pkh::unlock(pk.clone(), None);
            let script = p2pkh_unlocker.sign(tx, funding_index)?;
            tx.inputs[funding_index as usize].unlocking_script = Some(script);
        }
        SigningKey::Multi { .. } => {
            let unlocker = stas_template::unlock_from_signing_key(funding_key, None)?;
            let script = unlocker.sign(tx, funding_index)?;
            tx.inputs[funding_index as usize].unlocking_script = Some(script);
        }
    }

    Ok(())
}

/// Build a BTG transfer transaction.
///
/// Transfers a STAS-BTG token to a new owner, including the prev-TX proof
/// in the unlocking script. The output uses a STAS-BTG locking script.
///
/// # Transaction structure
/// - Input 0: Token UTXO (STAS-BTG, with prev-TX proof)
/// - Input 1: Funding UTXO (P2PKH)
/// - Output 0: STAS-BTG token to destination
/// - Output 1: Change
pub fn build_btg_transfer_tx(config: &BtgTransferConfig) -> Result<Transaction, TokenError> {
    if config.destination.satoshis != config.token_utxo.payment.satoshis {
        return Err(TokenError::AmountMismatch {
            expected: config.token_utxo.payment.satoshis,
            actual: config.destination.satoshis,
        });
    }

    let mut tx = Transaction::new();

    add_token_input(&mut tx, &config.token_utxo.payment);
    add_funding_input(&mut tx, &config.funding);

    let locking_script = build_stas_btg_locking_script(
        &config.destination.address,
        &config.redemption_pkh,
        config.splittable,
    )?;
    tx.add_output(TransactionOutput {
        satoshis: config.destination.satoshis,
        locking_script,
        change: false,
    });

    add_change_output(&mut tx, &config.funding, config.fee_rate)?;

    sign_btg_inputs(
        &mut tx,
        &[(
            &config.token_utxo.payment.signing_key,
            &config.token_utxo.prev_raw_tx,
            config.token_utxo.payment.vout,
        )],
        &config.funding.signing_key,
        1,
    )?;

    Ok(tx)
}

/// Build a BTG split transaction.
///
/// Splits a STAS-BTG token into multiple outputs, each with a STAS-BTG
/// locking script. The unlocking script includes the prev-TX proof.
///
/// # Transaction structure
/// - Input 0: Token UTXO (STAS-BTG, with prev-TX proof)
/// - Input 1: Funding UTXO (P2PKH)
/// - Outputs 0..N-1: STAS-BTG token outputs to destinations
/// - Output N: Change
pub fn build_btg_split_tx(config: &BtgSplitConfig) -> Result<Transaction, TokenError> {
    if config.destinations.is_empty() {
        return Err(TokenError::InvalidDestination(
            "at least one destination required".into(),
        ));
    }

    if config.destinations.len() > 4 {
        return Err(TokenError::InvalidDestination(
            "maximum 4 split destinations allowed".into(),
        ));
    }

    let total: u64 = config.destinations.iter().map(|d| d.satoshis).sum();
    if total != config.token_utxo.payment.satoshis {
        return Err(TokenError::AmountMismatch {
            expected: config.token_utxo.payment.satoshis,
            actual: total,
        });
    }

    let mut tx = Transaction::new();

    add_token_input(&mut tx, &config.token_utxo.payment);
    add_funding_input(&mut tx, &config.funding);

    for dest in &config.destinations {
        let locking_script = build_stas_btg_locking_script(
            &dest.address,
            &config.redemption_pkh,
            true, // splittable tokens only
        )?;
        tx.add_output(TransactionOutput {
            satoshis: dest.satoshis,
            locking_script,
            change: false,
        });
    }

    add_change_output(&mut tx, &config.funding, config.fee_rate)?;

    sign_btg_inputs(
        &mut tx,
        &[(
            &config.token_utxo.payment.signing_key,
            &config.token_utxo.prev_raw_tx,
            config.token_utxo.payment.vout,
        )],
        &config.funding.signing_key,
        1,
    )?;

    Ok(tx)
}

/// Build a BTG merge transaction.
///
/// Merges multiple STAS-BTG tokens into a single output. Each input includes
/// its own prev-TX proof in the unlocking script.
///
/// # Transaction structure
/// - Inputs 0..N-1: Token UTXOs (STAS-BTG, each with prev-TX proof)
/// - Input N: Funding UTXO (P2PKH)
/// - Output 0: Merged STAS-BTG token
/// - Output 1: Change
pub fn build_btg_merge_tx(config: &BtgMergeConfig) -> Result<Transaction, TokenError> {
    if config.token_utxos.len() < 2 {
        return Err(TokenError::InvalidDestination(
            "at least 2 token UTXOs required for merge".into(),
        ));
    }

    let total_tokens: u64 = config.token_utxos.iter().map(|u| u.payment.satoshis).sum();
    if total_tokens != config.destination.satoshis {
        return Err(TokenError::AmountMismatch {
            expected: total_tokens,
            actual: config.destination.satoshis,
        });
    }

    let mut tx = Transaction::new();

    for utxo in &config.token_utxos {
        add_token_input(&mut tx, &utxo.payment);
    }
    add_funding_input(&mut tx, &config.funding);

    let locking_script = build_stas_btg_locking_script(
        &config.destination.address,
        &config.redemption_pkh,
        config.splittable,
    )?;
    tx.add_output(TransactionOutput {
        satoshis: config.destination.satoshis,
        locking_script,
        change: false,
    });

    add_change_output(&mut tx, &config.funding, config.fee_rate)?;

    let btg_data: Vec<(&SigningKey, &[u8], u32)> = config
        .token_utxos
        .iter()
        .map(|u| {
            (
                &u.payment.signing_key,
                u.prev_raw_tx.as_slice(),
                u.payment.vout,
            )
        })
        .collect();
    let funding_index = config.token_utxos.len() as u32;
    sign_btg_inputs(&mut tx, &btg_data, &config.funding.signing_key, funding_index)?;

    Ok(tx)
}

/// Configuration for a BTG checkpoint transaction.
///
/// A checkpoint TX allows the issuer (redemption key holder) to co-sign
/// alongside the current owner, resetting the prev-TX proof chain depth.
/// This prevents linear size growth in BTG token transactions.
///
/// The issuer never takes custody — they merely attest that the current token
/// state is valid by co-signing. After the checkpoint TX, subsequent transfers
/// only need to include the small checkpoint TX as their prev-TX proof.
pub struct BtgCheckpointConfig {
    /// The current STAS-BTG token UTXO.
    pub token_utxo: Payment,
    /// The issuer's private key (redemption key) for attestation co-signing.
    pub issuer_private_key: PrivateKey,
    /// The recipient destination (typically the same owner).
    pub destination: Destination,
    /// The 20-byte redemption public key hash.
    pub redemption_pkh: [u8; 20],
    /// Whether the token is splittable.
    pub splittable: bool,
    /// Funding UTXO for fees.
    pub funding: Payment,
    /// Fee rate in satoshis per kilobyte.
    pub fee_rate: u64,
}

/// Build a BTG checkpoint transaction.
///
/// A checkpoint TX uses the issuer co-signature path (OP_ELSE branch) of the
/// dual-path STAS-BTG locking script. This resets the proof chain depth,
/// preventing linear size growth in successive token transfers.
///
/// # Transaction structure
/// - Input 0: Token UTXO (STAS-BTG, checkpoint path with issuer co-signature)
/// - Input 1: Funding UTXO (P2PKH)
/// - Output 0: Fresh STAS-BTG token to destination
/// - Output 1: Change
///
/// # Errors
/// Returns [`TokenError::AmountMismatch`] if destination satoshis don't match
/// the token UTXO, or [`TokenError::InsufficientFunds`] if funding is too low.
pub fn build_btg_checkpoint_tx(config: &BtgCheckpointConfig) -> Result<Transaction, TokenError> {
    if config.destination.satoshis != config.token_utxo.satoshis {
        return Err(TokenError::AmountMismatch {
            expected: config.token_utxo.satoshis,
            actual: config.destination.satoshis,
        });
    }

    let mut tx = Transaction::new();

    // Input 0: Token UTXO (will use checkpoint unlocking template)
    add_token_input(&mut tx, &config.token_utxo);
    // Input 1: Funding UTXO (P2PKH)
    add_funding_input(&mut tx, &config.funding);

    // Output 0: Fresh STAS-BTG token to destination
    let locking_script = build_stas_btg_locking_script(
        &config.destination.address,
        &config.redemption_pkh,
        config.splittable,
    )?;
    tx.add_output(TransactionOutput {
        satoshis: config.destination.satoshis,
        locking_script,
        change: false,
    });

    // Change output
    add_change_output(&mut tx, &config.funding, config.fee_rate)?;

    // Sign input 0 with checkpoint unlocking template (owner + issuer co-sign).
    // Checkpoint requires P2PKH — extract single keys.
    let owner_pk = match &config.token_utxo.signing_key {
        SigningKey::Single(pk) => pk.clone(),
        SigningKey::Multi { .. } => {
            return Err(TokenError::SigningFailed(
                "BTG checkpoint does not yet support P2MPKH token owner".to_string(),
            ));
        }
    };
    let checkpoint_unlocker = stas_btg_template::unlock_btg_checkpoint(
        owner_pk,
        config.issuer_private_key.clone(),
        None,
    );
    let checkpoint_script = checkpoint_unlocker.sign(&tx, 0)?;
    tx.inputs[0].unlocking_script = Some(checkpoint_script);

    // Sign input 1 with funding key.
    let funding_unlocker = stas_template::unlock_from_signing_key(&config.funding.signing_key, None)?;
    let funding_script = funding_unlocker.sign(&tx, 1)?;
    tx.inputs[1].unlocking_script = Some(funding_script);

    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_primitives::chainhash::Hash;
    use bsv_primitives::ec::PrivateKey;

    fn test_payment(satoshis: u64) -> Payment {
        let key = PrivateKey::new();
        let pubkey = key.pub_key().to_compressed();
        let pkh = bsv_primitives::hash::hash160(&pubkey);
        let addr = bsv_script::Address::from_public_key_hash(&pkh, bsv_script::Network::Mainnet);
        let locking = p2pkh::lock(&addr).unwrap();
        Payment {
            txid: Hash::from_bytes(&[0xaa; 32]).unwrap(),
            vout: 0,
            satoshis,
            locking_script: locking,
            signing_key: SigningKey::Single(key),
        }
    }

    fn test_destination(satoshis: u64) -> Destination {
        let key = PrivateKey::new();
        let pubkey = key.pub_key().to_compressed();
        let pkh = bsv_primitives::hash::hash160(&pubkey);
        Destination {
            address: bsv_script::Address::from_public_key_hash(&pkh, bsv_script::Network::Mainnet),
            satoshis,
        }
    }

    fn redemption_pkh() -> [u8; 20] {
        [0xbb; 20]
    }

    // ---------------------------------------------------------------
    // Issue tests
    // ---------------------------------------------------------------

    #[test]
    fn issue_tx_structure() {
        let contract = test_payment(10000);
        let funding = test_payment(50000);
        let dest = test_destination(10000);

        let config = IssueConfig {
            contract_utxo: contract,
            destinations: vec![dest],
            redemption_pkh: redemption_pkh(),
            splittable: true,
            funding,
            fee_rate: 500,
        };

        let tx = build_issue_tx(&config).unwrap();
        assert_eq!(tx.input_count(), 2);
        // At least 1 token output + possible change
        assert!(tx.output_count() >= 1);
        assert_eq!(tx.outputs[0].satoshis, 10000);
        // All inputs should be signed
        assert!(tx.inputs[0].unlocking_script.is_some());
        assert!(tx.inputs[1].unlocking_script.is_some());
    }

    #[test]
    fn issue_amount_mismatch() {
        let contract = test_payment(10000);
        let funding = test_payment(50000);
        let dest = test_destination(5000); // wrong amount

        let config = IssueConfig {
            contract_utxo: contract,
            destinations: vec![dest],
            redemption_pkh: redemption_pkh(),
            splittable: true,
            funding,
            fee_rate: 500,
        };

        assert!(build_issue_tx(&config).is_err());
    }

    #[test]
    fn issue_no_destinations() {
        let contract = test_payment(10000);
        let funding = test_payment(50000);

        let config = IssueConfig {
            contract_utxo: contract,
            destinations: vec![],
            redemption_pkh: redemption_pkh(),
            splittable: true,
            funding,
            fee_rate: 500,
        };

        assert!(build_issue_tx(&config).is_err());
    }

    #[test]
    fn issue_multiple_destinations() {
        let contract = test_payment(10000);
        let funding = test_payment(50000);
        let d1 = test_destination(3000);
        let d2 = test_destination(7000);

        let config = IssueConfig {
            contract_utxo: contract,
            destinations: vec![d1, d2],
            redemption_pkh: redemption_pkh(),
            splittable: true,
            funding,
            fee_rate: 500,
        };

        let tx = build_issue_tx(&config).unwrap();
        assert_eq!(tx.outputs[0].satoshis, 3000);
        assert_eq!(tx.outputs[1].satoshis, 7000);
    }

    // ---------------------------------------------------------------
    // Transfer tests
    // ---------------------------------------------------------------

    #[test]
    fn transfer_tx_structure() {
        let token = test_payment(5000);
        let funding = test_payment(50000);
        let dest = test_destination(5000);

        let config = TransferConfig {
            token_utxo: token,
            destination: dest,
            redemption_pkh: redemption_pkh(),
            splittable: true,
            funding,
            fee_rate: 500,
        };

        let tx = build_transfer_tx(&config).unwrap();
        assert_eq!(tx.input_count(), 2);
        assert!(tx.output_count() >= 1);
        assert_eq!(tx.outputs[0].satoshis, 5000);
        assert!(tx.inputs[0].unlocking_script.is_some());
        assert!(tx.inputs[1].unlocking_script.is_some());
    }

    #[test]
    fn transfer_amount_mismatch() {
        let token = test_payment(5000);
        let funding = test_payment(50000);
        let dest = test_destination(3000);

        let config = TransferConfig {
            token_utxo: token,
            destination: dest,
            redemption_pkh: redemption_pkh(),
            splittable: true,
            funding,
            fee_rate: 500,
        };

        assert!(build_transfer_tx(&config).is_err());
    }

    // ---------------------------------------------------------------
    // Split tests
    // ---------------------------------------------------------------

    #[test]
    fn split_tx_structure() {
        let token = test_payment(10000);
        let funding = test_payment(50000);
        let d1 = test_destination(4000);
        let d2 = test_destination(6000);

        let config = SplitConfig {
            token_utxo: token,
            destinations: vec![d1, d2],
            redemption_pkh: redemption_pkh(),
            funding,
            fee_rate: 500,
        };

        let tx = build_split_tx(&config).unwrap();
        assert_eq!(tx.input_count(), 2);
        assert_eq!(tx.outputs[0].satoshis, 4000);
        assert_eq!(tx.outputs[1].satoshis, 6000);
        assert!(tx.inputs[0].unlocking_script.is_some());
    }

    #[test]
    fn split_amount_conservation() {
        let token = test_payment(10000);
        let funding = test_payment(50000);
        let d1 = test_destination(4000);
        let d2 = test_destination(5000); // 9000 != 10000

        let config = SplitConfig {
            token_utxo: token,
            destinations: vec![d1, d2],
            redemption_pkh: redemption_pkh(),
            funding,
            fee_rate: 500,
        };

        assert!(build_split_tx(&config).is_err());
    }

    #[test]
    fn split_too_many_destinations() {
        let token = test_payment(10000);
        let funding = test_payment(50000);
        let dests: Vec<Destination> = (0..5).map(|_| test_destination(2000)).collect();

        let config = SplitConfig {
            token_utxo: token,
            destinations: dests,
            redemption_pkh: redemption_pkh(),
            funding,
            fee_rate: 500,
        };

        assert!(build_split_tx(&config).is_err());
    }

    #[test]
    fn split_no_destinations() {
        let token = test_payment(10000);
        let funding = test_payment(50000);

        let config = SplitConfig {
            token_utxo: token,
            destinations: vec![],
            redemption_pkh: redemption_pkh(),
            funding,
            fee_rate: 500,
        };

        assert!(build_split_tx(&config).is_err());
    }

    // ---------------------------------------------------------------
    // Merge tests
    // ---------------------------------------------------------------

    #[test]
    fn merge_tx_structure() {
        let t1 = test_payment(3000);
        let t2 = test_payment(7000);
        let funding = test_payment(50000);
        let dest = test_destination(10000);

        let config = MergeConfig {
            token_utxos: vec![t1, t2],
            destination: dest,
            redemption_pkh: redemption_pkh(),
            splittable: true,
            funding,
            fee_rate: 500,
        };

        let tx = build_merge_tx(&config).unwrap();
        assert_eq!(tx.input_count(), 3); // 2 tokens + 1 funding
        assert_eq!(tx.outputs[0].satoshis, 10000);
        assert!(tx.inputs[0].unlocking_script.is_some());
        assert!(tx.inputs[1].unlocking_script.is_some());
        assert!(tx.inputs[2].unlocking_script.is_some());
    }

    #[test]
    fn merge_amount_mismatch() {
        let t1 = test_payment(3000);
        let t2 = test_payment(7000);
        let funding = test_payment(50000);
        let dest = test_destination(9000); // wrong

        let config = MergeConfig {
            token_utxos: vec![t1, t2],
            destination: dest,
            redemption_pkh: redemption_pkh(),
            splittable: true,
            funding,
            fee_rate: 500,
        };

        assert!(build_merge_tx(&config).is_err());
    }

    #[test]
    fn merge_single_utxo_rejected() {
        let t1 = test_payment(3000);
        let funding = test_payment(50000);
        let dest = test_destination(3000);

        let config = MergeConfig {
            token_utxos: vec![t1],
            destination: dest,
            redemption_pkh: redemption_pkh(),
            splittable: true,
            funding,
            fee_rate: 500,
        };

        assert!(build_merge_tx(&config).is_err());
    }

    // ---------------------------------------------------------------
    // Redeem tests
    // ---------------------------------------------------------------

    #[test]
    fn redeem_tx_structure() {
        let token = test_payment(5000);
        let funding = test_payment(50000);

        let config = RedeemConfig {
            token_utxo: token,
            funding,
            fee_rate: 500,
        };

        let tx = build_redeem_tx(&config).unwrap();
        assert_eq!(tx.input_count(), 2);
        // Output 0 is OP_RETURN with 0 satoshis
        assert_eq!(tx.outputs[0].satoshis, 0);
        assert!(tx.outputs[0].locking_script.is_data());
        // Change output should have token + funding - fee
        if tx.output_count() > 1 {
            assert!(tx.outputs[1].satoshis > 0);
        }
        assert!(tx.inputs[0].unlocking_script.is_some());
        assert!(tx.inputs[1].unlocking_script.is_some());
    }

    // ---------------------------------------------------------------
    // BTG Transfer tests
    // ---------------------------------------------------------------

    /// Build a fake "previous transaction" for BTG proof testing.
    fn build_fake_prev_tx(satoshis: u64) -> (Payment, Vec<u8>) {
        let key = PrivateKey::new();
        let pubkey = key.pub_key().to_compressed();
        let pkh = bsv_primitives::hash::hash160(&pubkey);
        let addr = bsv_script::Address::from_public_key_hash(&pkh, bsv_script::Network::Mainnet);
        let locking = p2pkh::lock(&addr).unwrap();

        // Build a minimal "prev tx" with a single output
        let mut prev_tx = Transaction::new();
        let mut input = bsv_transaction::input::TransactionInput::new();
        input.source_txid = [0xdd; 32];
        input.source_tx_out_index = 0;
        input.unlocking_script = Some(Script::new());
        input.sequence_number = 0xffffffff;
        prev_tx.add_input(input);
        prev_tx.add_output(TransactionOutput {
            satoshis,
            locking_script: locking.clone(),
            change: false,
        });

        let raw = prev_tx.to_bytes();
        let txid_bytes = bsv_primitives::hash::sha256d(&raw);
        let mut txid_le = txid_bytes;
        txid_le.reverse();
        let txid = Hash::from_bytes(&txid_le).unwrap();

        let payment = Payment {
            txid,
            vout: 0,
            satoshis,
            locking_script: locking,
            signing_key: SigningKey::Single(key),
        };

        (payment, raw)
    }

    #[test]
    fn btg_transfer_tx_structure() {
        let (token_payment, prev_raw) = build_fake_prev_tx(5000);
        let funding = test_payment(50000);
        let dest = test_destination(5000);

        let config = BtgTransferConfig {
            token_utxo: BtgPayment {
                payment: token_payment,
                prev_raw_tx: prev_raw,
            },
            destination: dest,
            redemption_pkh: redemption_pkh(),
            splittable: true,
            funding,
            fee_rate: 500,
        };

        let tx = build_btg_transfer_tx(&config).unwrap();
        assert_eq!(tx.input_count(), 2);
        assert!(tx.output_count() >= 1);
        assert_eq!(tx.outputs[0].satoshis, 5000);
        // Token input should have a BTG unlocking script (longer than P2PKH)
        let token_unlock = tx.inputs[0].unlocking_script.as_ref().unwrap();
        assert!(
            token_unlock.len() > 106,
            "BTG unlocking script should be longer than P2PKH"
        );
        assert!(tx.inputs[1].unlocking_script.is_some());
    }

    #[test]
    fn btg_transfer_amount_mismatch() {
        let (token_payment, prev_raw) = build_fake_prev_tx(5000);
        let funding = test_payment(50000);
        let dest = test_destination(3000); // wrong

        let config = BtgTransferConfig {
            token_utxo: BtgPayment {
                payment: token_payment,
                prev_raw_tx: prev_raw,
            },
            destination: dest,
            redemption_pkh: redemption_pkh(),
            splittable: true,
            funding,
            fee_rate: 500,
        };

        assert!(build_btg_transfer_tx(&config).is_err());
    }

    // ---------------------------------------------------------------
    // BTG Split tests
    // ---------------------------------------------------------------

    #[test]
    fn btg_split_tx_structure() {
        let (token_payment, prev_raw) = build_fake_prev_tx(10000);
        let funding = test_payment(50000);
        let d1 = test_destination(4000);
        let d2 = test_destination(6000);

        let config = BtgSplitConfig {
            token_utxo: BtgPayment {
                payment: token_payment,
                prev_raw_tx: prev_raw,
            },
            destinations: vec![d1, d2],
            redemption_pkh: redemption_pkh(),
            funding,
            fee_rate: 500,
        };

        let tx = build_btg_split_tx(&config).unwrap();
        assert_eq!(tx.input_count(), 2);
        assert_eq!(tx.outputs[0].satoshis, 4000);
        assert_eq!(tx.outputs[1].satoshis, 6000);
    }

    // ---------------------------------------------------------------
    // BTG Merge tests
    // ---------------------------------------------------------------

    #[test]
    fn btg_merge_tx_structure() {
        let (t1, raw1) = build_fake_prev_tx(3000);
        let (t2, raw2) = build_fake_prev_tx(7000);
        let funding = test_payment(50000);
        let dest = test_destination(10000);

        let config = BtgMergeConfig {
            token_utxos: vec![
                BtgPayment {
                    payment: t1,
                    prev_raw_tx: raw1,
                },
                BtgPayment {
                    payment: t2,
                    prev_raw_tx: raw2,
                },
            ],
            destination: dest,
            redemption_pkh: redemption_pkh(),
            splittable: true,
            funding,
            fee_rate: 500,
        };

        let tx = build_btg_merge_tx(&config).unwrap();
        assert_eq!(tx.input_count(), 3); // 2 tokens + 1 funding
        assert_eq!(tx.outputs[0].satoshis, 10000);
        assert!(tx.inputs[0].unlocking_script.is_some());
        assert!(tx.inputs[1].unlocking_script.is_some());
        assert!(tx.inputs[2].unlocking_script.is_some());
    }

    // ---------------------------------------------------------------
    // BTG Checkpoint tests
    // ---------------------------------------------------------------

    #[test]
    fn btg_checkpoint_tx_structure() {
        let token = test_payment(5000);
        let issuer_key = PrivateKey::new();
        let funding = test_payment(50000);
        let dest = test_destination(5000);

        let config = BtgCheckpointConfig {
            token_utxo: token,
            issuer_private_key: issuer_key,
            destination: dest,
            redemption_pkh: redemption_pkh(),
            splittable: true,
            funding,
            fee_rate: 500,
        };

        let tx = build_btg_checkpoint_tx(&config).unwrap();
        assert_eq!(tx.input_count(), 2);
        assert!(tx.output_count() >= 1);
        assert_eq!(tx.outputs[0].satoshis, 5000);

        // Both inputs should be signed
        assert!(tx.inputs[0].unlocking_script.is_some());
        assert!(tx.inputs[1].unlocking_script.is_some());

        // Token input uses checkpoint template (~217 bytes, not proof template)
        let token_unlock = tx.inputs[0].unlocking_script.as_ref().unwrap();
        let unlock_bytes = token_unlock.to_bytes();

        // Last byte should be OP_FALSE (0x00) for checkpoint path
        assert_eq!(
            *unlock_bytes.last().unwrap(),
            0x00,
            "checkpoint unlocking script should end with OP_FALSE"
        );

        // Checkpoint unlock is ~217 bytes (shorter than BTG proof which includes prev TX)
        assert!(
            unlock_bytes.len() > 200 && unlock_bytes.len() < 250,
            "checkpoint unlock ({} bytes) should be ~217 bytes",
            unlock_bytes.len()
        );
    }

    #[test]
    fn btg_checkpoint_amount_mismatch() {
        let token = test_payment(5000);
        let issuer_key = PrivateKey::new();
        let funding = test_payment(50000);
        let dest = test_destination(3000); // wrong

        let config = BtgCheckpointConfig {
            token_utxo: token,
            issuer_private_key: issuer_key,
            destination: dest,
            redemption_pkh: redemption_pkh(),
            splittable: true,
            funding,
            fee_rate: 500,
        };

        assert!(build_btg_checkpoint_tx(&config).is_err());
    }

    #[test]
    fn btg_checkpoint_output_is_stas_btg() {
        let token = test_payment(5000);
        let issuer_key = PrivateKey::new();
        let funding = test_payment(50000);
        let dest = test_destination(5000);

        let config = BtgCheckpointConfig {
            token_utxo: token,
            issuer_private_key: issuer_key,
            destination: dest,
            redemption_pkh: redemption_pkh(),
            splittable: true,
            funding,
            fee_rate: 500,
        };

        let tx = build_btg_checkpoint_tx(&config).unwrap();
        let output_script = tx.outputs[0].locking_script.to_bytes();

        // Output should be a fresh STAS-BTG locking script (starts with OP_IF)
        assert_eq!(
            output_script[0], 0x63,
            "checkpoint output should be a STAS-BTG script (starts with OP_IF)"
        );
    }

    // -------------------------------------------------------------------
    // Gap 4: Factory integration with SigningKey::Multi
    // -------------------------------------------------------------------

    /// Create a Payment backed by a multisig signing key.
    fn test_multi_payment(satoshis: u64) -> Payment {
        use bsv_transaction::template::p2mpkh::MultisigScript;

        let keys: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::new()).collect();
        let pubs: Vec<_> = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(2, pubs).unwrap();
        let mpkh = ms.mpkh();
        let addr = bsv_script::Address::from_public_key_hash(&mpkh, bsv_script::Network::Mainnet);
        let locking = p2pkh::lock(&addr).unwrap();

        Payment {
            txid: Hash::from_bytes(&[0xcc; 32]).unwrap(),
            vout: 0,
            satoshis,
            locking_script: locking,
            signing_key: SigningKey::Multi {
                private_keys: vec![keys[0].clone(), keys[1].clone()],
                multisig: ms,
            },
        }
    }

    #[test]
    fn transfer_with_multi_signing_key_succeeds() {
        let token = test_multi_payment(5000);
        let funding = test_multi_payment(50000);
        let dest = test_destination(5000);

        let config = TransferConfig {
            token_utxo: token,
            destination: dest,
            redemption_pkh: redemption_pkh(),
            splittable: true,
            funding,
            fee_rate: 500,
        };

        let tx = build_transfer_tx(&config).unwrap();

        // Transaction should have 2 inputs, both signed
        assert_eq!(tx.input_count(), 2);
        assert!(
            tx.inputs[0].unlocking_script.is_some(),
            "token input should be signed"
        );
        assert!(
            tx.inputs[1].unlocking_script.is_some(),
            "funding input should be signed"
        );

        // Unlocking scripts should be non-empty
        let token_unlock = tx.inputs[0].unlocking_script.as_ref().unwrap();
        assert!(
            token_unlock.len() > 0,
            "token unlocking script should be non-empty"
        );
        let funding_unlock = tx.inputs[1].unlocking_script.as_ref().unwrap();
        assert!(
            funding_unlock.len() > 0,
            "funding unlocking script should be non-empty"
        );

        // Both unlocking scripts should be longer than P2PKH (106 bytes)
        // because they use multisig
        assert!(
            token_unlock.len() > 106,
            "multisig token unlock ({}) should be longer than P2PKH",
            token_unlock.len()
        );

        // Change output should exist and use the MPKH-derived address
        assert!(
            tx.output_count() >= 2,
            "should have token output + change output"
        );
    }

    #[test]
    fn transfer_with_mixed_keys_token_multi_funding_single() {
        let token = test_multi_payment(5000);
        let funding = test_payment(50000); // single key funding
        let dest = test_destination(5000);

        let config = TransferConfig {
            token_utxo: token,
            destination: dest,
            redemption_pkh: redemption_pkh(),
            splittable: true,
            funding,
            fee_rate: 500,
        };

        let tx = build_transfer_tx(&config).unwrap();
        assert_eq!(tx.input_count(), 2);
        assert!(tx.inputs[0].unlocking_script.is_some());
        assert!(tx.inputs[1].unlocking_script.is_some());

        // Token input (multisig) should be longer than funding (P2PKH)
        let token_len = tx.inputs[0].unlocking_script.as_ref().unwrap().len();
        let funding_len = tx.inputs[1].unlocking_script.as_ref().unwrap().len();
        assert!(
            token_len > funding_len,
            "multisig token unlock ({}) should be longer than P2PKH funding ({})",
            token_len,
            funding_len
        );
    }

    // -------------------------------------------------------------------
    // Gap 5: BTG rejection of P2MPKH
    // -------------------------------------------------------------------

    #[test]
    fn btg_transfer_rejects_multisig_token_key() {
        use bsv_transaction::template::p2mpkh::MultisigScript;

        let keys: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::new()).collect();
        let pubs: Vec<_> = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(2, pubs).unwrap();
        let mpkh = ms.mpkh();
        let addr = bsv_script::Address::from_public_key_hash(&mpkh, bsv_script::Network::Mainnet);
        let locking = p2pkh::lock(&addr).unwrap();

        let multi_payment = Payment {
            txid: Hash::from_bytes(&[0xcc; 32]).unwrap(),
            vout: 0,
            satoshis: 5000,
            locking_script: locking,
            signing_key: SigningKey::Multi {
                private_keys: vec![keys[0].clone(), keys[1].clone()],
                multisig: ms,
            },
        };

        // Build a fake prev tx for the BTG proof
        let mut prev_tx = Transaction::new();
        let mut prev_input = TransactionInput::new();
        prev_input.source_txid = [0xdd; 32];
        prev_input.unlocking_script = Some(Script::new());
        prev_tx.add_input(prev_input);
        prev_tx.add_output(TransactionOutput {
            satoshis: 5000,
            locking_script: multi_payment.locking_script.clone(),
            change: false,
        });
        let prev_raw = prev_tx.to_bytes();

        let funding = test_payment(50000);
        let dest = test_destination(5000);

        let config = BtgTransferConfig {
            token_utxo: BtgPayment {
                payment: multi_payment,
                prev_raw_tx: prev_raw,
            },
            destination: dest,
            redemption_pkh: redemption_pkh(),
            splittable: true,
            funding,
            fee_rate: 500,
        };

        let result = build_btg_transfer_tx(&config);
        assert!(result.is_err(), "BTG should reject P2MPKH token key");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("P2MPKH") || err_msg.contains("multisig"),
            "error should mention P2MPKH or multisig, got: {}",
            err_msg
        );
    }

    #[test]
    fn btg_checkpoint_rejects_multisig_token_key() {
        use bsv_transaction::template::p2mpkh::MultisigScript;

        let keys: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::new()).collect();
        let pubs: Vec<_> = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(2, pubs).unwrap();
        let mpkh = ms.mpkh();
        let addr = bsv_script::Address::from_public_key_hash(&mpkh, bsv_script::Network::Mainnet);
        let locking = p2pkh::lock(&addr).unwrap();

        let multi_payment = Payment {
            txid: Hash::from_bytes(&[0xcc; 32]).unwrap(),
            vout: 0,
            satoshis: 5000,
            locking_script: locking,
            signing_key: SigningKey::Multi {
                private_keys: vec![keys[0].clone(), keys[1].clone()],
                multisig: ms,
            },
        };

        let issuer_key = PrivateKey::new();
        let funding = test_payment(50000);
        let dest = test_destination(5000);

        let config = BtgCheckpointConfig {
            token_utxo: multi_payment,
            issuer_private_key: issuer_key,
            destination: dest,
            redemption_pkh: redemption_pkh(),
            splittable: true,
            funding,
            fee_rate: 500,
        };

        let result = build_btg_checkpoint_tx(&config);
        assert!(result.is_err(), "BTG checkpoint should reject P2MPKH token key");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("P2MPKH") || err_msg.contains("multisig"),
            "error should mention P2MPKH or multisig, got: {}",
            err_msg
        );
    }
}
