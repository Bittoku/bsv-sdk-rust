//! STAS3 transaction factories.
//!
//! Pure functions that build complete, signed transactions for STAS 3 token
//! operations: two-tx issuance, base spend, freeze, unfreeze, swap, split,
//! merge, confiscation, and redeem.

use bsv_primitives::chainhash::Hash;
use bsv_primitives::ec::PrivateKey;
use bsv_script::opcodes::{OP_FALSE, OP_RETURN};
use bsv_script::Script;
use bsv_transaction::input::TransactionInput;
use bsv_transaction::output::TransactionOutput;
use bsv_transaction::template::{p2pkh, p2mpkh};
use bsv_transaction::template::UnlockingScriptTemplate;
use bsv_transaction::transaction::Transaction;

use crate::error::TokenError;
use crate::scheme::TokenScheme;
use crate::script::stas3_builder::build_stas3_locking_script;
use crate::script::stas3_swap::{is_stas3_frozen, resolve_stas3_swap_mode};
use crate::template::stas3 as stas3_template;
use crate::types::{Stas3SpendType, Stas3SwapMode, SigningKey};

// -----------------------------------------------------------------------
// Config structs
// -----------------------------------------------------------------------

/// A single output in a STAS3 issuance.
pub struct Stas3IssueOutput {
    /// Satoshi value for this token output.
    pub satoshis: u64,
    /// Owner public key hash (20 bytes).
    pub owner_pkh: [u8; 20],
    /// Whether this token is freezable.
    pub freezable: bool,
}

/// Configuration for STAS3 issuance (two-transaction flow).
///
/// Accepts a `SigningKey` for the funding input so that issuance can be
/// performed from either a P2PKH or P2MPKH funding UTXO. The contract
/// output locking script is dispatched accordingly:
/// - `SigningKey::Single` produces a P2PKH contract output.
/// - `SigningKey::Multi` produces a bare multisig (P2MPKH) contract output.
pub struct Stas3IssueConfig {
    /// The token scheme to embed.
    pub scheme: TokenScheme,
    /// Funding UTXO txid.
    pub funding_txid: Hash,
    /// Funding UTXO vout.
    pub funding_vout: u32,
    /// Funding UTXO satoshis.
    pub funding_satoshis: u64,
    /// Funding UTXO locking script.
    pub funding_locking_script: Script,
    /// Signing key for the funding input. Use `SigningKey::Single` for P2PKH
    /// or `SigningKey::Multi` for P2MPKH funding UTXOs.
    pub funding_key: SigningKey,
    /// Token outputs to create.
    pub outputs: Vec<Stas3IssueOutput>,
    /// Fee rate in satoshis per kilobyte.
    pub fee_rate: u64,
}

/// Result of the two-transaction STAS3 issuance flow.
pub struct Stas3IssueTxs {
    /// The contract transaction.
    pub contract_tx: Transaction,
    /// The issue transaction that spends the contract output.
    pub issue_tx: Transaction,
}

/// A token input for STAS3 spend operations.
///
/// For P2PKH-owned tokens, use `SigningKey::Single`.
/// For P2MPKH-owned tokens, use `SigningKey::Multi`.
pub struct TokenInput {
    /// UTXO txid.
    pub txid: Hash,
    /// UTXO vout.
    pub vout: u32,
    /// UTXO satoshis.
    pub satoshis: u64,
    /// UTXO locking script.
    pub locking_script: Script,
    /// Signing credentials for this input.
    pub signing_key: SigningKey,
}

/// Parameters for a STAS3 output in spend operations.
#[derive(Clone)]
pub struct Stas3OutputParams {
    /// Satoshi value.
    pub satoshis: u64,
    /// Owner public key hash.
    pub owner_pkh: [u8; 20],
    /// Redemption public key hash.
    pub redemption_pkh: [u8; 20],
    /// Whether the token is frozen.
    pub frozen: bool,
    /// Whether the token is freezable.
    pub freezable: bool,
    /// Additional service field data.
    pub service_fields: Vec<Vec<u8>>,
    /// Additional optional data.
    pub optional_data: Vec<Vec<u8>>,
    /// Optional action data (e.g. swap action data for remainder legs).
    pub action_data: Option<crate::types::ActionData>,
}

/// Configuration for a generic STAS3 spend transaction.
pub struct Stas3BaseConfig {
    /// Token inputs (1 or 2).
    pub token_inputs: Vec<TokenInput>,
    /// Fee UTXO txid.
    pub fee_txid: Hash,
    /// Fee UTXO vout.
    pub fee_vout: u32,
    /// Fee UTXO satoshis.
    pub fee_satoshis: u64,
    /// Fee UTXO locking script.
    pub fee_locking_script: Script,
    /// Fee UTXO private key.
    pub fee_private_key: PrivateKey,
    /// Output destinations.
    pub destinations: Vec<Stas3OutputParams>,
    /// Spend type for this transaction.
    pub spend_type: Stas3SpendType,
    /// Fee rate in satoshis per kilobyte.
    pub fee_rate: u64,
}

/// Configuration for a STAS3 split transaction.
///
/// Splits a single STAS input into 1–4 STAS3 outputs while conserving
/// the total token satoshi value. Uses spending type 1 (regular transfer).
pub struct Stas3SplitConfig {
    /// The single STAS token input to split.
    pub token_input: TokenInput,
    /// Fee UTXO txid.
    pub fee_txid: Hash,
    /// Fee UTXO vout.
    pub fee_vout: u32,
    /// Fee UTXO satoshis.
    pub fee_satoshis: u64,
    /// Fee UTXO locking script.
    pub fee_locking_script: Script,
    /// Fee UTXO private key.
    pub fee_private_key: PrivateKey,
    /// Output destinations (1–4).
    pub destinations: Vec<Stas3OutputParams>,
    /// Fee rate in satoshis per kilobyte.
    pub fee_rate: u64,
}

/// Configuration for a STAS3 merge transaction.
///
/// Merges exactly 2 STAS inputs into 1–2 STAS3 outputs while conserving
/// the total token satoshi value. Uses spending type 1 (regular transfer).
pub struct Stas3MergeConfig {
    /// Exactly 2 STAS token inputs to merge.
    pub token_inputs: [TokenInput; 2],
    /// Fee UTXO txid.
    pub fee_txid: Hash,
    /// Fee UTXO vout.
    pub fee_vout: u32,
    /// Fee UTXO satoshis.
    pub fee_satoshis: u64,
    /// Fee UTXO locking script.
    pub fee_locking_script: Script,
    /// Fee UTXO private key.
    pub fee_private_key: PrivateKey,
    /// Output destinations (1–2).
    pub destinations: Vec<Stas3OutputParams>,
    /// Fee rate in satoshis per kilobyte.
    pub fee_rate: u64,
}

/// Configuration for a STAS3 confiscation transaction.
///
/// Confiscates 1–2 STAS 3.0 inputs using spending type 3 (confiscation authority
/// path). Frozen inputs may be confiscated. The confiscation flag (0x02) must
/// be enabled in the token scheme.
pub struct Stas3ConfiscateConfig {
    /// Token inputs (1 or 2) to confiscate.
    pub token_inputs: Vec<TokenInput>,
    /// Fee UTXO txid.
    pub fee_txid: Hash,
    /// Fee UTXO vout.
    pub fee_vout: u32,
    /// Fee UTXO satoshis.
    pub fee_satoshis: u64,
    /// Fee UTXO locking script.
    pub fee_locking_script: Script,
    /// Fee UTXO private key.
    pub fee_private_key: PrivateKey,
    /// Output destinations (redirected to authority/issuer).
    pub destinations: Vec<Stas3OutputParams>,
    /// Fee rate in satoshis per kilobyte.
    pub fee_rate: u64,
}

/// Classification of redeem output address type.
///
/// Controls whether the redeem output uses a P2PKH or P2MPKH (bare multisig)
/// locking script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RedeemAddressType {
    /// Standard Pay-to-Public-Key-Hash redeem output (default).
    #[default]
    P2pkh,
    /// Pay-to-Multiple-Public-Key-Hash (bare multisig) redeem output.
    P2mpkh,
}

/// Configuration for a STAS3 redeem transaction.
///
/// Redeems a single STAS token by returning its satoshis to a P2PKH or
/// P2MPKH output. Only the token issuer (owner_pkh == redemption_pkh) may
/// redeem. Frozen tokens cannot be redeemed. Uses spending type 1 (regular
/// transfer).
///
/// Conservation: `stas_input_sats == redeem_sats + sum(remaining STAS outputs)`.
pub struct Stas3RedeemConfig {
    /// The single STAS token input to redeem.
    pub token_input: TokenInput,
    /// Fee UTXO txid.
    pub fee_txid: Hash,
    /// Fee UTXO vout.
    pub fee_vout: u32,
    /// Fee UTXO satoshis.
    pub fee_satoshis: u64,
    /// Fee UTXO locking script.
    pub fee_locking_script: Script,
    /// Fee UTXO private key.
    pub fee_private_key: PrivateKey,
    /// Satoshis to redeem to the redeem output.
    pub redeem_satoshis: u64,
    /// Public key hash of the redemption address (must match the token's
    /// `redemption_pkh`, which must also match the token input `owner_pkh`).
    pub redemption_pkh: [u8; 20],
    /// Whether the token input is frozen (must be false — frozen tokens
    /// cannot be redeemed).
    pub input_frozen: bool,
    /// Optional remaining STAS outputs (partial redeem).
    pub remaining_outputs: Vec<Stas3OutputParams>,
    /// Fee rate in satoshis per kilobyte.
    pub fee_rate: u64,
    /// Address type for the redeem output. Defaults to P2PKH. Set to
    /// `RedeemAddressType::P2mpkh` for multisig-owned redemptions — requires
    /// the token input `signing_key` to be `SigningKey::Multi` so the
    /// multisig script can be extracted.
    pub redeem_address_type: RedeemAddressType,
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

/// Estimate transaction size.
fn estimate_size(num_inputs: usize, outputs: &[TransactionOutput]) -> usize {
    let mut size = 4 + 1 + 1 + 4;
    size += num_inputs * (32 + 4 + 1 + 106 + 4);
    for output in outputs {
        size += 8 + 1 + output.locking_script.len();
    }
    size
}

/// Produce a locking script appropriate for the given signing key.
///
/// Dispatches to P2PKH for `SigningKey::Single` and bare multisig
/// (P2MPKH) for `SigningKey::Multi`.
fn lock_from_signing_key(key: &SigningKey) -> Result<Script, TokenError> {
    match key {
        SigningKey::Single(pk) => {
            let pkh = bsv_primitives::hash::hash160(&pk.pub_key().to_compressed());
            let addr = bsv_script::Address::from_public_key_hash(
                &pkh,
                bsv_script::Network::Mainnet,
            );
            Ok(p2pkh::lock(&addr)?)
        }
        SigningKey::Multi { multisig, .. } => Ok(p2mpkh::lock(multisig)?),
    }
}

/// Sign a transaction input using the appropriate template for the key.
///
/// Dispatches to P2PKH unlocking for `SigningKey::Single` and P2MPKH
/// unlocking for `SigningKey::Multi`.
fn sign_with_key(
    key: &SigningKey,
    tx: &mut Transaction,
    input_index: usize,
) -> Result<(), TokenError> {
    match key {
        SigningKey::Single(pk) => {
            let unlocker = p2pkh::unlock(pk.clone(), None);
            let sig = unlocker.sign(tx, input_index as u32)?;
            tx.inputs[input_index].unlocking_script = Some(sig);
        }
        SigningKey::Multi {
            private_keys,
            multisig,
        } => {
            let unlocker = p2mpkh::unlock(private_keys.clone(), multisig.clone(), None)?;
            let sig = unlocker.sign(tx, input_index as u32)?;
            tx.inputs[input_index].unlocking_script = Some(sig);
        }
    }
    Ok(())
}

/// Add a change output using the signing key to derive the change address.
///
/// Works like [`add_fee_change`] but dispatches locking script type based
/// on the `SigningKey` variant (P2PKH or P2MPKH).
fn add_fee_change_from_key(
    tx: &mut Transaction,
    fee_satoshis: u64,
    key: &SigningKey,
    fee_rate: u64,
) -> Result<(), TokenError> {
    let est_size = estimate_size(tx.inputs.len(), &tx.outputs) + 34;
    let fee = (est_size as u64 * fee_rate).div_ceil(1000);

    if fee_satoshis < fee {
        return Err(TokenError::InsufficientFunds {
            needed: fee,
            available: fee_satoshis,
        });
    }

    let change = fee_satoshis - fee;
    if change > 0 {
        let change_script = lock_from_signing_key(key)?;
        tx.add_output(TransactionOutput {
            satoshis: change,
            locking_script: change_script,
            change: true,
        });
    }

    Ok(())
}

/// Add a change output for the fee payer. Returns error if insufficient funds.
fn add_fee_change(
    tx: &mut Transaction,
    fee_satoshis: u64,
    fee_private_key: &PrivateKey,
    fee_rate: u64,
) -> Result<(), TokenError> {
    let est_size = estimate_size(tx.inputs.len(), &tx.outputs) + 34;
    let fee = (est_size as u64 * fee_rate).div_ceil(1000);

    if fee_satoshis < fee {
        return Err(TokenError::InsufficientFunds {
            needed: fee,
            available: fee_satoshis,
        });
    }

    let change = fee_satoshis - fee;
    if change > 0 {
        let change_address = bsv_script::Address::from_public_key_hash(
            &bsv_primitives::hash::hash160(&fee_private_key.pub_key().to_compressed()),
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

// -----------------------------------------------------------------------
// Factory functions
// -----------------------------------------------------------------------

/// Build the two-transaction STAS3 issuance flow.
///
/// # Transaction 1 (Contract TX)
/// - Input 0: Funding UTXO (P2PKH)
/// - Output 0: P2PKH contract output (total token satoshis)
/// - Output 1: OP_RETURN with scheme JSON
/// - Output 2: Change
///
/// # Transaction 2 (Issue TX)
/// - Input 0: Contract output from TX 1
/// - Input 1: Change output from TX 1 (for fees)
/// - Outputs 0..N-1: STAS3 token outputs
/// - Output N: Change
pub fn build_stas3_issue_txs(config: &Stas3IssueConfig) -> Result<Stas3IssueTxs, TokenError> {
    if config.outputs.is_empty() {
        return Err(TokenError::InvalidDestination(
            "at least one output required for STAS3 issuance".into(),
        ));
    }

    let total_tokens: u64 = config.outputs.iter().map(|o| o.satoshis).sum();
    if total_tokens == 0 {
        return Err(TokenError::InvalidDestination(
            "total token satoshis must be > 0".into(),
        ));
    }

    // Derive issuer hash from funding key (PKH for Single, MPKH for Multi).
    let issuer_pkh = config.funding_key.hash160();

    // --- Contract TX ---
    let mut contract_tx = Transaction::new();

    // Funding input
    let mut fund_input = TransactionInput::new();
    fund_input.source_txid = *config.funding_txid.as_bytes();
    fund_input.source_tx_out_index = config.funding_vout;
    fund_input.set_source_output(Some(TransactionOutput {
        satoshis: config.funding_satoshis,
        locking_script: config.funding_locking_script.clone(),
        change: false,
    }));
    contract_tx.add_input(fund_input);

    // Output 0: contract locking script — P2PKH for single key, bare
    // multisig for multi key. The contract output holds the total token
    // satoshis and is spent by the issue TX.
    let contract_script = lock_from_signing_key(&config.funding_key)?;
    contract_tx.add_output(TransactionOutput {
        satoshis: total_tokens,
        locking_script: contract_script,
        change: false,
    });

    // Output 1: OP_RETURN scheme
    let scheme_bytes = config.scheme.to_bytes()?;
    let mut op_return_script = Script::new();
    op_return_script.append_opcodes(&[OP_FALSE, OP_RETURN])?;
    op_return_script.append_push_data(&scheme_bytes)?;
    contract_tx.add_output(TransactionOutput {
        satoshis: 0,
        locking_script: op_return_script,
        change: false,
    });

    // Estimate fee for contract TX
    let est_size = estimate_size(1, &contract_tx.outputs) + 34;
    let contract_fee = (est_size as u64 * config.fee_rate).div_ceil(1000);

    let needed = total_tokens + contract_fee;
    if config.funding_satoshis < needed {
        return Err(TokenError::InsufficientFunds {
            needed,
            available: config.funding_satoshis,
        });
    }

    let contract_change = config.funding_satoshis - total_tokens - contract_fee;
    if contract_change > 0 {
        let change_script = lock_from_signing_key(&config.funding_key)?;
        contract_tx.add_output(TransactionOutput {
            satoshis: contract_change,
            locking_script: change_script,
            change: true,
        });
    }

    // Sign contract TX — dispatch based on signing key variant.
    sign_with_key(&config.funding_key, &mut contract_tx, 0)?;

    // --- Issue TX ---
    let contract_txid = Hash::from_bytes(&contract_tx.tx_id())
        .map_err(|e| TokenError::InvalidScript(format!("txid error: {e}")))?;

    let mut issue_tx = Transaction::new();

    // Input 0: contract output
    let contract_output_script = lock_from_signing_key(&config.funding_key)?;
    let mut contract_input = TransactionInput::new();
    contract_input.source_txid = *contract_txid.as_bytes();
    contract_input.source_tx_out_index = 0;
    contract_input.set_source_output(Some(TransactionOutput {
        satoshis: total_tokens,
        locking_script: contract_output_script,
        change: false,
    }));
    issue_tx.add_input(contract_input);

    // Input 1: change from contract TX (for fees) — only if there was change
    let fee_available = if contract_change > 0 {
        let change_script = lock_from_signing_key(&config.funding_key)?;
        let mut change_input = TransactionInput::new();
        change_input.source_txid = *contract_txid.as_bytes();
        change_input.source_tx_out_index = 2; // change is output index 2
        change_input.set_source_output(Some(TransactionOutput {
            satoshis: contract_change,
            locking_script: change_script,
            change: false,
        }));
        issue_tx.add_input(change_input);
        contract_change
    } else {
        0
    };

    // Derive redemption PKH from scheme.token_id
    let redemption_pkh = issuer_pkh;

    // STAS3 token outputs
    for out in &config.outputs {
        let locking = build_stas3_locking_script(
            &out.owner_pkh,
            &redemption_pkh,
            None,
            false,
            out.freezable,
            &[],
            &[],
        )?;
        issue_tx.add_output(TransactionOutput {
            satoshis: out.satoshis,
            locking_script: locking,
            change: false,
        });
    }

    // Issue TX fee change
    if fee_available > 0 {
        add_fee_change_from_key(
            &mut issue_tx,
            fee_available,
            &config.funding_key,
            config.fee_rate,
        )?;
    }

    // Sign issue TX — all inputs use the same funding key (P2PKH or P2MPKH).
    for i in 0..issue_tx.inputs.len() {
        sign_with_key(&config.funding_key, &mut issue_tx, i)?;
    }

    Ok(Stas3IssueTxs {
        contract_tx,
        issue_tx,
    })
}

/// Build a generic STAS3 spend transaction.
///
/// # Transaction structure
/// - Inputs 0..N-1: Token inputs (STAS3, signed with STAS3 template)
/// - Input N: Fee input (P2PKH)
/// - Outputs 0..M-1: STAS3 token outputs
/// - Output M: Fee change
pub fn build_stas3_base_tx(config: &Stas3BaseConfig) -> Result<Transaction, TokenError> {
    if config.destinations.is_empty() {
        return Err(TokenError::InvalidDestination(
            "at least one destination required".into(),
        ));
    }

    if config.token_inputs.is_empty() || config.token_inputs.len() > 2 {
        return Err(TokenError::InvalidDestination(
            "STAS3 base tx requires 1 or 2 token inputs".into(),
        ));
    }

    let total_token_in: u64 = config.token_inputs.iter().map(|i| i.satoshis).sum();
    let total_token_out: u64 = config.destinations.iter().map(|d| d.satoshis).sum();
    if total_token_in != total_token_out {
        return Err(TokenError::AmountMismatch {
            expected: total_token_in,
            actual: total_token_out,
        });
    }

    let mut tx = Transaction::new();

    // Token inputs
    for ti in &config.token_inputs {
        let mut input = TransactionInput::new();
        input.source_txid = *ti.txid.as_bytes();
        input.source_tx_out_index = ti.vout;
        input.set_source_output(Some(TransactionOutput {
            satoshis: ti.satoshis,
            locking_script: ti.locking_script.clone(),
            change: false,
        }));
        tx.add_input(input);
    }

    // Fee input
    let mut fee_input = TransactionInput::new();
    fee_input.source_txid = *config.fee_txid.as_bytes();
    fee_input.source_tx_out_index = config.fee_vout;
    fee_input.set_source_output(Some(TransactionOutput {
        satoshis: config.fee_satoshis,
        locking_script: config.fee_locking_script.clone(),
        change: false,
    }));
    tx.add_input(fee_input);

    // STAS3 outputs
    for dest in &config.destinations {
        let locking = build_stas3_locking_script(
            &dest.owner_pkh,
            &dest.redemption_pkh,
            dest.action_data.as_ref(),
            dest.frozen,
            dest.freezable,
            &dest.service_fields,
            &dest.optional_data,
        )?;
        tx.add_output(TransactionOutput {
            satoshis: dest.satoshis,
            locking_script: locking,
            change: false,
        });
    }

    // Fee change
    add_fee_change(
        &mut tx,
        config.fee_satoshis,
        &config.fee_private_key,
        config.fee_rate,
    )?;

    // Sign token inputs with STAS3 template (dispatches P2PKH vs P2MPKH).
    for (i, ti) in config.token_inputs.iter().enumerate() {
        let unlocker = stas3_template::unlock_from_signing_key(
            &ti.signing_key, config.spend_type, None,
        )?;
        let sig = unlocker.sign(&tx, i as u32)?;
        tx.inputs[i].unlocking_script = Some(sig);
    }

    // Sign fee input with P2PKH
    let fee_idx = config.token_inputs.len();
    let p2pkh_unlocker = p2pkh::unlock(config.fee_private_key.clone(), None);
    let fee_sig = p2pkh_unlocker.sign(&tx, fee_idx as u32)?;
    tx.inputs[fee_idx].unlocking_script = Some(fee_sig);

    Ok(tx)
}

/// Build a STAS3 freeze transaction.
///
/// Wrapper around [`build_stas3_base_tx`] that sets `frozen = true` on all outputs
/// and uses `Stas3SpendType::FreezeUnfreeze`.
pub fn build_stas3_freeze_tx(config: &mut Stas3BaseConfig) -> Result<Transaction, TokenError> {
    config.spend_type = Stas3SpendType::FreezeUnfreeze;
    for dest in &mut config.destinations {
        dest.frozen = true;
    }
    build_stas3_base_tx(config)
}

/// Build a STAS3 unfreeze transaction.
///
/// Wrapper around [`build_stas3_base_tx`] that sets `frozen = false` on all outputs
/// and uses `Stas3SpendType::FreezeUnfreeze`.
pub fn build_stas3_unfreeze_tx(config: &mut Stas3BaseConfig) -> Result<Transaction, TokenError> {
    config.spend_type = Stas3SpendType::FreezeUnfreeze;
    for dest in &mut config.destinations {
        dest.frozen = false;
    }
    build_stas3_base_tx(config)
}

/// Build a STAS3 transfer-swap transaction.
///
/// One input is spent via the regular transfer path (spending type 1),
/// the other is consumed via swap matching. Requires exactly 2 token inputs.
/// Frozen inputs are rejected.
///
/// Outputs can be 2–4: principal swap legs (ownership exchanged) plus
/// optional remainder outputs for fractional-rate swaps.
pub fn build_stas3_transfer_swap_tx(
    config: &mut Stas3BaseConfig,
) -> Result<Transaction, TokenError> {
    validate_swap_inputs(config)?;
    config.spend_type = Stas3SpendType::Transfer;
    build_stas3_base_tx(config)
}

/// Build a STAS3 swap-swap transaction.
///
/// Both inputs have swap action data and are spent via the swap path
/// (spending type 4). Requires exactly 2 token inputs.
/// Frozen inputs are rejected.
///
/// Outputs can be 2–4: principal swap legs (ownership exchanged) plus
/// optional remainder outputs for fractional-rate swaps.
pub fn build_stas3_swap_swap_tx(
    config: &mut Stas3BaseConfig,
) -> Result<Transaction, TokenError> {
    validate_swap_inputs(config)?;
    config.spend_type = Stas3SpendType::SwapCancellation;
    build_stas3_base_tx(config)
}

/// Build a STAS3 swap flow transaction with auto-detected mode.
///
/// Inspects both input locking scripts to determine whether this is a
/// transfer-swap (one side transfers) or swap-swap (both sides have swap
/// action data). Delegates to the appropriate builder.
///
/// Requires exactly 2 token inputs. Frozen inputs are rejected.
pub fn build_stas3_swap_flow_tx(config: &mut Stas3BaseConfig) -> Result<Transaction, TokenError> {
    if config.token_inputs.len() != 2 {
        return Err(TokenError::InvalidDestination(
            "swap flow requires exactly 2 token inputs".into(),
        ));
    }

    let mode = resolve_stas3_swap_mode(
        config.token_inputs[0].locking_script.to_bytes(),
        config.token_inputs[1].locking_script.to_bytes(),
    );

    match mode {
        Stas3SwapMode::SwapSwap => build_stas3_swap_swap_tx(config),
        Stas3SwapMode::TransferSwap => build_stas3_transfer_swap_tx(config),
    }
}

/// Validate swap inputs: exactly 2, none frozen.
fn validate_swap_inputs(config: &Stas3BaseConfig) -> Result<(), TokenError> {
    if config.token_inputs.len() != 2 {
        return Err(TokenError::InvalidDestination(
            "swap requires exactly 2 token inputs".into(),
        ));
    }

    for ti in &config.token_inputs {
        if is_stas3_frozen(ti.locking_script.to_bytes()) {
            return Err(TokenError::FrozenToken);
        }
    }

    Ok(())
}

/// Build a STAS3 split transaction.
///
/// Splits a single STAS token input into 1–4 STAS3 outputs. The total
/// satoshi value across all outputs must equal the input value (conservation).
///
/// # Errors
///
/// Returns [`TokenError::InvalidDestination`] if destinations is empty or
/// exceeds 4, and propagates any error from [`build_stas3_base_tx`].
pub fn build_stas3_split_tx(config: Stas3SplitConfig) -> Result<Transaction, TokenError> {
    if config.destinations.is_empty() || config.destinations.len() > 4 {
        return Err(TokenError::InvalidDestination(
            "split requires 1–4 destinations".into(),
        ));
    }

    let base = Stas3BaseConfig {
        token_inputs: vec![config.token_input],
        fee_txid: config.fee_txid,
        fee_vout: config.fee_vout,
        fee_satoshis: config.fee_satoshis,
        fee_locking_script: config.fee_locking_script,
        fee_private_key: config.fee_private_key,
        destinations: config.destinations,
        spend_type: Stas3SpendType::Transfer,
        fee_rate: config.fee_rate,
    };

    build_stas3_base_tx(&base)
}

/// Build a STAS3 merge transaction.
///
/// Merges exactly 2 STAS token inputs into 1–2 STAS3 outputs. The combined
/// input value must equal the total output value (conservation).
///
/// # Errors
///
/// Returns [`TokenError::InvalidDestination`] if destinations is empty or
/// exceeds 2, and propagates any error from [`build_stas3_base_tx`].
pub fn build_stas3_merge_tx(config: Stas3MergeConfig) -> Result<Transaction, TokenError> {
    if config.destinations.is_empty() || config.destinations.len() > 2 {
        return Err(TokenError::InvalidDestination(
            "merge requires 1–2 destinations".into(),
        ));
    }

    let [input_a, input_b] = config.token_inputs;
    let base = Stas3BaseConfig {
        token_inputs: vec![input_a, input_b],
        fee_txid: config.fee_txid,
        fee_vout: config.fee_vout,
        fee_satoshis: config.fee_satoshis,
        fee_locking_script: config.fee_locking_script,
        fee_private_key: config.fee_private_key,
        destinations: config.destinations,
        spend_type: Stas3SpendType::Transfer,
        fee_rate: config.fee_rate,
    };

    build_stas3_base_tx(&base)
}

/// Build a STAS3 confiscation transaction.
///
/// Confiscates 1–2 STAS token inputs using the confiscation authority path
/// (spending type 3). Frozen tokens *can* be confiscated. The token scheme
/// must have the confiscation flag (0x02) enabled.
///
/// # Errors
///
/// Returns [`TokenError::InvalidDestination`] if `token_inputs` is empty,
/// and propagates any error from [`build_stas3_base_tx`].
pub fn build_stas3_confiscate_tx(config: Stas3ConfiscateConfig) -> Result<Transaction, TokenError> {
    if config.token_inputs.is_empty() {
        return Err(TokenError::InvalidDestination(
            "confiscation requires at least 1 token input".into(),
        ));
    }

    let base = Stas3BaseConfig {
        token_inputs: config.token_inputs,
        fee_txid: config.fee_txid,
        fee_vout: config.fee_vout,
        fee_satoshis: config.fee_satoshis,
        fee_locking_script: config.fee_locking_script,
        fee_private_key: config.fee_private_key,
        destinations: config.destinations,
        spend_type: Stas3SpendType::Confiscation,
        fee_rate: config.fee_rate,
    };

    build_stas3_base_tx(&base)
}

/// Build a STAS3 redeem transaction.
///
/// Redeems a single STAS token input by sending part or all of its satoshis
/// to a P2PKH output. Only the token issuer may redeem (the input `owner_pkh`
/// must match the token's `redemption_pkh`). Frozen tokens cannot be redeemed.
///
/// # Transaction structure
/// - Input 0: STAS token input
/// - Input 1: Fee input (P2PKH)
/// - Output 0: P2PKH redeem output (`redeem_satoshis`)
/// - Outputs 1..N: Optional remaining STAS3 outputs (partial redeem)
/// - Output N+1: Fee change (P2PKH)
///
/// # Conservation
/// `token_input.satoshis == redeem_satoshis + sum(remaining STAS3 outputs)`
///
/// # Errors
///
/// - [`TokenError::FrozenToken`] if `input_frozen` is true.
/// - [`TokenError::IssuerOnly`] if the token input owner is not the issuer.
/// - [`TokenError::AmountMismatch`] if conservation is violated.
/// - [`TokenError::InvalidDestination`] if `redeem_satoshis` is zero.
pub fn build_stas3_redeem_tx(config: Stas3RedeemConfig) -> Result<Transaction, TokenError> {
    // Frozen tokens cannot be redeemed
    if config.input_frozen {
        return Err(TokenError::FrozenToken);
    }

    // Redeem amount must be positive
    if config.redeem_satoshis == 0 {
        return Err(TokenError::InvalidDestination(
            "redeem satoshis must be > 0".into(),
        ));
    }

    // Conservation check: stas_in == redeem + remaining STAS outputs
    let remaining_sats: u64 = config.remaining_outputs.iter().map(|d| d.satoshis).sum();
    let total_out = config
        .redeem_satoshis
        .checked_add(remaining_sats)
        .ok_or_else(|| TokenError::InvalidDestination("satoshi overflow".into()))?;

    if config.token_input.satoshis != total_out {
        return Err(TokenError::AmountMismatch {
            expected: config.token_input.satoshis,
            actual: total_out,
        });
    }

    // Issuer-only check: we need the token input owner hash to match redemption_pkh.
    // For P2PKH this is HASH160(pubkey), for P2MPKH this is the MPKH.
    let owner_pkh = config.token_input.signing_key.hash160();
    if owner_pkh != config.redemption_pkh {
        return Err(TokenError::IssuerOnly(
            "token input owner must be the issuer (redemption_pkh)".into(),
        ));
    }

    let mut tx = Transaction::new();

    // Input 0: STAS token
    let mut token_in = TransactionInput::new();
    token_in.source_txid = *config.token_input.txid.as_bytes();
    token_in.source_tx_out_index = config.token_input.vout;
    token_in.set_source_output(Some(TransactionOutput {
        satoshis: config.token_input.satoshis,
        locking_script: config.token_input.locking_script.clone(),
        change: false,
    }));
    tx.add_input(token_in);

    // Input 1: Fee (P2PKH)
    let mut fee_input = TransactionInput::new();
    fee_input.source_txid = *config.fee_txid.as_bytes();
    fee_input.source_tx_out_index = config.fee_vout;
    fee_input.set_source_output(Some(TransactionOutput {
        satoshis: config.fee_satoshis,
        locking_script: config.fee_locking_script.clone(),
        change: false,
    }));
    tx.add_input(fee_input);

    // Output 0: redeem output — dispatched by address type.
    let redeem_script = match config.redeem_address_type {
        RedeemAddressType::P2pkh => {
            let redeem_address = bsv_script::Address::from_public_key_hash(
                &config.redemption_pkh,
                bsv_script::Network::Mainnet,
            );
            p2pkh::lock(&redeem_address)?
        }
        RedeemAddressType::P2mpkh => {
            // Extract the multisig script from the token input's signing key.
            // P2MPKH redeem requires the signing key to carry the multisig
            // configuration so we can produce the bare multisig locking script.
            match &config.token_input.signing_key {
                SigningKey::Multi { multisig, .. } => p2mpkh::lock(multisig)?,
                SigningKey::Single(_) => {
                    return Err(TokenError::InvalidScript(
                        "P2MPKH redeem requires a Multi signing key".into(),
                    ));
                }
            }
        }
    };
    tx.add_output(TransactionOutput {
        satoshis: config.redeem_satoshis,
        locking_script: redeem_script,
        change: false,
    });

    // Outputs 1..N: Remaining STAS3 outputs (partial redeem)
    for dest in &config.remaining_outputs {
        let locking = build_stas3_locking_script(
            &dest.owner_pkh,
            &dest.redemption_pkh,
            None,
            dest.frozen,
            dest.freezable,
            &dest.service_fields,
            &dest.optional_data,
        )?;
        tx.add_output(TransactionOutput {
            satoshis: dest.satoshis,
            locking_script: locking,
            change: false,
        });
    }

    // Fee change
    add_fee_change(
        &mut tx,
        config.fee_satoshis,
        &config.fee_private_key,
        config.fee_rate,
    )?;

    // Sign token input with STAS3 template (spending type 1 = Transfer).
    let unlocker = stas3_template::unlock_from_signing_key(
        &config.token_input.signing_key,
        Stas3SpendType::Transfer,
        None,
    )?;
    let sig = unlocker.sign(&tx, 0)?;
    tx.inputs[0].unlocking_script = Some(sig);

    // Sign fee input with P2PKH
    let p2pkh_unlocker = p2pkh::unlock(config.fee_private_key.clone(), None);
    let fee_sig = p2pkh_unlocker.sign(&tx, 1)?;
    tx.inputs[1].unlocking_script = Some(fee_sig);

    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_primitives::chainhash::Hash;
    use bsv_primitives::ec::PrivateKey;
    use crate::scheme::{Authority, TokenScheme};
    use crate::token_id::TokenId;
    use crate::script::reader::read_locking_script;
    use crate::ScriptType;

    fn test_key() -> PrivateKey {
        PrivateKey::new()
    }

    fn test_p2pkh_script(key: &PrivateKey) -> Script {
        let pkh = bsv_primitives::hash::hash160(&key.pub_key().to_compressed());
        let addr = bsv_script::Address::from_public_key_hash(&pkh, bsv_script::Network::Mainnet);
        p2pkh::lock(&addr).unwrap()
    }

    fn dummy_hash() -> Hash {
        Hash::from_bytes(&[0xaa; 32]).unwrap()
    }

    fn test_scheme() -> TokenScheme {
        TokenScheme {
            name: "TestSTAS3".into(),
            token_id: TokenId::from_pkh([0xaa; 20]),
            symbol: "TSTAS3".into(),
            satoshis_per_token: 1,
            freeze: true,
            confiscation: false,
            is_divisible: true,
            authority: Authority {
                m: 1,
                public_keys: vec!["02abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab".into()],
            },
        }
    }

    fn make_stas3_locking(owner_pkh: &[u8; 20], redemption_pkh: &[u8; 20]) -> Script {
        build_stas3_locking_script(owner_pkh, redemption_pkh, None, false, true, &[], &[]).unwrap()
    }

    // ---------------------------------------------------------------
    // Issue flow tests
    // ---------------------------------------------------------------

    #[test]
    fn issue_txs_structure() {
        let key = test_key();
        let config = Stas3IssueConfig {
            scheme: test_scheme(),
            funding_txid: dummy_hash(),
            funding_vout: 0,
            funding_satoshis: 100_000,
            funding_locking_script: test_p2pkh_script(&key),
            funding_key: SigningKey::Single(key),
            outputs: vec![
                Stas3IssueOutput {
                    satoshis: 5000,
                    owner_pkh: [0x11; 20],
                    freezable: true,
                },
                Stas3IssueOutput {
                    satoshis: 5000,
                    owner_pkh: [0x22; 20],
                    freezable: false,
                },
            ],
            fee_rate: 500,
        };

        let result = build_stas3_issue_txs(&config).unwrap();

        // Contract TX: 1 input, 2-3 outputs (contract + OP_RETURN + optional change)
        assert_eq!(result.contract_tx.input_count(), 1);
        assert!(result.contract_tx.output_count() >= 2);
        assert_eq!(result.contract_tx.outputs[0].satoshis, 10000);
        assert_eq!(result.contract_tx.outputs[1].satoshis, 0); // OP_RETURN

        // Issue TX: 1-2 inputs, 2-3 outputs (tokens + optional change)
        assert!(result.issue_tx.input_count() >= 1);
        assert!(result.issue_tx.output_count() >= 2);
        assert_eq!(result.issue_tx.outputs[0].satoshis, 5000);
        assert_eq!(result.issue_tx.outputs[1].satoshis, 5000);

        // All inputs should be signed
        for input in &result.contract_tx.inputs {
            assert!(input.unlocking_script.is_some());
        }
        for input in &result.issue_tx.inputs {
            assert!(input.unlocking_script.is_some());
        }
    }

    #[test]
    fn issue_txid_chaining() {
        let key = test_key();
        let config = Stas3IssueConfig {
            scheme: test_scheme(),
            funding_txid: dummy_hash(),
            funding_vout: 0,
            funding_satoshis: 100_000,
            funding_locking_script: test_p2pkh_script(&key),
            funding_key: SigningKey::Single(key),
            outputs: vec![Stas3IssueOutput {
                satoshis: 10000,
                owner_pkh: [0x11; 20],
                freezable: true,
            }],
            fee_rate: 500,
        };

        let result = build_stas3_issue_txs(&config).unwrap();

        // Issue TX input 0 should reference contract TX's txid
        let contract_txid = result.contract_tx.tx_id();
        assert_eq!(result.issue_tx.inputs[0].source_txid, contract_txid);
    }

    #[test]
    fn issue_empty_outputs_rejected() {
        let key = test_key();
        let config = Stas3IssueConfig {
            scheme: test_scheme(),
            funding_txid: dummy_hash(),
            funding_vout: 0,
            funding_satoshis: 100_000,
            funding_locking_script: test_p2pkh_script(&key),
            funding_key: SigningKey::Single(key),
            outputs: vec![],
            fee_rate: 500,
        };

        assert!(build_stas3_issue_txs(&config).is_err());
    }

    #[test]
    fn issue_insufficient_funds() {
        let key = test_key();
        let config = Stas3IssueConfig {
            scheme: test_scheme(),
            funding_txid: dummy_hash(),
            funding_vout: 0,
            funding_satoshis: 100, // too low
            funding_locking_script: test_p2pkh_script(&key),
            funding_key: SigningKey::Single(key),
            outputs: vec![Stas3IssueOutput {
                satoshis: 10000,
                owner_pkh: [0x11; 20],
                freezable: true,
            }],
            fee_rate: 500,
        };

        assert!(build_stas3_issue_txs(&config).is_err());
    }

    // ---------------------------------------------------------------
    // Base TX tests
    // ---------------------------------------------------------------

    #[test]
    fn base_tx_structure() {
        let token_key = test_key();
        let fee_key = test_key();
        let owner_pkh = [0x11; 20];
        let redemption_pkh = [0x22; 20];

        let config = Stas3BaseConfig {
            token_inputs: vec![TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 5000,
                locking_script: make_stas3_locking(&owner_pkh, &redemption_pkh),
                signing_key: SigningKey::Single(token_key),
            }],
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![Stas3OutputParams {
                satoshis: 5000,
                owner_pkh: [0x33; 20],
                redemption_pkh,
                frozen: false,
                freezable: true,
                service_fields: vec![],
                optional_data: vec![],
                action_data: None,
            }],
            spend_type: Stas3SpendType::Transfer,
            fee_rate: 500,
        };

        let tx = build_stas3_base_tx(&config).unwrap();
        assert_eq!(tx.input_count(), 2); // 1 token + 1 fee
        assert!(tx.output_count() >= 1); // 1 token + optional change
        assert_eq!(tx.outputs[0].satoshis, 5000);

        // All signed
        for input in &tx.inputs {
            assert!(input.unlocking_script.is_some());
        }
    }

    #[test]
    fn base_tx_amount_conservation() {
        let token_key = test_key();
        let fee_key = test_key();

        let config = Stas3BaseConfig {
            token_inputs: vec![TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 10000,
                locking_script: make_stas3_locking(&[0x11; 20], &[0x22; 20]),
                signing_key: SigningKey::Single(token_key),
            }],
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![
                Stas3OutputParams {
                    satoshis: 4000,
                    owner_pkh: [0x33; 20],
                    redemption_pkh: [0x22; 20],
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                action_data: None,
                },
                Stas3OutputParams {
                    satoshis: 6000,
                    owner_pkh: [0x44; 20],
                    redemption_pkh: [0x22; 20],
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                action_data: None,
                },
            ],
            spend_type: Stas3SpendType::Transfer,
            fee_rate: 500,
        };

        let tx = build_stas3_base_tx(&config).unwrap();
        // Token outputs should sum to input
        let token_out: u64 = tx.outputs.iter().filter(|o| !o.change).map(|o| o.satoshis).sum();
        assert_eq!(token_out, 10000);
    }

    #[test]
    fn base_tx_amount_mismatch() {
        let token_key = test_key();
        let fee_key = test_key();

        let config = Stas3BaseConfig {
            token_inputs: vec![TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 10000,
                locking_script: make_stas3_locking(&[0x11; 20], &[0x22; 20]),
                signing_key: SigningKey::Single(token_key),
            }],
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![Stas3OutputParams {
                satoshis: 9000, // != 10000
                owner_pkh: [0x33; 20],
                redemption_pkh: [0x22; 20],
                frozen: false,
                freezable: true,
                service_fields: vec![],
                optional_data: vec![],
                action_data: None,
            }],
            spend_type: Stas3SpendType::Transfer,
            fee_rate: 500,
        };

        assert!(build_stas3_base_tx(&config).is_err());
    }

    #[test]
    fn base_tx_empty_destinations() {
        let token_key = test_key();
        let fee_key = test_key();

        let config = Stas3BaseConfig {
            token_inputs: vec![TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 5000,
                locking_script: make_stas3_locking(&[0x11; 20], &[0x22; 20]),
                signing_key: SigningKey::Single(token_key),
            }],
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![],
            spend_type: Stas3SpendType::Transfer,
            fee_rate: 500,
        };

        assert!(build_stas3_base_tx(&config).is_err());
    }

    #[test]
    fn base_tx_too_many_inputs() {
        let fee_key = test_key();

        let config = Stas3BaseConfig {
            token_inputs: vec![
                TokenInput { txid: dummy_hash(), vout: 0, satoshis: 1000, locking_script: make_stas3_locking(&[0x11; 20], &[0x22; 20]), signing_key: SigningKey::Single(test_key()) },
                TokenInput { txid: dummy_hash(), vout: 1, satoshis: 1000, locking_script: make_stas3_locking(&[0x11; 20], &[0x22; 20]), signing_key: SigningKey::Single(test_key()) },
                TokenInput { txid: dummy_hash(), vout: 2, satoshis: 1000, locking_script: make_stas3_locking(&[0x11; 20], &[0x22; 20]), signing_key: SigningKey::Single(test_key()) },
            ],
            fee_txid: dummy_hash(),
            fee_vout: 3,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![Stas3OutputParams {
                satoshis: 3000,
                owner_pkh: [0x33; 20],
                redemption_pkh: [0x22; 20],
                frozen: false,
                freezable: true,
                service_fields: vec![],
                optional_data: vec![],
                action_data: None,
            }],
            spend_type: Stas3SpendType::Transfer,
            fee_rate: 500,
        };

        assert!(build_stas3_base_tx(&config).is_err());
    }

    // ---------------------------------------------------------------
    // Freeze / Unfreeze tests
    // ---------------------------------------------------------------

    #[test]
    fn freeze_tx_output_is_frozen() {
        let token_key = test_key();
        let fee_key = test_key();

        let mut config = Stas3BaseConfig {
            token_inputs: vec![TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 5000,
                locking_script: make_stas3_locking(&[0x11; 20], &[0x22; 20]),
                signing_key: SigningKey::Single(token_key),
            }],
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![Stas3OutputParams {
                satoshis: 5000,
                owner_pkh: [0x33; 20],
                redemption_pkh: [0x22; 20],
                frozen: false, // will be overridden
                freezable: true,
                service_fields: vec![],
                optional_data: vec![],
                action_data: None,
            }],
            spend_type: Stas3SpendType::Transfer, // will be overridden
            fee_rate: 500,
        };

        let tx = build_stas3_freeze_tx(&mut config).unwrap();

        // Parse the first output script to verify frozen
        let parsed = read_locking_script(tx.outputs[0].locking_script.to_bytes());
        assert_eq!(parsed.script_type, ScriptType::Stas3);
        let stas3 = parsed.stas3.unwrap();
        assert!(stas3.frozen);
    }

    #[test]
    fn unfreeze_tx_output_is_not_frozen() {
        let token_key = test_key();
        let fee_key = test_key();

        let mut config = Stas3BaseConfig {
            token_inputs: vec![TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 5000,
                locking_script: make_stas3_locking(&[0x11; 20], &[0x22; 20]),
                signing_key: SigningKey::Single(token_key),
            }],
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![Stas3OutputParams {
                satoshis: 5000,
                owner_pkh: [0x33; 20],
                redemption_pkh: [0x22; 20],
                frozen: true, // will be overridden to false
                freezable: true,
                service_fields: vec![],
                optional_data: vec![],
                action_data: None,
            }],
            spend_type: Stas3SpendType::Transfer,
            fee_rate: 500,
        };

        let tx = build_stas3_unfreeze_tx(&mut config).unwrap();

        let parsed = read_locking_script(tx.outputs[0].locking_script.to_bytes());
        assert_eq!(parsed.script_type, ScriptType::Stas3);
        let stas3 = parsed.stas3.unwrap();
        assert!(!stas3.frozen);
    }

    // ---------------------------------------------------------------
    // Swap flow tests
    // ---------------------------------------------------------------

    #[test]
    fn swap_flow_requires_two_inputs() {
        let fee_key = test_key();

        let mut config = Stas3BaseConfig {
            token_inputs: vec![TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 5000,
                locking_script: make_stas3_locking(&[0x11; 20], &[0x22; 20]),
                signing_key: SigningKey::Single(test_key()),
            }],
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![Stas3OutputParams {
                satoshis: 5000,
                owner_pkh: [0x33; 20],
                redemption_pkh: [0x22; 20],
                frozen: false,
                freezable: true,
                service_fields: vec![],
                optional_data: vec![],
                action_data: None,
            }],
            spend_type: Stas3SpendType::Transfer,
            fee_rate: 500,
        };

        assert!(build_stas3_swap_flow_tx(&mut config).is_err());
    }

    #[test]
    fn swap_flow_with_two_inputs() {
        let fee_key = test_key();

        let mut config = Stas3BaseConfig {
            token_inputs: vec![
                TokenInput {
                    txid: dummy_hash(),
                    vout: 0,
                    satoshis: 3000,
                    locking_script: make_stas3_locking(&[0x11; 20], &[0x22; 20]),
                    signing_key: SigningKey::Single(test_key()),
                },
                TokenInput {
                    txid: dummy_hash(),
                    vout: 1,
                    satoshis: 7000,
                    locking_script: make_stas3_locking(&[0x33; 20], &[0x22; 20]),
                    signing_key: SigningKey::Single(test_key()),
                },
            ],
            fee_txid: dummy_hash(),
            fee_vout: 2,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![
                Stas3OutputParams {
                    satoshis: 3000,
                    owner_pkh: [0x44; 20],
                    redemption_pkh: [0x22; 20],
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                action_data: None,
                },
                Stas3OutputParams {
                    satoshis: 7000,
                    owner_pkh: [0x55; 20],
                    redemption_pkh: [0x22; 20],
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                action_data: None,
                },
            ],
            spend_type: Stas3SpendType::SwapCancellation, // will be overridden
            fee_rate: 500,
        };

        let tx = build_stas3_swap_flow_tx(&mut config).unwrap();
        assert_eq!(tx.input_count(), 3); // 2 token + 1 fee
        assert!(tx.output_count() >= 2);
    }

    // ---------------------------------------------------------------
    // Split tests
    // ---------------------------------------------------------------

    #[test]
    fn split_single_to_two() {
        let token_key = test_key();
        let fee_key = test_key();
        let redemption_pkh = [0x22; 20];

        let config = Stas3SplitConfig {
            token_input: TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 10000,
                locking_script: make_stas3_locking(&[0x11; 20], &redemption_pkh),
                signing_key: SigningKey::Single(token_key),
            },
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![
                Stas3OutputParams {
                    satoshis: 4000,
                    owner_pkh: [0x33; 20],
                    redemption_pkh,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                action_data: None,
                },
                Stas3OutputParams {
                    satoshis: 6000,
                    owner_pkh: [0x44; 20],
                    redemption_pkh,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                action_data: None,
                },
            ],
            fee_rate: 500,
        };

        let tx = build_stas3_split_tx(config).unwrap();
        assert_eq!(tx.input_count(), 2); // 1 token + 1 fee
        assert!(tx.output_count() >= 2); // 2 STAS3 + optional change
        assert_eq!(tx.outputs[0].satoshis, 4000);
        assert_eq!(tx.outputs[1].satoshis, 6000);

        // All signed
        for input in &tx.inputs {
            assert!(input.unlocking_script.is_some());
        }
    }

    #[test]
    fn split_to_four_outputs() {
        let token_key = test_key();
        let fee_key = test_key();
        let redemption_pkh = [0x22; 20];

        let config = Stas3SplitConfig {
            token_input: TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 10000,
                locking_script: make_stas3_locking(&[0x11; 20], &redemption_pkh),
                signing_key: SigningKey::Single(token_key),
            },
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![
                Stas3OutputParams { satoshis: 2500, owner_pkh: [0x33; 20], redemption_pkh, frozen: false, freezable: true, service_fields: vec![], optional_data: vec![], action_data: None },
                Stas3OutputParams { satoshis: 2500, owner_pkh: [0x44; 20], redemption_pkh, frozen: false, freezable: true, service_fields: vec![], optional_data: vec![], action_data: None },
                Stas3OutputParams { satoshis: 2500, owner_pkh: [0x55; 20], redemption_pkh, frozen: false, freezable: true, service_fields: vec![], optional_data: vec![], action_data: None },
                Stas3OutputParams { satoshis: 2500, owner_pkh: [0x66; 20], redemption_pkh, frozen: false, freezable: true, service_fields: vec![], optional_data: vec![], action_data: None },
            ],
            fee_rate: 500,
        };

        let tx = build_stas3_split_tx(config).unwrap();
        assert!(tx.output_count() >= 4);
    }

    #[test]
    fn split_empty_destinations_rejected() {
        let token_key = test_key();
        let fee_key = test_key();

        let config = Stas3SplitConfig {
            token_input: TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 10000,
                locking_script: make_stas3_locking(&[0x11; 20], &[0x22; 20]),
                signing_key: SigningKey::Single(token_key),
            },
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![],
            fee_rate: 500,
        };

        assert!(build_stas3_split_tx(config).is_err());
    }

    #[test]
    fn split_five_destinations_rejected() {
        let token_key = test_key();
        let fee_key = test_key();
        let redemption_pkh = [0x22; 20];

        let dest = Stas3OutputParams {
            satoshis: 2000,
            owner_pkh: [0x33; 20],
            redemption_pkh,
            frozen: false,
            freezable: true,
            service_fields: vec![],
            optional_data: vec![],
                action_data: None,
        };

        let config = Stas3SplitConfig {
            token_input: TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 10000,
                locking_script: make_stas3_locking(&[0x11; 20], &redemption_pkh),
                signing_key: SigningKey::Single(token_key),
            },
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![dest.clone(), dest.clone(), dest.clone(), dest.clone(), dest],
            fee_rate: 500,
        };

        assert!(build_stas3_split_tx(config).is_err());
    }

    #[test]
    fn split_conservation_violation() {
        let token_key = test_key();
        let fee_key = test_key();
        let redemption_pkh = [0x22; 20];

        let config = Stas3SplitConfig {
            token_input: TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 10000,
                locking_script: make_stas3_locking(&[0x11; 20], &redemption_pkh),
                signing_key: SigningKey::Single(token_key),
            },
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![Stas3OutputParams {
                satoshis: 9000, // != 10000
                owner_pkh: [0x33; 20],
                redemption_pkh,
                frozen: false,
                freezable: true,
                service_fields: vec![],
                optional_data: vec![],
                action_data: None,
            }],
            fee_rate: 500,
        };

        assert!(build_stas3_split_tx(config).is_err());
    }

    // ---------------------------------------------------------------
    // Merge tests
    // ---------------------------------------------------------------

    #[test]
    fn merge_two_inputs_to_one() {
        let key_a = test_key();
        let key_b = test_key();
        let fee_key = test_key();
        let redemption_pkh = [0x22; 20];

        let config = Stas3MergeConfig {
            token_inputs: [
                TokenInput {
                    txid: dummy_hash(),
                    vout: 0,
                    satoshis: 3000,
                    locking_script: make_stas3_locking(&[0x11; 20], &redemption_pkh),
                    signing_key: SigningKey::Single(key_a),
                },
                TokenInput {
                    txid: dummy_hash(),
                    vout: 1,
                    satoshis: 7000,
                    locking_script: make_stas3_locking(&[0x33; 20], &redemption_pkh),
                    signing_key: SigningKey::Single(key_b),
                },
            ],
            fee_txid: dummy_hash(),
            fee_vout: 2,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![Stas3OutputParams {
                satoshis: 10000,
                owner_pkh: [0x55; 20],
                redemption_pkh,
                frozen: false,
                freezable: true,
                service_fields: vec![],
                optional_data: vec![],
                action_data: None,
            }],
            fee_rate: 500,
        };

        let tx = build_stas3_merge_tx(config).unwrap();
        assert_eq!(tx.input_count(), 3); // 2 token + 1 fee
        assert!(tx.output_count() >= 1); // 1 STAS3 + optional change
        assert_eq!(tx.outputs[0].satoshis, 10000);

        for input in &tx.inputs {
            assert!(input.unlocking_script.is_some());
        }
    }

    #[test]
    fn merge_empty_destinations_rejected() {
        let fee_key = test_key();
        let redemption_pkh = [0x22; 20];

        let config = Stas3MergeConfig {
            token_inputs: [
                TokenInput { txid: dummy_hash(), vout: 0, satoshis: 3000, locking_script: make_stas3_locking(&[0x11; 20], &redemption_pkh), signing_key: SigningKey::Single(test_key()) },
                TokenInput { txid: dummy_hash(), vout: 1, satoshis: 7000, locking_script: make_stas3_locking(&[0x33; 20], &redemption_pkh), signing_key: SigningKey::Single(test_key()) },
            ],
            fee_txid: dummy_hash(),
            fee_vout: 2,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![],
            fee_rate: 500,
        };

        assert!(build_stas3_merge_tx(config).is_err());
    }

    #[test]
    fn merge_three_destinations_rejected() {
        let fee_key = test_key();
        let redemption_pkh = [0x22; 20];

        let dest = Stas3OutputParams {
            satoshis: 3000,
            owner_pkh: [0x33; 20],
            redemption_pkh,
            frozen: false,
            freezable: true,
            service_fields: vec![],
            optional_data: vec![],
                action_data: None,
        };

        let config = Stas3MergeConfig {
            token_inputs: [
                TokenInput { txid: dummy_hash(), vout: 0, satoshis: 5000, locking_script: make_stas3_locking(&[0x11; 20], &redemption_pkh), signing_key: SigningKey::Single(test_key()) },
                TokenInput { txid: dummy_hash(), vout: 1, satoshis: 4000, locking_script: make_stas3_locking(&[0x33; 20], &redemption_pkh), signing_key: SigningKey::Single(test_key()) },
            ],
            fee_txid: dummy_hash(),
            fee_vout: 2,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![dest.clone(), dest.clone(), dest],
            fee_rate: 500,
        };

        assert!(build_stas3_merge_tx(config).is_err());
    }

    #[test]
    fn merge_conservation_violation() {
        let fee_key = test_key();
        let redemption_pkh = [0x22; 20];

        let config = Stas3MergeConfig {
            token_inputs: [
                TokenInput { txid: dummy_hash(), vout: 0, satoshis: 3000, locking_script: make_stas3_locking(&[0x11; 20], &redemption_pkh), signing_key: SigningKey::Single(test_key()) },
                TokenInput { txid: dummy_hash(), vout: 1, satoshis: 7000, locking_script: make_stas3_locking(&[0x33; 20], &redemption_pkh), signing_key: SigningKey::Single(test_key()) },
            ],
            fee_txid: dummy_hash(),
            fee_vout: 2,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![Stas3OutputParams {
                satoshis: 9000, // != 10000
                owner_pkh: [0x55; 20],
                redemption_pkh,
                frozen: false,
                freezable: true,
                service_fields: vec![],
                optional_data: vec![],
                action_data: None,
            }],
            fee_rate: 500,
        };

        assert!(build_stas3_merge_tx(config).is_err());
    }

    // ---------------------------------------------------------------
    // Confiscation tests
    // ---------------------------------------------------------------

    #[test]
    fn confiscate_single_input() {
        let token_key = test_key();
        let fee_key = test_key();
        let redemption_pkh = [0x22; 20];

        let config = Stas3ConfiscateConfig {
            token_inputs: vec![TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 5000,
                locking_script: make_stas3_locking(&[0x11; 20], &redemption_pkh),
                signing_key: SigningKey::Single(token_key),
            }],
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![Stas3OutputParams {
                satoshis: 5000,
                owner_pkh: redemption_pkh, // redirected to issuer
                redemption_pkh,
                frozen: false,
                freezable: true,
                service_fields: vec![],
                optional_data: vec![],
                action_data: None,
            }],
            fee_rate: 500,
        };

        let tx = build_stas3_confiscate_tx(config).unwrap();
        assert_eq!(tx.input_count(), 2); // 1 token + 1 fee
        assert!(tx.output_count() >= 1);
        assert_eq!(tx.outputs[0].satoshis, 5000);

        for input in &tx.inputs {
            assert!(input.unlocking_script.is_some());
        }
    }

    #[test]
    fn confiscate_frozen_input_allowed() {
        // Frozen inputs CAN be confiscated — this should succeed
        let token_key = test_key();
        let fee_key = test_key();
        let redemption_pkh = [0x22; 20];

        let frozen_locking =
            build_stas3_locking_script(&[0x11; 20], &redemption_pkh, None, true, true, &[], &[])
                .unwrap();

        let config = Stas3ConfiscateConfig {
            token_inputs: vec![TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 5000,
                locking_script: frozen_locking,
                signing_key: SigningKey::Single(token_key),
            }],
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![Stas3OutputParams {
                satoshis: 5000,
                owner_pkh: redemption_pkh,
                redemption_pkh,
                frozen: false,
                freezable: true,
                service_fields: vec![],
                optional_data: vec![],
                action_data: None,
            }],
            fee_rate: 500,
        };

        // Should succeed — confiscation path is valid for frozen UTXOs
        let tx = build_stas3_confiscate_tx(config).unwrap();
        assert_eq!(tx.outputs[0].satoshis, 5000);
    }

    #[test]
    fn confiscate_empty_inputs_rejected() {
        let fee_key = test_key();

        let config = Stas3ConfiscateConfig {
            token_inputs: vec![],
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![Stas3OutputParams {
                satoshis: 5000,
                owner_pkh: [0x22; 20],
                redemption_pkh: [0x22; 20],
                frozen: false,
                freezable: true,
                service_fields: vec![],
                optional_data: vec![],
                action_data: None,
            }],
            fee_rate: 500,
        };

        assert!(build_stas3_confiscate_tx(config).is_err());
    }

    // ---------------------------------------------------------------
    // Redeem tests
    // ---------------------------------------------------------------

    /// Helper: create a redeem config where the issuer key owns the token.
    fn make_redeem_config(
        issuer_key: &PrivateKey,
        fee_key: &PrivateKey,
        token_sats: u64,
        redeem_sats: u64,
        remaining: Vec<Stas3OutputParams>,
        frozen: bool,
    ) -> Stas3RedeemConfig {
        let issuer_pkh =
            bsv_primitives::hash::hash160(&issuer_key.pub_key().to_compressed());
        let locking = build_stas3_locking_script(
            &issuer_pkh, &issuer_pkh, None, frozen, true, &[], &[],
        ).unwrap();

        Stas3RedeemConfig {
            token_input: TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: token_sats,
                locking_script: locking,
                signing_key: SigningKey::Single(issuer_key.clone()),
            },
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(fee_key),
            fee_private_key: fee_key.clone(),
            redeem_satoshis: redeem_sats,
            redemption_pkh: issuer_pkh,
            input_frozen: frozen,
            remaining_outputs: remaining,
            fee_rate: 500,
            redeem_address_type: RedeemAddressType::P2pkh,
        }
    }

    #[test]
    fn redeem_full() {
        let issuer_key = test_key();
        let fee_key = test_key();

        let config = make_redeem_config(&issuer_key, &fee_key, 10000, 10000, vec![], false);
        let tx = build_stas3_redeem_tx(config).unwrap();

        // Input: 1 token + 1 fee
        assert_eq!(tx.input_count(), 2);
        // Output 0: P2PKH redeem + optional change
        assert_eq!(tx.outputs[0].satoshis, 10000);

        // All signed
        for input in &tx.inputs {
            assert!(input.unlocking_script.is_some());
        }
    }

    #[test]
    fn redeem_partial_with_remaining() {
        let issuer_key = test_key();
        let fee_key = test_key();
        let issuer_pkh =
            bsv_primitives::hash::hash160(&issuer_key.pub_key().to_compressed());

        let remaining = vec![Stas3OutputParams {
            satoshis: 4000,
            owner_pkh: issuer_pkh,
            redemption_pkh: issuer_pkh,
            frozen: false,
            freezable: true,
            service_fields: vec![],
            optional_data: vec![],
                action_data: None,
        }];

        let config = make_redeem_config(&issuer_key, &fee_key, 10000, 6000, remaining, false);
        let tx = build_stas3_redeem_tx(config).unwrap();

        assert_eq!(tx.outputs[0].satoshis, 6000); // P2PKH redeem
        assert_eq!(tx.outputs[1].satoshis, 4000); // remaining STAS3
    }

    #[test]
    fn redeem_frozen_rejected() {
        let issuer_key = test_key();
        let fee_key = test_key();

        let config = make_redeem_config(&issuer_key, &fee_key, 10000, 10000, vec![], true);
        let result = build_stas3_redeem_tx(config);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TokenError::FrozenToken));
    }

    #[test]
    fn redeem_non_issuer_rejected() {
        let issuer_key = test_key();
        let non_issuer_key = test_key();
        let fee_key = test_key();

        let issuer_pkh =
            bsv_primitives::hash::hash160(&issuer_key.pub_key().to_compressed());

        // Token is owned by non_issuer but redemption_pkh is the issuer
        let locking = build_stas3_locking_script(
            &[0x99; 20], &issuer_pkh, None, false, true, &[], &[],
        ).unwrap();

        let config = Stas3RedeemConfig {
            token_input: TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 10000,
                locking_script: locking,
                signing_key: SigningKey::Single(non_issuer_key),
            },
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            redeem_satoshis: 10000,
            redemption_pkh: issuer_pkh,
            input_frozen: false,
            remaining_outputs: vec![],
            fee_rate: 500,
            redeem_address_type: RedeemAddressType::P2pkh,
        };

        let result = build_stas3_redeem_tx(config);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TokenError::IssuerOnly(_)));
    }

    #[test]
    fn redeem_conservation_violation() {
        let issuer_key = test_key();
        let fee_key = test_key();

        // redeem_sats (8000) + remaining (0) != token_input (10000)
        let config = make_redeem_config(&issuer_key, &fee_key, 10000, 8000, vec![], false);
        let result = build_stas3_redeem_tx(config);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TokenError::AmountMismatch { .. }));
    }

    #[test]
    fn redeem_zero_amount_rejected() {
        let issuer_key = test_key();
        let fee_key = test_key();
        let issuer_pkh =
            bsv_primitives::hash::hash160(&issuer_key.pub_key().to_compressed());

        let remaining = vec![Stas3OutputParams {
            satoshis: 10000,
            owner_pkh: issuer_pkh,
            redemption_pkh: issuer_pkh,
            frozen: false,
            freezable: true,
            service_fields: vec![],
            optional_data: vec![],
                action_data: None,
        }];

        let config = make_redeem_config(&issuer_key, &fee_key, 10000, 0, remaining, false);
        let result = build_stas3_redeem_tx(config);
        assert!(result.is_err());
    }

    // ---------------------------------------------------------------
    // Extended swap tests
    // ---------------------------------------------------------------

    use crate::types::ActionData;

    /// Build a STAS3 locking script with swap action data embedded.
    fn make_stas3_swap_locking(
        owner_pkh: &[u8; 20],
        redemption_pkh: &[u8; 20],
        swap_data: &ActionData,
    ) -> Script {
        build_stas3_locking_script(
            owner_pkh, redemption_pkh, Some(swap_data), false, true, &[], &[],
        )
        .unwrap()
    }

    /// Build a frozen STAS3 locking script (no action data).
    fn make_stas3_frozen_locking(
        owner_pkh: &[u8; 20],
        redemption_pkh: &[u8; 20],
    ) -> Script {
        build_stas3_locking_script(
            owner_pkh, redemption_pkh, None, true, true, &[], &[],
        )
        .unwrap()
    }

    fn test_swap_data() -> ActionData {
        ActionData::Swap {
            requested_script_hash: [0xab; 32],
            requested_pkh: [0xcd; 20],
            rate_numerator: 1,
            rate_denominator: 1,
        }
    }

    #[test]
    fn transfer_swap_1_to_1_two_outputs() {
        let fee_key = test_key();
        let swap_data = test_swap_data();
        let redemption = [0x22; 20];

        let mut config = Stas3BaseConfig {
            token_inputs: vec![
                TokenInput {
                    txid: dummy_hash(),
                    vout: 0,
                    satoshis: 5000,
                    locking_script: make_stas3_locking(&[0x11; 20], &redemption),
                    signing_key: SigningKey::Single(test_key()),
                },
                TokenInput {
                    txid: dummy_hash(),
                    vout: 1,
                    satoshis: 5000,
                    locking_script: make_stas3_swap_locking(&[0x33; 20], &redemption, &swap_data),
                    signing_key: SigningKey::Single(test_key()),
                },
            ],
            fee_txid: dummy_hash(),
            fee_vout: 2,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![
                Stas3OutputParams {
                    satoshis: 5000,
                    owner_pkh: [0x44; 20],
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: None,
                },
                Stas3OutputParams {
                    satoshis: 5000,
                    owner_pkh: [0x55; 20],
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: None,
                },
            ],
            spend_type: Stas3SpendType::Transfer,
            fee_rate: 500,
        };

        let tx = build_stas3_transfer_swap_tx(&mut config).unwrap();
        assert_eq!(tx.input_count(), 3); // 2 token + 1 fee
        assert!(tx.output_count() >= 2);
        assert_eq!(tx.outputs[0].satoshis, 5000);
        assert_eq!(tx.outputs[1].satoshis, 5000);
    }

    #[test]
    fn swap_swap_1_to_1_two_outputs() {
        let fee_key = test_key();
        let swap_data = test_swap_data();
        let redemption = [0x22; 20];

        let mut config = Stas3BaseConfig {
            token_inputs: vec![
                TokenInput {
                    txid: dummy_hash(),
                    vout: 0,
                    satoshis: 5000,
                    locking_script: make_stas3_swap_locking(&[0x11; 20], &redemption, &swap_data),
                    signing_key: SigningKey::Single(test_key()),
                },
                TokenInput {
                    txid: dummy_hash(),
                    vout: 1,
                    satoshis: 5000,
                    locking_script: make_stas3_swap_locking(&[0x33; 20], &redemption, &swap_data),
                    signing_key: SigningKey::Single(test_key()),
                },
            ],
            fee_txid: dummy_hash(),
            fee_vout: 2,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![
                Stas3OutputParams {
                    satoshis: 5000,
                    owner_pkh: [0x44; 20],
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: None,
                },
                Stas3OutputParams {
                    satoshis: 5000,
                    owner_pkh: [0x55; 20],
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: None,
                },
            ],
            spend_type: Stas3SpendType::Transfer,
            fee_rate: 500,
        };

        let tx = build_stas3_swap_swap_tx(&mut config).unwrap();
        assert_eq!(tx.input_count(), 3);
        assert!(tx.output_count() >= 2);
    }

    #[test]
    fn transfer_swap_fractional_rate_with_remainder() {
        let fee_key = test_key();
        let swap_data = ActionData::Swap {
            requested_script_hash: [0xab; 32],
            requested_pkh: [0xcd; 20],
            rate_numerator: 2,
            rate_denominator: 3,
        };
        let redemption = [0x22; 20];

        // Input A: 6000 sats, Input B: 4000 sats with swap data
        // Output 0: 4000 (principal A→B), Output 1: 4000 (principal B→A), Output 2: 2000 (remainder A)
        let mut config = Stas3BaseConfig {
            token_inputs: vec![
                TokenInput {
                    txid: dummy_hash(),
                    vout: 0,
                    satoshis: 6000,
                    locking_script: make_stas3_locking(&[0x11; 20], &redemption),
                    signing_key: SigningKey::Single(test_key()),
                },
                TokenInput {
                    txid: dummy_hash(),
                    vout: 1,
                    satoshis: 4000,
                    locking_script: make_stas3_swap_locking(&[0x33; 20], &redemption, &swap_data),
                    signing_key: SigningKey::Single(test_key()),
                },
            ],
            fee_txid: dummy_hash(),
            fee_vout: 2,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![
                Stas3OutputParams {
                    satoshis: 4000,
                    owner_pkh: [0x44; 20],
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: None, // principal — neutral
                },
                Stas3OutputParams {
                    satoshis: 4000,
                    owner_pkh: [0x55; 20],
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: None, // principal — neutral
                },
                Stas3OutputParams {
                    satoshis: 2000,
                    owner_pkh: [0x11; 20], // remainder back to original owner
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: Some(swap_data.clone()), // remainder inherits action data
                },
            ],
            spend_type: Stas3SpendType::Transfer,
            fee_rate: 500,
        };

        let tx = build_stas3_transfer_swap_tx(&mut config).unwrap();
        assert_eq!(tx.input_count(), 3);
        assert!(tx.output_count() >= 3);
        assert_eq!(tx.outputs[0].satoshis, 4000);
        assert_eq!(tx.outputs[1].satoshis, 4000);
        assert_eq!(tx.outputs[2].satoshis, 2000);

        // Verify remainder output has swap action data
        let parsed = read_locking_script(tx.outputs[2].locking_script.to_bytes());
        assert_eq!(parsed.script_type, ScriptType::Stas3);
        let stas3 = parsed.stas3.unwrap();
        assert!(matches!(stas3.action_data_parsed, Some(ActionData::Swap { .. })));
    }

    #[test]
    fn swap_swap_fractional_rate_with_remainder() {
        let fee_key = test_key();
        let swap_data = ActionData::Swap {
            requested_script_hash: [0xab; 32],
            requested_pkh: [0xcd; 20],
            rate_numerator: 3,
            rate_denominator: 2,
        };
        let redemption = [0x22; 20];

        let mut config = Stas3BaseConfig {
            token_inputs: vec![
                TokenInput {
                    txid: dummy_hash(),
                    vout: 0,
                    satoshis: 7000,
                    locking_script: make_stas3_swap_locking(&[0x11; 20], &redemption, &swap_data),
                    signing_key: SigningKey::Single(test_key()),
                },
                TokenInput {
                    txid: dummy_hash(),
                    vout: 1,
                    satoshis: 3000,
                    locking_script: make_stas3_swap_locking(&[0x33; 20], &redemption, &swap_data),
                    signing_key: SigningKey::Single(test_key()),
                },
            ],
            fee_txid: dummy_hash(),
            fee_vout: 2,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![
                Stas3OutputParams {
                    satoshis: 3000,
                    owner_pkh: [0x44; 20],
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: None,
                },
                Stas3OutputParams {
                    satoshis: 3000,
                    owner_pkh: [0x55; 20],
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: None,
                },
                Stas3OutputParams {
                    satoshis: 4000,
                    owner_pkh: [0x11; 20],
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: Some(swap_data.clone()),
                },
            ],
            spend_type: Stas3SpendType::Transfer,
            fee_rate: 500,
        };

        let tx = build_stas3_swap_swap_tx(&mut config).unwrap();
        assert_eq!(tx.input_count(), 3);
        assert!(tx.output_count() >= 3);
    }

    #[test]
    fn transfer_swap_two_remainders_four_outputs() {
        let fee_key = test_key();
        let swap_data = test_swap_data();
        let redemption = [0x22; 20];

        let mut config = Stas3BaseConfig {
            token_inputs: vec![
                TokenInput {
                    txid: dummy_hash(),
                    vout: 0,
                    satoshis: 8000,
                    locking_script: make_stas3_locking(&[0x11; 20], &redemption),
                    signing_key: SigningKey::Single(test_key()),
                },
                TokenInput {
                    txid: dummy_hash(),
                    vout: 1,
                    satoshis: 7000,
                    locking_script: make_stas3_swap_locking(&[0x33; 20], &redemption, &swap_data),
                    signing_key: SigningKey::Single(test_key()),
                },
            ],
            fee_txid: dummy_hash(),
            fee_vout: 2,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![
                Stas3OutputParams {
                    satoshis: 5000,
                    owner_pkh: [0x44; 20],
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: None,
                },
                Stas3OutputParams {
                    satoshis: 5000,
                    owner_pkh: [0x55; 20],
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: None,
                },
                Stas3OutputParams {
                    satoshis: 3000,
                    owner_pkh: [0x11; 20],
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: None,
                },
                Stas3OutputParams {
                    satoshis: 2000,
                    owner_pkh: [0x33; 20],
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: Some(swap_data.clone()),
                },
            ],
            spend_type: Stas3SpendType::Transfer,
            fee_rate: 500,
        };

        let tx = build_stas3_transfer_swap_tx(&mut config).unwrap();
        assert_eq!(tx.input_count(), 3);
        assert!(tx.output_count() >= 4);
        assert_eq!(tx.outputs[0].satoshis, 5000);
        assert_eq!(tx.outputs[1].satoshis, 5000);
        assert_eq!(tx.outputs[2].satoshis, 3000);
        assert_eq!(tx.outputs[3].satoshis, 2000);
    }

    #[test]
    fn swap_swap_two_remainders_four_outputs() {
        let fee_key = test_key();
        let swap_data = test_swap_data();
        let redemption = [0x22; 20];

        let mut config = Stas3BaseConfig {
            token_inputs: vec![
                TokenInput {
                    txid: dummy_hash(),
                    vout: 0,
                    satoshis: 8000,
                    locking_script: make_stas3_swap_locking(&[0x11; 20], &redemption, &swap_data),
                    signing_key: SigningKey::Single(test_key()),
                },
                TokenInput {
                    txid: dummy_hash(),
                    vout: 1,
                    satoshis: 7000,
                    locking_script: make_stas3_swap_locking(&[0x33; 20], &redemption, &swap_data),
                    signing_key: SigningKey::Single(test_key()),
                },
            ],
            fee_txid: dummy_hash(),
            fee_vout: 2,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![
                Stas3OutputParams {
                    satoshis: 5000,
                    owner_pkh: [0x44; 20],
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: None,
                },
                Stas3OutputParams {
                    satoshis: 5000,
                    owner_pkh: [0x55; 20],
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: None,
                },
                Stas3OutputParams {
                    satoshis: 3000,
                    owner_pkh: [0x11; 20],
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: None,
                },
                Stas3OutputParams {
                    satoshis: 2000,
                    owner_pkh: [0x33; 20],
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: None,
                },
            ],
            spend_type: Stas3SpendType::Transfer,
            fee_rate: 500,
        };

        let tx = build_stas3_swap_swap_tx(&mut config).unwrap();
        assert_eq!(tx.input_count(), 3);
        assert!(tx.output_count() >= 4);
    }

    #[test]
    fn transfer_swap_frozen_input_rejected() {
        let fee_key = test_key();
        let redemption = [0x22; 20];

        let mut config = Stas3BaseConfig {
            token_inputs: vec![
                TokenInput {
                    txid: dummy_hash(),
                    vout: 0,
                    satoshis: 5000,
                    locking_script: make_stas3_frozen_locking(&[0x11; 20], &redemption),
                    signing_key: SigningKey::Single(test_key()),
                },
                TokenInput {
                    txid: dummy_hash(),
                    vout: 1,
                    satoshis: 5000,
                    locking_script: make_stas3_locking(&[0x33; 20], &redemption),
                    signing_key: SigningKey::Single(test_key()),
                },
            ],
            fee_txid: dummy_hash(),
            fee_vout: 2,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![
                Stas3OutputParams {
                    satoshis: 5000,
                    owner_pkh: [0x44; 20],
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: None,
                },
                Stas3OutputParams {
                    satoshis: 5000,
                    owner_pkh: [0x55; 20],
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: None,
                },
            ],
            spend_type: Stas3SpendType::Transfer,
            fee_rate: 500,
        };

        let result = build_stas3_transfer_swap_tx(&mut config);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TokenError::FrozenToken));
    }

    #[test]
    fn swap_swap_frozen_input_rejected() {
        let fee_key = test_key();
        let swap_data = test_swap_data();
        let redemption = [0x22; 20];

        let mut config = Stas3BaseConfig {
            token_inputs: vec![
                TokenInput {
                    txid: dummy_hash(),
                    vout: 0,
                    satoshis: 5000,
                    locking_script: make_stas3_swap_locking(&[0x11; 20], &redemption, &swap_data),
                    signing_key: SigningKey::Single(test_key()),
                },
                TokenInput {
                    txid: dummy_hash(),
                    vout: 1,
                    satoshis: 5000,
                    locking_script: make_stas3_frozen_locking(&[0x33; 20], &redemption),
                    signing_key: SigningKey::Single(test_key()),
                },
            ],
            fee_txid: dummy_hash(),
            fee_vout: 2,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![
                Stas3OutputParams {
                    satoshis: 5000,
                    owner_pkh: [0x44; 20],
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: None,
                },
                Stas3OutputParams {
                    satoshis: 5000,
                    owner_pkh: [0x55; 20],
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: None,
                },
            ],
            spend_type: Stas3SpendType::Transfer,
            fee_rate: 500,
        };

        let result = build_stas3_swap_swap_tx(&mut config);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TokenError::FrozenToken));
    }

    #[test]
    fn swap_flow_auto_detects_transfer_swap() {
        let fee_key = test_key();
        let swap_data = test_swap_data();
        let redemption = [0x22; 20];

        let mut config = Stas3BaseConfig {
            token_inputs: vec![
                TokenInput {
                    txid: dummy_hash(),
                    vout: 0,
                    satoshis: 5000,
                    locking_script: make_stas3_locking(&[0x11; 20], &redemption),
                    signing_key: SigningKey::Single(test_key()),
                },
                TokenInput {
                    txid: dummy_hash(),
                    vout: 1,
                    satoshis: 5000,
                    locking_script: make_stas3_swap_locking(&[0x33; 20], &redemption, &swap_data),
                    signing_key: SigningKey::Single(test_key()),
                },
            ],
            fee_txid: dummy_hash(),
            fee_vout: 2,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![
                Stas3OutputParams {
                    satoshis: 5000,
                    owner_pkh: [0x44; 20],
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: None,
                },
                Stas3OutputParams {
                    satoshis: 5000,
                    owner_pkh: [0x55; 20],
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: None,
                },
            ],
            spend_type: Stas3SpendType::SwapCancellation, // should be overridden
            fee_rate: 500,
        };

        // Auto-detect: one has swap data → TransferSwap → spending type Transfer
        let tx = build_stas3_swap_flow_tx(&mut config).unwrap();
        assert_eq!(tx.input_count(), 3);
    }

    #[test]
    fn swap_flow_auto_detects_swap_swap() {
        let fee_key = test_key();
        let swap_data = test_swap_data();
        let redemption = [0x22; 20];

        let mut config = Stas3BaseConfig {
            token_inputs: vec![
                TokenInput {
                    txid: dummy_hash(),
                    vout: 0,
                    satoshis: 5000,
                    locking_script: make_stas3_swap_locking(&[0x11; 20], &redemption, &swap_data),
                    signing_key: SigningKey::Single(test_key()),
                },
                TokenInput {
                    txid: dummy_hash(),
                    vout: 1,
                    satoshis: 5000,
                    locking_script: make_stas3_swap_locking(&[0x33; 20], &redemption, &swap_data),
                    signing_key: SigningKey::Single(test_key()),
                },
            ],
            fee_txid: dummy_hash(),
            fee_vout: 2,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![
                Stas3OutputParams {
                    satoshis: 5000,
                    owner_pkh: [0x44; 20],
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: None,
                },
                Stas3OutputParams {
                    satoshis: 5000,
                    owner_pkh: [0x55; 20],
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: None,
                },
            ],
            spend_type: Stas3SpendType::Transfer, // should be overridden to SwapCancellation
            fee_rate: 500,
        };

        // Auto-detect: both have swap data → SwapSwap → spending type SwapCancellation
        let tx = build_stas3_swap_flow_tx(&mut config).unwrap();
        assert_eq!(tx.input_count(), 3);
    }

    #[test]
    fn swap_action_data_roundtrip() {
        let owner = [0x11; 20];
        let redemption = [0x22; 20];
        let swap_data = ActionData::Swap {
            requested_script_hash: [0xab; 32],
            requested_pkh: [0xef; 20],
            rate_numerator: 42,
            rate_denominator: 7,
        };

        let script = build_stas3_locking_script(
            &owner, &redemption, Some(&swap_data), false, true, &[], &[],
        )
        .unwrap();

        let parsed = read_locking_script(script.to_bytes());
        assert_eq!(parsed.script_type, ScriptType::Stas3);
        let stas3 = parsed.stas3.unwrap();

        match stas3.action_data_parsed {
            Some(ActionData::Swap {
                requested_script_hash,
                requested_pkh,
                rate_numerator,
                rate_denominator,
            }) => {
                assert_eq!(requested_script_hash, [0xab; 32]);
                assert_eq!(requested_pkh, [0xef; 20]);
                assert_eq!(rate_numerator, 42);
                assert_eq!(rate_denominator, 7);
            }
            other => panic!("expected Swap action data, got {:?}", other),
        }
    }
}
