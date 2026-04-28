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
use crate::script::reader::read_locking_script;
use crate::script::stas3_builder::build_stas3_locking_script;
use crate::script::stas3_swap::{is_stas3_frozen, resolve_stas3_swap_mode};
use crate::script_type::ScriptType;
use crate::template::stas3 as stas3_template;
use crate::template::stas3::{
    Stas3UnlockWitness, Stas3WitnessChange, Stas3WitnessOutput, compute_input_preimage,
};
use crate::types::{SigningKey, Stas3SpendType, Stas3SwapMode, Stas3TxType};

use bsv_transaction::sighash::SIGHASH_ALL_FORKID;

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
    /// Transaction-type byte (spec §8.1).
    ///
    /// Per STAS 3.0 spec §4 confiscation row and §9.3, confiscation places
    /// **no** restriction on `txType`. Any value is accepted. Defaults to `0`.
    pub tx_type: u8,
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
// §7 Unlock witness derivation
// -----------------------------------------------------------------------

/// Derive the spec §7 unlock witness (slots 1..=20) from the structure of
/// the given spending transaction.
///
/// # Arguments
/// * `tx`                   – The (mostly-built, unsigned) transaction.
/// * `input_index`          – Index of the input being signed.
/// * `funding_input_index`  – Optional index of the funding input on `tx`
///   (used to populate slots 16–17). When `None`, the helper attempts to
///   auto-detect by scanning `tx.inputs` for the first non-STAS3-shaped
///   prev locking script.
/// * `tx_type`              – Spec §7 slot 18 (txType).
/// * `spend_type`           – Spec §7 slot 20 (spendType).
/// * `sighash_flag`         – Sighash flag used to compute slot 19's
///   BIP-143 preimage.
///
/// # Witness population (per spec §7)
/// * Slots 1–12: walks `tx.outputs` in order; for the first up-to-4
///   outputs whose locking script parses as `ScriptType::Stas3`, emits
///   `(amount, owner_pkh, var2)` triplets.
/// * Slots 13–14: scans the remaining (non-STAS3) outputs for the first
///   `ScriptType::P2pkh` (or `ScriptType::P2Mpkh`) — that's the change.
/// * Slot 15: looks for a trailing OP_RETURN-style output (`OP_FALSE
///   OP_RETURN <payload>` or `OP_RETURN <payload>`) and lifts the payload
///   into `note_data`.
/// * Slots 16–17: resolved from `funding_input_index` if provided,
///   otherwise auto-detected.
/// * Slot 18: caller-supplied `tx_type`.
/// * Slot 19: BIP-143 preimage of input `input_index`.
/// * Slot 20: caller-supplied `spend_type`.
fn derive_witness_for_input(
    tx: &Transaction,
    input_index: usize,
    funding_input_index: Option<usize>,
    tx_type: Stas3TxType,
    spend_type: Stas3SpendType,
    sighash_flag: u32,
) -> Result<Stas3UnlockWitness, TokenError> {
    // Slots 1–12: walk outputs in order, take first up-to-4 STAS3.
    let mut stas_outputs: Vec<Stas3WitnessOutput> = Vec::new();
    let mut change: Option<Stas3WitnessChange> = None;
    let mut note_data: Option<Vec<u8>> = None;

    for output in &tx.outputs {
        let script_bytes = output.locking_script.to_bytes();
        let parsed = read_locking_script(script_bytes);

        match parsed.script_type {
            ScriptType::Stas3 => {
                if stas_outputs.len() < 4 {
                    let stas3 = parsed
                        .stas3
                        .expect("STAS3 classification must yield Stas3Fields");
                    let var2 = stas3.action_data_raw.unwrap_or_default();
                    stas_outputs.push(Stas3WitnessOutput {
                        amount: output.satoshis,
                        owner_pkh: stas3.owner,
                        var2,
                    });
                }
            }
            ScriptType::P2pkh => {
                if change.is_none() {
                    // P2PKH layout: 76 a9 14 <20B PKH> 88 ac
                    let mut pkh = [0u8; 20];
                    pkh.copy_from_slice(&script_bytes[3..23]);
                    change = Some(Stas3WitnessChange {
                        amount: output.satoshis,
                        addr_pkh: pkh,
                    });
                }
            }
            ScriptType::P2Mpkh => {
                if change.is_none() {
                    // P2MPKH layout: 76 a9 14 <20B MPKH> ... (spec §10.2)
                    let mut pkh = [0u8; 20];
                    pkh.copy_from_slice(&script_bytes[3..23]);
                    change = Some(Stas3WitnessChange {
                        amount: output.satoshis,
                        addr_pkh: pkh,
                    });
                }
            }
            ScriptType::OpReturn => {
                if note_data.is_none() {
                    note_data = extract_op_return_payload(script_bytes);
                }
            }
            _ => {}
        }
    }

    // Slots 16–17: funding pointer.
    let funding_input = resolve_funding_input(tx, input_index, funding_input_index);

    // Slot 19: BIP-143 preimage.
    let sighash_preimage = compute_input_preimage(tx, input_index, sighash_flag)
        .map_err(TokenError::Transaction)?;

    Ok(Stas3UnlockWitness {
        stas_outputs,
        change,
        note_data,
        funding_input,
        tx_type,
        sighash_preimage,
        spend_type,
    })
}

/// Determine the funding-input pointer (slots 16–17) for the witness.
///
/// When `funding_input_index` is `Some`, that input is used. Otherwise,
/// scan the inputs and pick the first one whose previous locking script
/// is NOT a STAS 3.0 frame (typically the P2PKH fee input). Returns
/// `None` when no candidate is found.
fn resolve_funding_input(
    tx: &Transaction,
    input_index: usize,
    funding_input_index: Option<usize>,
) -> Option<([u8; 32], u32)> {
    let pick = |idx: usize| -> Option<([u8; 32], u32)> {
        let input = tx.inputs.get(idx)?;
        Some((input.source_txid, input.source_tx_out_index))
    };
    if let Some(idx) = funding_input_index {
        return pick(idx);
    }
    for (idx, input) in tx.inputs.iter().enumerate() {
        if idx == input_index {
            continue;
        }
        let prev_script = input
            .source_tx_output()
            .map(|o| o.locking_script.to_bytes().to_vec())
            .unwrap_or_default();
        let parsed = read_locking_script(&prev_script);
        if !matches!(parsed.script_type, ScriptType::Stas3) {
            return pick(idx);
        }
    }
    None
}

/// If `script` is an `OP_FALSE OP_RETURN <payload>` or `OP_RETURN <payload>`
/// data carrier (per spec §11 noteData output), return the raw payload
/// bytes. Otherwise `None`.
fn extract_op_return_payload(script: &[u8]) -> Option<Vec<u8>> {
    // Find the OP_RETURN (0x6a) and parse the first push that follows.
    let after = if script.len() >= 2 && script[0] == 0x00 && script[1] == 0x6a {
        2
    } else if !script.is_empty() && script[0] == 0x6a {
        1
    } else {
        return None;
    };
    if after >= script.len() {
        return Some(Vec::new());
    }
    let opcode = script[after];
    match opcode {
        0x00 => Some(Vec::new()),
        0x01..=0x4b => {
            let len = opcode as usize;
            let end = after + 1 + len;
            if end > script.len() {
                return None;
            }
            Some(script[after + 1..end].to_vec())
        }
        0x4c => {
            if after + 1 >= script.len() {
                return None;
            }
            let len = script[after + 1] as usize;
            let end = after + 2 + len;
            if end > script.len() {
                return None;
            }
            Some(script[after + 2..end].to_vec())
        }
        0x4d => {
            if after + 2 >= script.len() {
                return None;
            }
            let len =
                u16::from_le_bytes([script[after + 1], script[after + 2]]) as usize;
            let end = after + 3 + len;
            if end > script.len() {
                return None;
            }
            Some(script[after + 3..end].to_vec())
        }
        0x4e => {
            if after + 4 >= script.len() {
                return None;
            }
            let len = u32::from_le_bytes([
                script[after + 1],
                script[after + 2],
                script[after + 3],
                script[after + 4],
            ]) as usize;
            let end = after + 5 + len;
            if end > script.len() {
                return None;
            }
            Some(script[after + 5..end].to_vec())
        }
        _ => None,
    }
}

/// Default [`Stas3TxType`] (spec §7 slot 18) for the regular non-merge,
/// non-atomic-swap path. Atomic swap and merge variants override the
/// `tx_type` separately at the call site (see
/// [`build_stas3_transfer_swap_tx`], [`build_stas3_swap_swap_tx`], and
/// [`build_stas3_confiscate_tx`]).
fn default_tx_type_for(_spend_type: Stas3SpendType) -> Stas3TxType {
    Stas3TxType::Regular
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
    build_stas3_base_tx_with_tx_type(config, default_tx_type_for(config.spend_type))
}

/// Internal helper: same as [`build_stas3_base_tx`] but lets callers pin
/// the `tx_type` byte (spec §7 slot 18) so that atomic-swap (txType=1)
/// and merge (txType=2..=7) variants are encoded in the witness even
/// though the public API does not expose `tx_type` directly.
fn build_stas3_base_tx_with_tx_type(
    config: &Stas3BaseConfig,
    tx_type: Stas3TxType,
) -> Result<Transaction, TokenError> {
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

    // Sign token inputs with the §7 witness-aware STAS3 templates.
    // `unlock_for_input_with_witness` dispatches:
    //   - arbitrator-free owner (HASH160("")) → no-auth (witness ‖ OP_FALSE) (spec §10.3)
    //   - SigningKey::Single → P2PKH unlock (witness ‖ <sig> <pubkey>)
    //   - SigningKey::Multi  → P2MPKH unlock (witness ‖ OP_0 <sigs> <redeem>)
    let fee_idx = config.token_inputs.len();
    for (i, ti) in config.token_inputs.iter().enumerate() {
        let witness = derive_witness_for_input(
            &tx,
            i,
            Some(fee_idx),
            tx_type,
            config.spend_type,
            SIGHASH_ALL_FORKID,
        )?;
        let unlocker = stas3_template::unlock_for_input_with_witness(
            ti.locking_script.to_bytes(),
            &ti.signing_key,
            None,
            witness,
        )?;
        let sig = unlocker.sign(&tx, i as u32)?;
        tx.inputs[i].unlocking_script = Some(sig);
    }

    // Sign fee input with P2PKH
    let p2pkh_unlocker = p2pkh::unlock(config.fee_private_key.clone(), None);
    let fee_sig = p2pkh_unlocker.sign(&tx, fee_idx as u32)?;
    tx.inputs[fee_idx].unlocking_script = Some(fee_sig);

    Ok(tx)
}

/// Build a STAS3 freeze transaction.
///
/// Wrapper around [`build_stas3_base_tx`] that sets `frozen = true` on all
/// outputs and uses `Stas3SpendType::FreezeUnfreeze`.
///
/// # Spec §9.2 enforcement
/// - Exactly one STAS output must be produced.
/// - Output non-`var2` fields (owner, redemption, freezable flag) must be
///   byte-identical to the input.
/// - The input UTXO must have the FREEZABLE flag bit (0x01) set in its
///   `flags` byte.
///
/// # Errors
/// Returns [`TokenError::FreezeOutputCount`], [`TokenError::FreezeFieldDrift`]
/// or [`TokenError::FreezeFlagNotSet`] when these constraints are violated.
pub fn build_stas3_freeze_tx(config: &mut Stas3BaseConfig) -> Result<Transaction, TokenError> {
    enforce_freeze_invariants(config)?;
    config.spend_type = Stas3SpendType::FreezeUnfreeze;
    for dest in &mut config.destinations {
        dest.frozen = true;
    }
    build_stas3_base_tx(config)
}

/// Build a STAS3 unfreeze transaction.
///
/// Wrapper around [`build_stas3_base_tx`] that sets `frozen = false` on all
/// outputs and uses `Stas3SpendType::FreezeUnfreeze`. Same §9.2 invariants
/// as [`build_stas3_freeze_tx`].
pub fn build_stas3_unfreeze_tx(config: &mut Stas3BaseConfig) -> Result<Transaction, TokenError> {
    enforce_freeze_invariants(config)?;
    config.spend_type = Stas3SpendType::FreezeUnfreeze;
    for dest in &mut config.destinations {
        dest.frozen = false;
    }
    build_stas3_base_tx(config)
}

/// Validate spec §9.2 freeze/unfreeze invariants:
/// 1. Exactly one STAS output.
/// 2. Non-`var2` fields identical to the (single) input.
/// 3. FREEZABLE flag set on the input.
fn enforce_freeze_invariants(config: &Stas3BaseConfig) -> Result<(), TokenError> {
    if config.destinations.len() != 1 {
        return Err(TokenError::FreezeOutputCount(config.destinations.len()));
    }
    if config.token_inputs.len() != 1 {
        return Err(TokenError::FreezeFieldDrift(
            "freeze tx must have exactly one token input",
        ));
    }
    let input = &config.token_inputs[0];
    let parsed = crate::script::reader::read_locking_script(input.locking_script.to_bytes());
    let stas3 = parsed
        .stas3
        .ok_or(TokenError::FreezeFieldDrift("input is not a STAS 3.0 utxo"))?;
    let dest = &config.destinations[0];

    // Owner identical
    if stas3.owner != dest.owner_pkh {
        return Err(TokenError::FreezeFieldDrift("owner_pkh"));
    }
    // Redemption PKH identical
    if stas3.redemption != dest.redemption_pkh {
        return Err(TokenError::FreezeFieldDrift("redemption_pkh"));
    }
    // Freezable flag (bit 0 of flags byte). Input must be freezable;
    // output should preserve the same freezable bit.
    let input_freezable = stas3.flags.first().copied().unwrap_or(0) & 0x01 == 0x01;
    if !input_freezable {
        return Err(TokenError::FreezeFlagNotSet);
    }
    if input_freezable != dest.freezable {
        return Err(TokenError::FreezeFieldDrift("freezable"));
    }
    Ok(())
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
    // Spec §7 slot 18: atomic-swap execution sets txType = 1.
    build_stas3_base_tx_with_tx_type(config, Stas3TxType::AtomicSwap)
}

/// Build a STAS3 swap-swap transaction.
///
/// Both inputs have swap action data and are spent via the executing-swap
/// path. Per spec §9.5, atomic-swap execution uses `spendType = 1`
/// (Transfer) on BOTH inputs — the previous implementation incorrectly
/// used `SwapCancellation` (4). Requires exactly 2 token inputs. Frozen
/// inputs are rejected.
///
/// Outputs can be 2–4: principal swap legs (ownership exchanged) plus
/// optional remainder outputs for fractional-rate swaps.
pub fn build_stas3_swap_swap_tx(
    config: &mut Stas3BaseConfig,
) -> Result<Transaction, TokenError> {
    validate_swap_inputs(config)?;
    // Spec §9.5: atomic swap execution uses spendType = 1 (Transfer) on
    // both inputs. Cancellation (spendType = 4) is a separate factory —
    // see `build_stas3_swap_cancel_tx` for that path.
    config.spend_type = Stas3SpendType::Transfer;
    // Spec §7 slot 18: atomic-swap execution sets txType = 1.
    build_stas3_base_tx_with_tx_type(config, Stas3TxType::AtomicSwap)
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

/// Build a swap remainder/split output that inherits BOTH the source UTXO's
/// `owner` field and `var2` (action data / swap descriptor) per STAS 3.0 spec
/// v0.1 §9.5: "Remainder / split outputs inherit the source UTXO's both owner
/// and var2 fields."
///
/// The remainder UTXO continues to be takeable for the unmatched balance with
/// the same owner/swap-descriptor as the partially-consumed source.
///
/// # Arguments
/// * `source_locking_script` — the source STAS 3.0 locking script being
///   partially consumed.
/// * `satoshis`             — satoshi value for the remainder output.
/// * `redemption_pkh`       — the issuance redemption PKH (same as source).
/// * `freezable`            — freezable flag (typically inherited from source).
///
/// # Errors
/// Returns [`TokenError::InvalidScript`] if `source_locking_script` is not a
/// valid STAS 3.0 locking script.
pub fn build_swap_remainder_output(
    source_locking_script: &[u8],
    satoshis: u64,
    redemption_pkh: [u8; 20],
    freezable: bool,
) -> Result<Stas3OutputParams, TokenError> {
    use crate::script::reader::read_locking_script;

    let parsed = read_locking_script(source_locking_script);
    let stas3 = parsed.stas3.ok_or_else(|| {
        TokenError::InvalidScript("source script is not a STAS 3.0 locking script".into())
    })?;

    Ok(Stas3OutputParams {
        satoshis,
        owner_pkh: stas3.owner,                       // inherit owner
        redemption_pkh,
        frozen: stas3.frozen,
        freezable,
        service_fields: vec![],
        optional_data: vec![],
        action_data: stas3.action_data_parsed,        // inherit var2 (swap descriptor)
    })
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

    // Spec §9.3: every confiscated input MUST have the CONFISCATABLE
    // flag bit (0x02) set in its `flags` byte. Reject otherwise.
    for ti in &config.token_inputs {
        let parsed = crate::script::reader::read_locking_script(ti.locking_script.to_bytes());
        let Some(stas3) = parsed.stas3 else {
            return Err(TokenError::InvalidScript(
                "confiscate input is not a STAS 3.0 utxo".into(),
            ));
        };
        let flags = stas3.flags.first().copied().unwrap_or(0);
        if flags & 0x02 != 0x02 {
            return Err(TokenError::ConfiscateFlagNotSet);
        }
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

    // Spec §4 / §9.3: confiscation places no restriction on `txType` —
    // any value 0..=7 is valid. The `Stas3TxType` enum covers 0..=7;
    // values outside that range are clamped to `Regular` so the witness
    // still encodes a valid byte.
    let tx_type =
        Stas3TxType::from_u8(config.tx_type).unwrap_or(Stas3TxType::Regular);
    build_stas3_base_tx_with_tx_type(&base, tx_type)
}

/// Configuration for a STAS 3.0 swap-cancellation transaction (spec §9.4).
///
/// Cancels a single swap-bearing UTXO by spending it back to the
/// `receiveAddr` declared in the input's swap descriptor (var2). Uses
/// `spendType = 4` (SwapCancellation). Cannot be combined with an
/// executing swap.
pub struct Stas3SwapCancelConfig {
    /// The single STAS 3.0 token input being cancelled. Must carry a swap
    /// descriptor (action byte 0x01).
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
    /// The single STAS 3.0 output. Owner MUST equal
    /// `token_input.var2.receiveAddr`. Satoshis must equal
    /// `token_input.satoshis`.
    pub destination: Stas3OutputParams,
    /// Fee rate in satoshis per kilobyte.
    pub fee_rate: u64,
}

/// Build a STAS 3.0 swap-cancellation transaction (spec §9.4).
///
/// Invariants enforced before signing:
/// 1. Input MUST carry a swap descriptor (action byte 0x01).
/// 2. Output owner MUST equal the input descriptor's `receiveAddr`.
/// 3. Exactly one STAS output (no additional STAS outputs / cannot be
///    combined with an executing swap).
/// 4. Output satoshis must equal input satoshis (conservation).
///
/// Authorization is dispatched per the input `signing_key` (P2PKH or
/// P2MPKH). Uses `Stas3SpendType::SwapCancellation`.
pub fn build_stas3_swap_cancel_tx(
    config: Stas3SwapCancelConfig,
) -> Result<Transaction, TokenError> {
    use crate::script::reader::read_locking_script;
    use crate::types::ActionData;

    // 1. Input must carry a swap descriptor.
    let parsed = read_locking_script(config.token_input.locking_script.to_bytes());
    let stas3 = parsed
        .stas3
        .ok_or(TokenError::SwapCancelMissingDescriptor)?;
    let descriptor = match stas3.action_data_parsed.as_ref() {
        Some(ActionData::Swap { .. }) => stas3
            .action_data_parsed
            .as_ref()
            .and_then(|d| d.as_swap_descriptor())
            .ok_or(TokenError::SwapCancelMissingDescriptor)?,
        _ => return Err(TokenError::SwapCancelMissingDescriptor),
    };

    // 2 & 3. Exactly one output whose owner matches receiveAddr.
    // Caller passes a single destination; we wrap into a Vec for the base
    // builder.
    if config.destination.owner_pkh != descriptor.receive_addr {
        return Err(TokenError::SwapCancelOwnerMismatch);
    }

    // 4. Conservation
    if config.destination.satoshis != config.token_input.satoshis {
        return Err(TokenError::AmountMismatch {
            expected: config.token_input.satoshis,
            actual: config.destination.satoshis,
        });
    }

    let base = Stas3BaseConfig {
        token_inputs: vec![config.token_input],
        fee_txid: config.fee_txid,
        fee_vout: config.fee_vout,
        fee_satoshis: config.fee_satoshis,
        fee_locking_script: config.fee_locking_script,
        fee_private_key: config.fee_private_key,
        destinations: vec![config.destination],
        spend_type: Stas3SpendType::SwapCancellation,
        fee_rate: config.fee_rate,
    };

    let tx = build_stas3_base_tx(&base)?;

    // Defence-in-depth: the produced tx must contain exactly one non-change
    // STAS output (the engine output count restriction from spec §9.4).
    let stas_out_count = tx.outputs.iter().filter(|o| !o.change).count();
    if stas_out_count != 1 {
        return Err(TokenError::SwapCancelOutputCount(stas_out_count));
    }
    Ok(tx)
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

    // Sign token input with STAS3 template (spendType = 1 / Transfer per
    // spec §9.x). The §7 witness encodes slots 1..=20 verbatim from the
    // tx structure (the redeem-target P2PKH/P2MPKH output flows into the
    // change slots 13–14, since it isn't a STAS3 output).
    let witness = derive_witness_for_input(
        &tx,
        0,
        Some(1), // fee input is index 1
        Stas3TxType::Regular,
        Stas3SpendType::Transfer,
        SIGHASH_ALL_FORKID,
    )?;
    let unlocker = stas3_template::unlock_for_input_with_witness(
        config.token_input.locking_script.to_bytes(),
        &config.token_input.signing_key,
        None,
        witness,
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

    /// Build a STAS 3.0 locking script with both freezable and confiscatable
    /// flag bits set (flags = 0x03). Used by §9.3 confiscation tests.
    fn make_stas3_confiscatable_locking(
        owner_pkh: &[u8; 20],
        redemption_pkh: &[u8; 20],
    ) -> Script {
        crate::script::stas3_builder::build_stas3_locking_script_with_flags(
            owner_pkh,
            redemption_pkh,
            None,
            false,
            &[0x03], // freezable | confiscatable
            &[],
            &[],
        )
        .unwrap()
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

        // Spec §9.2 requires output owner == input owner.
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
                owner_pkh: [0x11; 20], // = input owner per §9.2
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
                owner_pkh: [0x11; 20], // = input owner per §9.2
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

    // -------------------------------------------------------------------
    // Spec §9.2 — freeze invariant tests (drift / non-freezable / count).
    // -------------------------------------------------------------------

    #[test]
    fn freeze_rejects_owner_drift() {
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
            fee_locking_script: test_p2pkh_script(&test_key()),
            fee_private_key: test_key(),
            destinations: vec![Stas3OutputParams {
                satoshis: 5000,
                owner_pkh: [0x33; 20], // drifted
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
        assert!(matches!(
            build_stas3_freeze_tx(&mut config),
            Err(TokenError::FreezeFieldDrift("owner_pkh"))
        ));
    }

    #[test]
    fn freeze_rejects_two_outputs() {
        let dest = Stas3OutputParams {
            satoshis: 2500,
            owner_pkh: [0x11; 20],
            redemption_pkh: [0x22; 20],
            frozen: false,
            freezable: true,
            service_fields: vec![],
            optional_data: vec![],
            action_data: None,
        };
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
            fee_locking_script: test_p2pkh_script(&test_key()),
            fee_private_key: test_key(),
            destinations: vec![dest.clone(), dest],
            spend_type: Stas3SpendType::Transfer,
            fee_rate: 500,
        };
        assert!(matches!(
            build_stas3_freeze_tx(&mut config),
            Err(TokenError::FreezeOutputCount(2))
        ));
    }

    #[test]
    fn freeze_rejects_input_without_freezable_flag() {
        // Build input with freezable = false → flags byte = 0x00.
        let owner = [0x11; 20];
        let redemption = [0x22; 20];
        let locking = build_stas3_locking_script(
            &owner, &redemption, None, false, false, &[], &[],
        )
        .unwrap();
        let mut config = Stas3BaseConfig {
            token_inputs: vec![TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 5000,
                locking_script: locking,
                signing_key: SigningKey::Single(test_key()),
            }],
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&test_key()),
            fee_private_key: test_key(),
            destinations: vec![Stas3OutputParams {
                satoshis: 5000,
                owner_pkh: owner,
                redemption_pkh: redemption,
                frozen: false,
                freezable: false,
                service_fields: vec![],
                optional_data: vec![],
                action_data: None,
            }],
            spend_type: Stas3SpendType::Transfer,
            fee_rate: 500,
        };
        assert!(matches!(
            build_stas3_freeze_tx(&mut config),
            Err(TokenError::FreezeFlagNotSet)
        ));
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
                // Spec §9.3: input MUST have CONFISCATABLE flag set.
                locking_script: make_stas3_confiscatable_locking(&[0x11; 20], &redemption_pkh),
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
            tx_type: 0,
        };

        let tx = build_stas3_confiscate_tx(config).unwrap();
        assert_eq!(tx.input_count(), 2); // 1 token + 1 fee
        assert!(tx.output_count() >= 1);
        assert_eq!(tx.outputs[0].satoshis, 5000);

        for input in &tx.inputs {
            assert!(input.unlocking_script.is_some());
        }
    }

    /// Spec §9.3: confiscation requires the CONFISCATABLE flag (0x02) on
    /// the input UTXO. An input lacking the flag must be rejected.
    #[test]
    fn confiscate_rejects_input_without_confiscatable_flag() {
        let token_key = test_key();
        let fee_key = test_key();
        let redemption_pkh = [0x22; 20];
        let config = Stas3ConfiscateConfig {
            token_inputs: vec![TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 5000,
                // freezable-only (flags = 0x01) → CONFISCATABLE not set.
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
                owner_pkh: redemption_pkh,
                redemption_pkh,
                frozen: false,
                freezable: true,
                service_fields: vec![],
                optional_data: vec![],
                action_data: None,
            }],
            fee_rate: 500,
            tx_type: 0,
        };

        assert!(matches!(
            build_stas3_confiscate_tx(config),
            Err(TokenError::ConfiscateFlagNotSet)
        ));
    }

    /// Fix G: spec §4 / §9.3 — confiscation places NO restriction on txType.
    /// Any caller-supplied `tx_type` (including non-zero, non-default values)
    /// MUST build successfully and round-trip through the parser.
    #[test]
    fn confiscate_accepts_arbitrary_tx_type() {
        let token_key = test_key();
        let fee_key = test_key();
        let redemption_pkh = [0x22; 20];

        // Try several non-default txType values; all must build and parse.
        for tx_type in [0u8, 1, 5, 42, 0xFF] {
            let config = Stas3ConfiscateConfig {
                token_inputs: vec![TokenInput {
                    txid: dummy_hash(),
                    vout: 0,
                    satoshis: 5000,
                    locking_script: make_stas3_confiscatable_locking(
                        &[0x11; 20],
                        &redemption_pkh,
                    ),
                    signing_key: SigningKey::Single(token_key.clone()),
                }],
                fee_txid: dummy_hash(),
                fee_vout: 1,
                fee_satoshis: 50_000,
                fee_locking_script: test_p2pkh_script(&fee_key),
                fee_private_key: fee_key.clone(),
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
                tx_type,
            };

            let tx = build_stas3_confiscate_tx(config)
                .unwrap_or_else(|e| panic!("tx_type={} should build, got {:?}", tx_type, e));
            assert_eq!(
                tx.outputs[0].satoshis, 5000,
                "tx_type={} must produce a valid tx",
                tx_type
            );
            // Round-trip the locking script through the parser.
            let parsed = read_locking_script(tx.outputs[0].locking_script.to_bytes());
            assert_eq!(
                parsed.script_type,
                ScriptType::Stas3,
                "tx_type={} output must parse as STAS3",
                tx_type
            );
        }
    }

    #[test]
    fn confiscate_frozen_input_allowed() {
        // Frozen inputs CAN be confiscated — this should succeed
        let token_key = test_key();
        let fee_key = test_key();
        let redemption_pkh = [0x22; 20];

        // Frozen + freezable + confiscatable so spec §9.3 invariants pass.
        let frozen_locking = crate::script::stas3_builder::build_stas3_locking_script_with_flags(
            &[0x11; 20],
            &redemption_pkh,
            None,
            true,
            &[0x03],
            &[],
            &[],
        )
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
            tx_type: 0,
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
            tx_type: 0,
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
            next: None,
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
            next: None,
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
            next: None,
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
            spend_type: Stas3SpendType::Transfer, // matches the swap-swap path
            fee_rate: 500,
        };

        // Auto-detect: both have swap data → SwapSwap → spendType = Transfer
        // (per spec §9.5; previously this path used SwapCancellation).
        let tx = build_stas3_swap_flow_tx(&mut config).unwrap();
        assert_eq!(tx.input_count(), 3);
    }

    // -------------------------------------------------------------------
    // Fix F: swap remainder inherits both owner and var2 (spec §9.5)
    // -------------------------------------------------------------------

    /// Build a 2-input swap where input A is partially consumed and a
    /// remainder output is produced. The remainder MUST inherit BOTH the
    /// source UTXO's `owner` field and `var2` (the swap descriptor).
    #[test]
    fn swap_remainder_inherits_owner_and_var2() {
        let fee_key = test_key();
        let owner_a: [u8; 20] = [0xA1; 20];
        let owner_b: [u8; 20] = [0xB2; 20];
        let redemption = [0x22; 20];

        // Source A's swap descriptor — must be inherited byte-for-byte by remainder.
        let swap_data_a = ActionData::Swap {
            requested_script_hash: [0xab; 32],
            requested_pkh: [0xcd; 20],
            rate_numerator: 2,
            rate_denominator: 3,
            next: None,
        };

        let source_a_locking = make_stas3_swap_locking(&owner_a, &redemption, &swap_data_a);
        let source_b_locking = make_stas3_swap_locking(&owner_b, &redemption, &swap_data_a);

        // Build the remainder output via the helper, which inherits owner + var2.
        let remainder = build_swap_remainder_output(
            source_a_locking.to_bytes(),
            2000,
            redemption,
            true,
        )
        .unwrap();

        assert_eq!(remainder.owner_pkh, owner_a, "remainder must inherit source owner");
        assert!(
            matches!(remainder.action_data, Some(ActionData::Swap { .. })),
            "remainder must inherit source var2 (swap descriptor)"
        );

        // 2-input swap with a remainder for input A (split path).
        let mut config = Stas3BaseConfig {
            token_inputs: vec![
                TokenInput {
                    txid: dummy_hash(),
                    vout: 0,
                    satoshis: 6000,
                    locking_script: source_a_locking.clone(),
                    signing_key: SigningKey::Single(test_key()),
                },
                TokenInput {
                    txid: dummy_hash(),
                    vout: 1,
                    satoshis: 4000,
                    locking_script: source_b_locking,
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
                    action_data: None,
                },
                Stas3OutputParams {
                    satoshis: 4000,
                    owner_pkh: [0x55; 20],
                    redemption_pkh: redemption,
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                    action_data: None,
                },
                remainder, // remainder for source A
            ],
            spend_type: Stas3SpendType::SwapCancellation,
            fee_rate: 500,
        };

        let tx = build_stas3_swap_swap_tx(&mut config).unwrap();

        // The remainder output is index 2.
        let parsed = read_locking_script(tx.outputs[2].locking_script.to_bytes());
        assert_eq!(parsed.script_type, ScriptType::Stas3);
        let stas3 = parsed.stas3.unwrap();

        // Owner inheritance
        assert_eq!(
            stas3.owner, owner_a,
            "remainder output owner must equal source A owner"
        );

        // Var2 (swap descriptor) inheritance — byte-identical
        match (stas3.action_data_parsed, &swap_data_a) {
            (
                Some(ActionData::Swap {
                    requested_script_hash: rh,
                    requested_pkh: rp,
                    rate_numerator: rn,
                    rate_denominator: rd,
                    next: rnext,
                }),
                ActionData::Swap {
                    requested_script_hash: sh,
                    requested_pkh: sp,
                    rate_numerator: sn,
                    rate_denominator: sd,
                    next: snext,
                },
            ) => {
                assert_eq!(rh, *sh);
                assert_eq!(rp, *sp);
                assert_eq!(rn, *sn);
                assert_eq!(rd, *sd);
                assert_eq!(&rnext, snext);
            }
            (other, _) => panic!("remainder must inherit Swap descriptor, got {:?}", other),
        }
    }

    // -------------------------------------------------------------------
    // Fix E: arbitrator-free swap (owner == HASH160(""))
    // -------------------------------------------------------------------

    #[test]
    fn arbitrator_free_input_unlocks_with_op_false() {
        use crate::script::stas3_swap::EMPTY_HASH160;

        let fee_key = test_key();
        let swap_data = test_swap_data();
        let redemption = [0x22; 20];

        // Input 0: regular signed input. Input 1: arbitrator-free (owner = EMPTY_HASH160).
        let arbfree_locking = make_stas3_swap_locking(&EMPTY_HASH160, &redemption, &swap_data);

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
                    locking_script: arbfree_locking,
                    // Any key — the no-auth path ignores it.
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

        // Input 1 (arbitrator-free) unlocking script per spec §10.3: full
        // §7 witness body (slots 1..=20) followed by `OP_FALSE` in place
        // of `<sig> <pubkey>`. The authz slot is therefore the LAST push
        // and MUST be empty (OP_FALSE).
        let unlock = tx.inputs[1].unlocking_script.as_ref().expect("must be signed");
        let chunks = unlock.chunks().expect("unlock script chunks parse");
        let last = chunks.last().expect("at least one push");
        assert!(
            last.data.is_none() || last.data.as_ref().is_some_and(|d| d.is_empty()),
            "arbitrator-free leg authz slot must be OP_FALSE"
        );
        // Witness body must be non-empty — this is no longer the legacy
        // single-OP_FALSE form.
        assert!(
            unlock.to_bytes().len() > 1,
            "arbitrator-free leg now carries §7 witness body (got {} bytes)",
            unlock.to_bytes().len()
        );

        // Input 0 (regular) must be witness ‖ <sig> <pubkey> (much longer).
        let unlock0 = tx.inputs[0].unlocking_script.as_ref().expect("must be signed");
        assert!(
            unlock0.to_bytes().len() > 70,
            "regular leg should be witness + sig + pubkey ({} bytes)",
            unlock0.to_bytes().len()
        );
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
            next: None,
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
                next,
            }) => {
                assert_eq!(requested_script_hash, [0xab; 32]);
                assert_eq!(requested_pkh, [0xef; 20]);
                assert_eq!(rate_numerator, 42);
                assert_eq!(rate_denominator, 7);
                assert!(next.is_none(), "non-recursive descriptor should have next = None");
            }
            other => panic!("expected Swap action data, got {:?}", other),
        }
    }

    // ---------------------------------------------------------------
    // §9.4 Swap cancellation tests (Priority 2c)
    // ---------------------------------------------------------------

    /// Build a swap descriptor whose `receive_addr` is the given PKH.
    fn cancel_swap_data(receive_pkh: [u8; 20]) -> ActionData {
        ActionData::Swap {
            requested_script_hash: [0xab; 32],
            requested_pkh: receive_pkh, // = receive_addr in the typed descriptor
            rate_numerator: 1,
            rate_denominator: 2,
            next: None,
        }
    }

    #[test]
    fn swap_cancel_succeeds_when_owner_matches_receive_addr() {
        let receive = [0x77; 20];
        let redemption = [0x22; 20];
        let owner_a = [0x11; 20];
        let token_key = test_key();
        let fee_key = test_key();

        let swap_data = cancel_swap_data(receive);
        let locking = make_stas3_swap_locking(&owner_a, &redemption, &swap_data);

        let config = Stas3SwapCancelConfig {
            token_input: TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 5000,
                locking_script: locking,
                signing_key: SigningKey::Single(token_key),
            },
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destination: Stas3OutputParams {
                satoshis: 5000,
                owner_pkh: receive, // == receive_addr
                redemption_pkh: redemption,
                frozen: false,
                freezable: true,
                service_fields: vec![],
                optional_data: vec![],
                action_data: None,
            },
            fee_rate: 500,
        };

        let tx = build_stas3_swap_cancel_tx(config).unwrap();
        // Exactly one non-change STAS output, addressed to receive_addr.
        let stas_outs: Vec<_> = tx.outputs.iter().filter(|o| !o.change).collect();
        assert_eq!(stas_outs.len(), 1);
        let parsed = read_locking_script(stas_outs[0].locking_script.to_bytes());
        assert_eq!(parsed.script_type, ScriptType::Stas3);
        assert_eq!(parsed.stas3.unwrap().owner, receive);
    }

    #[test]
    fn swap_cancel_rejects_owner_mismatch() {
        let receive = [0x77; 20];
        let redemption = [0x22; 20];
        let owner_a = [0x11; 20];
        let token_key = test_key();
        let fee_key = test_key();

        let swap_data = cancel_swap_data(receive);
        let locking = make_stas3_swap_locking(&owner_a, &redemption, &swap_data);

        let config = Stas3SwapCancelConfig {
            token_input: TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 5000,
                locking_script: locking,
                signing_key: SigningKey::Single(token_key),
            },
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destination: Stas3OutputParams {
                satoshis: 5000,
                owner_pkh: [0x99; 20], // != receive_addr
                redemption_pkh: redemption,
                frozen: false,
                freezable: true,
                service_fields: vec![],
                optional_data: vec![],
                action_data: None,
            },
            fee_rate: 500,
        };

        assert!(matches!(
            build_stas3_swap_cancel_tx(config),
            Err(TokenError::SwapCancelOwnerMismatch)
        ));
    }

    #[test]
    fn swap_cancel_rejects_input_without_swap_descriptor() {
        let redemption = [0x22; 20];
        let token_key = test_key();
        let fee_key = test_key();

        // No swap descriptor in the locking script.
        let locking = make_stas3_locking(&[0x11; 20], &redemption);

        let config = Stas3SwapCancelConfig {
            token_input: TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 5000,
                locking_script: locking,
                signing_key: SigningKey::Single(token_key),
            },
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destination: Stas3OutputParams {
                satoshis: 5000,
                owner_pkh: [0x77; 20],
                redemption_pkh: redemption,
                frozen: false,
                freezable: true,
                service_fields: vec![],
                optional_data: vec![],
                action_data: None,
            },
            fee_rate: 500,
        };

        assert!(matches!(
            build_stas3_swap_cancel_tx(config),
            Err(TokenError::SwapCancelMissingDescriptor)
        ));
    }

    // -------------------------------------------------------------------
    // §7 unlock witness — end-to-end shape tests across factory families.
    //
    // Each test builds a tx through the public API and asserts that the
    // produced unlocking script has the slots-1..=20 witness body
    // followed by the authz push (`<sig> <pubkey>` for P2PKH).
    // -------------------------------------------------------------------

    use crate::template::stas3::encode_unlock_amount;

    /// Walk a P2PKH-authz unlock and return slot pushes (1..=20) plus the
    /// trailing two authz pushes (sig + pubkey). Returns the full chunk
    /// list for callers that want to inspect raw shape too.
    fn split_witness_and_authz_p2pkh(
        unlock_bytes: &[u8],
    ) -> Vec<bsv_script::ScriptChunk> {
        let script = bsv_script::Script::from_bytes(unlock_bytes);
        script.chunks().expect("unlock script chunks parse")
    }

    /// Confirm that the chunk list represents a §7 witness followed by a
    /// P2PKH authz push (`<sig> <pubkey>` — last 2 chunks). Witness
    /// pushes follow the slot order described on `Stas3UnlockWitness`.
    ///
    /// Returns the witness slot chunks (everything but the last 2).
    fn assert_witness_shape_p2pkh<'a>(
        chunks: &'a [bsv_script::ScriptChunk],
        expected_first_amount: u64,
    ) -> &'a [bsv_script::ScriptChunk] {
        // Authz: last two chunks must be sig (~71..=73B) + pubkey (33B compressed).
        assert!(chunks.len() >= 2, "witness + authz must produce ≥2 chunks");
        let last = chunks.last().unwrap();
        let second_last = &chunks[chunks.len() - 2];
        let pubkey = last.data.as_ref().expect("pubkey push");
        let sig = second_last.data.as_ref().expect("sig push");
        assert_eq!(pubkey.len(), 33, "compressed pubkey is 33 bytes");
        assert!(
            (71..=73).contains(&sig.len()),
            "DER sig + sighash flag is 71..=73 bytes (got {})",
            sig.len()
        );
        assert_eq!(
            *sig.last().unwrap(),
            0x41,
            "sig must end with SIGHASH_ALL_FORKID (0x41)"
        );
        // Witness slot 1 = out1_amount: minimal LE encoding.
        let slot1 = chunks[0].data.as_ref();
        let expected = encode_unlock_amount(expected_first_amount);
        if expected.is_empty() {
            assert!(
                slot1.is_none() || slot1.is_some_and(|d| d.is_empty()),
                "slot 1 (out1_amount=0) must be OP_FALSE (empty push)"
            );
        } else {
            assert_eq!(
                slot1.expect("slot 1 must be a push").as_slice(),
                expected.as_slice(),
                "slot 1 (out1_amount={expected_first_amount}) must be minimal LE",
            );
        }
        &chunks[..chunks.len() - 2]
    }

    /// Locate the `txType` (slot 18) chunk in the witness body. The
    /// witness emits in order: 3*N STAS-output chunks (N≤4), 2 change
    /// slots, 1 noteData slot, 2 funding slots, then txType. The total
    /// preamble size is `3*N + 2 + 1 + 2 = 3N + 5`, so txType sits at
    /// index `3N + 5 - 1` (0-indexed) → `3N + 4` if we count from the
    /// start of the witness. But we don't always know N here — instead
    /// we look for the txType byte from the END: spendType is the LAST
    /// witness chunk, preimage is second-from-last, txType is third.
    fn extract_witness_tx_and_spend_types(
        witness_chunks: &[bsv_script::ScriptChunk],
    ) -> (u8, u8) {
        assert!(
            witness_chunks.len() >= 3,
            "witness must contain at least txType+preimage+spendType"
        );
        let n = witness_chunks.len();
        let tx_type = witness_chunks[n - 3]
            .data
            .as_ref()
            .map(|d| d.first().copied().unwrap_or(0))
            .unwrap_or(0);
        let spend_type = witness_chunks[n - 1]
            .data
            .as_ref()
            .map(|d| d.first().copied().unwrap_or(0))
            .unwrap_or(0);
        (tx_type, spend_type)
    }

    #[test]
    fn e2e_base_tx_unlock_carries_witness_then_p2pkh_authz() {
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
        let unlock = tx.inputs[0]
            .unlocking_script
            .as_ref()
            .expect("token input signed");
        let chunks = split_witness_and_authz_p2pkh(unlock.to_bytes());
        let witness = assert_witness_shape_p2pkh(&chunks, 5000);
        let (tx_type, spend_type) = extract_witness_tx_and_spend_types(witness);
        assert_eq!(tx_type, 0, "base/transfer tx_type = Regular");
        assert_eq!(spend_type, 1, "base/transfer spendType = Transfer");
    }

    #[test]
    fn e2e_freeze_tx_unlock_witness_spend_type_is_freeze_unfreeze() {
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
                owner_pkh: [0x11; 20],
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

        let tx = build_stas3_freeze_tx(&mut config).unwrap();
        let unlock = tx.inputs[0]
            .unlocking_script
            .as_ref()
            .expect("token input signed");
        let chunks = split_witness_and_authz_p2pkh(unlock.to_bytes());
        let witness = assert_witness_shape_p2pkh(&chunks, 5000);
        let (tx_type, spend_type) = extract_witness_tx_and_spend_types(witness);
        assert_eq!(tx_type, 0, "freeze tx_type = Regular");
        assert_eq!(spend_type, 2, "freeze spendType = FreezeUnfreeze (2)");
    }

    #[test]
    fn e2e_confiscate_tx_witness_spend_type_is_confiscation() {
        let token_key = test_key();
        let fee_key = test_key();
        let redemption_pkh = [0x22; 20];
        let config = Stas3ConfiscateConfig {
            token_inputs: vec![TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 5000,
                locking_script: make_stas3_confiscatable_locking(
                    &[0x11; 20],
                    &redemption_pkh,
                ),
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
            tx_type: 5, // pin a non-default txType to verify it round-trips.
        };
        let tx = build_stas3_confiscate_tx(config).unwrap();
        let unlock = tx.inputs[0]
            .unlocking_script
            .as_ref()
            .expect("token input signed");
        let chunks = split_witness_and_authz_p2pkh(unlock.to_bytes());
        let witness = assert_witness_shape_p2pkh(&chunks, 5000);
        let (tx_type, spend_type) = extract_witness_tx_and_spend_types(witness);
        assert_eq!(tx_type, 5, "confiscate tx_type echoes caller-supplied byte");
        assert_eq!(spend_type, 3, "confiscate spendType = Confiscation (3)");
    }

    #[test]
    fn e2e_swap_cancel_tx_witness_spend_type_is_swap_cancellation() {
        let receive = [0x77; 20];
        let redemption = [0x22; 20];
        let owner_a = [0x11; 20];
        let token_key = test_key();
        let fee_key = test_key();
        let swap_data = cancel_swap_data(receive);
        let locking = make_stas3_swap_locking(&owner_a, &redemption, &swap_data);
        let config = Stas3SwapCancelConfig {
            token_input: TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 5000,
                locking_script: locking,
                signing_key: SigningKey::Single(token_key),
            },
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destination: Stas3OutputParams {
                satoshis: 5000,
                owner_pkh: receive,
                redemption_pkh: redemption,
                frozen: false,
                freezable: true,
                service_fields: vec![],
                optional_data: vec![],
                action_data: None,
            },
            fee_rate: 500,
        };
        let tx = build_stas3_swap_cancel_tx(config).unwrap();
        let unlock = tx.inputs[0]
            .unlocking_script
            .as_ref()
            .expect("token input signed");
        let chunks = split_witness_and_authz_p2pkh(unlock.to_bytes());
        let witness = assert_witness_shape_p2pkh(&chunks, 5000);
        let (tx_type, spend_type) = extract_witness_tx_and_spend_types(witness);
        assert_eq!(tx_type, 0, "swap-cancel tx_type = Regular");
        assert_eq!(spend_type, 4, "swap-cancel spendType = SwapCancellation (4)");
    }

    #[test]
    fn e2e_atomic_swap_witness_tx_type_is_atomic_swap() {
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
        for i in 0..2 {
            let unlock = tx.inputs[i]
                .unlocking_script
                .as_ref()
                .expect("token input signed");
            let chunks = split_witness_and_authz_p2pkh(unlock.to_bytes());
            let witness = assert_witness_shape_p2pkh(&chunks, 5000);
            let (tx_type, spend_type) = extract_witness_tx_and_spend_types(witness);
            assert_eq!(
                tx_type, 1,
                "atomic-swap input {i} tx_type = AtomicSwap (1)"
            );
            assert_eq!(
                spend_type, 1,
                "atomic-swap input {i} spendType = Transfer (1) per spec §9.5"
            );
        }
    }

    #[test]
    fn e2e_redeem_tx_witness_spend_type_is_transfer() {
        let issuer_key = test_key();
        let fee_key = test_key();
        let config = make_redeem_config(&issuer_key, &fee_key, 10000, 10000, vec![], false);
        let tx = build_stas3_redeem_tx(config).unwrap();
        let unlock = tx.inputs[0]
            .unlocking_script
            .as_ref()
            .expect("token input signed");
        let chunks = split_witness_and_authz_p2pkh(unlock.to_bytes());
        // Note: redeem produces a P2PKH redeem output (NOT a STAS3 output)
        // → out1_amount slot reflects the lack of a leading STAS3 output, so
        // the FIRST chunk corresponds to the change_amount slot 13 (not slot 1).
        // Specifically: stas_outputs is empty → witness starts at slot 13.
        // Let's verify the LAST 3 chunks are txType / preimage / spendType,
        // and the trailing 2 are the P2PKH authz.
        assert!(chunks.len() >= 5);
        let last = chunks.last().unwrap();
        let second_last = &chunks[chunks.len() - 2];
        let pubkey = last.data.as_ref().expect("pubkey push");
        let sig = second_last.data.as_ref().expect("sig push");
        assert_eq!(pubkey.len(), 33, "compressed pubkey");
        assert!((71..=73).contains(&sig.len()), "DER sig + sighash flag");
        // Witness slots: spendType is third-from-end (after authz pubkey + sig).
        let n = chunks.len();
        let spend_type_byte = chunks[n - 3]
            .data
            .as_ref()
            .map(|d| d.first().copied().unwrap_or(0))
            .unwrap_or(0);
        assert_eq!(spend_type_byte, 1, "redeem spendType = Transfer (1)");
    }
}
