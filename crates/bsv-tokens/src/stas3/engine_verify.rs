//! End-to-end script-engine verification helper for STAS 3.0 transactions.
//!
//! Mirrors `BSV.Tokens.Stas3.EngineVerify.verify/4` from the Elixir SDK.
//! Given a fully-signed transaction produced by the STAS 3.0 factory, this
//! module pulls out the unlocking script for a single input, builds a
//! BIP-143 + ECDSA `TxContext`, and runs `bsv_script::interpreter::Engine`
//! against that input's previous locking script.
//!
//! The interpreter accepting the unlock-vs-lock pair is the canonical
//! end-to-end smoke check for STAS 3.0 in this SDK.
//!
//! # Output
//!
//! * `Ok(())` — interpreter accepted the script pair.
//! * `Err(Stas3VerifyError)` — interpreter rejected, with the underlying
//!   `InterpreterError` propagated, or a structural problem (no signed
//!   unlock, bad input index, etc.).

use bsv_primitives::ec::{PublicKey, Signature};
use bsv_script::interpreter::{Engine, InterpreterError, ScriptFlags, TxContext};
use bsv_script::Script;
use bsv_transaction::sighash::signature_hash;
use bsv_transaction::transaction::Transaction;

/// Error type returned by [`verify_input`].
#[derive(Debug)]
pub enum Stas3VerifyError {
    /// `input_index` was out of range for `tx`.
    InputOutOfRange {
        /// The requested input index.
        index: usize,
        /// The number of inputs the transaction has.
        input_count: usize,
    },
    /// The selected input had no `unlocking_script` (it wasn't signed yet).
    UnlockScriptMissing(usize),
    /// The script interpreter rejected the unlock-vs-lock pair.
    Interpreter(InterpreterError),
}

impl std::fmt::Display for Stas3VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InputOutOfRange { index, input_count } => write!(
                f,
                "input index {} out of range (tx has {} inputs)",
                index, input_count
            ),
            Self::UnlockScriptMissing(idx) => {
                write!(f, "input {} has no unlocking script", idx)
            }
            Self::Interpreter(err) => write!(f, "interpreter rejected: {:?}", err),
        }
    }
}

impl std::error::Error for Stas3VerifyError {}

impl From<InterpreterError> for Stas3VerifyError {
    fn from(err: InterpreterError) -> Self {
        Self::Interpreter(err)
    }
}

/// `TxContext` adapter that recomputes the BIP-143 sighash for `tx` against
/// `prev_locking_script` / `prev_amount` and verifies the supplied DER
/// signature with the supplied compressed pubkey.
struct EngineCtx<'a> {
    tx: &'a Transaction,
    prev_locking_script: Vec<u8>,
    prev_amount: u64,
}

impl<'a> TxContext for EngineCtx<'a> {
    fn verify_signature(
        &self,
        full_sig: &[u8],
        pub_key: &[u8],
        // The interpreter passes its own subscript here (the locking script
        // with sig-pushdata removed when forkid isn't set). For BIP-143 the
        // scriptCode that's committed to is the previous locking script, not
        // the engine's subscript — the Elixir reference uses the previous
        // locking script too. So we ignore `_sub_script` here on purpose.
        _sub_script: &Script,
        input_idx: usize,
        sighash_flag: u32,
    ) -> Result<bool, InterpreterError> {
        if full_sig.is_empty() {
            return Ok(false);
        }
        // Strip the trailing sighash flag byte to get the DER body.
        let der = &full_sig[..full_sig.len() - 1];

        let sig = match Signature::from_der(der) {
            Ok(s) => s,
            Err(_) => return Ok(false),
        };
        let pk = match PublicKey::from_bytes(pub_key) {
            Ok(p) => p,
            Err(_) => return Ok(false),
        };

        let hash = match signature_hash(
            self.tx,
            input_idx,
            &self.prev_locking_script,
            sighash_flag,
            self.prev_amount,
        ) {
            Ok(h) => h,
            Err(_) => return Ok(false),
        };

        Ok(sig.verify(&hash, &pk))
    }

    fn lock_time(&self) -> u32 {
        self.tx.lock_time
    }

    fn tx_version(&self) -> u32 {
        self.tx.version
    }

    fn input_sequence(&self, input_idx: usize) -> u32 {
        self.tx
            .inputs
            .get(input_idx)
            .map(|i| i.sequence_number)
            .unwrap_or(0xFFFF_FFFF)
    }
}

/// Verify a single input of `tx` against `prev_locking_script` (the
/// locking script of the UTXO that input is spending) using the SDK's
/// full script interpreter and a real BIP-143 sighash function.
///
/// Uses post-genesis interpreter flags (`UTXO_AFTER_GENESIS` +
/// `ENABLE_SIGHASH_FORKID`) — the same defaults the Elixir reference uses.
///
/// Returns `Ok(())` if the engine accepts the unlock-vs-lock pair, or
/// `Err(Stas3VerifyError)` otherwise.
pub fn verify_input(
    tx: &Transaction,
    input_index: usize,
    prev_locking_script: &Script,
    prev_amount: u64,
) -> Result<(), Stas3VerifyError> {
    if input_index >= tx.inputs.len() {
        return Err(Stas3VerifyError::InputOutOfRange {
            index: input_index,
            input_count: tx.inputs.len(),
        });
    }
    let input = &tx.inputs[input_index];
    let unlock = input
        .unlocking_script
        .as_ref()
        .ok_or(Stas3VerifyError::UnlockScriptMissing(input_index))?;

    let ctx = EngineCtx {
        tx,
        prev_locking_script: prev_locking_script.to_bytes().to_vec(),
        prev_amount,
    };

    let engine = Engine::new();
    engine
        .execute(
            unlock,
            prev_locking_script,
            ScriptFlags::UTXO_AFTER_GENESIS | ScriptFlags::ENABLE_SIGHASH_FORKID,
            Some(&ctx),
            input_index,
        )
        .map_err(Stas3VerifyError::from)
}
