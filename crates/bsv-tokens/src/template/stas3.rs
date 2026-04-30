//! STAS 3.0 unlocking script templates (P2PKH and P2MPKH).
//!
//! Structurally identical to the STAS unlocking scripts but stores the
//! [`STAS 3.0 spend type for future use when preimage-based validation is added.
//!
//! Also exposes a no-auth path for arbitrator-free swap inputs (spec §9.5 /
//! §10.3): when the owner field equals `HASH160("")`, the engine accepts
//! `OP_FALSE` in place of both signature and address preimage; this module
//! produces an unlocking script that pushes only `OP_FALSE`.

use bsv_primitives::ec::PrivateKey;
use bsv_script::Script;
use bsv_transaction::sighash::{calc_preimage, SIGHASH_ALL_FORKID};
use bsv_transaction::template::p2mpkh::MultisigScript;
use bsv_transaction::template::UnlockingScriptTemplate;
use bsv_transaction::transaction::Transaction;
use bsv_transaction::TransactionError;

use crate::script::stas3_swap::is_arbitrator_free_owner;
use crate::types::{Stas3SpendType, Stas3TxType, SigningKey};

// ---------------------------------------------------------------------------
// Fix K: STAS 3.0 unlocking-script amount encoding (spec §7).
//
// `out{1..4}_amount` and `change_amount` are "Unsigned LE (up to 8 B) or
// empty". This means minimal little-endian: zero is an empty push, otherwise
// emit only as many low-order bytes as needed (no sign-padding, since these
// are unsigned). Maximum width is 8 bytes (u64).
//
// Sign-bit safety
// ---------------
// The engine treats the pushed bytes as a Bitcoin script number when it
// later splices them into the BIP-143-style outputs blob via
// `OP_BIN2NUM` / `OP_NUM2BIN`. Bitcoin script numbers are sign-magnitude
// little-endian: when the high bit of the most-significant byte is set,
// the value is interpreted as negative. For unsigned-LE token amounts
// whose top byte happens to have its high bit set (any value with a top
// byte ≥ 0x80, e.g. 0xBD0E = 48398), we MUST append a `0x00` sentinel
// byte to keep the value non-negative when read as a script number.
// Without it the engine reconstructs a wildly different change amount in
// its outputs blob and the BIP-143 hashOutputs check fails.
// ---------------------------------------------------------------------------

/// Encode `value` as little-endian bytes, appending a `0x00` sign-bit
/// sentinel when the high bit of the most-significant byte is set so the
/// engine reads it back as the same non-negative integer via OP_BIN2NUM.
///
/// Returns an empty `Vec` for `0` (matching Bitcoin's "empty array = 0"
/// convention).
pub(crate) fn amount_to_script_num_le(value: u64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let raw = value.to_le_bytes();
    // Strip trailing zero bytes — minimal LE encoding for an unsigned value.
    let mut len = 8;
    while len > 1 && raw[len - 1] == 0 {
        len -= 1;
    }
    let mut bytes = raw[..len].to_vec();
    // Append a 0x00 sentinel when the high bit of the last byte is set so
    // the value isn't interpreted as a negative script number by the
    // engine (sign-magnitude little-endian).
    if bytes.last().map(|b| b & 0x80 != 0).unwrap_or(false) {
        bytes.push(0x00);
    }
    bytes
}

/// Encode an unsigned amount as the body of a minimal little-endian push,
/// per STAS 3.0 spec §7. Zero produces an empty body (intended to be emitted
/// as `OP_FALSE`/`OP_0`); non-zero amounts produce 1..=9 bytes — the
/// minimal LE encoding plus a `0x00` sign-bit sentinel when the high bit of
/// the most-significant byte is set.
///
/// This is the body only — callers wrap it with the appropriate push opcode
/// (`OP_FALSE` for empty, otherwise a bare push).
pub fn encode_unlock_amount(value: u64) -> Vec<u8> {
    amount_to_script_num_le(value)
}

/// Encode an amount as a complete minimal push (header + body) for inclusion
/// in a STAS 3.0 unlocking script per spec §7. Zero → `[0x00]` (`OP_FALSE`);
/// otherwise a bare push of 1..=9 minimal LE bytes (8 LE bytes + an
/// optional 0x00 sign-bit sentinel — see [`encode_unlock_amount`]).
pub fn push_unlock_amount(value: u64) -> Vec<u8> {
    let body = encode_unlock_amount(value);
    if body.is_empty() {
        vec![0x00] // OP_FALSE / OP_0 = empty push
    } else {
        let mut out = Vec::with_capacity(body.len() + 1);
        out.push(body.len() as u8); // bare push, len <= 9 always fits
        out.extend_from_slice(&body);
        out
    }
}

// ---------------------------------------------------------------------------
// §7 Unlock witness assembly (slots 1..=20)
// ---------------------------------------------------------------------------

/// Identifier for one of the four primary STAS outputs in a STAS 3.0 spend
/// (spec §7 slots 1..=12). Each present output contributes a triplet
/// `(amount, owner_pkh, var2)` to the witness; absent outputs are skipped
/// entirely (no push at all).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stas3WitnessOutput {
    /// STAS satoshi amount carried by the output. Encoded via
    /// [`encode_unlock_amount`].
    pub amount: u64,
    /// Owner public key hash (20 bytes raw).
    pub owner_pkh: [u8; 20],
    /// `var2` body bytes (the "action data") — pushed verbatim. Empty for a
    /// passive STAS output.
    pub var2: Vec<u8>,
}

/// Optional change leg of a STAS 3.0 spend (spec §7 slots 13–14).
///
/// Encoded as `<change_amount> <change_addr>`. Absence of change is encoded
/// as `OP_FALSE` for both slots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stas3WitnessChange {
    /// Change amount in satoshis (minimal LE).
    pub amount: u64,
    /// Change address PKH (20 bytes raw P2PKH-PKH).
    pub addr_pkh: [u8; 20],
}

/// Full STAS 3.0 unlocking-script witness (spec §7 slots 1..=20).
///
/// Slot 21+ (the authorization push: P2PKH `<sig> <pubkey>`, P2MPKH
/// `OP_0 sig … redeem_buffer`, or no-auth `OP_FALSE`) is appended by the
/// template implementation; this struct only encodes slots 1..=20.
#[derive(Debug, Clone)]
pub struct Stas3UnlockWitness {
    /// Up to 4 STAS output triplets (spec §7 slots 1–12). Position in the
    /// vec corresponds to STAS-output index. When fewer than 4 are present
    /// the trailing slots are SKIPPED ENTIRELY (no push at all per spec).
    pub stas_outputs: Vec<Stas3WitnessOutput>,
    /// Change leg (spec §7 slots 13–14). `None` → both emitted as OP_FALSE.
    pub change: Option<Stas3WitnessChange>,
    /// `noteData` payload (spec §7 slot 15). `None` → OP_FALSE. The payload
    /// must be ≤ 65 533 bytes; see [`Stas3UnlockWitness::write_into`].
    pub note_data: Option<Vec<u8>>,
    /// Funding input pointer (spec §7 slots 16–17): `(funding_txid,
    /// funding_vout)` of the funding input on this spending tx. `None` →
    /// both emitted as OP_FALSE.
    pub funding_input: Option<([u8; 32], u32)>,
    /// `txType` byte (spec §7 slot 18, range 0..=7).
    pub tx_type: Stas3TxType,
    /// BIP-143-style preimage of the input being signed (spec §7 slot 19).
    pub sighash_preimage: Vec<u8>,
    /// `spendType` byte (spec §7 slot 20).
    pub spend_type: Stas3SpendType,
}

impl Stas3UnlockWitness {
    /// Maximum allowed `noteData` length per spec §7.
    pub const MAX_NOTE_DATA_LEN: usize = 65_533;

    /// Write slots 1..=20 into `script` in stack-push order (i.e. bottom of
    /// stack first). The caller appends the slot 21+ authorization push
    /// afterward.
    ///
    /// # Errors
    /// Returns [`TransactionError::SigningError`] when:
    /// - `note_data` exceeds [`Self::MAX_NOTE_DATA_LEN`]
    /// - more than 4 STAS outputs are present
    /// - `tx_type` is out of range (compile-time guaranteed via the enum)
    pub fn write_into(&self, script: &mut Script) -> Result<(), TransactionError> {
        // Validation
        if self.stas_outputs.len() > 4 {
            return Err(TransactionError::SigningError(format!(
                "STAS 3.0 witness supports at most 4 STAS outputs, got {}",
                self.stas_outputs.len()
            )));
        }
        if let Some(note) = &self.note_data {
            if note.len() > Self::MAX_NOTE_DATA_LEN {
                return Err(TransactionError::SigningError(format!(
                    "noteData payload too large: {} bytes (max {})",
                    note.len(),
                    Self::MAX_NOTE_DATA_LEN
                )));
            }
        }

        // Slots 1–12: STAS output triplets in spec order — output 1, 2, 3, 4.
        // Outputs that are absent are SKIPPED ENTIRELY (no push at all).
        for out in &self.stas_outputs {
            // amount — minimal LE up to 8B (empty push for zero).
            script.append_push_data(&encode_unlock_amount(out.amount))?;
            // owner_pkh — 20B raw push.
            script.append_push_data(&out.owner_pkh)?;
            // var2 — single push of body bytes (may be empty → OP_FALSE).
            script.append_push_data(&out.var2)?;
        }

        // Slot 13: change_amount — minimal LE; OP_FALSE when no change.
        // Slot 14: change_addr — 20B; OP_FALSE when no change.
        match &self.change {
            Some(ch) => {
                script.append_push_data(&encode_unlock_amount(ch.amount))?;
                script.append_push_data(&ch.addr_pkh)?;
            }
            None => {
                push_op_false(script)?;
                push_op_false(script)?;
            }
        }

        // Slot 15: noteData — payload bytes; OP_FALSE when None.
        match &self.note_data {
            Some(note) => script.append_push_data(note)?,
            None => push_op_false(script)?,
        }

        // Slots 16–17: funding pointer — (fundIdx 4B LE, fundTxid 32B raw);
        // OP_FALSE for each when None.
        match &self.funding_input {
            Some((txid, vout)) => {
                script.append_push_data(&vout.to_le_bytes())?;
                script.append_push_data(txid)?;
            }
            None => {
                push_op_false(script)?;
                push_op_false(script)?;
            }
        }

        // Slot 18: txType — single byte (always present).
        script.append_push_data(&[self.tx_type.to_u8()])?;

        // Slot 19: sighashPreimage — variable push.
        script.append_push_data(&self.sighash_preimage)?;

        // Slot 20: spendType — single byte (always present).
        script.append_push_data(&[self.spend_type.to_u8()])?;

        Ok(())
    }
}

/// Push an `OP_FALSE` (single-byte 0x00 / empty push) into `script`.
fn push_op_false(script: &mut Script) -> Result<(), TransactionError> {
    script.append_push_data(&[])?;
    Ok(())
}

/// Compute the BIP-143-style preimage for the specified input of `tx` using
/// the input's source-output locking script and satoshi value.
///
/// Returns the raw preimage bytes (NOT yet hashed). Suitable for
/// [`Stas3UnlockWitness::sighash_preimage`].
pub fn compute_input_preimage(
    tx: &Transaction,
    input_index: usize,
    sighash_flag: u32,
) -> Result<Vec<u8>, TransactionError> {
    if input_index >= tx.inputs.len() {
        return Err(TransactionError::SigningError(format!(
            "input index {} out of range (tx has {} inputs)",
            input_index,
            tx.inputs.len()
        )));
    }
    let input = &tx.inputs[input_index];
    let source_output = input.source_tx_output().ok_or_else(|| {
        TransactionError::SigningError(
            "missing source output on input (no previous tx info)".to_string(),
        )
    })?;
    calc_preimage(
        tx,
        input_index,
        source_output.locking_script.to_bytes(),
        sighash_flag,
        source_output.satoshis,
    )
}

// ---------------------------------------------------------------------------
// No-auth STAS 3.0 unlocker (arbitrator-free swap)
// ---------------------------------------------------------------------------

/// STAS 3.0 no-auth unlocking template.
///
/// Used for inputs whose owner field is `HASH160("")` (arbitrator-free swap,
/// spec §9.5 / §10.3).
///
/// # Spec interpretation (FLAG FOR REVIEW)
///
/// Spec §10.3 reads "instructs the engine to accept OP_FALSE in place of
/// both signature and preimage". With the §7 witness now encoding the
/// preimage at slot 19 and the authz push at slot 21+, this template emits
/// `OP_FALSE` in the AUTHORIZATION slot only — i.e. the full unlock is the
/// witness body (with slot 19 already containing OP_FALSE) followed by a
/// single OP_FALSE in place of `<sig> <pubkey>`. This produces TWO
/// OP_FALSE pushes total: one for slot 19 (preimage) and one for slot 21+
/// (authz). Confirm with the spec author whether the §10.3 wording
/// requires emitting BOTH OP_FALSEs explicitly (current behaviour) or just
/// a single combined marker.
///
/// When constructed via [`Self::with_witness`], the produced unlocking
/// script is the full witness body followed by `OP_FALSE`. When
/// constructed via [`Self::new`] (legacy / back-compat), the produced
/// unlocking script is a single `OP_FALSE` byte.
pub struct Stas3NoAuthUnlockingTemplate {
    witness: Option<Stas3UnlockWitness>,
}

impl Stas3NoAuthUnlockingTemplate {
    /// Construct a legacy no-auth template that emits a single OP_FALSE.
    pub fn new() -> Self {
        Self { witness: None }
    }

    /// Construct a no-auth template that emits the full §7 witness with
    /// `OP_FALSE` in the authz slot (slot 21+). The witness's slot 19
    /// (preimage) should also be set to an empty body (use
    /// `sighash_preimage = Vec::new()`) to signal "no preimage" — see the
    /// §10.3 interpretation note on this struct.
    pub fn with_witness(witness: Stas3UnlockWitness) -> Self {
        Self {
            witness: Some(witness),
        }
    }
}

impl Default for Stas3NoAuthUnlockingTemplate {
    fn default() -> Self {
        Self::new()
    }
}

impl UnlockingScriptTemplate for Stas3NoAuthUnlockingTemplate {
    /// Produce the no-auth unlocking script.
    ///
    /// Without a witness: a single `OP_FALSE`. With a witness: full §7
    /// witness slots 1..=20 followed by `OP_FALSE` in the authz slot (see
    /// §10.3 interpretation note on the struct).
    fn sign(&self, _tx: &Transaction, _input_index: u32) -> Result<Script, TransactionError> {
        let mut script = Script::new();
        if let Some(w) = &self.witness {
            w.write_into(&mut script)?;
        }
        // Authz slot 21+: single OP_FALSE in place of `<sig> <pubkey>`.
        script.append_push_data(&[])?;
        Ok(script)
    }

    /// Estimated length of the no-auth unlocking script. Without a witness
    /// this is 1 byte (OP_FALSE). With a witness an upper bound is
    /// approximated from the witness sizes.
    fn estimate_length(&self, _tx: &Transaction, _input_index: u32) -> u32 {
        match &self.witness {
            None => 1,
            Some(w) => 1 + estimate_witness_len(w),
        }
    }
}

// ---------------------------------------------------------------------------
// P2PKH STAS 3.0 unlocker (existing)
// ---------------------------------------------------------------------------

/// STAS 3.0 unlocking script template.
///
/// By default produces `<DER_signature + sighash_byte> <compressed_pubkey>`,
/// identical to P2PKH / STAS. When constructed with a [`Stas3UnlockWitness`]
/// (via [`unlock_with_witness`]) the produced unlocking script is the full
/// §7 witness body (slots 1..=20) followed by the authz push
/// `<sig> <pubkey>`.
pub struct Stas3UnlockingTemplate {
    private_key: PrivateKey,
    sighash_flag: u32,
    /// The spend type for this unlock. Stored on the legacy path; consumed
    /// by the witness when the template is constructed via
    /// [`unlock_with_witness`].
    #[allow(dead_code)]
    spend_type: Stas3SpendType,
    /// Optional pre-built §7 witness (slots 1..=20). When present, the
    /// produced unlock script is `witness ‖ <sig> <pubkey>`.
    witness: Option<Stas3UnlockWitness>,
}

/// Create a STAS 3.0 unlocker.
///
/// # Arguments
/// * `private_key` – Signing key.
/// * `spend_type` – The STAS 3.0 spend type.
/// * `sighash_flag` – Optional sighash flag (defaults to `SIGHASH_ALL_FORKID`).
pub fn unlock(
    private_key: PrivateKey,
    spend_type: Stas3SpendType,
    sighash_flag: Option<u32>,
) -> Stas3UnlockingTemplate {
    Stas3UnlockingTemplate {
        private_key,
        sighash_flag: sighash_flag.unwrap_or(SIGHASH_ALL_FORKID),
        spend_type,
        witness: None,
    }
}

/// Create a STAS 3.0 unlocker that prepends the full §7 witness (slots
/// 1..=20) before the authz `<sig> <pubkey>` push.
///
/// The caller is responsible for constructing a witness whose `tx_type`,
/// `spend_type`, and per-output triplets match the spending tx structure.
pub fn unlock_with_witness(
    private_key: PrivateKey,
    sighash_flag: Option<u32>,
    witness: Stas3UnlockWitness,
) -> Stas3UnlockingTemplate {
    let spend_type = witness.spend_type;
    Stas3UnlockingTemplate {
        private_key,
        sighash_flag: sighash_flag.unwrap_or(SIGHASH_ALL_FORKID),
        spend_type,
        witness: Some(witness),
    }
}

impl UnlockingScriptTemplate for Stas3UnlockingTemplate {
    /// Sign the specified input and produce the unlocking script.
    ///
    /// When constructed via [`unlock_with_witness`], the produced script is
    /// `witness_body ‖ <sig> <pubkey>` per spec §7 + §10.1. Otherwise the
    /// legacy `<sig> <pubkey>` form is produced for back-compat.
    fn sign(&self, tx: &Transaction, input_index: u32) -> Result<Script, TransactionError> {
        let idx = input_index as usize;

        if idx >= tx.inputs.len() {
            return Err(TransactionError::SigningError(format!(
                "input index {} out of range (tx has {} inputs)",
                idx,
                tx.inputs.len()
            )));
        }

        let input = &tx.inputs[idx];
        if input.source_tx_output().is_none() {
            return Err(TransactionError::SigningError(
                "missing source output on input (no previous tx info)".to_string(),
            ));
        }

        let sig_hash = tx.calc_input_signature_hash(idx, self.sighash_flag)?;
        let signature = self.private_key.sign(&sig_hash)?;
        let pub_key_bytes = self.private_key.pub_key().to_compressed();

        let der_sig = signature.to_der();
        let mut sig_buf = Vec::with_capacity(der_sig.len() + 1);
        sig_buf.extend_from_slice(&der_sig);
        sig_buf.push(self.sighash_flag as u8);

        let mut script = Script::new();
        if let Some(w) = &self.witness {
            w.write_into(&mut script)?;
        }
        script.append_push_data(&sig_buf)?;
        script.append_push_data(&pub_key_bytes)?;

        Ok(script)
    }

    /// Estimate the byte length of a STAS 3.0 unlocking script. The legacy
    /// `<sig> <pubkey>` form is 106 bytes; with a witness, the witness
    /// body's bytes are added.
    fn estimate_length(&self, _tx: &Transaction, _input_index: u32) -> u32 {
        let base = 106;
        match &self.witness {
            None => base,
            Some(w) => base + estimate_witness_len(w),
        }
    }
}

// ---------------------------------------------------------------------------
// P2MPKH STAS 3.0 unlocker (new)
// ---------------------------------------------------------------------------

/// STAS 3.0 P2MPKH unlocking script template.
///
/// By default produces (per STAS 3.0 spec v0.1 § 10.2):
///   `OP_0 <sig_1> <sig_2> … <sig_m> <redeem_script>`
///
/// The leading `OP_0` is the `OP_CHECKMULTISIG` dummy stack element. The
/// final push is the canonical STAS 3.0 redeem buffer
/// `[m][0x21 pk1] … [0x21 pkN][n]` produced by
/// [`MultisigScript::to_serialized_bytes`].
///
/// When constructed with a [`Stas3UnlockWitness`] (via
/// [`unlock_mpkh_with_witness`]), the produced script is the §7 witness
/// body followed by the P2MPKH authz push.
pub struct Stas3MpkhUnlockingTemplate {
    /// The m private keys for threshold signing.
    private_keys: Vec<PrivateKey>,
    /// The full multisig script.
    multisig: MultisigScript,
    /// Sighash flag.
    sighash_flag: u32,
    /// The spend type. Stored on the legacy path; consumed by the witness
    /// when one is supplied.
    #[allow(dead_code)]
    spend_type: Stas3SpendType,
    /// Optional pre-built §7 witness (slots 1..=20).
    witness: Option<Stas3UnlockWitness>,
}

/// Create a STAS 3.0 P2MPKH unlocker.
///
/// # Arguments
/// * `private_keys` - The m private keys satisfying the threshold.
/// * `multisig` - The full m-of-n multisig script.
/// * `spend_type` - The STAS 3.0 spend type.
/// * `sighash_flag` - Optional sighash flag. Defaults to `SIGHASH_ALL_FORKID`.
///
/// # Errors
/// Returns an error if the number of private keys doesn't match the threshold.
pub fn unlock_mpkh(
    private_keys: Vec<PrivateKey>,
    multisig: MultisigScript,
    spend_type: Stas3SpendType,
    sighash_flag: Option<u32>,
) -> Result<Stas3MpkhUnlockingTemplate, TransactionError> {
    if private_keys.len() != multisig.threshold() as usize {
        return Err(TransactionError::SigningError(format!(
            "expected {} private keys for threshold, got {}",
            multisig.threshold(),
            private_keys.len()
        )));
    }
    Ok(Stas3MpkhUnlockingTemplate {
        private_keys,
        multisig,
        sighash_flag: sighash_flag.unwrap_or(SIGHASH_ALL_FORKID),
        spend_type,
        witness: None,
    })
}

/// Create a STAS 3.0 P2MPKH unlocker that prepends the full §7 witness.
///
/// Same key-count validation as [`unlock_mpkh`]. The produced unlock
/// script is `witness_body ‖ OP_0 <sig_1>..<sig_m> <redeem_script>`.
pub fn unlock_mpkh_with_witness(
    private_keys: Vec<PrivateKey>,
    multisig: MultisigScript,
    sighash_flag: Option<u32>,
    witness: Stas3UnlockWitness,
) -> Result<Stas3MpkhUnlockingTemplate, TransactionError> {
    if private_keys.len() != multisig.threshold() as usize {
        return Err(TransactionError::SigningError(format!(
            "expected {} private keys for threshold, got {}",
            multisig.threshold(),
            private_keys.len()
        )));
    }
    let spend_type = witness.spend_type;
    Ok(Stas3MpkhUnlockingTemplate {
        private_keys,
        multisig,
        sighash_flag: sighash_flag.unwrap_or(SIGHASH_ALL_FORKID),
        spend_type,
        witness: Some(witness),
    })
}

/// Create a STAS 3.0 unlocker from a [`SigningKey`] (dispatches P2PKH vs P2MPKH).
///
/// Returns a boxed `UnlockingScriptTemplate` suitable for either signing mode.
pub fn unlock_from_signing_key(
    key: &SigningKey,
    spend_type: Stas3SpendType,
    sighash_flag: Option<u32>,
) -> Result<Box<dyn UnlockingScriptTemplate>, TransactionError> {
    match key {
        SigningKey::Single(pk) => Ok(Box::new(unlock(pk.clone(), spend_type, sighash_flag))),
        SigningKey::Multi {
            private_keys,
            multisig,
        } => Ok(Box::new(unlock_mpkh(
            private_keys.clone(),
            multisig.clone(),
            spend_type,
            sighash_flag,
        )?)),
    }
}

/// Create a STAS 3.0 unlocker, dispatching to the no-auth path when the input
/// locking script's owner field equals `HASH160("")` (arbitrator-free swap,
/// spec §9.5 / §10.3). Otherwise behaves identically to
/// [`unlock_from_signing_key`].
pub fn unlock_for_input(
    locking_script: &[u8],
    key: &SigningKey,
    spend_type: Stas3SpendType,
    sighash_flag: Option<u32>,
) -> Result<Box<dyn UnlockingScriptTemplate>, TransactionError> {
    if is_arbitrator_free_owner(locking_script) {
        return Ok(Box::new(Stas3NoAuthUnlockingTemplate::new()));
    }
    unlock_from_signing_key(key, spend_type, sighash_flag)
}

/// Create a STAS 3.0 unlocker that prepends the spec §7 unlock witness
/// (slots 1..=20) before the authz push. Dispatches to:
///   - [`Stas3NoAuthUnlockingTemplate::with_witness`] when the input is
///     arbitrator-free (`HASH160("")` owner); the resulting unlock has the
///     full witness body followed by `OP_FALSE` in place of `<sig> <pubkey>`
///     (spec §10.3).
///   - [`unlock_with_witness`] for `SigningKey::Single`.
///   - [`unlock_mpkh_with_witness`] for `SigningKey::Multi`.
///
/// The caller is responsible for constructing a witness whose `tx_type`,
/// `spend_type`, and per-output triplets match the spending tx structure
/// (see `factory::stas3::derive_witness_for_input`).
pub fn unlock_for_input_with_witness(
    locking_script: &[u8],
    key: &SigningKey,
    sighash_flag: Option<u32>,
    witness: Stas3UnlockWitness,
) -> Result<Box<dyn UnlockingScriptTemplate>, TransactionError> {
    if is_arbitrator_free_owner(locking_script) {
        return Ok(Box::new(Stas3NoAuthUnlockingTemplate::with_witness(
            witness,
        )));
    }
    match key {
        SigningKey::Single(pk) => Ok(Box::new(unlock_with_witness(
            pk.clone(),
            sighash_flag,
            witness,
        ))),
        SigningKey::Multi {
            private_keys,
            multisig,
        } => Ok(Box::new(unlock_mpkh_with_witness(
            private_keys.clone(),
            multisig.clone(),
            sighash_flag,
            witness,
        )?)),
    }
}

impl UnlockingScriptTemplate for Stas3MpkhUnlockingTemplate {
    /// Sign the specified input and produce the P2MPKH unlocking script.
    ///
    /// Produces (spec v0.1 § 10.2):
    ///   `OP_0 <sig_1> … <sig_m> <redeem_script>`
    fn sign(&self, tx: &Transaction, input_index: u32) -> Result<Script, TransactionError> {
        let idx = input_index as usize;

        if idx >= tx.inputs.len() {
            return Err(TransactionError::SigningError(format!(
                "input index {} out of range (tx has {} inputs)",
                idx,
                tx.inputs.len()
            )));
        }

        let input = &tx.inputs[idx];
        if input.source_tx_output().is_none() {
            return Err(TransactionError::SigningError(
                "missing source output on input (no previous tx info)".to_string(),
            ));
        }

        let sig_hash = tx.calc_input_signature_hash(idx, self.sighash_flag)?;

        let mut script = Script::new();

        // §7 witness body (slots 1..=20) when present.
        if let Some(w) = &self.witness {
            w.write_into(&mut script)?;
        }

        // OP_0 dummy stack element required by OP_CHECKMULTISIG.
        script.append_push_data(&[])?;

        // Push each threshold signature.
        for pk in &self.private_keys {
            let signature = pk.sign(&sig_hash)?;
            let der_sig = signature.to_der();
            let mut sig_buf = Vec::with_capacity(der_sig.len() + 1);
            sig_buf.extend_from_slice(&der_sig);
            sig_buf.push(self.sighash_flag as u8);
            script.append_push_data(&sig_buf)?;
        }

        // Push the canonical STAS 3.0 redeem script.
        script.append_push_data(&self.multisig.to_serialized_bytes())?;

        Ok(script)
    }

    /// Estimate the byte length of a STAS 3.0 P2MPKH unlocking script.
    ///
    /// Layout: 1 (OP_0) + m * 73 (push + DER + sighash) + 2 (PUSHDATA1
    /// prefix) + redeem buffer (`2 + 34 * n` bytes). When a witness is
    /// present, its bytes are added.
    fn estimate_length(&self, _tx: &Transaction, _input_index: u32) -> u32 {
        let m = self.multisig.threshold() as u32;
        let n = self.multisig.n() as u32;
        let redeem_len = 2 + n * 34;
        let base = 1 + m * 73 + 2 + redeem_len;
        match &self.witness {
            None => base,
            Some(w) => base + estimate_witness_len(w),
        }
    }
}

/// Conservative byte-length estimate for a §7 witness body (slots 1..=20).
fn estimate_witness_len(w: &Stas3UnlockWitness) -> u32 {
    let mut total: u32 = 0;
    for out in &w.stas_outputs {
        // amount push: header (1) + body (0..=8)
        total += 1 + encode_unlock_amount(out.amount).len() as u32;
        // owner_pkh: 1 + 20
        total += 21;
        // var2: header (1..=3) + body
        total += push_header_len(out.var2.len()) + out.var2.len() as u32;
    }
    // Slots 13–14 (change)
    match &w.change {
        Some(ch) => {
            total += 1 + encode_unlock_amount(ch.amount).len() as u32;
            total += 21;
        }
        None => total += 2, // two OP_FALSE
    }
    // Slot 15 (noteData)
    match &w.note_data {
        Some(n) => total += push_header_len(n.len()) + n.len() as u32,
        None => total += 1,
    }
    // Slots 16–17 (funding)
    match &w.funding_input {
        Some(_) => total += 1 + 4 + 1 + 32, // (push 4B vout) + (push 32B txid)
        None => total += 2,
    }
    // Slot 18 (txType): 1B push (header 1 + body 1)
    total += 2;
    // Slot 19 (preimage): variable push
    total += push_header_len(w.sighash_preimage.len()) + w.sighash_preimage.len() as u32;
    // Slot 20 (spendType): 1B push (header 1 + body 1)
    total += 2;
    total
}

/// Header length for a minimal push of `body_len` bytes (excluding body).
///
/// 0 → 1 (`OP_FALSE`); 1..=75 → 1 (bare push opcode = length); 76..=255 → 2
/// (`OP_PUSHDATA1` + 1B length); 256..=65535 → 3 (`OP_PUSHDATA2` + 2B
/// length); larger → 5 (`OP_PUSHDATA4` + 4B length).
fn push_header_len(body_len: usize) -> u32 {
    match body_len {
        0..=75 => 1,
        76..=255 => 2,
        256..=65_535 => 3,
        _ => 5,
    }
}

// ---------------------------------------------------------------------------
// STAS 3.0 trailing-params wrapper (spec §8.1, §9.5 — atomic-swap & merge)
// ---------------------------------------------------------------------------

/// Wraps any inner [`UnlockingScriptTemplate`] and appends a raw trailing
/// parameter block (counterparty script + piece count + piece array, or
/// piece count + piece array for merge variants) AFTER the standard authz.
///
/// The trailing bytes are appended verbatim — they are NOT pushed as a
/// single push; the spec lays them out as per-parameter pushes that the
/// caller must encode separately. Use
/// [`crate::script::stas3_pieces::encode_atomic_swap_trailing_params`] or
/// [`crate::script::stas3_pieces::encode_merge_trailing_params`] to build
/// the block.
pub struct Stas3TrailingParamsTemplate {
    inner: Box<dyn UnlockingScriptTemplate>,
    trailing_bytes: Vec<u8>,
}

impl Stas3TrailingParamsTemplate {
    /// Create a wrapper that appends `trailing_bytes` verbatim after the
    /// inner template's produced unlocking script. Pass already-pushdata-
    /// encoded bytes when the spec requires per-parameter pushes; pass raw
    /// bytes when the engine expects them concatenated.
    pub fn new(
        inner: Box<dyn UnlockingScriptTemplate>,
        trailing_bytes: Vec<u8>,
    ) -> Self {
        Self {
            inner,
            trailing_bytes,
        }
    }
}

impl UnlockingScriptTemplate for Stas3TrailingParamsTemplate {
    fn sign(&self, tx: &Transaction, input_index: u32) -> Result<Script, TransactionError> {
        let mut inner_script = self.inner.sign(tx, input_index)?;
        // Append the trailing bytes directly; callers control push framing.
        let mut bytes = inner_script.to_bytes().to_vec();
        bytes.extend_from_slice(&self.trailing_bytes);
        inner_script = Script::from_bytes(&bytes);
        Ok(inner_script)
    }

    fn estimate_length(&self, tx: &Transaction, input_index: u32) -> u32 {
        self.inner.estimate_length(tx, input_index) + self.trailing_bytes.len() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_primitives::ec::PrivateKey;
    use bsv_transaction::template::p2mpkh::MultisigScript;
    use crate::types::SigningKey;

    #[test]
    fn stas3_unlock_from_signing_key_single() {
        let key = PrivateKey::new();
        let sk = SigningKey::Single(key);
        let result = unlock_from_signing_key(&sk, Stas3SpendType::Transfer, None);
        assert!(result.is_ok());
    }

    #[test]
    fn stas3_unlock_from_signing_key_multi() {
        let keys: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::new()).collect();
        let pubs = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(2, pubs).unwrap();
        let sk = SigningKey::Multi {
            private_keys: vec![keys[0].clone(), keys[1].clone()],
            multisig: ms,
        };
        let result = unlock_from_signing_key(&sk, Stas3SpendType::Transfer, None);
        assert!(result.is_ok());
    }

    #[test]
    fn stas3_unlock_mpkh_rejects_wrong_key_count() {
        let keys: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::new()).collect();
        let pubs = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(2, pubs).unwrap();
        let result = unlock_mpkh(keys, ms, Stas3SpendType::Transfer, None);
        assert!(result.is_err());
    }

    #[test]
    fn stas3_mpkh_estimate_length_2_of_3() {
        let keys: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::new()).collect();
        let pubs = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(2, pubs).unwrap();
        let unlocker = unlock_mpkh(
            vec![keys[0].clone(), keys[1].clone()],
            ms,
            Stas3SpendType::Transfer,
            None,
        ).unwrap();
        let tx = bsv_transaction::transaction::Transaction::default();
        let est = unlocker.estimate_length(&tx, 0);
        assert!(est > 106);
    }

    // -------------------------------------------------------------------
    // Gap 2: Stas3MpkhUnlockingTemplate::sign() tests
    // -------------------------------------------------------------------

    /// Build a mock transaction with a source output for signing tests.
    fn mock_tx_with_source(satoshis: u64) -> bsv_transaction::transaction::Transaction {
        use bsv_script::Script;
        use bsv_transaction::input::TransactionInput;
        use bsv_transaction::output::TransactionOutput;

        let locking_script = Script::from_asm(
            "OP_DUP OP_HASH160 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa OP_EQUALVERIFY OP_CHECKSIG",
        )
        .unwrap();

        let source_output = TransactionOutput {
            satoshis,
            locking_script: locking_script.clone(),
            change: false,
        };

        let mut input = TransactionInput::new();
        input.source_txid = [0u8; 32];
        input.source_tx_out_index = 0;
        input.set_source_output(Some(source_output));

        let mut tx = bsv_transaction::transaction::Transaction::new();
        tx.add_input(input);
        tx.add_output(TransactionOutput {
            satoshis: satoshis.saturating_sub(1000),
            locking_script,
            change: false,
        });
        tx
    }

    #[test]
    fn stas3_mpkh_sign_2_of_3_script_structure() {
        let keys: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::new()).collect();
        let pubs: Vec<_> = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(2, pubs).unwrap();
        let ms_bytes = ms.to_serialized_bytes();

        let unlocker = unlock_mpkh(
            vec![keys[0].clone(), keys[1].clone()],
            ms,
            Stas3SpendType::Transfer,
            None,
        )
        .unwrap();

        let tx = mock_tx_with_source(10_000);
        let script = unlocker.sign(&tx, 0).unwrap();
        let chunks = script.chunks().unwrap();

        // OP_0 dummy + 2 signatures + 1 redeem-script push = 4 chunks
        assert_eq!(
            chunks.len(),
            4,
            "expected OP_0 + 2 sigs + redeem script push"
        );

        // Chunk 0: OP_0 / empty push.
        let dummy = &chunks[0];
        assert!(
            dummy.data.is_none() || dummy.data.as_ref().is_some_and(|d| d.is_empty()),
            "first chunk must be OP_0 (empty push)"
        );

        // Chunks 1..=2: signatures.
        for i in 1..=2 {
            let sig_data = chunks[i].data.as_ref().expect("signature should be push data");
            assert!(
                sig_data.len() >= 71 && sig_data.len() <= 73,
                "signature {} length {} not in 71..=73",
                i - 1,
                sig_data.len()
            );
            assert_eq!(
                *sig_data.last().unwrap(),
                0x41,
                "signature {} should end with SIGHASH_ALL_FORKID",
                i - 1
            );
        }

        // Chunk 3: redeem script bytes.
        let ms_chunk = chunks[3].data.as_ref().expect("redeem script should be push data");
        assert_eq!(ms_chunk, &ms_bytes, "final chunk should be the redeem script bytes");
    }

    #[test]
    fn stas3_mpkh_sign_missing_source_output_returns_error() {
        let keys: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::new()).collect();
        let pubs: Vec<_> = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(2, pubs).unwrap();
        let unlocker = unlock_mpkh(
            vec![keys[0].clone(), keys[1].clone()],
            ms,
            Stas3SpendType::Transfer,
            None,
        )
        .unwrap();

        let mut tx = bsv_transaction::transaction::Transaction::new();
        let input = bsv_transaction::input::TransactionInput::new();
        tx.add_input(input);
        tx.add_output(bsv_transaction::output::TransactionOutput::new());

        let result = unlocker.sign(&tx, 0);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("missing source output"),
            "error should mention missing source output"
        );
    }

    #[test]
    fn stas3_mpkh_sign_carries_spend_type() {
        // Verify the template stores spend_type by constructing with different types
        let keys: Vec<PrivateKey> = (0..2).map(|_| PrivateKey::new()).collect();
        let pubs: Vec<_> = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(1, pubs).unwrap();

        // Both should succeed — spend_type doesn't affect signing yet,
        // but the template must accept different variants without error.
        let t1 = unlock_mpkh(
            vec![keys[0].clone()],
            ms.clone(),
            Stas3SpendType::Transfer,
            None,
        );
        assert!(t1.is_ok());

        let t2 = unlock_mpkh(
            vec![keys[0].clone()],
            ms.clone(),
            Stas3SpendType::Confiscation,
            None,
        );
        assert!(t2.is_ok());

        // Both produce valid signatures on the same tx
        let tx = mock_tx_with_source(5_000);
        let s1 = t1.unwrap().sign(&tx, 0).unwrap();
        let s2 = t2.unwrap().sign(&tx, 0).unwrap();
        // Scripts should be identical since spend_type isn't encoded yet
        assert_eq!(s1.to_bytes(), s2.to_bytes());
    }

    // -------------------------------------------------------------------
    // Gap 6 (STAS 3.0): estimate_length across multiple m-of-n combinations
    // -------------------------------------------------------------------

    #[test]
    fn stas3_mpkh_estimate_length_1_of_1() {
        let keys: Vec<PrivateKey> = (0..1).map(|_| PrivateKey::new()).collect();
        let pubs = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(1, pubs).unwrap();
        let unlocker = unlock_mpkh(vec![keys[0].clone()], ms, Stas3SpendType::Transfer, None).unwrap();
        let tx = bsv_transaction::transaction::Transaction::default();
        let est = unlocker.estimate_length(&tx, 0);
        // 1 (OP_0) + 1*73 (sig) + 2 (PUSHDATA1) + (2 + 1*34) redeem
        assert_eq!(est, 1 + 73 + 2 + (2 + 34));
    }

    // -------------------------------------------------------------------
    // Fix K: minimal-LE unlock amount encoding (spec §7)
    // -------------------------------------------------------------------

    #[test]
    fn encode_unlock_amount_zero_is_empty() {
        assert_eq!(encode_unlock_amount(0), Vec::<u8>::new());
        assert_eq!(push_unlock_amount(0), vec![0x00]); // OP_FALSE
    }

    #[test]
    fn encode_unlock_amount_one_byte() {
        assert_eq!(encode_unlock_amount(1), vec![0x01]);
        // 0xFF has the high bit set in its single byte → sign-bit sentinel appended.
        assert_eq!(encode_unlock_amount(0xFF), vec![0xFF, 0x00]);
        assert_eq!(push_unlock_amount(1), vec![0x01, 0x01]);
        assert_eq!(push_unlock_amount(0xFF), vec![0x02, 0xFF, 0x00]);
    }

    #[test]
    fn encode_unlock_amount_two_bytes() {
        assert_eq!(encode_unlock_amount(0x100), vec![0x00, 0x01]);
        // 0xFFFF: top byte is 0xFF, high bit set → sentinel appended.
        assert_eq!(encode_unlock_amount(0xFFFF), vec![0xFF, 0xFF, 0x00]);
        assert_eq!(push_unlock_amount(0x100), vec![0x02, 0x00, 0x01]);
    }

    #[test]
    fn encode_unlock_amount_three_bytes() {
        // 0x010000 → [0x00, 0x00, 0x01]
        assert_eq!(encode_unlock_amount(0x10000), vec![0x00, 0x00, 0x01]);
    }

    #[test]
    fn encode_unlock_amount_five_bytes() {
        // 0x100000000 → 5 bytes minimal LE (top byte 0x01, no sentinel needed)
        assert_eq!(
            encode_unlock_amount(0x100000000),
            vec![0x00, 0x00, 0x00, 0x00, 0x01]
        );
    }

    #[test]
    fn encode_unlock_amount_seven_bytes() {
        // 0xFFFFFFFFFFFFFF → 7 bytes of 0xFF + sign-bit sentinel.
        assert_eq!(
            encode_unlock_amount(0x00FF_FFFF_FFFF_FFFF),
            vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]
        );
    }

    #[test]
    fn encode_unlock_amount_eight_bytes_max() {
        // u64::MAX has the high bit set in the top byte → sentinel appended,
        // for 9 body bytes total.
        assert_eq!(
            encode_unlock_amount(u64::MAX),
            vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]
        );
        // The push form is 1-byte length prefix + 9 bytes body = 10 bytes.
        assert_eq!(push_unlock_amount(u64::MAX).len(), 10);
        assert_eq!(push_unlock_amount(u64::MAX)[0], 0x09);
    }

    #[test]
    fn encode_unlock_amount_appends_sign_bit_sentinel() {
        // 48398 = 0xBD0E. Minimal LE is [0x0E, 0xBD]; the high bit of 0xBD
        // is set, so the engine would otherwise read this back as a
        // negative script number (-15630). Append a 0x00 sentinel.
        assert_eq!(
            encode_unlock_amount(48398),
            vec![0x0E, 0xBD, 0x00],
            "values whose top byte has bit 7 set must carry a 0x00 sign sentinel"
        );
        // Push form is `0x03 0x0E 0xBD 0x00`.
        assert_eq!(
            push_unlock_amount(48398),
            vec![0x03, 0x0E, 0xBD, 0x00]
        );
    }

    #[test]
    fn encode_unlock_amount_snapshot_table() {
        // Comprehensive snapshot table covering the spec §7 examples.
        // Entries marked with the sign-bit sentinel (0x00 trailer) carry a
        // top byte ≥ 0x80 — see `encode_unlock_amount`'s sign-bit safety note.
        let cases: &[(u64, &[u8])] = &[
            (0, &[]),
            (1, &[0x01]),
            (0xFF, &[0xFF, 0x00]), // sign-bit sentinel
            (0x100, &[0x00, 0x01]),
            (0xFFFF, &[0xFF, 0xFF, 0x00]), // sign-bit sentinel
            (0x100000000, &[0x00, 0x00, 0x00, 0x00, 0x01]),
            (
                0x00FF_FFFF_FFFF_FFFF,
                &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00],
            ), // sign-bit sentinel
            (
                u64::MAX,
                &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00],
            ), // sign-bit sentinel
        ];
        for (value, expected) in cases {
            let got = encode_unlock_amount(*value);
            assert_eq!(
                got, *expected,
                "amount {} ({:#x}) → got {} expected {}",
                value,
                value,
                hex::encode(&got),
                hex::encode(expected)
            );
        }
    }

    // -------------------------------------------------------------------
    // Fix E: arbitrator-free swap unlock path
    // -------------------------------------------------------------------

    #[test]
    fn stas3_no_auth_template_emits_op_false() {
        use bsv_script::Script;
        use bsv_transaction::input::TransactionInput;
        use bsv_transaction::output::TransactionOutput;

        let mut tx = bsv_transaction::transaction::Transaction::new();
        let mut input = TransactionInput::new();
        input.set_source_output(Some(TransactionOutput {
            satoshis: 5000,
            locking_script: Script::new(),
            change: false,
        }));
        tx.add_input(input);

        let unlocker = Stas3NoAuthUnlockingTemplate::new();
        let script = unlocker.sign(&tx, 0).unwrap();
        // Legacy back-compat path (no witness): single OP_FALSE byte.
        // The full §7 witness path is exercised by the witness-aware tests
        // below — see `no_auth_with_witness_emits_two_op_false`.
        assert_eq!(script.to_bytes(), &[0x00]);
        assert_eq!(unlocker.estimate_length(&tx, 0), 1);
    }

    #[test]
    fn unlock_for_input_routes_arbitrator_free_to_no_auth() {
        use crate::script::stas3_builder::build_stas3_locking_script;
        use crate::script::stas3_swap::EMPTY_HASH160;

        // Build a STAS3 locking script whose owner is the EMPTY_HASH160 sentinel.
        let redemption = [0x22; 20];
        let locking = build_stas3_locking_script(
            &EMPTY_HASH160, &redemption, None, false, true, &[], &[],
        )
        .unwrap();

        // Any signing key — should be ignored on the no-auth path.
        let key = PrivateKey::new();
        let sk = SigningKey::Single(key);
        let unlocker = unlock_for_input(
            locking.to_bytes(), &sk, Stas3SpendType::Transfer, None,
        )
        .unwrap();

        // Build a minimal tx for sign(); for the no-auth template, the tx
        // is unused but a value is required by the trait signature.
        let tx = mock_tx_with_source(5000);
        let script = unlocker.sign(&tx, 0).unwrap();
        assert_eq!(
            script.to_bytes(), &[0x00],
            "arbitrator-free input should produce a single OP_FALSE push"
        );
    }

    #[test]
    fn unlock_for_input_routes_regular_owner_to_signing() {
        use crate::script::stas3_builder::build_stas3_locking_script;

        let owner = [0x11; 20]; // not the sentinel
        let redemption = [0x22; 20];
        let locking = build_stas3_locking_script(
            &owner, &redemption, None, false, true, &[], &[],
        )
        .unwrap();

        let key = PrivateKey::new();
        let sk = SigningKey::Single(key);
        let unlocker = unlock_for_input(
            locking.to_bytes(), &sk, Stas3SpendType::Transfer, None,
        )
        .unwrap();

        let tx = mock_tx_with_source(5000);
        let script = unlocker.sign(&tx, 0).unwrap();
        // Regular path should produce sig+pubkey (>= 70 bytes, not a single OP_FALSE).
        assert!(
            script.to_bytes().len() > 1,
            "regular owner should produce sig+pubkey, got {} bytes",
            script.to_bytes().len()
        );
    }

    #[test]
    fn stas3_mpkh_estimate_length_3_of_5() {
        let keys: Vec<PrivateKey> = (0..5).map(|_| PrivateKey::new()).collect();
        let pubs = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(3, pubs).unwrap();
        let unlocker = unlock_mpkh(
            vec![keys[0].clone(), keys[1].clone(), keys[2].clone()],
            ms,
            Stas3SpendType::Transfer,
            None,
        )
        .unwrap();
        let tx = bsv_transaction::transaction::Transaction::default();
        let est = unlocker.estimate_length(&tx, 0);
        // 1 (OP_0) + 3*73 (sigs) + 2 (PUSHDATA1) + (2 + 5*34) redeem
        assert_eq!(est, 1 + 3 * 73 + 2 + (2 + 5 * 34));
    }

    // -------------------------------------------------------------------
    // §7 Stas3UnlockWitness snapshot & shape tests (Priority 1)
    // -------------------------------------------------------------------

    fn fixed_preimage() -> Vec<u8> {
        // Deterministic 32-byte fixture so snapshot tests pin exact bytes.
        (0..32u8).map(|i| i.wrapping_mul(7)).collect()
    }

    /// Common-case witness: 1 STAS output, no change, no note, txType=0,
    /// spendType=Transfer, no funding pointer.
    fn build_witness_1out_no_change() -> Stas3UnlockWitness {
        Stas3UnlockWitness {
            stas_outputs: vec![Stas3WitnessOutput {
                amount: 5_000,
                owner_pkh: [0x33; 20],
                var2: vec![],
            }],
            change: None,
            note_data: None,
            funding_input: None,
            tx_type: Stas3TxType::Regular,
            sighash_preimage: fixed_preimage(),
            spend_type: Stas3SpendType::Transfer,
        }
    }

    #[test]
    fn witness_1out_no_change_no_note_layout() {
        let mut script = Script::new();
        let w = build_witness_1out_no_change();
        w.write_into(&mut script).unwrap();
        let bytes = script.to_bytes();

        // Spec §7 ordering for this configuration. Decode the chunks and
        // assert their layout slot-by-slot.
        let chunks = script.chunks().unwrap();
        assert!(chunks.len() >= 9, "expected at least 9 pushes, got {}", chunks.len());

        // Slot 1: amount → minimal LE [0x88, 0x13] for 5000.
        assert_eq!(chunks[0].data.as_deref(), Some(&[0x88u8, 0x13][..]));
        // Slot 2: owner_pkh → 20 bytes 0x33.
        assert_eq!(chunks[1].data.as_deref(), Some(&[0x33u8; 20][..]));
        // Slot 3: var2 → empty push.
        assert!(
            chunks[2].data.is_none() || chunks[2].data.as_ref().is_some_and(|d| d.is_empty()),
            "var2 should be empty"
        );
        // Slot 13: change_amount → OP_FALSE
        assert!(
            chunks[3].data.is_none() || chunks[3].data.as_ref().is_some_and(|d| d.is_empty())
        );
        // Slot 14: change_addr → OP_FALSE
        assert!(
            chunks[4].data.is_none() || chunks[4].data.as_ref().is_some_and(|d| d.is_empty())
        );
        // Slot 15: noteData → OP_FALSE
        assert!(
            chunks[5].data.is_none() || chunks[5].data.as_ref().is_some_and(|d| d.is_empty())
        );
        // Slot 16: fundIdx → OP_FALSE
        assert!(
            chunks[6].data.is_none() || chunks[6].data.as_ref().is_some_and(|d| d.is_empty())
        );
        // Slot 17: fundTxid → OP_FALSE
        assert!(
            chunks[7].data.is_none() || chunks[7].data.as_ref().is_some_and(|d| d.is_empty())
        );
        // Slot 18: txType
        assert_eq!(chunks[8].data.as_deref(), Some(&[0x00u8][..]));
        // Slot 19: preimage
        assert_eq!(chunks[9].data.as_deref(), Some(fixed_preimage().as_slice()));
        // Slot 20: spendType
        assert_eq!(chunks[10].data.as_deref(), Some(&[0x01u8][..]));

        // Snapshot the exact hex prefix (slots 1..=3 + change OP_FALSEs +
        // noteData OP_FALSE + funding OP_FALSEs + txType byte). 32 bytes
        // total (3 + 21 + 1 + 2 + 1 + 2 + 2). The preimage portion varies
        // less interestingly.
        let prefix_len = 3 + 21 + 1 + 2 + 1 + 2 + 2;
        let prefix_hex = hex::encode(&bytes[..prefix_len]);
        assert_eq!(
            prefix_hex,
            // 02 88 13               — amount push (5000 LE)
            // 14 33...33             — owner_pkh push (20×0x33)
            // 00                     — var2 empty
            // 00 00                  — change_amount + change_addr OP_FALSEs
            // 00                     — noteData OP_FALSE
            // 00 00                  — fundIdx + fundTxid OP_FALSEs
            // 01 00                  — txType byte 0x00
            "0288131433333333333333333333333333333333333333330000000000000100",
        );
    }

    #[test]
    fn witness_1out_with_change_layout() {
        let mut w = build_witness_1out_no_change();
        w.change = Some(Stas3WitnessChange {
            amount: 1234,
            addr_pkh: [0x44; 20],
        });
        let mut script = Script::new();
        w.write_into(&mut script).unwrap();
        let chunks = script.chunks().unwrap();
        // Slot 13 (change_amount): minimal LE for 1234 = 0x04 0xD2
        assert_eq!(chunks[3].data.as_deref(), Some(&[0xD2u8, 0x04][..]));
        // Slot 14 (change_addr): 20× 0x44
        assert_eq!(chunks[4].data.as_deref(), Some(&[0x44u8; 20][..]));
    }

    #[test]
    fn witness_2_outputs_layout_skips_outputs_3_and_4() {
        let mut w = build_witness_1out_no_change();
        // Add a second STAS output triplet.
        w.stas_outputs.push(Stas3WitnessOutput {
            amount: 0, // empty body push
            owner_pkh: [0xAA; 20],
            var2: vec![0x01],
        });
        let mut script = Script::new();
        w.write_into(&mut script).unwrap();
        let chunks = script.chunks().unwrap();

        // Output 1 occupies chunks 0..3, Output 2 occupies chunks 3..6.
        // Chunk 3: amount empty (zero). Chunk 4: 20×0xAA. Chunk 5: var2 [0x01].
        assert!(
            chunks[3].data.is_none() || chunks[3].data.as_ref().is_some_and(|d| d.is_empty())
        );
        assert_eq!(chunks[4].data.as_deref(), Some(&[0xAAu8; 20][..]));
        assert_eq!(chunks[5].data.as_deref(), Some(&[0x01u8][..]));
        // Slot 13 (change_amount) starts at chunk 6 — proves 3rd/4th
        // output triplets are skipped entirely (no extra pushes).
        assert!(
            chunks[6].data.is_none() || chunks[6].data.as_ref().is_some_and(|d| d.is_empty()),
            "slot 13 (change_amount) must be the 7th chunk when 2 outputs are present"
        );
    }

    #[test]
    fn witness_confiscation_tx_type_5() {
        let w = Stas3UnlockWitness {
            stas_outputs: vec![Stas3WitnessOutput {
                amount: 1,
                owner_pkh: [0x55; 20],
                var2: vec![],
            }],
            change: None,
            note_data: None,
            funding_input: Some(([0xCC; 32], 7)),
            tx_type: Stas3TxType::Merge5,
            sighash_preimage: fixed_preimage(),
            spend_type: Stas3SpendType::Confiscation,
        };
        let mut script = Script::new();
        w.write_into(&mut script).unwrap();
        let chunks = script.chunks().unwrap();
        // Slot 16 (fundIdx): 4-byte LE of 7 = [0x07, 0x00, 0x00, 0x00]
        assert_eq!(
            chunks[6].data.as_deref(),
            Some(&[0x07u8, 0x00, 0x00, 0x00][..]),
            "fundIdx must be 4B LE of vout"
        );
        // Slot 17 (fundTxid): 32 bytes 0xCC
        assert_eq!(chunks[7].data.as_deref(), Some(&[0xCCu8; 32][..]));
        // Slot 18 (txType): 0x05 (Merge5)
        assert_eq!(chunks[8].data.as_deref(), Some(&[0x05u8][..]));
        // Slot 20 (spendType): 0x03 (Confiscation)
        assert_eq!(chunks[10].data.as_deref(), Some(&[0x03u8][..]));
    }

    #[test]
    fn witness_rejects_too_many_stas_outputs() {
        let w = Stas3UnlockWitness {
            stas_outputs: vec![
                Stas3WitnessOutput { amount: 1, owner_pkh: [0; 20], var2: vec![] },
                Stas3WitnessOutput { amount: 1, owner_pkh: [0; 20], var2: vec![] },
                Stas3WitnessOutput { amount: 1, owner_pkh: [0; 20], var2: vec![] },
                Stas3WitnessOutput { amount: 1, owner_pkh: [0; 20], var2: vec![] },
                Stas3WitnessOutput { amount: 1, owner_pkh: [0; 20], var2: vec![] },
            ],
            change: None,
            note_data: None,
            funding_input: None,
            tx_type: Stas3TxType::Regular,
            sighash_preimage: vec![],
            spend_type: Stas3SpendType::Transfer,
        };
        let mut script = Script::new();
        assert!(w.write_into(&mut script).is_err());
    }

    #[test]
    fn witness_rejects_oversized_note_data() {
        let mut w = build_witness_1out_no_change();
        w.note_data = Some(vec![0u8; Stas3UnlockWitness::MAX_NOTE_DATA_LEN + 1]);
        let mut script = Script::new();
        assert!(w.write_into(&mut script).is_err());
    }

    #[test]
    fn witness_with_note_data_emits_push() {
        let mut w = build_witness_1out_no_change();
        w.note_data = Some(b"hello".to_vec());
        let mut script = Script::new();
        w.write_into(&mut script).unwrap();
        let chunks = script.chunks().unwrap();
        // Slot 15 (noteData) is at chunk 5 (3 output chunks + 2 change OP_FALSEs).
        assert_eq!(chunks[5].data.as_deref(), Some(&b"hello"[..]));
    }

    // -------------------------------------------------------------------
    // No-auth template § 10.3 interpretation: with-witness path emits
    // OP_FALSE in slot 19 (preimage) AND slot 21+ (authz) — TWO total.
    // -------------------------------------------------------------------

    #[test]
    fn no_auth_with_witness_emits_two_op_false() {
        let mut w = build_witness_1out_no_change();
        w.sighash_preimage = Vec::new(); // preimage encoded as OP_FALSE
        let unlocker = Stas3NoAuthUnlockingTemplate::with_witness(w);
        let tx = bsv_transaction::transaction::Transaction::default();
        let script = unlocker.sign(&tx, 0).unwrap();
        let chunks = script.chunks().unwrap();
        // The last two pushes should be empty pushes (OP_FALSE) — slot 19
        // (preimage) and slot 21+ (authz).
        let last = chunks.last().unwrap();
        let second_last = &chunks[chunks.len() - 3]; // slot 19 is 2 chunks before authz (after slot 20)
        assert!(
            last.data.is_none() || last.data.as_ref().is_some_and(|d| d.is_empty()),
            "authz slot must be OP_FALSE"
        );
        assert!(
            second_last.data.is_none()
                || second_last.data.as_ref().is_some_and(|d| d.is_empty()),
            "preimage slot 19 must be OP_FALSE"
        );
    }

    // -------------------------------------------------------------------
    // Priority 4: assert engine constants are baked into the template.
    // -------------------------------------------------------------------

    #[test]
    fn engine_constants_baked_into_template() {
        use crate::script::stas3_builder::build_stas3_locking_script;
        let script = build_stas3_locking_script(
            &[0u8; 20],
            &[0u8; 20],
            None,
            false,
            true,
            &[],
            &[],
        )
        .unwrap();
        let script_hex = hex::encode(script.to_bytes());

        // PUBKEY_A: hard-coded sigtail pubkey (spec §11 / template Section D).
        // Pinned in `stas_builder.rs` and `stas3_builder.rs`.
        let pubkey_a = "038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218";
        assert!(
            script_hex.contains(pubkey_a),
            "STAS3 template must bake PUBKEY_A {}",
            pubkey_a
        );
        // PUBKEY_B: secondary engine pubkey.
        let pubkey_b = "023635954789a02e39fb7e54440b6f528d53efd65635ddad7f3c4085f97fdbdc48";
        assert!(
            script_hex.contains(pubkey_b),
            "STAS3 template must bake PUBKEY_B {}",
            pubkey_b
        );
        // SIG_PREFIX_DER: the hard-coded ECDSA-trick DER prefix ending b16f
        // (canonical 79be… secp256k1 generator x-coord trick — see spec §11).
        let sig_prefix = "3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        assert!(
            script_hex.contains(sig_prefix),
            "STAS3 template must bake SIG_PREFIX_DER ending b16f81798"
        );
        // HALF_N: half-curve-order constant for low-S enforcement —
        // appears in the template as the 32-byte sequence
        // `414136d08c5ed2bf3ba048afe6dcaebafe`-prefixed (template uses the
        // little-endian-byte-reversed half-N constant). Pin its presence.
        let half_n_marker = "414136d08c5ed2bf3ba048afe6dcaebafe";
        assert!(
            script_hex.contains(half_n_marker),
            "STAS3 template must bake HALF_N marker {}",
            half_n_marker
        );
    }
}
