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
use bsv_transaction::sighash::SIGHASH_ALL_FORKID;
use bsv_transaction::template::p2mpkh::MultisigScript;
use bsv_transaction::template::UnlockingScriptTemplate;
use bsv_transaction::transaction::Transaction;
use bsv_transaction::TransactionError;

use crate::script::stas3_swap::is_arbitrator_free_owner;
use crate::types::{Stas3SpendType, SigningKey};

// ---------------------------------------------------------------------------
// Fix K: STAS 3.0 unlocking-script amount encoding (spec §7).
//
// `out{1..4}_amount` and `change_amount` are "Unsigned LE (up to 8 B) or
// empty". This means minimal little-endian: zero is an empty push, otherwise
// emit only as many low-order bytes as needed (no sign-padding, since these
// are unsigned). Maximum width is 8 bytes (u64).
// ---------------------------------------------------------------------------

/// Encode an unsigned amount as the body of a minimal little-endian push,
/// per STAS 3.0 spec §7. Zero produces an empty body (intended to be emitted
/// as `OP_FALSE`/`OP_0`); non-zero amounts produce 1..=8 bytes — only as
/// many as the most-significant nonzero byte requires.
///
/// This is the body only — callers wrap it with the appropriate push opcode
/// (`OP_FALSE` for empty, otherwise a bare push).
pub fn encode_unlock_amount(value: u64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let raw = value.to_le_bytes();
    // Strip trailing zero bytes — minimal LE encoding for an unsigned value.
    let mut len = 8;
    while len > 1 && raw[len - 1] == 0 {
        len -= 1;
    }
    raw[..len].to_vec()
}

/// Encode an amount as a complete minimal push (header + body) for inclusion
/// in a STAS 3.0 unlocking script per spec §7. Zero → `[0x00]` (`OP_FALSE`);
/// otherwise a bare push of 1..=8 minimal LE bytes.
pub fn push_unlock_amount(value: u64) -> Vec<u8> {
    let body = encode_unlock_amount(value);
    if body.is_empty() {
        vec![0x00] // OP_FALSE / OP_0 = empty push
    } else {
        let mut out = Vec::with_capacity(body.len() + 1);
        out.push(body.len() as u8); // bare push, len <= 8 always fits
        out.extend_from_slice(&body);
        out
    }
}

// ---------------------------------------------------------------------------
// No-auth STAS 3.0 unlocker (arbitrator-free swap)
// ---------------------------------------------------------------------------

/// STAS 3.0 no-auth unlocking template.
///
/// Used for inputs whose owner field is `HASH160("")` (arbitrator-free swap,
/// spec §9.5 / §10.3). Produces a single `OP_FALSE` push, signalling to the
/// engine that no signature or preimage is being supplied for this leg.
pub struct Stas3NoAuthUnlockingTemplate;

impl UnlockingScriptTemplate for Stas3NoAuthUnlockingTemplate {
    /// Produce the no-auth unlocking script: a single `OP_FALSE`.
    fn sign(&self, _tx: &Transaction, _input_index: u32) -> Result<Script, TransactionError> {
        let mut script = Script::new();
        script.append_push_data(&[])?; // OP_FALSE / OP_0
        Ok(script)
    }

    /// Estimated length of the no-auth unlocking script: 1 byte (OP_FALSE).
    fn estimate_length(&self, _tx: &Transaction, _input_index: u32) -> u32 {
        1
    }
}

// ---------------------------------------------------------------------------
// P2PKH STAS 3.0 unlocker (existing)
// ---------------------------------------------------------------------------

/// STAS 3.0 unlocking script template.
///
/// Produces `<DER_signature + sighash_byte> <compressed_pubkey>`, identical
/// to P2PKH / STAS.  The `spend_type` is stored for future preimage encoding.
pub struct Stas3UnlockingTemplate {
    private_key: PrivateKey,
    sighash_flag: u32,
    /// The spend type for this unlock (stored, not yet encoded in script).
    #[allow(dead_code)]
    spend_type: Stas3SpendType,
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
    }
}

impl UnlockingScriptTemplate for Stas3UnlockingTemplate {
    /// Sign the specified input and produce the unlocking script.
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
        script.append_push_data(&sig_buf)?;
        script.append_push_data(&pub_key_bytes)?;

        Ok(script)
    }

    /// Estimate the byte length of a STAS 3.0 unlocking script (same as P2PKH).
    fn estimate_length(&self, _tx: &Transaction, _input_index: u32) -> u32 {
        106
    }
}

// ---------------------------------------------------------------------------
// P2MPKH STAS 3.0 unlocker (new)
// ---------------------------------------------------------------------------

/// STAS 3.0 P2MPKH unlocking script template.
///
/// Produces (per STAS 3.0 spec v0.1 § 10.2):
///   `OP_0 <sig_1> <sig_2> … <sig_m> <redeem_script>`
///
/// The leading `OP_0` is the `OP_CHECKMULTISIG` dummy stack element. The
/// final push is the canonical STAS 3.0 redeem buffer
/// `[m][0x21 pk1] … [0x21 pkN][n]` produced by
/// [`MultisigScript::to_serialized_bytes`].
pub struct Stas3MpkhUnlockingTemplate {
    /// The m private keys for threshold signing.
    private_keys: Vec<PrivateKey>,
    /// The full multisig script.
    multisig: MultisigScript,
    /// Sighash flag.
    sighash_flag: u32,
    /// The spend type (stored for future preimage encoding).
    #[allow(dead_code)]
    spend_type: Stas3SpendType,
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
        return Ok(Box::new(Stas3NoAuthUnlockingTemplate));
    }
    unlock_from_signing_key(key, spend_type, sighash_flag)
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
    /// prefix) + redeem buffer (`2 + 34 * n` bytes).
    fn estimate_length(&self, _tx: &Transaction, _input_index: u32) -> u32 {
        let m = self.multisig.threshold() as u32;
        let n = self.multisig.n() as u32;
        let redeem_len = 2 + n * 34;
        1 + m * 73 + 2 + redeem_len
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
        assert_eq!(encode_unlock_amount(0xFF), vec![0xFF]);
        assert_eq!(push_unlock_amount(1), vec![0x01, 0x01]);
        assert_eq!(push_unlock_amount(0xFF), vec![0x01, 0xFF]);
    }

    #[test]
    fn encode_unlock_amount_two_bytes() {
        assert_eq!(encode_unlock_amount(0x100), vec![0x00, 0x01]);
        assert_eq!(encode_unlock_amount(0xFFFF), vec![0xFF, 0xFF]);
        assert_eq!(push_unlock_amount(0x100), vec![0x02, 0x00, 0x01]);
    }

    #[test]
    fn encode_unlock_amount_three_bytes() {
        // 0x010000 → [0x00, 0x00, 0x01]
        assert_eq!(encode_unlock_amount(0x10000), vec![0x00, 0x00, 0x01]);
    }

    #[test]
    fn encode_unlock_amount_five_bytes() {
        // 0x100000000 → 5 bytes minimal LE
        assert_eq!(
            encode_unlock_amount(0x100000000),
            vec![0x00, 0x00, 0x00, 0x00, 0x01]
        );
    }

    #[test]
    fn encode_unlock_amount_seven_bytes() {
        // 0xFFFFFFFFFFFFFF → 7 bytes
        assert_eq!(
            encode_unlock_amount(0x00FF_FFFF_FFFF_FFFF),
            vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }

    #[test]
    fn encode_unlock_amount_eight_bytes_max() {
        assert_eq!(
            encode_unlock_amount(u64::MAX),
            vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        // The push form is 1-byte length prefix + 8 bytes body = 9 bytes.
        assert_eq!(push_unlock_amount(u64::MAX).len(), 9);
        assert_eq!(push_unlock_amount(u64::MAX)[0], 0x08);
    }

    #[test]
    fn encode_unlock_amount_snapshot_table() {
        // Comprehensive snapshot table covering the spec §7 examples.
        let cases: &[(u64, &[u8])] = &[
            (0, &[]),
            (1, &[0x01]),
            (0xFF, &[0xFF]),
            (0x100, &[0x00, 0x01]),
            (0xFFFF, &[0xFF, 0xFF]),
            (0x100000000, &[0x00, 0x00, 0x00, 0x00, 0x01]),
            (0x00FF_FFFF_FFFF_FFFF, &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
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

        let unlocker = Stas3NoAuthUnlockingTemplate;
        let script = unlocker.sign(&tx, 0).unwrap();
        // OP_FALSE is encoded as a single 0x00 byte (an empty push).
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
}
