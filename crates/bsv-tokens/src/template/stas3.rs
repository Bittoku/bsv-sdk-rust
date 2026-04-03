//! STAS 3.0 unlocking script templates (P2PKH and P2MPKH).
//!
//! Structurally identical to the STAS unlocking scripts but stores the
//! [`STAS 3.0 spend type for future use when preimage-based validation is added.

use bsv_primitives::ec::PrivateKey;
use bsv_script::Script;
use bsv_transaction::sighash::SIGHASH_ALL_FORKID;
use bsv_transaction::template::p2mpkh::MultisigScript;
use bsv_transaction::template::UnlockingScriptTemplate;
use bsv_transaction::transaction::Transaction;
use bsv_transaction::TransactionError;

use crate::types::{Stas3SpendType, SigningKey};

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
/// Produces: `<sig1> <sig2> … <sigM> <serialized_multisig_script>`
///
/// Identical to `StasMpkhUnlockingTemplate` but carries the `Stas3SpendType`.
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

impl UnlockingScriptTemplate for Stas3MpkhUnlockingTemplate {
    /// Sign the specified input and produce the P2MPKH unlocking script.
    ///
    /// Produces: `<sig1> <sig2> … <sigM> <serialized_multisig_script>`
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

        // Push each threshold signature.
        for pk in &self.private_keys {
            let signature = pk.sign(&sig_hash)?;
            let der_sig = signature.to_der();
            let mut sig_buf = Vec::with_capacity(der_sig.len() + 1);
            sig_buf.extend_from_slice(&der_sig);
            sig_buf.push(self.sighash_flag as u8);
            script.append_push_data(&sig_buf)?;
        }

        // Push the serialized multisig script.
        script.append_push_data(&self.multisig.to_bytes())?;

        Ok(script)
    }

    /// Estimate the byte length of a STAS 3.0 P2MPKH unlocking script.
    fn estimate_length(&self, _tx: &Transaction, _input_index: u32) -> u32 {
        let m = self.multisig.threshold() as u32;
        let n = self.multisig.n() as u32;
        let sig_bytes = m * 73;
        let script_bytes = 3 + n * 34 + 3;
        sig_bytes + script_bytes
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
        let ms_bytes = ms.to_bytes();

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

        // 2 signatures + 1 multisig script = 3 chunks
        assert_eq!(chunks.len(), 3, "expected 2 sigs + 1 multisig script push");

        // Verify signature chunks
        for i in 0..2 {
            let sig_data = chunks[i].data.as_ref().expect("signature should be push data");
            assert!(
                sig_data.len() >= 71 && sig_data.len() <= 73,
                "signature {} length {} not in 71..=73",
                i,
                sig_data.len()
            );
            assert_eq!(
                *sig_data.last().unwrap(),
                0x41,
                "signature {} should end with SIGHASH_ALL_FORKID",
                i
            );
        }

        // Final chunk is multisig script
        let ms_chunk = chunks[2].data.as_ref().expect("multisig script should be push data");
        assert_eq!(ms_chunk, &ms_bytes, "final chunk should be the multisig script bytes");
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
        assert_eq!(est, 1 * 73 + 3 + 1 * 34 + 3);
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
        assert_eq!(est, 3 * 73 + 3 + 5 * 34 + 3);
    }
}
