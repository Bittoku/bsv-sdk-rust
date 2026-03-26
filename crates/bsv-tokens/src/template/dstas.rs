//! DSTAS unlocking script templates (P2PKH and P2MPKH).
//!
//! Structurally identical to the STAS unlocking scripts but stores the
//! [`DstasSpendType`] for future use when preimage-based validation is added.

use bsv_primitives::ec::PrivateKey;
use bsv_script::Script;
use bsv_transaction::sighash::SIGHASH_ALL_FORKID;
use bsv_transaction::template::p2mpkh::MultisigScript;
use bsv_transaction::template::UnlockingScriptTemplate;
use bsv_transaction::transaction::Transaction;
use bsv_transaction::TransactionError;

use crate::types::{DstasSpendType, SigningKey};

// ---------------------------------------------------------------------------
// P2PKH DSTAS unlocker (existing)
// ---------------------------------------------------------------------------

/// DSTAS unlocking script template.
///
/// Produces `<DER_signature + sighash_byte> <compressed_pubkey>`, identical
/// to P2PKH / STAS.  The `spend_type` is stored for future preimage encoding.
pub struct DstasUnlockingTemplate {
    private_key: PrivateKey,
    sighash_flag: u32,
    /// The spend type for this unlock (stored, not yet encoded in script).
    #[allow(dead_code)]
    spend_type: DstasSpendType,
}

/// Create a DSTAS unlocker.
///
/// # Arguments
/// * `private_key` – Signing key.
/// * `spend_type` – The DSTAS spend type.
/// * `sighash_flag` – Optional sighash flag (defaults to `SIGHASH_ALL_FORKID`).
pub fn unlock(
    private_key: PrivateKey,
    spend_type: DstasSpendType,
    sighash_flag: Option<u32>,
) -> DstasUnlockingTemplate {
    DstasUnlockingTemplate {
        private_key,
        sighash_flag: sighash_flag.unwrap_or(SIGHASH_ALL_FORKID),
        spend_type,
    }
}

impl UnlockingScriptTemplate for DstasUnlockingTemplate {
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

    /// Estimate the byte length of a DSTAS unlocking script (same as P2PKH).
    fn estimate_length(&self, _tx: &Transaction, _input_index: u32) -> u32 {
        106
    }
}

// ---------------------------------------------------------------------------
// P2MPKH DSTAS unlocker (new)
// ---------------------------------------------------------------------------

/// DSTAS P2MPKH unlocking script template.
///
/// Produces: `<sig1> <sig2> … <sigM> <serialized_multisig_script>`
///
/// Identical to `StasMpkhUnlockingTemplate` but carries the `DstasSpendType`.
pub struct DstasMpkhUnlockingTemplate {
    /// The m private keys for threshold signing.
    private_keys: Vec<PrivateKey>,
    /// The full multisig script.
    multisig: MultisigScript,
    /// Sighash flag.
    sighash_flag: u32,
    /// The spend type (stored for future preimage encoding).
    #[allow(dead_code)]
    spend_type: DstasSpendType,
}

/// Create a DSTAS P2MPKH unlocker.
///
/// # Arguments
/// * `private_keys` - The m private keys satisfying the threshold.
/// * `multisig` - The full m-of-n multisig script.
/// * `spend_type` - The DSTAS spend type.
/// * `sighash_flag` - Optional sighash flag. Defaults to `SIGHASH_ALL_FORKID`.
///
/// # Errors
/// Returns an error if the number of private keys doesn't match the threshold.
pub fn unlock_mpkh(
    private_keys: Vec<PrivateKey>,
    multisig: MultisigScript,
    spend_type: DstasSpendType,
    sighash_flag: Option<u32>,
) -> Result<DstasMpkhUnlockingTemplate, TransactionError> {
    if private_keys.len() != multisig.threshold() as usize {
        return Err(TransactionError::SigningError(format!(
            "expected {} private keys for threshold, got {}",
            multisig.threshold(),
            private_keys.len()
        )));
    }
    Ok(DstasMpkhUnlockingTemplate {
        private_keys,
        multisig,
        sighash_flag: sighash_flag.unwrap_or(SIGHASH_ALL_FORKID),
        spend_type,
    })
}

/// Create a DSTAS unlocker from a [`SigningKey`] (dispatches P2PKH vs P2MPKH).
///
/// Returns a boxed `UnlockingScriptTemplate` suitable for either signing mode.
pub fn unlock_from_signing_key(
    key: &SigningKey,
    spend_type: DstasSpendType,
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

impl UnlockingScriptTemplate for DstasMpkhUnlockingTemplate {
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

    /// Estimate the byte length of a DSTAS P2MPKH unlocking script.
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
    fn dstas_unlock_from_signing_key_single() {
        let key = PrivateKey::new();
        let sk = SigningKey::Single(key);
        let result = unlock_from_signing_key(&sk, DstasSpendType::Transfer, None);
        assert!(result.is_ok());
    }

    #[test]
    fn dstas_unlock_from_signing_key_multi() {
        let keys: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::new()).collect();
        let pubs = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(2, pubs).unwrap();
        let sk = SigningKey::Multi {
            private_keys: vec![keys[0].clone(), keys[1].clone()],
            multisig: ms,
        };
        let result = unlock_from_signing_key(&sk, DstasSpendType::Transfer, None);
        assert!(result.is_ok());
    }

    #[test]
    fn dstas_unlock_mpkh_rejects_wrong_key_count() {
        let keys: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::new()).collect();
        let pubs = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(2, pubs).unwrap();
        let result = unlock_mpkh(keys, ms, DstasSpendType::Transfer, None);
        assert!(result.is_err());
    }

    #[test]
    fn dstas_mpkh_estimate_length_2_of_3() {
        let keys: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::new()).collect();
        let pubs = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(2, pubs).unwrap();
        let unlocker = unlock_mpkh(
            vec![keys[0].clone(), keys[1].clone()],
            ms,
            DstasSpendType::Transfer,
            None,
        ).unwrap();
        let tx = bsv_transaction::transaction::Transaction::default();
        let est = unlocker.estimate_length(&tx, 0);
        assert!(est > 106);
    }
}
