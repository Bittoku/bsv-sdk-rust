//! STAS unlocking script templates (P2PKH and P2MPKH).
//!
//! The standard STAS unlocking script is identical to P2PKH: `<sig> <pubkey>`.
//! The P2MPKH variant produces: `<sig1> … <sigM> <serialized_multisig_script>`.
//!
//! The on-chain STAS script auto-detects the format: if the public key data
//! is 33 bytes it runs P2PKH verification; otherwise it parses the multisig
//! script and runs P2MPKH verification.

use bsv_primitives::ec::PrivateKey;
use bsv_script::Script;
use bsv_transaction::sighash::SIGHASH_ALL_FORKID;
use bsv_transaction::template::p2mpkh::MultisigScript;
use bsv_transaction::template::UnlockingScriptTemplate;
use bsv_transaction::transaction::Transaction;
use bsv_transaction::TransactionError;

use crate::types::SigningKey;

// ---------------------------------------------------------------------------
// P2PKH STAS unlocker (existing)
// ---------------------------------------------------------------------------

/// STAS unlocking script template holding a private key and sighash flag.
///
/// Produces unlocking scripts of the form `<DER_signature + sighash_byte> <compressed_pubkey>`,
/// identical to P2PKH.
pub struct StasUnlockingTemplate {
    private_key: PrivateKey,
    sighash_flag: u32,
}

/// Create a STAS unlocker for signing token inputs (P2PKH).
///
/// # Arguments
/// * `private_key` - The private key used to sign.
/// * `sighash_flag` - Optional sighash flag. Defaults to `SIGHASH_ALL_FORKID`.
///
/// # Returns
/// A `StasUnlockingTemplate` implementing `UnlockingScriptTemplate`.
pub fn unlock(private_key: PrivateKey, sighash_flag: Option<u32>) -> StasUnlockingTemplate {
    StasUnlockingTemplate {
        private_key,
        sighash_flag: sighash_flag.unwrap_or(SIGHASH_ALL_FORKID),
    }
}

impl UnlockingScriptTemplate for StasUnlockingTemplate {
    /// Sign the specified input and produce the unlocking script.
    ///
    /// Identical to P2PKH: computes BIP-143 sighash, signs with ECDSA,
    /// builds `<sig> <pubkey>`.
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

    /// Estimate the byte length of a STAS unlocking script (same as P2PKH).
    fn estimate_length(&self, _tx: &Transaction, _input_index: u32) -> u32 {
        106
    }
}

// ---------------------------------------------------------------------------
// P2MPKH STAS unlocker (new)
// ---------------------------------------------------------------------------

/// STAS P2MPKH unlocking script template.
///
/// Produces unlocking scripts of the form:
/// ```text
/// <sig1> <sig2> … <sigM> <serialized_multisig_script>
/// ```
///
/// The on-chain STAS script detects that the "public key" data is longer than
/// 33 bytes and switches to P2MPKH verification: it HASH160s the multisig
/// script to verify against the stored MPKH, then evaluates the embedded
/// `OP_CHECKMULTISIG` with the provided signatures.
///
/// Note: unlike the standalone bare multisig template, STAS P2MPKH does NOT
/// include the `OP_0` dummy element — the STAS script handles the multisig
/// evaluation internally.
pub struct StasMpkhUnlockingTemplate {
    /// The m private keys for threshold signing.
    private_keys: Vec<PrivateKey>,
    /// The full multisig script (all n public keys).
    multisig: MultisigScript,
    /// Sighash flag.
    sighash_flag: u32,
}

/// Create a STAS P2MPKH unlocker for signing token inputs.
///
/// # Arguments
/// * `private_keys` - The m private keys satisfying the threshold.
/// * `multisig` - The full m-of-n multisig script.
/// * `sighash_flag` - Optional sighash flag. Defaults to `SIGHASH_ALL_FORKID`.
///
/// # Returns
/// A `StasMpkhUnlockingTemplate` implementing `UnlockingScriptTemplate`.
///
/// # Errors
/// Returns an error if the number of private keys doesn't match the threshold.
pub fn unlock_mpkh(
    private_keys: Vec<PrivateKey>,
    multisig: MultisigScript,
    sighash_flag: Option<u32>,
) -> Result<StasMpkhUnlockingTemplate, TransactionError> {
    if private_keys.len() != multisig.threshold() as usize {
        return Err(TransactionError::SigningError(format!(
            "expected {} private keys for threshold, got {}",
            multisig.threshold(),
            private_keys.len()
        )));
    }
    Ok(StasMpkhUnlockingTemplate {
        private_keys,
        multisig,
        sighash_flag: sighash_flag.unwrap_or(SIGHASH_ALL_FORKID),
    })
}

/// Create a STAS unlocker from a [`SigningKey`] (dispatches P2PKH vs P2MPKH).
///
/// Returns a boxed `UnlockingScriptTemplate` suitable for either signing mode.
pub fn unlock_from_signing_key(
    key: &SigningKey,
    sighash_flag: Option<u32>,
) -> Result<Box<dyn UnlockingScriptTemplate>, TransactionError> {
    match key {
        SigningKey::Single(pk) => Ok(Box::new(unlock(pk.clone(), sighash_flag))),
        SigningKey::Multi {
            private_keys,
            multisig,
        } => Ok(Box::new(unlock_mpkh(
            private_keys.clone(),
            multisig.clone(),
            sighash_flag,
        )?)),
    }
}

impl UnlockingScriptTemplate for StasMpkhUnlockingTemplate {
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

        // Push the serialized multisig script (replaces the single pubkey).
        script.append_push_data(&self.multisig.to_bytes())?;

        Ok(script)
    }

    /// Estimate the byte length of a STAS P2MPKH unlocking script.
    ///
    /// m signatures: m * (1 push + 72 DER + sighash) = m * 73
    /// multisig script: 1 (OP_m) + n * 34 (OP_DATA_33 + 33) + 1 (OP_n) + 1 (OP_CHECKMULTISIG)
    /// Plus push-data prefix for the script (~3 bytes for OP_PUSHDATA1).
    fn estimate_length(&self, _tx: &Transaction, _input_index: u32) -> u32 {
        let m = self.multisig.threshold() as u32;
        let n = self.multisig.n() as u32;
        let sig_bytes = m * 73;
        let script_bytes = 3 + n * 34 + 3; // script + pushdata overhead
        sig_bytes + script_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_primitives::ec::PrivateKey;
    use bsv_transaction::template::p2mpkh::MultisigScript;

    #[test]
    fn unlock_from_signing_key_single() {
        let key = PrivateKey::new();
        let sk = SigningKey::Single(key);
        let result = unlock_from_signing_key(&sk, None);
        assert!(result.is_ok());
    }

    #[test]
    fn unlock_from_signing_key_multi() {
        let keys: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::new()).collect();
        let pubs = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(2, pubs).unwrap();
        let sk = SigningKey::Multi {
            private_keys: vec![keys[0].clone(), keys[1].clone()],
            multisig: ms,
        };
        let result = unlock_from_signing_key(&sk, None);
        assert!(result.is_ok());
    }

    #[test]
    fn unlock_mpkh_rejects_wrong_key_count() {
        let keys: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::new()).collect();
        let pubs = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(2, pubs).unwrap();
        // Provide 3 keys for threshold of 2
        let result = unlock_mpkh(keys, ms, None);
        assert!(result.is_err());
    }

    #[test]
    fn stas_mpkh_estimate_length_2_of_3() {
        let keys: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::new()).collect();
        let pubs = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(2, pubs).unwrap();
        let unlocker = unlock_mpkh(
            vec![keys[0].clone(), keys[1].clone()],
            ms,
            None,
        ).unwrap();
        let tx = bsv_transaction::transaction::Transaction::default();
        let est = unlocker.estimate_length(&tx, 0);
        // 2 * 73 (sigs) + 3 + 3*34 + 3 (script + overhead) = 146 + 108 = 254
        assert!(est > 106); // must be more than P2PKH
        assert_eq!(est, 2 * 73 + 3 + 3 * 34 + 3);
    }
}
