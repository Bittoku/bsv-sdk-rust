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
    /// `m` signatures: `m * (1 push + 72 DER + 1 sighash) = m * 73`.
    /// Redeem script buffer (STAS 3.0 wire format, spec § 10.2):
    /// `2 + 34 * n` bytes, plus a 2-byte `OP_PUSHDATA1` prefix.
    fn estimate_length(&self, _tx: &Transaction, _input_index: u32) -> u32 {
        let m = self.multisig.threshold() as u32;
        let n = self.multisig.n() as u32;
        let sig_bytes = m * 73;
        let redeem_len = 2 + n * 34;
        sig_bytes + 2 + redeem_len
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
        assert!(est > 106); // must be more than P2PKH
        // 2 * 73 (sigs) + 2 (PUSHDATA1) + (2 + 3*34) redeem = 146 + 2 + 104 = 252
        assert_eq!(est, 2 * 73 + 2 + (2 + 3 * 34));
    }

    // -------------------------------------------------------------------
    // Gap 1: StasMpkhUnlockingTemplate::sign() tests
    // -------------------------------------------------------------------

    /// Build a mock transaction with a source output set on input 0.
    fn mock_tx_with_source(satoshis: u64) -> bsv_transaction::transaction::Transaction {
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
    fn stas_mpkh_sign_2_of_3_script_structure() {
        let keys: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::new()).collect();
        let pubs: Vec<_> = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(2, pubs).unwrap();
        let ms_bytes = ms.to_bytes();

        let unlocker = unlock_mpkh(
            vec![keys[0].clone(), keys[1].clone()],
            ms,
            None,
        )
        .unwrap();

        let tx = mock_tx_with_source(10_000);
        let script = unlocker.sign(&tx, 0).unwrap();
        let chunks = script.chunks().unwrap();

        // M signatures + 1 multisig script push = 3 chunks total
        assert_eq!(chunks.len(), 3, "expected 2 sigs + 1 multisig script push");

        // Verify each signature chunk
        for i in 0..2 {
            let sig_data = chunks[i].data.as_ref().expect("signature should be push data");
            // DER signature + sighash flag: 71-73 bytes
            assert!(
                sig_data.len() >= 71 && sig_data.len() <= 73,
                "signature {} length {} not in 71..=73",
                i,
                sig_data.len()
            );
            // Last byte is SIGHASH_ALL_FORKID (0x41)
            assert_eq!(
                *sig_data.last().unwrap(),
                0x41,
                "signature {} should end with SIGHASH_ALL_FORKID",
                i
            );
        }

        // Last chunk is the serialized multisig script
        let ms_chunk = chunks[2].data.as_ref().expect("multisig script should be push data");
        assert_eq!(ms_chunk, &ms_bytes, "final chunk should be the multisig script bytes");
    }

    #[test]
    fn stas_mpkh_sign_1_of_1() {
        let keys: Vec<PrivateKey> = (0..1).map(|_| PrivateKey::new()).collect();
        let pubs: Vec<_> = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(1, pubs).unwrap();

        let unlocker = unlock_mpkh(vec![keys[0].clone()], ms, None).unwrap();
        let tx = mock_tx_with_source(5_000);
        let script = unlocker.sign(&tx, 0).unwrap();
        let chunks = script.chunks().unwrap();

        // 1 signature + 1 multisig script = 2 chunks
        assert_eq!(chunks.len(), 2);
        let sig_data = chunks[0].data.as_ref().unwrap();
        assert!(sig_data.len() >= 71 && sig_data.len() <= 73);
        assert_eq!(*sig_data.last().unwrap(), 0x41);
    }

    #[test]
    fn stas_mpkh_sign_3_of_5() {
        let keys: Vec<PrivateKey> = (0..5).map(|_| PrivateKey::new()).collect();
        let pubs: Vec<_> = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(3, pubs).unwrap();

        let unlocker = unlock_mpkh(
            vec![keys[0].clone(), keys[1].clone(), keys[2].clone()],
            ms,
            None,
        )
        .unwrap();

        let tx = mock_tx_with_source(20_000);
        let script = unlocker.sign(&tx, 0).unwrap();
        let chunks = script.chunks().unwrap();

        // 3 signatures + 1 multisig script = 4 chunks
        assert_eq!(chunks.len(), 4);
        for i in 0..3 {
            let sig = chunks[i].data.as_ref().unwrap();
            assert!(sig.len() >= 71 && sig.len() <= 73);
            assert_eq!(*sig.last().unwrap(), 0x41);
        }
    }

    #[test]
    fn stas_mpkh_sign_missing_source_output_returns_error() {
        let keys: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::new()).collect();
        let pubs: Vec<_> = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(2, pubs).unwrap();
        let unlocker = unlock_mpkh(
            vec![keys[0].clone(), keys[1].clone()],
            ms,
            None,
        )
        .unwrap();

        // Transaction with an input but no source output set
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
    fn stas_mpkh_sign_signatures_unique_per_key() {
        let keys: Vec<PrivateKey> = (0..3).map(|_| PrivateKey::new()).collect();
        let pubs: Vec<_> = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(2, pubs).unwrap();

        let unlocker = unlock_mpkh(
            vec![keys[0].clone(), keys[1].clone()],
            ms,
            None,
        )
        .unwrap();

        let tx = mock_tx_with_source(10_000);
        let script = unlocker.sign(&tx, 0).unwrap();
        let chunks = script.chunks().unwrap();

        let sig0 = chunks[0].data.as_ref().unwrap();
        let sig1 = chunks[1].data.as_ref().unwrap();
        assert_ne!(sig0, sig1, "signatures from different keys must differ");
    }

    // -------------------------------------------------------------------
    // Gap 6 (STAS): estimate_length across multiple m-of-n combinations
    // -------------------------------------------------------------------

    #[test]
    fn stas_mpkh_estimate_length_1_of_1() {
        let keys: Vec<PrivateKey> = (0..1).map(|_| PrivateKey::new()).collect();
        let pubs = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(1, pubs).unwrap();
        let unlocker = unlock_mpkh(vec![keys[0].clone()], ms, None).unwrap();
        let tx = bsv_transaction::transaction::Transaction::default();
        let est = unlocker.estimate_length(&tx, 0);
        // 1*73 + 2 (PUSHDATA1) + (2 + 1*34) redeem = 73 + 2 + 36 = 111
        assert_eq!(est, 73 + 2 + (2 + 34));
    }

    #[test]
    fn stas_mpkh_estimate_length_3_of_5() {
        let keys: Vec<PrivateKey> = (0..5).map(|_| PrivateKey::new()).collect();
        let pubs = keys.iter().map(|k| k.pub_key()).collect();
        let ms = MultisigScript::new(3, pubs).unwrap();
        let unlocker = unlock_mpkh(
            vec![keys[0].clone(), keys[1].clone(), keys[2].clone()],
            ms,
            None,
        )
        .unwrap();
        let tx = bsv_transaction::transaction::Transaction::default();
        let est = unlocker.estimate_length(&tx, 0);
        // 3*73 + 2 (PUSHDATA1) + (2 + 5*34) redeem = 219 + 2 + 172 = 393
        assert_eq!(est, 3 * 73 + 2 + (2 + 5 * 34));
    }
}
