//! Pay-to-Multiple-Public-Key-Hash (P2MPKH) script template.
//!
//! Extends P2PKH to support m-of-n multisig ownership while preserving the
//! privacy and security benefits of hashing. The locking script stores only
//! the HASH160 of a raw multisig script (the "MPKH") — the full multisig
//! script remains hidden until spending.
//!
//! ## Standalone vs STAS usage
//!
//! As a standalone template, P2MPKH produces bare multisig locking scripts
//! (`OP_m <pk1>…<pkN> OP_n OP_CHECKMULTISIG`) for direct on-chain use.
//!
//! For STAS integration, the [`MultisigScript`] type provides:
//! - [`MultisigScript::mpkh()`] — the 20-byte HASH160 stored in STAS Variable Field 1
//! - [`MultisigScript::to_script()`] — the serialized redeem script revealed at spend time
//!
//! STAS locking scripts auto-detect P2PKH vs P2MPKH based on the unlocking
//! data length: 33 bytes (compressed pubkey) → P2PKH; otherwise → P2MPKH.
//!
//! ## Script formats
//!
//! **Bare multisig locking script** (standalone):
//! ```text
//! OP_m <pubkey1> <pubkey2> … <pubkeyN> OP_n OP_CHECKMULTISIG
//! ```
//!
//! **Bare multisig unlocking script** (standalone):
//! ```text
//! OP_0 <sig1> <sig2> … <sigM>
//! ```
//!
//! **STAS unlocking script** (P2MPKH mode):
//! ```text
//! <sig1> <sig2> … <sigM> <serialized_multisig_script>
//! ```
//! (STAS handles HASH160 verification and OP_CHECKMULTISIG internally.)

use bsv_primitives::ec::{PrivateKey, PublicKey};
use bsv_primitives::hash::hash160;
use bsv_script::opcodes::*;
use bsv_script::Script;

use crate::sighash::SIGHASH_ALL_FORKID;
use crate::template::UnlockingScriptTemplate;
use crate::transaction::Transaction;
use crate::TransactionError;

/// Maximum number of public keys allowed in a multisig script.
///
/// BSV consensus permits up to 16, but STAS limits to 5. We use the BSV
/// consensus limit here; STAS enforces its own cap at the token layer.
pub const MAX_MULTISIG_KEYS: usize = 16;

/// Minimum number of public keys in a multisig script.
pub const MIN_MULTISIG_KEYS: usize = 1;

/// A raw m-of-n multisig script.
///
/// Represents the canonical multisig redeem script:
/// `OP_m <pk1> <pk2> … <pkN> OP_n OP_CHECKMULTISIG`
///
/// This type is the building block for both standalone P2MPKH locking scripts
/// and STAS MPKH address fields.
#[derive(Clone, Debug)]
pub struct MultisigScript {
    /// Threshold — minimum number of signatures required to spend.
    threshold: u8,
    /// The set of public keys (compressed, 33 bytes each).
    public_keys: Vec<PublicKey>,
}

impl MultisigScript {
    /// Create a new multisig script with the given threshold and public keys.
    ///
    /// # Arguments
    /// * `threshold` - The m in m-of-n (minimum signatures required).
    /// * `public_keys` - The n public keys. Order matters — signatures must
    ///   correspond to keys in the same order as they appear here.
    ///
    /// # Errors
    /// Returns an error if:
    /// - `threshold` is 0 or greater than the number of keys
    /// - `public_keys` is empty or exceeds [`MAX_MULTISIG_KEYS`]
    pub fn new(threshold: u8, public_keys: Vec<PublicKey>) -> Result<Self, TransactionError> {
        let n = public_keys.len();

        if n < MIN_MULTISIG_KEYS {
            return Err(TransactionError::InvalidTransaction(
                "multisig requires at least 1 public key".to_string(),
            ));
        }
        if n > MAX_MULTISIG_KEYS {
            return Err(TransactionError::InvalidTransaction(format!(
                "multisig supports at most {} public keys, got {}",
                MAX_MULTISIG_KEYS, n
            )));
        }
        if threshold == 0 {
            return Err(TransactionError::InvalidTransaction(
                "multisig threshold must be at least 1".to_string(),
            ));
        }
        if threshold as usize > n {
            return Err(TransactionError::InvalidTransaction(format!(
                "threshold {} exceeds number of keys {}",
                threshold, n
            )));
        }

        Ok(MultisigScript {
            threshold,
            public_keys,
        })
    }

    /// The threshold (m) — minimum signatures required.
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// The total number of keys (n).
    pub fn n(&self) -> usize {
        self.public_keys.len()
    }

    /// The public keys in this multisig script.
    pub fn public_keys(&self) -> &[PublicKey] {
        &self.public_keys
    }

    /// Serialize to the raw multisig script bytes.
    ///
    /// Produces: `OP_m <pk1> <pk2> … <pkN> OP_n OP_CHECKMULTISIG`
    ///
    /// Each public key is pushed as 33 bytes (compressed SEC1 format).
    pub fn to_script(&self) -> Script {
        let n = self.public_keys.len();
        // Estimate: 1 (OP_m) + n * (1 + 33) + 1 (OP_n) + 1 (OP_CHECKMULTISIG)
        let mut bytes = Vec::with_capacity(3 + n * 34);

        // OP_m (OP_1 = 0x51 for m=1, OP_2 = 0x52 for m=2, etc.)
        bytes.push(OP_BASE + self.threshold);

        // Push each compressed public key (33 bytes each).
        for pk in &self.public_keys {
            let compressed = pk.to_compressed();
            bytes.push(OP_DATA_33);
            bytes.extend_from_slice(&compressed);
        }

        // OP_n
        bytes.push(OP_BASE + n as u8);

        // OP_CHECKMULTISIG
        bytes.push(OP_CHECKMULTISIG);

        Script::from_bytes(&bytes)
    }

    /// Serialize to raw bytes (the script content without push-data envelope).
    ///
    /// This is the byte sequence that gets HASH160'd to produce the MPKH,
    /// and what gets pushed onto the stack in STAS unlocking scripts.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_script().to_bytes().to_vec()
    }

    /// Compute the MPKH — the 20-byte HASH160 of this multisig script.
    ///
    /// This is the value stored in STAS locking scripts in place of a
    /// single public key hash. It serves the same role as the PKH in P2PKH
    /// but commits to the entire multisig configuration.
    pub fn mpkh(&self) -> [u8; 20] {
        hash160(&self.to_bytes())
    }

    /// Parse a `MultisigScript` from raw script bytes.
    ///
    /// Expects the canonical format:
    /// `OP_m <pk1_33bytes> … <pkN_33bytes> OP_n OP_CHECKMULTISIG`
    ///
    /// # Errors
    /// Returns an error if the bytes don't match the expected multisig format.
    pub fn from_script_bytes(bytes: &[u8]) -> Result<Self, TransactionError> {
        // Minimum: OP_m + (OP_DATA_33 + 33 bytes) + OP_n + OP_CHECKMULTISIG = 37
        if bytes.len() < 37 {
            return Err(TransactionError::InvalidTransaction(
                "script too short for multisig".to_string(),
            ));
        }

        // Last byte must be OP_CHECKMULTISIG.
        if *bytes.last().unwrap() != OP_CHECKMULTISIG {
            return Err(TransactionError::InvalidTransaction(
                "script does not end with OP_CHECKMULTISIG".to_string(),
            ));
        }

        // First byte: OP_m (OP_1..OP_16)
        let m_op = bytes[0];
        if m_op < OP_1 || m_op > OP_16 {
            return Err(TransactionError::InvalidTransaction(format!(
                "invalid threshold opcode: 0x{:02x}",
                m_op
            )));
        }
        let m = (m_op - OP_BASE) as u8;

        // Second-to-last byte: OP_n
        let n_op = bytes[bytes.len() - 2];
        if n_op < OP_1 || n_op > OP_16 {
            return Err(TransactionError::InvalidTransaction(format!(
                "invalid key count opcode: 0x{:02x}",
                n_op
            )));
        }
        let n = (n_op - OP_BASE) as usize;

        // Parse public keys: each is OP_DATA_33 followed by 33 bytes.
        let key_section = &bytes[1..bytes.len() - 2]; // between OP_m and OP_n
        if key_section.len() != n * 34 {
            return Err(TransactionError::InvalidTransaction(format!(
                "expected {} key slots ({} bytes), got {} bytes",
                n,
                n * 34,
                key_section.len()
            )));
        }

        let mut public_keys = Vec::with_capacity(n);
        for i in 0..n {
            let offset = i * 34;
            if key_section[offset] != OP_DATA_33 {
                return Err(TransactionError::InvalidTransaction(format!(
                    "expected OP_DATA_33 at key {}, got 0x{:02x}",
                    i,
                    key_section[offset]
                )));
            }
            let pk_bytes = &key_section[offset + 1..offset + 34];
            let pk = PublicKey::from_bytes(pk_bytes).map_err(|e| {
                TransactionError::InvalidTransaction(format!(
                    "invalid public key at index {}: {}",
                    i, e
                ))
            })?;
            public_keys.push(pk);
        }

        MultisigScript::new(m, public_keys)
    }
}

/// Create a bare multisig locking script from a [`MultisigScript`].
///
/// Produces: `OP_m <pk1> <pk2> … <pkN> OP_n OP_CHECKMULTISIG`
///
/// This is the standalone locking script for direct on-chain use.
/// For STAS, use [`MultisigScript::mpkh()`] to get the 20-byte hash
/// embedded in the STAS locking script instead.
///
/// # Arguments
/// * `multisig` - The multisig configuration to lock to.
///
/// # Returns
/// `Ok(Script)` containing the bare multisig locking script.
pub fn lock(multisig: &MultisigScript) -> Result<Script, TransactionError> {
    Ok(multisig.to_script())
}

/// Create a P2MPKH unlocker for signing transaction inputs.
///
/// The unlocker holds the private keys for the threshold signers and
/// the full multisig script (needed to produce the unlocking script).
///
/// # Arguments
/// * `private_keys` - The private keys of the m signers (must be exactly `threshold` keys).
/// * `multisig` - The full multisig script (all n public keys + threshold).
/// * `sighash_flag` - Optional sighash flag. Defaults to `SIGHASH_ALL_FORKID` (0x41).
///
/// # Returns
/// A `P2MPKH` instance implementing `UnlockingScriptTemplate`.
///
/// # Errors
/// Returns an error if the number of private keys doesn't match the threshold.
pub fn unlock(
    private_keys: Vec<PrivateKey>,
    multisig: MultisigScript,
    sighash_flag: Option<u32>,
) -> Result<P2MPKH, TransactionError> {
    if private_keys.len() != multisig.threshold() as usize {
        return Err(TransactionError::SigningError(format!(
            "expected {} private keys for threshold, got {}",
            multisig.threshold(),
            private_keys.len()
        )));
    }
    Ok(P2MPKH {
        private_keys,
        multisig,
        sighash_flag: sighash_flag.unwrap_or(SIGHASH_ALL_FORKID),
    })
}

/// P2MPKH signing template holding m private keys and the full multisig script.
///
/// Implements [`UnlockingScriptTemplate`] to produce unlocking scripts of the form:
/// ```text
/// OP_0 <sig1> <sig2> … <sigM>
/// ```
///
/// For STAS usage, the STAS template appends the serialized multisig script
/// to the unlocking data. This template produces the standard bare multisig
/// unlocking script (with the OP_0 dummy element required by OP_CHECKMULTISIG).
#[derive(Debug)]
pub struct P2MPKH {
    /// The private keys of the m threshold signers.
    ///
    /// These must correspond to public keys in the [`MultisigScript`], in the
    /// same relative order (signatures are matched to keys sequentially by
    /// OP_CHECKMULTISIG).
    private_keys: Vec<PrivateKey>,

    /// The full multisig script containing all n public keys.
    multisig: MultisigScript,

    /// The sighash flag to use (e.g. `SIGHASH_ALL_FORKID`).
    sighash_flag: u32,
}

impl P2MPKH {
    /// Access the underlying multisig script.
    pub fn multisig(&self) -> &MultisigScript {
        &self.multisig
    }
}

impl UnlockingScriptTemplate for P2MPKH {
    /// Sign the specified input and produce the bare multisig unlocking script.
    ///
    /// Computes the BIP-143-style signature hash, signs it with each of the m
    /// private keys, and constructs:
    /// ```text
    /// OP_0 <DER_sig1 || sighash_byte> <DER_sig2 || sighash_byte> … <DER_sigM || sighash_byte>
    /// ```
    ///
    /// The `OP_0` dummy element is required by the OP_CHECKMULTISIG off-by-one
    /// behavior in the Bitcoin protocol.
    ///
    /// # Arguments
    /// * `tx` - The transaction being signed.
    /// * `input_index` - The index of the input to sign.
    ///
    /// # Returns
    /// `Ok(Script)` containing the P2MPKH unlocking script.
    fn sign(&self, tx: &Transaction, input_index: u32) -> Result<Script, TransactionError> {
        let idx = input_index as usize;

        if idx >= tx.inputs.len() {
            return Err(TransactionError::SigningError(format!(
                "input index {} out of range (tx has {} inputs)",
                idx,
                tx.inputs.len()
            )));
        }

        // Verify source output info is available.
        let input = &tx.inputs[idx];
        if input.source_tx_output().is_none() {
            return Err(TransactionError::SigningError(
                "missing source output on input (no previous tx info)".to_string(),
            ));
        }

        // Compute the signature hash.
        let sig_hash = tx.calc_input_signature_hash(idx, self.sighash_flag)?;

        // Build the unlocking script.
        let mut script = Script::new();

        // OP_0 dummy element (OP_CHECKMULTISIG off-by-one bug).
        script.append_push_data(&[])?;

        // Sign with each private key and push the DER signature + sighash byte.
        for pk in &self.private_keys {
            let signature = pk.sign(&sig_hash)?;
            let der_sig = signature.to_der();
            let mut sig_buf = Vec::with_capacity(der_sig.len() + 1);
            sig_buf.extend_from_slice(&der_sig);
            sig_buf.push(self.sighash_flag as u8);
            script.append_push_data(&sig_buf)?;
        }

        Ok(script)
    }

    /// Estimate the byte length of a P2MPKH unlocking script.
    ///
    /// Each signature slot: 1 (push len) + 72 (DER sig + sighash) = 73 bytes.
    /// Plus 1 byte for OP_0 dummy.
    ///
    /// # Returns
    /// Estimated byte length: `1 + m * 73`.
    fn estimate_length(&self, _tx: &Transaction, _input_index: u32) -> u32 {
        1 + (self.multisig.threshold() as u32) * 73
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: generate n random private keys and their public keys.
    fn gen_keys(n: usize) -> (Vec<PrivateKey>, Vec<PublicKey>) {
        let privs: Vec<PrivateKey> = (0..n).map(|_| PrivateKey::new()).collect();
        let pubs: Vec<PublicKey> = privs.iter().map(|k| k.pub_key()).collect();
        (privs, pubs)
    }

    #[test]
    fn multisig_script_2_of_3_roundtrip() {
        let (_privs, pubs) = gen_keys(3);
        let ms = MultisigScript::new(2, pubs).unwrap();

        assert_eq!(ms.threshold(), 2);
        assert_eq!(ms.n(), 3);

        // Serialize and parse back.
        let bytes = ms.to_bytes();
        let ms2 = MultisigScript::from_script_bytes(&bytes).unwrap();
        assert_eq!(ms2.threshold(), 2);
        assert_eq!(ms2.n(), 3);

        // MPKH should be deterministic.
        assert_eq!(ms.mpkh(), ms2.mpkh());
    }

    #[test]
    fn multisig_script_1_of_1() {
        let (_privs, pubs) = gen_keys(1);
        let ms = MultisigScript::new(1, pubs).unwrap();
        assert_eq!(ms.threshold(), 1);
        assert_eq!(ms.n(), 1);

        let bytes = ms.to_bytes();
        // OP_1 + (OP_DATA_33 + 33 bytes) + OP_1 + OP_CHECKMULTISIG = 37 bytes
        assert_eq!(bytes.len(), 37);
    }

    #[test]
    fn multisig_script_max_keys() {
        let (_privs, pubs) = gen_keys(MAX_MULTISIG_KEYS);
        let ms = MultisigScript::new(1, pubs).unwrap();
        assert_eq!(ms.n(), MAX_MULTISIG_KEYS);
    }

    #[test]
    fn multisig_script_rejects_zero_threshold() {
        let (_privs, pubs) = gen_keys(3);
        let err = MultisigScript::new(0, pubs).unwrap_err();
        assert!(err.to_string().contains("threshold must be at least 1"));
    }

    #[test]
    fn multisig_script_rejects_threshold_exceeding_keys() {
        let (_privs, pubs) = gen_keys(2);
        let err = MultisigScript::new(3, pubs).unwrap_err();
        assert!(err.to_string().contains("threshold 3 exceeds"));
    }

    #[test]
    fn multisig_script_rejects_too_many_keys() {
        let (_privs, pubs) = gen_keys(MAX_MULTISIG_KEYS + 1);
        let err = MultisigScript::new(1, pubs).unwrap_err();
        assert!(err.to_string().contains("at most"));
    }

    #[test]
    fn multisig_script_rejects_empty_keys() {
        let err = MultisigScript::new(1, vec![]).unwrap_err();
        assert!(err.to_string().contains("at least 1"));
    }

    #[test]
    fn lock_produces_bare_multisig() {
        let (_privs, pubs) = gen_keys(3);
        let ms = MultisigScript::new(2, pubs).unwrap();
        let script = lock(&ms).unwrap();
        let bytes = script.to_bytes();

        // First byte: OP_2 (threshold)
        assert_eq!(bytes[0], OP_2);
        // Last byte: OP_CHECKMULTISIG
        assert_eq!(*bytes.last().unwrap(), OP_CHECKMULTISIG);
        // Second-to-last: OP_3 (key count)
        assert_eq!(bytes[bytes.len() - 2], OP_3);
    }

    #[test]
    fn mpkh_is_20_bytes() {
        let (_privs, pubs) = gen_keys(3);
        let ms = MultisigScript::new(2, pubs).unwrap();
        assert_eq!(ms.mpkh().len(), 20);
    }

    #[test]
    fn mpkh_differs_for_different_key_sets() {
        let (_privs1, pubs1) = gen_keys(3);
        let (_privs2, pubs2) = gen_keys(3);
        let ms1 = MultisigScript::new(2, pubs1).unwrap();
        let ms2 = MultisigScript::new(2, pubs2).unwrap();
        assert_ne!(ms1.mpkh(), ms2.mpkh());
    }

    #[test]
    fn mpkh_differs_for_different_thresholds() {
        let (_privs, pubs) = gen_keys(3);
        let ms1 = MultisigScript::new(1, pubs.clone()).unwrap();
        let ms2 = MultisigScript::new(2, pubs).unwrap();
        assert_ne!(ms1.mpkh(), ms2.mpkh());
    }

    #[test]
    fn unlock_rejects_wrong_key_count() {
        let (privs, pubs) = gen_keys(3);
        let ms = MultisigScript::new(2, pubs).unwrap();
        // Provide 3 keys for threshold of 2 — should fail.
        let err = unlock(privs, ms, None).unwrap_err();
        assert!(err.to_string().contains("expected 2 private keys"));
    }

    #[test]
    fn estimate_length_2_of_3() {
        let (privs, pubs) = gen_keys(3);
        let ms = MultisigScript::new(2, pubs).unwrap();
        let unlocker = unlock(vec![privs[0].clone(), privs[1].clone()], ms, None).unwrap();

        // Dummy tx for estimate.
        let tx = Transaction::default();
        let est = unlocker.estimate_length(&tx, 0);
        // 1 (OP_0) + 2 * 73 (sigs) = 147
        assert_eq!(est, 147);
    }

    #[test]
    fn from_script_bytes_rejects_garbage() {
        let err = MultisigScript::from_script_bytes(&[0x00, 0x01, 0x02]).unwrap_err();
        assert!(err.to_string().contains("too short"));
    }
}
