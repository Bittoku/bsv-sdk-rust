//! Pay-to-Multiple-Public-Key-Hash (P2MPKH) script template.
//!
//! Implements the wire format defined by the **STAS 3.0 specification v0.1
//! § 10.2**.  P2MPKH extends P2PKH to support `m`-of-`n` multisig ownership
//! by hashing a fixed-format *redeem script* into a 20-byte `MPKH` digest.
//! The full redeem script is only revealed at spend time.
//!
//! # Module purpose
//!
//! - Build the canonical STAS 3.0 redeem script for a given threshold and
//!   key set.
//! - Compute the `MPKH = HASH160(redeem_script)` digest stored in
//!   STAS / P2MPKH locking scripts.
//! - Build the fixed 70-byte P2MPKH locking script that brackets a STAS
//!   token's lifecycle (issuance / redemption UTXOs).
//! - Construct unlocking scripts of the form
//!   `OP_0 <sig_1> … <sig_m> <redeem_script>` that satisfy the locking script.
//!
//! # Wire format (spec § 10.2)
//!
//! ```text
//! redeem_script = [m: 1B raw 0x01..0x05]
//!                 [0x21][pk1 33B compressed SEC1]
//!                 …
//!                 [0x21][pkN 33B compressed SEC1]
//!                 [n: 1B raw 0x01..0x05]
//! ```
//!
//! Length = `2 + 34 * N` bytes.  `m` and `n` are RAW length bytes (NOT
//! `OP_m` / `OP_n` opcodes) and there is **no** trailing `OP_CHECKMULTISIG`
//! byte – the engine inlines the `OP_CHECKMULTISIG` step.
//!
//! Constraints: `1 <= m <= n <= 5`.
//!
//! Example (3-of-5):
//! `03 21 <pk1> 21 <pk2> 21 <pk3> 21 <pk4> 21 <pk5> 05` (total 172 bytes).
//!
//! # Locking script (70 bytes)
//!
//! Used at issuance and redemption UTXOs only (in-life STAS UTXOs inline the
//! same logic):
//!
//! ```text
//! 76 a9 14 <MPKH:20> 88 82 01 21 87 63 ac 67
//! 51 7f 51 7f 73 63 7c 7f 68
//! 51 7f 73 63 7c 7f 68 51 7f 73 63 7c 7f 68
//! 51 7f 73 63 7c 7f 68 51 7f 73 63 7c 7f 68
//! ae 68
//! ```
//!
//! Total 70 bytes.
//!
//! # Unlocking script
//!
//! Per spec § 10.2 (lines 414/434):
//!
//! ```text
//! OP_0 <sig_1> <sig_2> … <sig_m> <redeem_script>
//! ```
//!
//! The leading `OP_0` is the dummy stack element required by
//! `OP_CHECKMULTISIG`.

use bsv_primitives::ec::{PrivateKey, PublicKey};
use bsv_primitives::hash::hash160;
use bsv_script::opcodes::OP_DATA_33;
use bsv_script::Script;

use crate::sighash::SIGHASH_ALL_FORKID;
use crate::template::UnlockingScriptTemplate;
use crate::transaction::Transaction;
use crate::TransactionError;

/// Maximum number of public keys allowed in a STAS 3.0 P2MPKH redeem script.
///
/// The STAS 3.0 specification (§ 10.2) constrains both the threshold `m`
/// and the key count `n` to the inclusive range `1..=5`, encoded as a
/// single raw length byte.
pub const MAX_MULTISIG_KEYS: usize = 5;

/// Minimum number of public keys in a multisig script.
pub const MIN_MULTISIG_KEYS: usize = 1;

/// Length of the fixed P2MPKH locking script body, in bytes.
pub const P2MPKH_LOCKING_SCRIPT_LEN: usize = 70;

/// The 51-byte tail of the P2MPKH locking script that follows the 20-byte
/// `MPKH`.  Spec § 10.2 reference assembly:
/// `OP_EQUALVERIFY OP_SIZE 0x21 OP_EQUAL OP_IF OP_CHECKSIG OP_ELSE
///  OP_1 OP_SPLIT (OP_1 OP_SPLIT OP_IFDUP OP_IF OP_SWAP OP_SPLIT OP_ENDIF)×5
///  OP_CHECKMULTISIG OP_ENDIF`
const P2MPKH_LOCKING_SUFFIX: [u8; 47] = [
    0x88, 0x82, 0x01, 0x21, 0x87, 0x63, 0xac, 0x67, 0x51, 0x7f, 0x51, 0x7f, 0x73, 0x63, 0x7c, 0x7f,
    0x68, 0x51, 0x7f, 0x73, 0x63, 0x7c, 0x7f, 0x68, 0x51, 0x7f, 0x73, 0x63, 0x7c, 0x7f, 0x68, 0x51,
    0x7f, 0x73, 0x63, 0x7c, 0x7f, 0x68, 0x51, 0x7f, 0x73, 0x63, 0x7c, 0x7f, 0x68, 0xae, 0x68,
];

/// The 3-byte prefix of the P2MPKH locking script: `OP_DUP OP_HASH160 OP_DATA_20`.
const P2MPKH_LOCKING_PREFIX: [u8; 3] = [0x76, 0xa9, 0x14];

/// A canonical STAS 3.0 multisig redeem-script container.
///
/// Holds an `m`-of-`n` threshold and the ordered list of `n` compressed
/// public keys.  Order matters — at spend time signatures are matched to
/// keys sequentially by `OP_CHECKMULTISIG`.
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
    /// * `threshold` - The `m` in `m`-of-`n` (minimum signatures required).
    ///   Must satisfy `1 <= m <= n`.
    /// * `public_keys` - The `n` public keys, in canonical order.  Must be
    ///   non-empty and contain at most [`MAX_MULTISIG_KEYS`] entries.
    ///
    /// # Returns
    /// `Ok(MultisigScript)` on success.
    ///
    /// # Errors
    /// Returns [`TransactionError::InvalidTransaction`] when the constraints
    /// above are violated.
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

    /// The threshold (`m`) — minimum signatures required.
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// The total number of keys (`n`).
    pub fn n(&self) -> usize {
        self.public_keys.len()
    }

    /// The public keys in this multisig script.
    pub fn public_keys(&self) -> &[PublicKey] {
        &self.public_keys
    }

    /// Serialize to the canonical STAS 3.0 redeem-script byte buffer.
    ///
    /// Produces:
    /// `[m_raw] [0x21 pk1] [0x21 pk2] … [0x21 pkN] [n_raw]`
    ///
    /// Length = `2 + 34 * N` bytes.
    ///
    /// `m_raw` and `n_raw` are RAW length bytes in the range `0x01..=0x05`,
    /// **not** `OP_m` / `OP_n` opcodes.  No trailing `OP_CHECKMULTISIG` byte
    /// is emitted — the engine inlines that step.  This is the exact buffer
    /// hashed to derive the `MPKH` and pushed onto the stack at spend time.
    pub fn to_serialized_bytes(&self) -> Vec<u8> {
        let n = self.public_keys.len();
        let mut bytes = Vec::with_capacity(2 + n * 34);

        // m: raw length byte (0x01..=0x05).
        bytes.push(self.threshold);

        // Each public key: 0x21 push-prefix + 33 bytes compressed SEC1.
        for pk in &self.public_keys {
            let compressed = pk.to_compressed();
            bytes.push(OP_DATA_33);
            bytes.extend_from_slice(&compressed);
        }

        // n: raw length byte (0x01..=0x05).
        bytes.push(n as u8);

        bytes
    }

    /// Alias for [`Self::to_serialized_bytes`].  This is the byte sequence
    /// that gets HASH160'd to produce the `MPKH` and pushed onto the stack
    /// in the unlocking script.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_serialized_bytes()
    }

    /// Compute the `MPKH` — the 20-byte HASH160 of the canonical redeem
    /// script (see [`Self::to_serialized_bytes`]).
    ///
    /// This is the value embedded in P2MPKH and STAS locking scripts in
    /// place of a single `PKH`.
    pub fn mpkh(&self) -> [u8; 20] {
        hash160(&self.to_serialized_bytes())
    }

    /// Build the fixed 70-byte P2MPKH locking script for this multisig.
    ///
    /// Equivalent to `p2mpkh_locking_script(self.mpkh())`.
    pub fn p2mpkh_locking_script(&self) -> [u8; P2MPKH_LOCKING_SCRIPT_LEN] {
        p2mpkh_locking_script(self.mpkh())
    }

    /// Parse a `MultisigScript` from the canonical STAS 3.0 wire format.
    ///
    /// Expects exactly:
    /// `[m_raw] [0x21 pk1] … [0x21 pkN] [n_raw]`
    ///
    /// # Errors
    /// Returns an error if the buffer length is wrong, the leading or
    /// trailing length bytes are out of range, any push-prefix is not
    /// `0x21`, or any embedded public key fails to decode.
    pub fn from_serialized_bytes(bytes: &[u8]) -> Result<Self, TransactionError> {
        // Minimum length: m + (0x21 + 33) + n = 2 + 34 = 36 (1-of-1).
        if bytes.len() < 2 + 34 {
            return Err(TransactionError::InvalidTransaction(format!(
                "redeem script too short: {} bytes",
                bytes.len()
            )));
        }

        let m = bytes[0];
        let n = *bytes.last().unwrap();

        if !(MIN_MULTISIG_KEYS as u8..=MAX_MULTISIG_KEYS as u8).contains(&m) {
            return Err(TransactionError::InvalidTransaction(format!(
                "invalid threshold byte: 0x{:02x}",
                m
            )));
        }
        if !(MIN_MULTISIG_KEYS as u8..=MAX_MULTISIG_KEYS as u8).contains(&n) {
            return Err(TransactionError::InvalidTransaction(format!(
                "invalid key-count byte: 0x{:02x}",
                n
            )));
        }
        if m > n {
            return Err(TransactionError::InvalidTransaction(format!(
                "threshold {} exceeds key count {}",
                m, n
            )));
        }

        let expected_len = 2 + (n as usize) * 34;
        if bytes.len() != expected_len {
            return Err(TransactionError::InvalidTransaction(format!(
                "expected {} bytes for {}-of-{} redeem script, got {}",
                expected_len,
                m,
                n,
                bytes.len()
            )));
        }

        // Parse public keys: each is OP_DATA_33 (0x21) followed by 33 bytes.
        let key_section = &bytes[1..bytes.len() - 1];
        let mut public_keys = Vec::with_capacity(n as usize);
        for i in 0..n as usize {
            let offset = i * 34;
            if key_section[offset] != OP_DATA_33 {
                return Err(TransactionError::InvalidTransaction(format!(
                    "expected 0x21 push-prefix at key {}, got 0x{:02x}",
                    i, key_section[offset]
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

    /// Backwards-compatible alias for [`Self::from_serialized_bytes`].
    pub fn from_script_bytes(bytes: &[u8]) -> Result<Self, TransactionError> {
        Self::from_serialized_bytes(bytes)
    }
}

/// Build the fixed 70-byte STAS 3.0 P2MPKH locking script for the given
/// `MPKH`.
///
/// Layout (spec § 10.2):
///
/// ```text
/// 76 a9 14 <MPKH:20> 88 82 01 21 87 63 ac 67
/// (51 7f 51 7f 73 63 7c 7f 68)
/// (51 7f 73 63 7c 7f 68) × 4
/// ae 68
/// ```
///
/// Total 70 bytes.  Used at issuance and redemption UTXOs — the non-STAS
/// outputs that bracket a STAS token's lifecycle.  In-life STAS UTXOs
/// embed the same logic inside the STAS 3.0 base template.
///
/// # Arguments
/// * `mpkh` – The 20-byte `HASH160` of a STAS 3.0 redeem script.
///
/// # Returns
/// A 70-byte array containing the locking-script body.
pub fn p2mpkh_locking_script(mpkh: [u8; 20]) -> [u8; P2MPKH_LOCKING_SCRIPT_LEN] {
    let mut out = [0u8; P2MPKH_LOCKING_SCRIPT_LEN];
    out[..3].copy_from_slice(&P2MPKH_LOCKING_PREFIX);
    out[3..23].copy_from_slice(&mpkh);
    out[23..].copy_from_slice(&P2MPKH_LOCKING_SUFFIX);
    out
}

/// Build the STAS 3.0 P2MPKH locking script for the given multisig.
///
/// Convenience wrapper that derives the `MPKH` and returns the 70-byte body
/// wrapped as a [`Script`] for use as a transaction-output locking script.
///
/// # Arguments
/// * `multisig` – The `MultisigScript` to lock to.
///
/// # Returns
/// `Ok(Script)` containing the 70-byte P2MPKH locking script.
pub fn lock(multisig: &MultisigScript) -> Result<Script, TransactionError> {
    let body = multisig.p2mpkh_locking_script();
    Ok(Script::from_bytes(&body))
}

/// Build a P2MPKH unlocker for signing transaction inputs.
///
/// The unlocker holds the private keys for the threshold signers and the
/// full multisig redeem script — both are required to construct the
/// unlocking script.
///
/// # Arguments
/// * `private_keys` - Exactly `multisig.threshold()` private keys.
/// * `multisig` - The full `m`-of-`n` redeem script.
/// * `sighash_flag` - Optional sighash flag.  Defaults to
///   `SIGHASH_ALL_FORKID` (0x41).
///
/// # Returns
/// A [`P2MPKH`] instance implementing [`UnlockingScriptTemplate`].
///
/// # Errors
/// Returns [`TransactionError::SigningError`] when the number of supplied
/// private keys does not match the multisig threshold.
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

/// P2MPKH unlocker template.
///
/// Implements [`UnlockingScriptTemplate`] to produce unlocking scripts of
/// the form (spec § 10.2):
///
/// ```text
/// OP_0 <sig_1> <sig_2> … <sig_m> <redeem_script>
/// ```
#[derive(Debug)]
pub struct P2MPKH {
    /// The private keys of the `m` threshold signers, in the same relative
    /// order as their public keys appear in [`MultisigScript`].
    private_keys: Vec<PrivateKey>,

    /// The full multisig redeem script containing all `n` public keys.
    multisig: MultisigScript,

    /// The sighash flag to use (e.g. `SIGHASH_ALL_FORKID`).
    sighash_flag: u32,
}

impl P2MPKH {
    /// Access the underlying multisig redeem script.
    pub fn multisig(&self) -> &MultisigScript {
        &self.multisig
    }
}

impl UnlockingScriptTemplate for P2MPKH {
    /// Sign the specified input and produce the P2MPKH unlocking script.
    ///
    /// Computes the BIP-143-style signature hash, signs it with each of
    /// the `m` private keys, and emits:
    ///
    /// ```text
    /// OP_0 <DER_sig1 || sighash> … <DER_sigM || sighash> <redeem_script>
    /// ```
    ///
    /// The leading `OP_0` is the dummy element required by
    /// `OP_CHECKMULTISIG`.  The trailing push is the canonical STAS 3.0
    /// redeem buffer (see [`MultisigScript::to_serialized_bytes`]).
    ///
    /// # Arguments
    /// * `tx` - The transaction being signed.
    /// * `input_index` - The index of the input to sign.
    ///
    /// # Returns
    /// `Ok(Script)` containing the unlocking script.
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

        let mut script = Script::new();

        // OP_0 dummy element (OP_CHECKMULTISIG off-by-one bug).
        script.append_push_data(&[])?;

        // Sign with each private key and push DER signature || sighash byte.
        for pk in &self.private_keys {
            let signature = pk.sign(&sig_hash)?;
            let der_sig = signature.to_der();
            let mut sig_buf = Vec::with_capacity(der_sig.len() + 1);
            sig_buf.extend_from_slice(&der_sig);
            sig_buf.push(self.sighash_flag as u8);
            script.append_push_data(&sig_buf)?;
        }

        // Push the canonical redeem script (revealed at spend time).
        script.append_push_data(&self.multisig.to_serialized_bytes())?;

        Ok(script)
    }

    /// Estimate the byte length of a P2MPKH unlocking script.
    ///
    /// Layout: 1 (OP_0) + m * 73 (pushlen + DER sig + sighash) + redeem
    /// push.  Redeem buffer = `2 + 34 * n` bytes; with an OP_PUSHDATA1
    /// prefix that is `2 + (2 + 34 * n)`.
    ///
    /// # Returns
    /// Estimated byte length of the full unlocking script.
    fn estimate_length(&self, _tx: &Transaction, _input_index: u32) -> u32 {
        let m = self.multisig.threshold() as u32;
        let n = self.multisig.n() as u32;
        let redeem_len = 2 + n * 34;
        // 1 byte OP_0 + m * 73 (sig push) + 2 (PUSHDATA1 + len) + redeem_len
        1 + m * 73 + 2 + redeem_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: generate `n` random private keys and their public keys.
    fn gen_keys(n: usize) -> (Vec<PrivateKey>, Vec<PublicKey>) {
        let privs: Vec<PrivateKey> = (0..n).map(|_| PrivateKey::new()).collect();
        let pubs: Vec<PublicKey> = privs.iter().map(|k| k.pub_key()).collect();
        (privs, pubs)
    }

    /// Deterministic 33-byte compressed public key for vector tests.
    /// Builds a valid SEC1 point by deriving from a known private key seed.
    fn det_pubkey(seed: u8) -> PublicKey {
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = seed;
        let sk = PrivateKey::from_bytes(&sk_bytes).expect("valid scalar");
        sk.pub_key()
    }

    #[test]
    fn multisig_script_2_of_3_roundtrip() {
        let (_privs, pubs) = gen_keys(3);
        let ms = MultisigScript::new(2, pubs).unwrap();

        assert_eq!(ms.threshold(), 2);
        assert_eq!(ms.n(), 3);

        // Serialize and parse back.
        let bytes = ms.to_serialized_bytes();
        // Length = 2 + 34 * 3 = 104
        assert_eq!(bytes.len(), 2 + 34 * 3);
        // First byte = m (raw 0x02), last byte = n (raw 0x03).
        assert_eq!(bytes[0], 0x02);
        assert_eq!(*bytes.last().unwrap(), 0x03);

        let ms2 = MultisigScript::from_serialized_bytes(&bytes).unwrap();
        assert_eq!(ms2.threshold(), 2);
        assert_eq!(ms2.n(), 3);

        // MPKH should be deterministic and round-trip.
        assert_eq!(ms.mpkh(), ms2.mpkh());
    }

    #[test]
    fn multisig_script_1_of_1_length_is_36() {
        let (_privs, pubs) = gen_keys(1);
        let ms = MultisigScript::new(1, pubs).unwrap();

        // 1 (m) + 34 (0x21 + 33 bytes pk) + 1 (n) = 36 bytes.
        let bytes = ms.to_serialized_bytes();
        assert_eq!(bytes.len(), 36);
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes[1], 0x21);
        assert_eq!(bytes[35], 0x01);
    }

    #[test]
    fn multisig_script_max_keys_is_5() {
        let (_privs, pubs) = gen_keys(MAX_MULTISIG_KEYS);
        let ms = MultisigScript::new(1, pubs).unwrap();
        assert_eq!(ms.n(), MAX_MULTISIG_KEYS);

        // 5-of-5 buffer length = 2 + 34 * 5 = 172.
        let ms5_5 = MultisigScript::new(5, ms.public_keys().to_vec()).unwrap();
        assert_eq!(ms5_5.to_serialized_bytes().len(), 172);
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
    fn lock_produces_70_byte_locking_script() {
        let (_privs, pubs) = gen_keys(3);
        let ms = MultisigScript::new(2, pubs).unwrap();
        let script = lock(&ms).unwrap();
        let bytes = script.to_bytes();

        // Locking script = 70 bytes.
        assert_eq!(bytes.len(), P2MPKH_LOCKING_SCRIPT_LEN);
        // Prefix = 76 a9 14
        assert_eq!(&bytes[..3], &[0x76, 0xa9, 0x14]);
        // MPKH at offset 3..23
        assert_eq!(&bytes[3..23], &ms.mpkh()[..]);
        // Last two bytes = 0xae 0x68 (OP_CHECKMULTISIG OP_ENDIF)
        assert_eq!(&bytes[68..70], &[0xae, 0x68]);
    }

    #[test]
    fn p2mpkh_locking_script_exact_bytes() {
        // For an arbitrary MPKH, build the locking script and compare against
        // the spec-mandated hex.
        let mpkh: [u8; 20] = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00, 0x01, 0x02, 0x03, 0x04,
        ];
        let body = p2mpkh_locking_script(mpkh);
        let expected_hex = format!(
            "{}{}{}",
            "76a914",
            hex::encode(mpkh),
            "8882012187 63ac6751 7f517f73 637c7f68 \
             517f7363 7c7f6851 7f73637c 7f68517f \
             73637c7f 68517f73 637c7f68 ae68"
                .replace(' ', ""),
        );
        assert_eq!(hex::encode(body), expected_hex);
        assert_eq!(body.len(), P2MPKH_LOCKING_SCRIPT_LEN);
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
    fn mpkh_round_trip() {
        let (_privs, pubs) = gen_keys(3);
        let ms = MultisigScript::new(2, pubs).unwrap();
        let bytes = ms.to_serialized_bytes();
        let parsed = MultisigScript::from_serialized_bytes(&bytes).unwrap();
        assert_eq!(parsed.mpkh(), ms.mpkh());
    }

    #[test]
    fn deterministic_3_of_5_redeem_vector() {
        // Deterministic 3-of-5 with public keys derived from secp256k1 scalar
        // seeds 1, 2, 3, 4, 5 (i.e. compressed encodings of `i * G`).
        let pubs: Vec<PublicKey> = (1u8..=5).map(det_pubkey).collect();
        let ms = MultisigScript::new(3, pubs.clone()).unwrap();
        let bytes = ms.to_serialized_bytes();

        // Spec mandates length = 2 + 34 * 5 = 172.
        assert_eq!(bytes.len(), 172);
        // m = 0x03, n = 0x05 raw bytes.
        assert_eq!(bytes[0], 0x03);
        assert_eq!(*bytes.last().unwrap(), 0x05);

        // Each key slot is 0x21 followed by 33 bytes; verify offsets.
        for i in 0..5 {
            let off = 1 + i * 34;
            assert_eq!(bytes[off], 0x21, "key {} push prefix should be 0x21", i);
            assert_eq!(
                &bytes[off + 1..off + 34],
                &pubs[i].to_compressed()[..],
                "key {} body must match seed-derived public key",
                i
            );
        }

        // Exact 172-byte hex of the canonical 3-of-5 redeem buffer for the
        // public keys `i * G` (i = 1..=5).  Useful for cross-validating
        // against independent implementations (e.g. the Elixir reference).
        let expected_hex = concat!(
            "03",
            // pk1 = 1 * G
            "21",
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            // pk2 = 2 * G
            "21",
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            // pk3 = 3 * G
            "21",
            "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
            // pk4 = 4 * G
            "21",
            "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
            // pk5 = 5 * G
            "21",
            "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
            "05",
        );
        assert_eq!(hex::encode(&bytes), expected_hex);

        // MPKH = HASH160(redeem_buffer); pinned for cross-SDK parity check
        // against the Elixir reference at
        // bsv_sdk_elixir/test/bsv/transaction/p2mpkh_test.exs.
        assert_eq!(
            hex::encode(ms.mpkh()),
            "deb7bfb8b45c2bfe4579af5126b46c4d95e4e3a6"
        );
    }

    #[test]
    fn from_serialized_bytes_rejects_short() {
        let err = MultisigScript::from_serialized_bytes(&[0x01, 0x02, 0x03]).unwrap_err();
        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn from_serialized_bytes_rejects_bad_threshold() {
        // m = 0x06 is out of 1..=5 range.
        let mut bytes = vec![0x06];
        bytes.push(0x21);
        bytes.extend_from_slice(&[0u8; 33]);
        bytes.push(0x06);
        let err = MultisigScript::from_serialized_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("invalid threshold byte"));
    }

    #[test]
    fn from_serialized_bytes_rejects_bad_push_prefix() {
        // Length matches a 1-of-1 redeem script (36 bytes) but the
        // push-prefix byte is wrong.
        let mut bytes = vec![0x01];
        bytes.push(0x4c); // wrong push prefix
        bytes.extend_from_slice(&[0u8; 33]);
        bytes.push(0x01);
        let err = MultisigScript::from_serialized_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("push-prefix"));
    }

    #[test]
    fn from_serialized_bytes_rejects_threshold_exceeds_count() {
        // m = 0x05 but only 1 key follows (n = 0x01).
        let mut bytes = vec![0x05];
        bytes.push(0x21);
        // Use a real public key so we don't trip the "invalid public key"
        // branch first.
        let pk = det_pubkey(1).to_compressed();
        bytes.extend_from_slice(&pk);
        bytes.push(0x01);
        let err = MultisigScript::from_serialized_bytes(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("threshold") || err.to_string().contains("exceeds"),
            "unexpected error: {}",
            err
        );
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

        let tx = Transaction::default();
        let est = unlocker.estimate_length(&tx, 0);
        // 1 (OP_0) + 2 * 73 (sigs) + 2 (PUSHDATA1 + len) + (2 + 3*34) redeem
        let expected = 1 + 2 * 73 + 2 + (2 + 3 * 34);
        assert_eq!(est, expected);
    }

    // -------------------------------------------------------------------
    // P2MPKH::sign() integration tests
    // -------------------------------------------------------------------

    use crate::input::TransactionInput;
    use crate::output::TransactionOutput;

    /// Build a mock transaction with a source output on input 0.
    fn mock_tx_with_source(satoshis: u64) -> Transaction {
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

        let mut tx = Transaction::new();
        tx.add_input(input);
        tx.add_output(TransactionOutput {
            satoshis: satoshis.saturating_sub(1000),
            locking_script,
            change: false,
        });
        tx
    }

    #[test]
    fn p2mpkh_sign_2_of_3_script_structure() {
        let (privs, pubs) = gen_keys(3);
        let ms = MultisigScript::new(2, pubs).unwrap();
        let ms_bytes = ms.to_serialized_bytes();
        let unlocker = unlock(vec![privs[0].clone(), privs[1].clone()], ms, None).unwrap();

        let tx = mock_tx_with_source(10_000);
        let script = unlocker.sign(&tx, 0).unwrap();
        let chunks = script.chunks().unwrap();

        // OP_0 + 2 signatures + redeem script = 4 chunks.
        assert_eq!(chunks.len(), 4, "expected OP_0 + 2 sigs + redeem push");

        // Chunk 0: OP_0 / empty push.
        let dummy = &chunks[0];
        assert!(
            dummy.data.is_none() || dummy.data.as_ref().is_some_and(|d| d.is_empty()),
            "first chunk must be OP_0 (empty push)"
        );

        // Chunks 1..=2: signatures.
        for i in 1..=2 {
            let sig = chunks[i].data.as_ref().expect("signature push expected");
            assert!(
                sig.len() >= 71 && sig.len() <= 73,
                "signature {} length {} out of range",
                i - 1,
                sig.len()
            );
            assert_eq!(*sig.last().unwrap(), 0x41);
        }

        // Chunk 3: redeem script bytes.
        let redeem = chunks[3].data.as_ref().expect("redeem push expected");
        assert_eq!(redeem, &ms_bytes);
    }

    #[test]
    fn p2mpkh_sign_1_of_1() {
        let (privs, pubs) = gen_keys(1);
        let ms = MultisigScript::new(1, pubs).unwrap();
        let ms_bytes = ms.to_serialized_bytes();
        let unlocker = unlock(vec![privs[0].clone()], ms, None).unwrap();

        let tx = mock_tx_with_source(5_000);
        let script = unlocker.sign(&tx, 0).unwrap();
        let chunks = script.chunks().unwrap();

        // OP_0 + 1 signature + redeem = 3 chunks.
        assert_eq!(chunks.len(), 3);
        let sig = chunks[1].data.as_ref().unwrap();
        assert!(sig.len() >= 71 && sig.len() <= 73);
        assert_eq!(*sig.last().unwrap(), 0x41);
        assert_eq!(chunks[2].data.as_ref().unwrap(), &ms_bytes);
    }

    #[test]
    fn p2mpkh_sign_missing_source_output_returns_error() {
        let (privs, pubs) = gen_keys(3);
        let ms = MultisigScript::new(2, pubs).unwrap();
        let unlocker = unlock(vec![privs[0].clone(), privs[1].clone()], ms, None).unwrap();

        // Input without source output.
        let mut tx = Transaction::new();
        tx.add_input(TransactionInput::new());
        tx.add_output(TransactionOutput::new());

        let result = unlocker.sign(&tx, 0);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("missing source output"),
            "error should mention missing source output"
        );
    }

    #[test]
    fn p2mpkh_sign_custom_sighash_flag() {
        use crate::sighash::{SIGHASH_FORKID, SIGHASH_NONE};
        let sighash_none_forkid = SIGHASH_NONE | SIGHASH_FORKID; // 0x42

        let (privs, pubs) = gen_keys(2);
        let ms = MultisigScript::new(1, pubs).unwrap();
        let unlocker = unlock(vec![privs[0].clone()], ms, Some(sighash_none_forkid)).unwrap();

        let tx = mock_tx_with_source(8_000);
        let script = unlocker.sign(&tx, 0).unwrap();
        let chunks = script.chunks().unwrap();

        // OP_0 + 1 sig + redeem = 3 chunks.
        assert_eq!(chunks.len(), 3);
        let sig = chunks[1].data.as_ref().unwrap();
        assert_eq!(*sig.last().unwrap(), sighash_none_forkid as u8);
    }

    #[test]
    fn p2mpkh_estimate_length_1_of_1() {
        let (privs, pubs) = gen_keys(1);
        let ms = MultisigScript::new(1, pubs).unwrap();
        let unlocker = unlock(vec![privs[0].clone()], ms, None).unwrap();
        let tx = Transaction::default();
        // 1 + 1*73 + 2 + (2 + 1*34) = 1 + 73 + 2 + 36 = 112
        assert_eq!(unlocker.estimate_length(&tx, 0), 112);
    }

    #[test]
    fn p2mpkh_estimate_length_3_of_5() {
        let (privs, pubs) = gen_keys(5);
        let ms = MultisigScript::new(3, pubs).unwrap();
        let unlocker = unlock(
            vec![privs[0].clone(), privs[1].clone(), privs[2].clone()],
            ms,
            None,
        )
        .unwrap();
        let tx = Transaction::default();
        // 1 + 3*73 + 2 + (2 + 5*34) = 1 + 219 + 2 + 172 = 394
        assert_eq!(unlocker.estimate_length(&tx, 0), 394);
    }
}
