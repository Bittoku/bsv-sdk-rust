//! Crypto operations for the script interpreter.

use num_bigint::BigInt;

use crate::opcodes::OP_CODESEPARATOR;
use super::error::{InterpreterError, InterpreterErrorCode};
use super::flags::ScriptFlags;
use super::parsed_opcode::*;
use super::thread::Thread;

pub(crate) enum HashType {
    Ripemd160,
    Sha1,
    Sha256,
    Hash160,
    Hash256,
}

impl<'a> Thread<'a> {
    pub(crate) fn op_hash(&mut self, hash_type: HashType) -> Result<(), InterpreterError> {
        let buf = self.dstack.pop_byte_array()?;
        let result = match hash_type {
            HashType::Ripemd160 => {
                use ripemd::Ripemd160;
                use sha2::Digest;
                let mut hasher = Ripemd160::new();
                hasher.update(&buf);
                hasher.finalize().to_vec()
            }
            HashType::Sha1 => {
                use sha1::Sha1;
                use sha1::Digest;
                let mut hasher = Sha1::new();
                hasher.update(&buf);
                hasher.finalize().to_vec()
            }
            HashType::Sha256 => {
                use sha2::{Sha256, Digest};
                let mut hasher = Sha256::new();
                hasher.update(&buf);
                hasher.finalize().to_vec()
            }
            HashType::Hash160 => {
                use sha2::{Sha256, Digest as Digest2};
                use ripemd::{Ripemd160, Digest};
                let sha = Sha256::digest(&buf);
                let mut ripe = Ripemd160::new();
                ripe.update(&sha);
                ripe.finalize().to_vec()
            }
            HashType::Hash256 => {
                use sha2::{Sha256, Digest};
                let first = Sha256::digest(&buf);
                let second = Sha256::digest(&first);
                second.to_vec()
            }
        };
        self.dstack.push_byte_array(result);
        Ok(())
    }

    pub(crate) fn sub_script(&self) -> ParsedScript {
        let skip = if self.last_code_sep > 0 {
            self.last_code_sep + 1
        } else {
            0
        };
        self.scripts[self.script_idx][skip..].to_vec()
    }

    pub(crate) fn op_checksig(&mut self) -> Result<(), InterpreterError> {
        let pk_bytes = self.dstack.pop_byte_array()?;
        let full_sig_bytes = self.dstack.pop_byte_array()?;

        if full_sig_bytes.is_empty() {
            self.dstack.push_bool(false);
            return Ok(());
        }

        let ctx = self.tx_context.ok_or_else(|| {
            InterpreterError::new(
                InterpreterErrorCode::InvalidParams,
                "no tx context for checksig".to_string(),
            )
        })?;

        let shf = *full_sig_bytes.last().ok_or_else(|| {
            InterpreterError::new(
                InterpreterErrorCode::InvalidParams,
                "empty signature in checksig".to_string(),
            )
        })? as u32;
        let sig_bytes = &full_sig_bytes[..full_sig_bytes.len() - 1];

        // Check encodings
        self.check_hash_type_encoding(shf)?;
        self.check_signature_encoding(sig_bytes)?;
        self.check_pub_key_encoding(&pk_bytes)?;

        // Get subscript
        let mut sub_script = self.sub_script();

        // Remove signature from subscript for non-forkid
        let has_forkid = self.has_flag(ScriptFlags::ENABLE_SIGHASH_FORKID)
            && (shf & 0x40) != 0; // SIGHASH_FORKID = 0x40
        if !has_forkid {
            sub_script = remove_opcode_by_data(&sub_script, &full_sig_bytes);
            sub_script = remove_opcode(&sub_script, OP_CODESEPARATOR);
        }

        let script_bytes = unparse(&sub_script);

        match ctx.verify_signature(&full_sig_bytes, &pk_bytes, &script_bytes, self.input_idx, shf) {
            Ok(valid) => {
                if !valid
                    && self.has_flag(ScriptFlags::VERIFY_NULL_FAIL)
                    && !sig_bytes.is_empty()
                {
                    return Err(InterpreterError::new(
                        InterpreterErrorCode::NullFail,
                        "signature not empty on failed checksig".to_string(),
                    ));
                }
                self.dstack.push_bool(valid);
                Ok(())
            }
            Err(_) => {
                self.dstack.push_bool(false);
                Ok(())
            }
        }
    }

    pub(crate) fn op_checksigverify(&mut self, pop: &ParsedOpcode) -> Result<(), InterpreterError> {
        self.op_checksig()?;
        self.abstract_verify(pop, InterpreterErrorCode::CheckSigVerify)
    }

    pub(crate) fn op_checkmultisig(&mut self) -> Result<(), InterpreterError> {
        let num_keys = self.dstack.pop_int()?;
        let num_pub_keys = num_keys.to_int() as i32;

        if num_pub_keys < 0 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::InvalidPubKeyCount,
                format!("number of pubkeys {} is negative", num_pub_keys),
            ));
        }
        if num_pub_keys as usize > self.cfg.max_pub_keys_per_multisig() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::InvalidPubKeyCount,
                format!(
                    "too many pubkeys: {} > {}",
                    num_pub_keys,
                    self.cfg.max_pub_keys_per_multisig()
                ),
            ));
        }

        self.num_ops += num_pub_keys as usize;
        if self.num_ops > self.cfg.max_ops() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::TooManyOperations,
                format!("exceeded max operation limit of {}", self.cfg.max_ops()),
            ));
        }

        let mut pub_keys = Vec::new();
        for _ in 0..num_pub_keys {
            pub_keys.push(self.dstack.pop_byte_array()?);
        }

        let num_sigs = self.dstack.pop_int()?;
        let num_signatures = num_sigs.to_int() as i32;

        if num_signatures < 0 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::InvalidSignatureCount,
                format!("number of signatures {} is negative", num_signatures),
            ));
        }
        if num_signatures > num_pub_keys {
            return Err(InterpreterError::new(
                InterpreterErrorCode::InvalidSignatureCount,
                format!(
                    "more signatures than pubkeys: {} > {}",
                    num_signatures, num_pub_keys
                ),
            ));
        }

        let mut signatures: Vec<Vec<u8>> = Vec::new();
        for _ in 0..num_signatures {
            signatures.push(self.dstack.pop_byte_array()?);
        }

        // Dummy element (Satoshi bug)
        let dummy = self.dstack.pop_byte_array()?;
        if self.has_flag(ScriptFlags::STRICT_MULTI_SIG) && !dummy.is_empty() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigNullDummy,
                format!(
                    "multisig dummy argument has length {} instead of 0",
                    dummy.len()
                ),
            ));
        }

        // Get subscript
        let mut scr = self.sub_script();
        for sig in &signatures {
            scr = remove_opcode_by_data(&scr, sig);
            scr = remove_opcode(&scr, OP_CODESEPARATOR);
        }

        let ctx = match self.tx_context {
            Some(c) => c,
            None => {
                self.dstack.push_bool(false);
                return Ok(());
            }
        };

        let script_bytes = unparse(&scr);
        let mut success = true;
        let mut remaining_keys = num_pub_keys + 1;
        let mut pub_key_idx: i32 = -1;
        let mut sig_idx: usize = 0;
        let mut remaining_sigs = num_signatures;

        while remaining_sigs > 0 {
            pub_key_idx += 1;
            remaining_keys -= 1;

            if remaining_sigs > remaining_keys {
                success = false;
                break;
            }

            let sig = &signatures[sig_idx];
            let pub_key = &pub_keys[pub_key_idx as usize];

            if sig.is_empty() {
                continue;
            }

            let shf = *sig.last().ok_or_else(|| {
                InterpreterError::new(
                    InterpreterErrorCode::InvalidParams,
                    "empty signature in checkmultisig".to_string(),
                )
            })? as u32;
            let sig_only = &sig[..sig.len() - 1];

            // Check encodings
            if let Err(e) = self.check_hash_type_encoding(shf) {
                return Err(e);
            }
            if let Err(e) = self.check_signature_encoding(sig_only) {
                return Err(e);
            }
            if let Err(e) = self.check_pub_key_encoding(pub_key) {
                return Err(e);
            }

            match ctx.verify_signature(sig, pub_key, &script_bytes, self.input_idx, shf) {
                Ok(true) => {
                    sig_idx += 1;
                    remaining_sigs -= 1;
                }
                _ => {}
            }
        }

        if !success && self.has_flag(ScriptFlags::VERIFY_NULL_FAIL) {
            for sig in &signatures {
                if !sig.is_empty() {
                    return Err(InterpreterError::new(
                        InterpreterErrorCode::NullFail,
                        "not all signatures empty on failed checkmultisig".to_string(),
                    ));
                }
            }
        }

        self.dstack.push_bool(success);
        Ok(())
    }

    pub(crate) fn op_checkmultisigverify(&mut self, pop: &ParsedOpcode) -> Result<(), InterpreterError> {
        self.op_checkmultisig()?;
        self.abstract_verify(pop, InterpreterErrorCode::CheckMultiSigVerify)
    }

    pub(crate) fn check_hash_type_encoding(&self, shf: u32) -> Result<(), InterpreterError> {
        if !self.has_flag(ScriptFlags::VERIFY_STRICT_ENCODING) {
            return Ok(());
        }

        let sighash_forkid: u32 = 0x40;
        let sighash_anyonecanpay: u32 = 0x80;

        let mut sig_hash_type = shf & !sighash_anyonecanpay;

        if self.has_flag(ScriptFlags::VERIFY_BIP143_SIGHASH) {
            sig_hash_type ^= sighash_forkid;
            if shf & sighash_forkid == 0 {
                return Err(InterpreterError::new(
                    InterpreterErrorCode::InvalidSigHashType,
                    format!("hash type does not contain uahf forkID 0x{:x}", shf),
                ));
            }
        }

        if sig_hash_type & sighash_forkid == 0 {
            // Non-forkid
            if sig_hash_type < 1 || sig_hash_type > 3 {
                return Err(InterpreterError::new(
                    InterpreterErrorCode::InvalidSigHashType,
                    format!("invalid hash type 0x{:x}", shf),
                ));
            }
            return Ok(());
        }

        // Has forkid
        let base = sig_hash_type & !sighash_forkid;
        if base < 1 || base > 3 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::InvalidSigHashType,
                format!("invalid hash type 0x{:x}", shf),
            ));
        }

        if !self.has_flag(ScriptFlags::ENABLE_SIGHASH_FORKID) && (shf & sighash_forkid != 0) {
            return Err(InterpreterError::new(
                InterpreterErrorCode::IllegalForkID,
                "fork id sighash set without flag".to_string(),
            ));
        }
        if self.has_flag(ScriptFlags::ENABLE_SIGHASH_FORKID) && (shf & sighash_forkid == 0) {
            return Err(InterpreterError::new(
                InterpreterErrorCode::IllegalForkID,
                "fork id sighash not set with flag".to_string(),
            ));
        }

        Ok(())
    }

    pub(crate) fn check_pub_key_encoding(&self, pub_key: &[u8]) -> Result<(), InterpreterError> {
        if !self.has_flag(ScriptFlags::VERIFY_STRICT_ENCODING) {
            return Ok(());
        }
        if pub_key.len() == 33 && (pub_key[0] == 0x02 || pub_key[0] == 0x03) {
            return Ok(());
        }
        if pub_key.len() == 65 && pub_key[0] == 0x04 {
            return Ok(());
        }
        Err(InterpreterError::new(
            InterpreterErrorCode::PubKeyType,
            "unsupported public key type".to_string(),
        ))
    }

    pub(crate) fn check_signature_encoding(&self, sig: &[u8]) -> Result<(), InterpreterError> {
        if !self.has_any(&[
            ScriptFlags::VERIFY_DER_SIGNATURES,
            ScriptFlags::VERIFY_LOW_S,
            ScriptFlags::VERIFY_STRICT_ENCODING,
        ]) {
            return Ok(());
        }

        if sig.is_empty() {
            return Ok(());
        }

        // DER format checks
        let sig_len = sig.len();
        if sig_len < 8 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigTooShort,
                format!("malformed signature: too short: {} < 8", sig_len),
            ));
        }
        if sig_len > 72 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigTooLong,
                format!("malformed signature: too long: {} > 72", sig_len),
            ));
        }
        if sig[0] != 0x30 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigInvalidSeqID,
                format!("malformed signature: format has wrong type: {:#x}", sig[0]),
            ));
        }
        if sig[1] as usize != sig_len - 2 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigInvalidDataLen,
                format!(
                    "malformed signature: bad length: {} != {}",
                    sig[1],
                    sig_len - 2
                ),
            ));
        }

        let r_len = sig[3] as usize;
        let s_type_offset = 4 + r_len;
        let s_len_offset = s_type_offset + 1;

        if s_type_offset >= sig_len {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigMissingSTypeID,
                "malformed signature: S type indicator missing".to_string(),
            ));
        }
        if s_len_offset >= sig_len {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigMissingSLen,
                "malformed signature: S length missing".to_string(),
            ));
        }

        let s_offset = s_len_offset + 1;
        let s_len = sig[s_len_offset] as usize;
        if s_offset + s_len != sig_len {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigInvalidSLen,
                "malformed signature: invalid S length".to_string(),
            ));
        }

        if sig[2] != 0x02 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigInvalidRIntID,
                format!(
                    "malformed signature: R integer marker: {:#x} != 0x02",
                    sig[2]
                ),
            ));
        }
        if r_len == 0 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigZeroRLen,
                "malformed signature: R length is zero".to_string(),
            ));
        }
        if sig[4] & 0x80 != 0 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigNegativeR,
                "malformed signature: R is negative".to_string(),
            ));
        }
        if r_len > 1 && sig[4] == 0x00 && sig[5] & 0x80 == 0 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigTooMuchRPadding,
                "malformed signature: R value has too much padding".to_string(),
            ));
        }

        if sig[s_type_offset] != 0x02 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigInvalidSIntID,
                format!(
                    "malformed signature: S integer marker: {:#x} != 0x02",
                    sig[s_type_offset]
                ),
            ));
        }
        if s_len == 0 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigZeroSLen,
                "malformed signature: S length is zero".to_string(),
            ));
        }
        if sig[s_offset] & 0x80 != 0 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigNegativeS,
                "malformed signature: S is negative".to_string(),
            ));
        }
        if s_len > 1 && sig[s_offset] == 0x00 && sig[s_offset + 1] & 0x80 == 0 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigTooMuchSPadding,
                "malformed signature: S value has too much padding".to_string(),
            ));
        }

        // Low-S check
        if self.has_flag(ScriptFlags::VERIFY_LOW_S) {
            // Half order of secp256k1 (computed once)
            use std::sync::LazyLock;
            static HALF_ORDER: LazyLock<BigInt> = LazyLock::new(|| {
                BigInt::parse_bytes(
                    b"7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0",
                    16,
                )
                .expect("valid hex constant")
            });
            let half_order = &*HALF_ORDER;
            let s_value = BigInt::from_bytes_be(
                num_bigint::Sign::Plus,
                &sig[s_offset..s_offset + s_len],
            );
            if s_value > *half_order {
                return Err(InterpreterError::new(
                    InterpreterErrorCode::SigHighS,
                    "signature is not canonical due to unnecessarily high S value".to_string(),
                ));
            }
        }

        Ok(())
    }
}
