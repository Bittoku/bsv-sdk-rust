/// Bitcoin Script type - a sequence of opcodes and data pushes.
///
/// Scripts are used in transaction inputs (unlocking) and outputs (locking)
/// to define spending conditions. The Script wraps a `Vec<u8>` and provides
/// methods for construction, classification, serialization, and ASM output.
use std::fmt;

use crate::chunk::{decode_script, push_data_prefix, ScriptChunk};
use crate::opcodes::*;
use crate::ScriptError;

/// A Bitcoin script, represented as a byte vector newtype.
#[derive(Clone, PartialEq, Eq)]
pub struct Script(Vec<u8>);

impl Script {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Create a new empty script.
    ///
    /// # Returns
    /// An empty `Script` instance.
    pub fn new() -> Self {
        Script(Vec::new())
    }

    /// Create a script from a hex-encoded string.
    ///
    /// # Arguments
    /// * `hex_str` - A hex string (e.g. "76a914...88ac").
    ///
    /// # Returns
    /// A `Script` wrapping the decoded bytes, or an error if the hex is invalid.
    pub fn from_hex(hex_str: &str) -> Result<Self, ScriptError> {
        let bytes = hex::decode(hex_str)?;
        Ok(Script(bytes))
    }

    /// Create a script from raw bytes.
    ///
    /// # Arguments
    /// * `bytes` - Raw script bytes.
    ///
    /// # Returns
    /// A `Script` wrapping a copy of the given bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Script(bytes.to_vec())
    }

    /// Create a script from a Bitcoin ASM string.
    ///
    /// Parses space-separated tokens where known opcodes (e.g. "OP_DUP") are
    /// emitted directly and hex strings are treated as push data.
    ///
    /// # Arguments
    /// * `asm` - A space-separated ASM string.
    ///
    /// # Returns
    /// A `Script`, or an error if any token is invalid.
    pub fn from_asm(asm: &str) -> Result<Self, ScriptError> {
        let mut script = Script::new();
        if asm.is_empty() {
            return Ok(script);
        }
        for section in asm.split(' ') {
            if let Some(opcode) = string_to_opcode(section) {
                script.append_opcodes(&[opcode])?;
            } else {
                script.append_push_data_hex(section)?;
            }
        }
        Ok(script)
    }

    // -----------------------------------------------------------------------
    // Serialization
    // -----------------------------------------------------------------------

    /// Encode the script as a hex string.
    ///
    /// # Returns
    /// A lowercase hex representation of the script bytes.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Convert the script to its ASM (human-readable assembly) representation.
    ///
    /// Each opcode or data push is represented as a space-separated token.
    /// Data pushes appear as their hex encoding; opcodes appear by name.
    ///
    /// # Returns
    /// A space-separated ASM string. Returns empty string for empty/invalid scripts.
    pub fn to_asm(&self) -> String {
        if self.0.is_empty() {
            return String::new();
        }
        let mut parts = Vec::new();
        let mut pos = 0;
        while pos < self.0.len() {
            match self.read_op(&mut pos) {
                Ok(chunk) => {
                    let s = chunk.to_asm_string();
                    if !s.is_empty() {
                        parts.push(s);
                    }
                }
                Err(_) => return String::new(),
            }
        }
        parts.join(" ")
    }

    /// Return a reference to the underlying bytes.
    ///
    /// # Returns
    /// A byte slice of the script contents.
    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Return the length of the script in bytes.
    ///
    /// # Returns
    /// The number of bytes in the script.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if the script is empty (zero bytes).
    ///
    /// # Returns
    /// `true` if the script has no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    // -----------------------------------------------------------------------
    // Script classification
    // -----------------------------------------------------------------------

    /// Check if this is a Pay-to-Public-Key-Hash (P2PKH) output script.
    ///
    /// Pattern: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    ///
    /// # Returns
    /// `true` if the script matches the P2PKH pattern.
    pub fn is_p2pkh(&self) -> bool {
        let b = &self.0;
        b.len() == 25
            && b[0] == OP_DUP
            && b[1] == OP_HASH160
            && b[2] == OP_DATA_20
            && b[23] == OP_EQUALVERIFY
            && b[24] == OP_CHECKSIG
    }

    /// Check if this is a Pay-to-Public-Key (P2PK) output script.
    ///
    /// Pattern: `<pubkey> OP_CHECKSIG` (pubkey is 33 or 65 bytes with valid prefix).
    ///
    /// # Returns
    /// `true` if the script matches the P2PK pattern.
    pub fn is_p2pk(&self) -> bool {
        let parts = match self.chunks() {
            Ok(p) => p,
            Err(_) => return false,
        };
        if parts.len() == 2 && parts[1].op == OP_CHECKSIG {
            if let Some(ref pubkey) = parts[0].data {
                if !pubkey.is_empty() {
                    let version = pubkey[0];
                    if (version == 0x04 || version == 0x06 || version == 0x07) && pubkey.len() == 65
                    {
                        return true;
                    } else if (version == 0x03 || version == 0x02) && pubkey.len() == 33 {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if this is a Pay-to-Script-Hash (P2SH) output script.
    ///
    /// Pattern: OP_HASH160 <20 bytes> OP_EQUAL
    ///
    /// # Returns
    /// `true` if the script matches the P2SH pattern.
    pub fn is_p2sh(&self) -> bool {
        let b = &self.0;
        b.len() == 23 && b[0] == OP_HASH160 && b[1] == OP_DATA_20 && b[22] == OP_EQUAL
    }

    /// Check if this is a data output script (OP_RETURN or OP_FALSE OP_RETURN).
    ///
    /// # Returns
    /// `true` if the script begins with OP_RETURN or OP_FALSE OP_RETURN.
    pub fn is_data(&self) -> bool {
        let b = &self.0;
        (!b.is_empty() && b[0] == OP_RETURN)
            || (b.len() > 1 && b[0] == OP_FALSE && b[1] == OP_RETURN)
    }

    /// Check if this is a multisig output script.
    ///
    /// Pattern: `OP_N <pubkey1> <pubkey2> ... OP_M OP_CHECKMULTISIG`
    ///
    /// # Returns
    /// `true` if the script matches the multisig output pattern.
    pub fn is_multisig_out(&self) -> bool {
        let parts = match self.chunks() {
            Ok(p) => p,
            Err(_) => return false,
        };
        if parts.len() < 3 {
            return false;
        }
        if !is_small_int_op(parts[0].op) {
            return false;
        }
        for chunk in &parts[1..parts.len() - 2] {
            match &chunk.data {
                Some(d) if !d.is_empty() => {}
                _ => return false,
            }
        }
        let second_last = &parts[parts.len() - 2];
        let last = &parts[parts.len() - 1];
        is_small_int_op(second_last.op) && last.op == OP_CHECKMULTISIG
    }

    // -----------------------------------------------------------------------
    // Data extraction
    // -----------------------------------------------------------------------

    /// Extract the public key hash from a P2PKH script.
    ///
    /// Returns the 20-byte hash160 if the script starts with OP_DUP OP_HASH160.
    ///
    /// # Returns
    /// The 20-byte public key hash, or an error if the script is not P2PKH.
    pub fn public_key_hash(&self) -> Result<Vec<u8>, ScriptError> {
        if self.0.is_empty() {
            return Err(ScriptError::EmptyScript);
        }
        if self.0.len() <= 2 || self.0[0] != OP_DUP || self.0[1] != OP_HASH160 {
            return Err(ScriptError::NotP2PKH);
        }
        let tail = &self.0[2..];
        let parts = decode_script(tail)?;
        match parts.first() {
            Some(chunk) => match &chunk.data {
                Some(data) => Ok(data.clone()),
                None => Err(ScriptError::NotP2PKH),
            },
            None => Err(ScriptError::NotP2PKH),
        }
    }

    /// Parse the script into a vector of decoded chunks.
    ///
    /// # Returns
    /// A vector of `ScriptChunk` values, or an error if the script is malformed.
    pub fn chunks(&self) -> Result<Vec<ScriptChunk>, ScriptError> {
        decode_script(&self.0)
    }

    // -----------------------------------------------------------------------
    // Mutation / building
    // -----------------------------------------------------------------------

    /// Append data bytes to the script with the proper PUSHDATA prefix.
    ///
    /// Chooses the minimal encoding: direct push for 1-75 bytes,
    /// OP_PUSHDATA1 for 76-255, OP_PUSHDATA2 for 256-65535, etc.
    ///
    /// # Arguments
    /// * `data` - The data bytes to push.
    ///
    /// # Returns
    /// `Ok(())` on success, or an error if the data is too large.
    pub fn append_push_data(&mut self, data: &[u8]) -> Result<(), ScriptError> {
        let prefix = push_data_prefix(data.len())?;
        self.0.extend_from_slice(&prefix);
        self.0.extend_from_slice(data);
        Ok(())
    }

    /// Append hex-encoded data to the script with proper PUSHDATA prefix.
    ///
    /// # Arguments
    /// * `hex_str` - Hex string to decode and push.
    ///
    /// # Returns
    /// `Ok(())` on success, or an error if the hex is invalid or data too large.
    pub fn append_push_data_hex(&mut self, hex_str: &str) -> Result<(), ScriptError> {
        let data = hex::decode(hex_str).map_err(|_| ScriptError::InvalidOpcodeData)?;
        self.append_push_data(&data)
    }

    /// Append raw opcodes to the script.
    ///
    /// Rejects push data opcodes (OP_DATA_1..OP_PUSHDATA4) to prevent misuse.
    /// Use `append_push_data` for those.
    ///
    /// # Arguments
    /// * `opcodes` - Slice of opcode bytes to append.
    ///
    /// # Returns
    /// `Ok(())` on success, or an error if a push data opcode is encountered.
    pub fn append_opcodes(&mut self, opcodes: &[u8]) -> Result<(), ScriptError> {
        for &op in opcodes {
            if op >= OP_DATA_1 && op <= OP_PUSHDATA4 {
                return Err(ScriptError::InvalidOpcodeType(
                    opcode_to_string(op).to_string(),
                ));
            }
        }
        self.0.extend_from_slice(opcodes);
        Ok(())
    }

    /// Check if this script is byte-equal to another script.
    ///
    /// # Arguments
    /// * `other` - The other script to compare with.
    ///
    /// # Returns
    /// `true` if both scripts have identical bytes.
    pub fn equals(&self, other: &Script) -> bool {
        self.0 == other.0
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Read a single script operation from the given position.
    ///
    /// Advances `pos` past the consumed bytes. Used internally by `to_asm`.
    ///
    /// # Arguments
    /// * `pos` - Mutable reference to the current read position.
    ///
    /// # Returns
    /// The parsed `ScriptChunk`, or an error if the data is truncated.
    fn read_op(&self, pos: &mut usize) -> Result<ScriptChunk, ScriptError> {
        let b = &self.0;
        if *pos >= b.len() {
            return Err(ScriptError::IndexOutOfRange);
        }
        let op = b[*pos];
        match op {
            OP_PUSHDATA1 => {
                if b.len() < *pos + 2 {
                    return Err(ScriptError::DataTooSmall);
                }
                let length = b[*pos + 1] as usize;
                *pos += 2;
                if b.len() < *pos + length {
                    return Err(ScriptError::DataTooSmall);
                }
                let data = b[*pos..*pos + length].to_vec();
                *pos += length;
                Ok(ScriptChunk {
                    op: OP_PUSHDATA1,
                    data: Some(data),
                })
            }
            OP_PUSHDATA2 => {
                if b.len() < *pos + 3 {
                    return Err(ScriptError::DataTooSmall);
                }
                let length = u16::from_le_bytes([b[*pos + 1], b[*pos + 2]]) as usize;
                *pos += 3;
                if b.len() < *pos + length {
                    return Err(ScriptError::DataTooSmall);
                }
                let data = b[*pos..*pos + length].to_vec();
                *pos += length;
                Ok(ScriptChunk {
                    op: OP_PUSHDATA2,
                    data: Some(data),
                })
            }
            OP_PUSHDATA4 => {
                if b.len() < *pos + 5 {
                    return Err(ScriptError::DataTooSmall);
                }
                let length =
                    u32::from_le_bytes([b[*pos + 1], b[*pos + 2], b[*pos + 3], b[*pos + 4]])
                        as usize;
                *pos += 5;
                if b.len() < *pos + length {
                    return Err(ScriptError::DataTooSmall);
                }
                let data = b[*pos..*pos + length].to_vec();
                *pos += length;
                Ok(ScriptChunk {
                    op: OP_PUSHDATA4,
                    data: Some(data),
                })
            }
            _ if op >= OP_DATA_1 && op < OP_PUSHDATA1 => {
                let length = op as usize;
                if b.len() < *pos + 1 + length {
                    return Err(ScriptError::DataTooSmall);
                }
                let data = b[*pos + 1..*pos + 1 + length].to_vec();
                *pos += 1 + length;
                Ok(ScriptChunk {
                    op,
                    data: Some(data),
                })
            }
            _ => {
                *pos += 1;
                Ok(ScriptChunk { op, data: None })
            }
        }
    }
}

impl Default for Script {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Script {
    /// Display the script as a lowercase hex string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for Script {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Script({})", self.to_hex())
    }
}

impl serde::Serialize for Script {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for Script {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Script::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    //! Tests for the Script type.
    //!
    //! Covers construction from hex/ASM, serialization roundtrips, script
    //! classification (P2PKH, P2PK, P2SH, data, multisig), public key hash
    //! extraction, push data operations, opcode appending, and equality checks.
    //! Test vectors are derived from the Go SDK reference implementation.

    use super::*;
    use crate::opcodes::*;

    // -----------------------------------------------------------------------
    // Construction & roundtrip tests
    // -----------------------------------------------------------------------

    /// Verify that from_hex correctly decodes a P2PKH script and to_hex
    /// produces the same lowercase hex string.
    #[test]
    fn test_from_hex_roundtrip() {
        let hex_str = "76a914e2a623699e81b291c0327f408fea765d534baa2a88ac";
        let script = Script::from_hex(hex_str).expect("valid hex should parse");
        assert_eq!(script.to_hex(), hex_str);
    }

    /// Verify that from_hex with an empty string produces an empty script.
    #[test]
    fn test_from_hex_empty() {
        let script = Script::from_hex("").expect("empty hex should parse");
        assert!(script.is_empty());
        assert_eq!(script.to_hex(), "");
    }

    /// Verify that from_hex rejects invalid hex characters.
    #[test]
    fn test_from_hex_invalid() {
        let result = Script::from_hex("ZZZZ");
        assert!(result.is_err());
    }

    /// Verify that to_asm produces the expected ASM string for a P2PKH script.
    #[test]
    fn test_to_asm_p2pkh() {
        let hex_str = "76a914e2a623699e81b291c0327f408fea765d534baa2a88ac";
        let script = Script::from_hex(hex_str).expect("valid hex should parse");
        let asm = script.to_asm();
        assert_eq!(
            asm,
            "OP_DUP OP_HASH160 e2a623699e81b291c0327f408fea765d534baa2a OP_EQUALVERIFY OP_CHECKSIG"
        );
    }

    /// Verify that an empty script produces an empty ASM string.
    #[test]
    fn test_to_asm_empty() {
        let script = Script::from_hex("").expect("empty hex should parse");
        assert_eq!(script.to_asm(), "");
    }

    /// Verify that from_asm correctly parses a P2PKH ASM string and produces
    /// the expected hex output.
    #[test]
    fn test_from_asm_p2pkh() {
        let asm =
            "OP_DUP OP_HASH160 e2a623699e81b291c0327f408fea765d534baa2a OP_EQUALVERIFY OP_CHECKSIG";
        let script = Script::from_asm(asm).expect("valid ASM should parse");
        assert_eq!(
            script.to_hex(),
            "76a914e2a623699e81b291c0327f408fea765d534baa2a88ac"
        );
    }

    /// Verify that from_asm with an empty string produces an empty script.
    #[test]
    fn test_from_asm_empty() {
        let script = Script::from_asm("").expect("empty ASM should parse");
        assert!(script.is_empty());
    }

    /// Verify that hex -> ASM -> hex roundtrip preserves the script.
    #[test]
    fn test_hex_asm_roundtrip() {
        let hex_str = "76a914e2a623699e81b291c0327f408fea765d534baa2a88ac";
        let script = Script::from_hex(hex_str).expect("valid hex should parse");
        let asm = script.to_asm();
        let script2 = Script::from_asm(&asm).expect("roundtrip ASM should parse");
        assert_eq!(script.to_hex(), script2.to_hex());
    }

    // -----------------------------------------------------------------------
    // Script classification tests
    // -----------------------------------------------------------------------

    /// Verify is_p2pkh returns true for a standard P2PKH script.
    #[test]
    fn test_is_p2pkh() {
        let script = Script::from_hex("76a91403ececf2d12a7f614aef4c82ecf13c303bd9975d88ac")
            .expect("valid hex");
        assert!(script.is_p2pkh());
    }

    /// Verify is_p2pkh returns false for a non-P2PKH script.
    #[test]
    fn test_is_p2pkh_false_for_p2sh() {
        let script =
            Script::from_hex("a9149de5aeaff9c48431ba4dd6e8af73d51f38e451cb87").expect("valid hex");
        assert!(!script.is_p2pkh());
    }

    /// Verify is_p2pk returns true for a compressed-key P2PK script.
    #[test]
    fn test_is_p2pk() {
        let script = Script::from_hex(
            "2102f0d97c290e79bf2a8660c406aa56b6f189ff79f2245cc5aff82808b58131b4d5ac",
        )
        .expect("valid hex");
        assert!(script.is_p2pk());
    }

    /// Verify is_p2pk returns false for a P2PKH script.
    #[test]
    fn test_is_p2pk_false_for_p2pkh() {
        let script = Script::from_hex("76a91403ececf2d12a7f614aef4c82ecf13c303bd9975d88ac")
            .expect("valid hex");
        assert!(!script.is_p2pk());
    }

    /// Verify is_p2sh returns true for a standard P2SH script.
    #[test]
    fn test_is_p2sh() {
        let script =
            Script::from_hex("a9149de5aeaff9c48431ba4dd6e8af73d51f38e451cb87").expect("valid hex");
        assert!(script.is_p2sh());
    }

    /// Verify is_p2sh returns false for a P2PKH script.
    #[test]
    fn test_is_p2sh_false_for_p2pkh() {
        let script = Script::from_hex("76a91403ececf2d12a7f614aef4c82ecf13c303bd9975d88ac")
            .expect("valid hex");
        assert!(!script.is_p2sh());
    }

    /// Verify is_data returns true for an OP_FALSE OP_RETURN data script.
    #[test]
    fn test_is_data_op_false_op_return() {
        // OP_FALSE OP_RETURN followed by data
        let script = Script::from_hex(
            "006a04ac1eed884d53027b2276657273696f6e223a22302e31222c22686569676874223a3634323436302c22707265764d696e65724964223a22303365393264336535633366376264393435646662663438653761393933393362316266623366313166333830616533306432383665376666326165633561323730227d"
        ).expect("valid hex");
        assert!(script.is_data());
    }

    /// Verify is_data returns true for a plain OP_RETURN script.
    #[test]
    fn test_is_data_op_return() {
        let script = Script::from_bytes(&[OP_RETURN, 0x04, 0x01, 0x02, 0x03, 0x04]);
        assert!(script.is_data());
    }

    /// Verify is_data returns false for a P2PKH script.
    #[test]
    fn test_is_data_false_for_p2pkh() {
        let script = Script::from_hex("76a91403ececf2d12a7f614aef4c82ecf13c303bd9975d88ac")
            .expect("valid hex");
        assert!(!script.is_data());
    }

    /// Verify is_multisig_out returns true for a valid multisig script.
    #[test]
    fn test_is_multisig_out() {
        // OP_2 <pubkey1> <pubkey2> <pubkey3> OP_3 OP_CHECKMULTISIG
        let script = Script::from_hex("5201110122013353ae").expect("valid hex");
        assert!(script.is_multisig_out());
    }

    /// Verify is_multisig_out returns false for a non-multisig script.
    #[test]
    fn test_is_multisig_out_false_for_p2pkh() {
        let script = Script::from_hex("76a91403ececf2d12a7f614aef4c82ecf13c303bd9975d88ac")
            .expect("valid hex");
        assert!(!script.is_multisig_out());
    }

    // -----------------------------------------------------------------------
    // Public key hash extraction
    // -----------------------------------------------------------------------

    /// Verify public_key_hash extracts the correct 20-byte hash from P2PKH.
    #[test]
    fn test_public_key_hash() {
        let script = Script::from_hex("76a91404d03f746652cfcb6cb55119ab473a045137d26588ac")
            .expect("valid hex");
        let pkh = script.public_key_hash().expect("should extract PKH");
        assert_eq!(
            hex::encode(&pkh),
            "04d03f746652cfcb6cb55119ab473a045137d265"
        );
    }

    /// Verify public_key_hash from bytes matches the hex-constructed version.
    #[test]
    fn test_public_key_hash_from_bytes() {
        let bytes =
            hex::decode("76a91404d03f746652cfcb6cb55119ab473a045137d26588ac").expect("valid hex");
        let script = Script::from_bytes(&bytes);
        let pkh = script.public_key_hash().expect("should extract PKH");
        assert_eq!(
            hex::encode(&pkh),
            "04d03f746652cfcb6cb55119ab473a045137d265"
        );
    }

    /// Verify public_key_hash returns an error for an empty script.
    #[test]
    fn test_public_key_hash_empty() {
        let script = Script::new();
        let result = script.public_key_hash();
        assert!(result.is_err());
    }

    /// Verify public_key_hash returns an error for a non-P2PKH script (OP_DUP alone).
    #[test]
    fn test_public_key_hash_nonstandard() {
        let script = Script::from_hex("76").expect("valid hex");
        let result = script.public_key_hash();
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Append operations
    // -----------------------------------------------------------------------

    /// Verify append_push_data correctly pushes small data (<=75 bytes).
    #[test]
    fn test_append_push_data_small() {
        let mut script = Script::new();
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        script.append_push_data(&data).expect("push should succeed");
        // 5-byte push: prefix is 0x05 (length), then the 5 data bytes
        assert_eq!(script.to_hex(), "050102030405");
    }

    /// Verify append_push_data uses OP_PUSHDATA1 for data in 76..=255 range.
    #[test]
    fn test_append_push_data_medium() {
        let mut script = Script::new();
        let data = vec![0xAA; 80]; // 80 bytes triggers OP_PUSHDATA1
        script.append_push_data(&data).expect("push should succeed");
        let hex_str = script.to_hex();
        // OP_PUSHDATA1 = 0x4c, then 0x50 (80), then 80 bytes of 0xAA
        assert_eq!(&hex_str[..4], "4c50");
        assert_eq!(hex_str.len(), 4 + 80 * 2);
    }

    /// Verify append_push_data uses OP_PUSHDATA2 for data in 256..=65535 range.
    #[test]
    fn test_append_push_data_large() {
        let mut script = Script::new();
        let data = vec![0xBB; 256]; // 256 bytes triggers OP_PUSHDATA2
        script.append_push_data(&data).expect("push should succeed");
        let hex_str = script.to_hex();
        // OP_PUSHDATA2 = 0x4d, then 0x0001 (256 LE), then 256 bytes of 0xBB
        assert_eq!(&hex_str[..6], "4d0001");
        assert_eq!(hex_str.len(), 6 + 256 * 2);
    }

    /// Verify append_opcodes appends a single valid opcode.
    #[test]
    fn test_append_opcodes_single() {
        let mut script = Script::from_asm("OP_2 OP_2 OP_ADD").expect("valid ASM");
        script
            .append_opcodes(&[OP_EQUALVERIFY])
            .expect("should succeed");
        assert_eq!(script.to_asm(), "OP_2 OP_2 OP_ADD OP_EQUALVERIFY");
    }

    /// Verify append_opcodes appends multiple valid opcodes.
    #[test]
    fn test_append_opcodes_multiple() {
        let mut script = Script::from_asm("OP_2 OP_2 OP_ADD").expect("valid ASM");
        script
            .append_opcodes(&[OP_EQUAL, OP_VERIFY])
            .expect("should succeed");
        assert_eq!(script.to_asm(), "OP_2 OP_2 OP_ADD OP_EQUAL OP_VERIFY");
    }

    /// Verify append_opcodes rejects push data opcodes (OP_PUSHDATA1 etc.).
    #[test]
    fn test_append_opcodes_rejects_pushdata() {
        let mut script = Script::from_asm("OP_2 OP_2 OP_ADD").expect("valid ASM");
        let result = script.append_opcodes(&[OP_EQUAL, OP_PUSHDATA1]);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Equality
    // -----------------------------------------------------------------------

    /// Verify two scripts built from the same hex are equal.
    #[test]
    fn test_equals_same_hex() {
        let s1 = Script::from_hex("76a91404d03f746652cfcb6cb55119ab473a045137d26588ac")
            .expect("valid hex");
        let s2 = Script::from_hex("76a91404d03f746652cfcb6cb55119ab473a045137d26588ac")
            .expect("valid hex");
        assert!(s1.equals(&s2));
        assert_eq!(s1, s2);
    }

    /// Verify two scripts built from the same bytes are equal.
    #[test]
    fn test_equals_same_bytes() {
        let bytes = hex::decode("5201110122013353ae").expect("valid hex");
        let s1 = Script::from_bytes(&bytes);
        let s2 = Script::from_bytes(&bytes);
        assert!(s1.equals(&s2));
    }

    /// Verify two scripts with different bytes are not equal.
    #[test]
    fn test_not_equals_different_hex() {
        let s1 = Script::from_hex("76a91404d03f746652cfcb6cb55119ab473a045137d26566ac")
            .expect("valid hex");
        let s2 = Script::from_hex("76a91404d03f746652cfcb6cb55119ab473a045137d26588ac")
            .expect("valid hex");
        assert!(!s1.equals(&s2));
        assert_ne!(s1, s2);
    }

    // -----------------------------------------------------------------------
    // Serialization (JSON)
    // -----------------------------------------------------------------------

    /// Verify Script serializes to a hex JSON string.
    #[test]
    fn test_serde_serialize() {
        let script = Script::from_asm("OP_2 OP_2 OP_ADD OP_4 OP_EQUALVERIFY").expect("valid ASM");
        let json_str = serde_json::to_string(&script).expect("should serialize");
        assert_eq!(json_str, r#""5252935488""#);
    }

    /// Verify Script deserializes from a hex JSON string.
    #[test]
    fn test_serde_deserialize() {
        let json_str = r#""5252935488""#;
        let script: Script = serde_json::from_str(json_str).expect("should deserialize");
        assert_eq!(script.to_hex(), "5252935488");
    }

    /// Verify Script deserializes from an empty hex JSON string.
    #[test]
    fn test_serde_deserialize_empty() {
        let json_str = r#""""#;
        let script: Script = serde_json::from_str(json_str).expect("should deserialize");
        assert_eq!(script.to_hex(), "");
    }

    // -----------------------------------------------------------------------
    // Display / Debug
    // -----------------------------------------------------------------------

    /// Verify Display trait outputs the hex string.
    #[test]
    fn test_display() {
        let script = Script::from_hex("76a914e2a623699e81b291c0327f408fea765d534baa2a88ac")
            .expect("valid hex");
        assert_eq!(
            format!("{}", script),
            "76a914e2a623699e81b291c0327f408fea765d534baa2a88ac"
        );
    }

    /// Verify Debug trait outputs the Script(...) format.
    #[test]
    fn test_debug() {
        let script = Script::from_hex("76a914e2a623699e81b291c0327f408fea765d534baa2a88ac")
            .expect("valid hex");
        let debug_str = format!("{:?}", script);
        assert!(debug_str.starts_with("Script("));
        assert!(debug_str.contains("76a914"));
    }

    // -----------------------------------------------------------------------
    // OP_RETURN / data script ASM roundtrip
    // -----------------------------------------------------------------------

    /// Verify OP_FALSE OP_RETURN data scripts produce correct ASM and roundtrip.
    #[test]
    fn test_op_false_op_return_asm() {
        let hex_str = "006a223139694733575459537362796f7333754a373333794b347a45696f69314665734e55010042666166383166326364346433663239383061623162363564616166656231656631333561626339643534386461633466366134656361623230653033656365362d300274780134";
        let script = Script::from_hex(hex_str).expect("valid hex");
        let asm = script.to_asm();
        // The ASM should start with OP_FALSE OP_RETURN
        assert!(asm.starts_with("OP_FALSE OP_RETURN"));
    }

    // -----------------------------------------------------------------------
    // Misc edge cases
    // -----------------------------------------------------------------------

    /// Verify from_bytes and len work as expected.
    #[test]
    fn test_from_bytes_len() {
        let bytes =
            hex::decode("76a91403ececf2d12a7f614aef4c82ecf13c303bd9975d88ac").expect("valid hex");
        let script = Script::from_bytes(&bytes);
        assert_eq!(script.len(), 25);
        assert!(!script.is_empty());
    }

    /// Verify Default produces an empty script.
    #[test]
    fn test_default() {
        let script = Script::default();
        assert!(script.is_empty());
        assert_eq!(script.len(), 0);
    }
}
