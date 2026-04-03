//! Token script type classification.

use std::fmt;

/// Classification of script types relevant to token operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScriptType {
    /// Standard Pay-to-Public-Key-Hash script.
    P2pkh,
    /// STAS token script.
    Stas,
    /// STAS-BTG (Back-to-Genesis) token script with on-chain prev-TX verification.
    StasBtg,
    /// STAS 3.0 (data STAS) token script.
    Dstas,
    /// OP_RETURN data carrier script.
    OpReturn,
    /// Unknown or unrecognized script type.
    Unknown,
}

impl fmt::Display for ScriptType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScriptType::P2pkh => write!(f, "P2PKH"),
            ScriptType::Stas => write!(f, "STAS"),
            ScriptType::StasBtg => write!(f, "STAS-BTG"),
            ScriptType::Dstas => write!(f, "STAS 3.0"),
            ScriptType::OpReturn => write!(f, "OP_RETURN"),
            ScriptType::Unknown => write!(f, "Unknown"),
        }
    }
}
