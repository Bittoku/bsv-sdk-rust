//! Parsed opcode representation and script parser.

use super::error::{InterpreterError, InterpreterErrorCode};
use crate::opcodes::*;
use crate::Script;

/// A parsed opcode with its data payload.
#[derive(Debug, Clone)]
pub struct ParsedOpcode {
    /// The opcode byte value.
    pub opcode: u8,
    /// The data payload associated with push opcodes (empty for non-push opcodes).
    pub data: Vec<u8>,
}

impl ParsedOpcode {
    /// Return the human-readable name of this opcode.
    pub fn name(&self) -> &'static str {
        crate::opcodes::opcode_to_string(self.opcode)
    }

    /// Return true if this opcode is disabled (OP_2MUL, OP_2DIV).
    pub fn is_disabled(&self) -> bool {
        matches!(self.opcode, OP_2MUL | OP_2DIV)
    }

    /// Return true if this opcode is always illegal (OP_VERIF, OP_VERNOTIF).
    pub fn always_illegal(&self) -> bool {
        matches!(self.opcode, OP_VERIF | OP_VERNOTIF)
    }

    /// Return true if this opcode is a conditional flow control opcode.
    pub fn is_conditional(&self) -> bool {
        matches!(
            self.opcode,
            OP_IF | OP_NOTIF | OP_ELSE | OP_ENDIF | OP_VERIF | OP_VERNOTIF
        )
    }

    /// Return true if this opcode requires a transaction context to execute.
    pub fn requires_tx(&self) -> bool {
        matches!(
            self.opcode,
            OP_CHECKSIG
                | OP_CHECKSIGVERIFY
                | OP_CHECKMULTISIG
                | OP_CHECKMULTISIGVERIFY
                | OP_CHECKSEQUENCEVERIFY
        )
    }

    /// Check that push uses minimal encoding.
    pub fn enforce_minimum_data_push(&self) -> Result<(), InterpreterError> {
        let data_len = self.data.len();
        if data_len == 0 && self.opcode != OP_0 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::MinimalData,
                format!(
                    "zero length data push is encoded with opcode {} instead of OP_0",
                    self.name()
                ),
            ));
        }
        if data_len == 1
            && (1..=16).contains(&self.data[0])
            && self.opcode != OP_1 + self.data[0] - 1
        {
            return Err(InterpreterError::new(
                InterpreterErrorCode::MinimalData,
                format!(
                    "data push of the value {} encoded with opcode {} instead of OP_{}",
                    self.data[0],
                    self.name(),
                    self.data[0]
                ),
            ));
        }
        if data_len == 1 && self.data[0] == 0x81 && self.opcode != OP_1NEGATE {
            return Err(InterpreterError::new(
                InterpreterErrorCode::MinimalData,
                format!(
                    "data push of the value -1 encoded with opcode {} instead of OP_1NEGATE",
                    self.name()
                ),
            ));
        }
        if data_len <= 75 {
            if self.opcode as usize != data_len {
                return Err(InterpreterError::new(
                    InterpreterErrorCode::MinimalData,
                    format!(
                        "data push of {} bytes encoded with opcode {} instead of OP_DATA_{}",
                        data_len,
                        self.name(),
                        data_len
                    ),
                ));
            }
        } else if data_len <= 255 {
            if self.opcode != OP_PUSHDATA1 {
                return Err(InterpreterError::new(
                    InterpreterErrorCode::MinimalData,
                    format!(
                        "data push of {} bytes encoded with opcode {} instead of OP_PUSHDATA1",
                        data_len,
                        self.name()
                    ),
                ));
            }
        } else if data_len <= 65535 && self.opcode != OP_PUSHDATA2 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::MinimalData,
                format!(
                    "data push of {} bytes encoded with opcode {} instead of OP_PUSHDATA2",
                    data_len,
                    self.name()
                ),
            ));
        }
        Ok(())
    }

    /// Check if this is a canonical push (matches the smallest push opcode).
    pub fn canonical_push(&self) -> bool {
        let opcode = self.opcode;
        let data = &self.data;
        let data_len = data.len();
        if opcode > OP_16 {
            return true;
        }
        if opcode < OP_PUSHDATA1 && opcode > OP_0 && data_len == 1 && data[0] <= 16 {
            return false;
        }
        if opcode == OP_PUSHDATA1 && data_len < OP_PUSHDATA1 as usize {
            return false;
        }
        if opcode == OP_PUSHDATA2 && data_len <= 0xff {
            return false;
        }
        if opcode == OP_PUSHDATA4 && data_len <= 0xffff {
            return false;
        }
        true
    }

    /// Serialize back to script bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.opcode];
        if self.opcode == 0
            || (self.opcode >= OP_1NEGATE && self.opcode <= OP_16)
            || self.opcode > OP_PUSHDATA4
        {
            // No data for these opcodes (except OP_RETURN which has special handling)
            if self.opcode == OP_RETURN && !self.data.is_empty() {
                out.extend_from_slice(&self.data);
            }
            return out;
        }
        // Push data opcodes
        match self.opcode {
            OP_PUSHDATA1 => {
                out.push(self.data.len() as u8);
                out.extend_from_slice(&self.data);
            }
            OP_PUSHDATA2 => {
                out.extend_from_slice(&(self.data.len() as u16).to_le_bytes());
                out.extend_from_slice(&self.data);
            }
            OP_PUSHDATA4 => {
                out.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
                out.extend_from_slice(&self.data);
            }
            _ => {
                // OP_DATA_1..OP_DATA_75
                out.extend_from_slice(&self.data);
            }
        }
        out
    }
}

/// A parsed script is a sequence of parsed opcodes.
pub type ParsedScript = Vec<ParsedOpcode>;

/// Check if a parsed script is push-only.
pub fn is_push_only(script: &ParsedScript) -> bool {
    script.iter().all(|op| op.opcode <= OP_16)
}

/// Remove opcodes that push the given data.
pub fn remove_opcode_by_data(script: &ParsedScript, data: &[u8]) -> ParsedScript {
    script
        .iter()
        .filter(|pop| !pop.canonical_push() || !pop.data.windows(data.len()).any(|w| w == data))
        .cloned()
        .collect()
}

/// Remove all occurrences of a specific opcode.
pub fn remove_opcode(script: &ParsedScript, opcode: u8) -> ParsedScript {
    script
        .iter()
        .filter(|pop| pop.opcode != opcode)
        .cloned()
        .collect()
}

/// Unparse a ParsedScript back to a Script.
pub fn unparse(pscript: &ParsedScript) -> Script {
    let mut bytes = Vec::new();
    for pop in pscript {
        bytes.extend_from_slice(&pop.to_bytes());
    }
    Script::from_bytes(&bytes)
}

/// Parse a Script into a ParsedScript.
///
/// `error_on_checksig` - if true, returns error for checksig ops (when no tx available)
pub fn parse_script(
    script: &Script,
    error_on_checksig: bool,
) -> Result<ParsedScript, InterpreterError> {
    let scr = script.to_bytes();
    let mut parsed_ops = Vec::new();
    let mut conditional_depth = 0i32;
    let mut i = 0;

    while i < scr.len() {
        let instruction = scr[i];
        let mut parsed_op = ParsedOpcode {
            opcode: instruction,
            data: Vec::new(),
        };

        if error_on_checksig && parsed_op.requires_tx() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::InvalidParams,
                "tx and previous output must be supplied for checksig".to_string(),
            ));
        }

        // Track conditionals and check for OP_RETURN
        match instruction {
            OP_IF | OP_NOTIF | OP_VERIF | OP_VERNOTIF => conditional_depth += 1,
            OP_ENDIF => {
                if conditional_depth > 0 {
                    conditional_depth -= 1;
                }
            }
            OP_RETURN if conditional_depth == 0 => {
                // OP_RETURN outside conditionals: consume remaining data
                if i + 1 < scr.len() {
                    parsed_op.data = scr[i + 1..].to_vec();
                }
                parsed_ops.push(parsed_op);
                return Ok(parsed_ops);
            }
            _ => {}
        }

        // Extract data for this opcode
        match instruction {
            OP_PUSHDATA1 => {
                if i + 1 >= scr.len() {
                    return Err(InterpreterError::new(
                        InterpreterErrorCode::MalformedPush,
                        "script truncated".to_string(),
                    ));
                }
                let data_len = scr[i + 1] as usize;
                if i + 2 + data_len > scr.len() {
                    return Err(InterpreterError::new(
                        InterpreterErrorCode::MalformedPush,
                        "push data exceeds script length".to_string(),
                    ));
                }
                parsed_op.data = scr[i + 2..i + 2 + data_len].to_vec();
                i += 2 + data_len;
            }
            OP_PUSHDATA2 => {
                if i + 2 >= scr.len() {
                    return Err(InterpreterError::new(
                        InterpreterErrorCode::MalformedPush,
                        "script truncated".to_string(),
                    ));
                }
                let data_len = u16::from_le_bytes([scr[i + 1], scr[i + 2]]) as usize;
                if i + 3 + data_len > scr.len() {
                    return Err(InterpreterError::new(
                        InterpreterErrorCode::MalformedPush,
                        "push data exceeds script length".to_string(),
                    ));
                }
                parsed_op.data = scr[i + 3..i + 3 + data_len].to_vec();
                i += 3 + data_len;
            }
            OP_PUSHDATA4 => {
                if i + 4 >= scr.len() {
                    return Err(InterpreterError::new(
                        InterpreterErrorCode::MalformedPush,
                        "script truncated".to_string(),
                    ));
                }
                let data_len =
                    u32::from_le_bytes([scr[i + 1], scr[i + 2], scr[i + 3], scr[i + 4]]) as usize;
                if i + 5 + data_len > scr.len() {
                    return Err(InterpreterError::new(
                        InterpreterErrorCode::MalformedPush,
                        "push data exceeds script length".to_string(),
                    ));
                }
                parsed_op.data = scr[i + 5..i + 5 + data_len].to_vec();
                i += 5 + data_len;
            }
            op if op >= OP_DATA_1 && op <= OP_DATA_75 => {
                let data_len = op as usize;
                if i + 1 + data_len > scr.len() {
                    return Err(InterpreterError::new(
                        InterpreterErrorCode::MalformedPush,
                        "script truncated".to_string(),
                    ));
                }
                parsed_op.data = scr[i + 1..i + 1 + data_len].to_vec();
                i += 1 + data_len;
            }
            _ => {
                // Single-byte opcode
                i += 1;
            }
        }

        parsed_ops.push(parsed_op);
    }

    Ok(parsed_ops)
}
