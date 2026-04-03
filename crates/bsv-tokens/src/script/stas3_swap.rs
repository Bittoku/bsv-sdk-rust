//! STAS3 swap utilities: script hash computation and swap mode detection.

use bsv_primitives::hash::sha256;

use crate::error::TokenError;
use crate::script::reader::read_locking_script;
use crate::types::{ActionData, Stas3SwapMode};
use crate::ScriptType;

/// Compute the SHA-256 hash of a STAS3 locking script's "tail".
///
/// The tail is everything after the owner pushdata and the action data
/// pushdata — i.e. the base template + OP_RETURN data section. This hash
/// is used in swap action data so the counterparty can verify that the
/// offered token has the expected script structure.
///
/// # Layout
/// ```text
/// [OP_DATA_20 + 20 bytes owner] [action_data push] [tail ...]
/// ```
///
/// Returns the 32-byte SHA-256 hash of the tail bytes.
pub fn compute_stas3_requested_script_hash(locking_script: &[u8]) -> Result<[u8; 32], TokenError> {
    if locking_script.is_empty() || locking_script[0] != 0x14 {
        return Err(TokenError::InvalidScript(
            "not a STAS3 locking script (expected OP_DATA_20 prefix)".into(),
        ));
    }

    // Skip owner field: OP_DATA_20 (1 byte) + 20 bytes
    let after_owner = 21;
    if after_owner >= locking_script.len() {
        return Err(TokenError::InvalidScript(
            "locking script too short after owner field".into(),
        ));
    }

    // Skip action data push
    let tail_start = skip_push_data(locking_script, after_owner)?;

    let tail = &locking_script[tail_start..];
    Ok(sha256(tail))
}

/// Skip a single push data item at the given offset, returning the offset
/// after the pushed data.
fn skip_push_data(script: &[u8], offset: usize) -> Result<usize, TokenError> {
    if offset >= script.len() {
        return Err(TokenError::InvalidScript(
            "unexpected end of script in push data".into(),
        ));
    }

    let opcode = script[offset];
    match opcode {
        // OP_0 — no data bytes
        0x00 => Ok(offset + 1),
        // OP_2 (frozen marker) — no data bytes
        0x52 => Ok(offset + 1),
        // Direct push: 1–75 bytes
        0x01..=0x4b => {
            let len = opcode as usize;
            let end = offset + 1 + len;
            if end > script.len() {
                return Err(TokenError::InvalidScript(
                    "push data extends past script end".into(),
                ));
            }
            Ok(end)
        }
        // OP_PUSHDATA1
        0x4c => {
            if offset + 1 >= script.len() {
                return Err(TokenError::InvalidScript("truncated OP_PUSHDATA1".into()));
            }
            let len = script[offset + 1] as usize;
            let end = offset + 2 + len;
            if end > script.len() {
                return Err(TokenError::InvalidScript(
                    "OP_PUSHDATA1 data extends past script end".into(),
                ));
            }
            Ok(end)
        }
        // OP_PUSHDATA2
        0x4d => {
            if offset + 2 >= script.len() {
                return Err(TokenError::InvalidScript("truncated OP_PUSHDATA2".into()));
            }
            let len =
                u16::from_le_bytes([script[offset + 1], script[offset + 2]]) as usize;
            let end = offset + 3 + len;
            if end > script.len() {
                return Err(TokenError::InvalidScript(
                    "OP_PUSHDATA2 data extends past script end".into(),
                ));
            }
            Ok(end)
        }
        _ => Ok(offset + 1),
    }
}

/// Detect swap mode by inspecting the locking scripts of both inputs.
///
/// Reads each input's locking script via the STAS3 reader. If both inputs
/// have swap action data (kind == 0x01 / `ActionData::Swap`), returns
/// `SwapSwap`. Otherwise returns `TransferSwap`.
pub fn resolve_stas3_swap_mode(
    locking_script_a: &[u8],
    locking_script_b: &[u8],
) -> Stas3SwapMode {
    let has_swap_a = extract_stas3_swap_flag(locking_script_a);
    let has_swap_b = extract_stas3_swap_flag(locking_script_b);

    if has_swap_a && has_swap_b {
        Stas3SwapMode::SwapSwap
    } else {
        Stas3SwapMode::TransferSwap
    }
}

/// Check whether a STAS3 locking script contains swap action data.
fn extract_stas3_swap_flag(script: &[u8]) -> bool {
    let parsed = read_locking_script(script);
    if parsed.script_type != ScriptType::Stas3 {
        return false;
    }
    matches!(
        parsed.stas3.as_ref().and_then(|d| d.action_data_parsed.as_ref()),
        Some(ActionData::Swap { .. })
    )
}

/// Check whether a STAS3 locking script indicates a frozen token.
///
/// Returns `true` if the script parses as STAS3 and the frozen flag is set.
pub fn is_stas3_frozen(script: &[u8]) -> bool {
    let parsed = read_locking_script(script);
    if parsed.script_type != ScriptType::Stas3 {
        return false;
    }
    parsed.stas3.map_or(false, |d| d.frozen)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::stas3_builder::build_stas3_locking_script;
    use crate::types::ActionData;

    fn make_swap_action_data() -> ActionData {
        ActionData::Swap {
            requested_script_hash: [0xab; 32],
            requested_pkh: [0xcd; 20],
            rate_numerator: 1,
            rate_denominator: 1,
        }
    }

    #[test]
    fn script_hash_roundtrip() {
        let owner = [0x11; 20];
        let redemption = [0x22; 20];

        let script_a = build_stas3_locking_script(
            &owner, &redemption, None, false, true, &[], &[],
        )
        .unwrap();
        let script_b = build_stas3_locking_script(
            &[0x33; 20], &redemption, None, false, true, &[], &[],
        )
        .unwrap();

        let hash_a = compute_stas3_requested_script_hash(script_a.to_bytes()).unwrap();
        let hash_b = compute_stas3_requested_script_hash(script_b.to_bytes()).unwrap();

        // Same tail (same redemption, flags, template) → same hash
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn script_hash_differs_for_different_redemption() {
        let owner = [0x11; 20];

        let script_a = build_stas3_locking_script(
            &owner, &[0x22; 20], None, false, true, &[], &[],
        )
        .unwrap();
        let script_b = build_stas3_locking_script(
            &owner, &[0x33; 20], None, false, true, &[], &[],
        )
        .unwrap();

        let hash_a = compute_stas3_requested_script_hash(script_a.to_bytes()).unwrap();
        let hash_b = compute_stas3_requested_script_hash(script_b.to_bytes()).unwrap();

        assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn swap_mode_both_swap_inputs() {
        let owner_a = [0x11; 20];
        let owner_b = [0x33; 20];
        let redemption = [0x22; 20];
        let swap_data = make_swap_action_data();

        let script_a = build_stas3_locking_script(
            &owner_a, &redemption, Some(&swap_data), false, true, &[], &[],
        )
        .unwrap();
        let script_b = build_stas3_locking_script(
            &owner_b, &redemption, Some(&swap_data), false, true, &[], &[],
        )
        .unwrap();

        let mode = resolve_stas3_swap_mode(script_a.to_bytes(), script_b.to_bytes());
        assert_eq!(mode, Stas3SwapMode::SwapSwap);
    }

    #[test]
    fn swap_mode_one_transfer_one_swap() {
        let owner_a = [0x11; 20];
        let owner_b = [0x33; 20];
        let redemption = [0x22; 20];
        let swap_data = make_swap_action_data();

        let script_a = build_stas3_locking_script(
            &owner_a, &redemption, None, false, true, &[], &[],
        )
        .unwrap();
        let script_b = build_stas3_locking_script(
            &owner_b, &redemption, Some(&swap_data), false, true, &[], &[],
        )
        .unwrap();

        let mode = resolve_stas3_swap_mode(script_a.to_bytes(), script_b.to_bytes());
        assert_eq!(mode, Stas3SwapMode::TransferSwap);
    }

    #[test]
    fn swap_mode_neither_has_swap() {
        let owner_a = [0x11; 20];
        let owner_b = [0x33; 20];
        let redemption = [0x22; 20];

        let script_a = build_stas3_locking_script(
            &owner_a, &redemption, None, false, true, &[], &[],
        )
        .unwrap();
        let script_b = build_stas3_locking_script(
            &owner_b, &redemption, None, false, true, &[], &[],
        )
        .unwrap();

        let mode = resolve_stas3_swap_mode(script_a.to_bytes(), script_b.to_bytes());
        assert_eq!(mode, Stas3SwapMode::TransferSwap);
    }

    #[test]
    fn frozen_detection() {
        let owner = [0x11; 20];
        let redemption = [0x22; 20];

        let unfrozen = build_stas3_locking_script(
            &owner, &redemption, None, false, true, &[], &[],
        )
        .unwrap();
        let frozen = build_stas3_locking_script(
            &owner, &redemption, None, true, true, &[], &[],
        )
        .unwrap();

        assert!(!is_stas3_frozen(unfrozen.to_bytes()));
        assert!(is_stas3_frozen(frozen.to_bytes()));
    }

    #[test]
    fn script_hash_not_stas3_rejected() {
        let p2pkh = hex::decode("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac").unwrap();
        assert!(compute_stas3_requested_script_hash(&p2pkh).is_err());
    }
}
