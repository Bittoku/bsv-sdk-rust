//! Script reader for parsing STAS and STAS 3.0 locking scripts.

use crate::script::templates::*;
use crate::types::{ActionData, SwapDescriptor};
use crate::{ScriptType, TokenId};


/// Result of parsing a locking script.
#[derive(Debug)]
pub struct ParsedScript {
    /// The classified script type.
    pub script_type: ScriptType,
    /// STAS-specific fields, if applicable.
    pub stas: Option<StasFields>,
    /// STAS 3.0-specific fields, if applicable.
    pub stas3: Option<Stas3Fields>,
}

/// Fields extracted from a STAS v2 locking script.
#[derive(Debug, Clone)]
pub struct StasFields {
    /// The 20-byte owner public key hash.
    pub owner_hash: [u8; 20],
    /// The token ID (derived from the redemption PKH).
    pub token_id: TokenId,
    /// The 20-byte redemption public key hash.
    pub redemption_hash: [u8; 20],
    /// Flags byte(s) from the OP_RETURN data section.
    pub flags: Vec<u8>,
}

/// Fields extracted from a STAS 3.0 locking script.
#[derive(Debug, Clone)]
pub struct Stas3Fields {
    /// The 20-byte owner public key hash.
    pub owner: [u8; 20],
    /// The 20-byte redemption public key hash.
    ///
    /// This is also exposed as a typed [`TokenId`] via [`Self::token_id`]
    /// (the protoID is derived from this PKH).
    pub redemption: [u8; 20],
    /// The token ID derived from `redemption` via [`TokenId::from_pkh`].
    ///
    /// Provides parity with `StasFields::token_id` so consumers can route
    /// STAS v2 and STAS 3.0 utxos through the same lineage / lookup paths.
    pub token_id: TokenId,
    /// Flag bytes from the OP_RETURN data section.
    pub flags: Vec<u8>,
    /// Raw action data bytes (if present).
    pub action_data_raw: Option<Vec<u8>>,
    /// Parsed action data (if recognized).
    pub action_data_parsed: Option<ActionData>,
    /// Service fields from the OP_RETURN data.
    pub service_fields: Vec<Vec<u8>>,
    /// Optional data fields from the OP_RETURN data.
    pub optional_data: Vec<Vec<u8>>,
    /// Whether the token is currently frozen.
    pub frozen: bool,
}

/// Parse a locking script and classify it.
pub fn read_locking_script(script: &[u8]) -> ParsedScript {
    // Try STAS v2
    if let Some(stas) = try_parse_stas_v2(script) {
        return ParsedScript {
            script_type: ScriptType::Stas,
            stas: Some(stas),
            stas3: None,
        };
    }

    // Try STAS 3.0
    if let Some(stas3) = try_parse_stas3(script) {
        return ParsedScript {
            script_type: ScriptType::Stas3,
            stas: None,
            stas3: Some(stas3),
        };
    }

    // P2PKH: 76 a9 14 [20 bytes] 88 ac = 25 bytes exactly
    if script.len() == 25
        && script[0] == 0x76
        && script[1] == 0xa9
        && script[2] == 0x14
        && script[23] == 0x88
        && script[24] == 0xac
    {
        return ParsedScript {
            script_type: ScriptType::P2pkh,
            stas: None,
            stas3: None,
        };
    }

    // P2MPKH (bare multisig): OP_m <pk1>...<pkN> OP_n OP_CHECKMULTISIG
    if is_p2mpkh(script) {
        return ParsedScript {
            script_type: ScriptType::P2Mpkh,
            stas: None,
            stas3: None,
        };
    }

    // OP_RETURN
    if !script.is_empty() && script[0] == 0x6a {
        return ParsedScript {
            script_type: ScriptType::OpReturn,
            stas: None,
            stas3: None,
        };
    }

    // Also check for OP_FALSE OP_RETURN pattern
    if script.len() >= 2 && script[0] == 0x00 && script[1] == 0x6a {
        return ParsedScript {
            script_type: ScriptType::OpReturn,
            stas: None,
            stas3: None,
        };
    }

    ParsedScript {
        script_type: ScriptType::Unknown,
        stas: None,
        stas3: None,
    }
}

/// Check if a script is a STAS v2 token script.
pub fn is_stas(script: &[u8]) -> bool {
    is_stas_v2(script)
}

/// Check if a script is a STAS 3.0 P2MPKH locking script.
///
/// Per STAS 3.0 spec v0.1 § 10.2, a P2MPKH locking script is a fixed
/// 70-byte template of the form:
///
/// ```text
/// 76 a9 14 <MPKH:20> 88 82 01 21 87 63 ac 67
/// (51 7f 51 7f 73 63 7c 7f 68)
/// (51 7f 73 63 7c 7f 68) × 4
/// ae 68
/// ```
///
/// Detection compares the fixed prefix and suffix bytes; the 20-byte
/// `MPKH` slot is unconstrained.
pub fn is_p2mpkh(script: &[u8]) -> bool {
    if script.len() != P2MPKH_LOCKING_LEN {
        return false;
    }
    if script[..3] != P2MPKH_LOCKING_PREFIX {
        return false;
    }
    script[23..] == P2MPKH_LOCKING_SUFFIX
}

/// Check STAS v2 identification bytes.
fn is_stas_v2(script: &[u8]) -> bool {
    script.len() >= STAS_V2_MIN_LEN
        && script[..3] == STAS_V2_PREFIX
        && script[23..29] == STAS_V2_MARKER
}

/// Attempt to parse a STAS v2 script, returning fields if valid.
fn try_parse_stas_v2(script: &[u8]) -> Option<StasFields> {
    if !is_stas_v2(script) {
        return None;
    }

    let mut owner_hash = [0u8; 20];
    owner_hash.copy_from_slice(&script[STAS_V2_OWNER_OFFSET..STAS_V2_OWNER_OFFSET + 20]);

    let mut redemption_hash = [0u8; 20];
    redemption_hash
        .copy_from_slice(&script[STAS_V2_REDEMPTION_OFFSET..STAS_V2_REDEMPTION_OFFSET + 20]);

    // Parse flags from OP_RETURN data (after template)
    let op_return_data = &script[STAS_V2_TEMPLATE_LEN..];
    let flags = parse_push_data_items(op_return_data)
        .first()
        .cloned()
        .unwrap_or_default();

    // Token ID is derived from the redemption PKH
    let token_id = TokenId::from_pkh(redemption_hash);

    Some(StasFields {
        owner_hash,
        token_id,
        redemption_hash,
        flags,
    })
}

/// Attempt to parse a STAS 3.0 script.
fn try_parse_stas3(script: &[u8]) -> Option<Stas3Fields> {
    // STAS 3.0 starts with OP_DATA_20 (0x14) + 20 bytes owner
    if script.len() < 26 || script[0] != 0x14 {
        return None;
    }

    let mut owner = [0u8; 20];
    owner.copy_from_slice(&script[1..21]);

    // Next: action data push
    let (action_data_raw, action_offset) = read_push_data(script, 21)?;

    // After action data, check for STAS 3.0 base template prefix
    if script.len() < action_offset + STAS3_BASE_PREFIX.len() {
        return None;
    }
    if script[action_offset..action_offset + STAS3_BASE_PREFIX.len()] != STAS3_BASE_PREFIX {
        return None;
    }

    // OP_RETURN (0x6a) is the last byte of the base template
    let op_return_pos = action_offset + STAS3_BASE_TEMPLATE_LEN - 1;
    if op_return_pos >= script.len() || script[op_return_pos] != 0x6a {
        return None;
    }

    let after_op_return = &script[op_return_pos + 1..];
    let items = parse_push_data_items(after_op_return);

    // First item: redemption PKH (20 bytes)
    let redemption_data = items.first()?;
    if redemption_data.len() != 20 {
        return None;
    }
    let mut redemption = [0u8; 20];
    redemption.copy_from_slice(redemption_data);

    // Second item: flags
    let flags = items.get(1).cloned().unwrap_or_default();

    // Determine frozen state from action data
    let frozen = action_data_raw
        .as_ref()
        .is_some_and(|d| d == &[0x52]); // OP_2

    // Parse action data
    let action_data_parsed = action_data_raw.as_ref().and_then(|raw| {
        // Swap action data: ≥61 bytes starting with kind 0x01 (spec §6.3).
        // The trailing bytes (if any) form the recursive `next` field —
        // delegated to `SwapDescriptor::parse` which understands all forms
        // including chained recursive swaps.
        if !raw.is_empty() && raw[0] == 0x01 && raw.len() >= 61 {
            if let Ok(descriptor) = SwapDescriptor::parse(raw) {
                return Some(ActionData::from(descriptor));
            }
            // Malformed swap descriptor — fall through to Custom.
        }
        if raw.len() == 32 {
            // Legacy: bare 32-byte hash (no kind byte) — treat as swap with zero rate
            let mut hash = [0u8; 32];
            hash.copy_from_slice(raw);
            return Some(ActionData::Swap {
                requested_script_hash: hash,
                requested_pkh: [0u8; 20],
                rate_numerator: 0,
                rate_denominator: 0,
                next: None,
            });
        }
        if !raw.is_empty() && raw != &[0x52] {
            Some(ActionData::Custom(raw.clone()))
        } else {
            None
        }
    });

    // Service fields and optional data: items after flags
    let service_fields = if items.len() > 2 {
        items[2..].to_vec()
    } else {
        vec![]
    };

    let token_id = TokenId::from_pkh(redemption);

    Some(Stas3Fields {
        owner,
        redemption,
        token_id,
        flags,
        action_data_raw,
        action_data_parsed,
        service_fields,
        optional_data: vec![],
        frozen,
    })
}

/// Read a single push data item from script at the given offset.
///
/// Handles all Bitcoin push opcodes per the STAS 3.0 specification:
/// - OP_0 (0x00): returns None (empty push)
/// - Bare push (0x01-0x4b): opcode is the byte length of following data
/// - OP_PUSHDATA1 (0x4c): 1-byte length prefix
/// - OP_PUSHDATA2 (0x4d): 2-byte LE length prefix
/// - OP_PUSHDATA4 (0x4e): 4-byte LE length prefix
/// - OP_1NEGATE (0x4f): returns the opcode byte (push value -1)
/// - OP_1-OP_16 (0x51-0x60): returns the opcode byte (push values 1-16)
///
/// Returns (data_or_none, next_offset).
fn read_push_data(script: &[u8], offset: usize) -> Option<(Option<Vec<u8>>, usize)> {
    if offset >= script.len() {
        return None;
    }

    let opcode = script[offset];
    match opcode {
        // OP_0: pushes empty byte string
        0x00 => Some((None, offset + 1)),

        // Direct push: 1-75 bytes (opcode IS the length)
        0x01..=0x4b => {
            let len = opcode as usize;
            let end = offset + 1 + len;
            if end > script.len() {
                return None;
            }
            Some((Some(script[offset + 1..end].to_vec()), end))
        }

        // OP_PUSHDATA1: next 1 byte is length
        0x4c => {
            if offset + 1 >= script.len() {
                return None;
            }
            let len = script[offset + 1] as usize;
            let end = offset + 2 + len;
            if end > script.len() {
                return None;
            }
            Some((Some(script[offset + 2..end].to_vec()), end))
        }

        // OP_PUSHDATA2: next 2 bytes (LE) are length
        0x4d => {
            if offset + 2 >= script.len() {
                return None;
            }
            let len = u16::from_le_bytes([script[offset + 1], script[offset + 2]]) as usize;
            let end = offset + 3 + len;
            if end > script.len() {
                return None;
            }
            Some((Some(script[offset + 3..end].to_vec()), end))
        }

        // OP_PUSHDATA4: next 4 bytes (LE) are length
        0x4e => {
            if offset + 4 >= script.len() {
                return None;
            }
            let len = u32::from_le_bytes([
                script[offset + 1],
                script[offset + 2],
                script[offset + 3],
                script[offset + 4],
            ]) as usize;
            let end = offset + 5 + len;
            if end > script.len() {
                return None;
            }
            Some((Some(script[offset + 5..end].to_vec()), end))
        }

        // OP_1NEGATE (0x4f): pushes -1, single byte opcode, no following data
        0x4f => Some((Some(vec![0x4f]), offset + 1)),

        // OP_1 through OP_16 (0x51-0x60): push respective values 1-16.
        // Single byte opcodes, no following data. Return the opcode byte
        // so downstream code can identify the push value.
        0x51..=0x60 => Some((Some(vec![opcode]), offset + 1)),

        // Unknown opcode: skip 1 byte, return None
        _ => Some((None, offset + 1)),
    }
}

/// Parse consecutive push data items from a byte slice.
///
/// Handles all Bitcoin push opcodes per the STAS 3.0 specification:
/// - OP_0 (0x00): pushes `[0x00]`
/// - Bare push (0x01-0x4b): opcode is the byte length of following data
/// - OP_PUSHDATA1 (0x4c): 1-byte length prefix
/// - OP_PUSHDATA2 (0x4d): 2-byte LE length prefix
/// - OP_PUSHDATA4 (0x4e): 4-byte LE length prefix
/// - OP_1NEGATE (0x4f), OP_1-OP_16 (0x51-0x60): single-byte value opcodes
///
/// Returns a vector of extracted data items.
fn parse_push_data_items(data: &[u8]) -> Vec<Vec<u8>> {
    let mut items = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let opcode = data[offset];
        match opcode {
            // OP_0: pushes empty/zero marker
            0x00 => {
                items.push(vec![0x00]);
                offset += 1;
            }
            // Bare push: 1-75 bytes (opcode IS the length)
            0x01..=0x4b => {
                let len = opcode as usize;
                let end = offset + 1 + len;
                if end > data.len() {
                    break;
                }
                items.push(data[offset + 1..end].to_vec());
                offset = end;
            }
            // OP_PUSHDATA1: next 1 byte is length
            0x4c => {
                if offset + 1 >= data.len() {
                    break;
                }
                let len = data[offset + 1] as usize;
                let end = offset + 2 + len;
                if end > data.len() {
                    break;
                }
                items.push(data[offset + 2..end].to_vec());
                offset = end;
            }
            // OP_PUSHDATA2: next 2 bytes (LE) are length
            0x4d => {
                if offset + 2 >= data.len() {
                    break;
                }
                let len = u16::from_le_bytes([data[offset + 1], data[offset + 2]]) as usize;
                let end = offset + 3 + len;
                if end > data.len() {
                    break;
                }
                items.push(data[offset + 3..end].to_vec());
                offset = end;
            }
            // OP_PUSHDATA4: next 4 bytes (LE) are length
            0x4e => {
                if offset + 4 >= data.len() {
                    break;
                }
                let len = u32::from_le_bytes([
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                    data[offset + 4],
                ]) as usize;
                let end = offset + 5 + len;
                if end > data.len() {
                    break;
                }
                items.push(data[offset + 5..end].to_vec());
                offset = end;
            }
            _ => {
                // OP_1NEGATE (0x4f), OP_1-OP_16 (0x51-0x60), or other
                // single-byte opcodes: push the opcode byte as the value
                items.push(vec![opcode]);
                offset += 1;
            }
        }
    }

    items
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a STAS v2 script with given owner and redemption PKHs + flags.
    fn build_stas_v2_script(owner: &[u8; 20], redemption: &[u8; 20], flags: u8) -> Vec<u8> {
        let template_hex = concat!(
            "76a914", "0000000000000000000000000000000000000000",
            "88ac6976aa607f5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e",
            "7c5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e",
            "01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00",
            "7d976e7c5296a06394677768827601249301307c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027e7c7e7c",
            "8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c",
            "8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c",
            "8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c",
            "8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c8276638c687f7c",
            "7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e",
            "01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad",
            "547f7701207f01207f7701247f517f7801007e8102fd00a063546752687f7801007e817f727e7b01177f777b557a766471567a577a786354807e7e676d68",
            "aa880067765158a569765187645294567a5379587a7e7e78637c8c7c53797e577a7e6878637c8c7c53797e577a7e6878637c8c7c53797e577a7e68",
            "78637c8c7c53797e577a7e6878637c8c7c53797e577a7e6867567a6876aa587a7d54807e577a597a5a7a786354807e6f7e7eaa727c7e676d6e7eaa7c687b7eaa",
            "587a7d877663516752687c72879b69537a647500687c7b547f77517f7853a0916901247f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81",
            "6854937f77788c6301247f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e816854937f777852946301247f77517f7c01007e81",
            "7602fc00a06302fd00a063546752687f7c01007e816854937f77686877517f7c52797d8b9f7c53a09b91697c76638c7c587f77517f7c01007e81",
            "7602fc00a06302fd00a063546752687f7c01007e81687f777c6876638c7c587f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81",
            "687f777c6863587f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81687f7768587f517f7801007e81",
            "7602fc00a06302fd00a063546752687f7801007e81727e7b7b687f75537f7c0376a9148801147f775379645579887567726881766968789263556753687a76",
            "026c057f7701147f8263517f7c766301007e817f7c6775006877686b537992635379528763547a6b547a6b677c6b567a6b537a7c717c71716868",
            "547a587f7c81547a557964936755795187637c686b687c547f7701207f75748c7a7669765880748c7a76567a876457790376a9147e7c7e557967",
            "041976a9147c7e0288ac687e7e5579636c766976748c7a9d58807e6c0376a9147e748c7a7e6c7e7e676c766b8263828c007c80517e846864745aa063",
            "7c748c7a76697d937b7b58807e56790376a9147e748c7a7e55797e7e6868686c567a5187637500678263828c007c80517e846868647459a063",
            "7c748c7a76697d937b7b58807e55790376a9147e748c7a7e55797e7e687459a0637c748c7a76697d937b7b58807e55790376a9147e748c7a7e55797e7e",
            "68687c537a9d547963557958807e041976a91455797e0288ac7e7e68aa87726d77776a14",
            "0000000000000000000000000000000000000000"
        );

        let mut script = hex::decode(template_hex).expect("valid template hex");

        // Patch owner PKH at bytes 3..23
        script[3..23].copy_from_slice(owner);

        // Patch redemption PKH at bytes 1411..1431
        script[1411..1431].copy_from_slice(redemption);

        // Append flags as push data
        script.push(0x01); // OP_DATA_1
        script.push(flags);

        script
    }

    #[test]
    fn classify_stas_v2() {
        let owner = [0xaa; 20];
        let redemption = [0xbb; 20];
        let script = build_stas_v2_script(&owner, &redemption, 0x00);

        let parsed = read_locking_script(&script);
        assert_eq!(parsed.script_type, ScriptType::Stas);

        let stas = parsed.stas.unwrap();
        assert_eq!(stas.owner_hash, owner);
        assert_eq!(stas.redemption_hash, redemption);
    }

    #[test]
    fn classify_p2pkh() {
        let script = hex::decode("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac").unwrap();
        let parsed = read_locking_script(&script);
        assert_eq!(parsed.script_type, ScriptType::P2pkh);
        assert!(parsed.stas.is_none());
    }

    #[test]
    fn classify_p2mpkh_70_byte_locking_script() {
        // Spec § 10.2 — fixed 70-byte P2MPKH locking script.
        let mpkh = [0xab; 20];
        let script = build_p2mpkh_locking_script(mpkh);

        let parsed = read_locking_script(&script);
        assert_eq!(parsed.script_type, ScriptType::P2Mpkh);
        assert!(parsed.stas.is_none());
        assert!(parsed.stas3.is_none());
    }

    #[test]
    fn is_p2mpkh_true_for_70_byte_template() {
        let body = build_p2mpkh_locking_script([0u8; 20]);
        assert!(is_p2mpkh(&body));
    }

    #[test]
    fn is_p2mpkh_false_for_p2pkh() {
        let script = hex::decode("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac").unwrap();
        assert!(!is_p2mpkh(&script));
    }

    #[test]
    fn is_p2mpkh_false_for_short_script() {
        assert!(!is_p2mpkh(&[0x51, 0xae]));
        assert!(!is_p2mpkh(&[]));
    }

    #[test]
    fn is_p2mpkh_false_for_bare_multisig_old_format() {
        // The legacy bare-multisig pattern (OP_m … OP_n OP_CHECKMULTISIG)
        // is NOT a P2MPKH locking script under STAS 3.0.
        let mut script = vec![0x52]; // OP_2
        for _ in 0..3 {
            script.push(0x21);
            script.push(0x02);
            script.extend_from_slice(&[0xab; 32]);
        }
        script.push(0x53); // OP_3
        script.push(0xae); // OP_CHECKMULTISIG
        assert!(!is_p2mpkh(&script));
    }

    #[test]
    fn classify_op_return() {
        let script = hex::decode("6a0568656c6c6f").unwrap();
        let parsed = read_locking_script(&script);
        assert_eq!(parsed.script_type, ScriptType::OpReturn);
    }

    #[test]
    fn classify_op_false_op_return() {
        let script = hex::decode("006a0568656c6c6f").unwrap();
        let parsed = read_locking_script(&script);
        assert_eq!(parsed.script_type, ScriptType::OpReturn);
    }

    #[test]
    fn classify_unknown() {
        let script = vec![0xff, 0xfe, 0xfd];
        let parsed = read_locking_script(&script);
        assert_eq!(parsed.script_type, ScriptType::Unknown);
    }

    #[test]
    fn classify_empty() {
        let parsed = read_locking_script(&[]);
        assert_eq!(parsed.script_type, ScriptType::Unknown);
    }

    #[test]
    fn is_stas_true() {
        let owner = [0x11; 20];
        let redemption = [0x22; 20];
        let script = build_stas_v2_script(&owner, &redemption, 0x01);
        assert!(is_stas(&script));
    }

    #[test]
    fn is_stas_false_for_p2pkh() {
        let script = hex::decode("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac").unwrap();
        assert!(!is_stas(&script));
    }

    #[test]
    fn is_stas_false_for_empty() {
        assert!(!is_stas(&[]));
    }

    #[test]
    fn stas3_extracts_token_id() {
        // Spec parity with STAS v2: STAS 3.0 fields must expose a TokenId
        // derived from the redemption PKH (Priority 2d).
        use crate::script::stas3_builder::build_stas3_locking_script;
        let owner = [0x11; 20];
        let redemption = [0x22; 20];
        let script = build_stas3_locking_script(
            &owner, &redemption, None, false, true, &[], &[],
        )
        .unwrap();
        let parsed = read_locking_script(script.to_bytes());
        assert_eq!(parsed.script_type, ScriptType::Stas3);
        let stas3 = parsed.stas3.unwrap();
        assert_eq!(stas3.token_id.public_key_hash(), &redemption);
    }

    #[test]
    fn stas_v2_extracts_token_id() {
        let owner = [0xcc; 20];
        let redemption = [0xdd; 20];
        let script = build_stas_v2_script(&owner, &redemption, 0x00);

        let parsed = read_locking_script(&script);
        let stas = parsed.stas.unwrap();
        assert_eq!(stas.token_id.public_key_hash(), &redemption);
    }

    #[test]
    fn garbage_bytes_no_panic() {
        for len in 0..50 {
            let script: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let _ = read_locking_script(&script);
            let _ = is_stas(&script);
        }
    }

    // ---------------------------------------------------------------
    // read_push_data unit tests — one per opcode variant in the spec
    // ---------------------------------------------------------------

    /// OP_0 (0x00) returns (None, offset + 1) — empty push.
    #[test]
    fn read_push_data_op_0() {
        let script = [0x00u8];
        let (data, next) = read_push_data(&script, 0).unwrap();
        assert!(data.is_none(), "OP_0 should return None (empty push)");
        assert_eq!(next, 1);
    }

    /// Bare push 1 byte (0x01) returns (Some([0xAB]), offset + 2).
    #[test]
    fn read_push_data_bare_1_byte() {
        let script = [0x01, 0xAB];
        let (data, next) = read_push_data(&script, 0).unwrap();
        assert_eq!(data.unwrap(), vec![0xAB]);
        assert_eq!(next, 2);
    }

    /// Bare push 20 bytes (0x14) returns (Some([20 bytes]), offset + 21).
    #[test]
    fn read_push_data_bare_20_bytes() {
        let mut script = vec![0x14];
        let payload: Vec<u8> = (0..20).collect();
        script.extend_from_slice(&payload);
        let (data, next) = read_push_data(&script, 0).unwrap();
        assert_eq!(data.unwrap(), payload);
        assert_eq!(next, 21);
    }

    /// Bare push 75 bytes (0x4B) — max bare push — returns all 75 bytes.
    #[test]
    fn read_push_data_bare_75_bytes() {
        let mut script = vec![0x4B];
        let payload: Vec<u8> = (0..75).map(|i| (i * 3) as u8).collect();
        script.extend_from_slice(&payload);
        let (data, next) = read_push_data(&script, 0).unwrap();
        assert_eq!(data.unwrap(), payload);
        assert_eq!(next, 76);
    }

    /// OP_PUSHDATA1 (0x4C) with 3-byte payload.
    #[test]
    fn read_push_data_pushdata1() {
        let script = [0x4C, 0x03, 0xAA, 0xBB, 0xCC];
        let (data, next) = read_push_data(&script, 0).unwrap();
        assert_eq!(data.unwrap(), vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(next, 5);
    }

    /// OP_PUSHDATA2 (0x4D) with 3-byte payload (LE length 0x0003).
    #[test]
    fn read_push_data_pushdata2() {
        let script = [0x4D, 0x03, 0x00, 0xAA, 0xBB, 0xCC];
        let (data, next) = read_push_data(&script, 0).unwrap();
        assert_eq!(data.unwrap(), vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(next, 6);
    }

    /// OP_PUSHDATA4 (0x4E) with 2-byte payload (LE length 0x00000002).
    #[test]
    fn read_push_data_pushdata4() {
        let script = [0x4E, 0x02, 0x00, 0x00, 0x00, 0xDD, 0xEE];
        let (data, next) = read_push_data(&script, 0).unwrap();
        assert_eq!(data.unwrap(), vec![0xDD, 0xEE]);
        assert_eq!(next, 7);
    }

    /// OP_1NEGATE (0x4F) returns (Some([0x4F]), offset + 1).
    #[test]
    fn read_push_data_op_1negate() {
        let script = [0x4F];
        let (data, next) = read_push_data(&script, 0).unwrap();
        assert_eq!(data.unwrap(), vec![0x4F]);
        assert_eq!(next, 1);
    }

    /// OP_1 (0x51) returns (Some([0x51]), offset + 1).
    #[test]
    fn read_push_data_op_1() {
        let script = [0x51];
        let (data, next) = read_push_data(&script, 0).unwrap();
        assert_eq!(data.unwrap(), vec![0x51]);
        assert_eq!(next, 1);
    }

    /// OP_2 (0x52) returns (Some([0x52]), offset + 1) — frozen flag.
    #[test]
    fn read_push_data_op_2() {
        let script = [0x52];
        let (data, next) = read_push_data(&script, 0).unwrap();
        assert_eq!(data.unwrap(), vec![0x52]);
        assert_eq!(next, 1);
    }

    /// OP_16 (0x60) returns (Some([0x60]), offset + 1).
    #[test]
    fn read_push_data_op_16() {
        let script = [0x60];
        let (data, next) = read_push_data(&script, 0).unwrap();
        assert_eq!(data.unwrap(), vec![0x60]);
        assert_eq!(next, 1);
    }

    /// OP_3 (0x53) returns (Some([0x53]), offset + 1) — mid-range check.
    #[test]
    fn read_push_data_op_3() {
        let script = [0x53];
        let (data, next) = read_push_data(&script, 0).unwrap();
        assert_eq!(data.unwrap(), vec![0x53]);
        assert_eq!(next, 1);
    }

    /// Verify read_push_data respects a non-zero starting offset.
    #[test]
    fn read_push_data_with_nonzero_offset() {
        let script = [0xFF, 0xFF, 0x01, 0xBE];
        let (data, next) = read_push_data(&script, 2).unwrap();
        assert_eq!(data.unwrap(), vec![0xBE]);
        assert_eq!(next, 4);
    }

    /// read_push_data returns None when offset is past end of script.
    #[test]
    fn read_push_data_offset_past_end() {
        let script = [0x01, 0xAA];
        assert!(read_push_data(&script, 5).is_none());
    }

    /// read_push_data returns None when bare push length exceeds script.
    #[test]
    fn read_push_data_bare_truncated() {
        let script = [0x05, 0xAA, 0xBB]; // claims 5 bytes but only 2 follow
        assert!(read_push_data(&script, 0).is_none());
    }

    // ---------------------------------------------------------------
    // Integration tests: STAS3 script with each opcode variant at
    // the 2nd variable field position (byte 21), verified through
    // read_stas3_fields (try_parse_stas3).
    // ---------------------------------------------------------------

    /// Build a minimal valid STAS3 script with the given action-data opcode
    /// sequence starting at byte 21 (after OP_DATA_20 + 20 owner bytes).
    ///
    /// Layout:
    ///   [0x14][20 owner bytes][action_data_bytes...][STAS3_BASE_PREFIX][padding to 2812 bytes, last byte 0x6a][OP_RETURN data: redemption + flags]
    fn build_stas3_script(action_data_bytes: &[u8]) -> Vec<u8> {
        let owner = [0xAA; 20];
        let redemption = [0xBB; 20];
        let flags: u8 = 0x01;

        // Header: OP_DATA_20 + owner
        let mut script = vec![0x14];
        script.extend_from_slice(&owner);

        // Action data opcode(s)
        script.extend_from_slice(action_data_bytes);

        // STAS3 base template: prefix bytes + filler + OP_RETURN at end
        let prefix_and_action_len = script.len(); // bytes consumed so far
        let template_body_len = STAS3_BASE_TEMPLATE_LEN; // 2812 bytes for the base template

        // Start with the 4-byte prefix
        script.extend_from_slice(&STAS3_BASE_PREFIX);

        // Fill the remaining template bytes (template_body_len - 4 prefix - 1 OP_RETURN) with 0x00
        let filler_len = template_body_len - 4 - 1;
        script.extend(std::iter::repeat(0x00).take(filler_len));

        // Last byte of template is OP_RETURN
        script.push(0x6a);

        // After OP_RETURN: redemption PKH (push 20 bytes) + flags (push 1 byte)
        script.push(0x14); // OP_DATA_20
        script.extend_from_slice(&redemption);
        script.push(0x01); // OP_DATA_1
        script.push(flags);

        let _ = prefix_and_action_len; // suppress unused warning
        script
    }

    /// Verify that try_parse_stas3 correctly extracts action_data_raw for
    /// each opcode variant placed in the 2nd variable field.
    #[test]
    fn stas3_action_data_op_0() {
        let script = build_stas3_script(&[0x00]); // OP_0
        let fields = try_parse_stas3(&script).expect("should parse STAS3 with OP_0 action data");
        assert_eq!(fields.owner, [0xAA; 20]);
        assert!(
            fields.action_data_raw.is_none(),
            "OP_0 action data should be None"
        );
        assert_eq!(fields.redemption, [0xBB; 20]);
    }

    #[test]
    fn stas3_action_data_bare_1_byte() {
        let script = build_stas3_script(&[0x01, 0xDE]); // bare push 1 byte
        let fields = try_parse_stas3(&script)
            .expect("should parse STAS3 with bare 1-byte action data");
        assert_eq!(fields.action_data_raw.as_deref(), Some(&[0xDE][..]));
    }

    #[test]
    fn stas3_action_data_bare_20_bytes() {
        let mut action = vec![0x14]; // bare push 20 bytes
        action.extend_from_slice(&[0xEE; 20]);
        let script = build_stas3_script(&action);
        let fields = try_parse_stas3(&script)
            .expect("should parse STAS3 with bare 20-byte action data");
        assert_eq!(fields.action_data_raw.as_deref(), Some(&[0xEE; 20][..]));
    }

    #[test]
    fn stas3_action_data_pushdata1() {
        let script = build_stas3_script(&[0x4C, 0x02, 0xCA, 0xFE]); // OP_PUSHDATA1, len=2
        let fields = try_parse_stas3(&script)
            .expect("should parse STAS3 with OP_PUSHDATA1 action data");
        assert_eq!(fields.action_data_raw.as_deref(), Some(&[0xCA, 0xFE][..]));
    }

    #[test]
    fn stas3_action_data_pushdata2() {
        let script = build_stas3_script(&[0x4D, 0x02, 0x00, 0xCA, 0xFE]); // OP_PUSHDATA2, len=2
        let fields = try_parse_stas3(&script)
            .expect("should parse STAS3 with OP_PUSHDATA2 action data");
        assert_eq!(fields.action_data_raw.as_deref(), Some(&[0xCA, 0xFE][..]));
    }

    #[test]
    fn stas3_action_data_pushdata4() {
        let script =
            build_stas3_script(&[0x4E, 0x02, 0x00, 0x00, 0x00, 0xCA, 0xFE]); // OP_PUSHDATA4, len=2
        let fields = try_parse_stas3(&script)
            .expect("should parse STAS3 with OP_PUSHDATA4 action data");
        assert_eq!(fields.action_data_raw.as_deref(), Some(&[0xCA, 0xFE][..]));
    }

    #[test]
    fn stas3_action_data_op_1negate() {
        let script = build_stas3_script(&[0x4F]); // OP_1NEGATE
        let fields = try_parse_stas3(&script)
            .expect("should parse STAS3 with OP_1NEGATE action data");
        assert_eq!(fields.action_data_raw.as_deref(), Some(&[0x4F][..]));
    }

    #[test]
    fn stas3_action_data_op_1() {
        let script = build_stas3_script(&[0x51]); // OP_1
        let fields =
            try_parse_stas3(&script).expect("should parse STAS3 with OP_1 action data");
        assert_eq!(fields.action_data_raw.as_deref(), Some(&[0x51][..]));
    }

    #[test]
    fn stas3_action_data_op_2_frozen() {
        let script = build_stas3_script(&[0x52]); // OP_2 — frozen flag
        let fields =
            try_parse_stas3(&script).expect("should parse STAS3 with OP_2 action data");
        assert_eq!(fields.action_data_raw.as_deref(), Some(&[0x52][..]));
        assert!(fields.frozen, "OP_2 action data should set frozen = true");
    }

    #[test]
    fn stas3_action_data_op_3() {
        let script = build_stas3_script(&[0x53]); // OP_3
        let fields =
            try_parse_stas3(&script).expect("should parse STAS3 with OP_3 action data");
        assert_eq!(fields.action_data_raw.as_deref(), Some(&[0x53][..]));
    }

    #[test]
    fn stas3_action_data_op_16() {
        let script = build_stas3_script(&[0x60]); // OP_16
        let fields =
            try_parse_stas3(&script).expect("should parse STAS3 with OP_16 action data");
        assert_eq!(fields.action_data_raw.as_deref(), Some(&[0x60][..]));
    }
}
