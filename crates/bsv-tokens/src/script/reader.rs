//! Script reader for parsing STAS and STAS 3.0 locking scripts.

use crate::script::templates::*;
use crate::types::ActionData;
use crate::{ScriptType, TokenId};

/// Result of parsing a locking script.
#[derive(Debug)]
pub struct ParsedScript {
    /// The classified script type.
    pub script_type: ScriptType,
    /// STAS-specific fields, if applicable.
    pub stas: Option<StasFields>,
    /// STAS 3.0-specific fields, if applicable.
    pub dstas: Option<DstasFields>,
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
pub struct DstasFields {
    /// The 20-byte owner public key hash.
    pub owner: [u8; 20],
    /// The 20-byte redemption public key hash.
    pub redemption: [u8; 20],
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
            dstas: None,
        };
    }

    // Try STAS 3.0
    if let Some(dstas) = try_parse_dstas(script) {
        return ParsedScript {
            script_type: ScriptType::Dstas,
            stas: None,
            dstas: Some(dstas),
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
            dstas: None,
        };
    }

    // OP_RETURN
    if !script.is_empty() && script[0] == 0x6a {
        return ParsedScript {
            script_type: ScriptType::OpReturn,
            stas: None,
            dstas: None,
        };
    }

    // Also check for OP_FALSE OP_RETURN pattern
    if script.len() >= 2 && script[0] == 0x00 && script[1] == 0x6a {
        return ParsedScript {
            script_type: ScriptType::OpReturn,
            stas: None,
            dstas: None,
        };
    }

    ParsedScript {
        script_type: ScriptType::Unknown,
        stas: None,
        dstas: None,
    }
}

/// Check if a script is a STAS v2 token script.
pub fn is_stas(script: &[u8]) -> bool {
    is_stas_v2(script)
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
fn try_parse_dstas(script: &[u8]) -> Option<DstasFields> {
    // STAS 3.0 starts with OP_DATA_20 (0x14) + 20 bytes owner
    if script.len() < 26 || script[0] != 0x14 {
        return None;
    }

    let mut owner = [0u8; 20];
    owner.copy_from_slice(&script[1..21]);

    // Next: action data push
    let (action_data_raw, action_offset) = read_push_data(script, 21)?;

    // After action data, check for STAS 3.0 base template prefix
    if script.len() < action_offset + DSTAS_BASE_PREFIX.len() {
        return None;
    }
    if script[action_offset..action_offset + DSTAS_BASE_PREFIX.len()] != DSTAS_BASE_PREFIX {
        return None;
    }

    // OP_RETURN (0x6a) is the last byte of the base template
    let op_return_pos = action_offset + DSTAS_BASE_TEMPLATE_LEN - 1;
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
        // Swap action data: 61 bytes starting with kind 0x01
        if raw.len() == 61 && raw[0] == 0x01 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&raw[1..33]);
            let mut pkh = [0u8; 20];
            pkh.copy_from_slice(&raw[33..53]);
            let rate_numerator = u32::from_le_bytes([raw[53], raw[54], raw[55], raw[56]]);
            let rate_denominator = u32::from_le_bytes([raw[57], raw[58], raw[59], raw[60]]);
            Some(ActionData::Swap {
                requested_script_hash: hash,
                requested_pkh: pkh,
                rate_numerator,
                rate_denominator,
            })
        } else if raw.len() == 32 {
            // Legacy: bare 32-byte hash (no kind byte) — treat as swap with zero rate
            let mut hash = [0u8; 32];
            hash.copy_from_slice(raw);
            Some(ActionData::Swap {
                requested_script_hash: hash,
                requested_pkh: [0u8; 20],
                rate_numerator: 0,
                rate_denominator: 0,
            })
        } else if !raw.is_empty() && raw != &[0x52] {
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

    Some(DstasFields {
        owner,
        redemption,
        flags,
        action_data_raw,
        action_data_parsed,
        service_fields,
        optional_data: vec![],
        frozen,
    })
}

/// Read a single push data item from script at the given offset.
/// Returns (data_or_none, next_offset).
fn read_push_data(script: &[u8], offset: usize) -> Option<(Option<Vec<u8>>, usize)> {
    if offset >= script.len() {
        return None;
    }

    let opcode = script[offset];
    match opcode {
        // OP_0
        0x00 => Some((None, offset + 1)),
        // OP_2 (used for frozen flag)
        0x52 => Some((Some(vec![0x52]), offset + 1)),
        // Direct push: 1-75 bytes
        0x01..=0x4b => {
            let len = opcode as usize;
            let end = offset + 1 + len;
            if end > script.len() {
                return None;
            }
            Some((Some(script[offset + 1..end].to_vec()), end))
        }
        // OP_PUSHDATA1
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
        // OP_PUSHDATA2
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
        _ => Some((None, offset + 1)),
    }
}

/// Parse consecutive push data items from a byte slice.
fn parse_push_data_items(data: &[u8]) -> Vec<Vec<u8>> {
    let mut items = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let opcode = data[offset];
        match opcode {
            0x00 => {
                items.push(vec![0x00]);
                offset += 1;
            }
            0x01..=0x4b => {
                let len = opcode as usize;
                let end = offset + 1 + len;
                if end > data.len() {
                    break;
                }
                items.push(data[offset + 1..end].to_vec());
                offset = end;
            }
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
            _ => {
                // Non-push opcode or OP_1-OP_16
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
}
