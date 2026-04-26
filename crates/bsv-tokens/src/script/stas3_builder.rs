//! Builder for STAS3 (stas3-freeze-multisig) locking scripts.

use bsv_script::Script;

use crate::error::TokenError;
use crate::types::{ActionData};

/// The compiled STAS3 base template bytes (hex-encoded).
/// Extracted from dxs-stas-sdk `stas3-freeze-multisig-base.ts`.
const STAS3_BASE_TEMPLATE_HEX: &str = "6d82736301218763007b7b517c6e5667766b517f786b517f73637c7f68517f73637c7f68517f73637c7f68517f73637c7f68517f73637c7f68766c936c7c5493686751687652937a76aa607f5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7c5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e011f7f7d7e01007e8111414136d08c5ed2bf3ba048afe6dcaebafe01005f80837e01007e7652967b537a7601ff877c0100879b7d648b6752799368537a7d9776547aa06394677768263044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802207c607f5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7c5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e01417e7c6421038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b92186721023635954789a02e39fb7e54440b6f528d53efd65635ddad7f3c4085f97fdbdc4868ad547f7701207f01207f7701247f517f7801007e02fd00a063546752687f7801007e817f727e7b517f7c01147d887f517f7c01007e817601619f6976014ea063517c7b6776014ba06376014da063755467014d9c6352675168687f7c01007e81687f007b7b687602fd0a7f7701147f7c5579876b826475020100686b587a5893766b7a765155a569005379736382013ca07c517f7c51877b9a6352795487637101007c7e717101207f01147f75777c7567756c766b8b8b79518868677568686c6c7c6b517f7c817f788273638c7f776775010068518463517f7c01147d887f547952876372777c717c767663517f756852875779766352790152879a689b63517f77567a7567527c7681014f0161a5587a9a63015094687e68746c766b5c9388748c76795879888c8c7978886777717c767663517f7568528778015287587a9a9b745394768b797663517f756852877c6c766b5c936ea0637c8c768b797663517f75685287726b9b7c6c686ea0637c5394768b797663517f75685287726b9b7c6c686ea063755494797663517f756852879b676d689b63006968687c717167567a75686d7c518763755279686c755879a9886b6b6b6b6b6b6b827763af686c6c6c6c6c6c6c547a577a7664577a577a587a597a786354807e7e676d68aa880067765158a569765187645294587a53795a7a7e7e78637c8c7c53797e597a7e6878637c8c7c53797e597a7e6878637c8c7c53797e597a7e6878637c8c7c53797e597a7e6878637c8c7c53797e597a7e6867587a6876aa5a7a7d54807e597a5b7a5c7a786354807e6f7e7eaa727c7e676d6e7eaa7c687b7eaa5a7a7d877663516752687c72879b69537a6491687c7b547f77517f7853a0916901247f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e816854937f77788c6301247f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e816854937f777852946301247f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e816854937f77686877517f7c52797d8b9f7c53a09b91697c76638c7c587f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81687f777c6876638c7c587f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81687f777c6863587f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81687f7768587f517f7801007e817602fc00a06302fd00a063546752687f7801007e81727e7b7b687f75517f7c01147d887f517f7c01007e817601619f6976014ea0637c6776014ba06376014da063755467014d9c6352675168687f7c01007e81687f68557964577988756d67716881687863567a677b68587f7c8153796353795287637b6b537a6b717c6b6b537a6b676b577a6b597a6b587a6b577a6b7c68677b93687c547f7701207f75748c7a7669765880044676a914780114748c7a76727b748c7a768291788251877c764f877c81510111a59b9a9b648276014ba1647602ff00a16351014c677603ffff00a16352014d6754014e68687b7b7f757e687c7e67736301509367010068685c795c79636c766b7363517f7c51876301207f7c5279a8877c011c7f5579877c01147f755679879a9a6967756868687e777e7e827602fc00a0637603ffff00a06301fe7c82546701fd7c8252687da0637f756780687e67517f75687c7e7e0a888201218763ac67517f07517f73637c7f6876767e767e7e02ae687e7e7c557a00740111a063005a79646b7c748c7a76697d937b7b58807e6c91677c748c7a7d58807e6c6c6c557a680114748c7a748c7a768291788251877c764f877c81510111a59b9a9b648276014ba1647602ff00a16351014c677603ffff00a16352014d6754014e68687b7b7f757e687c7e67736301509367010068685479635f79676c766b0115797363517f7c51876301207f7c5279a8877c011c7f5579877c01147f755679879a9a6967756868687e777e7e827602fc00a0637603ffff00a06301fe7c82546701fd7c8252687da0637f756780687e67517f75687c7e7c637e677c6b7c6b7c6b7e7c6b68685979636c6c766b786b7363517f7c51876301347f77547f547f75786352797b01007e81957c01007e81965379a169676d68677568685c797363517f7c51876301347f77547f547f75786354797b01007e81957c01007e819678a169676d68677568687568740111a063748c7a76697d58807e00005c79635e79768263517f756851876c6c766b7c6b768263517f756851877b6e9b63789c6375745294797b78877b7b877d9b69637c917c689167745294797c638777637c917c91686777876391677c917c686868676d6d68687863537a6c936c6c6c567a567a54795479587a676b72937b7b5c795e796c68748c7a748c7a7b636e717b7b877b7b879a6967726d6801147b7e7c8291788251877c764f877c81510111a59b9a9b648276014ba1647602ff00a16351014c677603ffff00a16352014d6754014e68687b7b7f757e687c7e67736301509367010068687e7c636c766b7e726b6b726b6b675b797e68827602fc00a0637603ffff00a06301fe7c82546701fd7c8252687da0637f756780687e67517f75687c7e7e68740111a063748c7a76697d58807e00005c79635e79768263517f756851876c6c766b7c6b768263517f756851877b6e9b63789c6375745294797b78877b7b877d9b69637c917c689167745294797c638777637c917c91686777876391677c917c686868676d6d68687863537a6c936c6c6c567a567a54795479587a676b72937b7b5c795e796c68748c7a748c7a7b636e717b7b877b7b879a6967726d6801147b7e7c8291788251877c764f877c81510111a59b9a9b648276014ba1647602ff00a16351014c677603ffff00a16352014d6754014e68687b7b7f757e687c7e67736301509367010068687e7c636c766b7e726b6b726b6b675b797e68827602fc00a0637603ffff00a06301fe7c82546701fd7c8252687da0637f756780687e67517f75687c7e7e68597a636c6c6c6d6c6c6d6c9d687c587a9d7d7e5c79635d795880041976a9145e797e0288ac7e7e6700687d7e5c7a766302006a7c7e827602fc00a06301fd7c7e536751687f757c7e0058807c7e687d7eaa6b7e7e7e7e7e7eaa78877c6c877c6c9a9b726d726d77776a";

/// Build a STAS3 locking script from parameters.
///
/// # Arguments
/// * `params` - The locking parameters including address, spend type, and action data
/// * `redemption_pkh` - The 20-byte redemption public key hash
/// * `frozen` - Whether the token is frozen
/// * `flags` - Flags bytes (use `build_stas3_flags` helper)
/// * `service_fields` - Additional service field data pushes
/// * `optional_data` - Additional optional data pushes
pub fn build_stas3_locking_script(
    owner_pkh: &[u8; 20],
    redemption_pkh: &[u8; 20],
    action_data: Option<&ActionData>,
    frozen: bool,
    freezable: bool,
    service_fields: &[Vec<u8>],
    optional_data: &[Vec<u8>],
) -> Result<Script, TokenError> {
    let base_template = hex::decode(STAS3_BASE_TEMPLATE_HEX)
        .map_err(|e| TokenError::InvalidScript(format!("stas3 template decode error: {e}")))?;

    let mut script = Vec::with_capacity(base_template.len() + 128);

    // 1. Push owner PKH (OP_DATA_20 + 20 bytes)
    script.push(0x14);
    script.extend_from_slice(owner_pkh);

    // 2. Action data encoding
    match (frozen, action_data) {
        (false, None) => {
            // OP_0
            script.push(0x00);
        }
        (true, None) => {
            // OP_2 (frozen marker)
            script.push(0x52);
        }
        (_, Some(data)) => {
            let bytes = match data {
                ActionData::Swap {
                    requested_script_hash,
                    requested_pkh,
                    rate_numerator,
                    rate_denominator,
                } => {
                    // 61 bytes: 1 (kind 0x01) + 32 (hash) + 20 (pkh) + 4 (num LE) + 4 (den LE)
                    let mut buf = Vec::with_capacity(61);
                    buf.push(0x01); // swap action kind
                    buf.extend_from_slice(requested_script_hash);
                    buf.extend_from_slice(requested_pkh);
                    buf.extend_from_slice(&rate_numerator.to_le_bytes());
                    buf.extend_from_slice(&rate_denominator.to_le_bytes());
                    buf
                }
                ActionData::Custom(b) => b.clone(),
            };
            push_data(&mut script, &bytes);
        }
    }

    // 3. Base template
    script.extend_from_slice(&base_template);

    // 4. OP_RETURN is the last byte of the base template (0x6a)

    // 5. Push redemption PKH
    script.push(0x14);
    script.extend_from_slice(redemption_pkh);

    // 6. Flags
    let flags = build_stas3_flags(freezable);
    push_data(&mut script, &flags);

    // 7. Service fields
    for field in service_fields {
        push_data(&mut script, field);
    }

    // 8. Optional data
    for data in optional_data {
        push_data(&mut script, data);
    }

    Ok(Script::from_bytes(&script))
}

/// Build flags byte from boolean options.
///
/// Bit 0: freezable (1 = freezable, 0 = not freezable)
pub fn build_stas3_flags(freezable: bool) -> Vec<u8> {
    if freezable {
        vec![0x01]
    } else {
        vec![0x00]
    }
}

/// Push data onto a script buffer with appropriate length prefix.
fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len == 0 {
        script.push(0x00); // OP_0
    } else if len <= 75 {
        script.push(len as u8);
        script.extend_from_slice(data);
    } else if len <= 255 {
        script.push(0x4c); // OP_PUSHDATA1
        script.push(len as u8);
        script.extend_from_slice(data);
    } else {
        script.push(0x4d); // OP_PUSHDATA2
        script.push((len & 0xff) as u8);
        script.push((len >> 8) as u8);
        script.extend_from_slice(data);
    }
}

// ---------------------------------------------------------------------------
// Fix J: Frozen marker conversion (STAS 3.0 spec v0.1 §6.2)
// ---------------------------------------------------------------------------

/// Convert a STAS 3.0 `var2` push (in original form) to its frozen-form
/// encoding per spec v0.1 §6.2.
///
/// The freeze operation rewrites the leading var2 push as follows:
/// - empty push (`OP_0`)             → `OP_2` (single opcode 0x52)
/// - direct push, OP_PUSHDATA{1,2,4} → prepend `0x02` to the pushed bytes,
///   re-emit with minimal pushdata header
/// - `OP_1`, `OP_3`..`OP_16`, `OP_1NEGATE` → first convert to pushdata form
///   (i.e. push the value the opcode pushes onto the stack), then prepend
///   `0x02` to that value.
///
/// `var2_push` is the entire push (header + body), exactly as found at the
/// var2 slot in a STAS 3.0 locking script.
///
/// Returns the new push bytes (header + body) ready to be substituted in
/// place of the original var2 push.
///
/// # Errors
/// Returns [`TokenError::InvalidScript`] if `var2_push` is empty, malformed,
/// or already in frozen form.
pub fn freeze_var2_push(var2_push: &[u8]) -> Result<Vec<u8>, TokenError> {
    if var2_push.is_empty() {
        return Err(TokenError::InvalidScript("empty var2 push".into()));
    }
    let value = decode_push_value(var2_push)?;

    // empty push → OP_2
    if value.is_empty() {
        return Ok(vec![0x52]);
    }

    // pushdata bytelength / OP_PUSHDATA1/2/4 OR a bare-opcode form already
    // converted to pushdata: prepend 0x02 to the pushed bytes and re-emit.
    let mut frozen_body = Vec::with_capacity(value.len() + 1);
    frozen_body.push(0x02);
    frozen_body.extend_from_slice(&value);

    Ok(encode_minimal_push(&frozen_body))
}

/// Inverse of [`freeze_var2_push`]: convert a frozen-form var2 push back to
/// its original form per spec v0.1 §6.2.
///
/// # Errors
/// Returns [`TokenError::InvalidScript`] if the input is not a recognised
/// frozen-form push.
pub fn unfreeze_var2_push(frozen_push: &[u8]) -> Result<Vec<u8>, TokenError> {
    if frozen_push.is_empty() {
        return Err(TokenError::InvalidScript("empty frozen push".into()));
    }

    // OP_2 → empty push (OP_0)
    if frozen_push == [0x52] {
        return Ok(vec![0x00]);
    }

    let value = decode_push_value(frozen_push)?;
    if value.is_empty() || value[0] != 0x02 {
        return Err(TokenError::InvalidScript(
            "not a frozen-form var2 push (missing leading 0x02)".into(),
        ));
    }

    // Strip the leading 0x02 frozen byte. The remainder is the original
    // pushed bytes (which for OP_1, OP_3..OP_16, OP_1NEGATE will be the
    // single-byte stack value rather than the original opcode form).
    Ok(encode_minimal_push(&value[1..]))
}

/// Decode a single push at offset 0 of `push` and return the bytes that the
/// push places on the stack. Handles all push forms in the STAS 3.0 spec:
///
/// - `OP_0` (`0x00`) → empty
/// - bare push `0x01..=0x4b` → following N bytes
/// - `OP_PUSHDATA1` / `OP_PUSHDATA2` / `OP_PUSHDATA4` → following N bytes
/// - `OP_1NEGATE` (`0x4f`) → `[0x81]` (the byte value -1 in script-num form)
/// - `OP_1` (`0x51`)..`OP_16` (`0x60`) → `[N]` (single byte value 1..16)
fn decode_push_value(push: &[u8]) -> Result<Vec<u8>, TokenError> {
    if push.is_empty() {
        return Err(TokenError::InvalidScript("empty push".into()));
    }
    let opcode = push[0];
    match opcode {
        0x00 => Ok(Vec::new()),
        0x01..=0x4b => {
            let len = opcode as usize;
            if push.len() < 1 + len {
                return Err(TokenError::InvalidScript(
                    "bare push truncated".into(),
                ));
            }
            Ok(push[1..1 + len].to_vec())
        }
        0x4c => {
            if push.len() < 2 {
                return Err(TokenError::InvalidScript("truncated OP_PUSHDATA1".into()));
            }
            let len = push[1] as usize;
            if push.len() < 2 + len {
                return Err(TokenError::InvalidScript("OP_PUSHDATA1 truncated".into()));
            }
            Ok(push[2..2 + len].to_vec())
        }
        0x4d => {
            if push.len() < 3 {
                return Err(TokenError::InvalidScript("truncated OP_PUSHDATA2".into()));
            }
            let len = u16::from_le_bytes([push[1], push[2]]) as usize;
            if push.len() < 3 + len {
                return Err(TokenError::InvalidScript("OP_PUSHDATA2 truncated".into()));
            }
            Ok(push[3..3 + len].to_vec())
        }
        0x4e => {
            if push.len() < 5 {
                return Err(TokenError::InvalidScript("truncated OP_PUSHDATA4".into()));
            }
            let len =
                u32::from_le_bytes([push[1], push[2], push[3], push[4]]) as usize;
            if push.len() < 5 + len {
                return Err(TokenError::InvalidScript("OP_PUSHDATA4 truncated".into()));
            }
            Ok(push[5..5 + len].to_vec())
        }
        // OP_1NEGATE pushes the script-num form of -1 (i.e. 0x81).
        0x4f => Ok(vec![0x81]),
        // OP_1..=OP_16 push the integer N (single byte 0x01..0x10).
        0x51..=0x60 => Ok(vec![opcode - 0x50]),
        _ => Err(TokenError::InvalidScript(format!(
            "unsupported push opcode 0x{:02x}",
            opcode
        ))),
    }
}

/// Encode `data` as a minimal push: empty → `OP_0`, 1..=75 → bare push,
/// 76..=255 → OP_PUSHDATA1, 256..=65535 → OP_PUSHDATA2, larger → OP_PUSHDATA4.
fn encode_minimal_push(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 5);
    push_data(&mut out, data);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::reader::read_locking_script;
    use crate::ScriptType;

    #[test]
    fn build_and_read_roundtrip_unfrozen() {
        let owner_pkh = [0xaa; 20];
        let redemption_pkh = [0xbb; 20];

        let script = build_stas3_locking_script(
            &owner_pkh,
            &redemption_pkh,
            None,
            false,
            true,
            &[],
            &[],
        )
        .unwrap();

        let parsed = read_locking_script(script.to_bytes());
        assert_eq!(parsed.script_type, ScriptType::Stas3);

        let stas3 = parsed.stas3.unwrap();
        assert_eq!(stas3.owner, owner_pkh);
        assert_eq!(stas3.redemption, redemption_pkh);
        assert!(!stas3.frozen);
    }

    #[test]
    fn build_and_read_roundtrip_frozen() {
        let owner_pkh = [0xcc; 20];
        let redemption_pkh = [0xdd; 20];

        let script = build_stas3_locking_script(
            &owner_pkh,
            &redemption_pkh,
            None,
            true,
            true,
            &[],
            &[],
        )
        .unwrap();

        let parsed = read_locking_script(script.to_bytes());
        assert_eq!(parsed.script_type, ScriptType::Stas3);

        let stas3 = parsed.stas3.unwrap();
        assert_eq!(stas3.owner, owner_pkh);
        assert_eq!(stas3.redemption, redemption_pkh);
        assert!(stas3.frozen);
    }

    #[test]
    fn build_flags_freezable() {
        assert_eq!(build_stas3_flags(true), vec![0x01]);
    }

    #[test]
    fn build_flags_not_freezable() {
        assert_eq!(build_stas3_flags(false), vec![0x00]);
    }

    // -----------------------------------------------------------------------
    // Fix J: Frozen marker conversion (spec §6.2)
    // -----------------------------------------------------------------------

    /// Helper: build a freeze test case.  Returns (label, original_push,
    /// expected_frozen_push, value_after_unfreeze_in_minimal_form).
    ///
    /// For bare-opcode forms (OP_1, OP_3..OP_16, OP_1NEGATE) the round-trip
    /// is value-preserving but NOT byte-preserving on the opcode side: per
    /// spec §6.2 they must first be converted to pushdata form before
    /// freezing, and unfreeze leaves them in pushdata form.
    fn freeze_case(label: &str, original: Vec<u8>, expected_frozen: Vec<u8>, expected_unfrozen: Vec<u8>) {
        let frozen = freeze_var2_push(&original).unwrap_or_else(|e| {
            panic!("freeze_var2_push({}) failed: {:?}", label, e)
        });
        assert_eq!(
            frozen, expected_frozen,
            "{}: freeze produced {} but expected {}",
            label,
            hex::encode(&frozen),
            hex::encode(&expected_frozen)
        );
        let unfrozen = unfreeze_var2_push(&frozen).unwrap_or_else(|e| {
            panic!("unfreeze_var2_push({}) failed: {:?}", label, e)
        });
        assert_eq!(
            unfrozen, expected_unfrozen,
            "{}: unfreeze produced {} but expected {}",
            label,
            hex::encode(&unfrozen),
            hex::encode(&expected_unfrozen)
        );
    }

    #[test]
    fn freeze_var2_op_0_to_op_2() {
        // empty push (OP_0) → OP_2 (single byte 0x52)
        // unfreeze: OP_2 → OP_0
        freeze_case("OP_0", vec![0x00], vec![0x52], vec![0x00]);
    }

    #[test]
    fn freeze_var2_pushdata_prepends_02() {
        // direct push 1 byte: 0x01 0xAB → frozen body [0x02, 0xAB]
        freeze_case(
            "push_1_byte",
            vec![0x01, 0xAB],
            vec![0x02, 0x02, 0xAB],
            vec![0x01, 0xAB],
        );
        // direct push 5 bytes
        freeze_case(
            "push_5_bytes",
            vec![0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
            vec![0x06, 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
            vec![0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
        );
    }

    #[test]
    fn freeze_var2_op_pushdata1() {
        // OP_PUSHDATA1 with 80-byte body — minimal-LE re-encoding still uses PUSHDATA1.
        let body: Vec<u8> = (0..80).map(|i| i as u8).collect();
        let mut original = vec![0x4cu8, 80];
        original.extend_from_slice(&body);

        // Frozen body: [0x02] + body, length 81 → still > 75, still PUSHDATA1.
        let mut frozen_body = vec![0x02u8];
        frozen_body.extend_from_slice(&body);
        let mut expected_frozen = vec![0x4cu8, 81];
        expected_frozen.extend_from_slice(&frozen_body);

        // Unfreeze: original body re-encoded minimal → PUSHDATA1 with 80 bytes.
        let mut expected_unfrozen = vec![0x4cu8, 80];
        expected_unfrozen.extend_from_slice(&body);

        freeze_case("PUSHDATA1_80", original, expected_frozen, expected_unfrozen);
    }

    #[test]
    fn freeze_var2_op_pushdata2() {
        // OP_PUSHDATA2 with 300-byte body.
        let body: Vec<u8> = (0..300).map(|i| (i & 0xFF) as u8).collect();
        let mut original = vec![0x4du8, 0x2C, 0x01]; // 300 LE = 0x012C
        original.extend_from_slice(&body);

        let mut frozen_body = vec![0x02u8];
        frozen_body.extend_from_slice(&body);
        // 301 = 0x012D LE
        let mut expected_frozen = vec![0x4du8, 0x2D, 0x01];
        expected_frozen.extend_from_slice(&frozen_body);

        // unfreeze body length 300 → PUSHDATA2 again.
        let mut expected_unfrozen = vec![0x4du8, 0x2C, 0x01];
        expected_unfrozen.extend_from_slice(&body);

        freeze_case("PUSHDATA2_300", original, expected_frozen, expected_unfrozen);
    }

    #[test]
    fn freeze_var2_op_1_to_pushdata_form() {
        // OP_1 (0x51) pushes the integer 1. Freeze MUST first convert to
        // pushdata form (push the value 0x01 = 1 as a single byte), then
        // prepend 0x02 → frozen body = [0x02, 0x01].
        // Unfreeze yields [0x01] re-encoded minimal = bare push [0x01, 0x01].
        freeze_case(
            "OP_1",
            vec![0x51],
            vec![0x02, 0x02, 0x01],
            vec![0x01, 0x01],
        );
    }

    #[test]
    fn freeze_var2_op_3_to_pushdata_form() {
        // OP_3 (0x53) → push value 0x03 → frozen [0x02, 0x03] (2 bytes).
        freeze_case(
            "OP_3",
            vec![0x53],
            vec![0x02, 0x02, 0x03],
            vec![0x01, 0x03],
        );
    }

    #[test]
    fn freeze_var2_op_16_to_pushdata_form() {
        // OP_16 (0x60) → push value 0x10 (16) → frozen body [0x02, 0x10].
        freeze_case(
            "OP_16",
            vec![0x60],
            vec![0x02, 0x02, 0x10],
            vec![0x01, 0x10],
        );
    }

    #[test]
    fn freeze_var2_op_1negate_to_pushdata_form() {
        // OP_1NEGATE (0x4f) pushes -1 in script-num form, encoded as 0x81.
        // Freeze: prepend 0x02 → frozen body [0x02, 0x81].
        freeze_case(
            "OP_1NEGATE",
            vec![0x4f],
            vec![0x02, 0x02, 0x81],
            vec![0x01, 0x81],
        );
    }

    #[test]
    fn freeze_var2_table_driven_round_trip() {
        // Comprehensive table covering every OP_N in the spec.
        for n in 1u8..=16 {
            if n == 2 { continue; } // OP_2 means frozen, not a freezable input
            let opcode = 0x50 + n;
            let original = vec![opcode];
            let frozen = freeze_var2_push(&original).expect("freeze should work");
            let unfrozen = unfreeze_var2_push(&frozen).expect("unfreeze should work");
            // After unfreeze we get the value-byte in minimal pushdata form.
            assert_eq!(unfrozen, vec![0x01, n], "round-trip OP_{}", n);
        }
    }

    #[test]
    fn unfreeze_op_2_yields_op_0() {
        let unfrozen = unfreeze_var2_push(&[0x52]).unwrap();
        assert_eq!(unfrozen, vec![0x00]);
    }

    #[test]
    fn unfreeze_rejects_non_frozen() {
        // Plain bare push without 0x02 prefix is not a frozen form.
        let result = unfreeze_var2_push(&[0x02, 0x03, 0xCA, 0xFE]); // body [0x03, 0xCA, 0xFE]
        assert!(
            result.is_err(),
            "non-frozen body (no leading 0x02) must error"
        );
    }

    #[test]
    fn build_with_service_fields() {
        let owner_pkh = [0x11; 20];
        let redemption_pkh = [0x22; 20];
        let service = vec![vec![0x01, 0x02, 0x03]];

        let script = build_stas3_locking_script(
            &owner_pkh,
            &redemption_pkh,
            None,
            false,
            false,
            &service,
            &[],
        )
        .unwrap();

        let parsed = read_locking_script(script.to_bytes());
        assert_eq!(parsed.script_type, ScriptType::Stas3);

        let stas3 = parsed.stas3.unwrap();
        assert_eq!(stas3.owner, owner_pkh);
        assert_eq!(stas3.redemption, redemption_pkh);
        assert!(!stas3.service_fields.is_empty());
        assert_eq!(stas3.service_fields[0], vec![0x01, 0x02, 0x03]);
    }
}
