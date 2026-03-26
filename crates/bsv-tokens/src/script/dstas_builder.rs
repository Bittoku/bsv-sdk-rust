//! Builder for DSTAS (stas3-freeze-multisig) locking scripts.

use bsv_script::Script;

use crate::error::TokenError;
use crate::types::{ActionData};

/// The compiled DSTAS base template bytes (hex-encoded).
/// Extracted from dxs-stas-sdk `stas3-freeze-multisig-base.ts`.
const DSTAS_BASE_TEMPLATE_HEX: &str = "6d82736301218763007b7b517c6e5667766b517f786b517f73637c7f68517f73637c7f68517f73637c7f68517f73637c7f68517f73637c7f68766c936c7c5493686751687652937a76aa607f5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7c5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e011f7f7d7e01007e8111414136d08c5ed2bf3ba048afe6dcaebafe01005f80837e01007e7652967b537a7601ff877c0100879b7d648b6752799368537a7d9776547aa06394677768263044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802207c607f5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7c5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e01417e7c6421038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b92186721023635954789a02e39fb7e54440b6f528d53efd65635ddad7f3c4085f97fdbdc4868ad547f7701207f01207f7701247f517f7801007e02fd00a063546752687f7801007e817f727e7b517f7c01147d887f517f7c01007e817601619f6976014ea063517c7b6776014ba06376014da063755467014d9c6352675168687f7c01007e81687f007b7b687602fd0a7f7701147f7c5579876b826475020100686b587a5893766b7a765155a569005379736382013ca07c517f7c51877b9a6352795487637101007c7e717101207f01147f75777c7567756c766b8b8b79518868677568686c6c7c6b517f7c817f788273638c7f776775010068518463517f7c01147d887f547952876372777c717c767663517f756852875779766352790152879a689b63517f77567a7567527c7681014f0161a5587a9a63015094687e68746c766b5c9388748c76795879888c8c7978886777717c767663517f7568528778015287587a9a9b745394768b797663517f756852877c6c766b5c936ea0637c8c768b797663517f75685287726b9b7c6c686ea0637c5394768b797663517f75685287726b9b7c6c686ea063755494797663517f756852879b676d689b63006968687c717167567a75686d7c518763755279686c755879a9886b6b6b6b6b6b6b827763af686c6c6c6c6c6c6c547a577a7664577a577a587a597a786354807e7e676d68aa880067765158a569765187645294587a53795a7a7e7e78637c8c7c53797e597a7e6878637c8c7c53797e597a7e6878637c8c7c53797e597a7e6878637c8c7c53797e597a7e6878637c8c7c53797e597a7e6867587a6876aa5a7a7d54807e597a5b7a5c7a786354807e6f7e7eaa727c7e676d6e7eaa7c687b7eaa5a7a7d877663516752687c72879b69537a6491687c7b547f77517f7853a0916901247f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e816854937f77788c6301247f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e816854937f777852946301247f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e816854937f77686877517f7c52797d8b9f7c53a09b91697c76638c7c587f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81687f777c6876638c7c587f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81687f777c6863587f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81687f7768587f517f7801007e817602fc00a06302fd00a063546752687f7801007e81727e7b7b687f75517f7c01147d887f517f7c01007e817601619f6976014ea0637c6776014ba06376014da063755467014d9c6352675168687f7c01007e81687f68557964577988756d67716881687863567a677b68587f7c8153796353795287637b6b537a6b717c6b6b537a6b676b577a6b597a6b587a6b577a6b7c68677b93687c547f7701207f75748c7a7669765880044676a914780114748c7a76727b748c7a768291788251877c764f877c81510111a59b9a9b648276014ba1647602ff00a16351014c677603ffff00a16352014d6754014e68687b7b7f757e687c7e67736301509367010068685c795c79636c766b7363517f7c51876301207f7c5279a8877c011c7f5579877c01147f755679879a9a6967756868687e777e7e827602fc00a0637603ffff00a06301fe7c82546701fd7c8252687da0637f756780687e67517f75687c7e7e0a888201218763ac67517f07517f73637c7f6876767e767e7e02ae687e7e7c557a00740111a063005a79646b7c748c7a76697d937b7b58807e6c91677c748c7a7d58807e6c6c6c557a680114748c7a748c7a768291788251877c764f877c81510111a59b9a9b648276014ba1647602ff00a16351014c677603ffff00a16352014d6754014e68687b7b7f757e687c7e67736301509367010068685479635f79676c766b0115797363517f7c51876301207f7c5279a8877c011c7f5579877c01147f755679879a9a6967756868687e777e7e827602fc00a0637603ffff00a06301fe7c82546701fd7c8252687da0637f756780687e67517f75687c7e7c637e677c6b7c6b7c6b7e7c6b68685979636c6c766b786b7363517f7c51876301347f77547f547f75786352797b01007e81957c01007e81965379a169676d68677568685c797363517f7c51876301347f77547f547f75786354797b01007e81957c01007e819678a169676d68677568687568740111a063748c7a76697d58807e00005c79635e79768263517f756851876c6c766b7c6b768263517f756851877b6e9b63789c6375745294797b78877b7b877d9b69637c917c689167745294797c638777637c917c91686777876391677c917c686868676d6d68687863537a6c936c6c6c567a567a54795479587a676b72937b7b5c795e796c68748c7a748c7a7b636e717b7b877b7b879a6967726d6801147b7e7c8291788251877c764f877c81510111a59b9a9b648276014ba1647602ff00a16351014c677603ffff00a16352014d6754014e68687b7b7f757e687c7e67736301509367010068687e7c636c766b7e726b6b726b6b675b797e68827602fc00a0637603ffff00a06301fe7c82546701fd7c8252687da0637f756780687e67517f75687c7e7e68740111a063748c7a76697d58807e00005c79635e79768263517f756851876c6c766b7c6b768263517f756851877b6e9b63789c6375745294797b78877b7b877d9b69637c917c689167745294797c638777637c917c91686777876391677c917c686868676d6d68687863537a6c936c6c6c567a567a54795479587a676b72937b7b5c795e796c68748c7a748c7a7b636e717b7b877b7b879a6967726d6801147b7e7c8291788251877c764f877c81510111a59b9a9b648276014ba1647602ff00a16351014c677603ffff00a16352014d6754014e68687b7b7f757e687c7e67736301509367010068687e7c636c766b7e726b6b726b6b675b797e68827602fc00a0637603ffff00a06301fe7c82546701fd7c8252687da0637f756780687e67517f75687c7e7e68597a636c6c6c6d6c6c6d6c9d687c587a9d7d7e5c79635d795880041976a9145e797e0288ac7e7e6700687d7e5c7a766302006a7c7e827602fc00a06301fd7c7e536751687f757c7e0058807c7e687d7eaa6b7e7e7e7e7e7eaa78877c6c877c6c9a9b726d726d77776a";

/// Build a DSTAS locking script from parameters.
///
/// # Arguments
/// * `params` - The locking parameters including address, spend type, and action data
/// * `redemption_pkh` - The 20-byte redemption public key hash
/// * `frozen` - Whether the token is frozen
/// * `flags` - Flags bytes (use `build_dstas_flags` helper)
/// * `service_fields` - Additional service field data pushes
/// * `optional_data` - Additional optional data pushes
pub fn build_dstas_locking_script(
    owner_pkh: &[u8; 20],
    redemption_pkh: &[u8; 20],
    action_data: Option<&ActionData>,
    frozen: bool,
    freezable: bool,
    service_fields: &[Vec<u8>],
    optional_data: &[Vec<u8>],
) -> Result<Script, TokenError> {
    let base_template = hex::decode(DSTAS_BASE_TEMPLATE_HEX)
        .map_err(|e| TokenError::InvalidScript(format!("dstas template decode error: {e}")))?;

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
    let flags = build_dstas_flags(freezable);
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
pub fn build_dstas_flags(freezable: bool) -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::reader::read_locking_script;
    use crate::ScriptType;

    #[test]
    fn build_and_read_roundtrip_unfrozen() {
        let owner_pkh = [0xaa; 20];
        let redemption_pkh = [0xbb; 20];

        let script = build_dstas_locking_script(
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
        assert_eq!(parsed.script_type, ScriptType::Dstas);

        let dstas = parsed.dstas.unwrap();
        assert_eq!(dstas.owner, owner_pkh);
        assert_eq!(dstas.redemption, redemption_pkh);
        assert!(!dstas.frozen);
    }

    #[test]
    fn build_and_read_roundtrip_frozen() {
        let owner_pkh = [0xcc; 20];
        let redemption_pkh = [0xdd; 20];

        let script = build_dstas_locking_script(
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
        assert_eq!(parsed.script_type, ScriptType::Dstas);

        let dstas = parsed.dstas.unwrap();
        assert_eq!(dstas.owner, owner_pkh);
        assert_eq!(dstas.redemption, redemption_pkh);
        assert!(dstas.frozen);
    }

    #[test]
    fn build_flags_freezable() {
        assert_eq!(build_dstas_flags(true), vec![0x01]);
    }

    #[test]
    fn build_flags_not_freezable() {
        assert_eq!(build_dstas_flags(false), vec![0x00]);
    }

    #[test]
    fn build_with_service_fields() {
        let owner_pkh = [0x11; 20];
        let redemption_pkh = [0x22; 20];
        let service = vec![vec![0x01, 0x02, 0x03]];

        let script = build_dstas_locking_script(
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
        assert_eq!(parsed.script_type, ScriptType::Dstas);

        let dstas = parsed.dstas.unwrap();
        assert_eq!(dstas.owner, owner_pkh);
        assert_eq!(dstas.redemption, redemption_pkh);
        assert!(!dstas.service_fields.is_empty());
        assert_eq!(dstas.service_fields[0], vec![0x01, 0x02, 0x03]);
    }
}
