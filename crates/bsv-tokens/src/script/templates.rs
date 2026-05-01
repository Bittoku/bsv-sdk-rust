//! Byte-pattern constants for classifying STAS script versions.
//!
//! These constants are derived from the TAAL stas-js v2 template and the
//! dxs-stas-sdk stas3-freeze-multisig template.

/// STAS v2 prefix: OP_DUP OP_HASH160 OP_DATA_20.
pub const STAS_V2_PREFIX: [u8; 3] = [0x76, 0xa9, 0x14];

/// Bytes immediately after the 20-byte owner PKH in a STAS v2 script:
/// OP_EQUALVERIFY OP_CHECKSIG OP_VERIFY OP_DUP OP_HASH160 OP_16.
pub const STAS_V2_MARKER: [u8; 6] = [0x88, 0xac, 0x69, 0x76, 0xaa, 0x60];

/// Offset of the owner public key hash in a STAS v2 script (bytes 3..23).
pub const STAS_V2_OWNER_OFFSET: usize = 3;

/// Length of the owner public key hash (20 bytes).
pub const PKH_LEN: usize = 20;

/// Offset where the post-owner marker begins (byte 23).
pub const STAS_V2_MARKER_OFFSET: usize = STAS_V2_OWNER_OFFSET + PKH_LEN;

/// Total length of the STAS v2 template (owner + body + OP_RETURN + redemption),
/// excluding appended OP_RETURN data (flags/symbol/data).
pub const STAS_V2_TEMPLATE_LEN: usize = 1431;

/// Offset of OP_RETURN (0x6a) in the STAS v2 template.
pub const STAS_V2_OP_RETURN_OFFSET: usize = 1409;

/// Offset of the redemption PKH in the STAS v2 template (bytes 1411..1431).
/// Preceded by OP_DATA_20 (0x14) at offset 1410.
pub const STAS_V2_REDEMPTION_OFFSET: usize = 1411;

/// Minimum length for a valid STAS v2 script (template + at least 1 byte of OP_RETURN data).
pub const STAS_V2_MIN_LEN: usize = STAS_V2_TEMPLATE_LEN + 1;

/// STAS3 (stas3-freeze-multisig) base template prefix opcodes.
/// OP_2MUL OP_SIZE OP_OVER OP_IF.
pub const STAS3_BASE_PREFIX: [u8; 4] = [0x6d, 0x82, 0x73, 0x63];

/// Length of the compiled STAS3 base template in bytes.
pub const STAS3_BASE_TEMPLATE_LEN: usize = 2812;

/// Standard P2PKH locking script length (25 bytes).
pub const P2PKH_LEN: usize = 25;

/// P2PKH prefix: OP_DUP OP_HASH160 OP_DATA_20.
pub const P2PKH_PREFIX: [u8; 3] = [0x76, 0xa9, 0x14];

/// P2PKH suffix: OP_EQUALVERIFY OP_CHECKSIG.
pub const P2PKH_SUFFIX: [u8; 2] = [0x88, 0xac];

/// Total length of the STAS 3.0 P2MPKH locking script body, in bytes.
///
/// The P2MPKH locking script (spec § 10.2) is a fixed 70-byte template:
///   `[3-byte prefix][20-byte MPKH][47-byte suffix]`
pub const P2MPKH_LOCKING_LEN: usize = 70;

/// STAS 3.0 P2MPKH locking-script prefix: OP_DUP OP_HASH160 OP_DATA_20.
pub const P2MPKH_LOCKING_PREFIX: [u8; 3] = [0x76, 0xa9, 0x14];

/// STAS 3.0 P2MPKH locking-script suffix (the 47 bytes that follow the
/// 20-byte `MPKH`).  Spec § 10.2 reference assembly:
/// `OP_EQUALVERIFY OP_SIZE 0x21 OP_EQUAL OP_IF OP_CHECKSIG OP_ELSE
///  OP_1 OP_SPLIT (OP_1 OP_SPLIT OP_IFDUP OP_IF OP_SWAP OP_SPLIT OP_ENDIF)×5
///  OP_CHECKMULTISIG OP_ENDIF`
pub const P2MPKH_LOCKING_SUFFIX: [u8; 47] = [
    0x88, 0x82, 0x01, 0x21, 0x87, 0x63, 0xac, 0x67, 0x51, 0x7f, 0x51, 0x7f, 0x73, 0x63, 0x7c, 0x7f,
    0x68, 0x51, 0x7f, 0x73, 0x63, 0x7c, 0x7f, 0x68, 0x51, 0x7f, 0x73, 0x63, 0x7c, 0x7f, 0x68, 0x51,
    0x7f, 0x73, 0x63, 0x7c, 0x7f, 0x68, 0x51, 0x7f, 0x73, 0x63, 0x7c, 0x7f, 0x68, 0xae, 0x68,
];

/// Build the fixed 70-byte STAS 3.0 P2MPKH locking script for a given `MPKH`.
///
/// # Arguments
/// * `mpkh` – 20-byte HASH160 of a STAS 3.0 redeem script.
///
/// # Returns
/// A 70-byte array containing the locking-script body.
pub fn build_p2mpkh_locking_script(mpkh: [u8; 20]) -> [u8; P2MPKH_LOCKING_LEN] {
    let mut out = [0u8; P2MPKH_LOCKING_LEN];
    out[..3].copy_from_slice(&P2MPKH_LOCKING_PREFIX);
    out[3..23].copy_from_slice(&mpkh);
    out[23..].copy_from_slice(&P2MPKH_LOCKING_SUFFIX);
    out
}

/// `EMPTY_HASH160 = HASH160("")` — the 20-byte sentinel used by STAS 3.0
/// to mean "skip authority check" in owner / arbitrator slots
/// (spec § 10.2).
pub const EMPTY_HASH160: [u8; 20] = [
    0xb4, 0x72, 0xa2, 0x66, 0xd0, 0xbd, 0x89, 0xc1, 0x37, 0x06, 0xa4, 0x13, 0x2c, 0xcf, 0xb1, 0x6f,
    0x7c, 0x3b, 0x9f, 0xcb,
];
