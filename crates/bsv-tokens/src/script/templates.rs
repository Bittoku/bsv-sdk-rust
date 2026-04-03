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
