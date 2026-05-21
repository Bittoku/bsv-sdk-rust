//! STAS 3.0 atomic-swap & merge piece-array encoding (spec v0.2.3 §8, §9.5).
//!
//! For `txType = 1` (atomic swap), the unlocking script's trailing parameters
//! are:
//!
//! ```text
//! pushdata(counterparty_locking_script)
//! pushdata(piece_count)
//! pushdata(piece_1) pushdata(piece_2) ... pushdata(piece_N)
//! ```
//!
//! For `txType = 2..7` (merge variants) the trailing parameters are the same
//! minus the leading counterparty script:
//!
//! ```text
//! pushdata(piece_count)
//! pushdata(piece_1) pushdata(piece_2) ... pushdata(piece_N)
//! ```
//!
//! "Pieces" are produced from the **preceding transaction** of an asset input
//! by excising the asset's locking script bytes (everything past the two
//! variable parameters at the very start of the STAS script — i.e. past
//! `[OP_DATA_20 + 20B owner][var2 push]`) from each named output, then
//! splitting the remaining preceding-tx bytes around those excised regions
//! (everything BEFORE the first asset, BETWEEN consecutive assets, and
//! AFTER the last). The piece array is reverse-ordered.
//!
//! ## Wire format (spec v0.2.3 §9.5 / §8)
//!
//! Each piece is **its own `OP_PUSHDATA` operation** in the unlocking
//! script. The canonical on-chain engine
//! (`github.com/stassso/STAS-3-script-templates`) consumes them via an
//! unrolled, counter-driven block:
//!
//! ```text
//! OP_OVER OP_IF OP_SWAP OP_1SUB OP_SWAP OP_3 OP_PICK OP_CAT OP_10 OP_ROLL OP_CAT OP_ENDIF
//! ```
//!
//! repeated 5×, driven by a decrementing `piece_count` counter sitting on
//! top of the stack. Each iteration takes one piece off the stack and
//! concatenates it into the reconstructed preceding tx; the guard
//! (`OP_OVER OP_IF`) skips iterations once the counter hits zero, which
//! is what makes the same template handle 1..6 pieces uniformly. There
//! is therefore **no concatenated length-prefixed blob** and **no
//! per-piece size limit** — the earlier "127-byte piece limit" was a
//! phantom created by the obsolete 1-byte length-prefix scheme and does
//! not exist in the protocol.
//!
//! The trailing-param block is the concatenation of independent Bitcoin
//! pushdata operations, each opcode chosen by size (direct `0x01..=0x4b`,
//! `OP_PUSHDATA1/2/4`):
//!
//! ```text
//! [merge]  push(piece_count) push(piece_1) ... push(piece_N)
//! [swap ]  push(counterparty_script) push(piece_count) push(piece_1) ... push(piece_N)
//! ```
//!
//! `piece_count` is encoded as a **minimal Bitcoin numeric push** — DXS's
//! convention (`ScriptBuilder.addNumber(n)`): for `n ∈ 1..=16` this emits
//! the single opcode `OP_<n>` (`0x50 + n`); for `n ∈ 17..=127` it emits
//! a 2-byte direct push `0x01 <n>`. The engine decrements this value via
//! `OP_1SUB` and tests it via `OP_OVER OP_IF` on each unrolled iteration.

use crate::error::TokenError;

// ---------------------------------------------------------------------------
// Bitcoin pushdata framing
// ---------------------------------------------------------------------------

/// Append a single Bitcoin pushdata operation for `data` to `out`.
///
/// Uses standard push framing, opcode chosen by size:
/// * empty            → `OP_0` (0x00)
/// * `1..=75` bytes   → direct push `0x01..=0x4b`
/// * `76..=255`       → `OP_PUSHDATA1`
/// * `256..=65535`    → `OP_PUSHDATA2`
/// * larger           → `OP_PUSHDATA4`
fn append_pushdata(out: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len == 0 {
        out.push(0x00);
    } else if len <= 0x4b {
        out.push(len as u8);
    } else if len <= 0xff {
        out.push(0x4c);
        out.push(len as u8);
    } else if len <= 0xffff {
        out.push(0x4d);
        out.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        out.push(0x4e);
        out.extend_from_slice(&(len as u32).to_le_bytes());
    }
    out.extend_from_slice(data);
}

/// Append a single Bitcoin numeric push for the unsigned value `n` to
/// `out`, using the minimal encoding chosen by DXS's `ScriptBuilder.addNumber`:
///
/// * `n == 0`         → `OP_0` (0x00)
/// * `n ∈ 1..=16`     → single opcode `OP_<n>` (`0x50 + n`)
/// * `n ∈ 17..=127`   → 2-byte direct push `0x01 <n>` (positive script-num)
/// * `n ∈ 128..=255`  → 3-byte push `0x02 <n> 0x00` (sign-bit sentinel)
///
/// This is the wire shape the canonical STAS 3.0 engine consumes for
/// `piece_count`: a single-stack-item Bitcoin numeric value that the
/// engine decrements via `OP_1SUB` and tests via `OP_OVER OP_IF` on each
/// unrolled iteration of the piece consumer.
fn append_minimal_numeric_push(out: &mut Vec<u8>, n: u8) {
    match n {
        0 => out.push(0x00),
        1..=16 => out.push(0x50 + n),
        17..=127 => {
            out.push(0x01);
            out.push(n);
        }
        _ => {
            out.push(0x02);
            out.push(n);
            out.push(0x00);
        }
    }
}

/// Read a single Bitcoin pushdata operation from `bytes` starting at
/// `cursor`. Returns `(body, num_bytes_consumed)`.
///
/// Recognises the data pushes (`OP_0`, `0x01..=0x4b`, `OP_PUSHDATA1/2/4`)
/// as well as the numeric stack-pushing opcodes (`OP_1NEGATE`,
/// `OP_1`..`OP_16`). Numeric opcodes are returned as 1-byte bodies
/// containing the script-num value they push (`OP_1NEGATE` → `[0x81]`,
/// `OP_<n>` → `[n]` for `n ∈ 1..=16`). This lets the parser uniformly
/// treat `piece_count` whether it was emitted as a numeric opcode (the
/// DXS convention for `n ∈ 1..=16`) or as a direct push.
fn read_pushdata(bytes: &[u8], cursor: usize) -> Result<(Vec<u8>, usize), TrailingParamsError> {
    if cursor >= bytes.len() {
        return Err(TrailingParamsError::Truncated(cursor));
    }
    let opcode = bytes[cursor];
    match opcode {
        0x00 => Ok((Vec::new(), 1)),
        // OP_1NEGATE pushes the script-num -1 (1-byte encoding 0x81).
        0x4f => Ok((vec![0x81], 1)),
        // OP_1..=OP_16 push the integer N (single byte 0x01..0x10).
        0x51..=0x60 => Ok((vec![opcode - 0x50], 1)),
        0x01..=0x4b => {
            let len = opcode as usize;
            let start = cursor + 1;
            let end = start
                .checked_add(len)
                .ok_or(TrailingParamsError::Truncated(cursor))?;
            if end > bytes.len() {
                return Err(TrailingParamsError::Truncated(cursor));
            }
            Ok((bytes[start..end].to_vec(), 1 + len))
        }
        0x4c => {
            if cursor + 1 >= bytes.len() {
                return Err(TrailingParamsError::Truncated(cursor));
            }
            let len = bytes[cursor + 1] as usize;
            let start = cursor + 2;
            let end = start
                .checked_add(len)
                .ok_or(TrailingParamsError::Truncated(cursor))?;
            if end > bytes.len() {
                return Err(TrailingParamsError::Truncated(cursor));
            }
            Ok((bytes[start..end].to_vec(), 2 + len))
        }
        0x4d => {
            if cursor + 2 >= bytes.len() {
                return Err(TrailingParamsError::Truncated(cursor));
            }
            let len = u16::from_le_bytes([bytes[cursor + 1], bytes[cursor + 2]]) as usize;
            let start = cursor + 3;
            let end = start
                .checked_add(len)
                .ok_or(TrailingParamsError::Truncated(cursor))?;
            if end > bytes.len() {
                return Err(TrailingParamsError::Truncated(cursor));
            }
            Ok((bytes[start..end].to_vec(), 3 + len))
        }
        0x4e => {
            if cursor + 4 >= bytes.len() {
                return Err(TrailingParamsError::Truncated(cursor));
            }
            let len = u32::from_le_bytes([
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
                bytes[cursor + 4],
            ]) as usize;
            let start = cursor + 5;
            let end = start
                .checked_add(len)
                .ok_or(TrailingParamsError::Truncated(cursor))?;
            if end > bytes.len() {
                return Err(TrailingParamsError::Truncated(cursor));
            }
            Ok((bytes[start..end].to_vec(), 5 + len))
        }
        _ => Err(TrailingParamsError::InvalidPushdata(cursor)),
    }
}

/// Encoded byte length of a pushdata operation for `data` (header + body).
#[cfg(test)]
fn pushdata_len(data: &[u8]) -> usize {
    let len = data.len();
    let header = if len == 0 || len <= 0x4b {
        1
    } else if len <= 0xff {
        2
    } else if len <= 0xffff {
        3
    } else {
        5
    };
    header + len
}

/// Encoded trailing-param block for a STAS 3.0 atomic-swap unlocking script
/// (`txType = 1`).
///
/// # Arguments
/// * `counterparty_locking_script` — full locking script of the counterparty
///   asset UTXO.
/// * `preceding_tx`               — raw serialized preceding-transaction bytes
///   (the transaction that produced the counterparty UTXO).
/// * `asset_output_indices`       — indices in `preceding_tx` of the STAS-shaped
///   outputs whose asset locking-script bytes must be excised.
///
/// # Returns
/// A byte vector that is the concatenation of independent Bitcoin pushdata
/// operations:
/// `push(counterparty_locking_script) ‖ push(piece_count) ‖ push(piece_1) ‖
/// … ‖ push(piece_N)`. The block is ready to append verbatim to an
/// unlocking script.
///
/// # Errors
/// * [`TokenError::InvalidScript`] — when `asset_output_indices` is empty,
///   when an index points at a non-STAS-shaped output, or when
///   `preceding_tx` is malformed.
pub fn encode_atomic_swap_trailing_params(
    counterparty_locking_script: &[u8],
    preceding_tx: &[u8],
    asset_output_indices: &[u32],
) -> Result<Vec<u8>, TokenError> {
    if asset_output_indices.is_empty() {
        return Err(TokenError::InvalidScript(
            "atomic-swap pieces: asset_output_indices must be non-empty".into(),
        ));
    }
    let pieces = build_pieces_from_tx(preceding_tx, asset_output_indices)?;
    let piece_count: u8 = pieces.len().try_into().map_err(|_| {
        TokenError::InvalidScript("atomic-swap pieces: piece count exceeds u8 range".into())
    })?;

    let mut out = Vec::new();
    append_pushdata(&mut out, counterparty_locking_script);
    append_minimal_numeric_push(&mut out, piece_count);
    for piece in &pieces {
        append_pushdata(&mut out, piece);
    }
    Ok(out)
}

/// Encoded trailing-param block for a STAS 3.0 merge unlocking script
/// (`txType = 2..=7`).
///
/// `piece_count` must equal `txType` (range 2..=7) per spec §8.
///
/// # Returns
/// A byte vector that is the concatenation of independent Bitcoin pushdata
/// operations: `push(piece_count) ‖ push(piece_1) ‖ … ‖ push(piece_N)`.
///
/// # Errors
/// * [`TokenError::InvalidScript`] — when `piece_count` is not in 2..=7,
///   when the produced piece-array length doesn't match `piece_count`,
///   when `asset_output_indices` is empty, or when `preceding_tx` is
///   malformed.
pub fn encode_merge_trailing_params(
    piece_count: u8,
    preceding_tx: &[u8],
    asset_output_indices: &[u32],
) -> Result<Vec<u8>, TokenError> {
    if !(2..=7).contains(&piece_count) {
        return Err(TokenError::InvalidScript(format!(
            "merge piece_count must be in 2..=7, got {piece_count}"
        )));
    }
    if asset_output_indices.is_empty() {
        return Err(TokenError::InvalidScript(
            "merge pieces: asset_output_indices must be non-empty".into(),
        ));
    }
    let pieces = build_pieces_from_tx(preceding_tx, asset_output_indices)?;
    if pieces.len() != piece_count as usize {
        return Err(TokenError::InvalidScript(format!(
            "merge piece_count ({}) does not match produced piece array length ({})",
            piece_count,
            pieces.len()
        )));
    }
    let mut out = Vec::new();
    append_minimal_numeric_push(&mut out, piece_count);
    for piece in &pieces {
        append_pushdata(&mut out, piece);
    }
    Ok(out)
}

/// Decoded trailing-param block from a STAS 3.0 unlocking script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTrailingParams {
    /// Counterparty locking script (only present for atomic-swap, `txType=1`).
    pub counterparty_locking_script: Option<Vec<u8>>,
    /// Declared piece count.
    pub piece_count: u8,
    /// Pieces in the encoded order (reverse-of-original per spec).
    pub pieces: Vec<Vec<u8>>,
}

/// Errors produced while parsing a STAS 3.0 trailing-param block.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrailingParamsError {
    /// Buffer too short to contain the expected fields.
    #[error("trailing params truncated at offset {0}")]
    Truncated(usize),
    /// A pushdata opcode at the given offset was invalid (not a push op).
    #[error("invalid pushdata opcode at offset {0}")]
    InvalidPushdata(usize),
    /// The `piece_count` push did not carry a single-byte numeric value.
    #[error("malformed piece_count push")]
    MalformedPieceCount,
    /// Declared piece count does not match the parsed array length.
    #[error("piece_count mismatch: declared {declared}, found {found}")]
    PieceCountMismatch {
        /// Piece count declared by the leading push.
        declared: u8,
        /// Number of pieces actually present in the array.
        found: usize,
    },
    /// `txType` argument out of supported range (must be 1..=7).
    #[error("unsupported tx_type {0}; expected 1..=7")]
    UnsupportedTxType(u8),
    /// Trailing bytes remain after consuming `piece_count` pushdata pieces.
    #[error("trailing bytes remain after piece_array (offset {0})")]
    TrailingBytesAfterPieces(usize),
}

/// Parse an existing trailing-param block.
///
/// The block is a sequence of independent Bitcoin pushdata operations:
/// for atomic swap (`tx_type = 1`) the first push is the counterparty
/// locking script, then `piece_count`, then `piece_count` piece pushes;
/// for merge (`tx_type = 2..=7`) the first push is `piece_count`, then the
/// pieces. No external length hints are required — each component is a
/// self-delimiting push.
pub fn parse_trailing_params(
    bytes: &[u8],
    tx_type: u8,
) -> Result<ParsedTrailingParams, TrailingParamsError> {
    if !(1..=7).contains(&tx_type) {
        return Err(TrailingParamsError::UnsupportedTxType(tx_type));
    }

    let mut cursor = 0usize;

    let counterparty_locking_script = if tx_type == 1 {
        let (cp, consumed) = read_pushdata(bytes, cursor)?;
        cursor += consumed;
        Some(cp)
    } else {
        None
    };

    let (count_body, consumed) = read_pushdata(bytes, cursor)?;
    cursor += consumed;
    if count_body.len() != 1 {
        return Err(TrailingParamsError::MalformedPieceCount);
    }
    let piece_count = count_body[0];

    let mut pieces: Vec<Vec<u8>> = Vec::with_capacity(piece_count as usize);
    for _ in 0..piece_count {
        let (piece, consumed) = read_pushdata(bytes, cursor)?;
        cursor += consumed;
        pieces.push(piece);
    }

    if cursor != bytes.len() {
        return Err(TrailingParamsError::TrailingBytesAfterPieces(cursor));
    }

    if pieces.len() != piece_count as usize {
        return Err(TrailingParamsError::PieceCountMismatch {
            declared: piece_count,
            found: pieces.len(),
        });
    }

    // Merge variants further constrain piece_count == tx_type.
    if tx_type >= 2 && piece_count != tx_type {
        return Err(TrailingParamsError::PieceCountMismatch {
            declared: piece_count,
            found: tx_type as usize,
        });
    }

    Ok(ParsedTrailingParams {
        counterparty_locking_script,
        piece_count,
        pieces,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Build the reverse-ordered piece array from a preceding transaction by
/// excising the asset locking script (everything past `[owner][var2]`)
/// from each named output, splitting the remaining tx bytes around those
/// regions, and reversing the result.
///
/// "Pieces" = byte slices BETWEEN excised regions (and at the head/tail).
fn build_pieces_from_tx(
    preceding_tx: &[u8],
    asset_output_indices: &[u32],
) -> Result<Vec<Vec<u8>>, TokenError> {
    // Compute the byte-range each asset locking script occupies inside the tx,
    // and within those scripts the byte-range to EXCISE (engine + post-data).
    let asset_excise_ranges = locate_asset_excise_ranges(preceding_tx, asset_output_indices)?;

    // Slice the tx into pieces: head (before first excise), gaps (between
    // consecutive excises), and tail (after the last excise).
    let mut pieces: Vec<Vec<u8>> = Vec::with_capacity(asset_excise_ranges.len() + 1);
    let mut cursor = 0usize;
    for (start, end) in &asset_excise_ranges {
        if *start < cursor {
            return Err(TokenError::InvalidScript(
                "preceding_tx: asset_output_indices not in ascending order".into(),
            ));
        }
        pieces.push(preceding_tx[cursor..*start].to_vec());
        cursor = *end;
    }
    pieces.push(preceding_tx[cursor..].to_vec());

    // Reverse order per spec §9.5.
    pieces.reverse();
    Ok(pieces)
}

/// For each output index in `asset_output_indices`, locate the byte range
/// (start..end) WITHIN the preceding transaction of the asset locking script
/// region to excise: i.e. everything in the output's locking script AFTER
/// the two leading variable parameters `[OP_DATA_20 + 20B owner][var2 push]`.
///
/// Indices are validated to lie within `vout_count` and to be in ascending
/// order. Returns ranges in **input order** (caller-supplied order, not
/// reversed).
fn locate_asset_excise_ranges(
    preceding_tx: &[u8],
    asset_output_indices: &[u32],
) -> Result<Vec<(usize, usize)>, TokenError> {
    // Walk the tx serialisation enough to locate each output's locking-script
    // byte range. Layout (BSV, no segwit):
    //   version (4) | input_count (varint) | inputs | output_count (varint) | outputs | locktime (4)
    // Each input:  prev_txid(32) | prev_vout(4) | scriptSig_len(varint) | scriptSig | sequence(4)
    // Each output: value(8) | scriptPubKey_len(varint) | scriptPubKey
    let mut sorted_indices = asset_output_indices.to_vec();
    sorted_indices.sort_unstable();
    if sorted_indices.windows(2).any(|w| w[0] == w[1]) {
        return Err(TokenError::InvalidScript(
            "asset_output_indices contains duplicates".into(),
        ));
    }

    let mut cursor = 0usize;
    if preceding_tx.len() < 4 {
        return Err(TokenError::InvalidScript("preceding_tx truncated".into()));
    }
    cursor += 4; // version

    let (input_count, n) = read_varint(preceding_tx, cursor)?;
    cursor += n;
    for _ in 0..input_count {
        // prev_txid + prev_vout
        cursor = checked_advance(cursor, 32 + 4, preceding_tx.len())?;
        let (script_len, n) = read_varint(preceding_tx, cursor)?;
        cursor += n;
        cursor = checked_advance(cursor, script_len as usize, preceding_tx.len())?;
        cursor = checked_advance(cursor, 4, preceding_tx.len())?; // sequence
    }

    let (output_count, n) = read_varint(preceding_tx, cursor)?;
    cursor += n;
    let mut output_excises: Vec<(usize, usize)> = Vec::with_capacity(asset_output_indices.len());

    let mut next_target_pos = 0usize;
    for vout in 0..output_count {
        cursor = checked_advance(cursor, 8, preceding_tx.len())?; // value
        let (script_len, n) = read_varint(preceding_tx, cursor)?;
        cursor += n;
        let script_start = cursor;
        let script_end = checked_advance(cursor, script_len as usize, preceding_tx.len())?;
        cursor = script_end;

        if next_target_pos < sorted_indices.len() && sorted_indices[next_target_pos] == vout as u32
        {
            // Within this script, excise everything past `[OP_DATA_20 + 20B owner][var2]`.
            let excise_start = excise_offset_in_script(&preceding_tx[script_start..script_end])
                .map(|o| script_start + o)
                .ok_or_else(|| {
                    TokenError::InvalidScript(format!(
                        "output {vout} is not STAS-shaped (missing OP_DATA_20 owner + var2)"
                    ))
                })?;
            output_excises.push((excise_start, script_end));
            next_target_pos += 1;
        }
    }

    if next_target_pos < sorted_indices.len() {
        return Err(TokenError::InvalidScript(
            "asset_output_indices contains an out-of-range vout".into(),
        ));
    }

    // Re-order to match caller's input order so that reversal in
    // `build_pieces_from_tx` honours their semantic ordering.
    let mut keyed: Vec<((usize, usize), u32)> = output_excises
        .into_iter()
        .zip(sorted_indices.iter().copied())
        .collect();
    let mut by_caller: Vec<(usize, usize)> = Vec::with_capacity(asset_output_indices.len());
    for vout in asset_output_indices {
        if let Some(pos) = keyed.iter().position(|(_, idx)| idx == vout) {
            let (range, _) = keyed.swap_remove(pos);
            by_caller.push(range);
        }
    }
    Ok(by_caller)
}

/// Offset within a STAS 3.0 locking script at which the "asset script"
/// portion begins (i.e. the byte AFTER `[OP_DATA_20 + 20B owner][var2]`).
///
/// Returns `None` if the script isn't STAS-shaped (missing the required
/// `0x14 + 20 bytes` owner prefix or a parseable var2 push).
fn excise_offset_in_script(script: &[u8]) -> Option<usize> {
    if script.len() < 22 || script[0] != 0x14 {
        return None;
    }
    let var2_offset = 21;
    skip_push_offset(script, var2_offset)
}

/// Given `script` and the offset of a push opcode, return the offset PAST
/// the entire push (header + body).
fn skip_push_offset(script: &[u8], offset: usize) -> Option<usize> {
    if offset >= script.len() {
        return None;
    }
    let opcode = script[offset];
    match opcode {
        0x00 => Some(offset + 1),
        0x4f | 0x51..=0x60 => Some(offset + 1),
        0x01..=0x4b => {
            let end = offset + 1 + opcode as usize;
            if end > script.len() {
                None
            } else {
                Some(end)
            }
        }
        0x4c => {
            if offset + 1 >= script.len() {
                return None;
            }
            let end = offset + 2 + script[offset + 1] as usize;
            if end > script.len() {
                None
            } else {
                Some(end)
            }
        }
        0x4d => {
            if offset + 2 >= script.len() {
                return None;
            }
            let len = u16::from_le_bytes([script[offset + 1], script[offset + 2]]) as usize;
            let end = offset + 3 + len;
            if end > script.len() {
                None
            } else {
                Some(end)
            }
        }
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
                None
            } else {
                Some(end)
            }
        }
        _ => None,
    }
}

/// Read a Bitcoin-style varint from `bytes` starting at `offset`.
/// Returns `(value, num_bytes_consumed)`.
fn read_varint(bytes: &[u8], offset: usize) -> Result<(u64, usize), TokenError> {
    if offset >= bytes.len() {
        return Err(TokenError::InvalidScript("varint truncated".into()));
    }
    let first = bytes[offset];
    match first {
        0xfd => {
            if offset + 3 > bytes.len() {
                return Err(TokenError::InvalidScript("varint(0xfd) truncated".into()));
            }
            let v = u16::from_le_bytes([bytes[offset + 1], bytes[offset + 2]]);
            Ok((v as u64, 3))
        }
        0xfe => {
            if offset + 5 > bytes.len() {
                return Err(TokenError::InvalidScript("varint(0xfe) truncated".into()));
            }
            let v = u32::from_le_bytes([
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
            ]);
            Ok((v as u64, 5))
        }
        0xff => {
            if offset + 9 > bytes.len() {
                return Err(TokenError::InvalidScript("varint(0xff) truncated".into()));
            }
            let v = u64::from_le_bytes([
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
                bytes[offset + 8],
            ]);
            Ok((v, 9))
        }
        _ => Ok((first as u64, 1)),
    }
}

/// Advance `cursor` by `n`, ensuring it stays within `total_len`.
fn checked_advance(cursor: usize, n: usize, total_len: usize) -> Result<usize, TokenError> {
    let next = cursor
        .checked_add(n)
        .ok_or_else(|| TokenError::InvalidScript("preceding_tx cursor overflow".into()))?;
    if next > total_len {
        return Err(TokenError::InvalidScript(
            "preceding_tx truncated while parsing".into(),
        ));
    }
    Ok(next)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a Bitcoin-style varint into a Vec<u8>.
    fn varint(v: u64) -> Vec<u8> {
        if v < 0xfd {
            vec![v as u8]
        } else if v <= 0xffff {
            let mut out = vec![0xfd];
            out.extend_from_slice(&(v as u16).to_le_bytes());
            out
        } else if v <= 0xffff_ffff {
            let mut out = vec![0xfe];
            out.extend_from_slice(&(v as u32).to_le_bytes());
            out
        } else {
            let mut out = vec![0xff];
            out.extend_from_slice(&v.to_le_bytes());
            out
        }
    }

    /// Build a fake STAS-shaped locking script:
    ///   `OP_DATA_20 [owner:20] [var2:1B push] [engine_payload]`
    /// where `engine_payload` is arbitrary bytes representing the section
    /// to be excised.
    fn fake_stas_script(owner: u8, var2: u8, engine_payload: &[u8]) -> Vec<u8> {
        let mut s = Vec::with_capacity(22 + 2 + engine_payload.len());
        s.push(0x14); // OP_DATA_20
        s.extend(std::iter::repeat(owner).take(20));
        s.push(0x01); // bare push of 1 byte for var2
        s.push(var2);
        s.extend_from_slice(engine_payload);
        s
    }

    /// Build a synthetic raw transaction containing N outputs with the
    /// supplied locking scripts, plus a single dummy input. Returns the
    /// tx bytes alongside per-output (script_start, script_end) offsets.
    fn fake_tx(output_scripts: &[Vec<u8>]) -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend_from_slice(&1u32.to_le_bytes()); // version
        tx.extend(varint(1)); // input_count
                              // dummy input
        tx.extend_from_slice(&[0u8; 32]); // prev_txid
        tx.extend_from_slice(&0u32.to_le_bytes()); // prev_vout
        tx.extend(varint(0)); // empty scriptSig
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
        tx.extend(varint(output_scripts.len() as u64));
        for s in output_scripts {
            tx.extend_from_slice(&1000u64.to_le_bytes()); // value
            tx.extend(varint(s.len() as u64));
            tx.extend_from_slice(s);
        }
        tx.extend_from_slice(&0u32.to_le_bytes()); // locktime
        tx
    }

    // ----- pushdata framing -----

    #[test]
    fn pushdata_framing_picks_correct_opcode() {
        let mut out = Vec::new();
        append_pushdata(&mut out, &[]);
        assert_eq!(out, vec![0x00]);

        let mut out = Vec::new();
        append_pushdata(&mut out, &[0xAB, 0xCD]);
        assert_eq!(out, vec![0x02, 0xAB, 0xCD]);

        // 75 bytes → direct push 0x4b.
        let mut out = Vec::new();
        append_pushdata(&mut out, &[0x11; 75]);
        assert_eq!(out[0], 0x4b);
        assert_eq!(out.len(), 76);

        // 76 bytes → OP_PUSHDATA1.
        let mut out = Vec::new();
        append_pushdata(&mut out, &[0x22; 76]);
        assert_eq!(out[0], 0x4c);
        assert_eq!(out[1], 76);
        assert_eq!(out.len(), 78);

        // 200 bytes → OP_PUSHDATA1 (no size limit on pieces anymore).
        let mut out = Vec::new();
        append_pushdata(&mut out, &[0x33; 200]);
        assert_eq!(out[0], 0x4c);
        assert_eq!(out[1], 200);
        assert_eq!(out.len(), 202);

        // 300 bytes → OP_PUSHDATA2.
        let mut out = Vec::new();
        append_pushdata(&mut out, &vec![0x44; 300]);
        assert_eq!(out[0], 0x4d);
        assert_eq!(out.len(), 303);
    }

    #[test]
    fn pushdata_round_trips() {
        for len in [0usize, 1, 75, 76, 127, 128, 200, 255, 256, 1000] {
            let data = vec![0x5Au8; len];
            let mut framed = Vec::new();
            append_pushdata(&mut framed, &data);
            assert_eq!(framed.len(), pushdata_len(&data));
            let (body, consumed) = read_pushdata(&framed, 0).unwrap();
            assert_eq!(body, data);
            assert_eq!(consumed, framed.len());
        }
    }

    // ----- atomic swap -----

    #[test]
    fn encode_atomic_swap_emits_counterparty_count_and_pieces() {
        let asset_a = fake_stas_script(0x11, 0xAA, &[0xE1, 0xE1, 0xE1, 0xE1]);
        let other = vec![0x76u8, 0xa9, 0x14]; // mock script (3 bytes)
        let tx = fake_tx(&[other.clone(), asset_a.clone()]);

        let counterparty_script = vec![0xCC, 0xCC];
        let trailing = encode_atomic_swap_trailing_params(&counterparty_script, &tx, &[1]).unwrap();

        // Trailing layout = push(counterparty_script) ‖ push(piece_count)
        // ‖ push(piece)... — the first push is the 2-byte counterparty.
        assert_eq!(&trailing[..3], &[0x02, 0xCC, 0xCC]);
        // Next push is piece_count as a minimal numeric opcode: count=2 → OP_2 (0x52).
        assert_eq!(trailing[3], 0x52);

        // Round-trip parse to validate the pushdata shape.
        let parsed = parse_trailing_params(&trailing, 1).unwrap();
        assert_eq!(
            parsed.counterparty_locking_script.as_deref(),
            Some(&[0xCC, 0xCC][..])
        );
        assert_eq!(parsed.piece_count, 2);
        assert_eq!(parsed.pieces.len(), 2);
    }

    #[test]
    fn encode_atomic_swap_zero_outputs_errors() {
        let tx = fake_tx(&[]);
        let result = encode_atomic_swap_trailing_params(&[], &tx, &[]);
        assert!(matches!(
            result,
            Err(TokenError::InvalidScript(msg)) if msg.contains("non-empty")
        ));
    }

    #[test]
    fn encode_atomic_swap_non_stas_output_errors() {
        let non_stas = vec![0x76, 0xa9, 0x14, 0x00, 0x88, 0xac]; // P2PKH-ish, no var2
        let tx = fake_tx(&[non_stas]);
        let result = encode_atomic_swap_trailing_params(&[0x01], &tx, &[0]);
        assert!(matches!(result, Err(TokenError::InvalidScript(_))));
    }

    // ----- merge -----

    #[test]
    fn encode_merge_two_pieces_basic() {
        let a = fake_stas_script(0x11, 0xAA, &[0xE1, 0xE1]);
        let tx = fake_tx(&[a.clone()]);
        // 1 asset → produces head + tail = 2 pieces → matches piece_count=2.
        let trailing = encode_merge_trailing_params(2, &tx, &[0]).unwrap();
        // First push is piece_count as a minimal numeric opcode: count=2 → OP_2 (0x52).
        assert_eq!(trailing[0], 0x52);
        let parsed = parse_trailing_params(&trailing, 2).unwrap();
        assert_eq!(parsed.pieces.len(), 2);
    }

    #[test]
    fn encode_merge_three_pieces() {
        let a = fake_stas_script(0x11, 0xAA, &[0xE1, 0xE1]);
        let b = fake_stas_script(0x22, 0xBB, &[0xE2, 0xE2]);
        let tx = fake_tx(&[a, b]);
        // 2 assets → 3 pieces (head, between, tail) → matches piece_count=3.
        let trailing = encode_merge_trailing_params(3, &tx, &[0, 1]).unwrap();
        // piece_count=3 → OP_3 (0x53).
        assert_eq!(trailing[0], 0x53);
        let parsed = parse_trailing_params(&trailing, 3).unwrap();
        assert_eq!(parsed.pieces.len(), 3);
    }

    #[test]
    fn encode_merge_four_pieces() {
        let a = fake_stas_script(0x11, 0xAA, &[0xE1, 0xE1]);
        let b = fake_stas_script(0x22, 0xBB, &[0xE2, 0xE2]);
        let c = fake_stas_script(0x33, 0xCC, &[0xE3, 0xE3]);
        let tx = fake_tx(&[a, b, c]);
        // 3 assets → 4 pieces → matches piece_count=4.
        let trailing = encode_merge_trailing_params(4, &tx, &[0, 1, 2]).unwrap();
        // piece_count=4 → OP_4 (0x54).
        assert_eq!(trailing[0], 0x54);
        let parsed = parse_trailing_params(&trailing, 4).unwrap();
        assert_eq!(parsed.pieces.len(), 4);
    }

    #[test]
    fn encode_merge_piece_count_out_of_range() {
        let a = fake_stas_script(0x11, 0xAA, &[0xE1]);
        let tx = fake_tx(&[a]);
        assert!(matches!(
            encode_merge_trailing_params(1, &tx, &[0]),
            Err(TokenError::InvalidScript(_))
        ));
        assert!(matches!(
            encode_merge_trailing_params(8, &tx, &[0]),
            Err(TokenError::InvalidScript(_))
        ));
    }

    #[test]
    fn encode_merge_count_mismatch_errors() {
        // 1 asset → 2 pieces, but request count=3 → mismatch.
        let a = fake_stas_script(0x11, 0xAA, &[0xE1, 0xE1]);
        let tx = fake_tx(&[a]);
        let res = encode_merge_trailing_params(3, &tx, &[0]);
        assert!(matches!(res, Err(TokenError::InvalidScript(_))));
    }

    // ----- parse / round-trip -----

    #[test]
    fn parse_round_trip_atomic_swap() {
        let asset_a = fake_stas_script(0x11, 0xAA, &[0xE1, 0xE1, 0xE1]);
        let tx = fake_tx(&[asset_a.clone()]);
        let counterparty = vec![0xCAu8, 0xFE, 0xBA, 0xBE];

        let encoded = encode_atomic_swap_trailing_params(&counterparty, &tx, &[0]).unwrap();
        let parsed = parse_trailing_params(&encoded, 1).unwrap();
        assert_eq!(
            parsed.counterparty_locking_script.as_deref(),
            Some(&counterparty[..])
        );
        assert_eq!(parsed.piece_count, 2);
        assert_eq!(parsed.pieces.len(), 2);
        // After reverse, the LAST piece is the head — which should start
        // with the version bytes [0x01,0x00,0x00,0x00].
        let head = parsed.pieces.last().unwrap();
        assert_eq!(&head[..4], &1u32.to_le_bytes()[..]);
    }

    #[test]
    fn parse_round_trip_merge() {
        let a = fake_stas_script(0x11, 0xAA, &[0xE1, 0xE1]);
        let b = fake_stas_script(0x22, 0xBB, &[0xE2, 0xE2]);
        let tx = fake_tx(&[a, b]);
        let encoded = encode_merge_trailing_params(3, &tx, &[0, 1]).unwrap();
        let parsed = parse_trailing_params(&encoded, 3).unwrap();
        assert!(parsed.counterparty_locking_script.is_none());
        assert_eq!(parsed.piece_count, 3);
        assert_eq!(parsed.pieces.len(), 3);
    }

    #[test]
    fn parse_rejects_truncated_piece() {
        // Merge block: piece_count opcode OP_2 (0x52), then one full piece
        // push [0x02,0xAA,0xBB], then a push header [0x05] with no body.
        let block = vec![0x52u8, 0x02, 0xAA, 0xBB, 0x05];
        let res = parse_trailing_params(&block, 2);
        assert!(matches!(res, Err(TrailingParamsError::Truncated(_))));
    }

    #[test]
    fn parse_rejects_trailing_bytes_after_pieces() {
        // tx_type=1: push(counterparty=[]) = [0x00], piece_count=1 → OP_1
        // (0x51), one piece push [0x01,0xAA], then a stray byte 0xCC.
        let block = vec![0x00u8, 0x51, 0x01, 0xAA, 0xCC];
        let res = parse_trailing_params(&block, 1);
        assert!(matches!(
            res,
            Err(TrailingParamsError::TrailingBytesAfterPieces(_))
        ));
    }

    #[test]
    fn parse_rejects_unsupported_tx_type() {
        let block = vec![0x01u8, 0x01];
        assert!(matches!(
            parse_trailing_params(&block, 0),
            Err(TrailingParamsError::UnsupportedTxType(0))
        ));
        assert!(matches!(
            parse_trailing_params(&block, 8),
            Err(TrailingParamsError::UnsupportedTxType(8))
        ));
    }

    #[test]
    fn parse_handles_empty_pieces() {
        // Merge tx_type=3: piece_count=3 → OP_3 (0x53), then three piece
        // pushes — [0x01,0xAA], [0x00] (empty), [0x01,0xBB].
        let block = vec![0x53u8, 0x01, 0xAA, 0x00, 0x01, 0xBB];
        let parsed = parse_trailing_params(&block, 3).unwrap();
        assert_eq!(parsed.pieces.len(), 3);
        assert_eq!(parsed.pieces[0], vec![0xAA]);
        assert_eq!(parsed.pieces[1], Vec::<u8>::new());
        assert_eq!(parsed.pieces[2], vec![0xBB]);
    }

    #[test]
    fn counterparty_script_length_variations() {
        for cp_len in [0usize, 1, 25, 200] {
            let counterparty = vec![0xAB; cp_len];
            let asset = fake_stas_script(0x11, 0xAA, &[0xE1]);
            let tx = fake_tx(&[asset]);
            let encoded = encode_atomic_swap_trailing_params(&counterparty, &tx, &[0]).unwrap();
            let parsed = parse_trailing_params(&encoded, 1).unwrap();
            assert_eq!(
                parsed.counterparty_locking_script.as_deref(),
                Some(&counterparty[..])
            );
            assert_eq!(parsed.piece_count, 2);
        }
    }

    // ----- snapshot pinning the trailing block shape -----

    #[test]
    fn snapshot_atomic_swap_shape() {
        let asset = fake_stas_script(0x77, 0x55, &[0xE1, 0xE2, 0xE3]);
        let tx = fake_tx(&[asset]);
        let counterparty = vec![0x99u8];
        let encoded = encode_atomic_swap_trailing_params(&counterparty, &tx, &[0]).unwrap();

        // First push: counterparty script [0x99] → [0x01, 0x99].
        assert_eq!(&encoded[..2], &[0x01, 0x99]);
        // Next push: piece_count=2 → OP_2 (single byte 0x52).
        assert_eq!(encoded[2], 0x52);
        let parsed = parse_trailing_params(&encoded, 1).unwrap();
        assert_eq!(parsed.pieces.len(), 2);
    }

    #[test]
    fn snapshot_merge_shape() {
        let a = fake_stas_script(0xAA, 0x11, &[0xE1]);
        let b = fake_stas_script(0xBB, 0x22, &[0xE2]);
        let c = fake_stas_script(0xCC, 0x33, &[0xE3]);
        let tx = fake_tx(&[a, b, c]);
        let encoded = encode_merge_trailing_params(4, &tx, &[0, 1, 2]).unwrap();
        // First push is piece_count: count=4 → OP_4 (0x54).
        assert_eq!(encoded[0], 0x54);
        let parsed = parse_trailing_params(&encoded, 4).unwrap();
        assert_eq!(parsed.pieces.len(), 4);
    }

    // ----- pushdata-per-piece shape regression -----

    /// Each piece is its own pushdata operation; piece_count is its own
    /// push. There is NO concatenated length-prefixed blob and NO 127-byte
    /// piece-size limit.
    #[test]
    fn piece_array_is_pushdata_per_piece() {
        // Synthesize a merge block with two known pieces by hand-framing.
        // piece_count uses the minimal numeric push (OP_2 = 0x52, single byte);
        // pieces use standard pushdata framing.
        let mut block = Vec::new();
        append_minimal_numeric_push(&mut block, 2); // piece_count → OP_2 (0x52)
        append_pushdata(&mut block, &[0x41, 0x42]); // piece 0
        append_pushdata(&mut block, &[0x43, 0x44]); // piece 1
        assert_eq!(
            block,
            vec![0x52, 0x02, 0x41, 0x42, 0x02, 0x43, 0x44],
            "trailing block must be OP_<n> piece_count followed by independent \
             pushdata operations: OP_<count> push(piece) push(piece)"
        );

        let parsed = parse_trailing_params(&block, 2).unwrap();
        assert_eq!(parsed.piece_count, 2);
        assert_eq!(parsed.pieces, vec![vec![0x41, 0x42], vec![0x43, 0x44]]);
    }

    /// A 200-byte piece must encode fine — there is no piece-size limit
    /// (the old "127-byte limit" was a phantom of the length-prefix scheme).
    #[test]
    fn piece_array_accepts_large_pieces() {
        // Build a STAS-shaped script whose excise leaves a >127-byte head.
        let big_payload = vec![0xEE; 300];
        let asset = fake_stas_script(0x11, 0xAA, &big_payload);
        // 200 bytes of leading dust to push the head piece well past 127.
        let dust = vec![0x6Au8; 200];
        let tx = fake_tx(&[dust, asset]);
        let trailing = encode_merge_trailing_params(2, &tx, &[1]).unwrap();
        let parsed = parse_trailing_params(&trailing, 2).unwrap();
        assert_eq!(parsed.pieces.len(), 2);
        // The head piece (last after reverse) is well over 127 bytes and
        // round-trips cleanly through pushdata framing.
        assert!(parsed.pieces.last().unwrap().len() > 127);
    }

    // ----- real STAS 3.0 fixture (cross-SDK pin) -----

    /// The 2899-byte STAS 3.0 canonical engine base template. Starts with
    /// the engine prefix `6d827363`, ends with `0x6a` (OP_RETURN). Same
    /// blob pinned in the Elixir SDK's `reader_push_data_test.exs` and
    /// `stas3_pieces_test.exs`. SHA-256:
    /// `5c659f5f3abdad612c4bfd19b6034f2df0c0bcef1af1ca928d0f5a34ac3ee371`.
    /// Source: `github.com/stassso/STAS-3-script-templates` (v0.2.3).
    const STAS3_BASE_TEMPLATE_HEX: &str = "6d82736301218763007b7b517c6e5667766b517f786b517f73637c7f68517f73637c7f68517f73637c7f68517f73637c7f68517f73637c7f68766c936c7c5493686751687652937a76aa607f5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7c5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e011f7f7d7e01007e8111414136d08c5ed2bf3ba048afe6dcaebafe01005f80837e01007e7652967b537a7601ff877c0100879b7d648b6752799368537a7d9776547aa06394677768263044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802207c607f5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7c5f7f7c5e7f7c5d7f7c5c7f7c5b7f7c5a7f7c597f7c587f7c577f7c567f7c557f7c547f7c537f7c527f7c517f7c7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e01417e7c6421038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b92186721023635954789a02e39fb7e54440b6f528d53efd65635ddad7f3c4085f97fdbdc4868ad547f7701207f01207f7701247f517f7801007e02fd00a063546752687f7801007e817f727e7b517f7c01147d887f517f7c01007e817601619f6976014ea063517c7b6776014ba06376014da063755467014d9c6352675168687f7c01007e81687f007b7b687602540b7f7701147f7c5579876b826475020100686b587a5893766b7a765155a569005379736382013ca07c517f7c51877b9a6352795487637101007c7e717101207f01147f7577776775785387646c766b8b8b7951886868677568686c6c7c6b517f7c817f788273638c7f776775010068518463517f7c01147d887f547952876372777c717c767663517f756852875779766352790152879a689b63517f77567a7567527c7681014f0161a5587a9a63015094687e68746c766b5c9388748c76795879888c8c7978886777717c567a5679538764780152879a787663517f756852879b745394768b797663517f756852877c6c766b5c936ea0637c8c768b797663517f75685287726b9b7c6c686ea0637c5394768b797663517f75685287726b9b7c6c686ea063755494797663517f756852879b676d689b63006968677568687c717167567a7568788273638c7f776775010068528463517f7c01147d887f547953876372777c677768686d6c75787653877c52879b636c75006b687c518763755279685879a9886b6b6b6b6b6b6b827763af686c6c6c6c6c6c6c547a577a7664577a577a587a597a786354807e7e676d68aa8800677b7c7651876375577a7c587a67007c68765258a569765187645294597a53795b7a7e7e78637c8c7c53797e5a7a7e6878637c8c7c53797e5a7a7e6878637c8c7c53797e5a7a7e6878637c8c7c53797e5a7a7e6878637c8c7c53797e5a7a7e68687276647572677772755168537a76aa5a7a7d54807e597a5b7a5c7a786354807e6f7e7eaa727c7e676d6e7eaa7c687b7eaa5a7a7d877663516752687c72879b69537a6491687c7b547f77517f7853a0916901247f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e816854937f77788c6301247f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e816854937f777852946301247f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e816854937f77686877517f7c52797d8b9f7c53a09b91697c76638c7c587f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81687f777c6876638c7c587f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81687f777c6863587f77517f7c01007e817602fc00a06302fd00a063546752687f7c01007e81687f7768587f517f7801007e817602fc00a06302fd00a063546752687f7801007e81727e7b7b687f75517f7c01147d887f517f7c01007e817601619f6976014ea0637c6776014ba06376014da063755467014d9c6352675168687f7c01007e81687f68557964577988756d67716881687863567a677b68587f7c8153796353795287637b6b537a6b717c6b6b537a6b676b577a6b597a6b587a6b577a6b7c68677b93687c547f7701207f75748c7a7669765880044676a914780114748c7a76727b748c7a768291788251877c764f877c81510111a59b9a9b648276014ba1647602ff00a16351014c677603ffff00a16352014d6754014e68687b7b7f757e687c7e67736301509367010068685c795c79636c766b7363517f7c51876301207f7c5279a8877c011c7f5579877c01147f755679879a9a6967756868687e777e7e827602fc00a0637603ffff00a06301fe7c82546701fd7c8252687da0637f756780687e67517f75687c7e7e0a888201218763ac67517f07517f73637c7f6876767e767e7e02ae687e7e7c557a00740111a063005a79646b7c748c7a76697d937b7b58807e6c91677c748c7a7d58807e6c6c6c557a680114748c7a748c7a768291788251877c764f877c81510111a59b9a9b648276014ba1647602ff00a16351014c677603ffff00a16352014d6754014e68687b7b7f757e687c7e67736301509367010068685479635f79676c766b0115797363517f7c51876301207f7c5279a8877c011c7f5579877c01147f755679879a9a6967756868687e777e7e827602fc00a0637603ffff00a06301fe7c82546701fd7c8252687da0637f756780687e67517f75687c7e7c637e677c6b7c6b7c6b7e7c6b68685979636c6c766b786b7363517f7c51876301347f77547f547f75786352797b01007e81957c01007e81965379a169676d68677568685c797363517f7c51876301347f77547f547f75786354797b01007e81957c01007e819678a169676d68677568687568740111a063748c7a76697d58807e00005c79635e79768263517f756851876c6c766b7c6b768263517f756851877b6e9b63789c6375745294797b78877b7b877d9b69637c917c689167745294797c638777637c917c91686777876391677c917c686868676d6d68687863537a6c936c6c6c567a567a54795479587a676b72937b7b5c795e796c68748c7a748c7a7b636e717b7b877b7b879a6967726d6801147b7e7c8291788251877c764f877c81510111a59b9a9b648276014ba1647602ff00a16351014c677603ffff00a16352014d6754014e68687b7b7f757e687c7e67736301509367010068687e7c636c766b7e726b6b726b6b675b797e68827602fc00a0637603ffff00a06301fe7c82546701fd7c8252687da0637f756780687e67517f75687c7e7e68740111a063748c7a76697d58807e00005c79635e79768263517f756851876c6c766b7c6b768263517f756851877b6e9b63789c6375745294797b78877b7b877d9b69637c917c689167745294797c638777637c917c91686777876391677c917c686868676d6d68687863537a6c936c6c6c567a567a54795479587a676b72937b7b5c795e796c68748c7a748c7a7b636e717b7b877b7b879a6967726d6801147b7e7c8291788251877c764f877c81510111a59b9a9b648276014ba1647602ff00a16351014c677603ffff00a16352014d6754014e68687b7b7f757e687c7e67736301509367010068687e7c636c766b7e726b6b726b6b675b797e68827602fc00a0637603ffff00a06301fe7c82546701fd7c8252687da0637f756780687e67517f75687c7e7e68597a636c6c6c6d6c6c6d6c9d687c587a9d7d7e5c79635d795880041976a9145e797e0288ac7e7e6700687d7e5c7a766302006a7c7e827602fc00a06301fd7c7e536751687f757c7e0058807c7e687d7eaa6b7e7e7e7e7e7eaa78877c6c877c6c9a9b726d726d77776a";

    /// Build a REAL STAS 3.0 locking script:
    ///   `0x14 <owner:20>` + `<var2 = OP_0>` + 2899-byte canonical base template
    ///   + `0x14 <redemption:20>` post-OP_RETURN data.
    fn real_stas3_locking_script(owner: u8, redemption: u8) -> Vec<u8> {
        let base: Vec<u8> = (0..STAS3_BASE_TEMPLATE_HEX.len() / 2)
            .map(|i| u8::from_str_radix(&STAS3_BASE_TEMPLATE_HEX[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        let mut s = Vec::with_capacity(22 + base.len() + 21);
        s.push(0x14); // OP_DATA_20
        s.extend(std::iter::repeat(owner).take(20));
        s.push(0x00); // var2 = OP_0
        s.extend_from_slice(&base);
        s.push(0x14); // post-OP_RETURN: OP_DATA_20
        s.extend(std::iter::repeat(redemption).take(20));
        s
    }

    /// CROSS-SDK FIXTURE: this exact preceding_tx + merge encoding is also
    /// pinned in the Elixir SDK at
    ///   `bsv_sdk_elixir/test/bsv/tokens/script/stas3_pieces_test.exs`
    ///   → describe `real STAS 3.0 locking-script fixture (cross-SDK pin)`.
    ///
    /// Both SDKs MUST produce byte-identical output for the same input.
    /// Build the cross-SDK preceding tx: 1 dummy input (prev_txid = 32×0x11,
    /// vout 0, empty scriptSig, sequence 0xFFFFFFFF), N outputs each with
    /// value 0, locktime 0. Construction is byte-identical to the Elixir
    /// SDK's `cross_sdk_preceding_tx/1` so the canonical hex matches.
    fn cross_sdk_preceding_tx(output_scripts: &[Vec<u8>]) -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend_from_slice(&1u32.to_le_bytes()); // version
        tx.extend(varint(1)); // input_count
        tx.extend_from_slice(&[0x11u8; 32]); // prev_txid
        tx.extend_from_slice(&0u32.to_le_bytes()); // prev_vout
        tx.extend(varint(0)); // empty scriptSig
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
        tx.extend(varint(output_scripts.len() as u64));
        for s in output_scripts {
            tx.extend_from_slice(&0u64.to_le_bytes()); // value = 0
            tx.extend(varint(s.len() as u64));
            tx.extend_from_slice(s);
        }
        tx.extend_from_slice(&0u32.to_le_bytes()); // locktime
        tx
    }

    /// Cross-SDK byte-identity pin for STAS 3.0 merge (txType=3) trailing
    /// params against the canonical engine + DXS option-3 conventions.
    /// The same hex is pinned in the Elixir SDK's `stas3_pieces_test.exs`
    /// → describe `real STAS 3.0 locking-script fixture (cross-SDK pin)`.
    /// Both SDKs MUST produce byte-identical output for the same input.
    ///
    /// Layout (decoded): OP_3 (0x53) piece_count ‖ pushdata(4B) tail
    /// piece (locktime) ‖ pushdata(33B) middle piece (out 1 value/varint
    /// + owner_push + var2) ‖ OP_PUSHDATA1(80B) head piece (version +
    /// input).
    #[test]
    fn real_stas3_merge_cross_sdk_pin() {
        let script0 = real_stas3_locking_script(0xA0, 0xCC);
        let script1 = real_stas3_locking_script(0xB0, 0xCC);
        let tx = cross_sdk_preceding_tx(&[script0, script1]);

        let trailing = encode_merge_trailing_params(3, &tx, &[0, 1]).unwrap();
        let hex: String = trailing.iter().map(|b| format!("{b:02x}")).collect();

        const CANONICAL_MERGE_HEX: &str = "530400000000210000000000000000fd7e0b14b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0004c50010000000111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff020000000000000000fd7e0b14a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a000";
        assert_eq!(
            hex, CANONICAL_MERGE_HEX,
            "Rust merge encoding diverged from the pinned cross-SDK \
             canonical hex (also pinned in the Elixir SDK)"
        );

        // Round-trips through the parser to 3 pieces.
        let parsed = parse_trailing_params(&trailing, 3).unwrap();
        assert_eq!(parsed.pieces.len(), 3);
    }
}
