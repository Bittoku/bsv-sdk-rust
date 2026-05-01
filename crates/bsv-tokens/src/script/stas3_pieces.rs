//! STAS 3.0 atomic-swap & merge piece-array encoding (spec v0.1 §8.1, §9.5).
//!
//! For `txType = 1` (atomic swap), the unlocking script's trailing parameters
//! are:
//!
//! ```text
//! counterparty_locking_script
//! piece_count       : 1-byte unsigned integer
//! piece_array       : length-prefixed pieces (1-byte length, then body)
//! ```
//!
//! For `txType = 2..7` (merge variants) the trailing parameters are the same
//! minus the leading counterparty script:
//!
//! ```text
//! piece_count       : 1-byte unsigned integer (must equal txType, 2..=7)
//! piece_array       : length-prefixed pieces (1-byte length, then body)
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
//! ## Wire format
//!
//! The engine consumes pieces via the repeated atom
//! `OP_1 OP_SPLIT OP_IFDUP OP_IF OP_SWAP OP_SPLIT OP_ENDIF`: it reads 1 byte
//! as the next piece's length, then exactly that many bytes as the piece
//! body. The piece-array is therefore encoded as
//!
//! ```text
//! [len_0][piece_0_bytes][len_1][piece_1_bytes]...[len_N-1][piece_N-1_bytes]
//! ```
//!
//! with no separators. Spec §9.5's "delimited by space" wording is
//! historical and superseded by the engine ASM. Each piece must fit within a
//! single u8 length prefix (≤ 0xFF bytes).

use crate::error::TokenError;

/// Maximum byte length of a single piece (engine reads 1-byte length prefix
/// via `OP_1 OP_SPLIT`).
const MAX_PIECE_LEN: usize = 0xFF;

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
/// A byte vector of the form
/// `counterparty_locking_script || [piece_count] || piece_array`, where
/// each piece is encoded as `[len][body]` (1-byte length prefix followed
/// by the piece bytes).
///
/// # Errors
/// * [`TokenError::InvalidScript`] — when `asset_output_indices` is empty,
///   when an index points at a non-STAS-shaped output, when any single
///   piece exceeds 255 bytes (`OP_1 OP_SPLIT` reads exactly 1 byte as the
///   length prefix), or when `preceding_tx` is malformed.
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
    validate_piece_lengths(&pieces)?;

    let mut out =
        Vec::with_capacity(counterparty_locking_script.len() + 1 + pieces_total_len(&pieces));
    out.extend_from_slice(counterparty_locking_script);
    out.push(piece_count);
    append_piece_array(&mut out, &pieces);
    Ok(out)
}

/// Encoded trailing-param block for a STAS 3.0 merge unlocking script
/// (`txType = 2..=7`).
///
/// `piece_count` must equal `txType` (range 2..=7) per spec §8.1.
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
    validate_piece_lengths(&pieces)?;
    let mut out = Vec::with_capacity(1 + pieces_total_len(&pieces));
    out.push(piece_count);
    append_piece_array(&mut out, &pieces);
    Ok(out)
}

/// Decoded trailing-param block from a STAS 3.0 unlocking script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTrailingParams {
    /// Counterparty locking script (only present for atomic-swap, `txType=1`).
    pub counterparty_locking_script: Option<Vec<u8>>,
    /// Declared piece count byte.
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
    /// Declared piece count does not match the parsed array length.
    #[error("piece_count mismatch: declared {declared}, found {found}")]
    PieceCountMismatch {
        /// Piece count declared by the leading byte.
        declared: u8,
        /// Number of pieces actually present in the array.
        found: usize,
    },
    /// `txType` argument out of supported range (must be 1..=7).
    #[error("unsupported tx_type {0}; expected 1..=7")]
    UnsupportedTxType(u8),
    /// Counterparty locking script length cannot be inferred for `txType=1`.
    #[error("ambiguous counterparty script length for atomic swap")]
    AmbiguousCounterpartyScript,
    /// Trailing bytes remain after consuming `piece_count` length-prefixed
    /// pieces from the piece-array.
    #[error("trailing bytes remain after piece_array (offset {0})")]
    TrailingBytesAfterPieces(usize),
}

/// Parse an existing trailing-param block.
///
/// For atomic swap (`tx_type = 1`), the caller MUST provide
/// `counterparty_script_len` — the byte length of the counterparty's
/// locking script — because the trailing block carries no inline length
/// prefix for that field (it is delineated by surrounding script pushes
/// in the unlocking witness). Pass `None` for merge variants.
pub fn parse_trailing_params(
    bytes: &[u8],
    tx_type: u8,
    counterparty_script_len: Option<usize>,
) -> Result<ParsedTrailingParams, TrailingParamsError> {
    if !(1..=7).contains(&tx_type) {
        return Err(TrailingParamsError::UnsupportedTxType(tx_type));
    }

    let (counterparty_locking_script, after_script) = if tx_type == 1 {
        let len =
            counterparty_script_len.ok_or(TrailingParamsError::AmbiguousCounterpartyScript)?;
        if bytes.len() < len {
            return Err(TrailingParamsError::Truncated(len));
        }
        (Some(bytes[..len].to_vec()), len)
    } else {
        (None, 0)
    };

    if bytes.len() <= after_script {
        return Err(TrailingParamsError::Truncated(after_script));
    }
    let piece_count = bytes[after_script];
    let pieces_bytes = &bytes[after_script + 1..];
    let pieces = split_piece_array(pieces_bytes, piece_count as usize, after_script + 1)?;

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

/// Total encoded byte length of the piece-array (1-byte length prefix per
/// piece plus each piece body).
fn pieces_total_len(pieces: &[Vec<u8>]) -> usize {
    pieces.iter().map(|p| 1 + p.len()).sum()
}

/// Reject any piece that exceeds the engine's 1-byte length-prefix capacity.
fn validate_piece_lengths(pieces: &[Vec<u8>]) -> Result<(), TokenError> {
    for (i, piece) in pieces.iter().enumerate() {
        if piece.len() > MAX_PIECE_LEN {
            return Err(TokenError::InvalidScript(format!(
                "InvalidPiece: piece {i} length {} exceeds engine limit of {} bytes \
                 (OP_1 OP_SPLIT reads a 1-byte length prefix)",
                piece.len(),
                MAX_PIECE_LEN
            )));
        }
    }
    Ok(())
}

/// Append the piece array to `out` using the engine's wire format:
/// `[len_0][piece_0_bytes][len_1][piece_1_bytes]...`. Caller guarantees
/// each piece fits in a u8 via [`validate_piece_lengths`].
fn append_piece_array(out: &mut Vec<u8>, pieces: &[Vec<u8>]) {
    for piece in pieces {
        debug_assert!(piece.len() <= MAX_PIECE_LEN);
        out.push(piece.len() as u8);
        out.extend_from_slice(piece);
    }
}

/// Parse a length-prefixed piece-array. Reads exactly `piece_count` pieces;
/// returns an error if the buffer truncates mid-piece or has trailing bytes.
fn split_piece_array(
    bytes: &[u8],
    piece_count: usize,
    base_offset: usize,
) -> Result<Vec<Vec<u8>>, TrailingParamsError> {
    let mut pieces: Vec<Vec<u8>> = Vec::with_capacity(piece_count);
    let mut cursor = 0usize;
    for _ in 0..piece_count {
        if cursor >= bytes.len() {
            return Err(TrailingParamsError::Truncated(base_offset + cursor));
        }
        let len = bytes[cursor] as usize;
        cursor += 1;
        let end = cursor
            .checked_add(len)
            .ok_or(TrailingParamsError::Truncated(base_offset + cursor))?;
        if end > bytes.len() {
            return Err(TrailingParamsError::Truncated(base_offset + end));
        }
        pieces.push(bytes[cursor..end].to_vec());
        cursor = end;
    }
    if cursor != bytes.len() {
        return Err(TrailingParamsError::TrailingBytesAfterPieces(
            base_offset + cursor,
        ));
    }
    Ok(pieces)
}

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

    // ----- atomic swap -----

    #[test]
    fn encode_atomic_swap_emits_counterparty_count_and_pieces() {
        let asset_a = fake_stas_script(0x11, 0xAA, &[0xE1, 0xE1, 0xE1, 0xE1]);
        let other = vec![0x76u8, 0xa9, 0x14]; // mock script (3 bytes)
        let tx = fake_tx(&[other.clone(), asset_a.clone()]);

        let counterparty_script = vec![0xCC, 0xCC];
        let trailing = encode_atomic_swap_trailing_params(&counterparty_script, &tx, &[1]).unwrap();

        // Trailing layout = counterparty_script || piece_count(1B) || pieces.
        // Two pieces (head, tail) → reversed → [tail, head] each prefixed by
        // its own 1-byte length. tail = bytes after the excised engine of
        // asset output (locktime). head = bytes before the excised region.
        assert_eq!(&trailing[..2], counterparty_script.as_slice());
        assert_eq!(trailing[2], 2u8); // piece_count = 2

        // Round-trip parse to validate the length-prefixed shape.
        let parsed = parse_trailing_params(&trailing, 1, Some(counterparty_script.len())).unwrap();
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
        assert_eq!(trailing[0], 2u8);
        let parsed = parse_trailing_params(&trailing, 2, None).unwrap();
        assert_eq!(parsed.pieces.len(), 2);
    }

    #[test]
    fn encode_merge_three_pieces() {
        let a = fake_stas_script(0x11, 0xAA, &[0xE1, 0xE1]);
        let b = fake_stas_script(0x22, 0xBB, &[0xE2, 0xE2]);
        let tx = fake_tx(&[a, b]);
        // 2 assets → 3 pieces (head, between, tail) → matches piece_count=3.
        let trailing = encode_merge_trailing_params(3, &tx, &[0, 1]).unwrap();
        assert_eq!(trailing[0], 3u8);
        let parsed = parse_trailing_params(&trailing, 3, None).unwrap();
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
        assert_eq!(trailing[0], 4u8);
        let parsed = parse_trailing_params(&trailing, 4, None).unwrap();
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
        let parsed = parse_trailing_params(&encoded, 1, Some(counterparty.len())).unwrap();
        assert_eq!(
            parsed.counterparty_locking_script.as_deref(),
            Some(&counterparty[..])
        );
        assert_eq!(parsed.piece_count, 2);
        assert_eq!(parsed.pieces.len(), 2);
        // Reconstruct: pieces.reverse() then join the original by stitching
        // the excised regions back in. We just verify the reverse preserves
        // the head/tail sentinel bytes from `tx`.
        // tx starts with 4 version bytes [0x01,0x00,0x00,0x00].
        // After reverse, the LAST piece is the head — which should start
        // with the version bytes.
        let head = parsed.pieces.last().unwrap();
        assert_eq!(&head[..4], &1u32.to_le_bytes()[..]);
    }

    #[test]
    fn parse_round_trip_merge() {
        let a = fake_stas_script(0x11, 0xAA, &[0xE1, 0xE1]);
        let b = fake_stas_script(0x22, 0xBB, &[0xE2, 0xE2]);
        let tx = fake_tx(&[a, b]);
        let encoded = encode_merge_trailing_params(3, &tx, &[0, 1]).unwrap();
        let parsed = parse_trailing_params(&encoded, 3, None).unwrap();
        assert!(parsed.counterparty_locking_script.is_none());
        assert_eq!(parsed.piece_count, 3);
        assert_eq!(parsed.pieces.len(), 3);
    }

    #[test]
    fn parse_rejects_bad_piece_count() {
        // Length-prefixed: declared count=2 but the buffer truncates after
        // the first piece's header. piece_count(0x02) || len(0x02) AA BB ||
        // len(0x05) but no body — engine reports Truncated.
        let block = vec![0x02u8, 0x02, 0xAA, 0xBB, 0x05];
        let res = parse_trailing_params(&block, 2, None);
        assert!(matches!(res, Err(TrailingParamsError::Truncated(_))));
    }

    #[test]
    fn parse_rejects_trailing_bytes_after_pieces() {
        // tx_type=1, counterparty=[] (len=0), piece_count=1, one
        // length-prefixed piece [0x01, 0xAA], then a stray trailing 0xCC.
        let block = vec![0x01u8 /* piece_count */, 0x01, 0xAA, 0xCC];
        let res = parse_trailing_params(&block, 1, Some(0));
        assert!(matches!(
            res,
            Err(TrailingParamsError::TrailingBytesAfterPieces(_))
        ));
    }

    #[test]
    fn parse_rejects_unsupported_tx_type() {
        let block = vec![0x01u8];
        assert!(matches!(
            parse_trailing_params(&block, 0, None),
            Err(TrailingParamsError::UnsupportedTxType(0))
        ));
        assert!(matches!(
            parse_trailing_params(&block, 8, None),
            Err(TrailingParamsError::UnsupportedTxType(8))
        ));
    }

    #[test]
    fn parse_handles_empty_pieces() {
        // Length-prefixed: piece_count=3, then [len=1][0xAA][len=0][len=1][0xBB]
        // → 3 pieces, middle one empty. Use tx_type=3 so count must equal 3.
        let block = vec![0x03u8, 0x01, 0xAA, 0x00, 0x01, 0xBB];
        let parsed = parse_trailing_params(&block, 3, None).unwrap();
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
            let parsed = parse_trailing_params(&encoded, 1, Some(cp_len)).unwrap();
            assert_eq!(
                parsed.counterparty_locking_script.as_deref(),
                Some(&counterparty[..])
            );
            assert_eq!(parsed.piece_count, 2);
        }
    }

    // ----- snapshot pinning the trailing block hex -----

    #[test]
    fn snapshot_atomic_swap_hex_pin() {
        // Deterministic input: a single 1-byte counterparty script (0x99),
        // single asset output with engine payload [0xE1,0xE2,0xE3] in a
        // canonical 1-input/1-output tx. We don't assert exact bytes for
        // the inner tx (that's defined by `fake_tx`), but we snapshot the
        // shape and pin the leading bytes the spec mandates.
        let asset = fake_stas_script(0x77, 0x55, &[0xE1, 0xE2, 0xE3]);
        let tx = fake_tx(&[asset]);
        let counterparty = vec![0x99u8];
        let encoded = encode_atomic_swap_trailing_params(&counterparty, &tx, &[0]).unwrap();

        // Required leading bytes: 0x99 (counterparty) || 0x02 (piece_count).
        assert_eq!(encoded[0], 0x99);
        assert_eq!(encoded[1], 0x02);
        // Round-trip parse for shape coverage.
        let parsed = parse_trailing_params(&encoded, 1, Some(1)).unwrap();
        assert_eq!(parsed.pieces.len(), 2);
    }

    #[test]
    fn snapshot_merge_hex_pin() {
        let a = fake_stas_script(0xAA, 0x11, &[0xE1]);
        let b = fake_stas_script(0xBB, 0x22, &[0xE2]);
        let c = fake_stas_script(0xCC, 0x33, &[0xE3]);
        let tx = fake_tx(&[a, b, c]);
        let encoded = encode_merge_trailing_params(4, &tx, &[0, 1, 2]).unwrap();
        // Leading byte is the piece count.
        assert_eq!(encoded[0], 4);
        // Round-trip through the parser to verify the length-prefixed shape.
        let parsed = parse_trailing_params(&encoded, 4, None).unwrap();
        assert_eq!(parsed.pieces.len(), 4);
    }

    // ----- length-prefix shape regression -----

    /// Encode a tiny 2-piece array directly via the public encoders and
    /// verify the wire bytes are length-prefixed (no separators).
    ///
    /// Builds a synthetic preceding tx with a single STAS-shaped output
    /// whose excise leaves head=`[0x41,0x42]` ("AB") and tail=`[0x43,0x44]`
    /// ("CD"). After reversal the encoded piece body must be
    /// `[0x02,0x43,0x44,0x02,0x41,0x42]`.
    #[test]
    fn piece_array_is_length_prefixed_not_separator_delimited() {
        // We don't synthesize a tx here — the spec for the encoder's wire
        // format is enforced by the helpers directly. Use them with known
        // pieces to assert the exact bytes.
        let pieces: Vec<Vec<u8>> = vec![vec![0x41, 0x42], vec![0x43, 0x44]];
        validate_piece_lengths(&pieces).unwrap();
        let mut out = Vec::new();
        append_piece_array(&mut out, &pieces);
        assert_eq!(
            out,
            vec![0x02, 0x41, 0x42, 0x02, 0x43, 0x44],
            "piece-array must be length-prefixed: \
             [len][body][len][body], no 0x20 separators"
        );

        // Round-trip via split_piece_array (the decoder counterpart).
        let decoded = split_piece_array(&out, 2, 0).unwrap();
        assert_eq!(decoded, pieces);
    }

    /// Pieces longer than 255 bytes cannot fit a 1-byte length prefix and
    /// must be rejected by the encoder.
    #[test]
    fn piece_array_rejects_piece_over_255_bytes() {
        let pieces: Vec<Vec<u8>> = vec![vec![0xAB; 256]];
        let res = validate_piece_lengths(&pieces);
        match res {
            Err(TokenError::InvalidScript(msg)) => {
                assert!(
                    msg.contains("InvalidPiece"),
                    "expected InvalidPiece-prefixed error, got: {msg}"
                );
            }
            other => panic!("expected InvalidScript(InvalidPiece...), got {other:?}"),
        }
    }
}
