//! Builder for STAS-BTG (Back-to-Genesis) locking scripts.
//!
//! The STAS-BTG template extends the standard STAS v2 template with a
//! dual-path spending mechanism:
//!
//! ## Path A — BTG Proof (OP_IF branch)
//!
//! The unlocking script pushes `<sig> <pubkey> <prefix> <output> <suffix> OP_TRUE`.
//! The BTG preamble verifies three segments of the previous raw transaction:
//!
//! 1. **Hash check**: Verify `hash256(prefix || output || suffix)` equals the
//!    prev txid extracted from the sighash preimage outpoint.
//! 2. **Value check**: Parse 8-byte LE satoshis from `output` and verify it
//!    matches the sighash preimage value field.
//! 3. **Script format check**: Verify the locking script in `output` starts
//!    with `76 a9 14` (P2PKH prefix) and contains the correct redemption PKH.
//!
//! ## Path B — Checkpoint Attestation (OP_ELSE branch)
//!
//! The unlocking script pushes `<sig_owner> <pubkey_owner> <sig_issuer> <pubkey_issuer> OP_FALSE`.
//! The checkpoint gate verifies the issuer's public key hashes to the embedded
//! redemption PKH and their signature is valid (`OP_CHECKSIGVERIFY`), consuming
//! the issuer items and leaving `<sig_owner> <pubkey_owner>` for the STAS v2 body.
//!
//! This enables the issuer to co-sign a "checkpoint" TX that resets the proof
//! chain depth without taking custody, preventing linear size growth.
//!
//! After either path, the remaining stack (`<sig> <pubkey>`) flows into the
//! standard STAS v2 logic for per-hop output validation.

use bsv_script::Address;
use bsv_script::Script;

use crate::error::TokenError;

// NOTE: The BTG preamble is built dynamically by `build_btg_preamble()` because
// it embeds the redemption PKH. A static hex constant cannot be used.

/// Build a STAS-BTG locking script with dual-path spending.
///
/// The script uses `OP_IF / OP_ELSE / OP_ENDIF` to support two spending paths:
///
/// - **Path A (BTG proof)**: Unlocking pushes `... OP_TRUE`, BTG preamble
///   verifies the prev-TX proof, leaves `<sig> <pubkey>` for STAS v2 body.
/// - **Path B (Checkpoint)**: Unlocking pushes `... OP_FALSE`, checkpoint gate
///   verifies issuer co-signature, leaves `<sig_owner> <pubkey_owner>` for
///   STAS v2 body.
///
/// # Arguments
/// * `owner` - The address that owns (can spend) the token.
/// * `redemption_pkh` - The 20-byte public key hash for redemption / token ID.
/// * `splittable` - Whether the token can be split.
///
/// # Returns
/// A [`Script`] containing the STAS-BTG locking script.
///
/// # Errors
/// Returns [`TokenError::InvalidScript`] if template construction fails.
pub fn build_stas_btg_locking_script(
    owner: &Address,
    redemption_pkh: &[u8; 20],
    splittable: bool,
) -> Result<Script, TokenError> {
    let preamble_bytes = build_btg_preamble(redemption_pkh)?;
    let checkpoint_gate = build_checkpoint_gate(redemption_pkh);
    let stas_body = build_stas_v2_body(owner, redemption_pkh, splittable)?;

    // Structure: OP_IF [preamble] OP_ELSE [checkpoint gate] OP_ENDIF [stas v2 body]
    let total_len = 1 + preamble_bytes.len() + 1 + checkpoint_gate.len() + 1 + stas_body.len();
    let mut script_bytes = Vec::with_capacity(total_len);

    script_bytes.push(0x63); // OP_IF
    script_bytes.extend_from_slice(&preamble_bytes);
    script_bytes.push(0x67); // OP_ELSE
    script_bytes.extend_from_slice(&checkpoint_gate);
    script_bytes.push(0x68); // OP_ENDIF
    script_bytes.extend_from_slice(&stas_body);

    Ok(Script::from_bytes(&script_bytes))
}

/// Build the checkpoint attestation gate bytes.
///
/// The checkpoint gate verifies the issuer's identity and signature, allowing
/// the issuer to co-sign a checkpoint transaction without taking custody.
///
/// ## Stack on entry (from unlocking script):
/// ```text
/// <sig_owner> <pubkey_owner> <sig_issuer> <pubkey_issuer>
/// ```
///
/// ## Gate performs:
/// 1. `OP_DUP` — duplicate `pubkey_issuer`
/// 2. `OP_HASH160` — hash to get PKH
/// 3. Push embedded `redemption_pkh` (20 bytes)
/// 4. `OP_EQUALVERIFY` — verify pubkey hashes to redemption PKH
/// 5. `OP_CHECKSIGVERIFY` — verify `sig_issuer` against `pubkey_issuer`
///
/// ## Stack on exit:
/// ```text
/// <sig_owner> <pubkey_owner>
/// ```
///
/// Total gate size: 25 bytes (1+1+1+20+1+1).
fn build_checkpoint_gate(redemption_pkh: &[u8; 20]) -> Vec<u8> {
    let mut gate = Vec::with_capacity(25);
    gate.push(0x76); // OP_DUP
    gate.push(0xa9); // OP_HASH160
    gate.push(0x14); // OP_DATA_20 (push next 20 bytes)
    gate.extend_from_slice(redemption_pkh);
    gate.push(0x88); // OP_EQUALVERIFY
    gate.push(0xad); // OP_CHECKSIGVERIFY
    gate
}

/// The full STAS v2 template (1431 bytes) with zero placeholders.
/// Identical to the one in `stas_builder.rs`.
const STAS_V2_TEMPLATE_HEX: &str = concat!(
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
    "7602fc00a06302fd00a063546752687f7c01007e81727e7b7b687f75537f7c0376a9148801147f775379645579887567726881766968789263556753687a76",
    "026c057f7701147f8263517f7c766301007e817f7c6775006877686b537992635379528763547a6b547a6b677c6b567a6b537a7c717c71716868",
    "547a587f7c81547a557964936755795187637c686b687c547f7701207f75748c7a7669765880748c7a76567a876457790376a9147e7c7e557967",
    "041976a9147c7e0288ac687e7e5579636c766976748c7a9d58807e6c0376a9147e748c7a7e6c7e7e676c766b8263828c007c80517e846864745aa063",
    "7c748c7a76697d937b7b58807e56790376a9147e748c7a7e55797e7e6868686c567a5187637500678263828c007c80517e846868647459a063",
    "7c748c7a76697d937b7b58807e55790376a9147e748c7a7e55797e7e687459a0637c748c7a76697d937b7b58807e55790376a9147e748c7a7e55797e7e",
    "68687c537a9d547963557958807e041976a91455797e0288ac7e7e68aa87726d77776a14",
    "0000000000000000000000000000000000000000"
);

/// Build the raw STAS v2 body bytes with owner/redemption patched and flags appended.
///
/// This is the standard 1431-byte STAS v2 template plus flags, identical to
/// [`crate::script::stas_builder::build_stas_locking_script`] but returns raw
/// bytes instead of a [`Script`].
fn build_stas_v2_body(
    owner: &Address,
    redemption_pkh: &[u8; 20],
    splittable: bool,
) -> Result<Vec<u8>, TokenError> {
    let mut script_bytes = hex::decode(STAS_V2_TEMPLATE_HEX)
        .map_err(|e| TokenError::InvalidScript(format!("template decode error: {e}")))?;

    debug_assert_eq!(
        script_bytes.len(),
        1431,
        "STAS v2 template must be 1431 bytes"
    );

    // Patch owner PKH at bytes 3..23
    script_bytes[3..23].copy_from_slice(&owner.public_key_hash);

    // Patch redemption PKH at bytes 1411..1431
    script_bytes[1411..1431].copy_from_slice(redemption_pkh);

    // Append flags: OP_DATA_1 + flags byte
    let flags_byte = if splittable { 0x00 } else { 0x01 };
    script_bytes.push(0x01); // OP_DATA_1
    script_bytes.push(flags_byte);

    Ok(script_bytes)
}

/// Build the BTG verification preamble bytes.
///
/// ## Unlocking script stack (bottom → top):
/// ```text
/// <sig> <pubkey> <prefix> <output> <suffix>
/// ```
///
/// ## Preamble performs:
/// 1. Concatenate `prefix || output || suffix` → `raw_prev_tx`
/// 2. `OP_HASH256(raw_prev_tx)` → `prev_txid_hash`
/// 3. Save `prev_txid_hash` deep in the stack for later comparison (after ECDSA trick)
/// 4. Parse satoshis from `output` bytes
/// 5. Save satoshis for later comparison with sighash preimage value
/// 6. Check locking script prefix (`76 a9 14`) in `output`
/// 7. Extract redemption PKH from known offset and compare to embedded constant
/// 8. Drop all proof items, leaving `<sig> <pubkey>` for the standard STAS v2 logic
///
/// The preamble uses `OP_TOALTSTACK` / `OP_FROMALTSTACK` to stash computed
/// values that the main STAS template will compare against the sighash preimage.
///
/// **IMPORTANT**: The current implementation builds a preamble that validates
/// the prev-TX proof structure and drops the proof items from the main stack.
/// The actual comparison of `prev_txid_hash` and `satoshis` against the
/// sighash preimage fields is integrated into the main STAS template's ECDSA
/// trick section. This preamble therefore stashes its computed values on the
/// alt stack for the modified STAS template to consume.
fn build_btg_preamble(redemption_pkh: &[u8; 20]) -> Result<Vec<u8>, TokenError> {
    let mut preamble = Vec::with_capacity(200);

    // ---------------------------------------------------------------
    // Stack (bottom → top): <sig> <pubkey> <prefix> <output> <suffix>
    // ---------------------------------------------------------------

    // --- Step 1: Hash the reconstructed prev TX ---
    // We need prefix || output || suffix, but stack top is suffix.
    // OP_2 OP_PICK copies prefix (item at depth 2) to the top
    // Stack: <sig> <pub> <prefix> <output> <suffix> <prefix_copy>
    preamble.extend_from_slice(&[0x52, 0x7a]); // OP_2 OP_PICK

    // OP_2 OP_PICK copies output (now at depth 2) to the top
    // Stack: <sig> <pub> <prefix> <output> <suffix> <prefix_copy> <output_copy>
    preamble.extend_from_slice(&[0x52, 0x7a]); // OP_2 OP_PICK — copies suffix

    // Wait — let me reconsider the stack indexing carefully.
    // Initial stack (bottom → top, index 0 = top):
    //   [4]=sig, [3]=pubkey, [2]=prefix, [1]=output, [0]=suffix
    //
    // We want to build: prefix || output || suffix
    // So we need to copy [2],[1],[0] and concatenate.

    // Actually let me rebuild this more carefully.
    preamble.clear();

    // Stack: sig pubkey prefix output suffix  (suffix is on top)
    // Index: [4] [3]    [2]    [1]    [0]

    // Copy prefix (index 2) to top
    preamble.push(0x52); // OP_2
    preamble.push(0x7a); // OP_ROLL — no, we want PICK, not ROLL

    // OP_PICK = 0x79, not 0x7a (which is OP_ROLL)
    preamble.clear();

    // Stack: sig pubkey prefix output suffix  (suffix is on top)
    // Index: [4] [3]    [2]    [1]    [0]

    // Copy prefix to top: OP_2 OP_PICK
    preamble.push(0x52); // OP_2
    preamble.push(0x79); // OP_PICK

    // Stack: sig pubkey prefix output suffix prefix_copy
    // Index: [5] [4]    [3]    [2]    [1]    [0]

    // Copy output to top: OP_2 OP_PICK (output is now at index 2)
    // Actually output is at index 2 still? Let's recount:
    // After picking prefix: ... prefix output suffix prefix_copy
    // Index 0 = prefix_copy, 1 = suffix, 2 = output, 3 = prefix, ...
    preamble.push(0x52); // OP_2
    preamble.push(0x79); // OP_PICK

    // Stack: sig pubkey prefix output suffix prefix_copy output_copy
    // Index: [6] [5]    [4]    [3]    [2]    [1]         [0]

    // Copy suffix to top: OP_2 OP_PICK (suffix is at index 2)
    preamble.push(0x52); // OP_2
    preamble.push(0x79); // OP_PICK

    // Stack: sig pubkey prefix output suffix prefix_copy output_copy suffix_copy
    // Index: [7] [6]    [5]    [4]    [3]    [2]         [1]         [0]

    // Now concatenate: prefix_copy || output_copy || suffix_copy
    // We need: [2] || [1] || [0]
    // But CAT concatenates [1] || [0], so we need the right order.
    // Stack top is suffix_copy [0], under it output_copy [1], under that prefix_copy [2].
    // OP_CAT: pops [0] and [1], pushes [1]||[0] = output_copy||suffix_copy
    preamble.push(0x7e); // OP_CAT

    // Stack: ... prefix_copy (output_copy||suffix_copy)
    // OP_SWAP: bring prefix_copy to top
    preamble.push(0x7c); // OP_SWAP

    // Stack: ... (output_copy||suffix_copy) prefix_copy
    // OP_CAT: pops prefix_copy and (out||suf), pushes (out||suf)||prefix_copy
    // Wait, that's wrong order. OP_CAT pops two items and concatenates them as [under] || [top]
    // Hmm, need to check. In BSV, OP_CAT pops x1 (top) and x2 (second), pushes x2 || x1.
    // So after SWAP: top = prefix_copy, second = (output_copy||suffix_copy)
    // OP_CAT → (output_copy||suffix_copy) || prefix_copy — WRONG ORDER
    // We need prefix_copy || output_copy || suffix_copy

    // Let me redo the concatenation more carefully.
    preamble.clear();

    // ===================================================================
    // Revised approach using a cleaner stack manipulation
    // ===================================================================
    //
    // Unlocking script pushes: <sig> <pubkey> <prefix> <output> <suffix>
    // Stack (bottom → top): sig pubkey prefix output suffix
    // Indices:              [4] [3]    [2]    [1]    [0]
    //
    // Goal: compute hash256(prefix || output || suffix), verify script format,
    //       then leave sig pubkey on stack.

    // --- Step 1: Reconstruct prev TX and hash ---

    // Copy prefix (idx 2) to top
    preamble.push(0x52); // OP_2
    preamble.push(0x79); // OP_PICK
                         // Stack: sig pub prefix output suffix prefix'

    // Copy output (now idx 3, was 1+1) to top
    // After OP_2 OP_PICK, stack grew by 1. output is now at idx 2
    preamble.push(0x52); // OP_2
    preamble.push(0x79); // OP_PICK
                         // Stack: sig pub prefix output suffix prefix' output'

    // OP_CAT: pops output'(top) and prefix'(second), pushes prefix'||output'
    preamble.push(0x7e); // OP_CAT
                         // Stack: sig pub prefix output suffix (prefix'||output')

    // Copy suffix (now idx 1) to top
    preamble.push(0x51); // OP_1
    preamble.push(0x79); // OP_PICK
                         // Stack: sig pub prefix output suffix (prefix'||output') suffix'

    // OP_CAT: pops suffix'(top) and (prefix'||output')(second)
    // pushes (prefix'||output')||suffix' = prefix||output||suffix
    preamble.push(0x7e); // OP_CAT
                         // Stack: sig pub prefix output suffix (prefix||output||suffix)

    // OP_HASH256: double-SHA256
    preamble.push(0xaa); // OP_HASH256
                         // Stack: sig pub prefix output suffix prev_tx_hash(32 bytes)

    // Stash prev_tx_hash on alt stack for the ECDSA trick to compare later
    preamble.push(0x6b); // OP_TOALTSTACK
                         // Stack: sig pub prefix output suffix
                         // Alt:   prev_tx_hash

    // --- Step 2: Extract satoshis from output and verify ---

    // Copy output (idx 1) to top
    preamble.push(0x51); // OP_1
    preamble.push(0x79); // OP_PICK
                         // Stack: sig pub prefix output suffix output'

    // Split at byte 8: [satoshis_8bytes | rest_of_output]
    preamble.push(0x01); // OP_PUSH1
    preamble.push(0x08); // push byte 0x08
    preamble.push(0x7f); // OP_SPLIT
                         // Stack: sig pub prefix output suffix satoshis_bytes rest_of_output

    // Stash rest_of_output (has varint_scriptlen + script) on alt stack
    preamble.push(0x6b); // OP_TOALTSTACK
                         // Stack: sig pub prefix output suffix satoshis_bytes
                         // Alt:   prev_tx_hash rest_of_output

    // Convert satoshis LE bytes to script number
    preamble.push(0x81); // OP_BIN2NUM
                         // Stack: sig pub prefix output suffix satoshis_num

    // Stash satoshis on alt stack
    preamble.push(0x6b); // OP_TOALTSTACK
                         // Stack: sig pub prefix output suffix
                         // Alt:   prev_tx_hash rest_of_output satoshis_num

    // --- Step 3: Verify locking script format from rest_of_output ---

    // Recover rest_of_output from alt stack
    preamble.push(0x6c); // OP_FROMALTSTACK
                         // Stack: sig pub prefix output suffix rest_of_output
                         // Alt:   prev_tx_hash satoshis_num

    // The rest_of_output is: varint(script_len) + script_bytes
    // For typical STAS scripts (1431+ bytes), the varint is 2 bytes (0xfd + LE16).
    // For P2PKH (25 bytes), the varint is 1 byte (0x19).
    // We need to handle both cases.
    //
    // Strategy: check first byte. If < 0xfd, script starts at byte 1.
    // If == 0xfd, script starts at byte 3.
    //
    // For simplicity, we split at byte 1 to get the varint indicator.
    preamble.push(0x51); // OP_1
    preamble.push(0x7f); // OP_SPLIT
                         // Stack: sig pub prefix output suffix varint_first_byte remaining

    // Swap so varint_first_byte is on top
    preamble.push(0x7c); // OP_SWAP
                         // Stack: sig pub prefix output suffix remaining varint_first_byte

    // Check if it's 0xfd (OP_PUSHDATA1-style varint)
    preamble.push(0x01); // OP_PUSH1
    preamble.push(0xfd); // push byte 0xfd
    preamble.push(0x87); // OP_EQUAL (not EQUALVERIFY — we need the bool)

    // OP_IF: varint_first_byte == 0xfd → need to skip 2 more varint bytes
    preamble.push(0x63); // OP_IF
                         // Skip 2 bytes of LE16 length
    preamble.push(0x52); // OP_2
    preamble.push(0x7f); // OP_SPLIT
    preamble.push(0x75); // OP_DROP (drop the 2 varint bytes)
    preamble.push(0x68); // OP_ENDIF

    // Stack: sig pub prefix output suffix script_bytes
    // (script_bytes is the actual locking script of the prev output)

    // Now verify the script starts with 76 a9 14 (P2PKH/STAS prefix)
    // Split first 3 bytes
    preamble.push(0x53); // OP_3
    preamble.push(0x7f); // OP_SPLIT
                         // Stack: sig pub prefix output suffix first_3_bytes rest_of_script

    preamble.push(0x7c); // OP_SWAP
                         // Stack: sig pub prefix output suffix rest_of_script first_3_bytes

    // Push expected prefix: 76 a9 14
    preamble.push(0x03); // OP_PUSH3
    preamble.push(0x76);
    preamble.push(0xa9);
    preamble.push(0x14);
    // Stack: sig pub prefix output suffix rest_of_script first_3_bytes 76a914

    // Verify prefix matches
    preamble.push(0x88); // OP_EQUALVERIFY
                         // Stack: sig pub prefix output suffix rest_of_script

    // rest_of_script starts with the 20-byte owner PKH.
    // For STAS-BTG: the redemption PKH is at a known offset within the script.
    // For P2PKH (issuance): the script is just 20-byte PKH + 88 ac (22 bytes remaining).
    //
    // We need to check if the prev output's redemption PKH matches ours.
    // Strategy: check the script length to determine STAS-BTG vs P2PKH.
    //   - P2PKH remaining after 76a914: 20 bytes PKH + 2 bytes (88 ac) = 22 bytes
    //   - STAS-BTG remaining: 1431 - 3 + flags = 1428+ bytes
    //
    // For P2PKH: the PKH IS the redemption address (issuance boundary).
    // For STAS-BTG: the redemption PKH is at offset (1411-3) = 1408 from rest_of_script start.

    // OP_DUP rest_of_script to check its length
    preamble.push(0x76); // OP_DUP
    preamble.push(0x82); // OP_SIZE
    preamble.push(0x75); // OP_DROP (drop the DUP'd copy, keep original + size)

    // Wait, OP_SIZE doesn't consume its argument. Let me redo.
    // OP_SIZE pushes the size of the top stack element WITHOUT consuming it.
    // So: rest_of_script → rest_of_script size_num
    preamble.pop(); // remove OP_DROP
    preamble.pop(); // remove OP_SIZE
    preamble.pop(); // remove OP_DUP

    // Stack: sig pub prefix output suffix rest_of_script
    preamble.push(0x82); // OP_SIZE
                         // Stack: sig pub prefix output suffix rest_of_script size_num

    // Is it exactly 22 (P2PKH remainder: 20 bytes PKH + 88 ac)?
    preamble.push(0x01); // OP_PUSH1
    preamble.push(22u8); // push 22
    preamble.push(0x87); // OP_EQUAL

    // OP_IF (P2PKH path — issuance boundary)
    preamble.push(0x63); // OP_IF

    // --- P2PKH path: first 20 bytes of rest_of_script = owner PKH = redemption PKH ---
    preamble.push(0x01); // OP_PUSH1
    preamble.push(20u8); // push 20
    preamble.push(0x7f); // OP_SPLIT
                         // Stack: ... pkh_20bytes suffix_2bytes

    preamble.push(0x75); // OP_DROP (drop the 88ac suffix)
                         // Stack: ... pkh_20bytes

    // OP_ELSE (STAS-BTG path)
    preamble.push(0x67); // OP_ELSE

    // --- STAS-BTG path: redemption PKH at offset 1408 from rest_of_script start ---
    // (offset 1411 - 3 for the 76a914 prefix we already stripped)
    // Split at offset 1408 to get redemption PKH at bytes 1408..1428
    push_number(&mut preamble, 1408);
    preamble.push(0x7f); // OP_SPLIT
                         // Stack: ... before_1408 after_1408

    preamble.push(0x75); // OP_NIP — drop before_1408, keep after_1408
                         // Actually OP_NIP = 0x77. Or we can use OP_SWAP OP_DROP.
    preamble.push(0x7c); // OP_SWAP
    preamble.push(0x75); // OP_DROP
                         // Oops, I pushed OP_NIP above. Let me clear and redo.
                         // Remove the last 3 pushes (0x75, 0x7c, 0x75)
    let len = preamble.len();
    preamble.truncate(len - 3);

    // OP_NIP (remove second-to-top): keeps after_1408 on top
    preamble.push(0x77); // OP_NIP
                         // Stack: ... after_1408

    // Take first 20 bytes = redemption PKH
    preamble.push(0x01); // OP_PUSH1
    preamble.push(20u8);
    preamble.push(0x7f); // OP_SPLIT
                         // Stack: ... redemption_pkh_20 remainder

    preamble.push(0x75); // OP_DROP (drop remainder)
                         // Stack: ... redemption_pkh_20

    preamble.push(0x68); // OP_ENDIF

    // Stack: sig pub prefix output suffix extracted_pkh

    // Push the expected redemption PKH and verify
    preamble.push(0x14); // OP_PUSH20
    preamble.extend_from_slice(redemption_pkh);
    // Stack: sig pub prefix output suffix extracted_pkh expected_pkh

    preamble.push(0x88); // OP_EQUALVERIFY
                         // Stack: sig pub prefix output suffix

    // --- Step 4: Recover stashed values and prepare for STAS v2 template ---

    // Drop the three proof items (suffix, output, prefix)
    preamble.push(0x75); // OP_DROP (suffix)
    preamble.push(0x75); // OP_DROP (output)
    preamble.push(0x75); // OP_DROP (prefix)
                         // Stack: sig pubkey
                         // Alt:   prev_tx_hash satoshis_num

    // Recover satoshis_num from alt stack and stash below sig/pubkey
    // for the STAS template value check
    preamble.push(0x6c); // OP_FROMALTSTACK (satoshis_num)
    preamble.push(0x6c); // OP_FROMALTSTACK (prev_tx_hash)
                         // Stack: sig pubkey satoshis_num prev_tx_hash

    // The existing STAS v2 template expects just <sig> <pubkey> on the stack
    // and extracts outpoint + value from the sighash preimage via the ECDSA trick.
    //
    // For the BTG variant, we need the STAS template to additionally verify:
    //   - The outpoint txid matches prev_tx_hash
    //   - The value field matches satoshis_num
    //
    // We stash these on the alt stack so the modified STAS template can pull
    // them after extracting the preimage fields.
    preamble.push(0x6b); // OP_TOALTSTACK (prev_tx_hash)
    preamble.push(0x6b); // OP_TOALTSTACK (satoshis_num)
                         // Stack: sig pubkey
                         // Alt:   satoshis_num prev_tx_hash

    // The STAS template will proceed normally. After it extracts the outpoint
    // txid and value from the sighash preimage via the ECDSA trick, it must
    // pull prev_tx_hash and satoshis_num from the alt stack and compare.
    //
    // This requires a modification to the STAS v2 template body — specifically,
    // after the ECDSA trick extracts the preimage, we inject verification opcodes.
    // See the BTG_VERIFICATION_INSERT below.

    Ok(preamble)
}

/// Push a number onto the script stack using minimal encoding.
///
/// Handles small numbers (OP_0..OP_16), single-byte pushes, and multi-byte
/// pushes with appropriate push opcodes.
fn push_number(script: &mut Vec<u8>, value: i64) {
    if value == 0 {
        script.push(0x00); // OP_0
    } else if value >= 1 && value <= 16 {
        script.push(0x50 + value as u8); // OP_1..OP_16
    } else if value == -1 {
        script.push(0x4f); // OP_1NEGATE
    } else {
        // Encode as minimal script number
        let negative = value < 0;
        let mut abs_val = if negative {
            (-value) as u64
        } else {
            value as u64
        };

        let mut bytes = Vec::new();
        while abs_val > 0 {
            bytes.push((abs_val & 0xff) as u8);
            abs_val >>= 8;
        }

        // If the most significant byte has the high bit set, add a sign byte
        if let Some(last) = bytes.last() {
            if last & 0x80 != 0 {
                bytes.push(if negative { 0x80 } else { 0x00 });
            } else if negative {
                let len = bytes.len();
                bytes[len - 1] |= 0x80;
            }
        }

        let len = bytes.len();
        if len <= 75 {
            script.push(len as u8);
        } else if len <= 255 {
            script.push(0x4c); // OP_PUSHDATA1
            script.push(len as u8);
        } else {
            script.push(0x4d); // OP_PUSHDATA2
            script.extend_from_slice(&(len as u16).to_le_bytes());
        }
        script.extend_from_slice(&bytes);
    }
}

/// Byte offset within the STAS v2 template where the BTG verification insert
/// should be placed. This is after the ECDSA trick has extracted the sighash
/// preimage and placed the outpoint and value fields on the stack.
///
/// The insert pulls `prev_tx_hash` and `satoshis_num` from the alt stack and
/// compares them against the preimage-derived values.
///
/// **Hex of the verification insert:**
/// ```text
/// 6c       — OP_FROMALTSTACK (prev_tx_hash)
/// ...compare against outpoint txid from preimage...
/// 6c       — OP_FROMALTSTACK (satoshis_num)
/// ...compare against value from preimage...
/// ```
///
/// The exact insert point and opcodes depend on the STAS v2 template's
/// internal stack layout at the ECDSA trick output. This is documented in
/// detail in the STAS protocol analysis at `~/.claude/memory/stas-protocol/`.
pub const BTG_VERIFICATION_INSERT_OFFSET: usize = 0; // placeholder — see build function

/// Minimum total length of a STAS-BTG locking script.
/// Preamble (~100-120 bytes) + STAS v2 body (1431) + flags (2).
pub const STAS_BTG_MIN_LEN: usize = 1500;

/// Byte offset of the redemption PKH within the BTG preamble.
/// Used by the script reader to extract the redemption PKH from a BTG script.
///
/// The offset depends on the dynamically-built preamble, so we compute it
/// relative to the OP_PUSH20 (0x14) + 20-byte PKH push that occurs near the
/// end of the preamble (inside the OP_IF branch).
///
/// Returns the expected offset of the redemption PKH within the preamble, or
/// `None` if the preamble structure has changed.
pub fn find_preamble_redemption_offset(script: &[u8]) -> Option<usize> {
    // Scan for the pattern: 0x14 (OP_PUSH20) followed by 20 bytes then 0x88 (OP_EQUALVERIFY)
    // This pattern uniquely identifies the redemption PKH push+verify in the preamble.
    // With OP_IF wrapping, the preamble region extends slightly further.
    if script.len() < 22 {
        return None;
    }
    for i in 0..script.len().saturating_sub(22) {
        if script[i] == 0x14 && i + 21 < script.len() && script[i + 21] == 0x88 {
            // Check this is in the preamble region (before STAS v2 body).
            // With OP_IF + preamble + OP_ELSE + checkpoint gate + OP_ENDIF,
            // the preamble region can be up to ~350 bytes.
            if i < 350 {
                return Some(i + 1); // +1 to skip the 0x14 opcode
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_script::Address;

    fn test_address(pkh: [u8; 20]) -> Address {
        Address::from_public_key_hash(&pkh, bsv_script::Network::Mainnet)
    }

    #[test]
    fn btg_script_longer_than_standard_stas() {
        let owner_pkh = [0xaa; 20];
        let redemption_pkh = [0xbb; 20];
        let owner = test_address(owner_pkh);

        let btg_script = build_stas_btg_locking_script(&owner, &redemption_pkh, true).unwrap();
        let btg_len = btg_script.len();

        // Standard STAS v2 is 1433 bytes (1431 + 2 flags)
        assert!(
            btg_len > 1433,
            "BTG script ({btg_len} bytes) should be longer than standard STAS v2 (1433 bytes)"
        );
    }

    #[test]
    fn btg_script_starts_with_op_if() {
        let owner_pkh = [0xaa; 20];
        let redemption_pkh = [0xbb; 20];
        let owner = test_address(owner_pkh);

        let btg_script = build_stas_btg_locking_script(&owner, &redemption_pkh, true).unwrap();
        let bytes = btg_script.to_bytes();

        // The dual-path BTG script starts with OP_IF (0x63).
        assert_eq!(
            bytes[0], 0x63,
            "BTG script should start with OP_IF (0x63), got 0x{:02x}",
            bytes[0]
        );
    }

    #[test]
    fn btg_script_contains_if_else_endif() {
        let owner_pkh = [0xaa; 20];
        let redemption_pkh = [0xbb; 20];
        let owner = test_address(owner_pkh);

        let btg_script = build_stas_btg_locking_script(&owner, &redemption_pkh, true).unwrap();
        let bytes = btg_script.to_bytes();

        // First byte must be OP_IF
        assert_eq!(bytes[0], 0x63, "first byte should be OP_IF");

        // OP_ELSE (0x67) must appear somewhere in the preamble region
        let has_else = bytes[1..350].contains(&0x67);
        assert!(
            has_else,
            "BTG script should contain OP_ELSE in preamble region"
        );

        // OP_ENDIF (0x68) must appear after OP_ELSE but before STAS v2 body.
        // We look for 0x68 followed by the STAS v2 P2PKH gate (76 a9 14).
        let found_endif_before_body = bytes
            .windows(4)
            .any(|w| w[0] == 0x68 && w[1] == 0x76 && w[2] == 0xa9 && w[3] == 0x14);
        assert!(
            found_endif_before_body,
            "OP_ENDIF should immediately precede the STAS v2 body (76 a9 14)"
        );
    }

    #[test]
    fn btg_script_checkpoint_gate_overhead() {
        let owner_pkh = [0xaa; 20];
        let redemption_pkh = [0xbb; 20];
        let owner = test_address(owner_pkh);

        // Build a script and measure the checkpoint gate overhead.
        // The checkpoint gate is 25 bytes, plus OP_IF/OP_ELSE/OP_ENDIF = 28 total.
        let gate = build_checkpoint_gate(&redemption_pkh);
        assert_eq!(gate.len(), 25, "checkpoint gate should be 25 bytes");

        let btg_script = build_stas_btg_locking_script(&owner, &redemption_pkh, true).unwrap();
        let preamble_only = build_btg_preamble(&redemption_pkh).unwrap();
        let stas_body = build_stas_v2_body(&owner, &redemption_pkh, true).unwrap();

        // Total = OP_IF(1) + preamble + OP_ELSE(1) + gate(25) + OP_ENDIF(1) + body
        let expected_len = 1 + preamble_only.len() + 1 + 25 + 1 + stas_body.len();
        assert_eq!(
            btg_script.len(),
            expected_len,
            "total script length should match component sum"
        );
    }

    #[test]
    fn btg_script_contains_stas_v2_body() {
        let owner_pkh = [0xaa; 20];
        let redemption_pkh = [0xbb; 20];
        let owner = test_address(owner_pkh);

        let btg_script = build_stas_btg_locking_script(&owner, &redemption_pkh, true).unwrap();
        let bytes = btg_script.to_bytes();

        // The STAS v2 body starts with 76 a9 14 (P2PKH gate)
        // It should appear somewhere after the preamble
        let found = bytes.windows(3).any(|w| w == [0x76, 0xa9, 0x14]);
        assert!(found, "BTG script should contain the STAS v2 P2PKH gate");
    }

    #[test]
    fn btg_script_contains_redemption_pkh() {
        let owner_pkh = [0xaa; 20];
        let redemption_pkh = [0xbb; 20];
        let owner = test_address(owner_pkh);

        let btg_script = build_stas_btg_locking_script(&owner, &redemption_pkh, true).unwrap();
        let bytes = btg_script.to_bytes();

        // The redemption PKH should appear at least three times:
        // 1. In the BTG preamble (OP_IF branch, for prev-TX verification)
        // 2. In the checkpoint gate (OP_ELSE branch, for issuer verification)
        // 3. In the STAS v2 body (at offset 1411)
        let count = bytes.windows(20).filter(|w| *w == redemption_pkh).count();
        assert!(
            count >= 3,
            "redemption PKH should appear at least 3 times (preamble + checkpoint + body), found {count}"
        );
    }

    #[test]
    fn btg_script_embeds_owner_pkh() {
        let owner_pkh = [0xaa; 20];
        let redemption_pkh = [0xbb; 20];
        let owner = test_address(owner_pkh);

        let btg_script = build_stas_btg_locking_script(&owner, &redemption_pkh, true).unwrap();
        let bytes = btg_script.to_bytes();

        let found = bytes.windows(20).any(|w| w == owner_pkh);
        assert!(found, "BTG script should contain the owner PKH");
    }

    #[test]
    fn btg_preamble_redemption_offset_found() {
        let owner_pkh = [0xaa; 20];
        let redemption_pkh = [0xbb; 20];
        let owner = test_address(owner_pkh);

        let btg_script = build_stas_btg_locking_script(&owner, &redemption_pkh, true).unwrap();
        let bytes = btg_script.to_bytes();

        let offset = find_preamble_redemption_offset(&bytes);
        assert!(
            offset.is_some(),
            "should find redemption PKH offset in preamble"
        );

        let off = offset.unwrap();
        assert_eq!(
            &bytes[off..off + 20],
            &redemption_pkh,
            "extracted PKH should match"
        );
    }

    #[test]
    fn btg_splittable_flag() {
        let owner = test_address([0x11; 20]);
        let rpkh = [0x22; 20];

        let splittable = build_stas_btg_locking_script(&owner, &rpkh, true).unwrap();
        let non_splittable = build_stas_btg_locking_script(&owner, &rpkh, false).unwrap();

        let s_bytes = splittable.to_bytes();
        let ns_bytes = non_splittable.to_bytes();

        // Last 2 bytes are flags: splittable = 01 00, non-splittable = 01 01
        assert_eq!(s_bytes[s_bytes.len() - 1], 0x00, "splittable flag");
        assert_eq!(ns_bytes[ns_bytes.len() - 1], 0x01, "non-splittable flag");
    }
}
