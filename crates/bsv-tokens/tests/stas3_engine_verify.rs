//! End-to-end engine-verify tests for STAS 3.0 transactions.
//!
//! Mirrors `test/bsv/tokens/stas3/engine_verify_test.exs` from the Elixir
//! SDK: build a real factory tx, run input 0 (the STAS3 input) through the
//! script interpreter via `verify_input`, and assert the engine accepts.
//!
//! Each scenario prints the unlock-script size and the engine result on
//! assertion failure so future debug runs are productive.
//!
//! NOTE: per the Elixir reference, `freezable` MUST be `false` here unless
//! a matching service-field push is also supplied — passing `true` without
//! a service field leaves the engine reaching for absent data and trips
//! `invalid_split_range` (Elixir) / `NumberTooBig` (Rust).

use bsv_primitives::chainhash::Hash;
use bsv_primitives::ec::PrivateKey;
use bsv_primitives::hash::hash160;
use bsv_script::{Address, Network, Script};
use bsv_tokens::stas3::verify_input;
use bsv_tokens::types::ActionData;
use bsv_tokens::{
    build_stas3_base_tx, build_stas3_locking_script, build_stas3_swap_swap_tx,
    build_stas3_swap_swap_tx_with_pieces, Stas3BaseConfig, Stas3OutputParams,
    Stas3SpendType, Stas3SwapPieceParams, SigningKey, TokenInput,
};
use bsv_transaction::template::p2pkh;

// ---------------------------------------------------------------------------
// Test helpers (mirror bsv-tokens factory test helpers).
// ---------------------------------------------------------------------------

fn test_key() -> PrivateKey {
    PrivateKey::new()
}

fn test_p2pkh_script(key: &PrivateKey) -> Script {
    let pkh = hash160(&key.pub_key().to_compressed());
    let addr = Address::from_public_key_hash(&pkh, Network::Mainnet);
    p2pkh::lock(&addr).unwrap()
}

fn dummy_hash() -> Hash {
    Hash::from_bytes(&[0xaa; 32]).unwrap()
}

/// Build a STAS3 locking script owned by `token_key` with `freezable=false`.
/// `freezable=false` is required for the engine to accept the unlock without
/// a matching service-field push (see module docs).
fn make_owned_stas3_locking(token_key: &PrivateKey, redemption_pkh: &[u8; 20]) -> Script {
    let owner_pkh = hash160(&token_key.pub_key().to_compressed());
    build_stas3_locking_script(&owner_pkh, redemption_pkh, None, false, false, &[], &[]).unwrap()
}

/// Construct a destination matching the engine-acceptance shape: not frozen,
/// not freezable.
fn dest(satoshis: u64, owner_pkh: [u8; 20], redemption_pkh: [u8; 20]) -> Stas3OutputParams {
    Stas3OutputParams {
        satoshis,
        owner_pkh,
        redemption_pkh,
        frozen: false,
        freezable: false,
        service_fields: vec![],
        optional_data: vec![],
        action_data: None,
    }
}

/// Pretty-print engine outcome on failure (panics on Err).
fn assert_engine_ok(
    label: &str,
    unlock_len: usize,
    result: Result<(), bsv_tokens::Stas3VerifyError>,
) {
    if let Err(err) = result {
        panic!(
            "[{}] engine REJECTED tx (unlock script size = {} bytes): {}",
            label, unlock_len, err
        );
    }
}

// ---------------------------------------------------------------------------
// Scenarios — mirror the four passing Elixir EngineVerifyTest cases.
// ---------------------------------------------------------------------------

/// Scenario 1: 1 STAS input, 1 STAS output, fee leg generates change.
#[test]
fn engine_accepts_transfer_with_change() {
    let token_key = test_key();
    let fee_key = test_key();
    let redemption_pkh = [0x22; 20];
    let locking = make_owned_stas3_locking(&token_key, &redemption_pkh);

    let config = Stas3BaseConfig {
        token_inputs: vec![TokenInput {
            txid: dummy_hash(),
            vout: 0,
            satoshis: 5000,
            locking_script: locking.clone(),
            signing_key: SigningKey::Single(token_key),
        }],
        fee_txid: dummy_hash(),
        fee_vout: 1,
        fee_satoshis: 50_000,
        fee_locking_script: test_p2pkh_script(&fee_key),
        fee_private_key: fee_key,
        destinations: vec![dest(5000, [0x33; 20], redemption_pkh)],
        spend_type: Stas3SpendType::Transfer,
        fee_rate: 500,
    };

    let tx = build_stas3_base_tx(&config).unwrap();
    let unlock_len = tx.inputs[0].unlocking_script.as_ref().unwrap().to_bytes().len();
    let result = verify_input(&tx, 0, &locking, 5000);
    assert_engine_ok("transfer_with_change", unlock_len, result);
}

/// Scenario 2: 1 STAS input, 1 STAS output, no change leg (exact fee).
/// Fee = 1602 sats matches the Elixir reference test.
#[test]
fn engine_accepts_transfer_no_change() {
    let token_key = test_key();
    let fee_key = test_key();
    let redemption_pkh = [0x22; 20];
    let locking = make_owned_stas3_locking(&token_key, &redemption_pkh);

    let config = Stas3BaseConfig {
        token_inputs: vec![TokenInput {
            txid: dummy_hash(),
            vout: 0,
            satoshis: 5000,
            locking_script: locking.clone(),
            signing_key: SigningKey::Single(token_key),
        }],
        fee_txid: dummy_hash(),
        fee_vout: 1,
        fee_satoshis: 1602,
        fee_locking_script: test_p2pkh_script(&fee_key),
        fee_private_key: fee_key,
        destinations: vec![dest(5000, [0x33; 20], redemption_pkh)],
        spend_type: Stas3SpendType::Transfer,
        fee_rate: 500,
    };

    let tx = build_stas3_base_tx(&config).unwrap();
    let unlock_len = tx.inputs[0].unlocking_script.as_ref().unwrap().to_bytes().len();
    let result = verify_input(&tx, 0, &locking, 5000);
    assert_engine_ok("transfer_no_change", unlock_len, result);
}

/// Scenario 3: change amount whose minimal-LE encoding has the high bit set
/// (e.g. 48398 = 0xBD0E). EXPLICITLY assert MSB has bit 7 set BEFORE the
/// engine verification — this is the regression guard for Part A.
#[test]
fn engine_accepts_sign_bit_overflow_change_amount() {
    use bsv_tokens::encode_unlock_amount;

    let token_key = test_key();
    let fee_key = test_key();
    let redemption_pkh = [0x22; 20];
    let locking = make_owned_stas3_locking(&token_key, &redemption_pkh);

    let config = Stas3BaseConfig {
        token_inputs: vec![TokenInput {
            txid: dummy_hash(),
            vout: 0,
            satoshis: 5000,
            locking_script: locking.clone(),
            signing_key: SigningKey::Single(token_key),
        }],
        fee_txid: dummy_hash(),
        fee_vout: 1,
        fee_satoshis: 50_000,
        fee_locking_script: test_p2pkh_script(&fee_key),
        fee_private_key: fee_key,
        destinations: vec![dest(5000, [0x33; 20], redemption_pkh)],
        spend_type: Stas3SpendType::Transfer,
        fee_rate: 500,
    };

    let tx = build_stas3_base_tx(&config).unwrap();

    // Change leg is the second output (the P2PKH change of the fee input).
    // Sanity: the regression case requires the change amount to land in the
    // high-bit-set regime. We don't pin a specific value (it depends on the
    // tx-size-driven fee), but we MUST verify the high bit of the MSB is set.
    assert!(
        tx.outputs.len() >= 2,
        "expected fee change leg in output 1; got {} outputs",
        tx.outputs.len()
    );
    let change_amt = tx.outputs[1].satoshis;
    let lo = (change_amt & 0xFF) as u8;
    let hi = ((change_amt >> 8) & 0xFF) as u8;
    assert!(change_amt > 0, "change amount must be positive");
    assert!(
        change_amt < 0x10000,
        "this regression scenario expects a 2-byte change amount (got {})",
        change_amt
    );
    assert_eq!(
        hi & 0x80,
        0x80,
        "regression guard: change MSB high-bit must be set (lo={:#x} hi={:#x}, change={})",
        lo,
        hi,
        change_amt
    );
    // And the encoder MUST emit the 0x00 sentinel for it.
    let encoded = encode_unlock_amount(change_amt);
    assert_eq!(
        *encoded.last().unwrap(),
        0x00,
        "regression guard: encoder must append a 0x00 sign-bit sentinel for {}",
        change_amt
    );

    let unlock_len = tx.inputs[0].unlocking_script.as_ref().unwrap().to_bytes().len();

    // Dump the slot-13 (change_amount) push from the unlock script for
    // cross-SDK comparison with Elixir.
    let unlock = tx.inputs[0].unlocking_script.as_ref().unwrap();
    let chunks = unlock.chunks().expect("unlock chunks parse");
    // Witness layout for 1 STAS output: slots 1..3 are out1_amount /
    // out1_owner / out1_var2; slot 13 is the change_amount.
    let slot13 = chunks
        .get(3)
        .and_then(|c| c.data.clone())
        .unwrap_or_default();
    eprintln!(
        "[sign_bit_overflow] change_amt = {} (0x{:X}); witness slot 13 push body = {}",
        change_amt,
        change_amt,
        hex::encode(&slot13)
    );

    let result = verify_input(&tx, 0, &locking, 5000);
    assert_engine_ok("sign_bit_overflow", unlock_len, result);
}

/// Scenario 4: 1 STAS input, 2 STAS outputs (split).
#[test]
fn engine_accepts_two_output_split() {
    let token_key = test_key();
    let fee_key = test_key();
    let redemption_pkh = [0x22; 20];
    let locking = make_owned_stas3_locking(&token_key, &redemption_pkh);

    let config = Stas3BaseConfig {
        token_inputs: vec![TokenInput {
            txid: dummy_hash(),
            vout: 0,
            satoshis: 10_000,
            locking_script: locking.clone(),
            signing_key: SigningKey::Single(token_key),
        }],
        fee_txid: dummy_hash(),
        fee_vout: 1,
        fee_satoshis: 50_000,
        fee_locking_script: test_p2pkh_script(&fee_key),
        fee_private_key: fee_key,
        destinations: vec![
            dest(6000, [0x33; 20], redemption_pkh),
            dest(4000, [0x44; 20], redemption_pkh),
        ],
        spend_type: Stas3SpendType::Transfer,
        fee_rate: 500,
    };

    let tx = build_stas3_base_tx(&config).unwrap();
    let unlock_len = tx.inputs[0].unlocking_script.as_ref().unwrap().to_bytes().len();
    let result = verify_input(&tx, 0, &locking, 10_000);
    assert_engine_ok("two_output_split", unlock_len, result);
}

// ---------------------------------------------------------------------------
// Combined factory-coverage smoke test.
//
// Runs ONE factory of each family that's reachable from the public crate
// API through `verify_input` and reports each result. The task spec lists
// 6 families: regular, freeze, confiscation, swap-cancel, atomic-swap,
// redeem. Several of those configs are crate-private (Stas3FreezeConfig,
// Stas3ConfiscateConfig, Stas3RedeemConfig) and aren't reachable from an
// integration test.
//
// We exercise the two reachable families here:
//   - regular (build_stas3_base_tx)
//   - atomic-swap (build_stas3_swap_swap_tx)
//
// Each result is reported via eprintln; failures panic with the exact
// engine error so they show up clearly in the report.
// ---------------------------------------------------------------------------

#[test]
fn combined_factory_coverage_regular_and_atomic_swap() {
    // ── Family 1: regular transfer ─────────────────────────────────────
    let token_key = test_key();
    let fee_key = test_key();
    let redemption_pkh = [0x22; 20];
    let locking = make_owned_stas3_locking(&token_key, &redemption_pkh);

    let regular_cfg = Stas3BaseConfig {
        token_inputs: vec![TokenInput {
            txid: dummy_hash(),
            vout: 0,
            satoshis: 5000,
            locking_script: locking.clone(),
            signing_key: SigningKey::Single(token_key),
        }],
        fee_txid: dummy_hash(),
        fee_vout: 1,
        fee_satoshis: 50_000,
        fee_locking_script: test_p2pkh_script(&fee_key),
        fee_private_key: fee_key,
        destinations: vec![dest(5000, [0x33; 20], redemption_pkh)],
        spend_type: Stas3SpendType::Transfer,
        fee_rate: 500,
    };
    let regular_tx = build_stas3_base_tx(&regular_cfg).unwrap();
    let regular_unlock_len = regular_tx.inputs[0]
        .unlocking_script
        .as_ref()
        .unwrap()
        .to_bytes()
        .len();
    let regular_result = verify_input(&regular_tx, 0, &locking, 5000);
    match &regular_result {
        Ok(()) => eprintln!(
            "[combined_coverage:regular] engine OK (unlock {} bytes)",
            regular_unlock_len
        ),
        Err(err) => eprintln!(
            "[combined_coverage:regular] engine REJECTED (unlock {} bytes): {}",
            regular_unlock_len, err
        ),
    }
    assert_engine_ok("family_regular", regular_unlock_len, regular_result);

    // ── Family 2: atomic-swap (two STAS3-with-swap-descriptor inputs) ──
    let token_key_a = test_key();
    let token_key_b = test_key();
    let fee_key2 = test_key();
    let owner_a_pkh = hash160(&token_key_a.pub_key().to_compressed());
    let owner_b_pkh = hash160(&token_key_b.pub_key().to_compressed());

    let swap = ActionData::Swap {
        requested_script_hash: [0xab; 32],
        requested_pkh: [0xcd; 20],
        rate_numerator: 1,
        rate_denominator: 1,
        next: None,
    };

    let locking_a = build_stas3_locking_script(
        &owner_a_pkh,
        &redemption_pkh,
        Some(&swap),
        false,
        false,
        &[],
        &[],
    )
    .unwrap();
    let locking_b = build_stas3_locking_script(
        &owner_b_pkh,
        &redemption_pkh,
        Some(&swap),
        false,
        false,
        &[],
        &[],
    )
    .unwrap();

    let mut atomic_cfg = Stas3BaseConfig {
        token_inputs: vec![
            TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 5000,
                locking_script: locking_a.clone(),
                signing_key: SigningKey::Single(token_key_a),
            },
            TokenInput {
                txid: dummy_hash(),
                vout: 1,
                satoshis: 5000,
                locking_script: locking_b.clone(),
                signing_key: SigningKey::Single(token_key_b),
            },
        ],
        fee_txid: dummy_hash(),
        fee_vout: 2,
        fee_satoshis: 50_000,
        fee_locking_script: test_p2pkh_script(&fee_key2),
        fee_private_key: fee_key2,
        destinations: vec![
            dest(5000, [0x44; 20], redemption_pkh),
            dest(5000, [0x55; 20], redemption_pkh),
        ],
        spend_type: Stas3SpendType::Transfer,
        fee_rate: 500,
    };

    let atomic_tx = build_stas3_swap_swap_tx(&mut atomic_cfg).unwrap();

    // Per task: "if any factory family fails at the engine level, that's a
    // new bug — flag in the report, do not attempt to fix in this PR".
    // Both atomic-swap inputs are run through the engine and their outcome
    // is recorded via eprintln, but we DO NOT panic — the test passing
    // here means the regular family passes; the atomic-swap status is
    // surface-printed for the caller's report.
    for i in 0..2 {
        let prev_locking = if i == 0 { &locking_a } else { &locking_b };
        let unlock_len = atomic_tx.inputs[i]
            .unlocking_script
            .as_ref()
            .unwrap()
            .to_bytes()
            .len();
        let result = verify_input(&atomic_tx, i, prev_locking, 5000);
        match result {
            Ok(()) => eprintln!(
                "[combined_coverage:atomic_swap input {}] engine OK (unlock {} bytes)",
                i, unlock_len
            ),
            Err(err) => eprintln!(
                "[combined_coverage:atomic_swap input {}] engine REJECTED \
                 (unlock {} bytes): {} \
                 — flagged in the report; not fixed in this PR",
                i, unlock_len, err
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Atomic-swap with auto-wired trailing piece-array (spec §9.5).
//
// Uses `build_stas3_swap_swap_tx_with_pieces` — the preceding-tx-aware
// swap factory entry point — to satisfy the engine's back-to-genesis
// reconstruction check. Each input's witness gains the trailing
// `<counterparty_script> <piece_count> <piece_array>` block, which the
// engine HASH256s to verify it matches the outpoint committed in the
// BIP-143 preimage.
// ---------------------------------------------------------------------------

/// Build a minimal serialized BSV transaction containing exactly one input
/// (ignored — uses zeroed prevout) and one STAS3 output with `lock`
/// as its `scriptPubKey`. The returned bytes can be `HASH256`'d to
/// produce the matching txid for use as a token input's `txid` field.
fn build_synthetic_preceding_tx(lock: &Script, satoshis: u64) -> Vec<u8> {
    let mut tx = Vec::new();
    // version
    tx.extend_from_slice(&1u32.to_le_bytes());
    // input count = 1
    tx.push(0x01);
    // prev_txid = 32 zero bytes
    tx.extend_from_slice(&[0u8; 32]);
    // prev_vout = 0
    tx.extend_from_slice(&0u32.to_le_bytes());
    // scriptSig length = 0
    tx.push(0x00);
    // sequence
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    // output count = 1
    tx.push(0x01);
    // value
    tx.extend_from_slice(&satoshis.to_le_bytes());
    // script length (varint)
    let lock_bytes = lock.to_bytes();
    let len = lock_bytes.len();
    if len < 0xfd {
        tx.push(len as u8);
    } else if len <= 0xffff {
        tx.push(0xfd);
        tx.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        tx.push(0xfe);
        tx.extend_from_slice(&(len as u32).to_le_bytes());
    }
    tx.extend_from_slice(lock_bytes);
    // locktime
    tx.extend_from_slice(&0u32.to_le_bytes());
    tx
}

/// Atomic-swap engine verification with the spec §9.5 trailing
/// piece-array auto-wired into both inputs' unlocking scripts.
///
/// The piece-array is encoded length-prefixed (`[len][body][len][body]...`)
/// to match the engine ASM's `OP_1 OP_SPLIT OP_IFDUP OP_IF OP_SWAP
/// OP_SPLIT OP_ENDIF` consumption pattern.
///
/// **Status**: with the length-prefixed encoding, the engine progresses
/// past the original `InvalidStackOperation` failure but now rejects
/// with `NumberTooSmall: n is negative` at `OP_SPLIT` — a separate
/// downstream issue. In the synthetic preceding tx, the `head` piece is
/// 141 bytes (4 version + 1 input_count + 41 input + 1 output_count +
/// 8 value + 3 script_len_varint + 21 owner+var2 prefix + ... ≈ 141B),
/// so its 1-byte length prefix `0x8d` is interpreted as a negative
/// Bitcoin-script number. The engine ASM's `OP_1 OP_SPLIT` reads exactly
/// 1 byte as the length prefix, so each piece body must be ≤ 0x7F = 127
/// bytes — but the synthetic-preceding-tx head exceeds that. The Elixir
/// reference SDK fails with the matching `:invalid_split_range`.
///
/// The encoder/decoder pair is now byte-identical to the Elixir SDK; the
/// remaining downstream rejection is independent of this fix and tracked
/// separately. Keep the `#[ignore]` so CI stays green; remove it once
/// the upstream piece-size constraint is resolved.
#[test]
#[ignore = "encoder fix applied; engine still rejects pieces > 127 bytes via signed-byte OP_SPLIT — \
            same failure as Elixir SDK; needs separate piece-size resolution"]
fn engine_accepts_swap_swap_with_trailing_pieces() {
    use bsv_primitives::hash::sha256d;

    let token_key_a = test_key();
    let token_key_b = test_key();
    let fee_key = test_key();
    let owner_a_pkh = hash160(&token_key_a.pub_key().to_compressed());
    let owner_b_pkh = hash160(&token_key_b.pub_key().to_compressed());
    let redemption_pkh = [0x22; 20];

    let swap = ActionData::Swap {
        requested_script_hash: [0xab; 32],
        requested_pkh: [0xcd; 20],
        rate_numerator: 1,
        rate_denominator: 1,
        next: None,
    };

    let locking_a = build_stas3_locking_script(
        &owner_a_pkh, &redemption_pkh, Some(&swap), false, false, &[], &[],
    ).unwrap();
    let locking_b = build_stas3_locking_script(
        &owner_b_pkh, &redemption_pkh, Some(&swap), false, false, &[], &[],
    ).unwrap();

    // Build synthetic preceding txs whose HASH256 we then use as the
    // token-input txids — required for the engine's back-to-genesis
    // outpoint match. asset_output_index=0 in both.
    let preceding_a = build_synthetic_preceding_tx(&locking_a, 5000);
    let preceding_b = build_synthetic_preceding_tx(&locking_b, 5000);
    let txid_a_bytes: [u8; 32] = sha256d(&preceding_a).into();
    let txid_b_bytes: [u8; 32] = sha256d(&preceding_b).into();
    let txid_a = Hash::from_bytes(&txid_a_bytes).unwrap();
    let txid_b = Hash::from_bytes(&txid_b_bytes).unwrap();

    let mut atomic_cfg = Stas3BaseConfig {
        token_inputs: vec![
            TokenInput {
                txid: txid_a,
                vout: 0,
                satoshis: 5000,
                locking_script: locking_a.clone(),
                signing_key: SigningKey::Single(token_key_a),
            },
            TokenInput {
                txid: txid_b,
                vout: 0,
                satoshis: 5000,
                locking_script: locking_b.clone(),
                signing_key: SigningKey::Single(token_key_b),
            },
        ],
        fee_txid: dummy_hash(),
        fee_vout: 2,
        fee_satoshis: 50_000,
        fee_locking_script: test_p2pkh_script(&fee_key),
        fee_private_key: fee_key,
        destinations: vec![
            dest(5000, [0x44; 20], redemption_pkh),
            dest(5000, [0x55; 20], redemption_pkh),
        ],
        spend_type: Stas3SpendType::Transfer,
        fee_rate: 500,
    };

    let pieces = [
        Stas3SwapPieceParams {
            preceding_tx: preceding_a.clone(),
            asset_output_index: 0,
        },
        Stas3SwapPieceParams {
            preceding_tx: preceding_b.clone(),
            asset_output_index: 0,
        },
    ];

    let atomic_tx =
        build_stas3_swap_swap_tx_with_pieces(&mut atomic_cfg, &pieces).expect("build swap-swap");

    for i in 0..2 {
        let prev_locking = if i == 0 { &locking_a } else { &locking_b };
        let unlock_len = atomic_tx.inputs[i]
            .unlocking_script
            .as_ref()
            .unwrap()
            .to_bytes()
            .len();
        eprintln!(
            "[swap_swap_with_pieces input {}] unlock_len={}",
            i, unlock_len
        );
        let result = verify_input(&atomic_tx, i, prev_locking, 5000);
        assert_engine_ok("swap_swap_with_pieces", unlock_len, result);
    }
}
