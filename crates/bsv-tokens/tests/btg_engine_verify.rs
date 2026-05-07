//! End-to-end script-engine tests for STAS-BTG.
//!
//! See `~/work/stas/STAS_BTG_SPEC_REVIEW.md` for the spec these tests target.
//! Q1 of that doc identifies the gap currently being filled by these tests:
//! the BTG preamble's `76 a9 14` prefix check rejects any parent whose
//! locking script is BTG-wrapped (and thus starts with `0x63` / `OP_IF`).
//!
//! These tests are the canonical end-to-end smoke check for BTG. They mirror
//! the existing `stas3_engine_verify` tests but exercise the BTG dual-path
//! locking script through the real `bsv_script::interpreter::Engine`.
//!
//! ## Test cases
//!
//! 1. [`btg_path_a_p2pkh_parent_engine_verify`] — issuance boundary.
//!    Parent UTXO is a plain `P2PKH(redemption_pkh)` output, child TX
//!    spends it via Path A. This exercises the "rest_of_script length 22"
//!    sub-branch of the preamble's parent-shape check.
//!
//! 2. [`btg_path_a_btg_parent_engine_verify`] — multi-hop.
//!    Parent UTXO is itself a STAS-BTG-locked output (i.e., starts with
//!    `OP_IF`). Child TX spends it via Path A. This is the BTG → BTG
//!    transition that the protocol must support for any post-issuance hop.
//!
//! Both tests are expected to FAIL until the implementation gap is closed.
//! When they pass, we have an end-to-end demonstration that BTG provenance
//! is engine-verifiable in both the bootstrap and the recursive cases.

use bsv_primitives::chainhash::Hash;
use bsv_primitives::ec::PrivateKey;
use bsv_primitives::hash::{hash160, sha256d};
use bsv_script::{Address, Network, Script};
use bsv_tokens::stas3_verify_input;
use bsv_tokens::{
    build_btg_transfer_tx, build_stas_btg_locking_script, BtgPayment, BtgTransferConfig,
    Destination, Payment, SigningKey,
};
use bsv_transaction::input::TransactionInput;
use bsv_transaction::output::TransactionOutput;
use bsv_transaction::template::p2pkh;
use bsv_transaction::transaction::Transaction;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn key_and_addr() -> (PrivateKey, Address, [u8; 20]) {
    let key = PrivateKey::new();
    let pkh = hash160(&key.pub_key().to_compressed());
    let addr = Address::from_public_key_hash(&pkh, Network::Mainnet);
    (key, addr, pkh)
}

/// Compute the `Hash` (internal-byte-order, as used by `Payment::txid`) for a
/// raw transaction.
fn raw_to_txid_hash(raw: &[u8]) -> Hash {
    let mut bytes = sha256d(raw);
    bytes.reverse();
    Hash::from_bytes(&bytes).unwrap()
}

/// Build a fake "parent" transaction whose `output[0]` carries `locking_script`
/// and `satoshis`. The single input points at a fixed dummy outpoint with an
/// empty unlocking script — sufficient because our tests never re-execute
/// this parent's input scripts; we only use the parent's bytes for the BTG
/// proof segments.
fn build_fake_parent_with_output(satoshis: u64, locking_script: Script) -> (Vec<u8>, Hash) {
    let mut tx = Transaction::new();

    let mut input = TransactionInput::new();
    input.source_txid = [0xdd; 32];
    input.source_tx_out_index = 0;
    input.unlocking_script = Some(Script::new());
    input.sequence_number = 0xffffffff;
    tx.add_input(input);

    tx.add_output(TransactionOutput {
        satoshis,
        locking_script,
        change: false,
    });

    let raw = tx.to_bytes();
    let txid = raw_to_txid_hash(&raw);
    (raw, txid)
}

/// Build a `Payment` that references `txid:vout`, owned by `key` (P2PKH-locked).
fn p2pkh_payment(txid: Hash, vout: u32, satoshis: u64, key: PrivateKey, addr: &Address) -> Payment {
    let locking_script = p2pkh::lock(addr).unwrap();
    Payment {
        txid,
        vout,
        satoshis,
        locking_script,
        signing_key: SigningKey::Single(key),
    }
}

/// Build a `Payment` that references `txid:vout`, owned by `key`, locked by
/// the canonical STAS-BTG script for the given owner / redemption PKH.
fn btg_payment(
    txid: Hash,
    vout: u32,
    satoshis: u64,
    key: PrivateKey,
    owner_addr: &Address,
    redemption_pkh: &[u8; 20],
) -> Payment {
    let locking_script = build_stas_btg_locking_script(owner_addr, redemption_pkh, true).unwrap();
    Payment {
        txid,
        vout,
        satoshis,
        locking_script,
        signing_key: SigningKey::Single(key),
    }
}

// ---------------------------------------------------------------------------
// Test 1 — issuance boundary (parent is P2PKH(redemption_pkh))
// ---------------------------------------------------------------------------

#[test]
#[ignore = "BTG preamble incomplete — currently fails with OP_EQUALVERIFY in the parent-shape check. See ~/work/stas/STAS_BTG_SPEC_REVIEW.md Q1. Run with `cargo test -- --ignored` to exercise."]
fn btg_path_a_p2pkh_parent_engine_verify() {
    // Token holder + redemption + funding keys.
    let (token_key, _token_addr, _token_pkh) = key_and_addr();
    let (_redemption_key, _redemption_addr, redemption_pkh) = key_and_addr();
    let (funding_key, funding_addr, _funding_pkh) = key_and_addr();
    let (_recipient_key, recipient_addr, _recipient_pkh) = key_and_addr();

    // ------------------------------------------------------------------
    // PARENT TX — has output[0] = P2PKH(redemption_pkh) holding the token.
    // This represents the issuance boundary: the very first BTG transfer
    // spends a P2PKH UTXO controlled by the redemption key.
    //
    // NOTE: under Path A the spent UTXO's locking script is the script
    // currently executing — which is the BTG-wrapped script, not P2PKH.
    // So this test really exercises whether Path A's "rest_of_script
    // length 22" sub-branch can ever be reached given that the wrapping
    // around the v2 body changes the prefix bytes.
    // ------------------------------------------------------------------
    let token_satoshis = 5_000;

    // Build P2PKH locking script as if it were the parent's output[0].
    // The redemption key holds the issuance UTXO.
    let redemption_addr = {
        let pkh = redemption_pkh;
        Address::from_public_key_hash(&pkh, Network::Mainnet)
    };
    let p2pkh_locking = p2pkh::lock(&redemption_addr).unwrap();
    let (parent_raw, parent_txid) = build_fake_parent_with_output(token_satoshis, p2pkh_locking);

    // ------------------------------------------------------------------
    // FUNDING TX — needed for the child TX's funding input.
    // We synthesise a P2PKH funding UTXO; its locking script just needs
    // to satisfy the engine when the funding input is signed.
    // ------------------------------------------------------------------
    let funding_satoshis = 50_000;
    let funding_locking = p2pkh::lock(&funding_addr).unwrap();
    let (_funding_raw, funding_txid) =
        build_fake_parent_with_output(funding_satoshis, funding_locking);

    // ------------------------------------------------------------------
    // CHILD TX — Path A spend of the parent's output[0]. The factory
    // builds a BTG-locked output[0] for the recipient.
    //
    // IMPORTANT: BtgTransferConfig.token_utxo.payment.locking_script
    // should hold the parent's actual locking script — which, in the
    // real protocol, is the BTG-wrapped script. We use P2PKH here as
    // a stress test of the issuance-boundary case.
    // ------------------------------------------------------------------
    let token_payment = p2pkh_payment(
        parent_txid,
        0,
        token_satoshis,
        token_key.clone(),
        &redemption_addr,
    );
    let parent_locking_for_verify = token_payment.locking_script.clone();
    let funding_payment = p2pkh_payment(
        funding_txid,
        0,
        funding_satoshis,
        funding_key,
        &funding_addr,
    );

    let cfg = BtgTransferConfig {
        token_utxo: BtgPayment {
            payment: token_payment,
            prev_raw_tx: parent_raw,
        },
        destination: Destination {
            address: recipient_addr,
            satoshis: token_satoshis,
        },
        redemption_pkh,
        splittable: true,
        funding: funding_payment,
        fee_rate: 500,
    };

    let child_tx = build_btg_transfer_tx(&cfg).expect("build_btg_transfer_tx failed");

    // ------------------------------------------------------------------
    // ENGINE VERIFY — run the child's input 0 through the script
    // interpreter against the parent's actual locking script.
    //
    // For the issuance boundary, the parent's locking script IS P2PKH —
    // and Path A's preamble expects a BTG-wrapped or P2PKH-shaped parent.
    // ------------------------------------------------------------------
    let result = stas3_verify_input(&child_tx, 0, &parent_locking_for_verify, token_satoshis);

    assert!(
        result.is_ok(),
        "BTG Path A engine verify (P2PKH parent / issuance boundary) rejected: {:?}",
        result.err()
    );
}

// ---------------------------------------------------------------------------
// Test 2 — multi-hop (parent is itself BTG-locked)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "BTG preamble incomplete — currently fails with NumberTooBig (OP_SPLIT out of bounds). The preamble's offset-1408 arithmetic does not match the byte layout of a BTG-wrapped parent. See ~/work/stas/STAS_BTG_SPEC_REVIEW.md Q1. Run with `cargo test -- --ignored` to exercise."]
fn btg_path_a_btg_parent_engine_verify() {
    // Token holder + redemption + funding keys.
    let (token_key, token_addr, _token_pkh) = key_and_addr();
    let (_redemption_key, _redemption_addr, redemption_pkh) = key_and_addr();
    let (funding_key, funding_addr, _funding_pkh) = key_and_addr();
    let (_recipient_key, recipient_addr, _recipient_pkh) = key_and_addr();

    // ------------------------------------------------------------------
    // PARENT TX — has output[0] = STAS-BTG locked, holding the token.
    // This is the multi-hop case: the parent UTXO being spent is itself
    // BTG-wrapped, so the Path A preamble must be able to recognise a
    // BTG-shaped parent locking script (length != 22 after stripping
    // `76 a9 14`, redemption PKH at offset 1408).
    // ------------------------------------------------------------------
    let token_satoshis = 5_000;
    let parent_btg_locking = build_stas_btg_locking_script(&token_addr, &redemption_pkh, true)
        .expect("build_stas_btg_locking_script failed for parent");
    let (parent_raw, parent_txid) =
        build_fake_parent_with_output(token_satoshis, parent_btg_locking.clone());

    // Funding UTXO.
    let funding_satoshis = 50_000;
    let funding_locking = p2pkh::lock(&funding_addr).unwrap();
    let (_funding_raw, funding_txid) =
        build_fake_parent_with_output(funding_satoshis, funding_locking);

    // ------------------------------------------------------------------
    // CHILD TX — Path A spend of the parent's BTG-locked output[0].
    // ------------------------------------------------------------------
    let token_payment = btg_payment(
        parent_txid,
        0,
        token_satoshis,
        token_key.clone(),
        &token_addr,
        &redemption_pkh,
    );
    let parent_locking_for_verify = token_payment.locking_script.clone();
    let funding_payment = p2pkh_payment(
        funding_txid,
        0,
        funding_satoshis,
        funding_key,
        &funding_addr,
    );

    let cfg = BtgTransferConfig {
        token_utxo: BtgPayment {
            payment: token_payment,
            prev_raw_tx: parent_raw,
        },
        destination: Destination {
            address: recipient_addr,
            satoshis: token_satoshis,
        },
        redemption_pkh,
        splittable: true,
        funding: funding_payment,
        fee_rate: 500,
    };

    let child_tx = build_btg_transfer_tx(&cfg).expect("build_btg_transfer_tx failed");

    // ------------------------------------------------------------------
    // ENGINE VERIFY — parent locking script IS the BTG-wrapped script.
    // ------------------------------------------------------------------
    let result = stas3_verify_input(&child_tx, 0, &parent_locking_for_verify, token_satoshis);

    assert!(
        result.is_ok(),
        "BTG Path A engine verify (BTG-locked parent / multi-hop) rejected: {:?}",
        result.err()
    );
}
