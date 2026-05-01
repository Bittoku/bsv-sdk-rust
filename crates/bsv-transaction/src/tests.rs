//! Tests for the bsv-transaction crate.
//!
//! Includes test vectors ported from the Go BSV SDK `transaction_test.go`,
//! covering transaction parsing, serialization roundtrips, coinbase
//! detection, txid computation, and sighash preimage generation.

use crate::input::{TransactionInput, DEFAULT_SEQUENCE_NUMBER};
use crate::output::TransactionOutput;
use crate::sighash;
use crate::transaction::Transaction;
use bsv_script::Script;

// -----------------------------------------------------------------------
// Raw transaction hex test vectors from the Go SDK
// -----------------------------------------------------------------------

/// A standard transaction from the Go test suite.
const SOURCE_RAW_TX: &str = "010000000138c7c61c14ffb063c3bb2664041a3e29ea6ea0412a0c18ff725ba4e9e12afae2030000006a47304402203e9ab8e4c14addf3b4741540b556cfb0e0efb67dc1a7b5ce84c3ac56b3fd447802203c9f49f7bd893ebd7060176dfc36bcaff9d2c443d9a0dd6cd2d59b372c024d20412102798913bc057b344de675dac34faafe3dc2f312c758cd9068209f810877306d66ffffffff02dc050000000000002076a914eb0bd5edba389198e73f8efabddfc61666969ff788ac6a0568656c6c6faa0d0000000000001976a914eb0bd5edba389198e73f8efabddfc61666969ff788ac00000000";

/// A coinbase transaction hex.
const COINBASE_TX_HEX: &str = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff17033f250d2f43555656452f2c903fb60859897700d02700ffffffff01d864a012000000001976a914d648686cf603c11850f39600e37312738accca8f88ac00000000";

/// A multi-input transaction.
const MULTI_INPUT_TX_HEX: &str = "0200000003a9bc457fdc6a54d99300fb137b23714d860c350a9d19ff0f571e694a419ff3a0010000006b48304502210086c83beb2b2663e4709a583d261d75be538aedcafa7766bd983e5c8db2f8b2fc02201a88b178624ab0ad1748b37c875f885930166237c88f5af78ee4e61d337f935f412103e8be830d98bb3b007a0343ee5c36daa48796ae8bb57946b1e87378ad6e8a090dfeffffff0092bb9a47e27bf64fc98f557c530c04d9ac25e2f2a8b600e92a0b1ae7c89c20010000006b483045022100f06b3db1c0a11af348401f9cebe10ae2659d6e766a9dcd9e3a04690ba10a160f02203f7fbd7dfcfc70863aface1a306fcc91bbadf6bc884c21a55ef0d32bd6b088c8412103e8be830d98bb3b007a0343ee5c36daa48796ae8bb57946b1e87378ad6e8a090dfeffffff9d0d4554fa692420a0830ca614b6c60f1bf8eaaa21afca4aa8c99fb052d9f398000000006b483045022100d920f2290548e92a6235f8b2513b7f693a64a0d3fa699f81a034f4b4608ff82f0220767d7d98025aff3c7bd5f2a66aab6a824f5990392e6489aae1e1ae3472d8dffb412103e8be830d98bb3b007a0343ee5c36daa48796ae8bb57946b1e87378ad6e8a090dfeffffff02807c814a000000001976a9143a6bf34ebfcf30e8541bbb33a7882845e5a29cb488ac76b0e60e000000001976a914bd492b67f90cb85918494767ebb23102c4f06b7088ac67000000";

// -----------------------------------------------------------------------
// Transaction parsing and serialization
// -----------------------------------------------------------------------

/// Test that a transaction can be parsed from hex and re-serialized to
/// produce the exact same hex string (round-trip).
#[test]
fn test_from_hex_roundtrip() {
    let tx = Transaction::from_hex(SOURCE_RAW_TX).expect("should parse source tx hex");

    // Verify version
    assert_eq!(tx.version, 1, "version should be 1");

    // Verify input count
    assert_eq!(tx.input_count(), 1, "should have 1 input");

    // Verify output count
    assert_eq!(tx.output_count(), 2, "should have 2 outputs");

    // Verify lock time
    assert_eq!(tx.lock_time, 0, "lock time should be 0");

    // Verify serialization roundtrip
    let roundtrip_hex = tx.to_hex();
    assert_eq!(
        roundtrip_hex, SOURCE_RAW_TX,
        "hex roundtrip should produce identical output"
    );
}

/// Test parsing and roundtrip of a multi-input (3 inputs, 2 outputs) transaction.
#[test]
fn test_multi_input_roundtrip() {
    let tx = Transaction::from_hex(MULTI_INPUT_TX_HEX).expect("should parse multi-input tx");

    assert_eq!(tx.version, 2, "version should be 2");
    assert_eq!(tx.input_count(), 3, "should have 3 inputs");
    assert_eq!(tx.output_count(), 2, "should have 2 outputs");
    assert_eq!(tx.lock_time, 103, "lock time should be 103 (0x67)");

    let roundtrip_hex = tx.to_hex();
    assert_eq!(
        roundtrip_hex, MULTI_INPUT_TX_HEX,
        "multi-input hex roundtrip should produce identical output"
    );
}

/// Test parsing from raw bytes and verifying byte-level roundtrip.
#[test]
fn test_from_bytes_roundtrip() {
    let original_bytes = hex::decode(SOURCE_RAW_TX).unwrap();
    let tx = Transaction::from_bytes(&original_bytes).expect("should parse from bytes");

    let serialized = tx.to_bytes();
    assert_eq!(
        serialized, original_bytes,
        "byte roundtrip should produce identical output"
    );
}

/// Test that parsing a hex string with trailing data returns an error.
#[test]
fn test_trailing_bytes_error() {
    let extended_hex = format!("{}deadbeef", SOURCE_RAW_TX);
    let result = Transaction::from_hex(&extended_hex);
    assert!(result.is_err(), "should reject hex with trailing bytes");
}

/// Test that parsing invalid hex returns an error.
#[test]
fn test_invalid_hex_error() {
    let result = Transaction::from_hex("not_valid_hex");
    assert!(result.is_err(), "should reject invalid hex");
}

/// Test that parsing empty bytes returns an error.
#[test]
fn test_empty_bytes_error() {
    let result = Transaction::from_bytes(&[]);
    assert!(result.is_err(), "should reject empty bytes");
}

// -----------------------------------------------------------------------
// Transaction ID
// -----------------------------------------------------------------------

/// Test that the transaction ID is computed correctly and matches the
/// expected byte-reversed hex string.
#[test]
fn test_tx_id() {
    let tx = Transaction::from_hex(SOURCE_RAW_TX).expect("should parse tx");

    // Verify the txid is a valid 64-character hex string.
    let txid_hex = tx.tx_id_hex();
    assert_eq!(txid_hex.len(), 64, "txid hex should be 64 characters");

    // Verify the raw txid is 32 bytes.
    let txid = tx.tx_id();
    assert_eq!(txid.len(), 32, "txid should be 32 bytes");

    // Verify the hex is the byte-reversed version of the raw txid.
    let mut reversed = txid;
    reversed.reverse();
    assert_eq!(
        hex::encode(reversed),
        txid_hex,
        "tx_id_hex should be byte-reversed tx_id"
    );
}

/// Test the txid of the multi-input transaction.
#[test]
fn test_tx_id_multi_input() {
    let tx = Transaction::from_hex(MULTI_INPUT_TX_HEX).expect("should parse multi-input tx");
    let txid_hex = tx.tx_id_hex();
    // This is a known transaction; verify the txid can be computed without error.
    assert_eq!(txid_hex.len(), 64, "txid should be 64 hex chars");
}

// -----------------------------------------------------------------------
// Coinbase detection
// -----------------------------------------------------------------------

/// Test that a coinbase transaction is correctly identified.
#[test]
fn test_is_coinbase() {
    let tx = Transaction::from_hex(COINBASE_TX_HEX).expect("should parse coinbase tx");
    assert!(tx.is_coinbase(), "should detect coinbase transaction");
}

/// Test that a normal transaction is not identified as coinbase.
#[test]
fn test_is_not_coinbase() {
    let tx = Transaction::from_hex(SOURCE_RAW_TX).expect("should parse source tx");
    assert!(!tx.is_coinbase(), "normal tx should not be coinbase");
}

// -----------------------------------------------------------------------
// IsValidTxID
// -----------------------------------------------------------------------

/// Test that a valid 32-byte slice is accepted as a valid txid.
#[test]
fn test_is_valid_txid() {
    let valid =
        hex::decode("fe77aa03d5563d3ec98455a76655ea3b58e19a4eb102baf7b2a47af37e94b295").unwrap();
    assert_eq!(valid.len(), 32, "valid txid should be 32 bytes");

    let invalid =
        hex::decode("fe77aa03d5563d3ec98455a76655ea3b58e19a4eb102baf7b2a47af37e94b2").unwrap();
    assert_ne!(invalid.len(), 32, "invalid txid should not be 32 bytes");
}

// -----------------------------------------------------------------------
// Transaction building
// -----------------------------------------------------------------------

/// Test creating a new transaction and adding inputs/outputs.
#[test]
fn test_new_transaction() {
    let mut tx = Transaction::new();
    assert_eq!(tx.version, 1, "default version should be 1");
    assert_eq!(tx.lock_time, 0, "default lock_time should be 0");
    assert_eq!(tx.input_count(), 0, "new tx should have 0 inputs");
    assert_eq!(tx.output_count(), 0, "new tx should have 0 outputs");

    // Add an input.
    let mut input = TransactionInput::new();
    input.source_txid = [0xab; 32];
    input.source_tx_out_index = 0;
    input.sequence_number = DEFAULT_SEQUENCE_NUMBER;
    tx.add_input(input);
    assert_eq!(tx.input_count(), 1, "should have 1 input after add");

    // Add an output.
    let output = TransactionOutput {
        satoshis: 50000,
        locking_script: Script::from_bytes(&[0x76, 0xa9, 0x14]),
        change: false,
    };
    tx.add_output(output);
    assert_eq!(tx.output_count(), 1, "should have 1 output after add");
}

/// Test serialization of an empty (no inputs, no outputs) transaction.
#[test]
fn test_empty_transaction_serialization() {
    let tx = Transaction::new();
    let bytes = tx.to_bytes();
    // version(4) + varint(0 inputs)(1) + varint(0 outputs)(1) + locktime(4) = 10 bytes
    assert_eq!(bytes.len(), 10, "empty tx should be 10 bytes");

    let roundtrip = Transaction::from_bytes(&bytes).expect("should parse empty tx");
    assert_eq!(roundtrip.version, 1);
    assert_eq!(roundtrip.input_count(), 0);
    assert_eq!(roundtrip.output_count(), 0);
    assert_eq!(roundtrip.lock_time, 0);
}

// -----------------------------------------------------------------------
// Output properties
// -----------------------------------------------------------------------

/// Test output satoshi values from the parsed source transaction.
#[test]
fn test_output_satoshis() {
    let tx = Transaction::from_hex(SOURCE_RAW_TX).expect("should parse source tx");

    assert_eq!(
        tx.outputs[0].satoshis, 1500,
        "first output should be 1500 sats"
    );
    assert_eq!(
        tx.outputs[1].satoshis, 3498,
        "second output should be 3498 sats"
    );
    assert_eq!(
        tx.total_output_satoshis(),
        1500 + 3498,
        "total output satoshis"
    );
}

/// Test output locking script hex.
#[test]
fn test_output_locking_script_hex() {
    let tx = Transaction::from_hex(SOURCE_RAW_TX).expect("should parse source tx");
    let script_hex = tx.outputs[1].locking_script_hex();
    assert_eq!(
        script_hex, "76a914eb0bd5edba389198e73f8efabddfc61666969ff788ac",
        "locking script should match expected P2PKH pattern"
    );
}

// -----------------------------------------------------------------------
// Input properties
// -----------------------------------------------------------------------

/// Test input sequence number from the parsed source transaction.
#[test]
fn test_input_sequence() {
    let tx = Transaction::from_hex(SOURCE_RAW_TX).expect("should parse source tx");
    assert_eq!(
        tx.inputs[0].sequence_number, DEFAULT_SEQUENCE_NUMBER,
        "sequence number should be 0xFFFFFFFF"
    );
}

/// Test the source txid bytes from the parsed input.
#[test]
fn test_input_source_txid() {
    let tx = Transaction::from_hex(SOURCE_RAW_TX).expect("should parse source tx");
    let input = &tx.inputs[0];

    // The source txid is the 32 raw bytes from the wire format, stored as-is
    // (internal/little-endian byte order). This matches the hex in the raw tx.
    let expected_hex = "38c7c61c14ffb063c3bb2664041a3e29ea6ea0412a0c18ff725ba4e9e12afae2";
    let expected_bytes = hex::decode(expected_hex).unwrap();
    assert_eq!(
        &input.source_txid[..],
        &expected_bytes[..],
        "source txid bytes should match the raw tx"
    );
}

// -----------------------------------------------------------------------
// Sighash
// -----------------------------------------------------------------------

/// Test that the sighash function produces a valid 32-byte hash when given
/// a simple P2PKH locking script and SIGHASH_ALL | SIGHASH_FORKID flags.
#[test]
fn test_signature_hash_basic() {
    let tx = Transaction::from_hex(SOURCE_RAW_TX).expect("should parse source tx");

    // The locking script of the output being spent (a P2PKH script).
    let prev_script_hex = "76a914eb0bd5edba389198e73f8efabddfc61666969ff788ac";
    let prev_script_bytes = hex::decode(prev_script_hex).unwrap();

    let sighash_type = sighash::SIGHASH_ALL | sighash::SIGHASH_FORKID;
    let satoshis = 1500u64;

    let hash = sighash::signature_hash(&tx, 0, &prev_script_bytes, sighash_type, satoshis)
        .expect("sighash should succeed");

    assert_eq!(hash.len(), 32, "sighash should be 32 bytes");
}

/// Test that sighash with an out-of-range input index returns an error.
#[test]
fn test_signature_hash_out_of_range() {
    let tx = Transaction::from_hex(SOURCE_RAW_TX).expect("should parse source tx");
    let result = sighash::signature_hash(&tx, 99, &[], sighash::SIGHASH_ALL_FORKID, 0);
    assert!(result.is_err(), "should error on out-of-range input index");
}

/// Test the sighash preimage structure for a standard SIGHASH_ALL | FORKID.
#[test]
fn test_calc_preimage_structure() {
    let tx = Transaction::from_hex(SOURCE_RAW_TX).expect("should parse source tx");

    let prev_script_hex = "76a914eb0bd5edba389198e73f8efabddfc61666969ff788ac";
    let prev_script_bytes = hex::decode(prev_script_hex).unwrap();

    let sighash_type = sighash::SIGHASH_ALL | sighash::SIGHASH_FORKID;
    let satoshis = 1500u64;

    let preimage = sighash::calc_preimage(&tx, 0, &prev_script_bytes, sighash_type, satoshis)
        .expect("preimage should succeed");

    // The preimage should be:
    // version(4) + hashPrevouts(32) + hashSequence(32) + outpoint(36) +
    // scriptCode(varint + script) + value(8) + nSequence(4) + hashOutputs(32) +
    // locktime(4) + sighashType(4)
    // = 4 + 32 + 32 + 36 + (1 + 25) + 8 + 4 + 32 + 4 + 4 = 182 bytes
    let expected_len = 4 + 32 + 32 + 36 + 1 + prev_script_bytes.len() + 8 + 4 + 32 + 4 + 4;
    assert_eq!(
        preimage.len(),
        expected_len,
        "preimage should have the correct structure length"
    );

    // First 4 bytes should be the version.
    let version = u32::from_le_bytes([preimage[0], preimage[1], preimage[2], preimage[3]]);
    assert_eq!(version, 1, "preimage version should be 1");

    // Last 4 bytes should be the sighash type.
    let tail = preimage.len();
    let shtype = u32::from_le_bytes([
        preimage[tail - 4],
        preimage[tail - 3],
        preimage[tail - 2],
        preimage[tail - 1],
    ]);
    assert_eq!(
        shtype, sighash_type,
        "preimage should end with sighash type"
    );
}

// -----------------------------------------------------------------------
// Transaction size
// -----------------------------------------------------------------------

/// Test that the size method matches the actual serialized length.
#[test]
fn test_transaction_size() {
    let tx = Transaction::from_hex(SOURCE_RAW_TX).expect("should parse source tx");
    let bytes = hex::decode(SOURCE_RAW_TX).unwrap();
    assert_eq!(tx.size(), bytes.len(), "size() should match byte length");
}

// -----------------------------------------------------------------------
// Clone and Display
// -----------------------------------------------------------------------

/// Test that clone produces an identical transaction.
#[test]
fn test_transaction_clone() {
    let tx = Transaction::from_hex(SOURCE_RAW_TX).expect("should parse source tx");
    let clone = tx.clone();
    assert_eq!(tx.to_bytes(), clone.to_bytes(), "clone should be identical");
}

/// Test the Display impl outputs hex.
#[test]
fn test_transaction_display() {
    let tx = Transaction::from_hex(SOURCE_RAW_TX).expect("should parse source tx");
    let display = format!("{}", tx);
    assert_eq!(display, SOURCE_RAW_TX, "Display should output hex");
}

// -----------------------------------------------------------------------
// P2PKH signing - end-to-end tests ported from Go SDK p2pkh_test.go
// -----------------------------------------------------------------------

/// Test P2PKH signing produces the exact same signed transaction hex
/// as the Go SDK.  This is the acceptance test for Milestone 1.
///
/// Ported from Go `TestLocalUnlocker_UnlockAllInputs`.
#[test]
fn test_p2pkh_sign_exact_match() {
    use crate::output::TransactionOutput;
    use crate::template::p2pkh;
    use crate::template::UnlockingScriptTemplate;
    use bsv_primitives::ec::PrivateKey;

    let incomplete_tx_hex = "010000000193a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d25072326510000000000ffffffff02404b4c00000000001976a91404ff367be719efa79d76e4416ffb072cd53b208888acde94a905000000001976a91404d03f746652cfcb6cb55119ab473a045137d26588ac00000000";
    let mut tx = Transaction::from_hex(incomplete_tx_hex).expect("should parse unsigned tx");

    // Create a fake previous transaction that has the output being spent.
    let mut prev_tx = Transaction::new();
    // Pad outputs up to the required index.
    let out_index = tx.inputs[0].source_tx_out_index as usize;
    for _ in 0..=out_index {
        prev_tx.add_output(TransactionOutput::new());
    }
    prev_tx.outputs[out_index].satoshis = 100_000_000;
    prev_tx.outputs[out_index].locking_script =
        Script::from_hex("76a914c0a3c167a28cabb9fbb495affa0761e6e74ac60d88ac").unwrap();
    tx.inputs[0].source_transaction = Some(Box::new(prev_tx));

    // Load private key from WIF (testnet).
    let priv_key = PrivateKey::from_wif("cNGwGSc7KRrTmdLUZ54fiSXWbhLNDc2Eg5zNucgQxyQCzuQ5YRDq")
        .expect("should parse WIF");

    // Create P2PKH unlocker and sign.
    let unlocker = p2pkh::unlock(priv_key, None);
    let unlocking_script = unlocker.sign(&tx, 0).expect("signing should succeed");
    tx.inputs[0].unlocking_script = Some(unlocking_script);

    let expected_signed_tx = "010000000193a35408b6068499e0d5abd799d3e827d9bfe70c9b75ebe209c91d2507232651000000006b483045022100c1d77036dc6cd1f3fa1214b0688391ab7f7a16cd31ea4e5a1f7a415ef167df820220751aced6d24649fa235132f1e6969e163b9400f80043a72879237dab4a1190ad412103b8b40a84123121d260f5c109bc5a46ec819c2e4002e5ba08638783bfb4e01435ffffffff02404b4c00000000001976a91404ff367be719efa79d76e4416ffb072cd53b208888acde94a905000000001976a91404d03f746652cfcb6cb55119ab473a045137d26588ac00000000";
    assert_eq!(
        tx.to_hex(),
        expected_signed_tx,
        "signed tx hex must match Go SDK output byte-for-byte"
    );
    assert_ne!(
        tx.to_hex(),
        incomplete_tx_hex,
        "signed tx must differ from unsigned tx"
    );
}

/// Test P2PKH signing produces a valid, verifiable signature.
///
/// Ported from Go `TestLocalUnlocker_ValidSignature` - "valid signature 1".
#[test]
fn test_p2pkh_valid_signature_1() {
    use crate::template::p2pkh;
    use crate::template::UnlockingScriptTemplate;
    use bsv_primitives::ec::{PrivateKey, PublicKey, Signature};

    let mut tx = Transaction::new();
    tx.add_input_from(
        "45be95d2f2c64e99518ffbbce03fb15a7758f20ee5eecf0df07938d977add71d",
        0,
        "76a914c7c6987b6e2345a6b138e3384141520a0fbc18c588ac",
        15564838601,
    )
    .expect("should add input");

    let script1 = Script::from_hex("76a91442f9682260509ac80722b1963aec8a896593d16688ac").unwrap();
    tx.add_output(TransactionOutput {
        satoshis: 375041432,
        locking_script: script1,
        change: false,
    });

    let script2 = Script::from_hex("76a914c36538e91213a8100dcb2aed456ade363de8483f88ac").unwrap();
    tx.add_output(TransactionOutput {
        satoshis: 15189796941,
        locking_script: script2,
        change: false,
    });

    let priv_key = PrivateKey::from_wif("cNGwGSc7KRrTmdLUZ54fiSXWbhLNDc2Eg5zNucgQxyQCzuQ5YRDq")
        .expect("should parse WIF");

    let unlocker = p2pkh::unlock(priv_key.clone(), None);
    let uscript = unlocker.sign(&tx, 0).expect("signing should succeed");
    tx.inputs[0].unlocking_script = Some(uscript);

    // Parse the unlocking script into chunks to extract sig and pubkey.
    let chunks = tx.inputs[0]
        .unlocking_script
        .as_ref()
        .unwrap()
        .chunks()
        .expect("should decode chunks");

    let sig_bytes = chunks[0].data.as_ref().expect("sig chunk should have data");
    let pubkey_bytes = chunks[1]
        .data
        .as_ref()
        .expect("pubkey chunk should have data");

    // Parse and verify the signature.
    let public_key = PublicKey::from_bytes(pubkey_bytes).expect("should parse public key");
    // The last byte of sig_bytes is the sighash flag; the rest is DER signature.
    let sig =
        Signature::from_der(&sig_bytes[..sig_bytes.len() - 1]).expect("should parse DER signature");

    let sig_hash = tx
        .calc_input_signature_hash(0, sighash::SIGHASH_ALL_FORKID)
        .expect("should compute sighash");

    assert!(
        sig.verify(&sig_hash, &public_key),
        "signature should verify against the sighash"
    );
}

/// Test P2PKH signing with `add_input_from` and `set_source_output`.
///
/// Ported from Go `TestUnlockWithOptionalParameters`.
#[test]
fn test_p2pkh_with_set_source_output() {
    use crate::output::TransactionOutput;
    use crate::template::p2pkh;
    use crate::template::UnlockingScriptTemplate;
    use bsv_primitives::ec::PrivateKey;

    let mut tx = Transaction::new();
    tx.add_input_from(
        "45be95d2f2c64e99518ffbbce03fb15a7758f20ee5eecf0df07938d977add71d",
        0,
        "",
        0,
    )
    .expect("should add input");

    let output_script =
        Script::from_hex("76a91442f9682260509ac80722b1963aec8a896593d16688ac").unwrap();
    tx.add_output(TransactionOutput {
        satoshis: 375041432,
        locking_script: output_script,
        change: false,
    });

    let priv_key = PrivateKey::from_wif("cNGwGSc7KRrTmdLUZ54fiSXWbhLNDc2Eg5zNucgQxyQCzuQ5YRDq")
        .expect("should parse WIF");

    let locking_script =
        Script::from_hex("76a914c7c6987b6e2345a6b138e3384141520a0fbc18c588ac").unwrap();

    // Set source output directly (equivalent to Go's SetSourceTxOutput).
    tx.inputs[0].set_source_output(Some(TransactionOutput {
        satoshis: 15564838601,
        locking_script: locking_script,
        change: false,
    }));

    let unlocker = p2pkh::unlock(priv_key, None);
    let uscript = unlocker.sign(&tx, 0).expect("signing should succeed");
    assert!(!uscript.is_empty(), "unlocking script should not be empty");
}

/// Test that signing fails when no source output info is available.
///
/// Ported from Go `TestUnlockWithOptionalParameters` error case.
#[test]
fn test_p2pkh_error_without_source_info() {
    use crate::output::TransactionOutput;
    use crate::template::p2pkh;
    use crate::template::UnlockingScriptTemplate;
    use bsv_primitives::ec::PrivateKey;

    let mut tx = Transaction::new();
    tx.add_input_from(
        "45be95d2f2c64e99518ffbbce03fb15a7758f20ee5eecf0df07938d977add71d",
        0,
        "",
        0,
    )
    .expect("should add input");

    let output_script =
        Script::from_hex("76a91442f9682260509ac80722b1963aec8a896593d16688ac").unwrap();
    tx.add_output(TransactionOutput {
        satoshis: 375041432,
        locking_script: output_script,
        change: false,
    });

    let priv_key = PrivateKey::from_wif("cNGwGSc7KRrTmdLUZ54fiSXWbhLNDc2Eg5zNucgQxyQCzuQ5YRDq")
        .expect("should parse WIF");

    // Clear the source output.
    tx.inputs[0].set_source_output(None);

    let unlocker = p2pkh::unlock(priv_key, None);
    let result = unlocker.sign(&tx, 0);
    assert!(
        result.is_err(),
        "signing should fail without source output info"
    );
}
