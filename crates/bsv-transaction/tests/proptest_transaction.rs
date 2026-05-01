use proptest::prelude::*;

use bsv_script::Script;
use bsv_transaction::{Transaction, TransactionInput, TransactionOutput};

/// Strategy to generate a valid random transaction.
fn arb_transaction() -> impl Strategy<Value = Transaction> {
    let arb_input = (
        prop::array::uniform32(any::<u8>()),       // prev tx hash
        any::<u32>(),                              // prev tx index
        prop::collection::vec(any::<u8>(), 0..64), // script bytes
        any::<u32>(),                              // sequence
    )
        .prop_map(|(hash, idx, script_bytes, seq)| {
            let mut input = TransactionInput::new();
            input.source_txid = hash;
            input.source_tx_out_index = idx;
            input.unlocking_script = Some(Script::from_bytes(&script_bytes));
            input.sequence_number = seq;
            input
        });

    let arb_output = (
        0..=2_100_000_000_000_000u64, // max 21M BSV in satoshis
        prop::collection::vec(any::<u8>(), 0..64),
    )
        .prop_map(|(satoshis, script_bytes)| {
            let mut output = TransactionOutput::new();
            output.satoshis = satoshis;
            output.locking_script = Script::from_bytes(&script_bytes);
            output
        });

    (
        any::<u32>(), // version
        prop::collection::vec(arb_input, 1..4),
        prop::collection::vec(arb_output, 1..4),
        any::<u32>(), // locktime
    )
        .prop_map(|(version, inputs, outputs, locktime)| {
            let mut tx = Transaction::new();
            tx.version = version;
            tx.lock_time = locktime;
            for i in inputs {
                tx.add_input(i);
            }
            for o in outputs {
                tx.add_output(o);
            }
            tx
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn transaction_serialize_deserialize_roundtrip(tx in arb_transaction()) {
        let bytes = tx.to_bytes();
        let tx2 = Transaction::from_bytes(&bytes).unwrap();
        let bytes2 = tx2.to_bytes();
        prop_assert_eq!(bytes, bytes2);
    }

    #[test]
    fn transaction_hex_roundtrip(tx in arb_transaction()) {
        let hex_str = tx.to_hex();
        let tx2 = Transaction::from_hex(&hex_str).unwrap();
        prop_assert_eq!(tx.to_hex(), tx2.to_hex());
    }
}
