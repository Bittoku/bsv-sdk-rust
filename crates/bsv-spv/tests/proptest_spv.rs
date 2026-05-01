use proptest::prelude::*;

use bsv_primitives::chainhash::Hash;
use bsv_spv::{MerklePath, PathElement};

/// Strategy to generate a valid MerklePath that can round-trip through serialization.
fn arb_merkle_path() -> impl Strategy<Value = MerklePath> {
    let arb_hash = prop::array::uniform32(any::<u8>()).prop_map(|b| Hash::new(b));

    // Generate 1..=8 levels, each with 1..=3 leaves
    let arb_level = prop::collection::vec(
        (0u64..256, arb_hash, any::<bool>()).prop_map(|(offset, hash, is_txid)| PathElement {
            offset,
            hash: Some(hash),
            txid: if is_txid { Some(true) } else { None },
            duplicate: None,
        }),
        1..=3,
    )
    .prop_map(|mut level| {
        // Ensure unique offsets by deduplicating
        level.sort_by_key(|e| e.offset);
        level.dedup_by_key(|e| e.offset);
        level
    });

    (any::<u32>(), prop::collection::vec(arb_level, 1..=8))
        .prop_map(|(block_height, path)| MerklePath::new(block_height, path))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn merkle_path_serialize_deserialize_roundtrip(mp in arb_merkle_path()) {
        let bytes = mp.to_bytes();
        let mp2 = MerklePath::from_bytes(&bytes).unwrap();
        let bytes2 = mp2.to_bytes();
        prop_assert_eq!(bytes, bytes2);
    }

    #[test]
    fn merkle_path_hex_roundtrip(mp in arb_merkle_path()) {
        let hex_str = mp.to_hex();
        let mp2 = MerklePath::from_hex(&hex_str).unwrap();
        prop_assert_eq!(mp.to_hex(), mp2.to_hex());
    }
}
