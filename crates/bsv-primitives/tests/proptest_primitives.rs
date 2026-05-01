use proptest::prelude::*;

use bsv_primitives::chainhash::Hash;
use bsv_primitives::ec::private_key::PrivateKey;
use bsv_primitives::ec::public_key::PublicKey;
use bsv_primitives::hash::sha256;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn private_key_to_public_key_to_address_roundtrip(seed in prop::array::uniform32(any::<u8>())) {
        // Not all 32-byte arrays are valid private keys (must be < curve order, nonzero).
        if let Ok(pk) = PrivateKey::from_bytes(&seed) {
            let pub_key = pk.pub_key();
            let address = pub_key.to_address();
            // Address should be a non-empty base58 string
            prop_assert!(!address.is_empty());
            // WIF round-trip
            let wif = pk.to_wif();
            let pk2 = PrivateKey::from_wif(&wif).unwrap();
            prop_assert_eq!(pk.to_hex(), pk2.to_hex());
        }
    }

    #[test]
    fn ecdsa_sign_verify_roundtrip(
        seed in prop::array::uniform32(any::<u8>()),
        msg in prop::collection::vec(any::<u8>(), 0..256)
    ) {
        if let Ok(pk) = PrivateKey::from_bytes(&seed) {
            let hash = sha256(&msg);
            let sig = pk.sign(&hash).unwrap();
            let pub_key = pk.pub_key();
            prop_assert!(pub_key.verify(&hash, &sig));
        }
    }

    #[test]
    fn hash_hex_roundtrip(bytes in prop::array::uniform32(any::<u8>())) {
        let hash = Hash::new(bytes);
        let hex_str = hash.to_string();
        let hash2 = Hash::from_hex(&hex_str).unwrap();
        prop_assert_eq!(hash.as_bytes(), hash2.as_bytes());
    }
}
