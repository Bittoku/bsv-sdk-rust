use proptest::prelude::*;

use bsv_script::interpreter::ScriptNumber;
use bsv_script::Script;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn script_number_encode_decode_roundtrip(val in -0x7FFFFFFFi64..=0x7FFFFFFFi64) {
        let sn = ScriptNumber::new(val, false);
        let bytes = sn.to_bytes();
        let sn2 = ScriptNumber::from_bytes(&bytes, 4, false, false).unwrap();
        prop_assert_eq!(sn.val, sn2.val);
    }

    #[test]
    fn script_bytes_roundtrip(data in prop::collection::vec(any::<u8>(), 0..512)) {
        let script = Script::from_bytes(&data);
        let out = script.to_bytes();
        prop_assert_eq!(&data[..], out);
    }

    #[test]
    fn script_hex_roundtrip(data in prop::collection::vec(any::<u8>(), 0..256)) {
        let script = Script::from_bytes(&data);
        let hex_str = script.to_hex();
        let script2 = Script::from_hex(&hex_str).unwrap();
        prop_assert_eq!(script.to_bytes(), script2.to_bytes());
    }
}
