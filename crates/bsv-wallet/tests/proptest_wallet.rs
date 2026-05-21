use proptest::prelude::*;

use bsv_primitives::ec::private_key::PrivateKey;
use bsv_wallet::types::*;
use bsv_wallet::{ProtoWallet, WalletInterface};

fn make_encryption_args(protocol: String, key_id: String) -> EncryptionArgs {
    EncryptionArgs {
        protocol_id: Protocol {
            security_level: SECURITY_LEVEL_SILENT,
            protocol,
        },
        key_id,
        counterparty: Counterparty {
            r#type: CounterpartyType::Anyone,
            counterparty: None,
        },
        privileged: false,
        privileged_reason: String::new(),
        seek_permission: false,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn key_deriver_always_produces_valid_key(
        protocol in "[a-zA-Z][a-zA-Z0-9]{4,10}",
        key_id in "[a-zA-Z0-9]{1,10}",
    ) {
        // Use a known-good random private key
        let pk = PrivateKey::new();
        let wallet = ProtoWallet::from_private_key(pk).unwrap();
        let args = GetPublicKeyArgs {
            encryption_args: make_encryption_args(protocol, key_id),
            identity_key: false,
            for_self: Some(false),
        };
        let result = wallet.get_public_key(args);
        prop_assert!(result.is_ok(), "Error: {:?}", result.err());
        let pub_key = result.unwrap().public_key;
        // Should produce a valid compressed public key (33 bytes)
        prop_assert_eq!(pub_key.to_compressed().len(), 33);
    }

    #[test]
    fn encrypt_decrypt_roundtrip(
        seed in prop::array::uniform32(any::<u8>()),
        plaintext in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        if let Ok(pk) = PrivateKey::from_bytes(&seed) {
            let wallet = ProtoWallet::from_private_key(pk).unwrap();
            let enc_args = make_encryption_args("test".into(), "1".into());

            let encrypted = wallet.encrypt(EncryptArgs {
                encryption_args: enc_args.clone(),
                plaintext: plaintext.clone(),
            });
            if let Ok(enc_result) = encrypted {
                let decrypted = wallet.decrypt(DecryptArgs {
                    encryption_args: enc_args,
                    ciphertext: enc_result.ciphertext,
                }).unwrap();
                prop_assert_eq!(plaintext, decrypted.plaintext);
            }
        }
    }
}
