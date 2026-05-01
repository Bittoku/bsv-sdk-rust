//! ProtoWallet — a foundational wallet capable of cryptographic operations
//! (key derivation, encrypt/decrypt, sign/verify, HMAC) but not transaction
//! management or blockchain interaction.

use bsv_primitives::ec::private_key::PrivateKey;
use bsv_primitives::hash::sha256;

use crate::error::WalletError;
use crate::key_deriver::KeyDeriver;
use crate::types::*;
use crate::wallet_trait::WalletInterface;

/// A precursor to a full wallet. Handles cryptographic operations only.
#[derive(Clone, Debug)]
pub struct ProtoWallet {
    key_deriver: KeyDeriver,
}

/// How to construct a ProtoWallet.
pub enum ProtoWalletArgs {
    /// Construct from an existing private key.
    PrivateKey(PrivateKey),
    /// Construct from a pre-built key deriver.
    KeyDeriver(KeyDeriver),
    /// Construct the special "anyone" wallet (scalar = 1).
    Anyone,
}

impl ProtoWallet {
    /// Create a new ProtoWallet from the given construction arguments.
    pub fn new(args: ProtoWalletArgs) -> Result<Self, WalletError> {
        let key_deriver = match args {
            ProtoWalletArgs::PrivateKey(pk) => KeyDeriver::new(Some(pk)),
            ProtoWalletArgs::KeyDeriver(kd) => kd,
            ProtoWalletArgs::Anyone => KeyDeriver::new(None),
        };
        Ok(ProtoWallet { key_deriver })
    }

    /// Convenience: create from a private key.
    pub fn from_private_key(pk: PrivateKey) -> Result<Self, WalletError> {
        Self::new(ProtoWalletArgs::PrivateKey(pk))
    }

    /// The identity public key.
    pub fn identity_key(&self) -> bsv_primitives::ec::public_key::PublicKey {
        self.key_deriver.identity_key()
    }

    /// Access to the underlying key deriver.
    pub fn key_deriver(&self) -> &KeyDeriver {
        &self.key_deriver
    }

    /// Default counterparty to Self_ if uninitialized.
    fn default_counterparty_self(c: &Counterparty) -> Counterparty {
        if c.r#type == CounterpartyType::Uninitialized {
            Counterparty {
                r#type: CounterpartyType::Self_,
                counterparty: None,
            }
        } else {
            c.clone()
        }
    }

    /// Default counterparty to Anyone if uninitialized.
    fn default_counterparty_anyone(c: &Counterparty) -> Counterparty {
        if c.r#type == CounterpartyType::Uninitialized {
            Counterparty {
                r#type: CounterpartyType::Anyone,
                counterparty: None,
            }
        } else {
            c.clone()
        }
    }
}

impl WalletInterface for ProtoWallet {
    fn get_public_key(&self, args: GetPublicKeyArgs) -> Result<GetPublicKeyResult, WalletError> {
        if args.identity_key {
            return Ok(GetPublicKeyResult {
                public_key: self.key_deriver.identity_key(),
            });
        }

        if args.encryption_args.protocol_id.protocol.is_empty()
            || args.encryption_args.key_id.is_empty()
        {
            return Err(WalletError::InvalidArgument(
                "protocolID and keyID are required if identityKey is false".into(),
            ));
        }

        let counterparty = Self::default_counterparty_self(&args.encryption_args.counterparty);
        let for_self = args.for_self.unwrap_or(false);

        let pub_key = self.key_deriver.derive_public_key(
            &args.encryption_args.protocol_id,
            &args.encryption_args.key_id,
            &counterparty,
            for_self,
        )?;

        Ok(GetPublicKeyResult {
            public_key: pub_key,
        })
    }

    fn encrypt(&self, args: EncryptArgs) -> Result<EncryptResult, WalletError> {
        let counterparty = Self::default_counterparty_self(&args.encryption_args.counterparty);

        let key = self.key_deriver.derive_symmetric_key(
            &args.encryption_args.protocol_id,
            &args.encryption_args.key_id,
            &counterparty,
        )?;

        let ciphertext = key
            .encrypt(&args.plaintext)
            .map_err(|e| WalletError::General(format!("encryption failed: {}", e)))?;

        Ok(EncryptResult { ciphertext })
    }

    fn decrypt(&self, args: DecryptArgs) -> Result<DecryptResult, WalletError> {
        let counterparty = Self::default_counterparty_self(&args.encryption_args.counterparty);

        let key = self.key_deriver.derive_symmetric_key(
            &args.encryption_args.protocol_id,
            &args.encryption_args.key_id,
            &counterparty,
        )?;

        let plaintext = key
            .decrypt(&args.ciphertext)
            .map_err(|e| WalletError::General(format!("decryption failed: {}", e)))?;

        Ok(DecryptResult { plaintext })
    }

    fn create_signature(
        &self,
        args: CreateSignatureArgs,
    ) -> Result<CreateSignatureResult, WalletError> {
        let data_hash = if !args.hash_to_directly_sign.is_empty() {
            args.hash_to_directly_sign.clone()
        } else {
            sha256(&args.data).to_vec()
        };

        let counterparty = Self::default_counterparty_anyone(&args.encryption_args.counterparty);

        let priv_key = self.key_deriver.derive_private_key(
            &args.encryption_args.protocol_id,
            &args.encryption_args.key_id,
            &counterparty,
        )?;

        let signature = priv_key
            .sign(&data_hash)
            .map_err(|e| WalletError::General(format!("signing failed: {}", e)))?;

        Ok(CreateSignatureResult { signature })
    }

    fn verify_signature(
        &self,
        args: VerifySignatureArgs,
    ) -> Result<VerifySignatureResult, WalletError> {
        if args.data.is_empty() && args.hash_to_directly_verify.is_empty() {
            return Err(WalletError::InvalidArgument(
                "data or hashToDirectlyVerify must be provided".into(),
            ));
        }

        let data_hash = if !args.hash_to_directly_verify.is_empty() {
            args.hash_to_directly_verify.clone()
        } else {
            sha256(&args.data).to_vec()
        };

        let counterparty = Self::default_counterparty_self(&args.encryption_args.counterparty);
        let for_self = args.for_self.unwrap_or(false);

        let pub_key = self.key_deriver.derive_public_key(
            &args.encryption_args.protocol_id,
            &args.encryption_args.key_id,
            &counterparty,
            for_self,
        )?;

        let sig = args.signature.ok_or(WalletError::SignatureNil)?;
        let valid = sig.verify(&data_hash, &pub_key);

        Ok(VerifySignatureResult { valid })
    }

    fn create_hmac(&self, args: CreateHmacArgs) -> Result<CreateHmacResult, WalletError> {
        let counterparty = Self::default_counterparty_self(&args.encryption_args.counterparty);

        let key = self.key_deriver.derive_symmetric_key(
            &args.encryption_args.protocol_id,
            &args.encryption_args.key_id,
            &counterparty,
        )?;

        let mac = bsv_primitives::hash::sha256_hmac(key.to_bytes(), &args.data);
        let mut hmac = [0u8; 32];
        hmac.copy_from_slice(&mac);

        Ok(CreateHmacResult { hmac })
    }

    fn verify_hmac(&self, args: VerifyHmacArgs) -> Result<VerifyHmacResult, WalletError> {
        let counterparty = Self::default_counterparty_self(&args.encryption_args.counterparty);

        let key = self.key_deriver.derive_symmetric_key(
            &args.encryption_args.protocol_id,
            &args.encryption_args.key_id,
            &counterparty,
        )?;

        let mac = bsv_primitives::hash::sha256_hmac(key.to_bytes(), &args.data);
        // Constant-time comparison to prevent timing side-channel attacks
        use subtle::ConstantTimeEq;
        let valid: bool = mac[..].ct_eq(&args.hmac[..]).into();

        Ok(VerifyHmacResult { valid })
    }
}

/// Full wallet wrapping ProtoWallet. Transaction/certificate methods
/// will be implemented in later milestones.
#[derive(Clone, Debug)]
pub struct Wallet {
    proto: ProtoWallet,
}

impl Wallet {
    /// Create a new Wallet from an optional private key. Uses "anyone" key if None.
    pub fn new(private_key: Option<PrivateKey>) -> Result<Self, WalletError> {
        let proto = match private_key {
            Some(pk) => ProtoWallet::from_private_key(pk)?,
            None => ProtoWallet::new(ProtoWalletArgs::Anyone)?,
        };
        Ok(Wallet { proto })
    }
}

impl std::ops::Deref for Wallet {
    type Target = ProtoWallet;
    fn deref(&self) -> &Self::Target {
        &self.proto
    }
}

impl WalletInterface for Wallet {
    fn get_public_key(&self, args: GetPublicKeyArgs) -> Result<GetPublicKeyResult, WalletError> {
        self.proto.get_public_key(args)
    }
    fn encrypt(&self, args: EncryptArgs) -> Result<EncryptResult, WalletError> {
        self.proto.encrypt(args)
    }
    fn decrypt(&self, args: DecryptArgs) -> Result<DecryptResult, WalletError> {
        self.proto.decrypt(args)
    }
    fn create_hmac(&self, args: CreateHmacArgs) -> Result<CreateHmacResult, WalletError> {
        self.proto.create_hmac(args)
    }
    fn verify_hmac(&self, args: VerifyHmacArgs) -> Result<VerifyHmacResult, WalletError> {
        self.proto.verify_hmac(args)
    }
    fn create_signature(
        &self,
        args: CreateSignatureArgs,
    ) -> Result<CreateSignatureResult, WalletError> {
        self.proto.create_signature(args)
    }
    fn verify_signature(
        &self,
        args: VerifySignatureArgs,
    ) -> Result<VerifySignatureResult, WalletError> {
        self.proto.verify_signature(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_primitives::ec::private_key::PrivateKey;

    fn make_key(val: u8) -> PrivateKey {
        let mut bytes = [0u8; 32];
        bytes[31] = val;
        PrivateKey::from_bytes(&bytes).unwrap()
    }

    fn test_protocol() -> Protocol {
        Protocol {
            security_level: 0,
            protocol: "testprotocol".into(),
        }
    }

    fn test_encryption_args(counterparty: Counterparty) -> EncryptionArgs {
        EncryptionArgs {
            protocol_id: test_protocol(),
            key_id: "test-key-1".into(),
            counterparty,
            privileged: false,
            privileged_reason: String::new(),
            seek_permission: false,
        }
    }

    #[test]
    fn test_proto_wallet_identity_key() {
        let pk = make_key(42);
        let expected_pub = pk.pub_key();
        let pw = ProtoWallet::from_private_key(pk).unwrap();
        assert_eq!(
            pw.identity_key().to_compressed(),
            expected_pub.to_compressed()
        );
    }

    #[test]
    fn test_get_public_key_identity() {
        let pk = make_key(42);
        let expected_pub = pk.pub_key();
        let pw = ProtoWallet::from_private_key(pk).unwrap();

        let result = pw
            .get_public_key(GetPublicKeyArgs {
                encryption_args: test_encryption_args(Counterparty::default()),
                identity_key: true,
                for_self: None,
            })
            .unwrap();
        assert_eq!(
            result.public_key.to_compressed(),
            expected_pub.to_compressed()
        );
    }

    #[test]
    fn test_get_public_key_derived() {
        let pk = make_key(42);
        let pw = ProtoWallet::from_private_key(pk).unwrap();

        let result = pw.get_public_key(GetPublicKeyArgs {
            encryption_args: test_encryption_args(Counterparty {
                r#type: CounterpartyType::Self_,
                counterparty: None,
            }),
            identity_key: false,
            for_self: None,
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_encrypt_decrypt_self() {
        let pk = make_key(42);
        let pw = ProtoWallet::from_private_key(pk).unwrap();
        let plaintext = b"Hello, BSV!".to_vec();

        let enc_args = test_encryption_args(Counterparty {
            r#type: CounterpartyType::Self_,
            counterparty: None,
        });

        let encrypted = pw
            .encrypt(EncryptArgs {
                encryption_args: enc_args.clone(),
                plaintext: plaintext.clone(),
            })
            .unwrap();

        assert_ne!(encrypted.ciphertext, plaintext);

        let decrypted = pw
            .decrypt(DecryptArgs {
                encryption_args: enc_args,
                ciphertext: encrypted.ciphertext,
            })
            .unwrap();

        assert_eq!(decrypted.plaintext, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_counterparty() {
        let alice_key = make_key(42);
        let bob_key = make_key(69);
        let alice = ProtoWallet::from_private_key(alice_key).unwrap();
        let bob = ProtoWallet::from_private_key(bob_key).unwrap();
        let plaintext = b"Secret message".to_vec();

        // Alice encrypts for Bob
        let enc_args_alice = test_encryption_args(Counterparty {
            r#type: CounterpartyType::Other,
            counterparty: Some(bob.identity_key()),
        });

        let encrypted = alice
            .encrypt(EncryptArgs {
                encryption_args: enc_args_alice,
                plaintext: plaintext.clone(),
            })
            .unwrap();

        // Bob decrypts from Alice
        let dec_args_bob = test_encryption_args(Counterparty {
            r#type: CounterpartyType::Other,
            counterparty: Some(alice.identity_key()),
        });

        let decrypted = bob
            .decrypt(DecryptArgs {
                encryption_args: dec_args_bob,
                ciphertext: encrypted.ciphertext,
            })
            .unwrap();

        assert_eq!(decrypted.plaintext, plaintext);
    }

    #[test]
    fn test_create_verify_signature() {
        let pk = make_key(42);
        let pw = ProtoWallet::from_private_key(pk).unwrap();
        let data = b"Sign this data".to_vec();

        let enc_args = test_encryption_args(Counterparty {
            r#type: CounterpartyType::Anyone,
            counterparty: None,
        });

        let sig_result = pw
            .create_signature(CreateSignatureArgs {
                encryption_args: enc_args.clone(),
                data: data.clone(),
                hash_to_directly_sign: vec![],
            })
            .unwrap();

        let verify_result = pw
            .verify_signature(VerifySignatureArgs {
                encryption_args: enc_args,
                data: data.clone(),
                hash_to_directly_verify: vec![],
                signature: Some(sig_result.signature),
                for_self: Some(true),
            })
            .unwrap();

        assert!(verify_result.valid);
    }

    #[test]
    fn test_create_verify_hmac() {
        let pk = make_key(42);
        let pw = ProtoWallet::from_private_key(pk).unwrap();
        let data = b"HMAC this data".to_vec();

        let enc_args = test_encryption_args(Counterparty {
            r#type: CounterpartyType::Self_,
            counterparty: None,
        });

        let hmac_result = pw
            .create_hmac(CreateHmacArgs {
                encryption_args: enc_args.clone(),
                data: data.clone(),
            })
            .unwrap();

        let verify_result = pw
            .verify_hmac(VerifyHmacArgs {
                encryption_args: enc_args,
                data,
                hmac: hmac_result.hmac,
            })
            .unwrap();

        assert!(verify_result.valid);
    }

    #[test]
    fn test_hmac_invalid() {
        let pk = make_key(42);
        let pw = ProtoWallet::from_private_key(pk).unwrap();

        let enc_args = test_encryption_args(Counterparty {
            r#type: CounterpartyType::Self_,
            counterparty: None,
        });

        let result = pw
            .verify_hmac(VerifyHmacArgs {
                encryption_args: enc_args,
                data: b"some data".to_vec(),
                hmac: [0u8; 32],
            })
            .unwrap();

        assert!(!result.valid);
    }

    #[test]
    fn test_wallet_wraps_proto() {
        let pk = make_key(42);
        let w = Wallet::new(Some(pk)).unwrap();
        let result = w.get_public_key(GetPublicKeyArgs {
            encryption_args: test_encryption_args(Counterparty::default()),
            identity_key: true,
            for_self: None,
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_anyone_wallet() {
        let w = Wallet::new(None).unwrap();
        let result = w.get_public_key(GetPublicKeyArgs {
            encryption_args: test_encryption_args(Counterparty::default()),
            identity_key: true,
            for_self: None,
        });
        assert!(result.is_ok());
    }
}
