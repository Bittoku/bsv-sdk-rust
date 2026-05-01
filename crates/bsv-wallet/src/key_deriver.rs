//! BRC-42/43 key derivation.
//!
//! KeyDeriver derives private, public, and symmetric keys from a root private key
//! using the BRC-42 invoice number scheme.

use regex::Regex;
use std::sync::LazyLock;

use bsv_primitives::ec::private_key::PrivateKey;
use bsv_primitives::ec::public_key::PublicKey;
use bsv_primitives::ec::symmetric::SymmetricKey;
use bsv_primitives::hash::sha256_hmac;

use crate::error::WalletError;
use crate::types::{anyone_key, Counterparty, CounterpartyType, Protocol};

static RE_ONLY_LETTERS_NUMBERS_SPACES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9 ]+$").unwrap());

/// Derives various key types from a root private key using BRC-42/43.
///
/// The root key material is zeroized when this value is dropped.
#[derive(Clone, Debug)]
pub struct KeyDeriver {
    root_key: PrivateKey,
}

impl Drop for KeyDeriver {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        let mut bytes = self.root_key.to_bytes();
        bytes.zeroize();
        // The inner PrivateKey's own Drop will also fire.
    }
}

impl KeyDeriver {
    /// Create a new KeyDeriver. If `private_key` is None, uses the "anyone" key (scalar=1).
    pub fn new(private_key: Option<PrivateKey>) -> Self {
        let root_key = private_key.unwrap_or_else(|| anyone_key().0);
        KeyDeriver { root_key }
    }

    /// The identity public key (root key's public key).
    pub fn identity_key(&self) -> PublicKey {
        self.root_key.pub_key()
    }

    /// Hex-encoded compressed identity public key.
    pub fn identity_key_hex(&self) -> String {
        hex::encode(self.identity_key().to_compressed())
    }

    /// Derive a symmetric key for the given protocol, key ID, and counterparty.
    pub fn derive_symmetric_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
    ) -> Result<SymmetricKey, WalletError> {
        // If counterparty is 'anyone', substitute the anyone public key
        let effective_counterparty = if counterparty.r#type == CounterpartyType::Anyone {
            Counterparty {
                r#type: CounterpartyType::Other,
                counterparty: Some(anyone_key().1),
            }
        } else {
            counterparty.clone()
        };

        let derived_pub =
            self.derive_public_key(protocol, key_id, &effective_counterparty, false)?;
        let derived_priv = self.derive_private_key(protocol, key_id, &effective_counterparty)?;

        // Shared secret between derived keys
        let shared_secret = derived_priv.derive_shared_secret(&derived_pub)?;

        // Return x-coordinate of shared secret as symmetric key
        // The compressed pubkey is 33 bytes: 0x02/0x03 prefix + 32 bytes x-coordinate
        let compressed = shared_secret.to_compressed();
        Ok(SymmetricKey::new(&compressed[1..]))
    }

    /// Derive a public key for the given protocol, key ID, counterparty, and direction.
    ///
    /// If `for_self` is true, derives the key that corresponds to our own private key
    /// (i.e., what the counterparty would compute for us). Otherwise derives the
    /// counterparty's key.
    pub fn derive_public_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
        for_self: bool,
    ) -> Result<PublicKey, WalletError> {
        let counterparty_key = self.normalize_counterparty(counterparty)?;
        let invoice_number = self.compute_invoice_number(protocol, key_id)?;

        if for_self {
            let priv_key = self
                .root_key
                .derive_child(&counterparty_key, &invoice_number)?;
            Ok(priv_key.pub_key())
        } else {
            let pub_key = counterparty_key.derive_child(&self.root_key, &invoice_number)?;
            Ok(pub_key)
        }
    }

    /// Derive a private key for the given protocol, key ID, and counterparty.
    pub fn derive_private_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
    ) -> Result<PrivateKey, WalletError> {
        let counterparty_key = self.normalize_counterparty(counterparty)?;
        let invoice_number = self.compute_invoice_number(protocol, key_id)?;
        let k = self
            .root_key
            .derive_child(&counterparty_key, &invoice_number)?;
        Ok(k)
    }

    /// Reveal the specific key association (HMAC of shared secret + invoice number).
    pub fn reveal_specific_secret(
        &self,
        counterparty: &Counterparty,
        protocol: &Protocol,
        key_id: &str,
    ) -> Result<Vec<u8>, WalletError> {
        let counterparty_key = self.normalize_counterparty(counterparty)?;
        let shared_secret = self.root_key.derive_shared_secret(&counterparty_key)?;
        let invoice_number = self.compute_invoice_number(protocol, key_id)?;

        // HMAC-SHA256(key=compressed_shared_secret, data=invoice_number)
        let mac = sha256_hmac(&shared_secret.to_compressed(), invoice_number.as_bytes());
        Ok(mac.to_vec())
    }

    /// Reveal the counterparty shared secret. Cannot be used for 'self'.
    pub fn reveal_counterparty_secret(
        &self,
        counterparty: &Counterparty,
    ) -> Result<PublicKey, WalletError> {
        if counterparty.r#type == CounterpartyType::Self_ {
            return Err(WalletError::InvalidCounterparty(
                "counterparty secrets cannot be revealed for counterparty=self".into(),
            ));
        }

        let counterparty_key = self.normalize_counterparty(counterparty)?;

        // Double-check: ensure counterparty is not actually self
        let self_pub = self.root_key.pub_key();
        let key_by_self = self.root_key.derive_child(&self_pub, "test")?;
        let key_by_counterparty = self.root_key.derive_child(&counterparty_key, "test")?;

        if key_by_self.to_bytes() == key_by_counterparty.to_bytes() {
            return Err(WalletError::InvalidCounterparty(
                "counterparty secrets cannot be revealed if counterparty key is self".into(),
            ));
        }

        let shared_secret = self.root_key.derive_shared_secret(&counterparty_key)?;
        Ok(shared_secret)
    }

    /// Normalize counterparty to a public key.
    fn normalize_counterparty(
        &self,
        counterparty: &Counterparty,
    ) -> Result<PublicKey, WalletError> {
        match counterparty.r#type {
            CounterpartyType::Self_ => Ok(self.root_key.pub_key()),
            CounterpartyType::Other => counterparty.counterparty.clone().ok_or_else(|| {
                WalletError::InvalidCounterparty(
                    "counterparty public key required for other".into(),
                )
            }),
            CounterpartyType::Anyone => Ok(anyone_key().1),
            CounterpartyType::Uninitialized => Err(WalletError::InvalidCounterparty(
                "invalid counterparty, must be self, other, or anyone".into(),
            )),
        }
    }

    /// Compute the invoice number string: "{security_level}-{protocol}-{key_id}"
    fn compute_invoice_number(
        &self,
        protocol: &Protocol,
        key_id: &str,
    ) -> Result<String, WalletError> {
        // Validate security level
        if protocol.security_level < 0 || protocol.security_level > 2 {
            return Err(WalletError::InvalidProtocol(
                "protocol security level must be 0, 1, or 2".into(),
            ));
        }

        // Validate key ID
        if key_id.is_empty() {
            return Err(WalletError::InvalidKeyId(
                "key IDs must be 1 character or more".into(),
            ));
        }
        if key_id.len() > 800 {
            return Err(WalletError::InvalidKeyId(
                "key IDs must be 800 characters or less".into(),
            ));
        }

        // Validate protocol name
        let protocol_name = protocol.protocol.trim().to_lowercase();
        if protocol_name.len() < 5 {
            return Err(WalletError::InvalidProtocol(
                "protocol names must be 5 characters or more".into(),
            ));
        }
        if protocol_name.len() > 400 {
            if protocol_name.starts_with("specific linkage revelation ") {
                if protocol_name.len() > 430 {
                    return Err(WalletError::InvalidProtocol(
                        "specific linkage revelation protocol names must be 430 characters or less"
                            .into(),
                    ));
                }
            } else {
                return Err(WalletError::InvalidProtocol(
                    "protocol names must be 400 characters or less".into(),
                ));
            }
        }
        if protocol_name.contains("  ") {
            return Err(WalletError::InvalidProtocol(
                "protocol names cannot contain multiple consecutive spaces (\"  \")".into(),
            ));
        }
        if !RE_ONLY_LETTERS_NUMBERS_SPACES.is_match(&protocol_name) {
            return Err(WalletError::InvalidProtocol(
                "protocol names can only contain letters, numbers and spaces".into(),
            ));
        }
        if protocol_name.ends_with(" protocol") {
            return Err(WalletError::InvalidProtocol(
                "no need to end your protocol name with \" protocol\"".into(),
            ));
        }

        Ok(format!(
            "{}-{}-{}",
            protocol.security_level, protocol_name, key_id
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_primitives::ec::private_key::PrivateKey;

    fn test_keys() -> (
        PrivateKey,
        PublicKey,
        PrivateKey,
        PublicKey,
        PrivateKey,
        PublicKey,
    ) {
        let root = PrivateKey::from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 42,
        ])
        .unwrap();
        let root_pub = root.pub_key();
        let counterparty = PrivateKey::from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 69,
        ])
        .unwrap();
        let counterparty_pub = counterparty.pub_key();
        let anyone = PrivateKey::from_bytes(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ])
        .unwrap();
        let anyone_pub = anyone.pub_key();
        (
            root,
            root_pub,
            counterparty,
            counterparty_pub,
            anyone,
            anyone_pub,
        )
    }

    fn test_protocol() -> Protocol {
        Protocol {
            security_level: 0,
            protocol: "testprotocol".into(),
        }
    }

    #[test]
    fn test_identity_key() {
        let (root, root_pub, ..) = test_keys();
        let kd = KeyDeriver::new(Some(root));
        assert_eq!(kd.identity_key().to_compressed(), root_pub.to_compressed());
    }

    #[test]
    fn test_identity_key_hex() {
        let (root, root_pub, ..) = test_keys();
        let kd = KeyDeriver::new(Some(root));
        assert_eq!(kd.identity_key_hex(), hex::encode(root_pub.to_compressed()));
    }

    #[test]
    fn test_compute_invoice_number() {
        let (root, ..) = test_keys();
        let kd = KeyDeriver::new(Some(root));
        let inv = kd
            .compute_invoice_number(&test_protocol(), "12345")
            .unwrap();
        assert_eq!(inv, "0-testprotocol-12345");
    }

    #[test]
    fn test_normalize_counterparty_self() {
        let (root, root_pub, ..) = test_keys();
        let kd = KeyDeriver::new(Some(root));
        let normalized = kd
            .normalize_counterparty(&Counterparty {
                r#type: CounterpartyType::Self_,
                counterparty: None,
            })
            .unwrap();
        assert_eq!(normalized.to_compressed(), root_pub.to_compressed());
    }

    #[test]
    fn test_normalize_counterparty_anyone() {
        let (root, _, _, _, _, anyone_pub) = test_keys();
        let kd = KeyDeriver::new(Some(root));
        let normalized = kd
            .normalize_counterparty(&Counterparty {
                r#type: CounterpartyType::Anyone,
                counterparty: None,
            })
            .unwrap();
        assert_eq!(normalized.to_compressed(), anyone_pub.to_compressed());
    }

    #[test]
    fn test_normalize_counterparty_other() {
        let (root, _, _, counterparty_pub, ..) = test_keys();
        let kd = KeyDeriver::new(Some(root));
        let normalized = kd
            .normalize_counterparty(&Counterparty {
                r#type: CounterpartyType::Other,
                counterparty: Some(counterparty_pub.clone()),
            })
            .unwrap();
        assert_eq!(normalized.to_compressed(), counterparty_pub.to_compressed());
    }

    #[test]
    fn test_derive_public_key_as_anyone() {
        let (_, _, _, counterparty_pub, ..) = test_keys();
        let kd = KeyDeriver::new(None); // anyone
        let result = kd.derive_public_key(
            &test_protocol(),
            "12345",
            &Counterparty {
                r#type: CounterpartyType::Other,
                counterparty: Some(counterparty_pub),
            },
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_derive_public_key_for_counterparty() {
        let (root, _, _, counterparty_pub, ..) = test_keys();
        let kd = KeyDeriver::new(Some(root));
        let result = kd.derive_public_key(
            &test_protocol(),
            "12345",
            &Counterparty {
                r#type: CounterpartyType::Other,
                counterparty: Some(counterparty_pub),
            },
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_derive_public_key_for_self() {
        let (root, _, _, counterparty_pub, ..) = test_keys();
        let kd = KeyDeriver::new(Some(root));
        let result = kd.derive_public_key(
            &test_protocol(),
            "12345",
            &Counterparty {
                r#type: CounterpartyType::Other,
                counterparty: Some(counterparty_pub),
            },
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_derive_private_key() {
        let (root, _, _, counterparty_pub, ..) = test_keys();
        let kd = KeyDeriver::new(Some(root));
        let result = kd.derive_private_key(
            &test_protocol(),
            "12345",
            &Counterparty {
                r#type: CounterpartyType::Other,
                counterparty: Some(counterparty_pub),
            },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_derive_symmetric_key() {
        let (root, _, _, counterparty_pub, ..) = test_keys();
        let kd = KeyDeriver::new(Some(root));
        let sk = kd
            .derive_symmetric_key(
                &test_protocol(),
                "12345",
                &Counterparty {
                    r#type: CounterpartyType::Other,
                    counterparty: Some(counterparty_pub),
                },
            )
            .unwrap();
        assert_eq!(
            hex::encode(sk.to_bytes()),
            "4ce8e868f2006e3fa8fc61ea4bc4be77d397b412b44b4dca047fb7ec3ca7cfd8"
        );
    }

    #[test]
    fn test_derive_symmetric_key_with_anyone() {
        let (root, ..) = test_keys();
        let kd = KeyDeriver::new(Some(root));
        let result = kd.derive_symmetric_key(
            &test_protocol(),
            "12345",
            &Counterparty {
                r#type: CounterpartyType::Anyone,
                counterparty: None,
            },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_reveal_counterparty_secret_not_self() {
        let (root, root_pub, ..) = test_keys();
        let kd = KeyDeriver::new(Some(root));

        // Cannot reveal for self
        let err = kd
            .reveal_counterparty_secret(&Counterparty {
                r#type: CounterpartyType::Self_,
                counterparty: None,
            })
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("counterparty secrets cannot be revealed for counterparty=self"));

        // Cannot reveal for own public key either
        let err = kd
            .reveal_counterparty_secret(&Counterparty {
                r#type: CounterpartyType::Other,
                counterparty: Some(root_pub),
            })
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("counterparty secrets cannot be revealed if counterparty key is self"));
    }

    #[test]
    fn test_reveal_counterparty_secret() {
        let (root, _, _, counterparty_pub, ..) = test_keys();
        let kd = KeyDeriver::new(Some(root.clone()));
        let shared = kd
            .reveal_counterparty_secret(&Counterparty {
                r#type: CounterpartyType::Other,
                counterparty: Some(counterparty_pub.clone()),
            })
            .unwrap();
        let expected = root.derive_shared_secret(&counterparty_pub).unwrap();
        assert_eq!(shared.to_der(), expected.to_der());
    }

    #[test]
    fn test_reveal_specific_secret() {
        let (root, _, _, counterparty_pub, ..) = test_keys();
        let kd = KeyDeriver::new(Some(root.clone()));
        let protocol = test_protocol();
        let key_id = "12345";

        let secret = kd
            .reveal_specific_secret(
                &Counterparty {
                    r#type: CounterpartyType::Other,
                    counterparty: Some(counterparty_pub.clone()),
                },
                &protocol,
                key_id,
            )
            .unwrap();
        assert!(!secret.is_empty());

        // Verify manually
        let shared = root.derive_shared_secret(&counterparty_pub).unwrap();
        let inv = kd.compute_invoice_number(&protocol, key_id).unwrap();
        let expected = sha256_hmac(&shared.to_compressed(), inv.as_bytes());
        assert_eq!(secret, expected.to_vec());
    }

    #[test]
    fn test_invalid_protocol_names() {
        let (root, ..) = test_keys();
        let kd = KeyDeriver::new(Some(root));
        let key_id = "12345";

        let cases = vec![
            // (protocol, key_id, should_error)
            (
                Protocol {
                    security_level: 2,
                    protocol: "test".into(),
                },
                "long".to_string() + &"x".repeat(800),
                "long key ID",
            ),
            (
                Protocol {
                    security_level: 2,
                    protocol: "test".into(),
                },
                "".into(),
                "empty key ID",
            ),
            (
                Protocol {
                    security_level: -3,
                    protocol: "otherwise valid".into(),
                },
                key_id.into(),
                "invalid security level",
            ),
            (
                Protocol {
                    security_level: 2,
                    protocol: "double  space".into(),
                },
                key_id.into(),
                "double space",
            ),
            (
                Protocol {
                    security_level: 0,
                    protocol: "".into(),
                },
                key_id.into(),
                "empty protocol",
            ),
            (
                Protocol {
                    security_level: 0,
                    protocol: "long".to_string() + &"x".repeat(400),
                },
                key_id.into(),
                "long protocol",
            ),
            (
                Protocol {
                    security_level: 2,
                    protocol: "redundant protocol protocol".into(),
                },
                key_id.into(),
                "redundant suffix",
            ),
            (
                Protocol {
                    security_level: 2,
                    protocol: "üñî√é®sål ©0på".into(),
                },
                key_id.into(),
                "invalid chars",
            ),
        ];

        for (proto, kid, label) in cases {
            let result = kd.compute_invoice_number(&proto, &kid);
            assert!(result.is_err(), "should error for: {}", label);
        }
    }
}
