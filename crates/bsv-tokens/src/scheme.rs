//! Token scheme definition and authority configuration.

use serde::{Deserialize, Serialize};

use crate::error::TokenError;
use crate::token_id::TokenId;

/// Multi-signature authority configuration for token governance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Authority {
    /// Number of required signatures (m-of-n).
    pub m: usize,
    /// Public keys (hex-encoded) of the authority signers.
    pub public_keys: Vec<String>,
}

impl Authority {
    /// Validate the authority configuration.
    ///
    /// Checks that `m` is at least 1, does not exceed the number of keys,
    /// and that at least one public key is provided.
    pub fn validate(&self) -> Result<(), TokenError> {
        if self.public_keys.is_empty() {
            return Err(TokenError::InvalidAuthority(
                "at least one public key is required".into(),
            ));
        }
        if self.m == 0 {
            return Err(TokenError::InvalidAuthority("m must be at least 1".into()));
        }
        if self.m > self.public_keys.len() {
            return Err(TokenError::InvalidAuthority(format!(
                "m ({}) exceeds number of public keys ({})",
                self.m,
                self.public_keys.len()
            )));
        }
        Ok(())
    }
}

/// A token scheme defining the properties of a token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokenScheme {
    /// Human-readable name of the token.
    pub name: String,
    /// Unique identifier for the token (derived from an address).
    pub token_id: TokenId,
    /// Short symbol (e.g. "BSV", "USDT").
    pub symbol: String,
    /// Number of satoshis backing each token unit.
    pub satoshis_per_token: u64,
    /// Whether the token supports freeze operations.
    pub freeze: bool,
    /// Whether the token supports confiscation operations.
    pub confiscation: bool,
    /// Whether the token can be split into fractional amounts.
    pub is_divisible: bool,
    /// Multi-signature authority controlling governance operations.
    pub authority: Authority,
}

impl TokenScheme {
    /// Serialize the scheme to JSON bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TokenError> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Deserialize a scheme from JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TokenError> {
        Ok(serde_json::from_slice(bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_scheme() -> TokenScheme {
        TokenScheme {
            name: "Test Token".into(),
            token_id: TokenId::from_string("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
            symbol: "TST".into(),
            satoshis_per_token: 1000,
            freeze: true,
            confiscation: false,
            is_divisible: true,
            authority: Authority {
                m: 2,
                public_keys: vec![
                    "02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc".into(),
                    "03a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc".into(),
                ],
            },
        }
    }

    #[test]
    fn roundtrip_serialization() {
        let scheme = sample_scheme();
        let bytes = scheme.to_bytes().unwrap();
        let restored = TokenScheme::from_bytes(&bytes).unwrap();
        assert_eq!(scheme, restored);
    }

    #[test]
    fn json_roundtrip() {
        let scheme = sample_scheme();
        let json = serde_json::to_string_pretty(&scheme).unwrap();
        let restored: TokenScheme = serde_json::from_str(&json).unwrap();
        assert_eq!(scheme, restored);
    }

    #[test]
    fn authority_validate_ok() {
        let auth = Authority {
            m: 1,
            public_keys: vec!["key1".into()],
        };
        assert!(auth.validate().is_ok());
    }

    #[test]
    fn authority_validate_m_zero() {
        let auth = Authority {
            m: 0,
            public_keys: vec!["key1".into()],
        };
        assert!(auth.validate().is_err());
    }

    #[test]
    fn authority_validate_m_exceeds_keys() {
        let auth = Authority {
            m: 3,
            public_keys: vec!["key1".into(), "key2".into()],
        };
        assert!(auth.validate().is_err());
    }

    #[test]
    fn authority_validate_empty_keys() {
        let auth = Authority {
            m: 1,
            public_keys: vec![],
        };
        assert!(auth.validate().is_err());
    }
}
