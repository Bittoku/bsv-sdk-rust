//! Chain hash type for transaction and block identification.
//!
//! Provides a `Hash` type — a 32-byte array displayed as byte-reversed hex,
//! matching Bitcoin's convention for transaction IDs and block hashes.
//! Ported from the Go BSV SDK (`chainhash` package).

use crate::hash::sha256;
use crate::PrimitivesError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

/// Size of a Hash in bytes.
pub const HASH_SIZE: usize = 32;

/// Maximum hex string length for a Hash (64 hex characters).
pub const MAX_HASH_STRING_SIZE: usize = HASH_SIZE * 2;

/// A 32-byte hash used for transaction IDs, block hashes, and merkle trees.
///
/// When displayed as a string, the bytes are reversed to match Bitcoin's
/// standard representation (little-endian internal, big-endian display).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct Hash([u8; HASH_SIZE]);

impl Hash {
    /// Create a Hash from a raw 32-byte array.
    ///
    /// The bytes are stored as-is (internal byte order).
    ///
    /// # Arguments
    /// * `bytes` - The 32 bytes in internal (little-endian) order.
    ///
    /// # Returns
    /// A new `Hash`.
    pub fn new(bytes: [u8; HASH_SIZE]) -> Self {
        Hash(bytes)
    }

    /// Create a Hash from a byte slice.
    ///
    /// # Arguments
    /// * `bytes` - A slice that must be exactly 32 bytes.
    ///
    /// # Returns
    /// `Ok(Hash)` if the slice is 32 bytes, or an error otherwise.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PrimitivesError> {
        if bytes.len() != HASH_SIZE {
            return Err(PrimitivesError::InvalidHash(format!(
                "invalid hash length of {}, want {}",
                bytes.len(),
                HASH_SIZE
            )));
        }
        let mut arr = [0u8; HASH_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Hash(arr))
    }

    /// Create a Hash from a byte-reversed hex string.
    ///
    /// This matches the Go SDK's `NewHashFromHex` / `Decode` function.
    /// The hex string represents bytes in display order (reversed from
    /// internal storage). Short strings are zero-padded on the high end.
    ///
    /// # Arguments
    /// * `hex_str` - A hex string of up to 64 characters.
    ///
    /// # Returns
    /// `Ok(Hash)` on success, or an error for invalid input.
    pub fn from_hex(hex_str: &str) -> Result<Self, PrimitivesError> {
        if hex_str.is_empty() {
            return Ok(Hash::default());
        }
        if hex_str.len() > MAX_HASH_STRING_SIZE {
            return Err(PrimitivesError::InvalidHash(format!(
                "max hash string length is {} bytes",
                MAX_HASH_STRING_SIZE
            )));
        }

        // Pad to even length if needed.
        let padded = if !hex_str.len().is_multiple_of(2) {
            format!("0{}", hex_str)
        } else {
            hex_str.to_string()
        };

        // Decode hex into a temporary buffer, right-aligned in a 32-byte array.
        let decoded = hex::decode(&padded)?;
        let mut reversed_hash = [0u8; HASH_SIZE];
        let offset = HASH_SIZE - decoded.len();
        reversed_hash[offset..].copy_from_slice(&decoded);

        // Reverse to get internal byte order.
        let mut dst = [0u8; HASH_SIZE];
        for i in 0..HASH_SIZE {
            dst[i] = reversed_hash[HASH_SIZE - 1 - i];
        }

        Ok(Hash(dst))
    }

    /// Return a copy of the internal bytes.
    ///
    /// # Returns
    /// A `Vec<u8>` containing the 32 hash bytes in internal order.
    pub fn clone_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Set the hash bytes from a slice.
    ///
    /// # Arguments
    /// * `bytes` - A slice that must be exactly 32 bytes.
    ///
    /// # Returns
    /// `Ok(())` on success, or an error if the length is wrong.
    pub fn set_bytes(&mut self, bytes: &[u8]) -> Result<(), PrimitivesError> {
        if bytes.len() != HASH_SIZE {
            return Err(PrimitivesError::InvalidHash(format!(
                "invalid hash length of {}, want {}",
                bytes.len(),
                HASH_SIZE
            )));
        }
        self.0.copy_from_slice(bytes);
        Ok(())
    }

    /// Check equality with another Hash reference.
    ///
    /// Handles the None/null case like the Go SDK's `IsEqual` method.
    ///
    /// # Arguments
    /// * `other` - An optional reference to another Hash.
    ///
    /// # Returns
    /// `true` if both hashes are equal.
    pub fn is_equal(&self, other: Option<&Hash>) -> bool {
        match other {
            Some(h) => self.0 == h.0,
            None => false,
        }
    }

    /// Access the internal byte array as a reference.
    ///
    /// # Returns
    /// A reference to the 32-byte internal array.
    pub fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }

    /// Return the size of the hash in bytes.
    ///
    /// # Returns
    /// Always returns 32.
    pub fn size(&self) -> usize {
        HASH_SIZE
    }
}

/// Display the hash as byte-reversed hex (Bitcoin convention).
///
/// Internal bytes `[0x06, 0xe5, ...]` display as `"...e506"`.
impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut reversed = self.0;
        reversed.reverse();
        write!(f, "{}", hex::encode(reversed))
    }
}

/// Parse a byte-reversed hex string into a Hash.
///
/// Equivalent to `Hash::from_hex`.
impl FromStr for Hash {
    type Err = PrimitivesError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Hash::from_hex(s)
    }
}

/// Serialize as a hex string in JSON.
impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

/// Deserialize from a hex string in JSON.
impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Hash::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Compute SHA-256 of the input and return the result as a Hash.
///
/// Equivalent to the Go SDK's `chainhash.HashH`.
///
/// # Arguments
/// * `data` - Byte slice to hash.
///
/// # Returns
/// A `Hash` containing the raw SHA-256 digest.
pub fn hash_h(data: &[u8]) -> Hash {
    Hash(sha256(data))
}

/// Compute double SHA-256 of the input and return the result as a Hash.
///
/// Equivalent to the Go SDK's `chainhash.DoubleHashH`.
///
/// # Arguments
/// * `data` - Byte slice to hash.
///
/// # Returns
/// A `Hash` containing the double SHA-256 digest.
pub fn double_hash_h(data: &[u8]) -> Hash {
    Hash(crate::hash::sha256d(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Genesis block hash bytes in internal (little-endian) order.
    const MAIN_NET_GENESIS_HASH: Hash = Hash([
        0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7,
        0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ]);

    #[test]
    fn test_hash_api() {
        // Hash of block 234439 (short hex string).
        let block_hash_str = "14a0810ac680a3eb3f82edc878cea25ec41d6b790744e5daeef";
        let block_hash = Hash::from_hex(block_hash_str).unwrap();

        // Hash of block 234440 as raw bytes.
        let buf: [u8; 32] = [
            0x79, 0xa6, 0x1a, 0xdb, 0xc6, 0xe5, 0xa2, 0xe1, 0x39, 0xd2, 0x71, 0x3a, 0x54, 0x6e,
            0xc7, 0xc8, 0x75, 0x63, 0x2e, 0x75, 0xf1, 0xdf, 0x9c, 0x3f, 0xa6, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let hash = Hash::from_bytes(&buf).unwrap();

        // Ensure proper size.
        assert_eq!(hash.size(), HASH_SIZE);

        // Ensure contents match.
        assert_eq!(hash.as_bytes(), &buf);

        // Block 234440 should not equal block 234439.
        assert!(!hash.is_equal(Some(&block_hash)));

        // Set hash from cloned bytes of block_hash.
        let mut hash2 = hash;
        hash2.set_bytes(&block_hash.clone_bytes()).unwrap();
        assert!(hash2.is_equal(Some(&block_hash)));

        // is_equal with None returns false for non-default hash.
        assert!(!hash.is_equal(None));

        // Invalid size for set_bytes.
        let mut h = Hash::default();
        assert!(h.set_bytes(&[0x00]).is_err());

        // Invalid size for from_bytes.
        let invalid = vec![0u8; HASH_SIZE + 1];
        assert!(Hash::from_bytes(&invalid).is_err());
    }

    #[test]
    fn test_hash_string() {
        // Block 100000 hash in internal byte order.
        let hash = Hash::new([
            0x06, 0xe5, 0x33, 0xfd, 0x1a, 0xda, 0x86, 0x39, 0x1f, 0x3f, 0x6c, 0x34, 0x32, 0x04,
            0xb0, 0xd2, 0x78, 0xd4, 0xaa, 0xec, 0x1c, 0x0b, 0x20, 0xaa, 0x27, 0xba, 0x03, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]);
        assert_eq!(
            hash.to_string(),
            "000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506"
        );
    }

    #[test]
    fn test_new_hash_from_hex() {
        // Genesis hash from hex string.
        let result =
            Hash::from_hex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .unwrap();
        assert_eq!(result, MAIN_NET_GENESIS_HASH);

        // Genesis hash with stripped leading zeros.
        let result =
            Hash::from_hex("19d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f").unwrap();
        assert_eq!(result, MAIN_NET_GENESIS_HASH);

        // Empty string -> zero hash.
        let result = Hash::from_hex("").unwrap();
        assert_eq!(result, Hash::default());

        // Single digit.
        let result = Hash::from_hex("1").unwrap();
        let expected = Hash::new([
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]);
        assert_eq!(result, expected);

        // Block 203707 with stripped leading zeros.
        let result = Hash::from_hex("3264bc2ac36a60840790ba1d475d01367e7c723da941069e9dc").unwrap();
        let expected = Hash::new([
            0xdc, 0xe9, 0x69, 0x10, 0x94, 0xda, 0x23, 0xc7, 0xe7, 0x67, 0x13, 0xd0, 0x75, 0xd4,
            0xa1, 0x0b, 0x79, 0x40, 0x08, 0xa6, 0x36, 0xac, 0xc2, 0x4b, 0x26, 0x03, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]);
        assert_eq!(result, expected);

        // String too long.
        let result =
            Hash::from_hex("01234567890123456789012345678901234567890123456789012345678912345");
        assert!(result.is_err());

        // Invalid hex character.
        let result = Hash::from_hex("abcdefg");
        assert!(result.is_err());
    }

    #[test]
    fn test_marshalling() {
        /// Helper struct for JSON round-trip testing.
        #[derive(Serialize, Deserialize)]
        struct TestData {
            hash: Hash,
        }

        // HashH("hello") should match Go SDK.
        let data = TestData {
            hash: hash_h(b"hello"),
        };
        assert_eq!(
            data.hash.to_string(),
            "24988b93623304735e42a71f5c1e161b9ee2b9c52a3be8260ea3b05fba4df22c"
        );

        // Serialize to JSON.
        let json = serde_json::to_string(&data).unwrap();
        assert_eq!(
            json,
            r#"{"hash":"24988b93623304735e42a71f5c1e161b9ee2b9c52a3be8260ea3b05fba4df22c"}"#
        );

        // Deserialize back.
        let data2: TestData = serde_json::from_str(&json).unwrap();
        assert_eq!(
            data2.hash.to_string(),
            "24988b93623304735e42a71f5c1e161b9ee2b9c52a3be8260ea3b05fba4df22c"
        );
    }
}
