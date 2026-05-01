/// Bitcoin address handling.
///
/// Supports P2PKH address generation from public key hashes,
/// address validation, and mainnet/testnet discrimination.
/// Uses Base58Check encoding with SHA-256d checksums.
use std::fmt;

use bsv_primitives::hash::{hash160, sha256d};

use crate::ScriptError;

/// Mainnet P2PKH address version byte.
const MAINNET_P2PKH: u8 = 0x00;
/// Testnet P2PKH address version byte.
const TESTNET_P2PKH: u8 = 0x6f;

/// Bitcoin network type for address prefix selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Network {
    /// Bitcoin mainnet (address prefix 0x00, starts with '1').
    Mainnet,
    /// Bitcoin testnet (address prefix 0x6f, starts with 'm' or 'n').
    Testnet,
}

/// A Bitcoin P2PKH address.
///
/// Contains the 20-byte public key hash and the network it belongs to.
/// Can be serialized to/from the Base58Check string format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    /// The human-readable Base58Check address string.
    pub address_string: String,
    /// The 20-byte RIPEMD-160(SHA-256(pubkey)) hash.
    pub public_key_hash: [u8; 20],
    /// The network this address belongs to.
    pub network: Network,
}

impl Address {
    /// Parse a Base58Check-encoded address string.
    ///
    /// Decodes the string, validates the checksum, and detects the network
    /// from the version byte (0x00 = mainnet, 0x6f = testnet).
    ///
    /// # Arguments
    /// * `addr` - The Base58Check address string.
    ///
    /// # Returns
    /// An `Address` or an error if the string is invalid.
    pub fn from_string(addr: &str) -> Result<Self, ScriptError> {
        let decoded = bs58::decode(addr)
            .into_vec()
            .map_err(|_| ScriptError::InvalidAddress(format!("bad char for '{}'", addr)))?;

        if decoded.len() != 25 {
            return Err(ScriptError::InvalidAddressLength(addr.to_string()));
        }

        // Verify checksum: last 4 bytes should equal sha256d of first 21 bytes.
        let checksum = sha256d(&decoded[..21]);
        if decoded[21..25] != checksum[..4] {
            return Err(ScriptError::EncodingChecksumFailed);
        }

        let network = match decoded[0] {
            MAINNET_P2PKH => Network::Mainnet,
            TESTNET_P2PKH => Network::Testnet,
            _ => return Err(ScriptError::UnsupportedAddress(addr.to_string())),
        };

        let mut pkh = [0u8; 20];
        pkh.copy_from_slice(&decoded[1..21]);

        Ok(Address {
            address_string: addr.to_string(),
            public_key_hash: pkh,
            network,
        })
    }

    /// Create an address from a 20-byte public key hash.
    ///
    /// # Arguments
    /// * `hash` - The 20-byte hash160 of the public key.
    /// * `network` - The target network (Mainnet or Testnet).
    ///
    /// # Returns
    /// A new `Address` with the encoded Base58Check string.
    pub fn from_public_key_hash(hash: &[u8; 20], network: Network) -> Self {
        let version = match network {
            Network::Mainnet => MAINNET_P2PKH,
            Network::Testnet => TESTNET_P2PKH,
        };

        let mut payload = Vec::with_capacity(25);
        payload.push(version);
        payload.extend_from_slice(hash);
        let checksum = sha256d(&payload);
        payload.extend_from_slice(&checksum[..4]);

        let address_string = bs58::encode(&payload).into_string();

        Address {
            address_string,
            public_key_hash: *hash,
            network,
        }
    }

    /// Create a mainnet address from a hex-encoded public key string.
    ///
    /// Computes hash160 of the decoded public key bytes and produces
    /// a mainnet address.
    ///
    /// # Arguments
    /// * `pub_key_hex` - Hex-encoded public key (compressed or uncompressed).
    ///
    /// # Returns
    /// A mainnet `Address`, or an error if the hex is invalid.
    pub fn from_public_key_string(pub_key_hex: &str, mainnet: bool) -> Result<Self, ScriptError> {
        let pub_key_bytes = hex::decode(pub_key_hex)?;
        let h = hash160(&pub_key_bytes);
        let network = if mainnet {
            Network::Mainnet
        } else {
            Network::Testnet
        };
        Ok(Self::from_public_key_hash(&h, network))
    }
}

impl fmt::Display for Address {
    /// Display the address as its Base58Check string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address_string)
    }
}

#[cfg(test)]
mod tests {
    //! Tests for Bitcoin address parsing, generation, and validation.
    //!
    //! Covers Address::from_string for mainnet/testnet addresses, checksum
    //! validation, network detection, Address::from_public_key_hash for both
    //! networks, Address::from_public_key_string roundtrips, Display output,
    //! and error cases for short/unsupported addresses. Test vectors are
    //! derived from the Go SDK reference implementation.

    use super::*;

    /// The public key hash shared across several test vectors.
    const TEST_PUBLIC_KEY_HASH: &str = "00ac6144c4db7b5790f343cf0477a65fb8a02eb7";

    // -----------------------------------------------------------------------
    // from_string (mainnet)
    // -----------------------------------------------------------------------

    /// Parse a known mainnet address and verify the public key hash and network.
    #[test]
    fn test_from_string_mainnet() {
        let address_str = "1E7ucTTWRTahCyViPhxSMor2pj4VGQdFMr";
        let addr = Address::from_string(address_str).expect("should parse mainnet");
        assert_eq!(addr.address_string, address_str);
        assert_eq!(
            hex::encode(addr.public_key_hash),
            "8fe80c75c9560e8b56ed64ea3c26e18d2c52211b"
        );
        assert_eq!(addr.network, Network::Mainnet);
    }

    // -----------------------------------------------------------------------
    // from_string (testnet)
    // -----------------------------------------------------------------------

    /// Parse a known testnet address and verify the public key hash and network.
    #[test]
    fn test_from_string_testnet() {
        let address_str = "mtdruWYVEV1wz5yL7GvpBj4MgifCB7yhPd";
        let addr = Address::from_string(address_str).expect("should parse testnet");
        assert_eq!(addr.address_string, address_str);
        assert_eq!(
            hex::encode(addr.public_key_hash),
            "8fe80c75c9560e8b56ed64ea3c26e18d2c52211b"
        );
        assert_eq!(addr.network, Network::Testnet);
    }

    /// Mainnet and testnet addresses for the same PKH should decode to the same hash.
    #[test]
    fn test_from_string_same_pkh_different_networks() {
        let mainnet_addr = Address::from_string("1E7ucTTWRTahCyViPhxSMor2pj4VGQdFMr")
            .expect("mainnet should parse");
        let testnet_addr = Address::from_string("mtdruWYVEV1wz5yL7GvpBj4MgifCB7yhPd")
            .expect("testnet should parse");
        assert_eq!(mainnet_addr.public_key_hash, testnet_addr.public_key_hash);
    }

    // -----------------------------------------------------------------------
    // from_string - error cases
    // -----------------------------------------------------------------------

    /// Verify that a short/invalid address returns an error.
    #[test]
    fn test_from_string_short_address() {
        let result = Address::from_string("ADD8E55");
        assert!(result.is_err());
    }

    /// Verify that an address with an unsupported version byte returns an error.
    #[test]
    fn test_from_string_unsupported_version() {
        let result = Address::from_string("27BvY7rFguYQvEL872Y7Fo77Y3EBApC2EK");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // from_public_key_string
    // -----------------------------------------------------------------------

    /// Create a mainnet address from a compressed public key hex string.
    #[test]
    fn test_from_public_key_string_mainnet() {
        let addr = Address::from_public_key_string(
            "026cf33373a9f3f6c676b75b543180703df225f7f8edbffedc417718a8ad4e89ce",
            true,
        )
        .expect("should create address");
        assert_eq!(hex::encode(addr.public_key_hash), TEST_PUBLIC_KEY_HASH);
        assert_eq!(addr.address_string, "114ZWApV4EEU8frr7zygqQcB1V2BodGZuS");
        assert_eq!(addr.network, Network::Mainnet);
    }

    /// Create a testnet address from the same compressed public key hex string.
    #[test]
    fn test_from_public_key_string_testnet() {
        let addr = Address::from_public_key_string(
            "026cf33373a9f3f6c676b75b543180703df225f7f8edbffedc417718a8ad4e89ce",
            false,
        )
        .expect("should create address");
        assert_eq!(hex::encode(addr.public_key_hash), TEST_PUBLIC_KEY_HASH);
        assert_eq!(addr.address_string, "mfaWoDuTsFfiunLTqZx4fKpVsUctiDV9jk");
        assert_eq!(addr.network, Network::Testnet);
    }

    /// Verify that an invalid public key hex returns an error.
    #[test]
    fn test_from_public_key_string_invalid() {
        let result = Address::from_public_key_string("invalid_pubkey", true);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // from_public_key_hash
    // -----------------------------------------------------------------------

    /// Create a mainnet address from a raw 20-byte public key hash.
    #[test]
    fn test_from_public_key_hash_mainnet() {
        let hash_bytes = hex::decode(TEST_PUBLIC_KEY_HASH).expect("valid hex");
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&hash_bytes);
        let addr = Address::from_public_key_hash(&hash, Network::Mainnet);
        assert_eq!(addr.public_key_hash, hash);
        assert_eq!(addr.address_string, "114ZWApV4EEU8frr7zygqQcB1V2BodGZuS");
        assert_eq!(addr.network, Network::Mainnet);
    }

    /// Create a testnet address from a raw 20-byte public key hash.
    #[test]
    fn test_from_public_key_hash_testnet() {
        let hash_bytes = hex::decode(TEST_PUBLIC_KEY_HASH).expect("valid hex");
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&hash_bytes);
        let addr = Address::from_public_key_hash(&hash, Network::Testnet);
        assert_eq!(addr.public_key_hash, hash);
        assert_eq!(addr.address_string, "mfaWoDuTsFfiunLTqZx4fKpVsUctiDV9jk");
        assert_eq!(addr.network, Network::Testnet);
    }

    // -----------------------------------------------------------------------
    // String roundtrip
    // -----------------------------------------------------------------------

    /// Verify that from_string -> to_string produces the original address.
    #[test]
    fn test_address_to_string_roundtrip_mainnet() {
        let address_str = "1E7ucTTWRTahCyViPhxSMor2pj4VGQdFMr";
        let addr = Address::from_string(address_str).expect("should parse");
        assert_eq!(format!("{}", addr), address_str);
    }

    /// Verify testnet address string roundtrip.
    #[test]
    fn test_address_to_string_roundtrip_testnet() {
        let address_str = "mtdruWYVEV1wz5yL7GvpBj4MgifCB7yhPd";
        let addr = Address::from_string(address_str).expect("should parse");
        assert_eq!(format!("{}", addr), address_str);
    }

    /// Verify that from_public_key_hash -> from_string roundtrip is consistent.
    #[test]
    fn test_public_key_hash_to_address_to_string_roundtrip() {
        let hash_bytes = hex::decode(TEST_PUBLIC_KEY_HASH).expect("valid hex");
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&hash_bytes);

        let addr = Address::from_public_key_hash(&hash, Network::Mainnet);
        let parsed = Address::from_string(&addr.address_string).expect("should parse back");

        assert_eq!(addr.public_key_hash, parsed.public_key_hash);
        assert_eq!(addr.address_string, parsed.address_string);
        assert_eq!(addr.network, parsed.network);
    }
}
