//! secp256k1 private key with Bitcoin-specific functionality.
//!
//! Wraps k256 signing key and adds WIF encoding, child key derivation (BRC-42),
//! shared secret computation, and compact signature support.

use k256::ecdsa::SigningKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::ScalarPrimitive;
use k256::{Scalar, Secp256k1};
use rand::rngs::OsRng;

use crate::ec::public_key::PublicKey;
use crate::ec::signature::Signature;
use crate::hash::{sha256d, sha256_hmac};
use crate::PrimitivesError;

/// A secp256k1 private key for signing and key derivation.
///
/// Wraps a k256 `SigningKey` and provides Bitcoin-specific functionality
/// including WIF serialization, BRC-42 child derivation, and ECDH shared secrets.
#[derive(Clone, Debug)]
pub struct PrivateKey {
    /// The underlying k256 signing key.
    inner: SigningKey,
}

/// Length of a serialized private key in bytes.
const PRIVATE_KEY_BYTES_LEN: usize = 32;

/// Mainnet WIF prefix byte.
const MAINNET_PREFIX: u8 = 0x80;

/// Compression flag byte appended to WIF for compressed public keys.
const COMPRESS_MAGIC: u8 = 0x01;

impl PrivateKey {
    /// Generate a new random private key using the OS random number generator.
    ///
    /// # Returns
    /// A new randomly generated `PrivateKey`.
    pub fn new() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        PrivateKey {
            inner: signing_key,
        }
    }

    /// Create a private key from raw 32-byte scalar.
    ///
    /// # Arguments
    /// * `bytes` - A 32-byte slice representing the private key scalar.
    ///
    /// # Returns
    /// `Ok(PrivateKey)` if the bytes represent a valid scalar on secp256k1,
    /// or an error if the scalar is zero or out of range.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PrimitivesError> {
        if bytes.len() != PRIVATE_KEY_BYTES_LEN {
            return Err(PrimitivesError::InvalidPrivateKey(format!(
                "expected {} bytes, got {}",
                PRIVATE_KEY_BYTES_LEN,
                bytes.len()
            )));
        }
        let signing_key = SigningKey::from_bytes(bytes.into())?;
        Ok(PrivateKey {
            inner: signing_key,
        })
    }

    /// Create a private key from a hexadecimal string.
    ///
    /// # Arguments
    /// * `hex_str` - A 64-character hex string representing the 32-byte scalar.
    ///
    /// # Returns
    /// `Ok(PrivateKey)` on success, or an error if the hex is invalid or the scalar is invalid.
    pub fn from_hex(hex_str: &str) -> Result<Self, PrimitivesError> {
        if hex_str.is_empty() {
            return Err(PrimitivesError::InvalidPrivateKey(
                "private key hex is empty".to_string(),
            ));
        }
        let bytes =
            hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }

    /// Create a private key from a WIF (Wallet Import Format) string.
    ///
    /// Decodes the Base58Check-encoded string, validates the checksum,
    /// and extracts the 32-byte private key scalar.
    ///
    /// # Arguments
    /// * `wif` - A Base58Check-encoded WIF string (compressed or uncompressed).
    ///
    /// # Returns
    /// `Ok(PrivateKey)` on success, or an error if the WIF is malformed or the checksum fails.
    pub fn from_wif(wif: &str) -> Result<Self, PrimitivesError> {
        let decoded = bs58::decode(wif)
            .into_vec()
            .map_err(|e| PrimitivesError::InvalidWif(e.to_string()))?;
        let decoded_len = decoded.len();

        // Determine if compressed based on length:
        // 1 byte prefix + 32 bytes key + 1 byte compress flag + 4 byte checksum = 38
        // 1 byte prefix + 32 bytes key + 4 byte checksum = 37
        let is_compressed = match decoded_len {
            38 => {
                if decoded[33] != COMPRESS_MAGIC {
                    return Err(PrimitivesError::InvalidWif(
                        "malformed private key: invalid compression flag".to_string(),
                    ));
                }
                true
            }
            37 => false,
            _ => {
                return Err(PrimitivesError::InvalidWif(format!(
                    "malformed private key: invalid length {}",
                    decoded_len
                )));
            }
        };

        // Verify checksum: first 4 bytes of sha256d of the payload
        let payload_end = if is_compressed {
            1 + PRIVATE_KEY_BYTES_LEN + 1
        } else {
            1 + PRIVATE_KEY_BYTES_LEN
        };
        let checksum = sha256d(&decoded[..payload_end]);
        if checksum[..4] != decoded[decoded_len - 4..] {
            return Err(PrimitivesError::ChecksumMismatch);
        }

        let key_bytes = &decoded[1..1 + PRIVATE_KEY_BYTES_LEN];
        Self::from_bytes(key_bytes)
    }

    /// Encode the private key as a WIF string with the mainnet prefix (0x80).
    ///
    /// Always encodes for compressed public key format.
    ///
    /// # Returns
    /// A Base58Check-encoded WIF string.
    pub fn to_wif(&self) -> String {
        self.to_wif_prefix(MAINNET_PREFIX)
    }

    /// Encode the private key as a WIF string with a custom network prefix.
    ///
    /// Always encodes for compressed public key format.
    ///
    /// # Arguments
    /// * `prefix` - The network prefix byte (0x80 for mainnet, 0xef for testnet).
    ///
    /// # Returns
    /// A Base58Check-encoded WIF string.
    pub fn to_wif_prefix(&self, prefix: u8) -> String {
        // Build payload: prefix + key_bytes + compress_flag
        let key_bytes = self.to_bytes();
        let mut payload = Vec::with_capacity(1 + PRIVATE_KEY_BYTES_LEN + 1 + 4);
        payload.push(prefix);
        payload.extend_from_slice(&key_bytes);
        payload.push(COMPRESS_MAGIC); // always compressed

        let checksum = sha256d(&payload);
        payload.extend_from_slice(&checksum[..4]);

        bs58::encode(payload).into_string()
    }

    /// Serialize the private key as a 32-byte big-endian array.
    ///
    /// # Returns
    /// A 32-byte array containing the private key scalar.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.inner.to_bytes());
        out
    }

    /// Serialize the private key as a lowercase hexadecimal string.
    ///
    /// # Returns
    /// A 64-character hex string representing the 32-byte scalar.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Derive the corresponding public key for this private key.
    ///
    /// # Returns
    /// The `PublicKey` corresponding to this private key.
    pub fn pub_key(&self) -> PublicKey {
        let verifying_key = self.inner.verifying_key();
        PublicKey::from_k256_verifying_key(verifying_key)
    }

    /// Sign a message hash using deterministic RFC6979 nonces.
    ///
    /// The input should be a pre-computed hash (typically 32 bytes).
    /// Produces a low-S normalized signature per BIP-0062.
    ///
    /// # Arguments
    /// * `hash` - The message hash to sign (should be 32 bytes).
    ///
    /// # Returns
    /// `Ok(Signature)` on success, or an error if signing fails.
    pub fn sign(&self, hash: &[u8]) -> Result<Signature, PrimitivesError> {
        Signature::sign(hash, self)
    }

    /// Compute an ECDH shared secret with another public key.
    ///
    /// Multiplies the other party's public key by this private key's scalar,
    /// producing a shared EC point.
    ///
    /// # Arguments
    /// * `pub_key` - The other party's public key.
    ///
    /// # Returns
    /// `Ok(PublicKey)` representing the shared secret point, or an error if the
    /// public key is not on the curve.
    pub fn derive_shared_secret(
        &self,
        pub_key: &PublicKey,
    ) -> Result<PublicKey, PrimitivesError> {
        let their_point = pub_key.to_projective_point()?;
        let scalar = self.to_scalar();
        let shared_point = their_point * scalar;

        let affine = shared_point.to_affine();
        let encoded = affine.to_encoded_point(true);
        PublicKey::from_bytes(encoded.as_bytes())
    }

    /// Derive a child private key using BRC-42 key derivation.
    ///
    /// Computes an ECDH shared secret with the provided public key, then uses
    /// HMAC-SHA256 with the invoice number to derive a new private key scalar.
    ///
    /// See BRC-42 spec: <https://github.com/bitcoin-sv/BRCs/blob/master/key-derivation/0042.md>
    ///
    /// # Arguments
    /// * `pub_key` - The counterparty's public key.
    /// * `invoice_number` - The invoice number string used as HMAC data.
    ///
    /// # Returns
    /// `Ok(PrivateKey)` with the derived child key, or an error if derivation fails.
    pub fn derive_child(
        &self,
        pub_key: &PublicKey,
        invoice_number: &str,
    ) -> Result<PrivateKey, PrimitivesError> {
        let shared_secret = self.derive_shared_secret(pub_key)?;
        let shared_compressed = shared_secret.to_compressed();

        // Go: crypto.Sha256HMAC(invoiceNumberBin, sharedSecret.Compressed())
        // Go Sha256HMAC(data, key) => Rust sha256_hmac(key, data)
        let hmac_result = sha256_hmac(&shared_compressed, invoice_number.as_bytes());

        // Add HMAC result to current private key scalar, mod curve order
        let current_scalar = self.to_scalar();
        let hmac_scalar = scalar_from_bytes(&hmac_result)?;
        let new_scalar = current_scalar + hmac_scalar;

        // Convert back to bytes
        let scalar_primitive: ScalarPrimitive<Secp256k1> = new_scalar.into();
        let bytes = scalar_primitive.to_bytes();
        PrivateKey::from_bytes(&bytes)
    }

    /// Access the underlying k256 `SigningKey`.
    ///
    /// # Returns
    /// A reference to the inner `SigningKey`.
    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.inner
    }

    /// Convert the private key to a k256 `Scalar` for arithmetic operations.
    ///
    /// # Returns
    /// The scalar representation of this private key.
    pub(crate) fn to_scalar(&self) -> Scalar {
        *self.inner.as_nonzero_scalar().as_ref()
    }
}

impl Default for PrivateKey {
    fn default() -> Self {
        Self::new()
    }
}

// Note: k256 0.13's `SigningKey` implements `ZeroizeOnDrop`, so the inner
// scalar IS zeroized when this struct is dropped. No custom Drop needed.
// The previous custom Drop only zeroized a *copy* of the bytes, not the
// actual inner memory. Removing it lets k256's own ZeroizeOnDrop work correctly.

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for PrivateKey {}

/// Convert a 32-byte array to a k256 Scalar.
///
/// # Arguments
/// * `bytes` - A 32-byte big-endian representation of a scalar.
///
/// # Returns
/// `Ok(Scalar)` if the bytes represent a valid scalar, or an error otherwise.
fn scalar_from_bytes(bytes: &[u8; 32]) -> Result<Scalar, PrimitivesError> {
    use k256::elliptic_curve::ops::Reduce;
    let uint = k256::U256::from_be_slice(bytes);
    Ok(<Scalar as Reduce<k256::U256>>::reduce(uint))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test basic private key generation, serialization, and signing.
    #[test]
    fn test_priv_keys() {
        let key_bytes: [u8; 32] = [
            0xea, 0xf0, 0x2c, 0xa3, 0x48, 0xc5, 0x24, 0xe6, 0x39, 0x26, 0x55, 0xba, 0x4d, 0x29,
            0x60, 0x3c, 0xd1, 0xa7, 0x34, 0x7d, 0x9d, 0x65, 0xcf, 0xe9, 0x3c, 0xe1, 0xeb, 0xff,
            0xdc, 0xa2, 0x26, 0x94,
        ];

        let priv_key = PrivateKey::from_bytes(&key_bytes).unwrap();
        let pub_key = priv_key.pub_key();

        // Verify public key can be parsed from uncompressed bytes
        let uncompressed = pub_key.to_uncompressed();
        let _parsed = PublicKey::from_bytes(&uncompressed).unwrap();

        // Sign and verify
        let hash: [u8; 10] = [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9];
        let sig = priv_key.sign(&hash).unwrap();
        assert!(pub_key.verify(&hash, &sig));

        // Round-trip serialization
        let serialized = priv_key.to_bytes();
        assert_eq!(serialized, key_bytes);
    }

    /// Test private key serialization and deserialization via bytes, hex, and WIF.
    #[test]
    fn test_private_key_serialization_and_deserialization() {
        let pk = PrivateKey::new();

        // bytes round-trip
        let serialized = pk.to_bytes();
        let deserialized = PrivateKey::from_bytes(&serialized).unwrap();
        assert_eq!(pk, deserialized);

        // hex round-trip
        let hex_str = pk.to_hex();
        let deserialized = PrivateKey::from_hex(&hex_str).unwrap();
        assert_eq!(pk, deserialized);

        // WIF round-trip
        let wif = pk.to_wif();
        let deserialized = PrivateKey::from_wif(&wif).unwrap();
        assert_eq!(pk, deserialized);
    }

    /// Test that empty hex returns an error.
    #[test]
    fn test_private_key_from_invalid_hex() {
        assert!(PrivateKey::from_hex("").is_err());

        // WIF string is not valid hex
        let wif = "L4o1GXuUSHauk19f9Cfpm1qfSXZuGLBUAC2VZM6vdmfMxRxAYkWq";
        assert!(PrivateKey::from_hex(wif).is_err());
    }

    /// Test that malformed WIF strings are rejected.
    #[test]
    fn test_private_key_from_invalid_wif() {
        // modified character
        assert!(PrivateKey::from_wif("L401GXuUSHauk19f9Cfpm1qfSXZuGLBUAC2VZM6vdmfMxRxAYkWq").is_err());
        // truncated
        assert!(PrivateKey::from_wif("L4o1GXuUSHauk19f9Cfpm1qfSXZuGLBUAC2VZM6vdmfMxRxAYkW").is_err());
        // doubled
        assert!(PrivateKey::from_wif(
            "L4o1GXuUSHauk19f9Cfpm1qfSXZuGLBUAC2VZM6vdmfMxRxAYkWqL4o1GXuUSHauk19f9Cfpm1qfSXZuGLBUAC2VZM6vdmfMxRxAYkWq"
        ).is_err());
    }

    /// Test BRC-42 private key child derivation against Go SDK test vectors.
    #[test]
    fn test_brc42_private_vectors() {
        let vectors_json = include_str!("testdata/BRC42.private.vectors.json");
        let vectors: Vec<serde_json::Value> = serde_json::from_str(vectors_json).unwrap();

        for (i, v) in vectors.iter().enumerate() {
            let sender_pub_hex = v["senderPublicKey"].as_str().unwrap();
            let recipient_priv_hex = v["recipientPrivateKey"].as_str().unwrap();
            let invoice_number = v["invoiceNumber"].as_str().unwrap();
            let expected_priv_hex = v["privateKey"].as_str().unwrap();

            let public_key = PublicKey::from_hex(sender_pub_hex)
                .unwrap_or_else(|e| panic!("vector #{}: parse pub key: {}", i + 1, e));
            let private_key = PrivateKey::from_hex(recipient_priv_hex)
                .unwrap_or_else(|e| panic!("vector #{}: parse priv key: {}", i + 1, e));

            let derived = private_key
                .derive_child(&public_key, invoice_number)
                .unwrap_or_else(|e| panic!("vector #{}: derive child: {}", i + 1, e));

            let derived_hex = derived.to_hex();
            assert_eq!(
                derived_hex, expected_priv_hex,
                "BRC42 private vector #{}: derived key mismatch",
                i + 1
            );
        }
    }
}
