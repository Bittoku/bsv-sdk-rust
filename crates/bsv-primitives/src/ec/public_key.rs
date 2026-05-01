//! secp256k1 public key with Bitcoin-specific functionality.
//!
//! Supports compressed/uncompressed serialization, child key derivation (BRC-42),
//! address generation, DER encoding, and signature verification.

use k256::ecdsa::VerifyingKey;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, ProjectivePoint, Scalar};
use std::fmt;

use crate::ec::private_key::PrivateKey;
use crate::ec::signature::Signature;
use crate::hash::{hash160, sha256_hmac};
use crate::PrimitivesError;

/// Length of a compressed public key in bytes (prefix + 32 byte x-coordinate).
const COMPRESSED_LEN: usize = 33;

/// Length of an uncompressed public key in bytes (prefix + 32 byte x + 32 byte y).
const UNCOMPRESSED_LEN: usize = 65;

/// A secp256k1 public key for verification and encryption.
///
/// Wraps a k256 `VerifyingKey` and provides Bitcoin-specific functionality
/// including compressed/uncompressed serialization, address generation,
/// BRC-42 child derivation, and ECDSA verification.
#[derive(Clone, Debug)]
pub struct PublicKey {
    /// The underlying k256 verifying key.
    inner: VerifyingKey,
}

impl PublicKey {
    /// Create a PublicKey from raw SEC1 encoded bytes.
    ///
    /// Accepts both compressed (33-byte) and uncompressed (65-byte) formats.
    ///
    /// # Arguments
    /// * `bytes` - SEC1-encoded public key bytes.
    ///
    /// # Returns
    /// `Ok(PublicKey)` on success, or an error if the bytes don't represent a valid point.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PrimitivesError> {
        if bytes.is_empty() {
            return Err(PrimitivesError::InvalidPublicKey(
                "pubkey string is empty".to_string(),
            ));
        }
        let vk = VerifyingKey::from_sec1_bytes(bytes)?;
        Ok(PublicKey { inner: vk })
    }

    /// Create a PublicKey from a hex-encoded SEC1 string.
    ///
    /// # Arguments
    /// * `hex_str` - A hex string of a compressed (66 chars) or uncompressed (130 chars) key.
    ///
    /// # Returns
    /// `Ok(PublicKey)` on success, or an error if the hex or point is invalid.
    pub fn from_hex(hex_str: &str) -> Result<Self, PrimitivesError> {
        let bytes = hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }

    /// Serialize the public key in compressed SEC1 format (33 bytes).
    ///
    /// The first byte is 0x02 (even Y) or 0x03 (odd Y), followed by the 32-byte X coordinate.
    ///
    /// # Returns
    /// A 33-byte array containing the compressed public key.
    pub fn to_compressed(&self) -> [u8; COMPRESSED_LEN] {
        let point = self.inner.to_encoded_point(true);
        let mut out = [0u8; COMPRESSED_LEN];
        out.copy_from_slice(point.as_bytes());
        out
    }

    /// Serialize the public key in uncompressed SEC1 format (65 bytes).
    ///
    /// The first byte is 0x04, followed by 32-byte X and 32-byte Y coordinates.
    ///
    /// # Returns
    /// A 65-byte array containing the uncompressed public key.
    pub fn to_uncompressed(&self) -> [u8; UNCOMPRESSED_LEN] {
        let point = self.inner.to_encoded_point(false);
        let mut out = [0u8; UNCOMPRESSED_LEN];
        out.copy_from_slice(point.as_bytes());
        out
    }

    /// Serialize the public key as a lowercase hexadecimal string (compressed format).
    ///
    /// # Returns
    /// A 66-character hex string of the compressed public key.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_compressed())
    }

    /// Serialize the public key as DER-encoded bytes.
    ///
    /// For secp256k1, this is equivalent to the compressed SEC1 encoding.
    ///
    /// # Returns
    /// A byte vector containing the DER-encoded public key.
    pub fn to_der(&self) -> Vec<u8> {
        self.to_compressed().to_vec()
    }

    /// Serialize the public key as a DER hex string.
    ///
    /// # Returns
    /// A hex string of the DER-encoded (compressed) public key.
    pub fn to_der_hex(&self) -> String {
        hex::encode(self.to_der())
    }

    /// Compute the Hash160 of the compressed public key.
    ///
    /// Hash160 = RIPEMD160(SHA256(compressed_pubkey)).
    ///
    /// # Returns
    /// A 20-byte hash digest.
    pub fn hash160(&self) -> [u8; 20] {
        hash160(&self.to_compressed())
    }

    /// Derive a Bitcoin P2PKH address from the compressed public key.
    ///
    /// Computes Hash160 of the compressed key, prepends a version byte (0x00 for mainnet),
    /// and encodes with Base58Check.
    ///
    /// # Returns
    /// A Base58Check-encoded P2PKH address string.
    pub fn to_address(&self) -> String {
        let h = self.hash160();
        let mut payload = Vec::with_capacity(25);
        payload.push(0x00); // mainnet version byte
        payload.extend_from_slice(&h);
        let checksum = crate::hash::sha256d(&payload);
        payload.extend_from_slice(&checksum[..4]);
        bs58::encode(payload).into_string()
    }

    /// Verify an ECDSA signature against a message hash using this public key.
    ///
    /// # Arguments
    /// * `hash` - The message hash that was signed.
    /// * `sig` - The ECDSA signature to verify.
    ///
    /// # Returns
    /// `true` if the signature is valid for this hash and public key, `false` otherwise.
    pub fn verify(&self, hash: &[u8], sig: &Signature) -> bool {
        sig.verify(hash, self)
    }

    /// Derive a child public key using BRC-42 key derivation.
    ///
    /// Computes the ECDH shared secret between this public key and the given private key,
    /// then uses HMAC-SHA256 with the invoice number to derive a point offset and adds
    /// it to this public key.
    ///
    /// See BRC-42 spec: <https://github.com/bitcoin-sv/BRCs/blob/master/key-derivation/0042.md>
    ///
    /// # Arguments
    /// * `private_key` - The sender's private key.
    /// * `invoice_number` - The invoice number string used as HMAC data.
    ///
    /// # Returns
    /// `Ok(PublicKey)` with the derived child key, or an error if derivation fails.
    pub fn derive_child(
        &self,
        private_key: &PrivateKey,
        invoice_number: &str,
    ) -> Result<PublicKey, PrimitivesError> {
        // Shared secret: priv * pub
        let shared_secret = self.derive_shared_secret(private_key)?;
        let shared_compressed = shared_secret.to_compressed();

        // Go: crypto.Sha256HMAC(invoiceNumberBin, pubKeyEncoded)
        // Go Sha256HMAC(data, key) => Rust sha256_hmac(key, data)
        let hmac_result = sha256_hmac(&shared_compressed, invoice_number.as_bytes());

        // Compute new_point = G * hmac_scalar
        use k256::elliptic_curve::ops::Reduce;
        let uint = k256::U256::from_be_slice(&hmac_result);
        let hmac_scalar = <Scalar as Reduce<k256::U256>>::reduce(uint);
        let new_point = ProjectivePoint::GENERATOR * hmac_scalar;

        // Add to this public key: result = self + new_point
        let self_point = self.to_projective_point()?;
        let result_point = self_point + new_point;

        let affine = result_point.to_affine();
        let encoded = affine.to_encoded_point(true);
        PublicKey::from_bytes(encoded.as_bytes())
    }

    /// Compute the ECDH shared secret between this public key and a private key.
    ///
    /// # Arguments
    /// * `priv_key` - The private key to use for ECDH.
    ///
    /// # Returns
    /// `Ok(PublicKey)` representing the shared secret point, or an error.
    pub fn derive_shared_secret(
        &self,
        priv_key: &PrivateKey,
    ) -> Result<PublicKey, PrimitivesError> {
        priv_key.derive_shared_secret(self)
    }

    /// Construct a PublicKey from a k256 `VerifyingKey`.
    ///
    /// # Arguments
    /// * `vk` - A k256 VerifyingKey.
    ///
    /// # Returns
    /// A new `PublicKey` wrapping the verifying key.
    pub(crate) fn from_k256_verifying_key(vk: &VerifyingKey) -> Self {
        PublicKey { inner: *vk }
    }

    /// Convert this public key to a k256 `ProjectivePoint` for EC arithmetic.
    ///
    /// # Returns
    /// `Ok(ProjectivePoint)` or an error if the point cannot be decoded.
    pub(crate) fn to_projective_point(&self) -> Result<ProjectivePoint, PrimitivesError> {
        let encoded = self.inner.to_encoded_point(false);
        let ct_option = AffinePoint::from_encoded_point(&encoded);
        if bool::from(ct_option.is_some()) {
            Ok(ProjectivePoint::from(ct_option.unwrap()))
        } else {
            Err(PrimitivesError::PointNotOnCurve)
        }
    }

    /// Access the underlying k256 `VerifyingKey`.
    ///
    /// # Returns
    /// A reference to the inner `VerifyingKey`.
    pub(crate) fn verifying_key(&self) -> &VerifyingKey {
        &self.inner
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_compressed() == other.to_compressed()
    }
}

impl Eq for PublicKey {}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test parsing various valid and invalid public key formats.
    /// Test vectors ported from Go SDK publickey_test.go.
    #[test]
    fn test_pub_keys() {
        struct PubKeyTest {
            name: &'static str,
            key: Vec<u8>,
            is_valid: bool,
        }

        let tests = vec![
            PubKeyTest {
                name: "uncompressed ok",
                key: vec![
                    0x04, 0x11, 0xdb, 0x93, 0xe1, 0xdc, 0xdb, 0x8a, 0x01, 0x6b, 0x49, 0x84, 0x0f,
                    0x8c, 0x53, 0xbc, 0x1e, 0xb6, 0x8a, 0x38, 0x2e, 0x97, 0xb1, 0x48, 0x2e, 0xca,
                    0xd7, 0xb1, 0x48, 0xa6, 0x90, 0x9a, 0x5c, 0xb2, 0xe0, 0xea, 0xdd, 0xfb, 0x84,
                    0xcc, 0xf9, 0x74, 0x44, 0x64, 0xf8, 0x2e, 0x16, 0x0b, 0xfa, 0x9b, 0x8b, 0x64,
                    0xf9, 0xd4, 0xc0, 0x3f, 0x99, 0x9b, 0x86, 0x43, 0xf6, 0x56, 0xb4, 0x12, 0xa3,
                ],
                is_valid: true,
            },
            PubKeyTest {
                name: "uncompressed x changed",
                key: vec![
                    0x04, 0x15, 0xdb, 0x93, 0xe1, 0xdc, 0xdb, 0x8a, 0x01, 0x6b, 0x49, 0x84, 0x0f,
                    0x8c, 0x53, 0xbc, 0x1e, 0xb6, 0x8a, 0x38, 0x2e, 0x97, 0xb1, 0x48, 0x2e, 0xca,
                    0xd7, 0xb1, 0x48, 0xa6, 0x90, 0x9a, 0x5c, 0xb2, 0xe0, 0xea, 0xdd, 0xfb, 0x84,
                    0xcc, 0xf9, 0x74, 0x44, 0x64, 0xf8, 0x2e, 0x16, 0x0b, 0xfa, 0x9b, 0x8b, 0x64,
                    0xf9, 0xd4, 0xc0, 0x3f, 0x99, 0x9b, 0x86, 0x43, 0xf6, 0x56, 0xb4, 0x12, 0xa3,
                ],
                is_valid: false,
            },
            PubKeyTest {
                name: "compressed ok (ybit = 0)",
                key: vec![
                    0x02, 0xce, 0x0b, 0x14, 0xfb, 0x84, 0x2b, 0x1b, 0xa5, 0x49, 0xfd, 0xd6, 0x75,
                    0xc9, 0x80, 0x75, 0xf1, 0x2e, 0x9c, 0x51, 0x0f, 0x8e, 0xf5, 0x2b, 0xd0, 0x21,
                    0xa9, 0xa1, 0xf4, 0x80, 0x9d, 0x3b, 0x4d,
                ],
                is_valid: true,
            },
            PubKeyTest {
                name: "compressed ok (ybit = 1)",
                key: vec![
                    0x03, 0x26, 0x89, 0xc7, 0xc2, 0xda, 0xb1, 0x33, 0x09, 0xfb, 0x14, 0x3e, 0x0e,
                    0x8f, 0xe3, 0x96, 0x34, 0x25, 0x21, 0x88, 0x7e, 0x97, 0x66, 0x90, 0xb6, 0xb4,
                    0x7f, 0x5b, 0x2a, 0x4b, 0x7d, 0x44, 0x8e,
                ],
                is_valid: true,
            },
            PubKeyTest {
                name: "wrong length",
                key: vec![0x05],
                is_valid: false,
            },
        ];

        for test in &tests {
            let result = PublicKey::from_bytes(&test.key);
            if test.is_valid {
                assert!(
                    result.is_ok(),
                    "{} pubkey should be valid but got error: {:?}",
                    test.name,
                    result.err()
                );
            } else {
                assert!(
                    result.is_err(),
                    "{} pubkey should be invalid but was accepted",
                    test.name
                );
            }
        }
    }

    /// Test PublicKey equality comparison.
    #[test]
    fn test_public_key_is_equal() {
        let pk1 = PublicKey::from_bytes(&[
            0x03, 0x26, 0x89, 0xc7, 0xc2, 0xda, 0xb1, 0x33, 0x09, 0xfb, 0x14, 0x3e, 0x0e, 0x8f,
            0xe3, 0x96, 0x34, 0x25, 0x21, 0x88, 0x7e, 0x97, 0x66, 0x90, 0xb6, 0xb4, 0x7f, 0x5b,
            0x2a, 0x4b, 0x7d, 0x44, 0x8e,
        ])
        .unwrap();

        let pk2 = PublicKey::from_bytes(&[
            0x02, 0xce, 0x0b, 0x14, 0xfb, 0x84, 0x2b, 0x1b, 0xa5, 0x49, 0xfd, 0xd6, 0x75, 0xc9,
            0x80, 0x75, 0xf1, 0x2e, 0x9c, 0x51, 0x0f, 0x8e, 0xf5, 0x2b, 0xd0, 0x21, 0xa9, 0xa1,
            0xf4, 0x80, 0x9d, 0x3b, 0x4d,
        ])
        .unwrap();

        assert_eq!(pk1, pk1);
        assert_ne!(pk1, pk2);
    }

    /// Test that compressed serialization round-trips correctly.
    #[test]
    fn test_compressed_round_trip() {
        let original_bytes: [u8; 33] = [
            0x02, 0xce, 0x0b, 0x14, 0xfb, 0x84, 0x2b, 0x1b, 0xa5, 0x49, 0xfd, 0xd6, 0x75, 0xc9,
            0x80, 0x75, 0xf1, 0x2e, 0x9c, 0x51, 0x0f, 0x8e, 0xf5, 0x2b, 0xd0, 0x21, 0xa9, 0xa1,
            0xf4, 0x80, 0x9d, 0x3b, 0x4d,
        ];

        let pk = PublicKey::from_bytes(&original_bytes).unwrap();
        let compressed = pk.to_compressed();
        assert_eq!(compressed, original_bytes);
    }

    /// Test Display trait outputs compressed hex.
    #[test]
    fn test_display() {
        let pk = PublicKey::from_bytes(&[
            0x02, 0xce, 0x0b, 0x14, 0xfb, 0x84, 0x2b, 0x1b, 0xa5, 0x49, 0xfd, 0xd6, 0x75, 0xc9,
            0x80, 0x75, 0xf1, 0x2e, 0x9c, 0x51, 0x0f, 0x8e, 0xf5, 0x2b, 0xd0, 0x21, 0xa9, 0xa1,
            0xf4, 0x80, 0x9d, 0x3b, 0x4d,
        ])
        .unwrap();

        assert_eq!(
            format!("{}", pk),
            "02ce0b14fb842b1ba549fdd675c98075f12e9c510f8ef52bd021a9a1f4809d3b4d"
        );
    }

    /// Test DER hex output matches compressed hex.
    #[test]
    fn test_to_der_hex() {
        let pk = PublicKey::from_bytes(&[
            0x02, 0xce, 0x0b, 0x14, 0xfb, 0x84, 0x2b, 0x1b, 0xa5, 0x49, 0xfd, 0xd6, 0x75, 0xc9,
            0x80, 0x75, 0xf1, 0x2e, 0x9c, 0x51, 0x0f, 0x8e, 0xf5, 0x2b, 0xd0, 0x21, 0xa9, 0xa1,
            0xf4, 0x80, 0x9d, 0x3b, 0x4d,
        ])
        .unwrap();

        assert_eq!(pk.to_der_hex(), pk.to_hex());
    }

    /// Test BRC-42 public key child derivation against Go SDK test vectors.
    #[test]
    fn test_brc42_public_vectors() {
        let vectors_json = include_str!("testdata/BRC42.public.vectors.json");
        let vectors: Vec<serde_json::Value> = serde_json::from_str(vectors_json).unwrap();

        for (i, v) in vectors.iter().enumerate() {
            let sender_priv_hex = v["senderPrivateKey"].as_str().unwrap();
            let recipient_pub_hex = v["recipientPublicKey"].as_str().unwrap();
            let invoice_number = v["invoiceNumber"].as_str().unwrap();
            let expected_pub_hex = v["publicKey"].as_str().unwrap();

            let private_key = PrivateKey::from_hex(sender_priv_hex)
                .unwrap_or_else(|e| panic!("vector #{}: parse priv key: {}", i + 1, e));
            let public_key = PublicKey::from_hex(recipient_pub_hex)
                .unwrap_or_else(|e| panic!("vector #{}: parse pub key: {}", i + 1, e));

            let derived = public_key
                .derive_child(&private_key, invoice_number)
                .unwrap_or_else(|e| panic!("vector #{}: derive child: {}", i + 1, e));

            let derived_hex = derived.to_hex();
            assert_eq!(
                derived_hex,
                expected_pub_hex,
                "BRC42 public vector #{}: derived key mismatch",
                i + 1
            );
        }
    }
}
