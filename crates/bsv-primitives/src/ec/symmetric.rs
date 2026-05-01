//! Symmetric key encryption using ECDH shared secrets and AES-GCM.
//!
//! Derives a shared symmetric key from two EC key pairs and provides
//! authenticated encryption/decryption. Uses AES-256-GCM with a 32-byte
//! initialization vector.

use aes::Aes256;
use aes_gcm::aead::generic_array::typenum::U32;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::AesGcm;
use aes_gcm::{AeadInPlace, KeyInit};
use rand::RngCore;

use crate::PrimitivesError;

/// IV (initialization vector) length used by the Go SDK (32 bytes).
const IV_LEN: usize = 32;

/// AES-GCM authentication tag length (16 bytes).
const TAG_LEN: usize = 16;

/// A symmetric encryption key derived from ECDH.
///
/// Provides AES-256-GCM authenticated encryption and decryption using a
/// 32-byte key. The encryption format is: IV (32 bytes) || ciphertext || tag (16 bytes).
///
/// The key material is automatically zeroized when this value is dropped.
pub struct SymmetricKey {
    /// The 32-byte AES key (zeroized on drop).
    key: zeroize::Zeroizing<[u8; 32]>,
}

impl SymmetricKey {
    /// Create a SymmetricKey from a byte slice.
    ///
    /// If the input is shorter than 32 bytes, it is left-padded with zeros.
    /// If the input is 32 bytes or longer, the first 32 bytes are used.
    ///
    /// # Arguments
    /// * `key` - The key bytes (ideally 32 bytes).
    ///
    /// # Returns
    /// A new `SymmetricKey`.
    pub fn new(key: &[u8]) -> Self {
        let mut padded = [0u8; 32];
        if key.len() < 32 {
            // Left-pad with zeros (matches Go SDK behavior)
            padded[32 - key.len()..].copy_from_slice(key);
        } else {
            padded.copy_from_slice(&key[..32]);
        }
        SymmetricKey {
            key: zeroize::Zeroizing::new(padded),
        }
    }

    /// Generate a random 32-byte symmetric key.
    ///
    /// # Returns
    /// A new `SymmetricKey` with cryptographically random bytes.
    pub fn new_random() -> Self {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        SymmetricKey {
            key: zeroize::Zeroizing::new(key),
        }
    }

    /// Create a SymmetricKey from a Base64-encoded string.
    ///
    /// # Arguments
    /// * `b64` - A Base64 (standard encoding) string of the key bytes.
    ///
    /// # Returns
    /// `Ok(SymmetricKey)` on success, or an error if the Base64 is invalid.
    pub fn from_base64(b64: &str) -> Result<Self, PrimitivesError> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| PrimitivesError::Other(e.to_string()))?;
        Ok(Self::new(&bytes))
    }

    /// Encrypt a plaintext message using AES-256-GCM.
    ///
    /// The output format is: IV (32 bytes) || ciphertext || tag (16 bytes),
    /// matching the Go SDK's symmetric encryption format.
    ///
    /// # Arguments
    /// * `plaintext` - The data to encrypt.
    ///
    /// # Returns
    /// `Ok(Vec<u8>)` containing the encrypted data, or an error if encryption fails.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, PrimitivesError> {
        // Generate 32-byte IV (Go SDK uses 32-byte IV)
        let mut iv = [0u8; IV_LEN];
        rand::rngs::OsRng.fill_bytes(&mut iv);

        self.encrypt_with_iv(plaintext, &iv)
    }

    /// Encrypt a plaintext message using AES-256-GCM with a specified IV.
    ///
    /// The Go SDK uses a 32-byte IV with a custom GCM implementation.
    /// We use `AesGcm<Aes256, U32>` to support the full 32-byte nonce.
    fn encrypt_with_iv(
        &self,
        plaintext: &[u8],
        iv: &[u8; IV_LEN],
    ) -> Result<Vec<u8>, PrimitivesError> {
        let cipher = AesGcm::<Aes256, U32>::new(GenericArray::from_slice(self.key.as_ref()));
        let nonce = GenericArray::from_slice(iv);

        let mut buffer = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(nonce, &[], &mut buffer)
            .map_err(|_| PrimitivesError::Aead)?;

        // Output: IV || ciphertext || tag
        let mut result = Vec::with_capacity(IV_LEN + buffer.len() + TAG_LEN);
        result.extend_from_slice(iv);
        result.extend_from_slice(&buffer);
        result.extend_from_slice(&tag);
        Ok(result)
    }

    /// Decrypt a ciphertext message using AES-256-GCM.
    ///
    /// Expected input format: IV (32 bytes) || ciphertext || tag (16 bytes).
    ///
    /// # Arguments
    /// * `message` - The encrypted data (IV + ciphertext + tag).
    ///
    /// # Returns
    /// `Ok(Vec<u8>)` containing the decrypted plaintext, or an error if decryption fails.
    pub fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>, PrimitivesError> {
        if message.len() < IV_LEN + TAG_LEN {
            return Err(PrimitivesError::DecryptionError(
                "message is too short to be a valid encrypted message".to_string(),
            ));
        }

        let iv = &message[..IV_LEN];
        let ciphertext = &message[IV_LEN..message.len() - TAG_LEN];
        let tag = &message[message.len() - TAG_LEN..];

        let cipher = AesGcm::<Aes256, U32>::new(GenericArray::from_slice(self.key.as_ref()));
        let nonce = GenericArray::from_slice(iv);
        let tag = GenericArray::from_slice(tag);

        let mut buffer = ciphertext.to_vec();
        cipher
            .decrypt_in_place_detached(nonce, &[], &mut buffer, tag)
            .map_err(|_| PrimitivesError::Aead)?;

        Ok(buffer)
    }

    /// Encrypt a string message.
    ///
    /// Convenience wrapper around `encrypt` for string data.
    ///
    /// # Arguments
    /// * `message` - The string to encrypt.
    ///
    /// # Returns
    /// `Ok(Vec<u8>)` containing the encrypted bytes.
    pub fn encrypt_string(&self, message: &str) -> Result<Vec<u8>, PrimitivesError> {
        self.encrypt(message.as_bytes())
    }

    /// Decrypt a message and return it as a string.
    ///
    /// Convenience wrapper around `decrypt` for string data.
    ///
    /// # Arguments
    /// * `message` - The encrypted data.
    ///
    /// # Returns
    /// `Ok(String)` containing the decrypted string.
    pub fn decrypt_string(&self, message: &[u8]) -> Result<String, PrimitivesError> {
        let plaintext = self.decrypt(message)?;
        String::from_utf8(plaintext).map_err(|e| PrimitivesError::DecryptionError(e.to_string()))
    }

    /// Get the raw key bytes.
    ///
    /// # Returns
    /// A reference to the 32-byte key.
    pub fn to_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test basic encryption and decryption round-trip.
    #[test]
    fn test_symmetric_key_encryption_and_decryption() {
        let key = SymmetricKey::new_random();
        let plaintext = b"a thing to encrypt";

        let ciphertext = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    /// Test decryption of Go SDK test vectors.
    #[test]
    fn test_symmetric_key_decryption_vectors() {
        let vectors_json = include_str!("testdata/SymmetricKey.vectors.json");
        let vectors: Vec<serde_json::Value> = serde_json::from_str(vectors_json).unwrap();

        for (i, v) in vectors.iter().enumerate() {
            let key_b64 = v["key"].as_str().unwrap();
            let ciphertext_b64 = v["ciphertext"].as_str().unwrap();
            let expected_plaintext = v["plaintext"].as_str().unwrap();

            use base64::Engine;
            let ciphertext = base64::engine::general_purpose::STANDARD
                .decode(ciphertext_b64)
                .unwrap();

            let sym_key = SymmetricKey::from_base64(key_b64).unwrap();
            let decrypted = sym_key.decrypt(&ciphertext).unwrap_or_else(|e| {
                panic!("vector #{}: decryption failed: {}", i + 1, e);
            });

            assert_eq!(
                String::from_utf8_lossy(&decrypted),
                expected_plaintext,
                "vector #{}: plaintext mismatch",
                i + 1
            );
        }
    }

    /// Test encryption with a 31-byte key (left-padded to 32).
    #[test]
    fn test_symmetric_key_with_short_key() {
        let short_key = vec![0xABu8; 31];
        let sym_key = SymmetricKey::new(&short_key);
        let plaintext = b"test message";

        let ciphertext = sym_key.encrypt(plaintext).unwrap();
        let decrypted = sym_key.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// Test that decrypting a too-short message returns an error.
    #[test]
    fn test_symmetric_key_decrypt_too_short() {
        let key = SymmetricKey::new_random();
        let short_msg = vec![0u8; 10];
        assert!(key.decrypt(&short_msg).is_err());
    }
}
