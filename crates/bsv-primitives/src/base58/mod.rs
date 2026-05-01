//! Base58 encoding and decoding with optional checksum support.
//!
//! Provides raw Base58 encode/decode (matching the Go BSV SDK's
//! `compat/base58` package) and Base58Check encode/decode (with
//! double-SHA-256 checksum) used for WIF private keys and Bitcoin
//! addresses.

use crate::hash::sha256d;
use crate::PrimitivesError;

/// Bitcoin's modified Base58 alphabet.
///
/// Excludes 0, O, I, l to reduce visual ambiguity.
const _ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode a byte slice to a Base58 string.
///
/// Uses Bitcoin's modified Base58 alphabet. Leading zero bytes
/// are encoded as leading '1' characters.
///
/// # Arguments
/// * `data` - The bytes to encode.
///
/// # Returns
/// A Base58-encoded string.
pub fn encode(data: &[u8]) -> String {
    bs58::encode(data)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_string()
}

/// Decode a Base58 string to a byte vector.
///
/// Leading '1' characters decode to leading zero bytes.
///
/// # Arguments
/// * `s` - The Base58 string to decode.
///
/// # Returns
/// `Ok(Vec<u8>)` on success, or an error for invalid characters.
pub fn decode(s: &str) -> Result<Vec<u8>, PrimitivesError> {
    bs58::decode(s)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_vec()
        .map_err(|e| PrimitivesError::InvalidBase58(e.to_string()))
}

/// Encode a byte slice with a 4-byte double-SHA-256 checksum appended (Base58Check).
///
/// The checksum is the first 4 bytes of SHA-256d(data). The result
/// is `encode(data || checksum)`.
///
/// # Arguments
/// * `data` - The bytes to encode (typically version byte + payload).
///
/// # Returns
/// A Base58Check-encoded string.
pub fn check_encode(data: &[u8]) -> String {
    let checksum = sha256d(data);
    let mut payload = data.to_vec();
    payload.extend_from_slice(&checksum[..4]);
    encode(&payload)
}

/// Decode a Base58Check string, verifying the 4-byte checksum.
///
/// Strips and validates the trailing 4-byte double-SHA-256 checksum.
///
/// # Arguments
/// * `s` - The Base58Check string to decode.
///
/// # Returns
/// `Ok(Vec<u8>)` of the payload (without checksum) on success, or an
/// error for invalid encoding or checksum mismatch.
pub fn check_decode(s: &str) -> Result<Vec<u8>, PrimitivesError> {
    let decoded = decode(s)?;
    if decoded.len() < 4 {
        return Err(PrimitivesError::InvalidBase58(
            "data too short for checksum".to_string(),
        ));
    }
    let (payload, checksum) = decoded.split_at(decoded.len() - 4);
    let expected = sha256d(payload);
    if checksum != &expected[..4] {
        return Err(PrimitivesError::ChecksumMismatch);
    }
    Ok(payload.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Tests from Go SDK base58_test.go TestBase58 --

    #[test]
    fn test_base58_empty_string() {
        let input = hex::decode("").unwrap();
        assert_eq!(encode(&input), "");
        let decoded = decode("").unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_base58_single_zero_byte() {
        let input = hex::decode("00").unwrap();
        assert_eq!(encode(&input), "1");
        let decoded = decode("1").unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_base58_decoded_address() {
        let input = hex::decode("00010966776006953D5567439E5E39F86A0D273BEED61967F6").unwrap();
        let encoded = encode(&input);
        assert_eq!(encoded, "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM");
        let decoded = decode("16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM").unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_base58_decoded_hash() {
        let input = hex::decode("0123456789ABCDEF").unwrap();
        let encoded = encode(&input);
        assert_eq!(encoded, "C3CPq7c8PY");
        let decoded = decode("C3CPq7c8PY").unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_base58_leading_zeros() {
        let input = hex::decode("000000287FB4CD").unwrap();
        let encoded = encode(&input);
        assert_eq!(encoded, "111233QC4");
        let decoded = decode("111233QC4").unwrap();
        assert_eq!(decoded, input);
    }

    // -- Tests from Go SDK base58_test.go TestBase58DecodeInvalid --

    #[test]
    fn test_base58_decode_invalid_character() {
        assert!(decode("invalid!@#$%").is_err());
    }

    #[test]
    fn test_base58_decode_mixed_valid_invalid() {
        assert!(decode("1234!@#$%").is_err());
    }

    // -- Tests from Go SDK base58_test.go TestBase58EncodeEdgeCases --

    #[test]
    fn test_base58_encode_nil_input() {
        assert_eq!(encode(&[]), "");
    }

    #[test]
    fn test_base58_encode_all_zeros() {
        assert_eq!(encode(&[0, 0, 0, 0]), "1111");
    }

    #[test]
    fn test_base58_encode_large_number() {
        assert_eq!(encode(&[255, 255, 255, 255]), "7YXq9G");
    }

    // -- Base58Check tests --

    #[test]
    fn test_base58_check_roundtrip() {
        let payload = hex::decode("00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31").unwrap();
        let encoded = check_encode(&payload);
        let decoded = check_decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_base58_check_bad_checksum() {
        // Encode then tamper with the last character.
        let payload = vec![0x80, 0x01, 0x02, 0x03];
        let mut encoded = check_encode(&payload);
        let last = encoded.pop().unwrap();
        let replacement = if last == '1' { '2' } else { '1' };
        encoded.push(replacement);
        assert!(check_decode(&encoded).is_err());
    }
}
