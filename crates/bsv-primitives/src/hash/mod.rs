//! Hash function primitives for the BSV SDK.
//!
//! Provides SHA-256, double SHA-256, RIPEMD-160, SHA-512, Hash160,
//! and HMAC variants used throughout the Bitcoin SV protocol.
//! These hash functions follow the conventions established by the
//! Go BSV SDK (`go-sdk/primitives/hash`).

use hmac::{Hmac, Mac};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};

/// Compute SHA-256 hash of the input data.
///
/// # Arguments
/// * `data` - Byte slice to hash.
///
/// # Returns
/// A 32-byte SHA-256 digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute double SHA-256 (SHA-256d) hash of the input data.
///
/// This is the standard Bitcoin hash function used for transaction IDs
/// and block hashes. Computes SHA-256(SHA-256(data)).
///
/// # Arguments
/// * `data` - Byte slice to hash.
///
/// # Returns
/// A 32-byte double-SHA-256 digest.
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// Compute RIPEMD-160 hash of the input data.
///
/// # Arguments
/// * `data` - Byte slice to hash.
///
/// # Returns
/// A 20-byte RIPEMD-160 digest.
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 20];
    output.copy_from_slice(&result);
    output
}

/// Compute Hash160: RIPEMD-160(SHA-256(data)).
///
/// Used for Bitcoin address generation from public keys.
///
/// # Arguments
/// * `data` - Byte slice to hash.
///
/// # Returns
/// A 20-byte Hash160 digest.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(data))
}

/// Compute SHA-512 hash of the input data.
///
/// # Arguments
/// * `data` - Byte slice to hash.
///
/// # Returns
/// A 64-byte SHA-512 digest.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(&result);
    output
}

/// Compute HMAC-SHA256 of the input data with the given key.
///
/// # Arguments
/// * `key` - The HMAC key bytes.
/// * `data` - The message bytes to authenticate.
///
/// # Returns
/// A 32-byte HMAC-SHA256 tag.
pub fn sha256_hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let result = mac.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result.into_bytes());
    output
}

/// Compute HMAC-SHA512 of the input data with the given key.
///
/// # Arguments
/// * `key` - The HMAC key bytes.
/// * `data` - The message bytes to authenticate.
///
/// # Returns
/// A 64-byte HMAC-SHA512 tag.
pub fn sha512_hmac(key: &[u8], data: &[u8]) -> [u8; 64] {
    type HmacSha512 = Hmac<Sha512>;
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let result = mac.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(&result.into_bytes());
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test data constants matching the Go SDK (hash_test.go).
    const TEST_DATA: &[u8] = b"I am a test";
    const TEST_DATA_2: &[u8] = b"this is the data I want to hash";

    // ---- RIPEMD-160 ----

    #[test]
    fn test_ripemd160_empty_string() {
        let hash = ripemd160(b"");
        assert_eq!(
            hex::encode(hash),
            "9c1185a5c5e9fc54612808977ee8f548b2258d31"
        );
    }

    #[test]
    fn test_ripemd160_string() {
        let hash = ripemd160(TEST_DATA);
        assert_eq!(
            hex::encode(hash),
            "09a23f506b4a37cabab8a9e49b541de582fca96b"
        );
    }

    // ---- SHA-256d (double SHA-256) ----

    #[test]
    fn test_sha256d_empty_string() {
        let hash = sha256d(b"");
        assert_eq!(
            hex::encode(hash),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
    }

    #[test]
    fn test_sha256d_string() {
        let hash = sha256d(TEST_DATA_2);
        assert_eq!(
            hex::encode(hash),
            "2209ddda5914a3fbad507ff2284c4b6e559c18a669f9fc3ad3b5826a2a999d58"
        );
    }

    // ---- SHA-256 ----

    #[test]
    fn test_sha256_empty_string() {
        let hash = sha256(b"");
        assert_eq!(
            hex::encode(hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_string() {
        let hash = sha256(TEST_DATA_2);
        assert_eq!(
            hex::encode(hash),
            "f88eec7ecabf88f9a64c4100cac1e0c0c4581100492137d1b656ea626cad63e3"
        );
    }

    // ---- Hash160 ----

    #[test]
    fn test_hash160_empty_string() {
        let hash = hash160(b"");
        assert_eq!(
            hex::encode(hash),
            "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"
        );
    }

    #[test]
    fn test_hash160_string() {
        let hash = hash160(TEST_DATA_2);
        assert_eq!(
            hex::encode(hash),
            "e7fb13ef86fef4203f042fbfc2703fa628301e90"
        );
    }

    // ---- SHA-512 ----

    #[test]
    fn test_sha512_empty_string() {
        let hash = sha512(b"");
        assert_eq!(
            hex::encode(hash),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn test_sha512_string() {
        let hash = sha512(TEST_DATA_2);
        assert_eq!(
            hex::encode(hash),
            "fe917669df24482f19e9fdd305a846ab5778708d75e05bef0eb9b349c22c21c0\
             168892058b26fe9ae0e3488f6b05b5cc6b356f4dd6093cdf9329ed800de3a165"
        );
    }

    // ---- HMAC-SHA256 ----
    // Note: Go SDK calls Sha256HMAC(msg, key) — message first, key second.
    // Our Rust signature is sha256_hmac(key, data).

    #[test]
    fn test_sha256_hmac_nist_1() {
        let key = hex::decode(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F\
             202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        )
        .unwrap();
        let msg = b"Sample message for keylen=blocklen";
        let mac = sha256_hmac(&key, msg);
        assert_eq!(
            hex::encode(mac),
            "8bb9a1db9806f20df7f77b82138c7914d174d59e13dc4d0169c9057b133e1d62"
        );
    }

    #[test]
    fn test_sha256_hmac_nist_2() {
        let key = hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
            .unwrap();
        let msg = b"Sample message for keylen<blocklen";
        let mac = sha256_hmac(&key, msg);
        assert_eq!(
            hex::encode(mac),
            "a28cf43130ee696a98f14a37678b56bcfcbdd9e5cf69717fecf5480f0ebdf790"
        );
    }

    // ---- HMAC-SHA512 ----
    // Note: Go SDK calls Sha512HMAC(msg, key) with both msg and key as hex-decoded bytes.

    #[test]
    fn test_sha512_hmac_case_1() {
        let key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let msg = hex::decode("4869205468657265").unwrap(); // "Hi There"
        let mac = sha512_hmac(&key, &msg);
        assert_eq!(
            hex::encode(mac),
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
             daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        );
    }

    #[test]
    fn test_sha512_hmac_case_2() {
        let key = hex::decode("4a656665").unwrap(); // "Jefe"
        let msg = hex::decode("7768617420646f2079612077616e7420666f72206e6f7468696e673f").unwrap();
        let mac = sha512_hmac(&key, &msg);
        assert_eq!(
            hex::encode(mac),
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
             9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        );
    }
}
