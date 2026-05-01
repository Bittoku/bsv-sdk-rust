//! ECDSA signature with DER serialization and RFC6979 deterministic nonces.
//!
//! Supports DER encoding/decoding, compact (recoverable) signatures,
//! low-S normalization, and signature verification.

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{self, RecoveryId, VerifyingKey};

use crate::ec::private_key::PrivateKey;
use crate::ec::public_key::PublicKey;
use crate::PrimitivesError;

/// The secp256k1 curve order N.
/// N = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
const CURVE_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// Half of the secp256k1 curve order (N/2), used for low-S normalization.
const HALF_ORDER: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];

/// An ECDSA signature with R and S components.
///
/// Provides DER and compact serialization, RFC6979 deterministic signing,
/// low-S normalization per BIP-0062, and public key recovery.
#[derive(Clone, Debug)]
pub struct Signature {
    /// The R component of the signature (32 bytes, big-endian).
    r: [u8; 32],
    /// The S component of the signature (32 bytes, big-endian).
    s: [u8; 32],
}

impl Signature {
    /// Create a signature from raw R and S 32-byte arrays.
    ///
    /// # Arguments
    /// * `r` - The R component (32 bytes, big-endian).
    /// * `s` - The S component (32 bytes, big-endian).
    ///
    /// # Returns
    /// A new `Signature` with the given R and S values.
    pub fn new(r: [u8; 32], s: [u8; 32]) -> Self {
        Signature { r, s }
    }

    /// Access the R component of the signature.
    ///
    /// # Returns
    /// A reference to the 32-byte R value.
    pub fn r(&self) -> &[u8; 32] {
        &self.r
    }

    /// Access the S component of the signature.
    ///
    /// # Returns
    /// A reference to the 32-byte S value.
    pub fn s(&self) -> &[u8; 32] {
        &self.s
    }

    /// Parse a DER-encoded ECDSA signature.
    ///
    /// Expected format: `0x30 <len> 0x02 <r_len> <r> 0x02 <s_len> <s>`
    ///
    /// # Arguments
    /// * `bytes` - DER-encoded signature bytes.
    ///
    /// # Returns
    /// `Ok(Signature)` on success, or an error if the DER encoding is malformed.
    pub fn from_der(bytes: &[u8]) -> Result<Self, PrimitivesError> {
        if bytes.len() < 8 {
            return Err(PrimitivesError::InvalidSignature(
                "malformed signature: too short".to_string(),
            ));
        }

        if bytes[0] != 0x30 {
            return Err(PrimitivesError::InvalidSignature(
                "malformed signature: no header magic".to_string(),
            ));
        }

        let sig_len = bytes[1] as usize;
        if sig_len + 2 > bytes.len() || sig_len + 2 < 8 {
            return Err(PrimitivesError::InvalidSignature(
                "malformed signature: bad length".to_string(),
            ));
        }

        let data = &bytes[..sig_len + 2];
        let mut idx = 2;

        // Parse R
        if data[idx] != 0x02 {
            return Err(PrimitivesError::InvalidSignature(
                "malformed signature: no 1st int marker".to_string(),
            ));
        }
        idx += 1;
        let r_len = data[idx] as usize;
        idx += 1;
        if r_len == 0 || idx + r_len > data.len() - 3 {
            return Err(PrimitivesError::InvalidSignature(
                "malformed signature: bogus R length".to_string(),
            ));
        }
        let r_bytes = &data[idx..idx + r_len];
        idx += r_len;

        // Parse S
        if data[idx] != 0x02 {
            return Err(PrimitivesError::InvalidSignature(
                "malformed signature: no 2nd int marker".to_string(),
            ));
        }
        idx += 1;
        let s_len = data[idx] as usize;
        idx += 1;
        if s_len == 0 || idx + s_len > data.len() {
            return Err(PrimitivesError::InvalidSignature(
                "malformed signature: bogus S length".to_string(),
            ));
        }
        let s_bytes = &data[idx..idx + s_len];

        // Convert R bytes to fixed 32-byte array (strip leading zeros, left-pad)
        let r = to_32_bytes(r_bytes)?;
        let s = to_32_bytes(s_bytes)?;

        // Validate R and S are non-zero and < curve order
        if is_zero(&r) {
            return Err(PrimitivesError::InvalidSignature(
                "signature R is zero".to_string(),
            ));
        }
        if is_zero(&s) {
            return Err(PrimitivesError::InvalidSignature(
                "signature S is zero".to_string(),
            ));
        }
        if !is_less_than(&r, &CURVE_ORDER) {
            return Err(PrimitivesError::InvalidSignature(
                "signature R is >= curve.N".to_string(),
            ));
        }
        if !is_less_than(&s, &CURVE_ORDER) {
            return Err(PrimitivesError::InvalidSignature(
                "signature S is >= curve.N".to_string(),
            ));
        }

        Ok(Signature { r, s })
    }

    /// Serialize the signature in DER format with low-S normalization.
    ///
    /// Output format: `0x30 <len> 0x02 <r_len> <r_bytes> 0x02 <s_len> <s_bytes>`
    /// The S value is normalized to the lower half of the curve order per BIP-0062.
    ///
    /// # Returns
    /// A byte vector containing the DER-encoded signature.
    pub fn to_der(&self) -> Vec<u8> {
        // Low-S normalization: if S > halfOrder, replace S with N - S
        let s = if is_greater_than(&self.s, &HALF_ORDER) {
            subtract_from_order(&self.s)
        } else {
            self.s
        };

        let rb = canonicalize_int(&self.r);
        let sb = canonicalize_int(&s);

        let total_len = 6 + rb.len() + sb.len();
        let mut out = Vec::with_capacity(total_len);
        out.push(0x30);
        out.push((total_len - 2) as u8);
        out.push(0x02);
        out.push(rb.len() as u8);
        out.extend_from_slice(&rb);
        out.push(0x02);
        out.push(sb.len() as u8);
        out.extend_from_slice(&sb);
        out
    }

    /// Parse a 65-byte compact (recoverable) signature.
    ///
    /// Format: <recovery_id_byte> <32-byte R> <32-byte S>
    /// The recovery ID byte encodes: 27 + iteration + 4 (if compressed).
    ///
    /// # Arguments
    /// * `bytes` - 65-byte compact signature.
    ///
    /// # Returns
    /// `Ok(Signature)` on success, or an error if the format is invalid.
    pub fn from_compact(bytes: &[u8]) -> Result<Self, PrimitivesError> {
        if bytes.len() != 65 {
            return Err(PrimitivesError::InvalidSignature(
                "invalid compact signature size".to_string(),
            ));
        }
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[1..33]);
        s.copy_from_slice(&bytes[33..65]);
        Ok(Signature { r, s })
    }

    /// Serialize the signature in 65-byte compact format with recovery ID.
    ///
    /// Format: <recovery_id_byte> <32-byte R> <32-byte S>
    ///
    /// This method re-signs the hash to find the correct recovery ID by
    /// trial recovery of the public key.
    ///
    /// # Arguments
    /// * `hash` - The original message hash that was signed.
    /// * `priv_key` - The private key used to sign.
    ///
    /// # Returns
    /// A 65-byte vector containing the compact signature with recovery ID.
    pub fn to_compact(&self, hash: &[u8], priv_key: &PrivateKey) -> Vec<u8> {
        // Use k256's recoverable signing to get the recovery ID
        let signing_key = priv_key.signing_key();
        if let Ok((k256_sig, recovery_id)) = signing_key.sign_prehash_recoverable(hash) {
            let mut result = vec![0u8; 65];
            let recid_byte = 27 + recovery_id.to_byte() + 4; // +4 for compressed
            result[0] = recid_byte;
            let (r_bytes, s_bytes) = k256_sig.split_bytes();
            result[1..33].copy_from_slice(&r_bytes);
            result[33..65].copy_from_slice(&s_bytes);
            return result;
        }

        // Fallback: use our own R/S
        let mut result = vec![0u8; 65];
        result[0] = 27 + 4; // compressed, recovery ID 0
        result[1..33].copy_from_slice(&self.r);
        result[33..65].copy_from_slice(&self.s);
        result
    }

    /// Sign a message hash using RFC6979 deterministic nonces.
    ///
    /// Normalize an arbitrary-length hash to exactly 32 bytes for secp256k1 ECDSA.
    ///
    /// Pads shorter hashes with leading zeros, truncates longer hashes.
    /// This matches Go's ecdsa behavior which accepts arbitrary-length data.
    fn normalize_hash(hash: &[u8]) -> [u8; 32] {
        let mut padded = [0u8; 32];
        if hash.len() >= 32 {
            padded.copy_from_slice(&hash[..32]);
        } else {
            padded[32 - hash.len()..].copy_from_slice(hash);
        }
        padded
    }

    /// Produces a low-S normalized signature per BIP-0062.
    ///
    /// # Arguments
    /// * `hash` - The message hash to sign (should be 32 bytes).
    /// * `priv_key` - The private key to sign with.
    ///
    /// # Returns
    /// `Ok(Signature)` on success, or an error if signing fails.
    pub fn sign(hash: &[u8], priv_key: &PrivateKey) -> Result<Self, PrimitivesError> {
        let signing_key = priv_key.signing_key();

        // Pad or truncate hash to 32 bytes to match secp256k1 scalar size.
        // Go's ecdsa package internally handles arbitrary-length hashes.
        let padded = Self::normalize_hash(hash);

        let (k256_sig, _recovery_id) = signing_key.sign_prehash_recoverable(&padded)?;

        let (r_bytes, s_bytes) = k256_sig.split_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&r_bytes);
        s.copy_from_slice(&s_bytes);

        // Low-S normalization
        if is_greater_than(&s, &HALF_ORDER) {
            s = subtract_from_order(&s);
        }

        Ok(Signature { r, s })
    }

    /// Verify this signature against a message hash and public key.
    ///
    /// # Arguments
    /// * `hash` - The message hash that was signed.
    /// * `pub_key` - The public key to verify against.
    ///
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise.
    pub fn verify(&self, hash: &[u8], pub_key: &PublicKey) -> bool {
        // Build a k256 signature from R and S
        let k256_sig = match ecdsa::Signature::from_scalars(
            k256::FieldBytes::from(self.r),
            k256::FieldBytes::from(self.s),
        ) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        let padded = Self::normalize_hash(hash);
        pub_key
            .verifying_key()
            .verify_prehash(&padded, &k256_sig)
            .is_ok()
    }

    /// Recover the public key from a compact signature and message hash.
    ///
    /// # Arguments
    /// * `compact_sig` - 65-byte compact signature (recovery_id + R + S).
    /// * `hash` - The message hash that was signed.
    ///
    /// # Returns
    /// `Ok(PublicKey)` if recovery succeeds, or an error otherwise.
    pub fn recover_public_key(
        compact_sig: &[u8],
        hash: &[u8],
    ) -> Result<PublicKey, PrimitivesError> {
        if compact_sig.len() != 65 {
            return Err(PrimitivesError::InvalidSignature(
                "invalid compact signature size".to_string(),
            ));
        }

        let header = compact_sig[0];
        let iteration = (header - 27) & !4u8;

        let recovery_id = RecoveryId::from_byte(iteration)
            .ok_or_else(|| PrimitivesError::InvalidSignature("invalid recovery id".to_string()))?;

        let k256_sig = ecdsa::Signature::from_scalars(
            *k256::FieldBytes::from_slice(&compact_sig[1..33]),
            *k256::FieldBytes::from_slice(&compact_sig[33..65]),
        )?;

        let padded = Self::normalize_hash(hash);
        let recovered_key = VerifyingKey::recover_from_prehash(&padded, &k256_sig, recovery_id)?;

        PublicKey::from_bytes(recovered_key.to_encoded_point(false).as_bytes())
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.r == other.r && self.s == other.s
    }
}

impl Eq for Signature {}

/// Canonicalize an integer for DER encoding.
///
/// Strips leading zeros from the big-endian representation and adds
/// a 0x00 padding byte if the high bit is set (to prevent interpretation
/// as a negative number).
///
/// # Arguments
/// * `val` - A 32-byte big-endian integer.
///
/// # Returns
/// A byte vector suitable for DER integer encoding.
fn canonicalize_int(val: &[u8; 32]) -> Vec<u8> {
    // Strip leading zeros
    let mut start = 0;
    while start < 31 && val[start] == 0 {
        start += 1;
    }
    let trimmed = &val[start..];

    if trimmed.is_empty() {
        return vec![0x00];
    }

    // Add padding byte if high bit is set
    if trimmed[0] & 0x80 != 0 {
        let mut out = Vec::with_capacity(trimmed.len() + 1);
        out.push(0x00);
        out.extend_from_slice(trimmed);
        out
    } else {
        trimmed.to_vec()
    }
}

/// Convert a variable-length big-endian byte slice to a fixed 32-byte array.
///
/// Strips any leading zero-padding and left-pads to 32 bytes.
///
/// # Arguments
/// * `bytes` - Variable-length big-endian integer bytes.
///
/// # Returns
/// `Ok([u8; 32])` or an error if the value exceeds 32 bytes after trimming.
fn to_32_bytes(bytes: &[u8]) -> Result<[u8; 32], PrimitivesError> {
    // Strip leading zero padding
    let mut trimmed = bytes;
    while trimmed.len() > 1 && trimmed[0] == 0 {
        trimmed = &trimmed[1..];
    }
    if trimmed.len() > 32 {
        return Err(PrimitivesError::InvalidSignature(
            "integer value too large for 32 bytes".to_string(),
        ));
    }
    let mut out = [0u8; 32];
    out[32 - trimmed.len()..].copy_from_slice(trimmed);
    Ok(out)
}

/// Check if a 32-byte big-endian integer is zero.
fn is_zero(val: &[u8; 32]) -> bool {
    val.iter().all(|&b| b == 0)
}

/// Compare two 32-byte big-endian integers: a < b.
fn is_less_than(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] < b[i] {
            return true;
        }
        if a[i] > b[i] {
            return false;
        }
    }
    false // equal
}

/// Compare two 32-byte big-endian integers: a > b.
fn is_greater_than(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    false // equal
}

/// Compute N - val where N is the secp256k1 curve order.
///
/// Used for low-S normalization.
fn subtract_from_order(val: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut borrow: i32 = 0;
    for i in (0..32).rev() {
        let diff = CURVE_ORDER[i] as i32 - val[i] as i32 - borrow;
        if diff < 0 {
            result[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            result[i] = diff as u8;
            borrow = 0;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha256;

    /// Test DER parsing of valid and invalid signatures.
    /// Test vectors ported from Go SDK signature_test.go.
    #[test]
    fn test_signatures_der_parsing() {
        // Valid signature from Bitcoin blockchain
        let valid_sig: Vec<u8> = vec![
            0x30, 0x44, 0x02, 0x20, 0x4e, 0x45, 0xe1, 0x69, 0x32, 0xb8, 0xaf, 0x51, 0x49, 0x61,
            0xa1, 0xd3, 0xa1, 0xa2, 0x5f, 0xdf, 0x3f, 0x4f, 0x77, 0x32, 0xe9, 0xd6, 0x24, 0xc6,
            0xc6, 0x15, 0x48, 0xab, 0x5f, 0xb8, 0xcd, 0x41, 0x02, 0x20, 0x18, 0x15, 0x22, 0xec,
            0x8e, 0xca, 0x07, 0xde, 0x48, 0x60, 0xa4, 0xac, 0xdd, 0x12, 0x90, 0x9d, 0x83, 0x1c,
            0xc5, 0x6c, 0xbb, 0xac, 0x46, 0x22, 0x08, 0x22, 0x21, 0xa8, 0x76, 0x8d, 0x1d, 0x09,
        ];
        assert!(Signature::from_der(&valid_sig).is_ok());

        // Empty signature
        assert!(Signature::from_der(&[]).is_err());

        // Bad magic byte
        let mut bad_magic = valid_sig.clone();
        bad_magic[0] = 0x31;
        assert!(Signature::from_der(&bad_magic).is_err());

        // Bad 1st int marker
        let mut bad_marker = valid_sig.clone();
        bad_marker[2] = 0x03;
        assert!(Signature::from_der(&bad_marker).is_err());
    }

    /// Test DER serialization of known signature values.
    /// Test vectors ported from Go SDK signature_test.go.
    #[test]
    fn test_signature_serialize() {
        // "valid 1 - r and s most significant bits are zero"
        let sig = Signature::new(
            hex_to_32("4e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41"),
            hex_to_32("181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09"),
        );
        let expected = hex::decode(
            "304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41\
             0220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09",
        )
        .unwrap();
        assert_eq!(sig.to_der(), expected, "valid 1");

        // "valid 4 - s is bigger than half order" (low-S normalization)
        let sig = Signature::new(
            hex_to_32("a196ed0e7ebcbe7b63fe1d8eecbdbde03a67ceba4fc8f6482bdcb9606a911404"),
            hex_to_32("971729c7fa944b465b35250c6570a2f31acbb14b13d1565fab7330dcb2b3dfb1"),
        );
        let expected = hex::decode(
            "3045022100a196ed0e7ebcbe7b63fe1d8eecbdbde03a67ceba4fc8f6482bdcb9606a911404\
             022068e8d638056bb4b9a4cadaf39a8f5d0b9fe32b9b9b7749dc145f2db01d826190",
        )
        .unwrap();
        assert_eq!(sig.to_der(), expected, "valid 4 - low-S normalization");

        // "zero signature"
        let sig = Signature::new([0u8; 32], [0u8; 32]);
        let expected: Vec<u8> = vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00];
        assert_eq!(sig.to_der(), expected, "zero signature");
    }

    /// Test RFC6979 deterministic signing against known Trezor/CoreBitcoin vectors.
    /// Test vectors ported from Go SDK signature_test.go.
    #[test]
    fn test_rfc6979() {
        let tests = vec![
            (
                "cca9fbcc1b41e5a95d369eaa6ddcff73b61a4efaa279cfc6567e8daa39cbaf50",
                "sample",
                "3045022100af340daf02cc15c8d5d08d7735dfe6b98a474ed373bdb5fbecf7571be52b384202205009fb27f37034a9b24b707b7c6b79ca23ddef9e25f7282e8a797efe53a8f124",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "Satoshi Nakamoto",
                "3045022100934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d802202442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5",
            ),
            (
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                "Satoshi Nakamoto",
                "3045022100fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447cd6af2d002206b39cd0eb1bc8603e159ef5c20a5c8ad685a45b06ce9bebed3f153d10d93bed5",
            ),
            (
                "f8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181",
                "Alan Turing",
                "304402207063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15c022058dfcc1e00a35e1572f366ffe34ba0fc47db1e7189759b9fb233c5b05ab388ea",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                "All those moments will be lost in time, like tears in rain. Time to die...",
                "30450221008600dbd41e348fe5c9465ab92d23e3db8b98b873beecd930736488696438cb6b0220547fe64427496db33bf66019dacbf0039c04199abb0122918601db38a72cfc21",
            ),
            (
                "e91671c46231f833a6406ccbea0e3e392c76c167bac1cb013f6f1013980455c2",
                "There is a computer disease that anybody who works with computers knows about. It's a very serious disease and it interferes completely with the work. The trouble with computers is that you 'play' with them!",
                "3045022100b552edd27580141f3b2a5463048cb7cd3e047b97c9f98076c32dbdf85a68718b0220279fa72dd19bfae05577e06c7c0c1900c371fcd5893f7e1d56a37d30174671f6",
            ),
        ];

        for (key_hex, msg, expected_sig_hex) in &tests {
            let priv_key = PrivateKey::from_bytes(&hex::decode(key_hex).unwrap()).unwrap();
            let hash = sha256(msg.as_bytes());

            let sig = priv_key.sign(&hash).unwrap();
            let sig_bytes = sig.to_der();
            let expected_bytes = hex::decode(expected_sig_hex).unwrap();

            assert_eq!(
                hex::encode(&sig_bytes),
                hex::encode(&expected_bytes),
                "RFC6979 test for message '{}'",
                msg
            );

            // Also verify the signature
            assert!(priv_key.pub_key().verify(&hash, &sig));
        }
    }

    /// Test compact signature creation and public key recovery.
    #[test]
    fn test_sign_compact() {
        for _ in 0..10 {
            let priv_key = PrivateKey::new();
            let hash = crate::hash::sha256d(b"test data for compact signature");

            let sig = priv_key.sign(&hash).unwrap();
            let compact = sig.to_compact(&hash, &priv_key);
            assert_eq!(compact.len(), 65);

            let recovered = Signature::recover_public_key(&compact, &hash).unwrap();
            assert_eq!(
                recovered.to_compressed(),
                priv_key.pub_key().to_compressed(),
                "recovered public key should match"
            );
        }
    }

    /// Test signature equality comparison.
    #[test]
    fn test_signature_is_equal() {
        let sig1 = Signature::new(
            hex_to_32("4e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd41"),
            hex_to_32("181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d09"),
        );
        let sig2 = Signature::new(
            hex_to_32("a196ed0e7ebcbe7b63fe1d8eecbdbde03a67ceba4fc8f6482bdcb9606a911404"),
            hex_to_32("971729c7fa944b465b35250c6570a2f31acbb14b13d1565fab7330dcb2b3dfb1"),
        );

        assert_eq!(sig1, sig1);
        assert_ne!(sig1, sig2);
    }

    /// Helper to convert a hex string to a 32-byte array.
    fn hex_to_32(s: &str) -> [u8; 32] {
        let bytes = hex::decode(s).unwrap();
        let mut out = [0u8; 32];
        // Handle cases where hex might be > 32 bytes (leading zeros)
        if bytes.len() > 32 {
            out.copy_from_slice(&bytes[bytes.len() - 32..]);
        } else {
            out[32 - bytes.len()..].copy_from_slice(&bytes);
        }
        out
    }
}
