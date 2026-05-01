//! Merkle tree parent computation.
//!
//! Ported from the Go SDK's `merkletreeparent.go`.

use bsv_primitives::chainhash::Hash;
use bsv_primitives::hash::sha256d;

/// Compute the Merkle tree parent of two children using hex strings.
///
/// The hex strings are byte-reversed (display order), concatenated in
/// reversed form, double-SHA256'd, then reversed back.
pub fn merkle_tree_parent_str(left: &str, right: &str) -> Result<String, hex::FromHexError> {
    let l = hex::decode(left)?;
    let r = hex::decode(right)?;
    Ok(hex::encode(merkle_tree_parent_bytes(&l, &r)))
}

/// Compute the Merkle tree parent of two children as byte slices.
///
/// Byte slices are in display order (big-endian). They are reversed,
/// concatenated, double-SHA256'd, then reversed.
pub fn merkle_tree_parent_bytes(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut concatenated = Vec::with_capacity(left.len() + right.len());
    for b in left.iter().rev() {
        concatenated.push(*b);
    }
    for b in right.iter().rev() {
        concatenated.push(*b);
    }
    let hash = sha256d(&concatenated);
    let mut result = hash.to_vec();
    result.reverse();
    result
}

/// Compute the Merkle tree parent of two `Hash` values.
///
/// The hashes are in internal (little-endian) byte order. They are
/// concatenated directly (no reversal), double-SHA256'd.
pub fn merkle_tree_parent(left: &Hash, right: &Hash) -> Hash {
    let mut concatenated = [0u8; 64];
    concatenated[..32].copy_from_slice(left.as_bytes());
    concatenated[32..].copy_from_slice(right.as_bytes());
    let hash = sha256d(&concatenated);
    Hash::new(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_parent_str() {
        let left = "d6c79a6ef05572f0cb8e9a450c561fc40b0a8a7d48faad95e20d93ddeb08c231";
        let right = "b1ed931b79056438b990d8981ba46fae97e5574b142445a74a44b978af284f98";
        let expected = "b0d537b3ee52e472507f453df3d69561720346118a5a8c4d85ca0de73bc792be";
        let parent = merkle_tree_parent_str(left, right).unwrap();
        assert_eq!(expected, parent);
    }

    #[test]
    fn test_merkle_tree_parent_bytes() {
        let left = hex::decode("d6c79a6ef05572f0cb8e9a450c561fc40b0a8a7d48faad95e20d93ddeb08c231")
            .unwrap();
        let right = hex::decode("b1ed931b79056438b990d8981ba46fae97e5574b142445a74a44b978af284f98")
            .unwrap();
        let expected =
            hex::decode("b0d537b3ee52e472507f453df3d69561720346118a5a8c4d85ca0de73bc792be")
                .unwrap();
        let parent = merkle_tree_parent_bytes(&left, &right);
        assert_eq!(expected, parent);
    }
}
