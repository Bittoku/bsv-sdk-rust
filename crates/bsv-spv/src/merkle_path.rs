//! Merkle path (BUMP) types and verification.
//!
//! Ported from the Go SDK's `merklepath.go`. Implements BRC-74 binary format.

use bsv_primitives::chainhash::Hash;
use bsv_primitives::util::{BsvReader, BsvWriter, VarInt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::SpvError;
use crate::merkle_tree_parent::merkle_tree_parent;

/// A single element in a Merkle path level.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PathElement {
    /// Position offset within this tree level.
    pub offset: u64,
    /// Hash value at this position (absent when `duplicate` is set).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<Hash>,
    /// When `Some(true)`, indicates this element is the target transaction ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txid: Option<bool>,
    /// When `Some(true)`, the sibling hash is a duplicate of its pair (odd leaf count).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duplicate: Option<bool>,
}

/// A Merkle path (BUMP) associating a transaction with a block via a
/// sequence of hashes at each tree level.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MerklePath {
    /// Block height at which the transaction was mined.
    pub block_height: u32,
    /// Path levels from leaf (index 0) to root, each containing one or more elements.
    pub path: Vec<Vec<PathElement>>,
}

/// Indexed path for efficient offset lookups with recursive computation.
struct IndexedPath(Vec<HashMap<u64, PathElement>>);

impl IndexedPath {
    fn from_merkle_path(mp: &MerklePath) -> Self {
        let mut indexed = Vec::with_capacity(mp.path.len());
        for level in &mp.path {
            let mut map = HashMap::new();
            for elem in level {
                map.insert(elem.offset, elem.clone());
            }
            indexed.push(map);
        }
        IndexedPath(indexed)
    }

    fn get_offset_leaf(&self, layer: usize, offset: u64) -> Option<PathElement> {
        if let Some(leaf) = self.0[layer].get(&offset) {
            return Some(leaf.clone());
        }
        if layer == 0 {
            return None;
        }
        let prev_offset = offset * 2;
        let left = self.get_offset_leaf(layer - 1, prev_offset)?;
        let right = self.get_offset_leaf(layer - 1, prev_offset + 1)?;
        let left_hash = left.hash.as_ref()?;
        let parent_hash = if right.duplicate == Some(true) {
            merkle_tree_parent(left_hash, left_hash)
        } else {
            let right_hash = right.hash.as_ref()?;
            merkle_tree_parent(left_hash, right_hash)
        };
        Some(PathElement {
            offset,
            hash: Some(parent_hash),
            txid: None,
            duplicate: None,
        })
    }
}

impl MerklePath {
    /// Create a new MerklePath.
    pub fn new(block_height: u32, path: Vec<Vec<PathElement>>) -> Self {
        MerklePath { block_height, path }
    }

    /// Parse a MerklePath from a hex string (BRC-74 binary format).
    pub fn from_hex(hex_data: &str) -> Result<Self, SpvError> {
        let bin = hex::decode(hex_data)?;
        Self::from_bytes(&bin)
    }

    /// Parse a MerklePath from binary data (BRC-74).
    pub fn from_bytes(data: &[u8]) -> Result<Self, SpvError> {
        if data.len() < 37 {
            return Err(SpvError::InvalidMerklePath(
                "BUMP bytes do not contain enough data to be valid".to_string(),
            ));
        }
        let mut reader = BsvReader::new(data);
        Self::from_reader(&mut reader)
    }

    /// Parse a MerklePath from a BsvReader.
    pub fn from_reader(reader: &mut BsvReader) -> Result<Self, SpvError> {
        let block_height_vi = reader
            .read_varint()
            .map_err(|e| SpvError::InvalidMerklePath(format!("reading block height: {}", e)))?;
        let block_height = block_height_vi.value() as u32;

        let tree_height = reader
            .read_u8()
            .map_err(|e| SpvError::InvalidMerklePath(format!("reading tree height: {}", e)))?;

        let mut path = Vec::with_capacity(tree_height as usize);

        for _ in 0..tree_height {
            let n_leaves = reader
                .read_varint()
                .map_err(|e| SpvError::InvalidMerklePath(format!("reading leaf count: {}", e)))?;

            let mut level = Vec::with_capacity(n_leaves.value() as usize);
            for _ in 0..n_leaves.value() {
                let offset_vi = reader
                    .read_varint()
                    .map_err(|e| SpvError::InvalidMerklePath(format!("reading offset: {}", e)))?;
                let offset = offset_vi.value();

                let flags = reader
                    .read_u8()
                    .map_err(|e| SpvError::InvalidMerklePath(format!("reading flags: {}", e)))?;

                let dup = (flags & 1) != 0;
                let is_txid = (flags & 2) != 0;

                let mut elem = PathElement {
                    offset,
                    hash: None,
                    txid: None,
                    duplicate: None,
                };

                if dup {
                    elem.duplicate = Some(true);
                } else {
                    let hash_bytes = reader
                        .read_bytes(32)
                        .map_err(|e| SpvError::InvalidMerklePath(format!("reading hash: {}", e)))?;
                    elem.hash = Some(Hash::from_bytes(hash_bytes).map_err(|e| {
                        SpvError::InvalidMerklePath(format!("invalid hash: {}", e))
                    })?);
                }

                if is_txid {
                    elem.txid = Some(true);
                }

                level.push(elem);
            }

            // Sort by offset for consistency
            level.sort_by_key(|e| e.offset);
            path.push(level);
        }

        Ok(MerklePath { block_height, path })
    }

    /// Serialize to BRC-74 binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = BsvWriter::new();
        writer.write_varint(VarInt(self.block_height as u64));
        let tree_height = self.path.len();
        writer.write_u8(tree_height as u8);

        for level in &self.path {
            writer.write_varint(VarInt(level.len() as u64));
            for leaf in level {
                writer.write_varint(VarInt(leaf.offset));
                let mut flags = 0u8;
                if leaf.duplicate == Some(true) {
                    flags |= 1;
                }
                if leaf.txid == Some(true) {
                    flags |= 2;
                }
                writer.write_u8(flags);
                if (flags & 1) == 0 {
                    if let Some(ref hash) = leaf.hash {
                        writer.write_bytes(hash.as_bytes());
                    }
                }
            }
        }

        writer.into_bytes()
    }

    /// Serialize to hex string (BRC-74).
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Clone by serializing and deserializing.
    pub fn deep_clone(&self) -> Self {
        Self::from_bytes(&self.to_bytes()).unwrap()
    }

    /// Compute the Merkle root given a transaction ID.
    /// If `txid` is None, uses the first available hash from level 0.
    pub fn compute_root(&self, txid: Option<&Hash>) -> Result<Hash, SpvError> {
        let txid = match txid {
            Some(t) => *t,
            None => {
                let mut found = None;
                for l in &self.path[0] {
                    if let Some(ref h) = l.hash {
                        found = Some(*h);
                        break;
                    }
                }
                found.ok_or_else(|| {
                    SpvError::InvalidMerklePath("no hash found at level 0".to_string())
                })?
            }
        };

        // Special case: single tx in block
        if self.path.len() == 1 && self.path[0].len() == 1 {
            return Ok(txid);
        }

        let indexed_path = IndexedPath::from_merkle_path(self);

        // Find the leaf matching this txid
        let tx_leaf = self.path[0]
            .iter()
            .find(|l| l.hash.as_ref().is_some_and(|h| *h == txid))
            .ok_or_else(|| {
                SpvError::InvalidMerklePath(format!("the BUMP does not contain the txid: {}", txid))
            })?;

        let mut working_hash = tx_leaf.hash.unwrap();
        let index = tx_leaf.offset;

        for height in 0..self.path.len() {
            let offset = (index >> height) ^ 1;
            let leaf = indexed_path
                .get_offset_leaf(height, offset)
                .ok_or_else(|| {
                    SpvError::InvalidMerklePath(format!(
                        "we do not have a hash for this index at height: {}",
                        height
                    ))
                })?;

            if leaf.duplicate == Some(true) {
                working_hash = merkle_tree_parent(&working_hash, &working_hash);
            } else {
                let leaf_hash = leaf.hash.ok_or_else(|| {
                    SpvError::InvalidMerklePath(format!(
                        "missing hash at height {} offset {}",
                        height, offset
                    ))
                })?;
                if (offset % 2) != 0 {
                    working_hash = merkle_tree_parent(&working_hash, &leaf_hash);
                } else {
                    working_hash = merkle_tree_parent(&leaf_hash, &working_hash);
                }
            }
        }

        Ok(working_hash)
    }

    /// Compute root from hex txid string.
    pub fn compute_root_hex(&self, txid_str: Option<&str>) -> Result<String, SpvError> {
        let txid = match txid_str {
            Some(s) => Some(
                Hash::from_hex(s)
                    .map_err(|e| SpvError::InvalidMerklePath(format!("invalid txid hex: {}", e)))?,
            ),
            None => None,
        };
        let root = self.compute_root(txid.as_ref())?;
        Ok(root.to_string())
    }

    /// Combine another MerklePath into this one.
    /// Both must have the same block height and same root.
    pub fn combine(&mut self, other: &MerklePath) -> Result<(), SpvError> {
        if self.block_height != other.block_height {
            return Err(SpvError::InvalidMerklePath(
                "cannot combine MerklePaths with different block heights".to_string(),
            ));
        }

        let root1 = self.compute_root_hex(None)?;
        let root2 = other.compute_root_hex(None)?;
        if root1 != root2 {
            return Err(SpvError::InvalidMerklePath(
                "cannot combine MerklePaths with different roots".to_string(),
            ));
        }

        // Build combined indexed path
        let max_len = self.path.len().max(other.path.len());
        let mut combined: Vec<HashMap<u64, PathElement>> = Vec::with_capacity(max_len);
        for h in 0..max_len {
            let mut map = HashMap::new();
            if h < self.path.len() {
                for elem in &self.path[h] {
                    map.insert(elem.offset, elem.clone());
                }
            }
            if h < other.path.len() {
                for elem in &other.path[h] {
                    map.insert(elem.offset, elem.clone());
                }
            }
            combined.push(map);
        }

        // Rebuild path, trimming nodes whose children are both present
        self.path = Vec::with_capacity(combined.len());
        for h in (0..combined.len()).rev() {
            let mut level = Vec::new();
            for (&offset, elem) in &combined[h] {
                if h > 0 {
                    let child_offset = offset * 2;
                    let has_left = combined[h - 1].contains_key(&child_offset);
                    let has_right = combined[h - 1].contains_key(&(child_offset + 1));
                    if has_left && has_right {
                        continue;
                    }
                }
                level.push(elem.clone());
            }
            level.sort_by_key(|e| e.offset);
            // Insert at front since we're iterating in reverse
            self.path.insert(0, level);
        }

        Ok(())
    }

    /// Find a PathElement at the given offset in the specified level.
    pub fn find_leaf_by_offset(&self, level: usize, offset: u64) -> Option<&PathElement> {
        if level >= self.path.len() {
            return None;
        }
        self.path[level].iter().find(|l| l.offset == offset)
    }

    /// Add a PathElement to the specified level, growing the path if needed.
    pub fn add_leaf(&mut self, level: usize, element: PathElement) {
        while self.path.len() <= level {
            self.path.push(Vec::new());
        }
        self.path[level].push(element);
    }

    /// Compute missing intermediate hashes from level 0 upward.
    pub fn compute_missing_hashes(&mut self) {
        if self.path.len() < 2 {
            return;
        }

        for level in 1..self.path.len() {
            let mut new_elements = Vec::new();

            // Collect left leaves from prev level
            let prev_level = &self.path[level - 1];
            for left_leaf in prev_level {
                if left_leaf.hash.is_none() || (left_leaf.offset & 1) != 0 {
                    continue;
                }
                let right_offset = left_leaf.offset + 1;
                let parent_offset = left_leaf.offset >> 1;

                // Check if parent already exists at current level
                let parent_exists = self.path[level].iter().any(|e| e.offset == parent_offset);
                if parent_exists {
                    continue;
                }

                // Find right leaf
                let right_leaf = prev_level.iter().find(|e| e.offset == right_offset);

                if let Some(right) = right_leaf {
                    let left_hash = left_leaf.hash.as_ref().unwrap();
                    let parent_hash = if right.duplicate == Some(true) {
                        merkle_tree_parent(left_hash, left_hash)
                    } else if let Some(ref right_hash) = right.hash {
                        merkle_tree_parent(left_hash, right_hash)
                    } else {
                        continue;
                    };
                    new_elements.push(PathElement {
                        offset: parent_offset,
                        hash: Some(parent_hash),
                        txid: None,
                        duplicate: None,
                    });
                }
            }

            self.path[level].extend(new_elements);
        }

        // Sort each level by offset
        for level in &mut self.path {
            level.sort_by_key(|e| e.offset);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BRC74_HEX: &str = "fe8a6a0c000c04fde80b0011774f01d26412f0d16ea3f0447be0b5ebec67b0782e321a7a01cbdf7f734e30fde90b02004e53753e3fe4667073063a17987292cfdea278824e9888e52180581d7188d8fdea0b025e441996fc53f0191d649e68a200e752fb5f39e0d5617083408fa179ddc5c998fdeb0b0102fdf405000671394f72237d08a4277f4435e5b6edf7adc272f25effef27cdfe805ce71a81fdf50500262bccabec6c4af3ed00cc7a7414edea9c5efa92fb8623dd6160a001450a528201fdfb020101fd7c010093b3efca9b77ddec914f8effac691ecb54e2c81d0ab81cbc4c4b93befe418e8501bf01015e005881826eb6973c54003a02118fe270f03d46d02681c8bc71cd44c613e86302f8012e00e07a2bb8bb75e5accff266022e1e5e6e7b4d6d943a04faadcf2ab4a22f796ff30116008120cafa17309c0bb0e0ffce835286b3a2dcae48e4497ae2d2b7ced4f051507d010a00502e59ac92f46543c23006bff855d96f5e648043f0fb87a7a5949e6a9bebae430104001ccd9f8f64f4d0489b30cc815351cf425e0e78ad79a589350e4341ac165dbe45010301010000af8764ce7e1cc132ab5ed2229a005c87201c9a5ee15c0f91dd53eff31ab30cd4";
    const BRC74_ROOT: &str = "57aab6e6fb1b697174ffb64e062c4728f2ffd33ddcfa02a43b64d8cd29b483b4";
    const BRC74_TXID1: &str = "304e737fdfcb017a1a322e78b067ecebb5e07b44f0a36ed1f01264d2014f7711";
    const BRC74_TXID2: &str = "d888711d588021e588984e8278a2decf927298173a06737066e43f3e75534e00";
    const BRC74_TXID3: &str = "98c9c5dd79a18f40837061d5e0395ffb52e700a2689e641d19f053fc9619445e";

    #[test]
    fn test_parse_from_hex() {
        let mp = MerklePath::from_hex(BRC74_HEX).unwrap();
        assert_eq!(BRC74_HEX, mp.to_hex());
    }

    #[test]
    fn test_compute_root() {
        let mp = MerklePath::from_hex(BRC74_HEX).unwrap();
        let root = mp.compute_root_hex(Some(BRC74_TXID1)).unwrap();
        assert_eq!(BRC74_ROOT, root);
    }

    #[test]
    fn test_compute_root_txid2() {
        let mp = MerklePath::from_hex(BRC74_HEX).unwrap();
        let root = mp.compute_root_hex(Some(BRC74_TXID2)).unwrap();
        assert_eq!(BRC74_ROOT, root);
    }

    #[test]
    fn test_compute_root_txid3() {
        let mp = MerklePath::from_hex(BRC74_HEX).unwrap();
        let root = mp.compute_root_hex(Some(BRC74_TXID3)).unwrap();
        assert_eq!(BRC74_ROOT, root);
    }

    #[test]
    fn test_serialize_to_hex() {
        let mp = MerklePath::from_hex(BRC74_HEX).unwrap();
        assert_eq!(BRC74_HEX, mp.to_hex());
    }

    #[test]
    fn test_clone() {
        let original = MerklePath::from_hex(BRC74_HEX).unwrap();
        let mut cloned = original.deep_clone();
        assert_eq!(original.block_height, cloned.block_height);
        cloned.block_height = 999999;
        assert_ne!(original.block_height, cloned.block_height);
    }

    #[test]
    fn test_combine() {
        let mp = MerklePath::from_hex(BRC74_HEX).unwrap();

        // Split into path A and B
        let mut path0a = mp.path[0][..2].to_vec();
        path0a.extend_from_slice(&mp.path[0][4..]);
        let path0b = mp.path[0][2..].to_vec();
        let path1a = mp.path[1][1..].to_vec();
        let path1b = mp.path[1][..mp.path[1].len() - 1].to_vec();

        let mut path_a_levels = vec![path0a, path1a];
        path_a_levels.extend_from_slice(&mp.path[2..]);
        let mut path_a = MerklePath::new(mp.block_height, path_a_levels);

        let mut path_b_levels = vec![path0b, path1b];
        path_b_levels.extend_from_slice(&mp.path[2..]);
        let path_b = MerklePath::new(mp.block_height, path_b_levels);

        // Path A can compute root for TXID2 but not TXID3
        let root_a = path_a.compute_root_hex(Some(BRC74_TXID2)).unwrap();
        assert_eq!(root_a, BRC74_ROOT);
        assert!(path_a.compute_root_hex(Some(BRC74_TXID3)).is_err());

        // Path B can compute root for TXID3 but not TXID2
        let root_b = path_b.compute_root_hex(Some(BRC74_TXID3)).unwrap();
        assert_eq!(root_b, BRC74_ROOT);
        assert!(path_b.compute_root_hex(Some(BRC74_TXID2)).is_err());

        // After combining, both work
        path_a.combine(&path_b).unwrap();
        let root = path_a.compute_root_hex(Some(BRC74_TXID2)).unwrap();
        assert_eq!(root, BRC74_ROOT);
        let root = path_a.compute_root_hex(Some(BRC74_TXID3)).unwrap();
        assert_eq!(root, BRC74_ROOT);
    }

    #[test]
    fn test_add_leaf_and_compute_missing_hashes() {
        let leaf0 =
            Hash::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let leaf1 =
            Hash::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();
        let leaf2 =
            Hash::from_hex("0000000000000000000000000000000000000000000000000000000000000003")
                .unwrap();
        let leaf3 =
            Hash::from_hex("0000000000000000000000000000000000000000000000000000000000000004")
                .unwrap();

        let h01 = merkle_tree_parent(&leaf0, &leaf1);
        let h23 = merkle_tree_parent(&leaf2, &leaf3);
        let root = merkle_tree_parent(&h01, &h23);

        let mut mp = MerklePath::new(1000, vec![]);
        mp.add_leaf(
            0,
            PathElement {
                offset: 0,
                hash: Some(leaf0),
                txid: None,
                duplicate: None,
            },
        );
        mp.add_leaf(
            0,
            PathElement {
                offset: 1,
                hash: Some(leaf1),
                txid: None,
                duplicate: None,
            },
        );
        mp.add_leaf(
            0,
            PathElement {
                offset: 2,
                hash: Some(leaf2),
                txid: Some(true),
                duplicate: None,
            },
        );
        mp.add_leaf(
            0,
            PathElement {
                offset: 3,
                hash: Some(leaf3),
                txid: None,
                duplicate: None,
            },
        );

        // Add empty levels
        mp.add_leaf(
            1,
            PathElement {
                offset: 0,
                hash: None,
                txid: None,
                duplicate: None,
            },
        );
        mp.add_leaf(
            2,
            PathElement {
                offset: 0,
                hash: None,
                txid: None,
                duplicate: None,
            },
        );
        mp.path[1].clear();
        mp.path[2].clear();

        mp.compute_missing_hashes();

        assert_eq!(mp.path[1].len(), 2);
        let found01 = mp.find_leaf_by_offset(1, 0).unwrap();
        assert_eq!(found01.hash.unwrap().to_string(), h01.to_string());
        let found23 = mp.find_leaf_by_offset(1, 1).unwrap();
        assert_eq!(found23.hash.unwrap().to_string(), h23.to_string());

        assert_eq!(mp.path[2].len(), 1);
        let found_root = mp.find_leaf_by_offset(2, 0).unwrap();
        assert_eq!(found_root.hash.unwrap().to_string(), root.to_string());
    }

    #[test]
    fn test_duplicate_handling() {
        let leaf0 =
            Hash::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let leaf1 =
            Hash::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();
        let leaf2 =
            Hash::from_hex("0000000000000000000000000000000000000000000000000000000000000003")
                .unwrap();

        let mut mp = MerklePath::new(1000, vec![Vec::new(), Vec::new(), Vec::new()]);
        mp.add_leaf(
            0,
            PathElement {
                offset: 0,
                hash: Some(leaf0),
                txid: None,
                duplicate: None,
            },
        );
        mp.add_leaf(
            0,
            PathElement {
                offset: 1,
                hash: Some(leaf1),
                txid: None,
                duplicate: None,
            },
        );
        mp.add_leaf(
            0,
            PathElement {
                offset: 2,
                hash: Some(leaf2),
                txid: None,
                duplicate: None,
            },
        );
        mp.add_leaf(
            0,
            PathElement {
                offset: 3,
                hash: None,
                txid: None,
                duplicate: Some(true),
            },
        );

        mp.compute_missing_hashes();

        let h01 = merkle_tree_parent(&leaf0, &leaf1);
        let found01 = mp.find_leaf_by_offset(1, 0).unwrap();
        assert_eq!(found01.hash.unwrap().to_string(), h01.to_string());

        let h23 = merkle_tree_parent(&leaf2, &leaf2);
        let found23 = mp.find_leaf_by_offset(1, 1).unwrap();
        assert_eq!(found23.hash.unwrap().to_string(), h23.to_string());
    }

    #[test]
    fn test_grow_path() {
        let mut mp = MerklePath::new(1000, vec![]);
        let leaf =
            Hash::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        mp.add_leaf(
            5,
            PathElement {
                offset: 0,
                hash: Some(leaf),
                txid: None,
                duplicate: None,
            },
        );
        assert_eq!(mp.path.len(), 6);
        assert_eq!(mp.path[5].len(), 1);
    }

    // Test vectors from Go SDK
    #[test]
    fn test_valid_bumps() {
        let valid = vec![
            "fed79f0c000c02fd3803029b490d9c8358ff11afaf45628417c9eb52c1a1fd404078a101b4f71dbba06aa9fd390300fe82f2768edc3d0cfe4d06b7f390dcb0b7e61cca7f70117d83be0f023204d8ef01fd9d010060893ac65c8a8e6b9ef7ed5e05dc3bd25aa904812c09853c5dbf423b58a75d0e01cf0012c3c76d9c332e4701b27bfe7013e7963b92d1851d59c56955b35aecabbc8bae0166000894384f86a5c4d0d294f9b9441c3ee3d13afa094cca4515d32813b3fa4fdf3601320002aac507f74c9ff2676705eee1e70897a8baeecaf30c5f49bb22a0c5ce5fda9a01180021f7e27a08d61245be893a238853d72340881cbd47e0a390895231fa1cc44db9010d004d7a12738a1654777867182ee6f6efc4d692209badfa5ba9bb126d08da18ed880107004f8e96b4ee6154bd44b7709f3fb4041bf4426d5f5a594408345605e254af7cdd010200ec7d8b185bc7c096b9b88de6f63ab22baf738d5fc4cbc328f2e00644749acf520100007fd48b1d2b678907ba045b07132003db8116468cd6a3d4764e0df4a644ea0a220101009bb8ffc1a6ed2ba80ea1b09ff797387115a7129d19e93c003a74e3a20ed6ce590101001106e6ece3f70a16de42d0f87b459c71a2440201728bd8541334933726807921",
            "feb39d0c000c02fd340700ed4cb1fdd81916dabb69b63bcd378559cf40916205cd004e7f5381cc2b1ea6acfd350702957998e38434782b1c40c63a4aca0ffaf4d5d9bc3385f0e9e396f4dd3238f0df01fd9b030012f77e65627c341a3aaea3a0ed645c0082ef53995f446ab9901a27e4622fd1cc01fdcc010074026299a4ba40fbcf33cc0c64b384f0bb2fb17c61125609a666b546539c221c01e700730f99f8cf10fccd30730474449172c5f97cde6a6cf65163359e778463e9f2b9017200a202c78dee487cf96e1a6a04d51faec4debfad09eea28cc624483f2d6fa53d54013800b51ecabaa590b6bd1805baf4f19fc0eae0dedb533302603579d124059b374b1e011d00a0f36640f32a43d790bb4c3e7877011aa8ae25e433b2b83c952a16f8452b6b79010f005d68efab62c6c457ce0bb526194cc16b27f93f8a4899f6d59ffffdddc06e345c01060099f66a0ef693d151bbe9aeb10392ac5a7712243406f9e821219fd13d1865f569010200201fa17c98478675a96703ded42629a3c7bf32b45d0bff25f8be6849d02889ae010000367765c2d68e0c926d81ecdf9e3c86991ccf5a52e97c49ad5cf584c8ab030427010100237b58d3217709b6ebc3bdc093413ba788739f052a0b5b3a413e65444b146bc1",
        ];
        for hex_str in valid {
            MerklePath::from_hex(hex_str)
                .expect(&format!("should parse valid bump: {}", &hex_str[..20]));
        }
    }

    #[test]
    fn test_invalid_bumps() {
        let invalid = vec![
            "feb39d0c000c01fd9b030012f77e65627c341a3aaea3a0ed645c0082ef53995f446ab9901a27e4622fd1cc01fdcc010074026299a4ba40fbcf33cc0c64b384f0bb2fb17c61125609a666b546539c221c01e700730f99f8cf10fccd30730474449172c5f97cde6a6cf65163359e778463e9f2b9017200a202c78dee487cf96e1a6a04d51faec4debfad09eea28cc624483f2d6fa53d54013800b51ecabaa590b6bd1805baf4f19fc0eae0dedb533302603579d124059b374b1e011d00a0f36640f32a43d790bb4c3e7877011aa8ae25e433b2b83c952a16f8452b6b79010f005d68efab62c6c457ce0bb526194cc16b27f93f8a4899f6d59ffffdddc06e345c01060099f66a0ef693d151bbe9aeb10392ac5a7712243406f9e821219fd13d1865f569010200201fa17c98478675a96703ded42629a3c7bf32b45d0bff25f8be6849d02889ae010000367765c2d68e0c926d81ecdf9e3c86991ccf5a52e97c49ad5cf584c8ab030427010100237b58d3217709b6ebc3bdc093413ba788739f052a0b5b3a413e65444b146bc1",
        ];
        for hex_str in invalid {
            assert!(
                MerklePath::from_hex(hex_str).is_err(),
                "should reject invalid bump"
            );
        }
    }
}
