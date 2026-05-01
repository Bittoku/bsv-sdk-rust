#![deny(missing_docs)]

//! BSV Blockchain SDK - SPV verification.
//!
//! Provides Simplified Payment Verification (SPV) types including
//! Merkle paths (BUMP format), BEEF transaction containers, chain
//! tracking traits, and broadcaster interfaces.
//!
//! Ported from the Go BSV SDK's transaction/merklepath.go, transaction/beef.go,
//! transaction/chaintracker/, and transaction/broadcaster.go.

/// BEEF (Background Evaluation Extended Format) transaction container (BRC-64/95/96).
pub mod beef;
/// Transaction broadcasting interfaces.
pub mod broadcaster;
/// Chain tracker trait for verifying Merkle roots against block headers.
pub mod chain_tracker;
/// Error types for SPV operations.
pub mod error;
/// Merkle path (BUMP) types and verification (BRC-74).
pub mod merkle_path;
/// Merkle tree parent hash computation utilities.
pub mod merkle_tree_parent;

pub use beef::{Beef, BeefTx, DataFormat, ATOMIC_BEEF, BEEF_V1, BEEF_V2};
pub use broadcaster::{BroadcastFailure, BroadcastSuccess, Broadcaster};
pub use chain_tracker::ChainTracker;
pub use error::SpvError;
pub use merkle_path::{MerklePath, PathElement};
pub use merkle_tree_parent::{
    merkle_tree_parent, merkle_tree_parent_bytes, merkle_tree_parent_str,
};
