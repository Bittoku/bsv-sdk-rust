#![deny(missing_docs)]

//! BSV Blockchain SDK - Wallet interface and key derivation.
//!
//! Defines the 29-method Wallet trait, key derivation (BRC-42),
//! proto-wallet implementation, and wire protocol serialization.

mod error;
pub use error::WalletError;

pub mod key_deriver;
pub mod proto_wallet;
/// Core wallet types — Protocol, Counterparty, EncryptionArgs, and wire-format structs.
pub mod types;
pub mod wallet_trait;

pub use key_deriver::KeyDeriver;
pub use proto_wallet::{ProtoWallet, ProtoWalletArgs, Wallet};
pub use wallet_trait::WalletInterface;

/// Binary serialization for wallet request/response frames.
pub mod serializer;
