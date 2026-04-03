#![deny(missing_docs)]
//! BSV Token protocol support (STAS, STAS 3.0, STAS-BTG).
//!
//! Provides types and utilities for creating, transferring, and managing
//! tokens on the BSV blockchain using the STAS and STAS 3.0 protocols.
//!
//! The STAS-BTG (Back-to-Genesis) variant adds on-chain prev-TX verification
//! to each token hop, eliminating the need for full ancestor chain traversal
//! to validate token legitimacy.

#[cfg(feature = "bundle")]
pub mod bundle;
pub mod error;
pub mod factory;
pub mod lineage;
pub mod proof;
pub mod scheme;
pub mod script;
pub mod script_type;
pub mod template;
pub mod token_id;
pub mod types;

pub use error::TokenError;
pub use scheme::{Authority, TokenScheme};
pub use token_id::TokenId;
pub use script_type::ScriptType;
pub use types::{Payment, Destination, DstasSpendType, DstasSwapMode, ActionData, DstasLockingParams, DstasDestination, SigningKey, OwnerAddress};
pub use script::stas_builder::build_stas_locking_script;
pub use script::stas_btg_builder::build_stas_btg_locking_script;
pub use script::dstas_builder::{build_dstas_locking_script, build_dstas_flags};
pub use script::dstas_swap::{compute_dstas_requested_script_hash, resolve_dstas_swap_mode, is_dstas_frozen};
pub use template::stas::{StasUnlockingTemplate, StasMpkhUnlockingTemplate};
pub use template::stas_btg::{StasBtgUnlockingTemplate, StasBtgCheckpointUnlockingTemplate};
pub use template::dstas::{DstasUnlockingTemplate, DstasMpkhUnlockingTemplate};
pub use proof::split_tx_around_output;
pub use lineage::{LineageValidator, TxFetcher};
pub use factory::{
    build_contract_tx, ContractConfig,
    build_issue_tx, build_transfer_tx, build_split_tx, build_merge_tx, build_redeem_tx,
    IssueConfig, TransferConfig, SplitConfig, MergeConfig, RedeemConfig,
    build_btg_transfer_tx, build_btg_split_tx, build_btg_merge_tx, build_btg_checkpoint_tx,
    BtgTransferConfig, BtgSplitConfig, BtgMergeConfig, BtgCheckpointConfig, BtgPayment,
    build_dstas_issue_txs, build_dstas_base_tx, build_dstas_freeze_tx, build_dstas_unfreeze_tx,
    build_dstas_swap_flow_tx, build_dstas_transfer_swap_tx, build_dstas_swap_swap_tx,
    DstasIssueConfig, DstasIssueOutput, DstasIssueTxs,
    DstasBaseConfig, DstasOutputParams, TokenInput,
};
