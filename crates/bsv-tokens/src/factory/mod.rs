//! Transaction factories for STAS token operations.
//!
//! Each factory is a pure function that builds a complete, signed `Transaction`.

pub mod contract;
pub mod stas3;
pub mod stas;

pub use contract::{build_contract_tx, ContractConfig};
pub use stas3::{
    build_stas3_base_tx, build_stas3_freeze_tx, build_stas3_issue_txs, build_stas3_swap_flow_tx,
    build_stas3_transfer_swap_tx, build_stas3_swap_swap_tx,
    build_stas3_unfreeze_tx, Stas3BaseConfig, Stas3IssueConfig, Stas3IssueOutput, Stas3IssueTxs,
    Stas3OutputParams, TokenInput,
};
pub use stas::{
    build_issue_tx, build_merge_tx, build_redeem_tx, build_split_tx, build_transfer_tx,
    IssueConfig, MergeConfig, RedeemConfig, SplitConfig, TransferConfig,
    build_btg_transfer_tx, build_btg_split_tx, build_btg_merge_tx, build_btg_checkpoint_tx,
    BtgTransferConfig, BtgSplitConfig, BtgMergeConfig, BtgCheckpointConfig, BtgPayment,
};
