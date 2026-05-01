//! Transaction factories for STAS token operations.
//!
//! Each factory is a pure function that builds a complete, signed `Transaction`.

pub mod contract;
pub mod stas;
pub mod stas3;

pub use contract::{build_contract_tx, ContractConfig};
pub use stas::{
    build_btg_checkpoint_tx, build_btg_merge_tx, build_btg_split_tx, build_btg_transfer_tx,
    build_issue_tx, build_merge_tx, build_redeem_tx, build_split_tx, build_transfer_tx,
    BtgCheckpointConfig, BtgMergeConfig, BtgPayment, BtgSplitConfig, BtgTransferConfig,
    IssueConfig, MergeConfig, RedeemConfig, SplitConfig, TransferConfig,
};
pub use stas3::{
    build_stas3_base_tx, build_stas3_confiscate_tx, build_stas3_freeze_tx, build_stas3_issue_txs,
    build_stas3_merge_tx, build_stas3_redeem_tx, build_stas3_split_tx, build_stas3_swap_cancel_tx,
    build_stas3_swap_flow_tx, build_stas3_swap_swap_tx, build_stas3_swap_swap_tx_with_pieces,
    build_stas3_transfer_swap_tx, build_stas3_unfreeze_tx, build_swap_remainder_output,
    RedeemAddressType, Stas3BaseConfig, Stas3ConfiscateConfig, Stas3IssueConfig, Stas3IssueOutput,
    Stas3IssueTxs, Stas3MergeConfig, Stas3OutputParams, Stas3RedeemConfig, Stas3SplitConfig,
    Stas3SwapCancelConfig, Stas3SwapPieceParams, TokenInput,
};
