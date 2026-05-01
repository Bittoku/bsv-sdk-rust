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
pub mod stas3;
pub mod template;
pub mod token_id;
pub mod types;

pub use error::TokenError;
pub use factory::{
    build_btg_checkpoint_tx, build_btg_merge_tx, build_btg_split_tx, build_btg_transfer_tx,
    build_contract_tx, build_issue_tx, build_merge_tx, build_redeem_tx, build_split_tx,
    build_stas3_base_tx, build_stas3_freeze_tx, build_stas3_issue_txs, build_stas3_swap_cancel_tx,
    build_stas3_swap_flow_tx, build_stas3_swap_swap_tx, build_stas3_swap_swap_tx_with_pieces,
    build_stas3_transfer_swap_tx, build_stas3_unfreeze_tx, build_transfer_tx, BtgCheckpointConfig,
    BtgMergeConfig, BtgPayment, BtgSplitConfig, BtgTransferConfig, ContractConfig, IssueConfig,
    MergeConfig, RedeemConfig, SplitConfig, Stas3BaseConfig, Stas3IssueConfig, Stas3IssueOutput,
    Stas3IssueTxs, Stas3OutputParams, Stas3SwapCancelConfig, Stas3SwapPieceParams, TokenInput,
    TransferConfig,
};
pub use lineage::{LineageValidator, TxFetcher};
pub use proof::split_tx_around_output;
pub use scheme::{Authority, TokenScheme};
pub use script::stas3_builder::{
    build_stas3_flags, build_stas3_locking_script, build_stas3_locking_script_with_flags,
    freeze_var2_push, unfreeze_var2_push,
};
pub use script::stas3_pieces::{
    encode_atomic_swap_trailing_params, encode_merge_trailing_params, parse_trailing_params,
    ParsedTrailingParams, TrailingParamsError,
};
pub use script::stas3_swap::{
    compute_stas3_requested_script_hash, is_arbitrator_free_owner, is_stas3_frozen,
    resolve_stas3_swap_mode, EMPTY_HASH160,
};
pub use script::stas_btg_builder::build_stas_btg_locking_script;
pub use script::stas_builder::build_stas_locking_script;
pub use script_type::ScriptType;
pub use stas3::{verify_input as stas3_verify_input, Stas3VerifyError};
pub use template::stas::{StasMpkhUnlockingTemplate, StasUnlockingTemplate};
pub use template::stas3::{
    compute_input_preimage, encode_unlock_amount, push_unlock_amount, unlock_for_input,
    unlock_for_input_with_witness, unlock_mpkh_with_witness, unlock_with_witness,
    Stas3MpkhUnlockingTemplate, Stas3NoAuthUnlockingTemplate, Stas3TrailingParamsTemplate,
    Stas3UnlockWitness, Stas3UnlockingTemplate, Stas3WitnessChange, Stas3WitnessOutput,
};
pub use template::stas_btg::{StasBtgCheckpointUnlockingTemplate, StasBtgUnlockingTemplate};
pub use token_id::TokenId;
pub use types::{
    ActionData, Destination, NextVar2, OwnerAddress, Payment, SigningKey, Stas3Destination,
    Stas3LockingParams, Stas3SpendType, Stas3SwapMode, Stas3TxType, SwapDescriptor,
    SwapDescriptorError,
};
