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
pub use scheme::{Authority, TokenScheme};
pub use token_id::TokenId;
pub use script_type::ScriptType;
pub use types::{Payment, Destination, Stas3SpendType, Stas3TxType, Stas3SwapMode, ActionData, Stas3LockingParams, Stas3Destination, SigningKey, OwnerAddress, SwapDescriptor, NextVar2, SwapDescriptorError};
pub use script::stas_builder::build_stas_locking_script;
pub use script::stas_btg_builder::build_stas_btg_locking_script;
pub use script::stas3_builder::{build_stas3_locking_script, build_stas3_locking_script_with_flags, build_stas3_flags, freeze_var2_push, unfreeze_var2_push};
pub use script::stas3_pieces::{
    encode_atomic_swap_trailing_params, encode_merge_trailing_params, parse_trailing_params,
    ParsedTrailingParams, TrailingParamsError,
};
pub use script::stas3_swap::{compute_stas3_requested_script_hash, resolve_stas3_swap_mode, is_stas3_frozen, is_arbitrator_free_owner, EMPTY_HASH160};
pub use template::stas::{StasUnlockingTemplate, StasMpkhUnlockingTemplate};
pub use template::stas_btg::{StasBtgUnlockingTemplate, StasBtgCheckpointUnlockingTemplate};
pub use template::stas3::{
    Stas3UnlockingTemplate, Stas3MpkhUnlockingTemplate, Stas3NoAuthUnlockingTemplate,
    Stas3TrailingParamsTemplate, encode_unlock_amount, push_unlock_amount, unlock_for_input,
    unlock_for_input_with_witness,
    Stas3UnlockWitness, Stas3WitnessOutput, Stas3WitnessChange, compute_input_preimage,
    unlock_with_witness, unlock_mpkh_with_witness,
};
pub use proof::split_tx_around_output;
pub use lineage::{LineageValidator, TxFetcher};
pub use stas3::{verify_input as stas3_verify_input, Stas3VerifyError};
pub use factory::{
    build_contract_tx, ContractConfig,
    build_issue_tx, build_transfer_tx, build_split_tx, build_merge_tx, build_redeem_tx,
    IssueConfig, TransferConfig, SplitConfig, MergeConfig, RedeemConfig,
    build_btg_transfer_tx, build_btg_split_tx, build_btg_merge_tx, build_btg_checkpoint_tx,
    BtgTransferConfig, BtgSplitConfig, BtgMergeConfig, BtgCheckpointConfig, BtgPayment,
    build_stas3_issue_txs, build_stas3_base_tx, build_stas3_freeze_tx, build_stas3_unfreeze_tx,
    build_stas3_swap_flow_tx, build_stas3_transfer_swap_tx, build_stas3_swap_swap_tx,
    build_stas3_swap_cancel_tx,
    Stas3IssueConfig, Stas3IssueOutput, Stas3IssueTxs,
    Stas3BaseConfig, Stas3OutputParams, Stas3SwapCancelConfig, TokenInput,
};
