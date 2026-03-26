//! Multi-transaction bundle factories for STAS and DSTAS operations.
//!
//! Requires the `bundle` feature.

pub mod planner;
pub mod stas_bundle;
pub mod dstas_bundle;

pub use planner::{PlannedOp, plan_operations};
pub use stas_bundle::{PayoutBundle, StasBundleConfig, TokenUtxo, FundingUtxo, build_stas_bundle};
pub use dstas_bundle::{
    DstasBundleFactory, BundleResult, BundleSpendType,
    StasOutPoint, FundingOutPoint, FundingRequest, Recipient,
    TransferOutput, TransferRequest,
    LockingParamsArgs, LockingParamsResult,
    AVG_FEE_FOR_DSTAS_MERGE,
};
