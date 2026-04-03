//! Multi-transaction bundle factories for STAS and STAS3 operations.
//!
//! Requires the `bundle` feature.

pub mod planner;
pub mod stas_bundle;
pub mod stas3_bundle;

pub use planner::{PlannedOp, plan_operations};
pub use stas_bundle::{PayoutBundle, StasBundleConfig, TokenUtxo, FundingUtxo, build_stas_bundle};
pub use stas3_bundle::{
    Stas3BundleFactory, BundleResult, BundleSpendType,
    StasOutPoint, FundingOutPoint, FundingRequest, Recipient,
    TransferOutput, TransferRequest,
    LockingParamsArgs, LockingParamsResult,
    AVG_FEE_FOR_STAS3_MERGE,
};
