//! Token error types.

use bsv_primitives::PrimitivesError;
use bsv_script::ScriptError;
use bsv_transaction::TransactionError;

/// Errors that can occur during token operations.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// The token scheme is invalid.
    #[error("invalid scheme: {0}")]
    InvalidScheme(String),

    /// Token amounts do not match.
    #[error("amount mismatch: expected {expected}, actual {actual}")]
    AmountMismatch {
        /// Expected amount.
        expected: u64,
        /// Actual amount.
        actual: u64,
    },

    /// The script is invalid for the token operation.
    #[error("invalid script: {0}")]
    InvalidScript(String),

    /// The destination is invalid.
    #[error("invalid destination: {0}")]
    InvalidDestination(String),

    /// The authority configuration is invalid.
    #[error("invalid authority: {0}")]
    InvalidAuthority(String),

    /// Signing failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// The token is not splittable.
    #[error("token is not splittable")]
    NotSplittable,

    /// Insufficient funds for the operation.
    #[error("insufficient funds: needed {needed}, available {available}")]
    InsufficientFunds {
        /// Amount needed.
        needed: u64,
        /// Amount available.
        available: u64,
    },

    /// The token is frozen and cannot be used for this operation.
    #[error("token is frozen")]
    FrozenToken,

    /// The operation is restricted to the token issuer.
    #[error("issuer only: {0}")]
    IssuerOnly(String),

    /// Bundle operation error.
    #[error("bundle error: {0}")]
    BundleError(String),

    /// Transaction error.
    #[error(transparent)]
    Transaction(#[from] TransactionError),

    /// Script error.
    #[error(transparent)]
    Script(#[from] ScriptError),

    /// Primitives error.
    #[error(transparent)]
    Primitives(#[from] PrimitivesError),

    /// JSON serialization error.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
