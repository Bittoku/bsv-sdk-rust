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

    /// STAS 3.0 §9.2 — Freeze tx must produce exactly one STAS output.
    #[error("freeze tx must produce exactly one STAS output, found {0}")]
    FreezeOutputCount(usize),

    /// STAS 3.0 §9.2 — Freeze output non-`var2` fields must be byte-identical
    /// to the input.
    #[error("freeze tx output drifted from input on field: {0}")]
    FreezeFieldDrift(&'static str),

    /// STAS 3.0 §9.2 — Freeze requires the FREEZABLE flag to be set on the
    /// input UTXO's `flags` byte.
    #[error("freeze tx requires the FREEZABLE flag bit set on the input")]
    FreezeFlagNotSet,

    /// STAS 3.0 §9.3 — Confiscation requires the CONFISCATABLE flag to be
    /// set on the input UTXO's `flags` byte.
    #[error("confiscate tx requires the CONFISCATABLE flag bit set on the input")]
    ConfiscateFlagNotSet,

    /// STAS 3.0 §9.4 — Swap cancellation requires exactly one output.
    #[error("swap cancel tx requires exactly one output, found {0}")]
    SwapCancelOutputCount(usize),

    /// STAS 3.0 §9.4 — Swap cancellation output owner must equal the input
    /// swap descriptor's `receiveAddr` (per spec §6.3).
    #[error("swap cancel output owner does not match input receiveAddr")]
    SwapCancelOwnerMismatch,

    /// STAS 3.0 §9.4 — Swap cancellation requires the input to carry a swap
    /// descriptor (action byte 0x01).
    #[error("swap cancel input must carry a swap descriptor (action 0x01)")]
    SwapCancelMissingDescriptor,

    /// STAS 3.0 §7 — `noteData` payload exceeds the 65 533-byte maximum.
    #[error("noteData payload too large: {0} bytes (max 65533)")]
    NoteDataTooLarge(usize),
}
