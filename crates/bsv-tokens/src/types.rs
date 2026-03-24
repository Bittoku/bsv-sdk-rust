//! Common types for token operations.

use serde::{Deserialize, Serialize};

use bsv_primitives::chainhash::Hash;
use bsv_primitives::ec::PrivateKey;
use bsv_script::{Address, Script};

/// A UTXO payment input for token transactions.
pub struct Payment {
    /// Transaction hash of the UTXO.
    pub txid: Hash,
    /// Output index within the transaction.
    pub vout: u32,
    /// Satoshi value of the UTXO.
    pub satoshis: u64,
    /// The locking script of the UTXO.
    pub locking_script: Script,
    /// Private key to sign this input.
    pub private_key: PrivateKey,
}

/// A destination for token transfer.
#[derive(Debug, Clone)]
pub struct Destination {
    /// The recipient address.
    pub address: Address,
    /// Satoshi amount to send.
    pub satoshis: u64,
}

/// dSTAS spending operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DstasSpendType {
    /// Standard token transfer.
    Transfer = 1,
    /// Freeze or unfreeze operation.
    FreezeUnfreeze = 2,
    /// Confiscation by authority.
    Confiscation = 3,
    /// Cancel a pending swap.
    SwapCancellation = 4,
}

/// Additional data attached to a dSTAS action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionData {
    /// Atomic swap action data.
    ///
    /// Encoded as 61 bytes per leg: 1 (kind 0x01) + 32 (hash) + 20 (PKH) +
    /// 4 (numerator LE) + 4 (denominator LE).
    Swap {
        /// SHA-256 hash of the counterparty's locking script tail.
        requested_script_hash: [u8; 32],
        /// The 20-byte public key hash of the requested recipient.
        requested_pkh: [u8; 20],
        /// Exchange rate numerator (little-endian u32).
        rate_numerator: u32,
        /// Exchange rate denominator (little-endian u32).
        rate_denominator: u32,
    },
    /// Custom application data.
    Custom(Vec<u8>),
}

/// The detected swap mode for a two-input DSTAS transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DstasSwapMode {
    /// One input is a regular transfer, the other is consumed via swap matching.
    TransferSwap,
    /// Both inputs have swap action data — atomic counter-swap.
    SwapSwap,
}

/// Parameters for constructing a dSTAS locking script.
#[derive(Debug, Clone)]
pub struct DstasLockingParams {
    /// The recipient address.
    pub address: Address,
    /// The spend type for this locking script.
    pub spend_type: DstasSpendType,
    /// Optional action data.
    pub action_data: Option<ActionData>,
}

/// A destination specific to dSTAS token operations.
#[derive(Debug, Clone)]
pub struct DstasDestination {
    /// The recipient address.
    pub address: Address,
    /// Satoshi amount.
    pub satoshis: u64,
    /// The dSTAS spend type.
    pub spend_type: DstasSpendType,
    /// Optional action data.
    pub action_data: Option<ActionData>,
}
