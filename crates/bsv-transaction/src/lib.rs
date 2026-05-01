#![deny(missing_docs)]

//! BSV Blockchain SDK - Transaction building, signing, and serialization.
//!
//! Provides the Transaction type with inputs, outputs, fee calculation,
//! signature hash computation, and binary/hex serialization.

pub mod input;
pub mod output;
pub mod sighash;
pub mod template;
pub mod transaction;

mod error;
pub use error::TransactionError;
pub use input::TransactionInput;
pub use output::TransactionOutput;
pub use transaction::Transaction;

#[cfg(test)]
mod tests;
