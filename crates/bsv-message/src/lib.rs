#![deny(missing_docs)]

//! BSV Blockchain SDK - BRC-78 message encryption and BRC-77 message signing.
//!
//! Provides encrypted message exchange between parties using EC key pairs
//! and symmetric encryption, as well as message signing and verification.

pub mod encrypted;
mod error;
pub mod signed;

pub use encrypted::{decrypt, encrypt};
pub use error::MessageError;
pub use signed::{sign, verify};
