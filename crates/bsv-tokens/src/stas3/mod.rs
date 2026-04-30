//! STAS 3.0 helpers that aren't part of the script-construction or
//! factory layers.
//!
//! Currently houses [`engine_verify::verify_input`], the end-to-end
//! script-engine smoke check that runs a factory-built tx through
//! `bsv_script::interpreter::Engine` with a real BIP-143 + ECDSA sighash
//! function.

pub mod engine_verify;

pub use engine_verify::{verify_input, Stas3VerifyError};
