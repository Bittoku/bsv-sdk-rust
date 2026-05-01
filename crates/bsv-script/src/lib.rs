#![deny(missing_docs)]
#![allow(
    clippy::collapsible_if,
    clippy::empty_line_after_doc_comments,
    clippy::if_same_then_else,
    clippy::manual_range_contains,
    clippy::needless_borrows_for_generic_args,
    clippy::new_without_default,
    clippy::question_mark,
    clippy::single_match,
    unused_imports
)]

//! BSV Blockchain SDK - Script parsing, execution, and address handling.
//!
//! Provides the Bitcoin Script type, opcode definitions, script chunk parsing,
//! address generation/validation, and a full script interpreter engine.

/// Bitcoin address generation and validation (P2PKH, P2SH).
pub mod address;
/// Script chunk parsing for extracting data pushes and opcodes.
pub mod chunk;
/// Full Bitcoin script interpreter engine.
pub mod interpreter;
/// Bitcoin Script opcode constant definitions.
pub mod opcodes;
/// Bitcoin Script type with serialization and template detection.
pub mod script;

mod error;
pub use address::{Address, Network};
pub use chunk::ScriptChunk;
pub use error::ScriptError;
pub use script::Script;
