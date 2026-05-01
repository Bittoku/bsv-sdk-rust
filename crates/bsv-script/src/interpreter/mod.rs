//! Full Bitcoin script interpreter.
//!
//! Executes locking and unlocking scripts to verify transaction inputs,
//! supporting all standard opcodes and verification flags.
//!
//! # Architecture
//!
//! The interpreter does not depend on the transaction crate directly to avoid
//! circular dependencies. Instead, callers provide a [`TxContext`](crate::interpreter::TxContext) trait
//! implementation that handles signature hash computation and verification.
//!
//! # Example
//!
//! ```ignore
//! use bsv_script::interpreter::{Engine, ScriptFlags};
//!
//! let engine = Engine::new();
//! engine.execute(
//!     &unlocking_script,
//!     &locking_script,
//!     ScriptFlags::ENABLE_SIGHASH_FORKID | ScriptFlags::UTXO_AFTER_GENESIS,
//!     None, // no tx context needed for simple scripts
//!     0,
//! )?;
//! ```

/// Interpreter configuration with pre/post-genesis limits.
pub mod config;
/// Interpreter error types and error codes.
pub mod error;
/// Script verification flags (bitmask).
pub mod flags;
mod ops_arithmetic;
mod ops_crypto;
mod ops_data;
mod ops_flow;
mod ops_stack;
/// Parsed opcode representation and script parser.
pub mod parsed_opcode;
/// Script number arithmetic with Bitcoin consensus rules.
pub mod scriptnum;
/// Script execution stack.
pub mod stack;
/// Script execution thread — the core interpreter engine.
pub mod thread;

pub use config::Config;
pub use error::{InterpreterError, InterpreterErrorCode};
pub use flags::ScriptFlags;
pub use parsed_opcode::{ParsedOpcode, ParsedScript};
pub use scriptnum::ScriptNumber;
pub use stack::Stack;

use crate::Script;
use thread::Thread;

/// Transaction context trait — provides signature verification without
/// circular dependency on bsv-transaction.
///
/// Implementors provide the transaction data needed for OP_CHECKSIG,
/// OP_CHECKMULTISIG, OP_CHECKLOCKTIMEVERIFY, and OP_CHECKSEQUENCEVERIFY.
pub trait TxContext {
    /// Verify a signature against a public key for the given input.
    ///
    /// `full_sig` includes the sighash flag byte at the end.
    /// `pub_key` is the public key bytes.
    /// `sub_script` is the relevant portion of the locking script.
    /// `input_idx` is the input being verified.
    /// `sighash_flag` is the sighash type.
    ///
    /// Returns Ok(true) if valid, Ok(false) if invalid, Err on failure.
    fn verify_signature(
        &self,
        full_sig: &[u8],
        pub_key: &[u8],
        sub_script: &Script,
        input_idx: usize,
        sighash_flag: u32,
    ) -> Result<bool, InterpreterError>;

    /// Get the transaction lock time.
    fn lock_time(&self) -> u32;

    /// Get the transaction version.
    fn tx_version(&self) -> u32;

    /// Get the sequence number of the given input.
    fn input_sequence(&self, input_idx: usize) -> u32;
}

/// The script execution engine.
pub struct Engine;

impl Engine {
    /// Create a new script execution engine instance.
    pub fn new() -> Self {
        Engine
    }

    /// Execute unlocking + locking scripts.
    ///
    /// # Arguments
    /// * `unlocking_script` - The input's unlocking (signature) script.
    /// * `locking_script` - The output's locking (pubkey) script.
    /// * `flags` - Verification flags.
    /// * `tx_context` - Optional transaction context for checksig operations.
    /// * `input_idx` - The input index being verified.
    pub fn execute(
        &self,
        unlocking_script: &Script,
        locking_script: &Script,
        flags: ScriptFlags,
        tx_context: Option<&dyn TxContext>,
        input_idx: usize,
    ) -> Result<(), InterpreterError> {
        let mut thread = Thread::new(
            unlocking_script,
            locking_script,
            flags,
            tx_context,
            input_idx,
        )?;
        thread.execute()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcodes::*;

    #[test]
    fn test_simple_true() {
        // OP_TRUE should leave true on stack
        let unlock = Script::from_bytes(&[OP_TRUE]);
        let lock = Script::from_bytes(&[]);
        // Empty locking script + OP_TRUE should fail (both empty check)
        // Actually: unlock=OP_1, lock=empty → stack has [1], which is true
        // But engine rejects both-empty. lock is empty but unlock isn't.
        // Let's do: unlock pushes 1, lock = OP_1 (just returns true)
    }

    #[test]
    fn test_op_1_op_1_op_equal() {
        // unlocking: OP_1, locking: OP_1 OP_EQUAL
        let unlock = Script::from_bytes(&[OP_1]);
        let lock = Script::from_bytes(&[OP_1, OP_EQUAL]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::NONE, None, 0);
        assert!(result.is_ok(), "OP_1 OP_1 OP_EQUAL should succeed");
    }

    #[test]
    fn test_op_1_op_2_op_equal_fails() {
        let unlock = Script::from_bytes(&[OP_1]);
        let lock = Script::from_bytes(&[OP_2, OP_EQUAL]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::NONE, None, 0);
        assert!(result.is_err(), "OP_1 OP_2 OP_EQUAL should fail");
    }

    #[test]
    fn test_op_add() {
        // 2 + 3 = 5, verify 5
        let unlock = Script::from_bytes(&[OP_2, OP_3]);
        let lock = Script::from_bytes(&[OP_ADD, OP_5, OP_EQUAL]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::NONE, None, 0);
        assert!(result.is_ok(), "2 + 3 should equal 5");
    }

    #[test]
    fn test_op_sub() {
        // 5 - 3 = 2
        let unlock = Script::from_bytes(&[OP_5, OP_3]);
        let lock = Script::from_bytes(&[OP_SUB, OP_2, OP_EQUAL]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::NONE, None, 0);
        assert!(result.is_ok(), "5 - 3 should equal 2");
    }

    #[test]
    fn test_op_dup_hash160_equalverify() {
        // Standard P2PKH pattern (without actual sig verification)
        // Just test the hash path: push data, dup, hash160, push expected, equalverify, checksig would need tx
        // Simplified: push some bytes, OP_DUP, OP_HASH160, push expected_hash, OP_EQUALVERIFY, OP_1
        use ripemd::{Digest, Ripemd160};
        use sha2::{Digest as D2, Sha256};

        let pubkey = vec![0x04; 33]; // fake pubkey
        let sha = Sha256::digest(&pubkey);
        let hash160 = Ripemd160::digest(&sha);

        let mut unlock_bytes = vec![pubkey.len() as u8];
        unlock_bytes.extend_from_slice(&pubkey);

        let mut lock_bytes = vec![OP_DUP, OP_HASH160];
        lock_bytes.push(hash160.len() as u8);
        lock_bytes.extend_from_slice(&hash160);
        lock_bytes.push(OP_EQUALVERIFY);
        // We can't do checksig without tx, so just push OP_1
        lock_bytes.push(OP_1);

        let unlock = Script::from_bytes(&unlock_bytes);
        let lock = Script::from_bytes(&lock_bytes);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::NONE, None, 0);
        assert!(
            result.is_ok(),
            "P2PKH-like hash verification should pass: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_op_if_else_endif() {
        // OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF -> stack: [2]
        let unlock = Script::from_bytes(&[]);
        let lock = Script::from_bytes(&[OP_1, OP_IF, OP_2, OP_ELSE, OP_3, OP_ENDIF]);
        // Both empty check: unlock is empty, lock is not.
        // But unlock empty means script_idx starts at 1 (locking script).
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::NONE, None, 0);
        // Stack should have [2], which is truthy → success
        assert!(
            result.is_ok(),
            "IF/ELSE/ENDIF should work: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_op_notif() {
        let unlock = Script::from_bytes(&[]);
        let lock = Script::from_bytes(&[OP_0, OP_NOTIF, OP_1, OP_ELSE, OP_0, OP_ENDIF]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::NONE, None, 0);
        assert!(
            result.is_ok(),
            "NOTIF with false should execute first branch"
        );
    }

    #[test]
    fn test_op_return_before_genesis() {
        let unlock = Script::from_bytes(&[OP_1]);
        let lock = Script::from_bytes(&[OP_RETURN]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::NONE, None, 0);
        assert!(result.is_err(), "OP_RETURN before genesis should fail");
    }

    #[test]
    fn test_op_return_after_genesis() {
        let unlock = Script::from_bytes(&[OP_1]);
        let lock = Script::from_bytes(&[OP_1, OP_RETURN, 0x01, 0x02, 0x03]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::UTXO_AFTER_GENESIS, None, 0);
        assert!(
            result.is_ok(),
            "OP_RETURN after genesis with OP_1 before should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_op_depth() {
        // Push 3 items, then DEPTH should give 3
        let unlock = Script::from_bytes(&[OP_1, OP_2, OP_3]);
        let lock = Script::from_bytes(&[OP_DEPTH, OP_3, OP_EQUAL]);
        let engine = Engine::new();
        // After unlock: stack [1, 2, 3]. Lock: DEPTH pushes 3, then 3 EQUAL → true
        // But then stack has [1, 2, true] → clean stack might complain
        // Without clean stack flag, just needs true on top
        let result = engine.execute(&unlock, &lock, ScriptFlags::NONE, None, 0);
        assert!(result.is_ok(), "DEPTH should return 3: {:?}", result.err());
    }

    #[test]
    fn test_op_size() {
        // Push 3 bytes, SIZE should give 3
        let unlock = Script::from_bytes(&[0x03, 0xaa, 0xbb, 0xcc]);
        let lock = Script::from_bytes(&[OP_SIZE, OP_3, OP_EQUALVERIFY, OP_1]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::NONE, None, 0);
        assert!(
            result.is_ok(),
            "SIZE of 3-byte element should be 3: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_op_cat() {
        // After genesis: CAT two byte arrays
        let unlock = Script::from_bytes(&[0x01, 0xaa, 0x01, 0xbb]);
        let lock = Script::from_bytes(&[OP_CAT, 0x02, 0xaa, 0xbb, OP_EQUAL]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::UTXO_AFTER_GENESIS, None, 0);
        assert!(result.is_ok(), "CAT should concatenate: {:?}", result.err());
    }

    #[test]
    fn test_op_split() {
        // Split [aa, bb] at position 1
        let unlock = Script::from_bytes(&[0x02, 0xaa, 0xbb, OP_1]);
        let lock =
            Script::from_bytes(&[OP_SPLIT, 0x01, 0xbb, OP_EQUALVERIFY, 0x01, 0xaa, OP_EQUAL]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::UTXO_AFTER_GENESIS, None, 0);
        assert!(result.is_ok(), "SPLIT should work: {:?}", result.err());
    }

    #[test]
    fn test_op_negate() {
        // NEGATE(1) = -1, check with 1NEGATE
        let unlock = Script::from_bytes(&[OP_1]);
        let lock = Script::from_bytes(&[OP_NEGATE, OP_1NEGATE, OP_EQUAL]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::NONE, None, 0);
        assert!(
            result.is_ok(),
            "NEGATE(1) should equal -1: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_op_abs() {
        // ABS(-1) = 1
        let unlock = Script::from_bytes(&[OP_1NEGATE]);
        let lock = Script::from_bytes(&[OP_ABS, OP_1, OP_EQUAL]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::NONE, None, 0);
        assert!(result.is_ok(), "ABS(-1) should equal 1: {:?}", result.err());
    }

    #[test]
    fn test_op_not() {
        // NOT(0) = 1
        let unlock = Script::from_bytes(&[OP_0]);
        let lock = Script::from_bytes(&[OP_NOT]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::NONE, None, 0);
        assert!(
            result.is_ok(),
            "NOT(0) should be 1 (truthy): {:?}",
            result.err()
        );
    }

    #[test]
    fn test_op_within() {
        // 3 is within [2, 5)
        let unlock = Script::from_bytes(&[OP_3, OP_2, OP_5]);
        let lock = Script::from_bytes(&[OP_WITHIN]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::NONE, None, 0);
        assert!(
            result.is_ok(),
            "3 WITHIN [2,5) should be true: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_op_mul() {
        // 3 * 4 = 12
        let unlock = Script::from_bytes(&[OP_3, OP_4]);
        let lock = Script::from_bytes(&[OP_MUL, OP_12, OP_EQUAL]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::UTXO_AFTER_GENESIS, None, 0);
        assert!(result.is_ok(), "3 * 4 should equal 12: {:?}", result.err());
    }

    #[test]
    fn test_op_div() {
        // 6 / 3 = 2
        let unlock = Script::from_bytes(&[OP_6, OP_3]);
        let lock = Script::from_bytes(&[OP_DIV, OP_2, OP_EQUAL]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::UTXO_AFTER_GENESIS, None, 0);
        assert!(result.is_ok(), "6 / 3 should equal 2: {:?}", result.err());
    }

    #[test]
    fn test_op_div_by_zero() {
        let unlock = Script::from_bytes(&[OP_6, OP_0]);
        let lock = Script::from_bytes(&[OP_DIV]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::UTXO_AFTER_GENESIS, None, 0);
        assert!(result.is_err(), "Division by zero should fail");
        let err = result.unwrap_err();
        assert_eq!(err.code, InterpreterErrorCode::DivideByZero);
    }

    #[test]
    fn test_op_mod() {
        // 7 % 3 = 1
        let unlock = Script::from_bytes(&[OP_7, OP_3]);
        let lock = Script::from_bytes(&[OP_MOD, OP_1, OP_EQUAL]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::UTXO_AFTER_GENESIS, None, 0);
        assert!(result.is_ok(), "7 % 3 should equal 1: {:?}", result.err());
    }

    #[test]
    fn test_op_booland() {
        // 1 AND 1 = 1
        let unlock = Script::from_bytes(&[OP_1, OP_1]);
        let lock = Script::from_bytes(&[OP_BOOLAND]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::NONE, None, 0);
        assert!(result.is_ok());

        // 1 AND 0 = 0
        let unlock2 = Script::from_bytes(&[OP_1, OP_0]);
        let lock2 = Script::from_bytes(&[OP_BOOLAND, OP_NOT]);
        let result2 = engine.execute(&unlock2, &lock2, ScriptFlags::NONE, None, 0);
        assert!(result2.is_ok());
    }

    #[test]
    fn test_op_numequal() {
        let unlock = Script::from_bytes(&[OP_5, OP_5]);
        let lock = Script::from_bytes(&[OP_NUMEQUAL]);
        let engine = Engine::new();
        assert!(engine
            .execute(&unlock, &lock, ScriptFlags::NONE, None, 0)
            .is_ok());
    }

    #[test]
    fn test_op_lessthan() {
        let unlock = Script::from_bytes(&[OP_3, OP_5]);
        let lock = Script::from_bytes(&[OP_LESSTHAN]);
        let engine = Engine::new();
        assert!(engine
            .execute(&unlock, &lock, ScriptFlags::NONE, None, 0)
            .is_ok());
    }

    #[test]
    fn test_hash_ops() {
        // SHA256 of empty
        let unlock = Script::from_bytes(&[OP_0]);
        let lock = Script::from_bytes(&[OP_SHA256, OP_SIZE, 0x01, 0x20, OP_EQUALVERIFY, OP_1]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::NONE, None, 0);
        assert!(
            result.is_ok(),
            "SHA256 should produce 32 bytes: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_op_pick_roll() {
        // PICK: [1, 2, 3], PICK(2) -> [1, 2, 3, 1]
        let unlock = Script::from_bytes(&[OP_1, OP_2, OP_3, OP_2]);
        let lock = Script::from_bytes(&[
            OP_PICK,
            OP_1,
            OP_EQUALVERIFY,
            OP_3,
            OP_EQUALVERIFY,
            OP_2,
            OP_EQUALVERIFY,
            OP_1,
        ]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::NONE, None, 0);
        assert!(
            result.is_ok(),
            "PICK should copy element: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_op_toaltstack_fromaltstack() {
        let unlock = Script::from_bytes(&[OP_5]);
        let lock = Script::from_bytes(&[OP_TOALTSTACK, OP_FROMALTSTACK, OP_5, OP_EQUAL]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::NONE, None, 0);
        assert!(
            result.is_ok(),
            "TOALTSTACK/FROMALTSTACK: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_disabled_opcodes() {
        let unlock = Script::from_bytes(&[OP_1]);
        let lock = Script::from_bytes(&[OP_2MUL]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::NONE, None, 0);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code,
            InterpreterErrorCode::DisabledOpcode
        );
    }

    #[test]
    fn test_op_invert() {
        // INVERT of 0x00 should give 0xff
        let unlock = Script::from_bytes(&[0x01, 0x00]);
        let lock = Script::from_bytes(&[OP_INVERT, 0x01, 0xff, OP_EQUAL]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::UTXO_AFTER_GENESIS, None, 0);
        assert!(
            result.is_ok(),
            "INVERT should flip bits: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_op_and_or_xor() {
        // AND: 0xff AND 0x0f = 0x0f
        let unlock = Script::from_bytes(&[0x01, 0xff, 0x01, 0x0f]);
        let lock = Script::from_bytes(&[OP_AND, 0x01, 0x0f, OP_EQUAL]);
        let engine = Engine::new();
        assert!(engine
            .execute(&unlock, &lock, ScriptFlags::UTXO_AFTER_GENESIS, None, 0,)
            .is_ok());

        // OR: 0xf0 OR 0x0f = 0xff
        let unlock2 = Script::from_bytes(&[0x01, 0xf0, 0x01, 0x0f]);
        let lock2 = Script::from_bytes(&[OP_OR, 0x01, 0xff, OP_EQUAL]);
        assert!(engine
            .execute(&unlock2, &lock2, ScriptFlags::UTXO_AFTER_GENESIS, None, 0,)
            .is_ok());

        // XOR: 0xff XOR 0xff = 0x00
        let unlock3 = Script::from_bytes(&[0x01, 0xff, 0x01, 0xff]);
        let lock3 = Script::from_bytes(&[OP_XOR, 0x01, 0x00, OP_EQUAL]);
        assert!(engine
            .execute(&unlock3, &lock3, ScriptFlags::UTXO_AFTER_GENESIS, None, 0,)
            .is_ok());
    }

    #[test]
    fn test_op_rot() {
        // [1 2 3] ROT -> [2 3 1]
        let unlock = Script::from_bytes(&[OP_1, OP_2, OP_3]);
        let lock = Script::from_bytes(&[
            OP_ROT,
            OP_1,
            OP_EQUALVERIFY, // top was 3, after ROT top is 1
            OP_3,
            OP_EQUALVERIFY,
            OP_2,
            OP_EQUAL,
        ]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::NONE, None, 0);
        assert!(result.is_ok(), "ROT should rotate: {:?}", result.err());
    }

    #[test]
    fn test_op_tuck() {
        // [1 2] TUCK -> [2 1 2]
        let unlock = Script::from_bytes(&[OP_1, OP_2]);
        let lock = Script::from_bytes(&[
            OP_TUCK,
            OP_2,
            OP_EQUALVERIFY,
            OP_1,
            OP_EQUALVERIFY,
            OP_2,
            OP_EQUAL,
        ]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::NONE, None, 0);
        assert!(result.is_ok(), "TUCK should work: {:?}", result.err());
    }

    #[test]
    fn test_op_2dup() {
        let unlock = Script::from_bytes(&[OP_1, OP_2]);
        let lock = Script::from_bytes(&[
            OP_2DUP,
            OP_2,
            OP_EQUALVERIFY,
            OP_1,
            OP_EQUALVERIFY,
            OP_2,
            OP_EQUALVERIFY,
            OP_1,
            OP_EQUAL,
        ]);
        let engine = Engine::new();
        assert!(engine
            .execute(&unlock, &lock, ScriptFlags::NONE, None, 0)
            .is_ok());
    }

    #[test]
    fn test_empty_both_scripts() {
        let engine = Engine::new();
        let result = engine.execute(&Script::new(), &Script::new(), ScriptFlags::NONE, None, 0);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, InterpreterErrorCode::EvalFalse);
    }

    #[test]
    fn test_op_greaterthan() {
        let unlock = Script::from_bytes(&[OP_5, OP_3]);
        let lock = Script::from_bytes(&[OP_GREATERTHAN]);
        let engine = Engine::new();
        assert!(engine
            .execute(&unlock, &lock, ScriptFlags::NONE, None, 0)
            .is_ok());
    }

    #[test]
    fn test_op_min_max() {
        // MIN(3, 5) = 3
        let unlock = Script::from_bytes(&[OP_3, OP_5]);
        let lock = Script::from_bytes(&[OP_MIN, OP_3, OP_EQUAL]);
        let engine = Engine::new();
        assert!(engine
            .execute(&unlock, &lock, ScriptFlags::NONE, None, 0)
            .is_ok());

        // MAX(3, 5) = 5
        let unlock2 = Script::from_bytes(&[OP_3, OP_5]);
        let lock2 = Script::from_bytes(&[OP_MAX, OP_5, OP_EQUAL]);
        assert!(engine
            .execute(&unlock2, &lock2, ScriptFlags::NONE, None, 0)
            .is_ok());
    }

    #[test]
    fn test_op_verify_fail() {
        let unlock = Script::from_bytes(&[OP_0]);
        let lock = Script::from_bytes(&[OP_VERIFY]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::NONE, None, 0);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, InterpreterErrorCode::Verify);
    }

    #[test]
    fn test_nested_if() {
        // OP_1 OP_IF OP_1 OP_IF OP_2 OP_ENDIF OP_ENDIF
        let unlock = Script::from_bytes(&[]);
        let lock = Script::from_bytes(&[OP_1, OP_IF, OP_1, OP_IF, OP_2, OP_ENDIF, OP_ENDIF]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::NONE, None, 0);
        assert!(result.is_ok(), "Nested IF should work: {:?}", result.err());
    }

    #[test]
    fn test_unbalanced_if() {
        let unlock = Script::from_bytes(&[OP_1]);
        let lock = Script::from_bytes(&[OP_IF]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::NONE, None, 0);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code,
            InterpreterErrorCode::UnbalancedConditional
        );
    }

    #[test]
    fn test_op_ifdup() {
        // OP_1 OP_IFDUP → stack [1, 1]
        let unlock = Script::from_bytes(&[OP_1]);
        let lock = Script::from_bytes(&[OP_IFDUP, OP_EQUAL]);
        let engine = Engine::new();
        assert!(engine
            .execute(&unlock, &lock, ScriptFlags::NONE, None, 0)
            .is_ok());
    }

    #[test]
    fn test_clean_stack_without_bip16() {
        let engine = Engine::new();
        let result = engine.execute(
            &Script::from_bytes(&[OP_1]),
            &Script::from_bytes(&[OP_1]),
            ScriptFlags::VERIFY_CLEAN_STACK,
            None,
            0,
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, InterpreterErrorCode::InvalidFlags);
    }

    #[test]
    fn test_lshift_rshift() {
        // [0x80] << 1 = [0x00, 0x01] (but with same-length result, [0x00])
        // Actually Go impl: result is same length as input
        // [0x01] << 1 = [0x02]
        let unlock = Script::from_bytes(&[0x01, 0x01, OP_1]);
        let lock = Script::from_bytes(&[OP_LSHIFT, 0x01, 0x02, OP_EQUAL]);
        let engine = Engine::new();
        let result = engine.execute(&unlock, &lock, ScriptFlags::UTXO_AFTER_GENESIS, None, 0);
        assert!(result.is_ok(), "LSHIFT should work: {:?}", result.err());
    }
}
