//! Script execution thread — the core interpreter engine.

use crate::opcodes::*;
use crate::Script;

use super::config::Config;
use super::error::{InterpreterError, InterpreterErrorCode};
use super::flags::ScriptFlags;
use super::ops_crypto::HashType;
use super::parsed_opcode::*;
use super::scriptnum::*;
use super::stack::*;
use super::TxContext;

// ---------------------------------------------------------------------------
// Optional opcode tracing (diagnostic). Zero-cost when STAS3_TRACE is unset.
// Activate by setting STAS3_TRACE=1 (or any non-empty value) in the
// environment. Output goes to stderr (one line per executed step).
// Format: TRACE step={N} script={S}:{O} op=0x{HH}({NAME}) depth={D} top5=[..]
// ---------------------------------------------------------------------------
fn stas3_trace_enabled() -> bool {
    use std::sync::atomic::{AtomicU8, Ordering};
    static CACHE: AtomicU8 = AtomicU8::new(0xff); // 0xff=uninit, 0=off, 1=on
    let v = CACHE.load(Ordering::Relaxed);
    if v != 0xff {
        return v == 1;
    }
    let on = std::env::var("STAS3_TRACE")
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    CACHE.store(if on { 1 } else { 0 }, Ordering::Relaxed);
    on
}

fn fmt_top(stk: &[Vec<u8>], n: usize) -> String {
    let len = stk.len();
    let take = n.min(len);
    let mut out = String::from("[");
    // Bottom-of-window..top: print depth indices for clarity.
    for i in 0..take {
        let item = &stk[len - 1 - i]; // top = i=0
        let hex: String = item.iter().map(|b| format!("{:02x}", b)).collect();
        let display = if hex.len() > 64 {
            format!("{}..(len={})", &hex[..64], item.len())
        } else {
            hex
        };
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&format!("@-{}={}", i, display));
    }
    out.push(']');
    out
}

/// Conditional execution constants.
const OP_COND_FALSE: i32 = 0;
const OP_COND_TRUE: i32 = 1;

/// The execution thread for the script interpreter.
pub struct Thread<'a> {
    /// The main data stack used during script execution.
    pub dstack: Stack,
    /// The alternate stack used by OP_TOALTSTACK and OP_FROMALTSTACK.
    pub astack: Stack,
    /// Stack tracking nested IF/ELSE/ENDIF conditional execution state.
    pub else_stack: BoolStack,
    /// Interpreter configuration with pre/post-genesis limits.
    pub cfg: Config,
    /// The parsed scripts to execute (unlocking, locking, and optionally P2SH).
    pub scripts: Vec<ParsedScript>,
    /// Stack of conditional execution flags for nested IF/ELSE blocks.
    pub cond_stack: Vec<i32>,
    /// Saved copy of the data stack after the first (unlocking) script for BIP16.
    pub saved_first_stack: Vec<Vec<u8>>,
    /// Index of the currently executing script in the scripts array.
    pub script_idx: usize,
    /// Offset of the currently executing opcode within the current script.
    pub script_off: usize,
    /// Offset of the most recent OP_CODESEPARATOR in the current script.
    pub last_code_sep: usize,
    /// Running count of non-push opcodes executed (checked against max_ops).
    pub num_ops: usize,
    /// Active script verification flags controlling interpreter behavior.
    pub flags: ScriptFlags,
    /// Whether BIP16 (P2SH) evaluation is active for this execution.
    pub bip16: bool,
    /// Whether post-genesis rules are active (relaxed limits, OP_RETURN behavior).
    pub after_genesis: bool,
    /// Whether an OP_RETURN has been encountered in post-genesis mode.
    pub early_return_after_genesis: bool,
    /// Optional transaction context for signature and locktime verification.
    pub tx_context: Option<&'a dyn TxContext>,
    /// The transaction input index being verified.
    pub input_idx: usize,
}

impl<'a> Thread<'a> {
    /// Create a new execution thread from unlocking and locking scripts.
    ///
    /// Validates script sizes, parses both scripts, and initializes the
    /// execution environment with the appropriate flags and configuration.
    pub fn new(
        unlocking_script: &Script,
        locking_script: &Script,
        flags: ScriptFlags,
        tx_context: Option<&'a dyn TxContext>,
        input_idx: usize,
    ) -> Result<Self, InterpreterError> {
        let after_genesis = flags.has_flag(ScriptFlags::UTXO_AFTER_GENESIS);
        let cfg = if after_genesis {
            Config::after_genesis()
        } else {
            Config::before_genesis()
        };

        let mut actual_flags = flags;

        // ForkID implies strict encoding
        if actual_flags.has_flag(ScriptFlags::ENABLE_SIGHASH_FORKID) {
            actual_flags.add_flag(ScriptFlags::VERIFY_STRICT_ENCODING);
        }

        // Clean stack requires BIP16
        if actual_flags.has_flag(ScriptFlags::VERIFY_CLEAN_STACK)
            && !actual_flags.has_flag(ScriptFlags::BIP16)
        {
            return Err(InterpreterError::new(
                InterpreterErrorCode::InvalidFlags,
                "invalid scriptflag combination".to_string(),
            ));
        }

        let verify_minimal_data = actual_flags.has_flag(ScriptFlags::VERIFY_MINIMAL_DATA);

        // Validate script sizes
        if unlocking_script.to_bytes().len() > cfg.max_script_size() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::ScriptTooBig,
                format!(
                    "unlocking script size {} is larger than the max allowed size {}",
                    unlocking_script.to_bytes().len(),
                    cfg.max_script_size()
                ),
            ));
        }
        if locking_script.to_bytes().len() > cfg.max_script_size() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::ScriptTooBig,
                format!(
                    "locking script size {} is larger than the max allowed size {}",
                    locking_script.to_bytes().len(),
                    cfg.max_script_size()
                ),
            ));
        }

        // Empty scripts = eval false
        if unlocking_script.to_bytes().is_empty() && locking_script.to_bytes().is_empty() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::EvalFalse,
                "false stack entry at end of script execution".to_string(),
            ));
        }

        let error_on_checksig = tx_context.is_none();

        let uscript = parse_script(unlocking_script, error_on_checksig)?;
        let lscript = parse_script(locking_script, error_on_checksig)?;

        // Verify sig push only
        if actual_flags.has_flag(ScriptFlags::VERIFY_SIG_PUSH_ONLY) && !is_push_only(&uscript) {
            return Err(InterpreterError::new(
                InterpreterErrorCode::NotPushOnly,
                "signature script is not push only".to_string(),
            ));
        }

        let bip16 = actual_flags.has_flag(ScriptFlags::BIP16) && locking_script.is_p2sh();
        if bip16 && !is_push_only(&uscript) {
            return Err(InterpreterError::new(
                InterpreterErrorCode::NotPushOnly,
                "pay to script hash is not push only".to_string(),
            ));
        }

        let scripts = vec![uscript, lscript];
        let mut script_idx = 0;

        // Skip empty unlocking script
        if unlocking_script.to_bytes().is_empty() {
            script_idx = 1;
        }

        let max_num_len = cfg.max_script_number_length();

        let thread = Thread {
            dstack: Stack::new(max_num_len, after_genesis, verify_minimal_data),
            astack: Stack::new(max_num_len, after_genesis, verify_minimal_data),
            else_stack: BoolStack::new(),
            cfg,
            scripts,
            cond_stack: Vec::new(),
            saved_first_stack: Vec::new(),
            script_idx,
            script_off: 0,
            last_code_sep: 0,
            num_ops: 0,
            flags: actual_flags,
            bip16,
            after_genesis,
            early_return_after_genesis: false,
            tx_context,
            input_idx,
        };

        Ok(thread)
    }

    /// Check if a specific script verification flag is set.
    pub fn has_flag(&self, flag: ScriptFlags) -> bool {
        self.flags.has_flag(flag)
    }

    /// Check if any of the given script verification flags are set.
    pub fn has_any(&self, flags: &[ScriptFlags]) -> bool {
        self.flags.has_any(flags)
    }

    /// Return true if the current conditional branch is executing.
    pub fn is_branch_executing(&self) -> bool {
        self.cond_stack.is_empty() || *self.cond_stack.last().unwrap() == OP_COND_TRUE
    }

    /// Return true if the given opcode should be executed in the current state.
    pub fn should_exec(&self, pop: &ParsedOpcode) -> bool {
        if !self.after_genesis {
            return true;
        }
        let cf = self.cond_stack.iter().all(|&v| v != OP_COND_FALSE);
        cf && (!self.early_return_after_genesis || pop.opcode == OP_RETURN)
    }

    /// Execute all scripts.
    pub fn execute(&mut self) -> Result<(), InterpreterError> {
        loop {
            let done = self.step()?;
            if done {
                break;
            }
        }
        self.check_error_condition(true)
    }

    /// Execute one step. Returns true if execution is complete.
    pub fn step(&mut self) -> Result<bool, InterpreterError> {
        // Valid PC check
        if self.script_idx >= self.scripts.len() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::InvalidProgramCounter,
                format!(
                    "past input scripts {}:{} {}:xxxx",
                    self.script_idx,
                    self.script_off,
                    self.scripts.len()
                ),
            ));
        }
        if self.script_off >= self.scripts[self.script_idx].len() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::InvalidProgramCounter,
                format!(
                    "past input scripts {}:{} {}:{:04}",
                    self.script_idx,
                    self.script_off,
                    self.script_idx,
                    self.scripts[self.script_idx].len()
                ),
            ));
        }

        let opcode = self.scripts[self.script_idx][self.script_off].clone();

        // Diagnostic tracing (gated on STAS3_TRACE env var; cached).
        if stas3_trace_enabled() {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static STEP: AtomicUsize = AtomicUsize::new(0);
            let step_no = STEP.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "TRACE step={} script={}:{} op=0x{:02x}({}) data_len={} depth={} astack={} top5={}",
                step_no,
                self.script_idx,
                self.script_off,
                opcode.opcode,
                opcode.name(),
                opcode.data.len(),
                self.dstack.depth(),
                self.astack.depth(),
                fmt_top(&self.dstack.stk, 5),
            );
        }

        if let Err(e) = self.execute_opcode(&opcode) {
            if e.code == InterpreterErrorCode::Ok {
                // Early success (OP_RETURN after genesis)
                self.shift_script();
                return Ok(self.script_idx >= self.scripts.len());
            }
            return Err(e);
        }

        self.script_off += 1;

        // Stack size check
        let combined = self.dstack.depth() + self.astack.depth();
        if combined > self.cfg.max_stack_size() as i32 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::StackOverflow,
                format!(
                    "combined stack size {} > max allowed {}",
                    combined,
                    self.cfg.max_stack_size()
                ),
            ));
        }

        if self.script_off < self.scripts[self.script_idx].len() {
            return Ok(false);
        }

        // End of script - check conditionals
        if !self.cond_stack.is_empty() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::UnbalancedConditional,
                "end of script reached in conditional execution".to_string(),
            ));
        }

        // Alt stack doesn't persist between scripts
        self.astack.clear();

        // Move to next script
        self.shift_script();

        // BIP16 handling
        if self.bip16 && !self.after_genesis && self.script_idx <= 2 {
            match self.script_idx {
                1 => {
                    self.saved_first_stack = self.dstack.get_stack();
                }
                2 => {
                    self.check_error_condition(false)?;
                    let scr_bytes = self.saved_first_stack.last().cloned().unwrap_or_default();
                    let scr = Script::from_bytes(&scr_bytes);
                    let pops = parse_script(&scr, false)?;
                    self.scripts.push(pops);
                    let len = self.saved_first_stack.len();
                    let new_stack = self.saved_first_stack[..len.saturating_sub(1)].to_vec();
                    self.dstack.set_stack(new_stack);
                }
                _ => {}
            }
        }

        // Skip zero-length scripts
        if self.script_idx < self.scripts.len()
            && self.script_off >= self.scripts[self.script_idx].len()
        {
            self.script_idx += 1;
        }

        self.last_code_sep = 0;
        if self.script_idx >= self.scripts.len() {
            return Ok(true);
        }

        Ok(false)
    }

    fn shift_script(&mut self) {
        self.num_ops = 0;
        self.script_off = 0;
        self.script_idx += 1;
        self.early_return_after_genesis = false;
    }

    fn check_error_condition(&mut self, final_script: bool) -> Result<(), InterpreterError> {
        if self.dstack.depth() < 1 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::EmptyStack,
                "stack empty at end of script execution".to_string(),
            ));
        }

        if final_script
            && self.has_flag(ScriptFlags::VERIFY_CLEAN_STACK)
            && self.dstack.depth() != 1
        {
            return Err(InterpreterError::new(
                InterpreterErrorCode::CleanStack,
                format!(
                    "stack contains {} unexpected items",
                    self.dstack.depth() - 1
                ),
            ));
        }

        let v = self.dstack.pop_bool()?;
        if !v {
            return Err(InterpreterError::new(
                InterpreterErrorCode::EvalFalse,
                "false stack entry at end of script execution".to_string(),
            ));
        }

        Ok(())
    }

    fn execute_opcode(&mut self, pop: &ParsedOpcode) -> Result<(), InterpreterError> {
        // Element size check
        if pop.data.len() > self.cfg.max_script_element_size() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::ElementTooBig,
                format!(
                    "element size {} exceeds max allowed size {}",
                    pop.data.len(),
                    self.cfg.max_script_element_size()
                ),
            ));
        }

        let exec = self.should_exec(pop);

        // Disabled opcodes fail on program counter
        if pop.is_disabled() && (!self.after_genesis || exec) {
            return Err(InterpreterError::new(
                InterpreterErrorCode::DisabledOpcode,
                format!("attempt to execute disabled opcode {}", pop.name()),
            ));
        }

        // Always-illegal opcodes
        if pop.always_illegal() && !self.after_genesis {
            return Err(InterpreterError::new(
                InterpreterErrorCode::ReservedOpcode,
                format!("attempt to execute reserved opcode {}", pop.name()),
            ));
        }

        // Count non-push operations
        if pop.opcode > OP_16 {
            self.num_ops += 1;
            if self.num_ops > self.cfg.max_ops() {
                return Err(InterpreterError::new(
                    InterpreterErrorCode::TooManyOperations,
                    format!("exceeded max operation limit of {}", self.cfg.max_ops()),
                ));
            }
        }

        // Not executing and not conditional => skip
        if !self.is_branch_executing() && !pop.is_conditional() {
            return Ok(());
        }

        // Minimal data push check
        if self.dstack.verify_minimal_data
            && self.is_branch_executing()
            && pop.opcode <= OP_PUSHDATA4
            && exec
        {
            pop.enforce_minimum_data_push()?;
        }

        // If we already hit OP_RETURN, skip non-conditionals
        if !exec && !pop.is_conditional() {
            return Ok(());
        }

        // Dispatch
        self.dispatch_opcode(pop)
    }

    fn dispatch_opcode(&mut self, pop: &ParsedOpcode) -> Result<(), InterpreterError> {
        match pop.opcode {
            OP_FALSE => {
                self.dstack.push_byte_array(vec![]);
                Ok(())
            }
            op if (OP_DATA_1..=OP_DATA_75).contains(&op) => {
                self.dstack.push_byte_array(pop.data.clone());
                Ok(())
            }
            OP_PUSHDATA1 | OP_PUSHDATA2 | OP_PUSHDATA4 => {
                self.dstack.push_byte_array(pop.data.clone());
                Ok(())
            }
            OP_1NEGATE => {
                self.dstack
                    .push_int(&ScriptNumber::new(-1, self.after_genesis));
                Ok(())
            }
            OP_RESERVED => self.op_reserved(pop),
            op if (OP_1..=OP_16).contains(&op) => {
                self.dstack.push_byte_array(vec![op - (OP_1 - 1)]);
                Ok(())
            }
            OP_NOP => Ok(()),
            OP_VER => self.op_reserved(pop),
            OP_IF => self.op_if(pop),
            OP_NOTIF => self.op_notif(pop),
            OP_VERIF | OP_VERNOTIF => self.op_ver_conditional(pop),
            OP_ELSE => self.op_else(pop),
            OP_ENDIF => self.op_endif(pop),
            OP_VERIFY => self.op_verify(pop),
            OP_RETURN => self.op_return(),

            // Locktime
            OP_CHECKLOCKTIMEVERIFY => self.op_check_locktime_verify(),
            OP_CHECKSEQUENCEVERIFY => self.op_check_sequence_verify(),

            // Stack ops
            OP_TOALTSTACK => self.op_to_alt_stack(),
            OP_FROMALTSTACK => self.op_from_alt_stack(),
            OP_2DROP => self.dstack.drop_n(2),
            OP_2DUP => self.dstack.dup_n(2),
            OP_3DUP => self.dstack.dup_n(3),
            OP_2OVER => self.dstack.over_n(2),
            OP_2ROT => self.dstack.rot_n(2),
            OP_2SWAP => self.dstack.swap_n(2),
            OP_IFDUP => self.op_ifdup(),
            OP_DEPTH => {
                let d = self.dstack.depth();
                self.dstack
                    .push_int(&ScriptNumber::new(d as i64, self.after_genesis));
                Ok(())
            }
            OP_DROP => self.dstack.drop_n(1),
            OP_DUP => self.dstack.dup_n(1),
            OP_NIP => self.dstack.nip_n_discard(1),
            OP_OVER => self.dstack.over_n(1),
            OP_PICK => self.op_pick(),
            OP_ROLL => self.op_roll(),
            OP_ROT => self.dstack.rot_n(1),
            OP_SWAP => self.dstack.swap_n(1),
            OP_TUCK => self.dstack.tuck(),

            // Splice
            OP_CAT => self.op_cat(),
            OP_SPLIT => self.op_split(),
            OP_NUM2BIN => self.op_num2bin(),
            OP_BIN2NUM => self.op_bin2num(),
            OP_SIZE => self.op_size(),

            // Bitwise
            OP_INVERT => self.op_invert(),
            OP_AND => self.op_bitwise(|a, b| a & b),
            OP_OR => self.op_bitwise(|a, b| a | b),
            OP_XOR => self.op_bitwise(|a, b| a ^ b),
            OP_EQUAL => self.op_equal(),
            OP_EQUALVERIFY => self.op_equalverify(pop),
            OP_RESERVED1 | OP_RESERVED2 => self.op_reserved(pop),

            // Arithmetic
            OP_1ADD => self.op_unary_int(|m| {
                m.incr();
            }),
            OP_1SUB => self.op_unary_int(|m| {
                m.decr();
            }),
            OP_2MUL | OP_2DIV => Err(InterpreterError::new(
                InterpreterErrorCode::DisabledOpcode,
                format!("attempt to execute disabled opcode {}", pop.name()),
            )),
            OP_NEGATE => self.op_unary_int(|m| {
                m.neg();
            }),
            OP_ABS => self.op_unary_int(|m| {
                m.abs();
            }),
            OP_NOT => self.op_not(),
            OP_0NOTEQUAL => self.op_0notequal(),
            OP_ADD => self.op_add(),
            OP_SUB => self.op_sub(),
            OP_MUL => self.op_mul(),
            OP_DIV => self.op_div(),
            OP_MOD => self.op_mod(),
            OP_LSHIFT => self.op_lshift(),
            OP_RSHIFT => self.op_rshift(),
            OP_BOOLAND => self.op_bool_binop(|a, b| !a.is_zero() && !b.is_zero()),
            OP_BOOLOR => self.op_bool_binop(|a, b| !a.is_zero() || !b.is_zero()),
            OP_NUMEQUAL => self.op_bool_binop(|a, b| a.equal(b)),
            OP_NUMEQUALVERIFY => self.op_numequalverify(pop),
            OP_NUMNOTEQUAL => self.op_bool_binop(|a, b| !a.equal(b)),
            OP_LESSTHAN => self.op_bool_binop(|a, b| a.less_than(b)),
            OP_GREATERTHAN => self.op_bool_binop(|a, b| a.greater_than(b)),
            OP_LESSTHANOREQUAL => self.op_bool_binop(|a, b| a.less_than_or_equal(b)),
            OP_GREATERTHANOREQUAL => self.op_bool_binop(|a, b| a.greater_than_or_equal(b)),
            OP_MIN => self.op_min(),
            OP_MAX => self.op_max(),
            OP_WITHIN => self.op_within(),

            // Crypto
            OP_RIPEMD160 => self.op_hash(HashType::Ripemd160),
            OP_SHA1 => self.op_hash(HashType::Sha1),
            OP_SHA256 => self.op_hash(HashType::Sha256),
            OP_HASH160 => self.op_hash(HashType::Hash160),
            OP_HASH256 => self.op_hash(HashType::Hash256),
            OP_CODESEPARATOR => {
                self.last_code_sep = self.script_off;
                Ok(())
            }
            OP_CHECKSIG => self.op_checksig(),
            OP_CHECKSIGVERIFY => self.op_checksigverify(pop),
            OP_CHECKMULTISIG => self.op_checkmultisig(),
            OP_CHECKMULTISIGVERIFY => self.op_checkmultisigverify(pop),

            // NOP opcodes
            OP_NOP1 | OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7 | OP_NOP8 | OP_NOP9 | OP_NOP10 => {
                if self.has_flag(ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS) {
                    return Err(InterpreterError::new(
                        InterpreterErrorCode::DiscourageUpgradableNOPs,
                        format!(
                            "OP_NOP{} reserved for soft-fork upgrades",
                            pop.opcode - (OP_NOP1 - 1)
                        ),
                    ));
                }
                Ok(())
            }

            // All unknown/invalid opcodes
            _ => Err(InterpreterError::new(
                InterpreterErrorCode::ReservedOpcode,
                format!("attempt to execute invalid opcode {}", pop.name()),
            )),
        }
    }
}
