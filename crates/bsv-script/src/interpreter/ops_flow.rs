//! Flow control operations for the script interpreter.

use super::error::{InterpreterError, InterpreterErrorCode};
use super::flags::ScriptFlags;
use super::parsed_opcode::ParsedOpcode;
use super::scriptnum::ScriptNumber;
use super::stack::as_bool;
use super::thread::Thread;

/// Conditional execution constants.
const OP_COND_FALSE: i32 = 0;
const OP_COND_TRUE: i32 = 1;
const OP_COND_SKIP: i32 = 2;

/// Lock time threshold (block vs timestamp).
const LOCK_TIME_THRESHOLD: i64 = 500000000;

/// Max sequence number.
const MAX_TX_IN_SEQUENCE_NUM: u32 = 0xffffffff;
/// Sequence lock time disabled bit.
const SEQUENCE_LOCK_TIME_DISABLED: u32 = 1 << 31;
/// Sequence lock time is seconds flag.
const SEQUENCE_LOCK_TIME_IS_SECONDS: i64 = 1 << 22;
/// Sequence lock time mask.
const SEQUENCE_LOCK_TIME_MASK: i64 = 0x0000ffff;

impl<'a> Thread<'a> {
    pub(crate) fn op_reserved(&self, pop: &ParsedOpcode) -> Result<(), InterpreterError> {
        Err(InterpreterError::new(
            InterpreterErrorCode::ReservedOpcode,
            format!("attempt to execute reserved opcode {}", pop.name()),
        ))
    }

    pub(crate) fn op_ver_conditional(
        &mut self,
        pop: &ParsedOpcode,
    ) -> Result<(), InterpreterError> {
        if self.after_genesis && !self.should_exec(pop) {
            return Ok(());
        }
        self.op_reserved(pop)
    }

    pub(crate) fn pop_if_bool(&mut self) -> Result<bool, InterpreterError> {
        if self.has_flag(ScriptFlags::VERIFY_MINIMAL_IF) {
            let b = self.dstack.pop_byte_array()?;
            if b.len() > 1 {
                return Err(InterpreterError::new(
                    InterpreterErrorCode::MinimalIf,
                    format!("conditional has data of length {}", b.len()),
                ));
            }
            if b.len() == 1 && b[0] != 1 {
                return Err(InterpreterError::new(
                    InterpreterErrorCode::MinimalIf,
                    "conditional failed".to_string(),
                ));
            }
            return Ok(as_bool(&b));
        }
        self.dstack.pop_bool()
    }

    pub(crate) fn op_if(&mut self, pop: &ParsedOpcode) -> Result<(), InterpreterError> {
        let mut cond_val = OP_COND_FALSE;
        if self.should_exec(pop) {
            if self.is_branch_executing() {
                let ok = self.pop_if_bool()?;
                if ok {
                    cond_val = OP_COND_TRUE;
                }
            } else {
                cond_val = OP_COND_SKIP;
            }
        }
        self.cond_stack.push(cond_val);
        self.else_stack.push_bool(false);
        Ok(())
    }

    pub(crate) fn op_notif(&mut self, pop: &ParsedOpcode) -> Result<(), InterpreterError> {
        let mut cond_val = OP_COND_FALSE;
        if self.should_exec(pop) {
            if self.is_branch_executing() {
                let ok = self.pop_if_bool()?;
                if !ok {
                    cond_val = OP_COND_TRUE;
                }
            } else {
                cond_val = OP_COND_SKIP;
            }
        }
        self.cond_stack.push(cond_val);
        self.else_stack.push_bool(false);
        Ok(())
    }

    pub(crate) fn op_else(&mut self, pop: &ParsedOpcode) -> Result<(), InterpreterError> {
        if self.cond_stack.is_empty() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::UnbalancedConditional,
                format!(
                    "encountered opcode {} with no matching opcode to begin conditional execution",
                    pop.name()
                ),
            ));
        }

        let ok = self.else_stack.pop_bool()?;
        if ok {
            return Err(InterpreterError::new(
                InterpreterErrorCode::UnbalancedConditional,
                format!(
                    "encountered opcode {} with no matching opcode to begin conditional execution",
                    pop.name()
                ),
            ));
        }

        let idx = self.cond_stack.len() - 1;
        match self.cond_stack[idx] {
            OP_COND_TRUE => self.cond_stack[idx] = OP_COND_FALSE,
            OP_COND_FALSE => self.cond_stack[idx] = OP_COND_TRUE,
            _ => {} // OP_COND_SKIP stays
        }

        self.else_stack.push_bool(true);
        Ok(())
    }

    pub(crate) fn op_endif(&mut self, pop: &ParsedOpcode) -> Result<(), InterpreterError> {
        if self.cond_stack.is_empty() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::UnbalancedConditional,
                format!(
                    "encountered opcode {} with no matching opcode to begin conditional execution",
                    pop.name()
                ),
            ));
        }
        self.cond_stack.pop();
        self.else_stack.pop_bool()?;
        Ok(())
    }

    pub(crate) fn op_verify(&mut self, pop: &ParsedOpcode) -> Result<(), InterpreterError> {
        self.abstract_verify(pop, InterpreterErrorCode::Verify)
    }

    pub(crate) fn abstract_verify(
        &mut self,
        pop: &ParsedOpcode,
        code: InterpreterErrorCode,
    ) -> Result<(), InterpreterError> {
        let verified = self.dstack.pop_bool()?;
        if !verified {
            return Err(InterpreterError::new(
                code,
                format!("{} failed", pop.name()),
            ));
        }
        Ok(())
    }

    pub(crate) fn op_return(&mut self) -> Result<(), InterpreterError> {
        if !self.after_genesis {
            return Err(InterpreterError::new(
                InterpreterErrorCode::EarlyReturn,
                "script returned early".to_string(),
            ));
        }
        self.early_return_after_genesis = true;
        if self.cond_stack.is_empty() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::Ok,
                "success".to_string(),
            ));
        }
        Ok(())
    }

    pub(crate) fn op_check_locktime_verify(&mut self) -> Result<(), InterpreterError> {
        if !self.has_flag(ScriptFlags::VERIFY_CHECKLOCKTIMEVERIFY) || self.after_genesis {
            if self.has_flag(ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS) {
                return Err(InterpreterError::new(
                    InterpreterErrorCode::DiscourageUpgradableNOPs,
                    "OP_NOP2 reserved for soft-fork upgrades".to_string(),
                ));
            }
            return Ok(());
        }

        let ctx = self.tx_context.ok_or_else(|| {
            InterpreterError::new(
                InterpreterErrorCode::InvalidParams,
                "no tx context for CHECKLOCKTIMEVERIFY".to_string(),
            )
        })?;

        let so = self.dstack.peek_byte_array(0)?;
        let lock_time =
            ScriptNumber::from_bytes(&so, 5, self.dstack.verify_minimal_data, self.after_genesis)?;

        if lock_time.less_than_int(0) {
            return Err(InterpreterError::new(
                InterpreterErrorCode::NegativeLockTime,
                format!("negative lock time: {}", lock_time.to_i64()),
            ));
        }

        let tx_lock_time = ctx.lock_time() as i64;
        verify_lock_time(tx_lock_time, LOCK_TIME_THRESHOLD, lock_time.to_i64())?;

        if ctx.input_sequence(self.input_idx) == MAX_TX_IN_SEQUENCE_NUM {
            return Err(InterpreterError::new(
                InterpreterErrorCode::UnsatisfiedLockTime,
                "transaction input is finalized".to_string(),
            ));
        }

        Ok(())
    }

    pub(crate) fn op_check_sequence_verify(&mut self) -> Result<(), InterpreterError> {
        if !self.has_flag(ScriptFlags::VERIFY_CHECKSEQUENCEVERIFY) || self.after_genesis {
            if self.has_flag(ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS) {
                return Err(InterpreterError::new(
                    InterpreterErrorCode::DiscourageUpgradableNOPs,
                    "OP_NOP3 reserved for soft-fork upgrades".to_string(),
                ));
            }
            return Ok(());
        }

        let ctx = self.tx_context.ok_or_else(|| {
            InterpreterError::new(
                InterpreterErrorCode::InvalidParams,
                "no tx context for CHECKSEQUENCEVERIFY".to_string(),
            )
        })?;

        let so = self.dstack.peek_byte_array(0)?;
        let stack_seq =
            ScriptNumber::from_bytes(&so, 5, self.dstack.verify_minimal_data, self.after_genesis)?;

        if stack_seq.less_than_int(0) {
            return Err(InterpreterError::new(
                InterpreterErrorCode::NegativeLockTime,
                format!("negative sequence: {}", stack_seq.to_i64()),
            ));
        }

        let sequence = stack_seq.to_i64();

        if sequence & (SEQUENCE_LOCK_TIME_DISABLED as i64) != 0 {
            return Ok(());
        }

        if ctx.tx_version() < 2 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::UnsatisfiedLockTime,
                format!("invalid transaction version: {}", ctx.tx_version()),
            ));
        }

        let tx_sequence = ctx.input_sequence(self.input_idx) as i64;
        if tx_sequence & (SEQUENCE_LOCK_TIME_DISABLED as i64) != 0 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::UnsatisfiedLockTime,
                format!(
                    "transaction sequence has sequence locktime disabled bit set: 0x{:x}",
                    tx_sequence
                ),
            ));
        }

        let lock_time_mask = SEQUENCE_LOCK_TIME_IS_SECONDS | SEQUENCE_LOCK_TIME_MASK;
        verify_lock_time(
            tx_sequence & lock_time_mask,
            SEQUENCE_LOCK_TIME_IS_SECONDS,
            sequence & lock_time_mask,
        )
    }
}

pub(crate) fn verify_lock_time(
    tx_lock_time: i64,
    threshold: i64,
    lock_time: i64,
) -> Result<(), InterpreterError> {
    if (tx_lock_time < threshold && lock_time >= threshold)
        || (tx_lock_time >= threshold && lock_time < threshold)
    {
        return Err(InterpreterError::new(
            InterpreterErrorCode::UnsatisfiedLockTime,
            format!(
                "mismatched locktime types -- tx locktime {}, stack locktime {}",
                tx_lock_time, lock_time
            ),
        ));
    }
    if lock_time > tx_lock_time {
        return Err(InterpreterError::new(
            InterpreterErrorCode::UnsatisfiedLockTime,
            format!(
                "locktime requirement not satisfied -- locktime is greater than the transaction locktime: {} > {}",
                lock_time, tx_lock_time
            ),
        ));
    }
    Ok(())
}
