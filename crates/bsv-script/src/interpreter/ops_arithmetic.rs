//! Arithmetic operations for the script interpreter.

use super::error::{InterpreterError, InterpreterErrorCode};
use super::parsed_opcode::ParsedOpcode;
use super::scriptnum::ScriptNumber;
use super::thread::Thread;

impl<'a> Thread<'a> {
    pub(crate) fn op_unary_int(
        &mut self,
        f: impl FnOnce(&mut ScriptNumber),
    ) -> Result<(), InterpreterError> {
        let mut m = self.dstack.pop_int()?;
        f(&mut m);
        self.dstack.push_int(&m);
        Ok(())
    }

    pub(crate) fn op_not(&mut self) -> Result<(), InterpreterError> {
        let m = self.dstack.pop_int()?;
        let n = if m.is_zero() { 1i64 } else { 0 };
        self.dstack
            .push_int(&ScriptNumber::new(n, self.after_genesis));
        Ok(())
    }

    pub(crate) fn op_0notequal(&mut self) -> Result<(), InterpreterError> {
        let mut m = self.dstack.pop_int()?;
        if !m.is_zero() {
            m.set(1);
        }
        self.dstack.push_int(&m);
        Ok(())
    }

    pub(crate) fn op_add(&mut self) -> Result<(), InterpreterError> {
        let mut v0 = self.dstack.pop_int()?;
        let v1 = self.dstack.pop_int()?;
        v0.add(&v1);
        self.dstack.push_int(&v0);
        Ok(())
    }

    pub(crate) fn op_sub(&mut self) -> Result<(), InterpreterError> {
        let v0 = self.dstack.pop_int()?;
        let mut v1 = self.dstack.pop_int()?;
        v1.sub(&v0);
        self.dstack.push_int(&v1);
        Ok(())
    }

    pub(crate) fn op_mul(&mut self) -> Result<(), InterpreterError> {
        let mut n1 = self.dstack.pop_int()?;
        let n2 = self.dstack.pop_int()?;
        n1.mul(&n2);
        self.dstack.push_int(&n1);
        Ok(())
    }

    pub(crate) fn op_div(&mut self) -> Result<(), InterpreterError> {
        let b = self.dstack.pop_int()?;
        let mut a = self.dstack.pop_int()?;
        if b.is_zero() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::DivideByZero,
                "divide by zero".to_string(),
            ));
        }
        a.div(&b);
        self.dstack.push_int(&a);
        Ok(())
    }

    pub(crate) fn op_mod(&mut self) -> Result<(), InterpreterError> {
        let b = self.dstack.pop_int()?;
        let mut a = self.dstack.pop_int()?;
        if b.is_zero() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::DivideByZero,
                "mod by zero".to_string(),
            ));
        }
        a.modulo(&b);
        self.dstack.push_int(&a);
        Ok(())
    }

    pub(crate) fn op_lshift(&mut self) -> Result<(), InterpreterError> {
        let num = self.dstack.pop_int()?;
        let n = num.to_int() as usize;
        if (num.to_int()) < 0 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::NumberTooSmall,
                "n less than 0".to_string(),
            ));
        }
        let x = self.dstack.pop_byte_array()?;

        let bit_shift = n % 8;
        let byte_shift = n / 8;
        let masks: [u8; 8] = [0xFF, 0x7F, 0x3F, 0x1F, 0x0F, 0x07, 0x03, 0x01];
        let mask = masks[bit_shift];
        let overflow_mask = !mask;

        let mut result = vec![0u8; x.len()];
        for idx in (1..=x.len()).rev() {
            let i = idx - 1;
            if byte_shift <= i {
                let k = i - byte_shift;
                let val = (x[i] & mask) << bit_shift;
                result[k] |= val;
                if k >= 1 {
                    let carry = (x[i] & overflow_mask) >> (8 - bit_shift);
                    result[k - 1] |= carry;
                }
            }
        }
        self.dstack.push_byte_array(result);
        Ok(())
    }

    pub(crate) fn op_rshift(&mut self) -> Result<(), InterpreterError> {
        let num = self.dstack.pop_int()?;
        let n = num.to_int() as usize;
        if (num.to_int()) < 0 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::NumberTooSmall,
                "n less than 0".to_string(),
            ));
        }
        let x = self.dstack.pop_byte_array()?;

        let byte_shift = n / 8;
        let bit_shift = n % 8;
        let masks: [u8; 8] = [0xFF, 0xFE, 0xFC, 0xF8, 0xF0, 0xE0, 0xC0, 0x80];
        let mask = masks[bit_shift];
        let overflow_mask = !mask;

        let mut result = vec![0u8; x.len()];
        for (i, &b) in x.iter().enumerate() {
            let k = i + byte_shift;
            if k < x.len() {
                let val = (b & mask) >> bit_shift;
                result[k] |= val;
            }
            if k + 1 < x.len() {
                let carry = (b & overflow_mask) << (8 - bit_shift);
                result[k + 1] |= carry;
            }
        }
        self.dstack.push_byte_array(result);
        Ok(())
    }

    pub(crate) fn op_bool_binop(
        &mut self,
        f: impl FnOnce(&ScriptNumber, &ScriptNumber) -> bool,
    ) -> Result<(), InterpreterError> {
        let v0 = self.dstack.pop_int()?;
        let v1 = self.dstack.pop_int()?;
        let n = if f(&v1, &v0) { 1i64 } else { 0 };
        self.dstack
            .push_int(&ScriptNumber::new(n, self.after_genesis));
        Ok(())
    }

    pub(crate) fn op_numequalverify(&mut self, pop: &ParsedOpcode) -> Result<(), InterpreterError> {
        self.op_bool_binop(|a, b| a.equal(b))?;
        self.abstract_verify(pop, InterpreterErrorCode::NumEqualVerify)
    }

    pub(crate) fn op_min(&mut self) -> Result<(), InterpreterError> {
        let v0 = self.dstack.pop_int()?;
        let v1 = self.dstack.pop_int()?;
        if v1.less_than(&v0) {
            self.dstack.push_int(&v1);
        } else {
            self.dstack.push_int(&v0);
        }
        Ok(())
    }

    pub(crate) fn op_max(&mut self) -> Result<(), InterpreterError> {
        let v0 = self.dstack.pop_int()?;
        let v1 = self.dstack.pop_int()?;
        if v1.greater_than(&v0) {
            self.dstack.push_int(&v1);
        } else {
            self.dstack.push_int(&v0);
        }
        Ok(())
    }

    pub(crate) fn op_within(&mut self) -> Result<(), InterpreterError> {
        let max_val = self.dstack.pop_int()?;
        let min_val = self.dstack.pop_int()?;
        let x = self.dstack.pop_int()?;
        let n = if min_val.less_than_or_equal(&x) && x.less_than(&max_val) {
            1i64
        } else {
            0
        };
        self.dstack
            .push_int(&ScriptNumber::new(n, self.after_genesis));
        Ok(())
    }
}
