//! Data/string operations for the script interpreter.

use super::error::{InterpreterError, InterpreterErrorCode};
use super::parsed_opcode::ParsedOpcode;
use super::scriptnum::*;
use super::thread::Thread;

impl<'a> Thread<'a> {
    pub(crate) fn op_cat(&mut self) -> Result<(), InterpreterError> {
        let b = self.dstack.pop_byte_array()?;
        let a = self.dstack.pop_byte_array()?;
        let mut c = a;
        c.extend_from_slice(&b);
        if c.len() > self.cfg.max_script_element_size() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::ElementTooBig,
                format!(
                    "concatenated size {} exceeds max allowed size {}",
                    c.len(),
                    self.cfg.max_script_element_size()
                ),
            ));
        }
        self.dstack.push_byte_array(c);
        Ok(())
    }

    pub(crate) fn op_split(&mut self) -> Result<(), InterpreterError> {
        let n = self.dstack.pop_int()?;
        let c = self.dstack.pop_byte_array()?;
        if n.to_i32() > c.len() as i32 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::NumberTooBig,
                "n is larger than length of array".to_string(),
            ));
        }
        if n.less_than_int(0) {
            return Err(InterpreterError::new(
                InterpreterErrorCode::NumberTooSmall,
                "n is negative".to_string(),
            ));
        }
        let pos = n.to_int() as usize;
        let a = c[..pos].to_vec();
        let b = c[pos..].to_vec();
        self.dstack.push_byte_array(a);
        self.dstack.push_byte_array(b);
        Ok(())
    }

    pub(crate) fn op_num2bin(&mut self) -> Result<(), InterpreterError> {
        let n = self.dstack.pop_int()?;
        let a = self.dstack.pop_byte_array()?;

        if n.greater_than_int(self.cfg.max_script_element_size() as i64) {
            return Err(InterpreterError::new(
                InterpreterErrorCode::NumberTooBig,
                format!(
                    "n is larger than the max of {}",
                    self.cfg.max_script_element_size()
                ),
            ));
        }

        let sn = ScriptNumber::from_bytes(&a, a.len(), false, self.after_genesis)?;
        let mut b = sn.to_bytes();

        if n.less_than_int(b.len() as i64) {
            return Err(InterpreterError::new(
                InterpreterErrorCode::NumberTooSmall,
                "cannot fit it into n sized array".to_string(),
            ));
        }
        if n.equal_int(b.len() as i64) {
            self.dstack.push_byte_array(b);
            return Ok(());
        }

        let mut signbit: u8 = 0x00;
        if !b.is_empty() {
            signbit = b[b.len() - 1] & 0x80;
            let last = b.len() - 1;
            b[last] &= 0x7f;
        }

        while n.greater_than_int((b.len() + 1) as i64) {
            b.push(0x00);
        }
        b.push(signbit);

        self.dstack.push_byte_array(b);
        Ok(())
    }

    pub(crate) fn op_bin2num(&mut self) -> Result<(), InterpreterError> {
        let a = self.dstack.pop_byte_array()?;
        let b = minimally_encode(&a);
        if b.len() > self.cfg.max_script_number_length() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::NumberTooBig,
                format!(
                    "script numbers are limited to {} bytes",
                    self.cfg.max_script_number_length()
                ),
            ));
        }
        self.dstack.push_byte_array(b);
        Ok(())
    }

    pub(crate) fn op_size(&mut self) -> Result<(), InterpreterError> {
        let so = self.dstack.peek_byte_array(0)?;
        self.dstack
            .push_int(&ScriptNumber::new(so.len() as i64, self.after_genesis));
        Ok(())
    }

    pub(crate) fn op_invert(&mut self) -> Result<(), InterpreterError> {
        let ba = self.dstack.pop_byte_array()?;
        let inverted: Vec<u8> = ba.iter().map(|b| b ^ 0xFF).collect();
        self.dstack.push_byte_array(inverted);
        Ok(())
    }

    pub(crate) fn op_bitwise(&mut self, f: fn(u8, u8) -> u8) -> Result<(), InterpreterError> {
        let a = self.dstack.pop_byte_array()?;
        let b = self.dstack.pop_byte_array()?;
        if a.len() != b.len() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::InvalidInputLength,
                "byte arrays are not the same length".to_string(),
            ));
        }
        let c: Vec<u8> = a.iter().zip(b.iter()).map(|(&x, &y)| f(x, y)).collect();
        self.dstack.push_byte_array(c);
        Ok(())
    }

    pub(crate) fn op_equal(&mut self) -> Result<(), InterpreterError> {
        let a = self.dstack.pop_byte_array()?;
        let b = self.dstack.pop_byte_array()?;
        self.dstack.push_bool(a == b);
        Ok(())
    }

    pub(crate) fn op_equalverify(&mut self, pop: &ParsedOpcode) -> Result<(), InterpreterError> {
        self.op_equal()?;
        self.abstract_verify(pop, InterpreterErrorCode::EqualVerify)
    }
}
