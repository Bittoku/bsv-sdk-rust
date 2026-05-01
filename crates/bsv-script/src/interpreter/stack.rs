//! Script execution stack.

use super::error::{InterpreterError, InterpreterErrorCode};
use super::scriptnum::ScriptNumber;

/// Convert byte array to boolean (Bitcoin consensus rules).
pub fn as_bool(t: &[u8]) -> bool {
    for i in 0..t.len() {
        if t[i] != 0 {
            // Negative 0 is also considered false
            if i == t.len() - 1 && t[i] == 0x80 {
                return false;
            }
            return true;
        }
    }
    false
}

/// Convert boolean to byte array.
pub fn from_bool(v: bool) -> Vec<u8> {
    if v {
        vec![1]
    } else {
        vec![]
    }
}

/// The main data/alt stack used by the script interpreter.
pub struct Stack {
    /// The underlying stack storage, where the last element is the top.
    pub stk: Vec<Vec<u8>>,
    /// Maximum allowed byte length for numeric values on this stack.
    pub max_num_length: usize,
    /// Whether post-genesis rules are active (relaxed limits).
    pub after_genesis: bool,
    /// Whether to enforce minimal data encoding for numeric conversions.
    pub verify_minimal_data: bool,
}

impl Stack {
    /// Create a new empty stack with the given numeric limits and flags.
    pub fn new(max_num_length: usize, after_genesis: bool, verify_minimal_data: bool) -> Self {
        Stack {
            stk: Vec::new(),
            max_num_length,
            after_genesis,
            verify_minimal_data,
        }
    }

    /// Return the number of elements on the stack.
    pub fn depth(&self) -> i32 {
        self.stk.len() as i32
    }

    /// Push a raw byte array onto the top of the stack.
    pub fn push_byte_array(&mut self, data: Vec<u8>) {
        self.stk.push(data);
    }

    /// Push a script number onto the stack, serialized to bytes.
    pub fn push_int(&mut self, n: &ScriptNumber) {
        self.push_byte_array(n.to_bytes());
    }

    /// Push a boolean value onto the stack.
    pub fn push_bool(&mut self, val: bool) {
        self.push_byte_array(from_bool(val));
    }

    /// Pop and return the top byte array from the stack.
    pub fn pop_byte_array(&mut self) -> Result<Vec<u8>, InterpreterError> {
        self.nip_n(0)
    }

    /// Pop the top element and decode it as a script number.
    pub fn pop_int(&mut self) -> Result<ScriptNumber, InterpreterError> {
        let data = self.pop_byte_array()?;
        ScriptNumber::from_bytes(
            &data,
            self.max_num_length,
            self.verify_minimal_data,
            self.after_genesis,
        )
    }

    /// Pop the top element and interpret it as a boolean.
    pub fn pop_bool(&mut self) -> Result<bool, InterpreterError> {
        let data = self.pop_byte_array()?;
        Ok(as_bool(&data))
    }

    /// Peek at a byte array at the given depth index (0 = top) without removing it.
    pub fn peek_byte_array(&self, idx: i32) -> Result<Vec<u8>, InterpreterError> {
        let sz = self.stk.len() as i32;
        if idx < 0 || idx >= sz {
            return Err(InterpreterError::new(
                InterpreterErrorCode::InvalidStackOperation,
                format!("index {} is invalid for stack size {}", idx, sz),
            ));
        }
        Ok(self.stk[(sz - idx - 1) as usize].clone())
    }

    /// Peek at a script number at the given depth index without removing it.
    pub fn peek_int(&self, idx: i32) -> Result<ScriptNumber, InterpreterError> {
        let data = self.peek_byte_array(idx)?;
        ScriptNumber::from_bytes(
            &data,
            self.max_num_length,
            self.verify_minimal_data,
            self.after_genesis,
        )
    }

    /// Peek at a boolean at the given depth index without removing it.
    pub fn peek_bool(&self, idx: i32) -> Result<bool, InterpreterError> {
        let data = self.peek_byte_array(idx)?;
        Ok(as_bool(&data))
    }

    fn nip_n(&mut self, idx: i32) -> Result<Vec<u8>, InterpreterError> {
        let sz = self.stk.len() as i32;
        if idx < 0 || idx > sz - 1 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::InvalidStackOperation,
                format!("index {} is invalid for stack size {}", idx, sz),
            ));
        }
        let pos = (sz - idx - 1) as usize;
        Ok(self.stk.remove(pos))
    }

    /// Remove and discard the element at the given depth index (0 = top).
    pub fn nip_n_discard(&mut self, idx: i32) -> Result<(), InterpreterError> {
        self.nip_n(idx)?;
        Ok(())
    }

    /// Copy the top element and insert it before the second-to-top element (OP_TUCK).
    pub fn tuck(&mut self) -> Result<(), InterpreterError> {
        let so2 = self.pop_byte_array()?;
        let so1 = self.pop_byte_array()?;
        self.push_byte_array(so2.clone());
        self.push_byte_array(so1);
        self.push_byte_array(so2);
        Ok(())
    }

    /// Remove the top `n` elements from the stack.
    pub fn drop_n(&mut self, n: i32) -> Result<(), InterpreterError> {
        if n < 1 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::InvalidStackOperation,
                format!("attempt to drop {} items from stack", n),
            ));
        }
        for _ in 0..n {
            self.pop_byte_array()?;
        }
        Ok(())
    }

    /// Duplicate the top `n` elements on the stack.
    pub fn dup_n(&mut self, n: i32) -> Result<(), InterpreterError> {
        if n < 1 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::InvalidStackOperation,
                format!("attempt to dup {} stack items", n),
            ));
        }
        for _ in (0..n).rev() {
            let so = self.peek_byte_array(n - 1)?;
            self.push_byte_array(so);
        }
        Ok(())
    }

    /// Rotate the top `3*n` elements: move the bottom `n` of that group to the top.
    pub fn rot_n(&mut self, n: i32) -> Result<(), InterpreterError> {
        if n < 1 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::InvalidStackOperation,
                format!("attempt to rotate {} stack items", n),
            ));
        }
        let entry = 3 * n - 1;
        for _ in (0..n).rev() {
            let so = self.nip_n(entry)?;
            self.push_byte_array(so);
        }
        Ok(())
    }

    /// Swap the top `n` elements with the `n` elements below them.
    pub fn swap_n(&mut self, n: i32) -> Result<(), InterpreterError> {
        if n < 1 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::InvalidStackOperation,
                format!("attempt to swap {} stack items", n),
            ));
        }
        let entry = 2 * n - 1;
        for _ in (0..n).rev() {
            let so = self.nip_n(entry)?;
            self.push_byte_array(so);
        }
        Ok(())
    }

    /// Copy `n` elements from below the top `n` elements and push them on top.
    pub fn over_n(&mut self, n: i32) -> Result<(), InterpreterError> {
        if n < 1 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::InvalidStackOperation,
                format!("attempt to perform over on {} stack items", n),
            ));
        }
        let entry = 2 * n - 1;
        for _ in (0..n).rev() {
            let so = self.peek_byte_array(entry)?;
            self.push_byte_array(so);
        }
        Ok(())
    }

    /// Copy the element at depth `n` and push it on top (OP_PICK).
    pub fn pick_n(&mut self, n: i32) -> Result<(), InterpreterError> {
        let so = self.peek_byte_array(n)?;
        self.push_byte_array(so);
        Ok(())
    }

    /// Remove the element at depth `n` and push it on top (OP_ROLL).
    pub fn roll_n(&mut self, n: i32) -> Result<(), InterpreterError> {
        let so = self.nip_n(n)?;
        self.push_byte_array(so);
        Ok(())
    }

    /// Get stack contents as array (bottom to top).
    pub fn get_stack(&self) -> Vec<Vec<u8>> {
        self.stk.clone()
    }

    /// Set stack contents from array (last = top).
    pub fn set_stack(&mut self, data: Vec<Vec<u8>>) {
        self.stk = data;
    }

    /// Clear all items.
    pub fn clear(&mut self) {
        self.stk.clear();
    }
}

/// A simple boolean stack for tracking if/else state.
pub struct BoolStack {
    stk: Vec<bool>,
}

impl BoolStack {
    /// Create a new empty boolean stack.
    pub fn new() -> Self {
        BoolStack { stk: Vec::new() }
    }

    /// Push a boolean value onto the stack.
    pub fn push_bool(&mut self, b: bool) {
        self.stk.push(b);
    }

    /// Pop and return the top boolean value from the stack.
    pub fn pop_bool(&mut self) -> Result<bool, InterpreterError> {
        self.stk.pop().ok_or_else(|| {
            InterpreterError::new(
                InterpreterErrorCode::InvalidStackOperation,
                "bool stack empty".to_string(),
            )
        })
    }

    /// Return the number of elements on the boolean stack.
    pub fn depth(&self) -> i32 {
        self.stk.len() as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_as_bool() {
        assert!(!as_bool(&[]));
        assert!(!as_bool(&[0x00]));
        assert!(!as_bool(&[0x80])); // negative zero
        assert!(as_bool(&[0x01]));
        assert!(as_bool(&[0x00, 0x01]));
        assert!(!as_bool(&[0x00, 0x00]));
        assert!(!as_bool(&[0x00, 0x80])); // negative zero
    }

    #[test]
    fn test_stack_basic_ops() {
        let mut s = Stack::new(4, false, false);
        s.push_byte_array(vec![1, 2, 3]);
        s.push_byte_array(vec![4, 5]);
        assert_eq!(s.depth(), 2);
        let top = s.pop_byte_array().unwrap();
        assert_eq!(top, vec![4, 5]);
        assert_eq!(s.depth(), 1);
    }

    #[test]
    fn test_stack_dup() {
        let mut s = Stack::new(4, false, false);
        s.push_byte_array(vec![1]);
        s.push_byte_array(vec![2]);
        s.dup_n(2).unwrap();
        assert_eq!(s.depth(), 4);
        assert_eq!(s.pop_byte_array().unwrap(), vec![2]);
        assert_eq!(s.pop_byte_array().unwrap(), vec![1]);
    }

    #[test]
    fn test_stack_swap() {
        let mut s = Stack::new(4, false, false);
        s.push_byte_array(vec![1]);
        s.push_byte_array(vec![2]);
        s.swap_n(1).unwrap();
        assert_eq!(s.pop_byte_array().unwrap(), vec![1]);
        assert_eq!(s.pop_byte_array().unwrap(), vec![2]);
    }
}
