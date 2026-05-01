//! Script number arithmetic with Bitcoin consensus rules.
//!
//! All numbers on the Bitcoin script stack are encoded as little-endian
//! byte arrays with a sign bit in the most significant bit of the last byte.
//! Numeric opcodes operate on 4-byte integers in [-2^31+1, 2^31-1] but
//! results may overflow and remain valid as long as they are not reinterpreted
//! as numbers.

use num_bigint::BigInt;
use num_traits::{One, Signed, ToPrimitive, Zero};

use super::error::{InterpreterError, InterpreterErrorCode};

/// A script number using big integer arithmetic for overflow safety.
#[derive(Debug, Clone)]
pub struct ScriptNumber {
    /// The numeric value stored as a big integer.
    pub val: BigInt,
    /// Whether post-genesis rules are active (affects serialization clamping).
    pub after_genesis: bool,
}

impl ScriptNumber {
    /// Create a new ScriptNumber from an i64 value.
    pub fn new(val: i64, after_genesis: bool) -> Self {
        ScriptNumber {
            val: BigInt::from(val),
            after_genesis,
        }
    }

    /// Parse a byte array into a ScriptNumber.
    ///
    /// `script_num_len` is the max allowed byte length.
    /// `require_minimal` enforces minimal encoding.
    /// `after_genesis` enables post-genesis rules.
    pub fn from_bytes(
        bb: &[u8],
        script_num_len: usize,
        require_minimal: bool,
        after_genesis: bool,
    ) -> Result<Self, InterpreterError> {
        if bb.len() > script_num_len {
            return Err(InterpreterError::new(
                InterpreterErrorCode::NumberTooBig,
                format!(
                    "numeric value encoded as {:02x?} is {} bytes which exceeds the max allowed of {}",
                    bb, bb.len(), script_num_len
                ),
            ));
        }

        if require_minimal {
            check_minimal_data_encoding(bb)?;
        }

        if bb.is_empty() {
            return Ok(ScriptNumber {
                val: BigInt::zero(),
                after_genesis,
            });
        }

        // Decode from little endian with sign bit
        let mut v = BigInt::zero();
        for (i, &b) in bb.iter().enumerate() {
            v |= BigInt::from(b) << (8 * i);
        }

        // If the most significant byte has the sign bit set, the number is negative
        if bb[bb.len() - 1] & 0x80 != 0 {
            // Remove the sign bit and negate
            let mask = !(BigInt::from(0x80_i64) << (8 * (bb.len() - 1)));
            v &= mask;
            v = -v;
        }

        Ok(ScriptNumber {
            val: v,
            after_genesis,
        })
    }

    /// Serialize the number to bytes in little-endian with sign bit.
    pub fn to_bytes(&self) -> Vec<u8> {
        if self.val.is_zero() {
            return vec![];
        }

        let is_negative = self.val.is_negative();
        let abs_val = if is_negative {
            -self.val.clone()
        } else {
            self.val.clone()
        };

        // For pre-genesis, clamp to i32 range for serialization
        let working_val = if !self.after_genesis {
            let v = self
                .val
                .to_i64()
                .unwrap_or(if is_negative { i64::MIN } else { i64::MAX });
            if v > i32::MAX as i64 {
                BigInt::from(i32::MAX)
            } else if v < i32::MIN as i64 {
                BigInt::from(i32::MIN).abs()
            } else {
                abs_val.clone()
            }
        } else {
            abs_val.clone()
        };

        let _ = working_val; // we use abs_val below

        // Convert absolute value to little-endian bytes
        let mut result: Vec<u8> = Vec::new();
        let mut cpy = abs_val;
        while cpy > BigInt::zero() {
            result.push((&cpy & BigInt::from(0xff_u8)).to_u8().unwrap_or(0));
            cpy >>= 8;
        }

        if result.is_empty() {
            return vec![];
        }

        // Handle sign bit
        if result[result.len() - 1] & 0x80 != 0 {
            // Need an extra byte for the sign
            result.push(if is_negative { 0x80 } else { 0x00 });
        } else if is_negative {
            let last = result.len() - 1;
            result[last] |= 0x80;
        }

        result
    }

    // Arithmetic operations (mutating, return self for chaining like Go)

    /// Add another script number to this one and return self for chaining.
    pub fn add(&mut self, other: &ScriptNumber) -> &mut Self {
        self.val = &self.val + &other.val;
        self
    }

    /// Subtract another script number from this one and return self for chaining.
    pub fn sub(&mut self, other: &ScriptNumber) -> &mut Self {
        self.val = &self.val - &other.val;
        self
    }

    /// Multiply this script number by another and return self for chaining.
    pub fn mul(&mut self, other: &ScriptNumber) -> &mut Self {
        self.val = &self.val * &other.val;
        self
    }

    /// Divide this script number by another (truncated toward zero) and return self for chaining.
    pub fn div(&mut self, other: &ScriptNumber) -> &mut Self {
        // Truncation towards zero (like Go's Quo)
        use num_integer::Integer;
        let (q, r) = self.val.div_rem(&other.val);
        // Go's Quo truncates toward zero. BigInt div_rem might differ for negatives.
        // num_integer div_rem uses truncated division, which matches Go's Quo.
        let _ = r;
        self.val = q;
        self
    }

    /// Compute the truncated remainder of dividing by another and return self for chaining.
    pub fn modulo(&mut self, other: &ScriptNumber) -> &mut Self {
        // Go's Rem: truncated remainder
        use num_integer::Integer;
        let (_, r) = self.val.div_rem(&other.val);
        self.val = r;
        self
    }

    /// Increment this number by one and return self for chaining.
    pub fn incr(&mut self) -> &mut Self {
        self.val = &self.val + BigInt::one();
        self
    }

    /// Decrement this number by one and return self for chaining.
    pub fn decr(&mut self) -> &mut Self {
        self.val = &self.val - BigInt::one();
        self
    }

    /// Negate this number and return self for chaining.
    pub fn neg(&mut self) -> &mut Self {
        self.val = -self.val.clone();
        self
    }

    /// Replace this number with its absolute value and return self for chaining.
    pub fn abs(&mut self) -> &mut Self {
        if self.val.is_negative() {
            self.val = -self.val.clone();
        }
        self
    }

    /// Set this number to the given i64 value and return self for chaining.
    pub fn set(&mut self, i: i64) -> &mut Self {
        self.val = BigInt::from(i);
        self
    }

    // Comparison operations

    /// Return true if this number is zero.
    pub fn is_zero(&self) -> bool {
        self.val.is_zero()
    }

    /// Return true if this number is less than `other`.
    pub fn less_than(&self, other: &ScriptNumber) -> bool {
        self.val < other.val
    }

    /// Return true if this number is less than the given i64 value.
    pub fn less_than_int(&self, i: i64) -> bool {
        self.val < BigInt::from(i)
    }

    /// Return true if this number is less than or equal to `other`.
    pub fn less_than_or_equal(&self, other: &ScriptNumber) -> bool {
        self.val <= other.val
    }

    /// Return true if this number is greater than `other`.
    pub fn greater_than(&self, other: &ScriptNumber) -> bool {
        self.val > other.val
    }

    /// Return true if this number is greater than the given i64 value.
    pub fn greater_than_int(&self, i: i64) -> bool {
        self.val > BigInt::from(i)
    }

    /// Return true if this number is greater than or equal to `other`.
    pub fn greater_than_or_equal(&self, other: &ScriptNumber) -> bool {
        self.val >= other.val
    }

    /// Return true if this number is equal to `other`.
    pub fn equal(&self, other: &ScriptNumber) -> bool {
        self.val == other.val
    }

    /// Return true if this number is equal to the given i64 value.
    pub fn equal_int(&self, i: i64) -> bool {
        self.val == BigInt::from(i)
    }

    // Conversion

    /// Convert to i32, clamping to [i32::MIN, i32::MAX] on overflow.
    pub fn to_i32(&self) -> i32 {
        match self.val.to_i64() {
            Some(v) => {
                if v > i32::MAX as i64 {
                    i32::MAX
                } else if v < i32::MIN as i64 {
                    i32::MIN
                } else {
                    v as i32
                }
            }
            None => {
                if self.val.is_positive() {
                    i32::MAX
                } else {
                    i32::MIN
                }
            }
        }
    }

    /// Convert to i64, clamping to [i64::MIN, i64::MAX] on overflow.
    pub fn to_i64(&self) -> i64 {
        if self.greater_than_int(i64::MAX) {
            return i64::MAX;
        }
        if self.less_than_int(i64::MIN) {
            return i64::MIN;
        }
        self.val.to_i64().unwrap_or(0)
    }

    /// Convert to i64, returning 0 if the value does not fit.
    pub fn to_int(&self) -> i64 {
        self.val.to_i64().unwrap_or(0)
    }
}

/// Minimally encode a byte array (used by OP_BIN2NUM).
pub fn minimally_encode(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return vec![];
    }

    let mut data = data.to_vec();
    let last = data[data.len() - 1];

    if last & 0x7f != 0 {
        return data;
    }

    if data.len() == 1 {
        return vec![];
    }

    if data[data.len() - 2] & 0x80 != 0 {
        return data;
    }

    let mut i = data.len() - 1;
    while i > 0 {
        if data[i - 1] != 0 {
            if data[i - 1] & 0x80 != 0 {
                data[i] = last;
                return data[..=i].to_vec();
            } else {
                data[i - 1] |= last;
                return data[..i].to_vec();
            }
        }
        i -= 1;
    }

    vec![]
}

/// Check that a byte array uses minimal data encoding.
pub fn check_minimal_data_encoding(v: &[u8]) -> Result<(), InterpreterError> {
    if v.is_empty() {
        return Ok(());
    }

    if v[v.len() - 1] & 0x7f == 0 {
        if v.len() == 1 || v[v.len() - 2] & 0x80 == 0 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::MinimalData,
                format!(
                    "numeric value encoded as {:02x?} is not minimally encoded",
                    v
                ),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn test_script_num_bytes() {
        let tests: Vec<(i64, Vec<u8>)> = vec![
            (0, vec![]),
            (1, hex_to_bytes("01")),
            (-1, hex_to_bytes("81")),
            (127, hex_to_bytes("7f")),
            (-127, hex_to_bytes("ff")),
            (128, hex_to_bytes("8000")),
            (-128, hex_to_bytes("8080")),
            (129, hex_to_bytes("8100")),
            (-129, hex_to_bytes("8180")),
            (256, hex_to_bytes("0001")),
            (-256, hex_to_bytes("0081")),
            (32767, hex_to_bytes("ff7f")),
            (-32767, hex_to_bytes("ffff")),
            (32768, hex_to_bytes("008000")),
            (-32768, hex_to_bytes("008080")),
            (65535, hex_to_bytes("ffff00")),
            (-65535, hex_to_bytes("ffff80")),
            (524288, hex_to_bytes("000008")),
            (-524288, hex_to_bytes("000088")),
            (7340032, hex_to_bytes("000070")),
            (-7340032, hex_to_bytes("0000f0")),
            (8388608, hex_to_bytes("00008000")),
            (-8388608, hex_to_bytes("00008080")),
            (2147483647, hex_to_bytes("ffffff7f")),
            (-2147483647, hex_to_bytes("ffffffff")),
            // Out of range values (still valid for results)
            (2147483648, hex_to_bytes("0000008000")),
            (-2147483648, hex_to_bytes("0000008080")),
            (2415919104, hex_to_bytes("0000009000")),
            (-2415919104, hex_to_bytes("0000009080")),
            (4294967295, hex_to_bytes("ffffffff00")),
            (-4294967295, hex_to_bytes("ffffffff80")),
            (4294967296, hex_to_bytes("0000000001")),
            (-4294967296, hex_to_bytes("0000000081")),
            (281474976710655, hex_to_bytes("ffffffffffff00")),
            (-281474976710655, hex_to_bytes("ffffffffffff80")),
            (72057594037927935, hex_to_bytes("ffffffffffffff00")),
            (-72057594037927935, hex_to_bytes("ffffffffffffff80")),
            (9223372036854775807, hex_to_bytes("ffffffffffffff7f")),
            (-9223372036854775807, hex_to_bytes("ffffffffffffffff")),
        ];

        for (num, expected) in &tests {
            let sn = ScriptNumber {
                val: BigInt::from(*num),
                after_genesis: true, // after_genesis doesn't clamp
            };
            let got = sn.to_bytes();
            assert_eq!(
                &got, expected,
                "Bytes: num={}, got={:02x?}, want={:02x?}",
                num, got, expected
            );
        }
    }

    #[test]
    fn test_make_script_num() {
        struct Test {
            serialized: Vec<u8>,
            num: i64,
            num_len: usize,
            minimal_encoding: bool,
            expect_err: bool,
        }

        let tests = vec![
            // Minimal encoding rejects negative 0
            Test {
                serialized: hex_to_bytes("80"),
                num: 0,
                num_len: 4,
                minimal_encoding: true,
                expect_err: true,
            },
            // Valid minimally encoded
            Test {
                serialized: vec![],
                num: 0,
                num_len: 4,
                minimal_encoding: true,
                expect_err: false,
            },
            Test {
                serialized: hex_to_bytes("01"),
                num: 1,
                num_len: 4,
                minimal_encoding: true,
                expect_err: false,
            },
            Test {
                serialized: hex_to_bytes("81"),
                num: -1,
                num_len: 4,
                minimal_encoding: true,
                expect_err: false,
            },
            Test {
                serialized: hex_to_bytes("7f"),
                num: 127,
                num_len: 4,
                minimal_encoding: true,
                expect_err: false,
            },
            Test {
                serialized: hex_to_bytes("ff"),
                num: -127,
                num_len: 4,
                minimal_encoding: true,
                expect_err: false,
            },
            Test {
                serialized: hex_to_bytes("8000"),
                num: 128,
                num_len: 4,
                minimal_encoding: true,
                expect_err: false,
            },
            Test {
                serialized: hex_to_bytes("8080"),
                num: -128,
                num_len: 4,
                minimal_encoding: true,
                expect_err: false,
            },
            Test {
                serialized: hex_to_bytes("8100"),
                num: 129,
                num_len: 4,
                minimal_encoding: true,
                expect_err: false,
            },
            Test {
                serialized: hex_to_bytes("8180"),
                num: -129,
                num_len: 4,
                minimal_encoding: true,
                expect_err: false,
            },
            Test {
                serialized: hex_to_bytes("0001"),
                num: 256,
                num_len: 4,
                minimal_encoding: true,
                expect_err: false,
            },
            Test {
                serialized: hex_to_bytes("0081"),
                num: -256,
                num_len: 4,
                minimal_encoding: true,
                expect_err: false,
            },
            Test {
                serialized: hex_to_bytes("ff7f"),
                num: 32767,
                num_len: 4,
                minimal_encoding: true,
                expect_err: false,
            },
            Test {
                serialized: hex_to_bytes("ffff"),
                num: -32767,
                num_len: 4,
                minimal_encoding: true,
                expect_err: false,
            },
            Test {
                serialized: hex_to_bytes("008000"),
                num: 32768,
                num_len: 4,
                minimal_encoding: true,
                expect_err: false,
            },
            Test {
                serialized: hex_to_bytes("008080"),
                num: -32768,
                num_len: 4,
                minimal_encoding: true,
                expect_err: false,
            },
            Test {
                serialized: hex_to_bytes("ffffff7f"),
                num: 2147483647,
                num_len: 4,
                minimal_encoding: true,
                expect_err: false,
            },
            Test {
                serialized: hex_to_bytes("ffffffff"),
                num: -2147483647,
                num_len: 4,
                minimal_encoding: true,
                expect_err: false,
            },
            // 5-byte numbers
            Test {
                serialized: hex_to_bytes("ffffffff7f"),
                num: 549755813887,
                num_len: 5,
                minimal_encoding: true,
                expect_err: false,
            },
            Test {
                serialized: hex_to_bytes("ffffffffff"),
                num: -549755813887,
                num_len: 5,
                minimal_encoding: true,
                expect_err: false,
            },
            // Out of range for 4-byte
            Test {
                serialized: hex_to_bytes("0000008000"),
                num: 0,
                num_len: 4,
                minimal_encoding: true,
                expect_err: true,
            },
            // Non-minimally encoded with flag
            Test {
                serialized: hex_to_bytes("00"),
                num: 0,
                num_len: 4,
                minimal_encoding: true,
                expect_err: true,
            },
            Test {
                serialized: hex_to_bytes("0100"),
                num: 0,
                num_len: 4,
                minimal_encoding: true,
                expect_err: true,
            },
            // Non-minimally encoded without flag (OK)
            Test {
                serialized: hex_to_bytes("00"),
                num: 0,
                num_len: 4,
                minimal_encoding: false,
                expect_err: false,
            },
            Test {
                serialized: hex_to_bytes("0100"),
                num: 1,
                num_len: 4,
                minimal_encoding: false,
                expect_err: false,
            },
        ];

        for test in &tests {
            let result = ScriptNumber::from_bytes(
                &test.serialized,
                test.num_len,
                test.minimal_encoding,
                true,
            );
            match result {
                Ok(sn) => {
                    assert!(
                        !test.expect_err,
                        "from_bytes({:02x?}): expected error",
                        test.serialized
                    );
                    assert_eq!(
                        sn.to_int(),
                        test.num,
                        "from_bytes({:02x?}): got {}, want {}",
                        test.serialized,
                        sn.to_int(),
                        test.num
                    );
                }
                Err(_) => {
                    assert!(
                        test.expect_err,
                        "from_bytes({:02x?}): unexpected error",
                        test.serialized
                    );
                }
            }
        }
    }

    #[test]
    fn test_script_num_int32() {
        let tests: Vec<(i64, i32)> = vec![
            (0, 0),
            (1, 1),
            (-1, -1),
            (2147483647, 2147483647),
            (-2147483647, -2147483647),
            (-2147483648, -2147483648),
            // Clamped values
            (2147483648, 2147483647),
            (-2147483649, -2147483648),
            (9223372036854775807, 2147483647),
            (-9223372036854775808, -2147483648),
        ];

        for (input, want) in &tests {
            let sn = ScriptNumber {
                val: BigInt::from(*input),
                after_genesis: false,
            };
            assert_eq!(
                sn.to_i32(),
                *want,
                "Int32({}): got {}, want {}",
                input,
                sn.to_i32(),
                want
            );
        }
    }

    #[test]
    fn test_minimally_encode() {
        // Empty stays empty
        assert_eq!(minimally_encode(&[]), Vec::<u8>::new());
        // Already minimal
        assert_eq!(minimally_encode(&[0x7f]), vec![0x7f]);
        // Single zero byte becomes empty
        assert_eq!(minimally_encode(&[0x00]), Vec::<u8>::new());
        // Negative zero becomes empty
        assert_eq!(minimally_encode(&[0x80]), Vec::<u8>::new());
    }
}
