//! Utility types for binary serialization.
//!
//! Provides VarInt encoding/decoding, `BsvReader` and `BsvWriter` structs
//! for reading/writing Bitcoin protocol binary data, and byte manipulation
//! helpers used in transaction serialization.
//! Ported from the Go BSV SDK (`util` package).

use crate::PrimitivesError;

// ---------------------------------------------------------------------------
// VarInt
// ---------------------------------------------------------------------------

/// A Bitcoin protocol variable-length integer.
///
/// VarInt is used in transaction data to indicate the number of upcoming fields
/// or the length of an upcoming field. The encoding uses 1, 3, 5, or 9 bytes
/// depending on the magnitude of the value.
///
/// See <http://learnmeabitcoin.com/glossary/varint>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VarInt(pub u64);

impl VarInt {
    /// Decode a VarInt from a byte slice.
    ///
    /// Returns the decoded value and the number of bytes consumed.
    ///
    /// # Arguments
    /// * `data` - Byte slice starting with a VarInt encoding.
    ///
    /// # Returns
    /// `Ok((VarInt, bytes_consumed))` or `Err` if the slice is too short.
    ///
    /// # Panics
    /// None — all bounds are checked.
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize), PrimitivesError> {
        if data.is_empty() {
            return Err(PrimitivesError::UnexpectedEof);
        }
        match data[0] {
            0xff => {
                if data.len() < 9 {
                    return Err(PrimitivesError::UnexpectedEof);
                }
                let val = u64::from_le_bytes([
                    data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
                ]);
                Ok((VarInt(val), 9))
            }
            0xfe => {
                if data.len() < 5 {
                    return Err(PrimitivesError::UnexpectedEof);
                }
                let val = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as u64;
                Ok((VarInt(val), 5))
            }
            0xfd => {
                if data.len() < 3 {
                    return Err(PrimitivesError::UnexpectedEof);
                }
                let val = u16::from_le_bytes([data[1], data[2]]) as u64;
                Ok((VarInt(val), 3))
            }
            b => Ok((VarInt(b as u64), 1)),
        }
    }

    /// Return the wire-format byte length of this VarInt.
    ///
    /// # Returns
    /// 1, 3, 5, or 9 depending on the value.
    pub fn length(&self) -> usize {
        if self.0 < 253 {
            1
        } else if self.0 < 65536 {
            3
        } else if self.0 < 4294967296 {
            5
        } else {
            9
        }
    }

    /// Encode the VarInt into a new byte vector.
    ///
    /// # Returns
    /// A `Vec<u8>` of 1, 3, 5, or 9 bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.length()];
        self.put_bytes(&mut buf);
        buf
    }

    /// Write the VarInt into a destination buffer.
    ///
    /// The buffer must be at least `self.length()` bytes long.
    ///
    /// # Arguments
    /// * `dst` - Destination buffer to write into.
    ///
    /// # Returns
    /// The number of bytes written.
    pub fn put_bytes(&self, dst: &mut [u8]) -> usize {
        let v = self.0;
        if v < 0xfd {
            dst[0] = v as u8;
            1
        } else if v < 0x10000 {
            dst[0] = 0xfd;
            dst[1..3].copy_from_slice(&(v as u16).to_le_bytes());
            3
        } else if v < 0x100000000 {
            dst[0] = 0xfe;
            dst[1..5].copy_from_slice(&(v as u32).to_le_bytes());
            5
        } else {
            dst[0] = 0xff;
            dst[1..9].copy_from_slice(&v.to_le_bytes());
            9
        }
    }

    /// Check if this value is at the upper boundary of a VarInt size class.
    ///
    /// Returns how many extra bytes would be needed if the value were
    /// incremented by 1. Returns -1 at `u64::MAX` (cannot increment).
    ///
    /// # Returns
    /// 0 if not at a boundary, 2 or 4 for size-class transitions, -1 at max.
    pub fn upper_limit_inc(&self) -> i32 {
        match self.0 {
            252 | 65535 => 2,
            4294967295 => 4,
            u64::MAX => -1,
            _ => 0,
        }
    }

    /// Return the underlying u64 value.
    ///
    /// # Returns
    /// The integer value.
    pub fn value(&self) -> u64 {
        self.0
    }
}

impl From<u64> for VarInt {
    fn from(v: u64) -> Self {
        VarInt(v)
    }
}

impl From<usize> for VarInt {
    fn from(v: usize) -> Self {
        VarInt(v as u64)
    }
}

// ---------------------------------------------------------------------------
// BsvReader
// ---------------------------------------------------------------------------

/// A cursor-based reader for Bitcoin protocol binary data.
///
/// Wraps a byte slice and maintains a read position, providing methods
/// to read fixed-size integers and VarInt values in little-endian order.
pub struct BsvReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BsvReader<'a> {
    /// Create a new reader over the given byte slice.
    ///
    /// # Arguments
    /// * `data` - The byte slice to read from.
    ///
    /// # Returns
    /// A `BsvReader` positioned at the start of the data.
    pub fn new(data: &'a [u8]) -> Self {
        BsvReader { data, pos: 0 }
    }

    /// Read `n` bytes and advance the position.
    ///
    /// # Arguments
    /// * `n` - Number of bytes to read.
    ///
    /// # Returns
    /// A byte slice of length `n`, or an error if insufficient data remains.
    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], PrimitivesError> {
        if self.pos + n > self.data.len() {
            return Err(PrimitivesError::UnexpectedEof);
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Read a single byte and advance the position.
    ///
    /// # Returns
    /// The byte value, or an error if no data remains.
    pub fn read_u8(&mut self) -> Result<u8, PrimitivesError> {
        let bytes = self.read_bytes(1)?;
        Ok(bytes[0])
    }

    /// Read a little-endian u16 and advance the position by 2 bytes.
    ///
    /// # Returns
    /// The decoded u16, or an error if insufficient data.
    pub fn read_u16_le(&mut self) -> Result<u16, PrimitivesError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Read a little-endian u32 and advance the position by 4 bytes.
    ///
    /// # Returns
    /// The decoded u32, or an error if insufficient data.
    pub fn read_u32_le(&mut self) -> Result<u32, PrimitivesError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read a little-endian u64 and advance the position by 8 bytes.
    ///
    /// # Returns
    /// The decoded u64, or an error if insufficient data.
    pub fn read_u64_le(&mut self) -> Result<u64, PrimitivesError> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Read a VarInt and advance the position accordingly.
    ///
    /// # Returns
    /// The decoded `VarInt`, or an error if insufficient data.
    pub fn read_varint(&mut self) -> Result<VarInt, PrimitivesError> {
        let first = self.read_u8()?;
        match first {
            0xff => {
                let val = self.read_u64_le()?;
                Ok(VarInt(val))
            }
            0xfe => {
                let val = self.read_u32_le()? as u64;
                Ok(VarInt(val))
            }
            0xfd => {
                let val = self.read_u16_le()? as u64;
                Ok(VarInt(val))
            }
            b => Ok(VarInt(b as u64)),
        }
    }

    /// Return the number of bytes remaining.
    ///
    /// # Returns
    /// The count of unread bytes.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
}

// ---------------------------------------------------------------------------
// BsvWriter
// ---------------------------------------------------------------------------

/// A buffer-based writer for Bitcoin protocol binary data.
///
/// Wraps a `Vec<u8>` and provides methods to append fixed-size integers
/// and VarInt values in little-endian order.
pub struct BsvWriter {
    buf: Vec<u8>,
}

impl BsvWriter {
    /// Create a new empty writer.
    ///
    /// # Returns
    /// A `BsvWriter` with an empty internal buffer.
    pub fn new() -> Self {
        BsvWriter { buf: Vec::new() }
    }

    /// Create a new writer with a pre-allocated capacity.
    ///
    /// # Arguments
    /// * `capacity` - Initial byte capacity of the internal buffer.
    ///
    /// # Returns
    /// A `BsvWriter` with the given capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        BsvWriter {
            buf: Vec::with_capacity(capacity),
        }
    }

    /// Append raw bytes to the buffer.
    ///
    /// # Arguments
    /// * `bytes` - The bytes to append.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Append a single byte to the buffer.
    ///
    /// # Arguments
    /// * `val` - The byte value.
    pub fn write_u8(&mut self, val: u8) {
        self.buf.push(val);
    }

    /// Append a little-endian u16 (2 bytes) to the buffer.
    ///
    /// # Arguments
    /// * `val` - The u16 value.
    pub fn write_u16_le(&mut self, val: u16) {
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    /// Append a little-endian u32 (4 bytes) to the buffer.
    ///
    /// # Arguments
    /// * `val` - The u32 value.
    pub fn write_u32_le(&mut self, val: u32) {
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    /// Append a little-endian u64 (8 bytes) to the buffer.
    ///
    /// # Arguments
    /// * `val` - The u64 value.
    pub fn write_u64_le(&mut self, val: u64) {
        self.buf.extend_from_slice(&val.to_le_bytes());
    }

    /// Append a VarInt to the buffer.
    ///
    /// # Arguments
    /// * `varint` - The VarInt value to encode and append.
    pub fn write_varint(&mut self, varint: VarInt) {
        let bytes = varint.to_bytes();
        self.buf.extend_from_slice(&bytes);
    }

    /// Consume the writer and return the accumulated bytes.
    ///
    /// # Returns
    /// The internal byte buffer.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Return a reference to the current buffer contents.
    ///
    /// # Returns
    /// A byte slice of the written data.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Return the current length of the buffer.
    ///
    /// # Returns
    /// The number of bytes written so far.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Check if the buffer is empty.
    ///
    /// # Returns
    /// `true` if no bytes have been written.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

impl Default for BsvWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- VarInt decode tests (from Go varint_test.go TestDecodeVarInt) --

    /// Helper to convert a u64 to 8 little-endian bytes.
    fn le_bytes(v: u64) -> Vec<u8> {
        v.to_le_bytes().to_vec()
    }

    #[test]
    fn test_decode_varint() {
        // 0xff prefix -> reads 8 bytes after prefix -> value 0, size 9
        let mut input = vec![0xff, 0, 0, 0, 0, 0, 0, 0, 0]; // 1 prefix + 8 data bytes
        let (vi, sz) = VarInt::from_bytes(&input).unwrap();
        assert_eq!(vi.0, 0);
        assert_eq!(sz, 9);

        // 0xfe prefix -> reads 4 bytes after prefix -> value 0, size 5
        input = vec![0xfe, 0, 0, 0, 0];
        let (vi, sz) = VarInt::from_bytes(&input).unwrap();
        assert_eq!(vi.0, 0);
        assert_eq!(sz, 5);

        // 0xfd prefix -> reads 2 bytes after prefix -> value 0, size 3
        input = vec![0xfd, 0, 0];
        let (vi, sz) = VarInt::from_bytes(&input).unwrap();
        assert_eq!(vi.0, 0);
        assert_eq!(sz, 3);

        // value 1 -> single byte, size 1
        let input = le_bytes(1);
        let (vi, sz) = VarInt::from_bytes(&input).unwrap();
        assert_eq!(vi.0, 1);
        assert_eq!(sz, 1);
    }

    #[test]
    fn test_decode_varint_too_short() {
        assert!(VarInt::from_bytes(&[]).is_err());
        assert!(VarInt::from_bytes(&[0xff, 0, 0]).is_err());
        assert!(VarInt::from_bytes(&[0xfe, 0]).is_err());
        assert!(VarInt::from_bytes(&[0xfd]).is_err());
    }

    // -- VarInt upper-limit-inc tests --

    #[test]
    fn test_varint_upper_limit_inc() {
        assert_eq!(VarInt(0).upper_limit_inc(), 0);
        assert_eq!(VarInt(10).upper_limit_inc(), 0);
        assert_eq!(VarInt(100).upper_limit_inc(), 0);
        assert_eq!(VarInt(252).upper_limit_inc(), 2);
        assert_eq!(VarInt(65535).upper_limit_inc(), 2);
        assert_eq!(VarInt(4294967295).upper_limit_inc(), 4);
        assert_eq!(VarInt(u64::MAX).upper_limit_inc(), -1);
    }

    // -- VarInt byte-length tests --

    #[test]
    fn test_varint_byte_length() {
        assert_eq!(VarInt(0).to_bytes().len(), 1); // 1 byte lower
        assert_eq!(VarInt(252).to_bytes().len(), 1); // 1 byte upper
        assert_eq!(VarInt(253).to_bytes().len(), 3); // 3 byte lower
        assert_eq!(VarInt(65535).to_bytes().len(), 3); // 3 byte upper
        assert_eq!(VarInt(65536).to_bytes().len(), 5); // 5 byte lower
        assert_eq!(VarInt(4294967295).to_bytes().len(), 5); // 5 byte upper
        assert_eq!(VarInt(4294967296).to_bytes().len(), 9); // 9 byte lower
        assert_eq!(VarInt(u64::MAX).to_bytes().len(), 9); // 9 byte upper
    }

    // -- VarInt size (length) tests --

    #[test]
    fn test_varint_size() {
        assert_eq!(VarInt(252).length(), 1);
        assert_eq!(VarInt(253).length(), 3);
        assert_eq!(VarInt(65535).length(), 3);
        assert_eq!(VarInt(65536).length(), 5);
        assert_eq!(VarInt(4294967295).length(), 5);
        assert_eq!(VarInt(4294967296).length(), 9);
    }

    // -- VarInt put_bytes tests --

    #[test]
    fn test_varint_put_bytes() {
        let cases: Vec<(u64, Vec<u8>)> = vec![
            (0, vec![0x00]),
            (1, vec![0x01]),
            (252, vec![0xfc]),
            (253, vec![0xfd, 0xfd, 0x00]),
            (65535, vec![0xfd, 0xff, 0xff]),
            (65536, vec![0xfe, 0x00, 0x00, 0x01, 0x00]),
            (4294967295, vec![0xfe, 0xff, 0xff, 0xff, 0xff]),
            (
                4294967296,
                vec![0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
            ),
            (
                u64::MAX,
                vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ];

        for (value, expected) in cases {
            let vi = VarInt(value);
            let mut buf = vec![0u8; vi.length()];
            let n = vi.put_bytes(&mut buf);
            assert_eq!(n, expected.len(), "put_bytes length mismatch for {}", value);
            assert_eq!(buf, expected, "put_bytes content mismatch for {}", value);
            // Verify put_bytes matches to_bytes.
            assert_eq!(vi.to_bytes(), buf, "to_bytes != put_bytes for {}", value);
        }
    }

    // -- BsvReader / BsvWriter round-trip tests --

    #[test]
    fn test_bsv_reader_writer_roundtrip() {
        let mut writer = BsvWriter::new();
        writer.write_u8(0x42);
        writer.write_u16_le(0x1234);
        writer.write_u32_le(0xDEADBEEF);
        writer.write_u64_le(0x0102030405060708);
        writer.write_varint(VarInt(300));
        writer.write_bytes(b"hello");

        let data = writer.into_bytes();
        let mut reader = BsvReader::new(&data);

        assert_eq!(reader.read_u8().unwrap(), 0x42);
        assert_eq!(reader.read_u16_le().unwrap(), 0x1234);
        assert_eq!(reader.read_u32_le().unwrap(), 0xDEADBEEF);
        assert_eq!(reader.read_u64_le().unwrap(), 0x0102030405060708);
        assert_eq!(reader.read_varint().unwrap(), VarInt(300));
        assert_eq!(reader.read_bytes(5).unwrap(), b"hello");
        assert_eq!(reader.remaining(), 0);
    }

    #[test]
    fn test_bsv_reader_eof() {
        let reader_data: &[u8] = &[0x01];
        let mut reader = BsvReader::new(reader_data);
        assert!(reader.read_u8().is_ok());
        assert!(reader.read_u8().is_err());
    }

    #[test]
    fn test_bsv_reader_varint_sizes() {
        // 1-byte varint
        let mut reader = BsvReader::new(&[0x05]);
        assert_eq!(reader.read_varint().unwrap(), VarInt(5));

        // 3-byte varint (0xfd prefix)
        let mut reader = BsvReader::new(&[0xfd, 0x00, 0x01]);
        assert_eq!(reader.read_varint().unwrap(), VarInt(256));

        // 5-byte varint (0xfe prefix)
        let mut reader = BsvReader::new(&[0xfe, 0x00, 0x00, 0x01, 0x00]);
        assert_eq!(reader.read_varint().unwrap(), VarInt(65536));

        // 9-byte varint (0xff prefix)
        let mut reader = BsvReader::new(&[0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
        assert_eq!(reader.read_varint().unwrap(), VarInt(4294967296));
    }
}
