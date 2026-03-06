// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Sequential file interface — procfs/sysfs helper for read-only text streams.
//!
//! Implements the `seq_file` pattern from Linux: a virtual file whose content
//! is generated on demand by a `SeqOps` implementation. Handles buffering,
//! partial reads, and position tracking.

use oncrix_lib::{Error, Result};

/// Maximum size of the seq_file output buffer.
pub const SEQ_BUF_SIZE: usize = 4096;

/// Maximum number of simultaneously open seq_files.
pub const MAX_SEQ_FILES: usize = 32;

/// Output buffer for a seq_file.
#[derive(Debug)]
pub struct SeqBuf {
    data: [u8; SEQ_BUF_SIZE],
    len: usize,
    overflowed: bool,
}

impl SeqBuf {
    /// Create an empty seq buffer.
    pub const fn new() -> Self {
        Self {
            data: [0u8; SEQ_BUF_SIZE],
            len: 0,
            overflowed: false,
        }
    }

    /// Append a byte slice to the buffer.
    ///
    /// Sets the overflow flag if the buffer is full.
    pub fn put_bytes(&mut self, bytes: &[u8]) {
        let remaining = SEQ_BUF_SIZE.saturating_sub(self.len);
        let to_copy = bytes.len().min(remaining);
        self.data[self.len..self.len + to_copy].copy_from_slice(&bytes[..to_copy]);
        self.len += to_copy;
        if bytes.len() > remaining {
            self.overflowed = true;
        }
    }

    /// Append an ASCII decimal representation of a `u64`.
    pub fn put_u64(&mut self, value: u64) {
        let mut buf = [0u8; 20];
        let mut n = value;
        let mut idx = buf.len();
        if n == 0 {
            idx -= 1;
            buf[idx] = b'0';
        } else {
            while n > 0 {
                idx -= 1;
                buf[idx] = b'0' + (n % 10) as u8;
                n /= 10;
            }
        }
        self.put_bytes(&buf[idx..]);
    }

    /// Append an ASCII decimal representation of an `i64`.
    pub fn put_i64(&mut self, value: i64) {
        if value < 0 {
            self.put_bytes(b"-");
            self.put_u64(value.unsigned_abs());
        } else {
            self.put_u64(value as u64);
        }
    }

    /// Append a newline character.
    pub fn put_newline(&mut self) {
        self.put_bytes(b"\n");
    }

    /// Append a space character.
    pub fn put_space(&mut self) {
        self.put_bytes(b" ");
    }

    /// Return the buffered content as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Return the current buffer length.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Return true if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Return true if data was truncated due to overflow.
    pub fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Reset the buffer to empty.
    pub fn reset(&mut self) {
        self.len = 0;
        self.overflowed = false;
    }

    /// Copy up to `len` bytes starting at `offset` into `out`.
    ///
    /// Returns the number of bytes copied.
    pub fn read_at(&self, offset: usize, out: &mut [u8]) -> usize {
        if offset >= self.len {
            return 0;
        }
        let available = self.len - offset;
        let to_copy = available.min(out.len());
        out[..to_copy].copy_from_slice(&self.data[offset..offset + to_copy]);
        to_copy
    }
}

impl Default for SeqBuf {
    fn default() -> Self {
        Self::new()
    }
}

/// Operations that produce the content of a seq_file.
pub trait SeqOps {
    /// Called once at the beginning of a read to initialise iteration state.
    ///
    /// Returns the initial iterator position, or `None` if empty.
    fn start(&self, pos: u64) -> Option<u64>;

    /// Advance the iteration position. Returns the next position or `None`.
    fn next(&self, pos: u64) -> Option<u64>;

    /// Write the entry at `pos` into `buf`.
    fn show(&self, pos: u64, buf: &mut SeqBuf) -> Result<()>;

    /// Called when iteration is complete (cleanup).
    fn stop(&self) {}
}

/// State for an open seq_file instance.
pub struct SeqFile {
    buf: SeqBuf,
    /// Current read position within the generated output buffer.
    read_offset: usize,
    /// Iterator position (passed to SeqOps::start/next).
    iter_pos: u64,
    /// Whether the buffer has been filled for the current read.
    filled: bool,
}

impl SeqFile {
    /// Create a new seq_file starting at iterator position 0.
    pub const fn new() -> Self {
        Self {
            buf: SeqBuf::new(),
            read_offset: 0,
            iter_pos: 0,
            filled: false,
        }
    }

    /// Seek to the beginning (for re-reads after lseek(0)).
    pub fn seek_reset(&mut self) {
        self.buf.reset();
        self.read_offset = 0;
        self.iter_pos = 0;
        self.filled = false;
    }

    /// Generate all output using `ops` and store in the internal buffer.
    pub fn fill<O: SeqOps>(&mut self, ops: &O) -> Result<()> {
        if self.filled {
            return Ok(());
        }
        self.buf.reset();
        let mut pos_opt = ops.start(0);
        while let Some(pos) = pos_opt {
            ops.show(pos, &mut self.buf)?;
            if self.buf.overflowed() {
                break;
            }
            pos_opt = ops.next(pos);
        }
        ops.stop();
        self.filled = true;
        Ok(())
    }

    /// Read up to `out.len()` bytes from the generated output.
    ///
    /// Returns the number of bytes read (0 = EOF).
    pub fn read<O: SeqOps>(&mut self, ops: &O, out: &mut [u8]) -> Result<usize> {
        self.fill(ops)?;
        let copied = self.buf.read_at(self.read_offset, out);
        self.read_offset += copied;
        Ok(copied)
    }

    /// Return the total size of the generated content.
    pub fn content_len(&self) -> usize {
        self.buf.len()
    }
}

impl Default for SeqFile {
    fn default() -> Self {
        Self::new()
    }
}

/// A simple single-string seq_file implementation.
///
/// Useful for procfs files that produce a single fixed string.
pub struct SingleLineSeq {
    content: &'static [u8],
}

impl SingleLineSeq {
    /// Create a single-line seq implementation with the given static content.
    pub const fn new(content: &'static [u8]) -> Self {
        Self { content }
    }
}

impl SeqOps for SingleLineSeq {
    fn start(&self, pos: u64) -> Option<u64> {
        if pos == 0 { Some(0) } else { None }
    }

    fn next(&self, _pos: u64) -> Option<u64> {
        None
    }

    fn show(&self, _pos: u64, buf: &mut SeqBuf) -> Result<()> {
        buf.put_bytes(self.content);
        Ok(())
    }
}

/// A seq implementation backed by a list of key=value pairs.
pub struct KvSeq<'a> {
    pairs: &'a [(&'static str, u64)],
}

impl<'a> KvSeq<'a> {
    /// Create a key-value seq implementation.
    pub const fn new(pairs: &'a [(&'static str, u64)]) -> Self {
        Self { pairs }
    }
}

impl<'a> SeqOps for KvSeq<'a> {
    fn start(&self, pos: u64) -> Option<u64> {
        if (pos as usize) < self.pairs.len() {
            Some(pos)
        } else {
            None
        }
    }

    fn next(&self, pos: u64) -> Option<u64> {
        let next = pos + 1;
        if (next as usize) < self.pairs.len() {
            Some(next)
        } else {
            None
        }
    }

    fn show(&self, pos: u64, buf: &mut SeqBuf) -> Result<()> {
        let idx = pos as usize;
        if idx >= self.pairs.len() {
            return Err(Error::InvalidArgument);
        }
        let (key, val) = self.pairs[idx];
        buf.put_bytes(key.as_bytes());
        buf.put_bytes(b"\t");
        buf.put_u64(val);
        buf.put_newline();
        Ok(())
    }
}
