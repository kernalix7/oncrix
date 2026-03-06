// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! File position management — `lseek(2)` and `llseek(2)` semantics.
//!
//! Handles POSIX seek origins (SEEK_SET, SEEK_CUR, SEEK_END, SEEK_HOLE,
//! SEEK_DATA) and validates the resulting file offset.

use oncrix_lib::{Error, Result};

/// Maximum allowed file offset (off_t max for 64-bit).
pub const OFFSET_MAX: i64 = i64::MAX;

/// Minimum valid file offset (negative offsets are illegal for regular files).
pub const OFFSET_MIN: i64 = 0;

/// `lseek` `whence` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeekWhence {
    /// Set position to `offset`.
    Set,
    /// Set position to current + `offset`.
    Cur,
    /// Set position to file_size + `offset`.
    End,
    /// Set position to start of next hole at or after `offset`.
    Hole,
    /// Set position to start of next data at or after `offset`.
    Data,
}

impl SeekWhence {
    /// Parse from the raw POSIX integer constant.
    pub fn from_raw(raw: i32) -> Result<Self> {
        match raw {
            0 => Ok(Self::Set),
            1 => Ok(Self::Cur),
            2 => Ok(Self::End),
            4 => Ok(Self::Hole),
            3 => Ok(Self::Data),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Convert back to the raw POSIX constant.
    pub const fn to_raw(self) -> i32 {
        match self {
            Self::Set => 0,
            Self::Cur => 1,
            Self::End => 2,
            Self::Data => 3,
            Self::Hole => 4,
        }
    }
}

/// Track the current file position and support seek operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct FilePosition {
    /// Current byte offset within the file.
    pub offset: i64,
    /// Maximum offset reached (for statistics / sparse file tracking).
    pub max_offset: i64,
}

impl FilePosition {
    /// Create a new file position at offset 0.
    pub const fn new() -> Self {
        Self {
            offset: 0,
            max_offset: 0,
        }
    }

    /// Create a file position at a specific offset.
    pub const fn at(offset: i64) -> Self {
        Self {
            offset,
            max_offset: offset,
        }
    }

    /// Compute the new file offset for a seek operation.
    ///
    /// `file_size` — current size of the file in bytes.
    ///
    /// For `SEEK_HOLE` and `SEEK_DATA`, returns the provided `sparse_result`
    /// (the filesystem must compute those). Pass `None` if not supported.
    pub fn compute_seek(
        &self,
        whence: SeekWhence,
        offset: i64,
        file_size: i64,
        sparse_result: Option<i64>,
    ) -> Result<i64> {
        let new_pos = match whence {
            SeekWhence::Set => offset,
            SeekWhence::Cur => self
                .offset
                .checked_add(offset)
                .ok_or(Error::InvalidArgument)?,
            SeekWhence::End => file_size
                .checked_add(offset)
                .ok_or(Error::InvalidArgument)?,
            SeekWhence::Hole | SeekWhence::Data => sparse_result.ok_or(Error::NotImplemented)?,
        };

        if new_pos < 0 {
            return Err(Error::InvalidArgument);
        }
        if new_pos > OFFSET_MAX {
            return Err(Error::InvalidArgument);
        }
        Ok(new_pos)
    }

    /// Apply a computed new offset.
    pub fn apply(&mut self, new_offset: i64) {
        self.offset = new_offset;
        if new_offset > self.max_offset {
            self.max_offset = new_offset;
        }
    }

    /// Advance the position by `delta` bytes (after a read or write).
    ///
    /// Returns the new offset.
    pub fn advance(&mut self, delta: u64) -> i64 {
        let new = self.offset.saturating_add(delta as i64);
        self.apply(new);
        new
    }

    /// Return the current offset.
    pub const fn tell(&self) -> i64 {
        self.offset
    }
}

/// Validate that a file offset is appropriate for a read/write operation.
///
/// Returns `Err(InvalidArgument)` for negative offsets or offsets that would
/// overflow when combined with the I/O length.
pub fn validate_file_offset(offset: i64, length: u64) -> Result<()> {
    if offset < 0 {
        return Err(Error::InvalidArgument);
    }
    // Check for overflow of offset + length.
    let end = (offset as u64)
        .checked_add(length)
        .ok_or(Error::InvalidArgument)?;
    if end > (OFFSET_MAX as u64) {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// State for a directory seek operation.
///
/// Directory seeks use an opaque `off_t` cookie rather than a byte offset.
#[derive(Debug, Clone, Copy, Default)]
pub struct DirPosition {
    /// Opaque directory position cookie.
    pub cookie: i64,
    /// Number of entries emitted so far (for `telldir`/`seekdir`).
    pub entry_count: u32,
}

impl DirPosition {
    /// Create a position at the beginning of the directory.
    pub const fn beginning() -> Self {
        Self {
            cookie: 0,
            entry_count: 0,
        }
    }

    /// Advance to the next directory entry.
    pub fn advance(&mut self, next_cookie: i64) {
        self.cookie = next_cookie;
        self.entry_count += 1;
    }

    /// Rewind to the beginning of the directory.
    pub fn rewind(&mut self) {
        self.cookie = 0;
        self.entry_count = 0;
    }
}
