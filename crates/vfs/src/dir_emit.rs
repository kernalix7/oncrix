// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Directory entry emission for the ONCRIX VFS.
//!
//! Provides the `dir_emit` family of helpers used by filesystem
//! `readdir`/`getdents64` implementations to fill user-space buffers with
//! `linux_dirent64` records. Filesystems call `emit` for each directory
//! entry; the helper handles serialization, alignment, and buffer overflow
//! detection.

use oncrix_lib::{Error, Result};

/// Maximum file name length for a directory entry.
pub const DIRENT_MAX_NAME: usize = 255;

/// Size of the fixed part of a `linux_dirent64` record (excluding name).
pub const DIRENT64_FIXED_SIZE: usize = 19; // d_ino(8) + d_off(8) + d_reclen(2) + d_type(1)

/// File type values for the `d_type` field of `linux_dirent64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DirentType {
    /// Unknown type.
    Unknown = 0,
    /// Named pipe (FIFO).
    Fifo = 1,
    /// Character device.
    CharDev = 2,
    /// Directory.
    Dir = 4,
    /// Block device.
    BlkDev = 6,
    /// Regular file.
    RegFile = 8,
    /// Symbolic link.
    Symlink = 10,
    /// Unix-domain socket.
    Socket = 12,
    /// Whiteout (overlay/union filesystems).
    Whiteout = 14,
}

impl DirentType {
    /// Convert a Unix inode mode type nibble (the `S_IFMT` portion >> 12) to a `DirentType`.
    pub fn from_mode_nibble(nibble: u8) -> Self {
        match nibble {
            1 => Self::Fifo,
            2 => Self::CharDev,
            4 => Self::Dir,
            6 => Self::BlkDev,
            8 => Self::RegFile,
            10 => Self::Symlink,
            12 => Self::Socket,
            14 => Self::Whiteout,
            _ => Self::Unknown,
        }
    }
}

/// A single directory entry ready to be emitted to user space.
#[derive(Debug, Clone, Copy)]
pub struct DirEntry {
    /// Inode number of the entry.
    pub ino: u64,
    /// Cookie for `telldir`/`seekdir` (byte offset in the directory).
    pub offset: u64,
    /// File type.
    pub file_type: DirentType,
    /// Name bytes.
    name: [u8; DIRENT_MAX_NAME + 1],
    /// Length of the name in bytes (excluding null terminator).
    name_len: usize,
}

impl DirEntry {
    /// Construct a new directory entry.
    ///
    /// Returns `InvalidArgument` if `name` is empty or exceeds `DIRENT_MAX_NAME`.
    pub fn new(ino: u64, offset: u64, file_type: DirentType, name: &[u8]) -> Result<Self> {
        if name.is_empty() || name.len() > DIRENT_MAX_NAME {
            return Err(Error::InvalidArgument);
        }
        let mut entry = Self {
            ino,
            offset,
            file_type,
            name: [0u8; DIRENT_MAX_NAME + 1],
            name_len: name.len(),
        };
        entry.name[..name.len()].copy_from_slice(name);
        Ok(entry)
    }

    /// Return the entry name as a byte slice (without null terminator).
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Compute the size of the `linux_dirent64` record for this entry (8-byte aligned).
    pub fn record_size(&self) -> usize {
        let raw = DIRENT64_FIXED_SIZE + self.name_len + 1; // +1 for null terminator
        (raw + 7) & !7 // round up to 8-byte alignment
    }

    /// Encode this entry as a `linux_dirent64` record into `buf`.
    ///
    /// Returns the number of bytes written, or `InvalidArgument` if `buf` is too small.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        let reclen = self.record_size();
        if buf.len() < reclen {
            return Err(Error::InvalidArgument);
        }
        // Zero the record first (handles alignment padding).
        for b in &mut buf[..reclen] {
            *b = 0;
        }
        buf[0..8].copy_from_slice(&self.ino.to_le_bytes());
        buf[8..16].copy_from_slice(&self.offset.to_le_bytes());
        buf[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
        buf[18] = self.file_type as u8;
        buf[19..19 + self.name_len].copy_from_slice(self.name());
        // buf[19 + name_len] is already 0 from the zero-fill above.
        Ok(reclen)
    }
}

/// Context passed to filesystem `readdir` implementations to receive entries.
pub struct DirEmitCtx<'a> {
    /// Output buffer for `linux_dirent64` records.
    buf: &'a mut [u8],
    /// Bytes consumed so far.
    pos: usize,
    /// Total bytes successfully emitted.
    pub emitted: usize,
    /// Set to `true` when the buffer is full.
    pub full: bool,
}

impl<'a> DirEmitCtx<'a> {
    /// Create a new emit context wrapping `buf`.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            emitted: 0,
            full: false,
        }
    }

    /// Emit a directory entry into the output buffer.
    ///
    /// Returns `WouldBlock` if the buffer is full (caller should stop iteration).
    pub fn emit(&mut self, entry: &DirEntry) -> Result<()> {
        let reclen = entry.record_size();
        if self.pos + reclen > self.buf.len() {
            self.full = true;
            return Err(Error::WouldBlock);
        }
        entry.encode(&mut self.buf[self.pos..self.pos + reclen])?;
        self.pos += reclen;
        self.emitted += reclen;
        Ok(())
    }

    /// Emit a `.` (current directory) entry.
    pub fn emit_dot(&mut self, dir_ino: u64, offset: u64) -> Result<()> {
        let entry = DirEntry::new(dir_ino, offset, DirentType::Dir, b".")?;
        self.emit(&entry)
    }

    /// Emit a `..` (parent directory) entry.
    pub fn emit_dotdot(&mut self, parent_ino: u64, offset: u64) -> Result<()> {
        let entry = DirEntry::new(parent_ino, offset, DirentType::Dir, b"..")?;
        self.emit(&entry)
    }

    /// Return the number of bytes successfully written to the buffer.
    pub fn bytes_written(&self) -> usize {
        self.emitted
    }
}

/// Compute the `linux_dirent64` record length for a name of `name_len` bytes.
pub fn dirent64_reclen(name_len: usize) -> usize {
    let raw = DIRENT64_FIXED_SIZE + name_len + 1;
    (raw + 7) & !7
}

/// Validate that a directory entry name is a valid non-empty path component.
///
/// Rejects empty names, names containing `/`, and `.`/`..`.
pub fn validate_entry_name(name: &[u8]) -> Result<()> {
    if name.is_empty() || name.len() > DIRENT_MAX_NAME {
        return Err(Error::InvalidArgument);
    }
    if name == b"." || name == b".." {
        return Err(Error::InvalidArgument);
    }
    if name.contains(&b'/') {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}
