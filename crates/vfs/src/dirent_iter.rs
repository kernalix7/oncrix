// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Directory entry iterator — `getdents64(2)` output formatting.
//!
//! Provides the `DirentIter` abstraction which packs `linux_dirent64`-style
//! records into a caller-supplied output buffer, tracking position and
//! handling buffer-full conditions.

use oncrix_lib::{Error, Result};

/// Alignment for `linux_dirent64` records (8-byte).
const DIRENT_ALIGN: usize = 8;

/// File type constants for `d_type` field.
pub mod dtype {
    pub const UNKNOWN: u8 = 0;
    pub const FIFO: u8 = 1;
    pub const CHR: u8 = 2;
    pub const DIR: u8 = 4;
    pub const BLK: u8 = 6;
    pub const REG: u8 = 8;
    pub const LNK: u8 = 10;
    pub const SOCK: u8 = 12;
    pub const WHT: u8 = 14;
}

/// A single directory entry description (before encoding).
#[derive(Debug, Clone, Copy)]
pub struct DirentRecord {
    /// Inode number.
    pub ino: u64,
    /// File type (`dtype::*`).
    pub dtype: u8,
    /// File name (NOT NUL-terminated in this struct; the iterator adds NUL).
    pub name: [u8; 256],
    /// Name length (not including the NUL terminator).
    pub name_len: u8,
    /// Filesystem-specific opaque offset cookie (position of *next* entry).
    pub next_offset: i64,
}

impl DirentRecord {
    /// Create a new directory entry record.
    ///
    /// `name` must be no longer than 255 bytes.
    pub fn new(ino: u64, dtype: u8, name: &[u8], next_offset: i64) -> Result<Self> {
        if name.is_empty() || name.len() > 255 {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; 256];
        buf[..name.len()].copy_from_slice(name);
        Ok(Self {
            ino,
            dtype,
            name: buf,
            name_len: name.len() as u8,
            next_offset,
        })
    }

    /// Return the name as a byte slice (without NUL terminator).
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Compute the encoded record size (aligned to 8 bytes):
    ///
    /// `sizeof(ino64) + sizeof(off64) + sizeof(reclen) + sizeof(type) + name_len + 1 (NUL)`
    pub fn encoded_len(&self) -> usize {
        // 8 (ino) + 8 (off) + 2 (reclen) + 1 (type) + name_len + 1 (NUL)
        let raw = 8 + 8 + 2 + 1 + (self.name_len as usize) + 1;
        (raw + DIRENT_ALIGN - 1) & !(DIRENT_ALIGN - 1)
    }
}

/// Iterator that packs directory entries into a user-space buffer.
pub struct DirentIter<'a> {
    buf: &'a mut [u8],
    written: usize,
    entries_packed: u32,
    /// Current directory read position (opaque cookie from filesystem).
    pub pos: i64,
}

impl<'a> DirentIter<'a> {
    /// Create a new iterator writing into `buf`, starting at directory `pos`.
    pub fn new(buf: &'a mut [u8], start_pos: i64) -> Self {
        Self {
            buf,
            written: 0,
            entries_packed: 0,
            pos: start_pos,
        }
    }

    /// Pack a single directory entry into the buffer.
    ///
    /// Returns `Err(WouldBlock)` when the buffer is full (caller should stop
    /// iterating and return what has been packed so far).
    pub fn pack(&mut self, entry: &DirentRecord) -> Result<()> {
        let reclen = entry.encoded_len();
        if self.written + reclen > self.buf.len() {
            if self.entries_packed == 0 {
                // Buffer too small even for one entry.
                return Err(Error::InvalidArgument);
            }
            return Err(Error::WouldBlock);
        }
        let dst = &mut self.buf[self.written..self.written + reclen];

        // Encode `linux_dirent64` layout:
        // [u64 d_ino][i64 d_off][u16 d_reclen][u8 d_type][name bytes][NUL][pad]
        let ino_bytes = entry.ino.to_ne_bytes();
        let off_bytes = entry.next_offset.to_ne_bytes();
        let reclen_u16 = reclen as u16;
        let reclen_bytes = reclen_u16.to_ne_bytes();

        dst[0..8].copy_from_slice(&ino_bytes);
        dst[8..16].copy_from_slice(&off_bytes);
        dst[16..18].copy_from_slice(&reclen_bytes);
        dst[18] = entry.dtype;
        let name_start = 19;
        let name_end = name_start + entry.name_len as usize;
        dst[name_start..name_end].copy_from_slice(entry.name_bytes());
        dst[name_end] = 0; // NUL terminator
        // Padding bytes are already zeroed (buffer is caller-provided; we
        // zero the remainder of the record here).
        for b in &mut dst[name_end + 1..] {
            *b = 0;
        }

        self.written += reclen;
        self.entries_packed += 1;
        self.pos = entry.next_offset;
        Ok(())
    }

    /// Return the number of bytes written to the buffer.
    pub fn bytes_written(&self) -> usize {
        self.written
    }

    /// Return the number of entries packed.
    pub fn count(&self) -> u32 {
        self.entries_packed
    }

    /// Return `true` if at least one entry has been packed.
    pub fn has_entries(&self) -> bool {
        self.entries_packed > 0
    }
}

/// Filesystem-level `readdir` operations.
pub trait ReaddirOps {
    /// Fill `iter` with directory entries starting at `iter.pos`.
    ///
    /// The implementation calls `iter.pack()` for each entry and stops when
    /// it returns `Err(WouldBlock)`. Return the number of entries added.
    fn readdir(&self, sb_id: u64, dir_ino: u64, iter: &mut DirentIter<'_>) -> Result<u32>;
}

/// Emit the mandatory `.` and `..` entries for a directory.
///
/// `ino` is the directory's own inode; `parent_ino` is the parent's.
pub fn emit_dot_entries(iter: &mut DirentIter<'_>, ino: u64, parent_ino: u64) -> Result<()> {
    let dot = DirentRecord::new(ino, dtype::DIR, b".", 1)?;
    iter.pack(&dot)?;
    let dotdot = DirentRecord::new(parent_ino, dtype::DIR, b"..", 2)?;
    iter.pack(&dotdot)?;
    Ok(())
}
