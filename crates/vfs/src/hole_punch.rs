// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! File hole punching support for the ONCRIX VFS.
//!
//! Implements the `FALLOC_FL_PUNCH_HOLE` operation that deallocates a byte
//! range within a file, replacing the region with a sparse hole that reads
//! back as zeros without consuming storage blocks.

use oncrix_lib::{Error, Result};

/// Flag bit for `fallocate` to punch a hole (deallocate) instead of allocate.
pub const FALLOC_FL_PUNCH_HOLE: u32 = 0x02;

/// Flag bit to keep the file size unchanged during hole punch.
pub const FALLOC_FL_KEEP_SIZE: u32 = 0x01;

/// Maximum number of hole descriptors per inode.
pub const HOLE_MAX_ENTRIES: usize = 128;

/// Describes a single sparse hole within a file.
#[derive(Debug, Clone, Copy, Default)]
pub struct HoleEntry {
    /// Byte offset at which the hole begins (page-aligned).
    pub offset: u64,
    /// Length of the hole in bytes (page-aligned).
    pub length: u64,
    /// Whether this entry is active.
    pub active: bool,
}

impl HoleEntry {
    /// Construct a new hole entry.
    pub const fn new(offset: u64, length: u64) -> Self {
        Self {
            offset,
            length,
            active: true,
        }
    }

    /// Return the exclusive end byte of this hole.
    pub fn end(&self) -> u64 {
        self.offset + self.length
    }

    /// Return `true` if a byte at `pos` falls within this hole.
    pub fn contains(&self, pos: u64) -> bool {
        self.active && pos >= self.offset && pos < self.end()
    }

    /// Return `true` if this hole overlaps the range `[start, start+len)`.
    pub fn overlaps(&self, start: u64, len: u64) -> bool {
        if !self.active {
            return false;
        }
        let end = start + len;
        self.offset < end && self.end() > start
    }
}

/// Per-inode table of sparse hole descriptors.
pub struct HoleTable {
    entries: [HoleEntry; HOLE_MAX_ENTRIES],
    count: usize,
}

impl HoleTable {
    /// Create an empty hole table.
    pub const fn new() -> Self {
        Self {
            entries: [HoleEntry {
                offset: 0,
                length: 0,
                active: false,
            }; HOLE_MAX_ENTRIES],
            count: 0,
        }
    }

    /// Punch a new hole covering `[offset, offset+length)`.
    ///
    /// Both `offset` and `length` must be page-aligned. Returns `OutOfMemory`
    /// if the table is full, `InvalidArgument` if alignment is violated.
    pub fn punch(&mut self, offset: u64, length: u64) -> Result<()> {
        validate_alignment(offset, length)?;
        if self.count >= HOLE_MAX_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        // Merge with an existing adjacent or overlapping entry if possible.
        for i in 0..self.count {
            let e = &mut self.entries[i];
            if !e.active {
                continue;
            }
            // Overlapping or adjacent — extend the existing entry.
            if e.overlaps(offset, length) || e.end() == offset || offset + length == e.offset {
                let new_start = e.offset.min(offset);
                let new_end = e.end().max(offset + length);
                e.offset = new_start;
                e.length = new_end - new_start;
                return Ok(());
            }
        }
        // No merge possible — insert a new entry.
        let idx = self.count;
        self.entries[idx] = HoleEntry::new(offset, length);
        self.count += 1;
        Ok(())
    }

    /// Return `true` if the byte at `pos` falls within any hole.
    pub fn is_hole(&self, pos: u64) -> bool {
        for i in 0..self.count {
            if self.entries[i].contains(pos) {
                return true;
            }
        }
        false
    }

    /// Find the next data offset at or after `pos` (skipping holes).
    ///
    /// Returns `pos` if it is already in a data region, or `NotFound` if
    /// the file ends in a hole.
    pub fn next_data_offset(&self, pos: u64, file_size: u64) -> Result<u64> {
        if pos >= file_size {
            return Err(Error::NotFound);
        }
        let mut cur = pos;
        loop {
            if cur >= file_size {
                return Err(Error::NotFound);
            }
            if !self.is_hole(cur) {
                return Ok(cur);
            }
            // Advance past this hole.
            let mut advanced = false;
            for i in 0..self.count {
                let e = &self.entries[i];
                if e.active && e.contains(cur) {
                    cur = e.end();
                    advanced = true;
                    break;
                }
            }
            if !advanced {
                return Ok(cur);
            }
        }
    }

    /// Remove all holes that overlap a given range (e.g., after write fills data).
    pub fn remove_overlapping(&mut self, offset: u64, length: u64) {
        for i in 0..self.count {
            if self.entries[i].overlaps(offset, length) {
                self.entries[i].active = false;
            }
        }
    }

    /// Return the number of active hole entries.
    pub fn active_count(&self) -> usize {
        self.entries[..self.count]
            .iter()
            .filter(|e| e.active)
            .count()
    }
}

impl Default for HoleTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a lseek `SEEK_HOLE` / `SEEK_DATA` query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeekResult {
    /// Position of the next hole.
    Hole(u64),
    /// Position of the next data region.
    Data(u64),
    /// No more holes or data regions (end of file).
    Eof,
}

/// Validate that `offset` and `length` are 4 KiB page-aligned.
pub fn validate_alignment(offset: u64, length: u64) -> Result<()> {
    const PAGE_MASK: u64 = 4095;
    if offset & PAGE_MASK != 0 || length & PAGE_MASK != 0 {
        return Err(Error::InvalidArgument);
    }
    if length == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Round a byte length up to the next page boundary.
pub fn page_align_up(len: u64) -> u64 {
    const PAGE_SIZE: u64 = 4096;
    (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// Round a byte offset down to its page boundary.
pub fn page_align_down(offset: u64) -> u64 {
    offset & !4095u64
}
