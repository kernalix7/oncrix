// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! devpts PTY index allocation.
//!
//! Implements pseudo-terminal index management for the devpts filesystem.
//! Each PTY pair (master/slave) is assigned a unique numeric index that
//! determines the device file name in `/dev/pts/<N>`.
//!
//! # Design
//!
//! - [`PtsDevice`] — in-memory representation of an allocated PTY
//! - [`PtsAllocator`] — bitmap-based allocator for PTY indices
//! - `alloc_pts` — allocate the next free PTY index
//! - `free_pts` — release a PTY index back to the pool
//! - `get_pts_path` — format the `/dev/pts/<N>` path
//!
//! # Reference
//!
//! Linux `fs/devpts/inode.c`, `drivers/tty/pty.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of pseudo-terminals.
pub const MAX_PTYS: usize = 256;

/// Number of u64 words needed for the bitmap.
const BITMAP_WORDS: usize = MAX_PTYS / 64;

/// Base path prefix for devpts entries.
const DEVPTS_PREFIX: &[u8] = b"/dev/pts/";

/// Maximum length of a formatted PTY path.
const MAX_PTS_PATH: usize = 16;

// ---------------------------------------------------------------------------
// PTS device
// ---------------------------------------------------------------------------

/// An allocated PTY device.
#[derive(Debug, Clone, Copy)]
pub struct PtsDevice {
    /// PTY index (0..MAX_PTYS).
    pub index: u32,
    /// Simulated master file descriptor.
    pub master_fd: i32,
    /// Simulated slave file descriptor.
    pub slave_fd: i32,
    /// User ID that opened this PTY.
    pub uid: u32,
    /// Group ID for the slave device.
    pub gid: u32,
    /// Slave device permission mode.
    pub mode: u16,
    /// Whether this PTY is currently active.
    pub active: bool,
    /// Window size: rows.
    pub rows: u16,
    /// Window size: columns.
    pub cols: u16,
}

impl PtsDevice {
    /// Creates a new PTY device.
    pub const fn new(index: u32, uid: u32) -> Self {
        Self {
            index,
            master_fd: -1,
            slave_fd: -1,
            uid,
            gid: 5, // Standard tty group.
            mode: 0o620,
            active: true,
            rows: 24,
            cols: 80,
        }
    }

    /// Writes the /dev/pts/<N> path into `out`. Returns bytes written.
    pub fn format_path(&self, out: &mut [u8]) -> usize {
        let prefix = DEVPTS_PREFIX;
        let idx = self.index;
        if out.len() < prefix.len() + 4 {
            return 0;
        }
        out[..prefix.len()].copy_from_slice(prefix);
        let n = write_u32(idx, &mut out[prefix.len()..]);
        prefix.len() + n
    }
}

// ---------------------------------------------------------------------------
// Bitmap allocator
// ---------------------------------------------------------------------------

/// Bitmap-based PTY index allocator.
pub struct PtsAllocator {
    /// Bitmap: bit N set means index N is allocated.
    bitmap: [u64; BITMAP_WORDS],
    /// Number of currently allocated PTYs.
    count: usize,
    /// Allocated PTY devices.
    devices: [Option<PtsDevice>; MAX_PTYS],
    /// Next master fd to assign (synthetic).
    next_fd: i32,
}

impl PtsAllocator {
    /// Creates a new empty allocator.
    pub fn new() -> Self {
        Self {
            bitmap: [0u64; BITMAP_WORDS],
            count: 0,
            devices: core::array::from_fn(|_| None),
            next_fd: 10,
        }
    }

    /// Returns the number of allocated PTYs.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns whether a given index is allocated.
    pub fn is_allocated(&self, index: usize) -> bool {
        if index >= MAX_PTYS {
            return false;
        }
        let word = index / 64;
        let bit = index % 64;
        self.bitmap[word] & (1u64 << bit) != 0
    }

    /// Finds the lowest free index.
    fn find_free(&self) -> Option<usize> {
        for (word_idx, &word) in self.bitmap.iter().enumerate() {
            if word != u64::MAX {
                let bit = word.trailing_ones() as usize;
                let idx = word_idx * 64 + bit;
                if idx < MAX_PTYS {
                    return Some(idx);
                }
            }
        }
        None
    }

    /// Marks an index as allocated.
    fn mark_used(&mut self, index: usize) {
        let word = index / 64;
        let bit = index % 64;
        self.bitmap[word] |= 1u64 << bit;
    }

    /// Marks an index as free.
    fn mark_free(&mut self, index: usize) {
        let word = index / 64;
        let bit = index % 64;
        self.bitmap[word] &= !(1u64 << bit);
    }

    /// Allocates the next free PTY index.
    ///
    /// Returns a reference to the newly created `PtsDevice`.
    pub fn alloc_pts(&mut self, uid: u32) -> Result<u32> {
        if self.count >= MAX_PTYS {
            return Err(Error::OutOfMemory);
        }
        let index = self.find_free().ok_or(Error::OutOfMemory)?;
        self.mark_used(index);

        let mut dev = PtsDevice::new(index as u32, uid);
        dev.master_fd = self.next_fd;
        self.next_fd += 1;
        dev.slave_fd = self.next_fd;
        self.next_fd += 1;

        self.devices[index] = Some(dev);
        self.count += 1;
        Ok(index as u32)
    }

    /// Frees a PTY index.
    pub fn free_pts(&mut self, index: u32) -> Result<()> {
        let idx = index as usize;
        if idx >= MAX_PTYS {
            return Err(Error::InvalidArgument);
        }
        if !self.is_allocated(idx) {
            return Err(Error::NotFound);
        }
        if let Some(dev) = &mut self.devices[idx] {
            dev.active = false;
        }
        self.devices[idx] = None;
        self.mark_free(idx);
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Returns the PTY device for a given index.
    pub fn get_device(&self, index: u32) -> Option<&PtsDevice> {
        let idx = index as usize;
        if idx >= MAX_PTYS {
            return None;
        }
        self.devices[idx].as_ref().filter(|d| d.active)
    }

    /// Returns a mutable reference to the PTY device.
    pub fn get_device_mut(&mut self, index: u32) -> Option<&mut PtsDevice> {
        let idx = index as usize;
        if idx >= MAX_PTYS {
            return None;
        }
        self.devices[idx].as_mut().filter(|d| d.active)
    }
}

impl Default for PtsAllocator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Path formatting
// ---------------------------------------------------------------------------

/// Returns the `/dev/pts/<N>` path for a given PTY index.
///
/// Writes into `out` and returns the number of bytes written.
pub fn get_pts_path(index: u32, out: &mut [u8; MAX_PTS_PATH]) -> usize {
    let prefix = DEVPTS_PREFIX;
    if out.len() < prefix.len() {
        return 0;
    }
    out[..prefix.len()].copy_from_slice(prefix);
    let n = write_u32(index, &mut out[prefix.len()..]);
    prefix.len() + n
}

// ---------------------------------------------------------------------------
// Window size operations
// ---------------------------------------------------------------------------

/// Updates the window size for a PTY.
pub fn pts_set_winsize(alloc: &mut PtsAllocator, index: u32, rows: u16, cols: u16) -> Result<()> {
    let dev = alloc.get_device_mut(index).ok_or(Error::NotFound)?;
    dev.rows = rows;
    dev.cols = cols;
    Ok(())
}

/// Returns the window size for a PTY.
pub fn pts_get_winsize(alloc: &PtsAllocator, index: u32) -> Result<(u16, u16)> {
    let dev = alloc.get_device(index).ok_or(Error::NotFound)?;
    Ok((dev.rows, dev.cols))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn write_u32(mut v: u32, out: &mut [u8]) -> usize {
    if out.is_empty() {
        return 0;
    }
    if v == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut buf = [0u8; 10];
    let mut i = 10usize;
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    let digits = &buf[i..];
    let copy_len = digits.len().min(out.len());
    out[..copy_len].copy_from_slice(&digits[..copy_len]);
    copy_len
}
