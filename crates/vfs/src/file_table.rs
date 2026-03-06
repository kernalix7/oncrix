// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Global file table — system-wide open file description table.
//!
//! Each open file description (`struct file` in the Linux kernel) is an entry
//! in the global file table.  Multiple file descriptors (in the same or
//! different processes) can share a single file description; sharing is
//! tracked via a reference count.
//!
//! # Relationship between fd and file description
//!
//! ```text
//! Process A                     Global FileTable
//! ┌─────────────┐               ┌─────────────────────────────────┐
//! │ fd 3  ──────┼──────────────►│ slot 42: FileDescription        │
//! │             │               │   inode_id=100, pos=0, refs=2   │
//! └─────────────┘               └──────────────────┬──────────────┘
//! Process B                                         │
//! ┌─────────────┐                                   │ (shared via dup/fork)
//! │ fd 5  ──────┼───────────────────────────────────┘
//! └─────────────┘
//! ```
//!
//! # Reference counting
//!
//! - [`FileTable::alloc_file`] sets `ref_count = 1`.
//! - [`FileTable::get_file`] increments `ref_count` and returns the slot.
//! - [`FileTable::put_file`] decrements `ref_count`; when it reaches 0
//!   the slot is freed.
//! - [`FileTable::dup_file`] increments `ref_count` (for `dup2`/`fork`).
//!
//! # References
//!
//! - Linux `fs/file.c`, `include/linux/fs.h` (`struct file`)
//! - POSIX.1-2024 `open(2)`, `dup(2)`, `close(2)`

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of global open file descriptions.
const MAX_FILE_DESCRIPTIONS: usize = 1024;

// ── FileMode ──────────────────────────────────────────────────────────────────

/// Access mode for an open file description.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FileMode {
    /// Open for reading only (`O_RDONLY`).
    #[default]
    ReadOnly,
    /// Open for writing only (`O_WRONLY`).
    WriteOnly,
    /// Open for reading and writing (`O_RDWR`).
    ReadWrite,
}

impl FileMode {
    /// Returns `true` if the mode permits reading.
    pub fn can_read(self) -> bool {
        matches!(self, Self::ReadOnly | Self::ReadWrite)
    }

    /// Returns `true` if the mode permits writing.
    pub fn can_write(self) -> bool {
        matches!(self, Self::WriteOnly | Self::ReadWrite)
    }

    /// Construct from the low two bits of an O_ flags word.
    pub fn from_flags(flags: u32) -> Self {
        match flags & 0x03 {
            0 => Self::ReadOnly,
            1 => Self::WriteOnly,
            _ => Self::ReadWrite,
        }
    }
}

// ── O_ flag constants ─────────────────────────────────────────────────────────

/// Open-file flag: reads/writes go to end of file (`O_APPEND`).
pub const O_APPEND: u32 = 0x0400;
/// Open-file flag: non-blocking I/O (`O_NONBLOCK`).
pub const O_NONBLOCK: u32 = 0x0800;
/// Open-file flag: close on exec (`O_CLOEXEC`).
pub const O_CLOEXEC: u32 = 0x80000;

// ── FileStatusFlags ───────────────────────────────────────────────────────────

/// Status flags that may be changed on an open file description via `fcntl(F_SETFL)`.
#[derive(Debug, Clone, Copy, Default)]
pub struct FileStatusFlags(pub u32);

impl FileStatusFlags {
    /// Writes always go to the end of file.
    pub const APPEND: u32 = 0x01;
    /// Non-blocking I/O.
    pub const NONBLOCK: u32 = 0x02;
    /// Data-integrity sync on write.
    pub const DSYNC: u32 = 0x04;
    /// Full integrity sync on write.
    pub const SYNC: u32 = 0x08;
    /// Direct I/O (bypass page cache).
    pub const DIRECT: u32 = 0x10;
    /// Do not update access time on read.
    pub const NOATIME: u32 = 0x20;

    /// Returns `true` if the APPEND flag is set.
    pub fn is_append(self) -> bool {
        self.0 & Self::APPEND != 0
    }

    /// Returns `true` if the NONBLOCK flag is set.
    pub fn is_nonblock(self) -> bool {
        self.0 & Self::NONBLOCK != 0
    }

    /// Returns `true` if the SYNC flag is set.
    pub fn is_sync(self) -> bool {
        self.0 & Self::SYNC != 0
    }

    /// Returns `true` if DIRECT I/O is requested.
    pub fn is_direct(self) -> bool {
        self.0 & Self::DIRECT != 0
    }
}

// ── FileDescription ───────────────────────────────────────────────────────────

/// A single entry in the global file table.
///
/// Corresponds to `struct file` in the Linux kernel.
#[derive(Debug, Clone, Copy)]
pub struct FileDescription {
    /// Inode this file description refers to.
    pub inode_id: u64,
    /// Mount instance identifier (which mounted FS owns the inode).
    pub mount_id: u64,
    /// Open flags (O_RDONLY, O_WRONLY, O_RDWR, O_APPEND, O_NONBLOCK, O_CLOEXEC).
    pub flags: u32,
    /// Current file position (bytes from beginning of file).
    pub pos: u64,
    /// Number of file descriptors (across all processes) sharing this description.
    pub ref_count: u32,
    /// Status flags modifiable via `fcntl(F_SETFL)`.
    pub status_flags: FileStatusFlags,
    /// Access mode derived from `flags`.
    pub mode: FileMode,
    /// Monotonic generation counter (incremented on each reuse of this slot).
    pub generation: u32,
    /// Whether this slot is occupied.
    in_use: bool,
}

impl FileDescription {
    /// Create an empty (unused) slot.
    pub const fn empty() -> Self {
        Self {
            inode_id: 0,
            mount_id: 0,
            flags: 0,
            pos: 0,
            ref_count: 0,
            status_flags: FileStatusFlags(0),
            mode: FileMode::ReadOnly,
            generation: 0,
            in_use: false,
        }
    }

    /// Returns `true` if the description permits reading.
    pub fn can_read(&self) -> bool {
        self.mode.can_read()
    }

    /// Returns `true` if the description permits writing.
    pub fn can_write(&self) -> bool {
        self.mode.can_write()
    }

    /// Returns `true` if the `O_APPEND` flag is set.
    pub fn is_append(&self) -> bool {
        self.flags & O_APPEND != 0 || self.status_flags.is_append()
    }

    /// Returns `true` if the `O_NONBLOCK` flag is set.
    pub fn is_nonblock(&self) -> bool {
        self.flags & O_NONBLOCK != 0 || self.status_flags.is_nonblock()
    }

    /// Returns `true` if the `O_CLOEXEC` flag is set.
    pub fn is_cloexec(&self) -> bool {
        self.flags & O_CLOEXEC != 0
    }
}

// ── FileTableStats ────────────────────────────────────────────────────────────

/// Aggregate statistics for the global file table.
#[derive(Debug, Clone, Copy, Default)]
pub struct FileTableStats {
    /// Number of file descriptions currently open.
    pub total_open: u64,
    /// Peak number of simultaneously open file descriptions.
    pub peak_open: u64,
    /// Total file descriptions allocated since boot.
    pub total_allocations: u64,
    /// Total file descriptions freed since boot.
    pub total_frees: u64,
}

// ── FileTable ─────────────────────────────────────────────────────────────────

/// The system-wide global file table.
pub struct FileTable {
    /// Fixed-size pool of file description slots.
    descriptions: [FileDescription; MAX_FILE_DESCRIPTIONS],
    /// Operational statistics.
    pub stats: FileTableStats,
}

impl FileTable {
    /// Create a new, empty global file table.
    pub const fn new() -> Self {
        Self {
            descriptions: [const { FileDescription::empty() }; MAX_FILE_DESCRIPTIONS],
            stats: FileTableStats {
                total_open: 0,
                peak_open: 0,
                total_allocations: 0,
                total_frees: 0,
            },
        }
    }

    /// Allocate a new file description.
    ///
    /// Sets `ref_count = 1`.  Returns the slot index on success.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] — no free slots available.
    /// - [`Error::InvalidArgument`] — `inode_id` is zero.
    pub fn alloc_file(&mut self, inode_id: u64, mount_id: u64, flags: u32) -> Result<usize> {
        if inode_id == 0 {
            return Err(Error::InvalidArgument);
        }
        let slot = self
            .descriptions
            .iter()
            .position(|d| !d.in_use)
            .ok_or(Error::OutOfMemory)?;
        let desc = &mut self.descriptions[slot];
        let new_gen = desc.generation.wrapping_add(1);
        *desc = FileDescription::empty();
        desc.inode_id = inode_id;
        desc.mount_id = mount_id;
        desc.flags = flags;
        desc.mode = FileMode::from_flags(flags);
        desc.status_flags = FileStatusFlags(
            (if flags & O_APPEND != 0 {
                FileStatusFlags::APPEND
            } else {
                0
            }) | (if flags & O_NONBLOCK != 0 {
                FileStatusFlags::NONBLOCK
            } else {
                0
            }),
        );
        desc.ref_count = 1;
        desc.generation = new_gen;
        desc.in_use = true;
        self.stats.total_allocations += 1;
        self.stats.total_open += 1;
        if self.stats.total_open > self.stats.peak_open {
            self.stats.peak_open = self.stats.total_open;
        }
        Ok(slot)
    }

    /// Increment the reference count for the description at `slot`.
    ///
    /// Returns the slot index.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — slot not in use.
    pub fn get_file(&mut self, slot: usize) -> Result<usize> {
        if slot >= MAX_FILE_DESCRIPTIONS {
            return Err(Error::InvalidArgument);
        }
        let desc = &mut self.descriptions[slot];
        if !desc.in_use {
            return Err(Error::NotFound);
        }
        desc.ref_count = desc.ref_count.saturating_add(1);
        Ok(slot)
    }

    /// Decrement the reference count for the description at `slot`.
    ///
    /// Frees the slot when the count reaches zero.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — slot not in use.
    pub fn put_file(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_FILE_DESCRIPTIONS {
            return Err(Error::InvalidArgument);
        }
        let desc = &mut self.descriptions[slot];
        if !desc.in_use {
            return Err(Error::NotFound);
        }
        desc.ref_count = desc.ref_count.saturating_sub(1);
        if desc.ref_count == 0 {
            desc.in_use = false;
            self.stats.total_open = self.stats.total_open.saturating_sub(1);
            self.stats.total_frees += 1;
        }
        Ok(())
    }

    /// Duplicate a file description, incrementing its reference count.
    ///
    /// Used by `dup(2)`, `dup2(2)`, and `fork(2)`.  Returns the same slot
    /// index with an incremented `ref_count`.
    pub fn dup_file(&mut self, slot: usize) -> Result<usize> {
        self.get_file(slot)
    }

    /// Set the status flags (`fcntl(F_SETFL)`) for the description at `slot`.
    ///
    /// Only the mutable subset of flags is accepted (APPEND, NONBLOCK, DSYNC,
    /// SYNC, DIRECT, NOATIME).  The access mode bits are immutable.
    pub fn set_flags(&mut self, slot: usize, new_flags: FileStatusFlags) -> Result<()> {
        if slot >= MAX_FILE_DESCRIPTIONS {
            return Err(Error::InvalidArgument);
        }
        let desc = &mut self.descriptions[slot];
        if !desc.in_use {
            return Err(Error::NotFound);
        }
        desc.status_flags = new_flags;
        // Mirror APPEND into the raw flags word as well.
        if new_flags.is_append() {
            desc.flags |= O_APPEND;
        } else {
            desc.flags &= !O_APPEND;
        }
        if new_flags.is_nonblock() {
            desc.flags |= O_NONBLOCK;
        } else {
            desc.flags &= !O_NONBLOCK;
        }
        Ok(())
    }

    /// Retrieve the current status flags (`fcntl(F_GETFL)`) for `slot`.
    pub fn get_flags(&self, slot: usize) -> Result<FileStatusFlags> {
        if slot >= MAX_FILE_DESCRIPTIONS {
            return Err(Error::InvalidArgument);
        }
        let desc = &self.descriptions[slot];
        if !desc.in_use {
            return Err(Error::NotFound);
        }
        Ok(desc.status_flags)
    }

    /// Update the file position for `slot`.
    ///
    /// Called by `lseek(2)` and the internal I/O paths.
    pub fn set_pos(&mut self, slot: usize, pos: u64) -> Result<()> {
        if slot >= MAX_FILE_DESCRIPTIONS {
            return Err(Error::InvalidArgument);
        }
        let desc = &mut self.descriptions[slot];
        if !desc.in_use {
            return Err(Error::NotFound);
        }
        desc.pos = pos;
        Ok(())
    }

    /// Return an immutable reference to the description at `slot`.
    pub fn get(&self, slot: usize) -> Option<&FileDescription> {
        self.descriptions.get(slot).filter(|d| d.in_use)
    }

    /// Return a mutable reference to the description at `slot`.
    pub fn get_mut(&mut self, slot: usize) -> Option<&mut FileDescription> {
        let desc = self.descriptions.get_mut(slot)?;
        if desc.in_use { Some(desc) } else { None }
    }

    /// Return the number of currently occupied slots.
    pub fn active_count(&self) -> usize {
        self.descriptions.iter().filter(|d| d.in_use).count()
    }
}

impl Default for FileTable {
    fn default() -> Self {
        Self::new()
    }
}
