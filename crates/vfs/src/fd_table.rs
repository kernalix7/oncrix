// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-process file descriptor table.
//!
//! Manages the mapping from file descriptor numbers (integers) to open-file
//! description slots, supporting open, close, dup, and cloexec semantics.

use oncrix_lib::{Error, Result};

/// Maximum file descriptors per process (POSIX minimum is 20; we use 256).
pub const MAX_FDS: usize = 256;

/// Flags associated with a file descriptor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FdFlags(pub u32);

impl FdFlags {
    /// Close-on-exec flag (FD_CLOEXEC).
    pub const CLOEXEC: u32 = 1 << 0;

    /// Test whether a flag is set.
    pub const fn has(self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }

    /// Return a new FdFlags with the given flag set.
    pub const fn with(self, flag: u32) -> Self {
        Self(self.0 | flag)
    }

    /// Return a new FdFlags with the given flag cleared.
    pub const fn without(self, flag: u32) -> Self {
        Self(self.0 & !flag)
    }
}

/// A single file descriptor slot in the per-process table.
#[derive(Debug, Clone, Copy)]
pub struct FdEntry {
    /// Index into the system-wide open-file description table.
    /// `u32::MAX` means the slot is free.
    pub ofd_index: u32,
    /// Per-descriptor flags (e.g., FD_CLOEXEC).
    pub flags: FdFlags,
}

impl FdEntry {
    const FREE_SENTINEL: u32 = u32::MAX;

    /// Create a free (unused) entry.
    pub const fn free() -> Self {
        Self {
            ofd_index: Self::FREE_SENTINEL,
            flags: FdFlags(0),
        }
    }

    /// Create an active entry pointing to an OFD slot.
    pub const fn active(ofd_index: u32, flags: FdFlags) -> Self {
        Self { ofd_index, flags }
    }

    /// Return true if this slot is free.
    pub const fn is_free(self) -> bool {
        self.ofd_index == Self::FREE_SENTINEL
    }
}

/// Per-process file descriptor table.
pub struct FdTable {
    entries: [FdEntry; MAX_FDS],
    /// Lowest fd known to be possibly free (hint for allocation).
    next_free_hint: usize,
    /// Number of open file descriptors.
    open_count: usize,
}

impl FdTable {
    /// Create a new, empty file descriptor table.
    ///
    /// By convention, fds 0, 1, 2 (stdin/stdout/stderr) are left for the
    /// caller to populate via `open_at`.
    pub fn new() -> Self {
        Self {
            entries: [const { FdEntry::free() }; MAX_FDS],
            next_free_hint: 0,
            open_count: 0,
        }
    }

    /// Allocate the lowest available file descriptor and associate it with
    /// the given open-file description index.
    ///
    /// Returns the new fd number.
    pub fn open_at(&mut self, ofd_index: u32, flags: FdFlags) -> Result<usize> {
        self.alloc_fd_from(self.next_free_hint, ofd_index, flags)
    }

    /// Allocate the lowest fd >= `min_fd`.
    pub fn open_at_min(&mut self, min_fd: usize, ofd_index: u32, flags: FdFlags) -> Result<usize> {
        self.alloc_fd_from(min_fd, ofd_index, flags)
    }

    fn alloc_fd_from(&mut self, start: usize, ofd_index: u32, flags: FdFlags) -> Result<usize> {
        for fd in start..MAX_FDS {
            if self.entries[fd].is_free() {
                self.entries[fd] = FdEntry::active(ofd_index, flags);
                self.open_count += 1;
                self.next_free_hint = fd + 1;
                return Ok(fd);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Close (free) a file descriptor.
    ///
    /// Returns the OFD index that was associated with it.
    pub fn close(&mut self, fd: usize) -> Result<u32> {
        self.check_fd(fd)?;
        let entry = self.entries[fd];
        if entry.is_free() {
            return Err(Error::NotFound);
        }
        self.entries[fd] = FdEntry::free();
        self.open_count -= 1;
        if fd < self.next_free_hint {
            self.next_free_hint = fd;
        }
        Ok(entry.ofd_index)
    }

    /// Duplicate a file descriptor to the lowest available fd >= `min_fd`.
    ///
    /// Returns the new fd number.
    pub fn dup(&mut self, oldfd: usize, min_fd: usize, flags: FdFlags) -> Result<usize> {
        self.check_fd(oldfd)?;
        let entry = self.entries[oldfd];
        if entry.is_free() {
            return Err(Error::NotFound);
        }
        self.alloc_fd_from(min_fd, entry.ofd_index, flags)
    }

    /// Duplicate `oldfd` onto exactly `newfd`, closing `newfd` if open.
    ///
    /// Returns the OFD index of the old `newfd` (if it was open) so the
    /// caller can drop its reference.
    pub fn dup2(&mut self, oldfd: usize, newfd: usize) -> Result<Option<u32>> {
        self.check_fd(oldfd)?;
        self.check_fd(newfd)?;
        let src = self.entries[oldfd];
        if src.is_free() {
            return Err(Error::NotFound);
        }
        if oldfd == newfd {
            return Ok(None);
        }
        let old_ofd = if self.entries[newfd].is_free() {
            None
        } else {
            self.open_count -= 1;
            Some(self.entries[newfd].ofd_index)
        };
        self.entries[newfd] = FdEntry::active(src.ofd_index, FdFlags(0));
        self.open_count += 1;
        Ok(old_ofd)
    }

    /// Get the OFD index for an open fd.
    pub fn get_ofd(&self, fd: usize) -> Result<u32> {
        self.check_fd(fd)?;
        let entry = self.entries[fd];
        if entry.is_free() {
            Err(Error::NotFound)
        } else {
            Ok(entry.ofd_index)
        }
    }

    /// Get the flags for a file descriptor.
    pub fn get_flags(&self, fd: usize) -> Result<FdFlags> {
        self.check_fd(fd)?;
        let entry = self.entries[fd];
        if entry.is_free() {
            Err(Error::NotFound)
        } else {
            Ok(entry.flags)
        }
    }

    /// Set the flags for a file descriptor.
    pub fn set_flags(&mut self, fd: usize, flags: FdFlags) -> Result<()> {
        self.check_fd(fd)?;
        if self.entries[fd].is_free() {
            return Err(Error::NotFound);
        }
        self.entries[fd].flags = flags;
        Ok(())
    }

    /// Close all file descriptors that have the FD_CLOEXEC flag set (on exec).
    ///
    /// Returns a slice-like iterator of closed OFD indices for the caller to
    /// decrement reference counts. Since we are `no_std`, this returns a small
    /// fixed-size array of the first closed indices (caller must call multiple
    /// times or handle the rest).
    pub fn close_on_exec(&mut self) -> CloseOnExecIter<'_> {
        CloseOnExecIter {
            table: self,
            pos: 0,
        }
    }

    /// Return the number of open file descriptors.
    pub fn open_count(&self) -> usize {
        self.open_count
    }

    /// Clone this fd table for fork (increases OFD reference count tracking
    /// is the caller's responsibility).
    pub fn fork_clone(&self) -> Self {
        Self {
            entries: self.entries,
            next_free_hint: self.next_free_hint,
            open_count: self.open_count,
        }
    }

    fn check_fd(&self, fd: usize) -> Result<()> {
        if fd < MAX_FDS {
            Ok(())
        } else {
            Err(Error::InvalidArgument)
        }
    }
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Iterator over file descriptors to close on exec.
pub struct CloseOnExecIter<'a> {
    table: &'a mut FdTable,
    pos: usize,
}

impl<'a> CloseOnExecIter<'a> {
    /// Advance to the next cloexec fd and close it.
    ///
    /// Returns `Some(ofd_index)` for each closed descriptor, `None` when done.
    pub fn next_close(&mut self) -> Option<u32> {
        while self.pos < MAX_FDS {
            let fd = self.pos;
            self.pos += 1;
            let entry = self.table.entries[fd];
            if !entry.is_free() && entry.flags.has(FdFlags::CLOEXEC) {
                self.table.entries[fd] = FdEntry::free();
                self.table.open_count -= 1;
                return Some(entry.ofd_index);
            }
        }
        None
    }
}

/// Standard file descriptor numbers.
pub mod stdfd {
    /// Standard input.
    pub const STDIN: usize = 0;
    /// Standard output.
    pub const STDOUT: usize = 1;
    /// Standard error.
    pub const STDERR: usize = 2;
}

/// Install standard fds (0/1/2) pointing at the given OFD indices.
///
/// Typically called when setting up a new process image.
pub fn install_std_fds(table: &mut FdTable, stdin: u32, stdout: u32, stderr: u32) -> Result<()> {
    if !table.entries[stdfd::STDIN].is_free()
        || !table.entries[stdfd::STDOUT].is_free()
        || !table.entries[stdfd::STDERR].is_free()
    {
        return Err(Error::AlreadyExists);
    }
    table.entries[stdfd::STDIN] = FdEntry::active(stdin, FdFlags(0));
    table.entries[stdfd::STDOUT] = FdEntry::active(stdout, FdFlags(0));
    table.entries[stdfd::STDERR] = FdEntry::active(stderr, FdFlags(0));
    table.open_count += 3;
    Ok(())
}
