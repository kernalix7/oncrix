// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Open file descriptions and file descriptor table.
//!
//! Each process holds a file descriptor table mapping integer FDs
//! to open file descriptions. This module defines the structures
//! for tracking open files.

use crate::inode::InodeNumber;
use core::fmt;

/// File descriptor (small non-negative integer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Fd(pub u32);

impl Fd {
    /// Standard input.
    pub const STDIN: Self = Self(0);
    /// Standard output.
    pub const STDOUT: Self = Self(1);
    /// Standard error.
    pub const STDERR: Self = Self(2);
}

impl fmt::Display for Fd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fd:{}", self.0)
    }
}

/// Open file flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenFlags(pub u32);

impl fmt::Display for OpenFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "O_{:#x}", self.0)
    }
}

impl OpenFlags {
    /// Read-only.
    pub const O_RDONLY: Self = Self(0);
    /// Write-only.
    pub const O_WRONLY: Self = Self(1);
    /// Read-write.
    pub const O_RDWR: Self = Self(2);
    /// Create if not exists.
    pub const O_CREAT: Self = Self(0o100);
    /// Truncate on open.
    pub const O_TRUNC: Self = Self(0o1000);
    /// Append mode.
    pub const O_APPEND: Self = Self(0o2000);
}

/// An open file description.
#[derive(Debug, Clone, Copy)]
pub struct OpenFile {
    /// Inode this file refers to.
    pub inode: InodeNumber,
    /// Current seek offset.
    pub offset: u64,
    /// Open mode flags.
    pub flags: OpenFlags,
}

/// Maximum number of open files per process (POSIX OPEN_MAX).
pub const MAX_OPEN_FILES: usize = 256;

/// Per-process file descriptor table.
pub struct FdTable {
    /// File descriptor slots.
    files: [Option<OpenFile>; MAX_OPEN_FILES],
}

impl fmt::Debug for FdTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let open_count = self.files.iter().filter(|s| s.is_some()).count();
        f.debug_struct("FdTable")
            .field("open_count", &open_count)
            .finish()
    }
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FdTable {
    /// Create an empty file descriptor table.
    pub const fn new() -> Self {
        const NONE: Option<OpenFile> = None;
        Self {
            files: [NONE; MAX_OPEN_FILES],
        }
    }

    /// Allocate the lowest available file descriptor.
    pub fn alloc(&mut self, file: OpenFile) -> oncrix_lib::Result<Fd> {
        for (i, slot) in self.files.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(file);
                return Ok(Fd(i as u32));
            }
        }
        Err(oncrix_lib::Error::OutOfMemory)
    }

    /// Get an open file by descriptor.
    pub fn get(&self, fd: Fd) -> Option<&OpenFile> {
        self.files.get(fd.0 as usize).and_then(|s| s.as_ref())
    }

    /// Get a mutable reference to an open file.
    pub fn get_mut(&mut self, fd: Fd) -> Option<&mut OpenFile> {
        self.files.get_mut(fd.0 as usize).and_then(|s| s.as_mut())
    }

    /// Close a file descriptor.
    pub fn close(&mut self, fd: Fd) -> oncrix_lib::Result<()> {
        let slot = self
            .files
            .get_mut(fd.0 as usize)
            .ok_or(oncrix_lib::Error::InvalidArgument)?;
        if slot.is_none() {
            return Err(oncrix_lib::Error::InvalidArgument);
        }
        *slot = None;
        Ok(())
    }

    /// Duplicate `oldfd` to `newfd` (dup2 semantics).
    pub fn dup2(&mut self, oldfd: Fd, newfd: Fd) -> oncrix_lib::Result<Fd> {
        let file = self
            .get(oldfd)
            .copied()
            .ok_or(oncrix_lib::Error::InvalidArgument)?;
        let slot = self
            .files
            .get_mut(newfd.0 as usize)
            .ok_or(oncrix_lib::Error::InvalidArgument)?;
        *slot = Some(file);
        Ok(newfd)
    }
}
