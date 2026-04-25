// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel VFS API — thin facade for syscall handlers.
//!
//! Exposes the minimal set of VFS operations that the kernel-side
//! syscall handlers need without forcing those callers to understand
//! the internals of [`Ramfs`], [`MountTable`], or [`DentryCache`].
//!
//! All functions take `&mut KernelVfs` (a lightweight aggregate of
//! the ramfs, mount table and dentry cache) rather than individual
//! components, so the call-site is a single `with_global_mut` grab.
//!
//! # POSIX.1-2024 references
//!
//! - `open(3p)` / `openat(3p)` — path resolution and fd allocation.
//! - `read(3p)` — sequential read with offset advancement.
//! - `write(3p)` — sequential write with offset advancement.
//! - `lseek(3p)` — random-access seek.

use crate::dentry::{Dentry, DentryCache, DentryName};
use crate::file::OpenFlags;
use crate::inode::{FileMode, FileType, Inode, InodeNumber, InodeOps};
use crate::path::{resolve_path, split_path};
use crate::ramfs::Ramfs;
use crate::superblock::MountTable;
use oncrix_lib::{Error, Result};

// ── POSIX whence constants ────────────────────────────────────────

/// `lseek` whence: set absolute offset.
pub const SEEK_SET: i32 = 0;
/// `lseek` whence: set offset relative to current position.
pub const SEEK_CUR: i32 = 1;
/// `lseek` whence: set offset relative to file end.
pub const SEEK_END: i32 = 2;

// ── O_* flag constants (POSIX.1-2024) ────────────────────────────

/// `open(2)` flag: open for reading only.
pub const O_RDONLY: u32 = 0;
/// `open(2)` flag: open for writing only.
pub const O_WRONLY: u32 = 1;
/// `open(2)` flag: open for reading and writing.
pub const O_RDWR: u32 = 2;
/// `open(2)` flag: create file if it does not exist.
pub const O_CREAT: u32 = 0o100;
/// `open(2)` flag: truncate file to zero length on open.
pub const O_TRUNC: u32 = 0o1000;
/// `open(2)` flag: append writes to end of file.
pub const O_APPEND: u32 = 0o2000;

// ── KernelVfs ────────────────────────────────────────────────────

/// Aggregate of VFS subsystem state owned by [`KernelState`].
///
/// Holds the live ramfs, the mount table, and the dentry cache so
/// that syscall handlers can perform all VFS operations through a
/// single `&mut KernelVfs` borrow.
pub struct KernelVfs {
    /// Root in-memory filesystem.
    pub ramfs: Ramfs,
    /// Global mount table.
    pub mount_table: MountTable,
    /// Dentry (path component) cache.
    pub dcache: DentryCache,
}

impl KernelVfs {
    /// Create a new, empty VFS state.
    pub fn new() -> Self {
        Self {
            ramfs: Ramfs::new(),
            mount_table: MountTable::new(),
            dcache: DentryCache::new(),
        }
    }

    /// Return the root inode of the ramfs.
    pub fn root_inode(&self) -> Inode {
        let ino = self.ramfs.root_inode();
        Inode::new(ino, FileType::Directory, FileMode::DIR_DEFAULT)
    }

    /// Resolve an absolute path to its inode.
    ///
    /// Returns `Err(NotFound)` when any component does not exist.
    /// Returns `Err(InvalidArgument)` for non-absolute or empty paths.
    pub fn lookup_path(&self, path: &[u8]) -> Result<Inode> {
        let root = self.root_inode();
        resolve_path(path, &root, &self.ramfs, &self.mount_table, &self.dcache)
    }

    /// Open a file, creating it if `O_CREAT` is set.
    ///
    /// Returns the opened inode on success. The inode number is stable
    /// for the lifetime of the file so the caller may cache it in a
    /// file-handle offset tracker.
    ///
    /// POSIX.1-2024 errno mapping (Phase 12 subset):
    /// - `ENOENT` (`NotFound`) — path does not exist and `O_CREAT` is absent.
    /// - `EINVAL` (`InvalidArgument`) — path is empty or non-absolute.
    /// - `ENOMEM` (`OutOfMemory`) — ramfs inode or data table is full.
    pub fn open_path(&mut self, path: &[u8], flags: u32, mode: u32) -> Result<Inode> {
        let of = OpenFlags(flags);
        let fm = FileMode(mode as u16);
        let root = self.root_inode();

        // Try to resolve the existing file first.
        match resolve_path(path, &root, &self.ramfs, &self.mount_table, &self.dcache) {
            Ok(inode) => {
                // File exists.
                if flags & O_TRUNC != 0
                    && (flags & O_WRONLY != 0 || flags & O_RDWR != 0)
                    && inode.file_type == FileType::Regular
                {
                    self.ramfs.truncate(&inode, 0)?;
                }
                Ok(inode)
            }
            Err(Error::NotFound) => {
                if of.0 & OpenFlags::O_CREAT.0 == 0 {
                    return Err(Error::NotFound);
                }
                self.create_file(path, fm)
            }
            Err(e) => Err(e),
        }
    }

    /// Create a regular file at `path`, creating parent components only if
    /// they already exist.
    ///
    /// Returns the new inode on success.
    fn create_file(&mut self, path: &[u8], mode: FileMode) -> Result<Inode> {
        let root = self.root_inode();
        let (components, count) = split_path(path);
        if count == 0 {
            return Err(Error::InvalidArgument);
        }

        // Resolve parent directory.
        let parent = if count == 1 {
            root
        } else {
            let mut cur = root;
            for component in &components[..count - 1] {
                let name = core::str::from_utf8(component).map_err(|_| Error::InvalidArgument)?;
                cur = self.ramfs.lookup(&cur, name)?;
            }
            cur
        };

        let filename =
            core::str::from_utf8(components[count - 1]).map_err(|_| Error::InvalidArgument)?;
        let new_inode = self.ramfs.create(&parent, filename, mode)?;

        // Update dentry cache.
        if let Some(dname) = DentryName::from_name(filename) {
            self.dcache
                .insert(Dentry::new(dname, new_inode.ino, parent.ino));
        }

        Ok(new_inode)
    }

    /// Read up to `buf.len()` bytes from `inode` at the given `offset`.
    ///
    /// Returns the number of bytes actually read (0 = EOF).
    /// `POSIX.1-2024 read(3p)` semantics.
    pub fn read_inode(&self, inode: &Inode, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.ramfs.read(inode, offset, buf)
    }

    /// Write `data` to `inode` at the given `offset`.
    ///
    /// Returns the number of bytes actually written.
    /// `POSIX.1-2024 write(3p)` semantics.
    pub fn write_inode(&mut self, inode: &Inode, offset: u64, data: &[u8]) -> Result<usize> {
        self.ramfs.write(inode, offset, data)
    }

    /// Return the current size of the file identified by `ino`, or `None`
    /// if no such inode exists.
    ///
    /// Used by `SEEK_END` to compute the post-seek offset.
    pub fn inode_size(&self, ino: InodeNumber) -> Option<u64> {
        self.ramfs.inode_size(ino)
    }

    /// Look up an [`Inode`] by its inode number.
    ///
    /// Returns `None` if no inode with that number exists in the ramfs.
    /// Used by the fd-dispatch layer to materialise an inode struct from
    /// the number stored inside a [`FileBackend::RamfsFile`] handle.
    pub fn lookup_path_by_ino(&self, ino: InodeNumber) -> Option<Inode> {
        self.ramfs.inode_by_number(ino)
    }
}

impl Default for KernelVfs {
    fn default() -> Self {
        Self::new()
    }
}
