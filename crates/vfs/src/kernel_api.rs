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

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::dentry::{Dentry, DentryCache, DentryName};
use crate::file::OpenFlags;
use crate::inode::{FileMode, FileType, Inode, InodeNumber, InodeOps};
use crate::path::{resolve_path, split_path};
use crate::ramfs::Ramfs;
use crate::superblock::MountTable;
use oncrix_lib::{Error, Result};

/// A directory listing entry returned by [`KernelVfs::list_dir`].
pub struct DirEntry {
    /// Entry name.
    pub name: alloc::string::String,
    /// File type.
    pub kind: FileType,
    /// Inode number.
    pub ino: u64,
}

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
                self.create_file_inode(path, fm)
            }
            Err(e) => Err(e),
        }
    }

    /// Create a regular file at `path` with optional initial `content`.
    ///
    /// Parent directories must already exist.  Suitable for `touch` (pass
    /// an empty slice) or for writing small files at creation time.
    ///
    /// Returns `Err(AlreadyExists)` if the path already names a file.
    pub fn create_file(&mut self, path: &[u8], content: &[u8]) -> Result<()> {
        let inode = self.create_file_inode(path, FileMode::FILE_DEFAULT)?;
        if !content.is_empty() {
            self.ramfs.write(&inode, 0, content)?;
        }
        Ok(())
    }

    /// Create a directory at `path`.
    ///
    /// The parent directory must already exist.
    ///
    /// Returns `Err(AlreadyExists)` if the path already exists.
    pub fn create_dir(&mut self, path: &[u8]) -> Result<()> {
        let root = self.root_inode();
        let (components, count) = split_path(path);
        if count == 0 {
            return Err(Error::InvalidArgument);
        }

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

        let dirname =
            core::str::from_utf8(components[count - 1]).map_err(|_| Error::InvalidArgument)?;
        let new_inode = self.ramfs.mkdir(&parent, dirname, FileMode::DIR_DEFAULT)?;

        if let Some(dname) = DentryName::from_name(dirname) {
            self.dcache
                .insert(Dentry::new(dname, new_inode.ino, parent.ino));
        }
        Ok(())
    }

    /// Remove the file at `path`.
    ///
    /// Returns `Err(InvalidArgument)` if `path` names a directory.
    /// Returns `Err(NotFound)` if the path does not exist.
    pub fn unlink_path(&mut self, path: &[u8]) -> Result<()> {
        let (parent_ino, name_bytes) = self.resolve_parent_and_name(path)?;
        let parent_inode = self
            .ramfs
            .inode_by_number(parent_ino)
            .ok_or(Error::NotFound)?;
        let name = core::str::from_utf8(name_bytes).map_err(|_| Error::InvalidArgument)?;
        self.ramfs.unlink_entry(&parent_inode, name)
    }

    /// Rename `old_path` to `new_path`.
    ///
    /// POSIX.1-2024 `rename(2)` (ramfs subset). Both paths are resolved
    /// to (parent dir, final name); the source name is moved to the
    /// destination, overwriting any existing destination entry. The
    /// underlying inode is preserved.
    ///
    /// Returns `NotFound` if `old_path` does not exist, `InvalidArgument`
    /// for malformed paths.
    pub fn rename_path(&mut self, old_path: &[u8], new_path: &[u8]) -> Result<()> {
        let (old_parent_ino, old_name_bytes) = self.resolve_parent_and_name(old_path)?;
        let (new_parent_ino, new_name_bytes) = self.resolve_parent_and_name(new_path)?;
        let old_parent = self
            .ramfs
            .inode_by_number(old_parent_ino)
            .ok_or(Error::NotFound)?;
        let new_parent = self
            .ramfs
            .inode_by_number(new_parent_ino)
            .ok_or(Error::NotFound)?;
        let old_name = core::str::from_utf8(old_name_bytes).map_err(|_| Error::InvalidArgument)?;
        let new_name = core::str::from_utf8(new_name_bytes).map_err(|_| Error::InvalidArgument)?;
        self.ramfs
            .rename(&old_parent, old_name, &new_parent, new_name)
    }

    /// Create a hard link `new_path` pointing at the existing `old_path`.
    ///
    /// POSIX.1-2024 `link(2)` (ramfs subset). Returns `NotFound` if
    /// `old_path` does not exist, `AlreadyExists` if `new_path` does,
    /// `InvalidArgument` for malformed paths or a directory target.
    pub fn link_path(&mut self, old_path: &[u8], new_path: &[u8]) -> Result<()> {
        let target = self.lookup_path(old_path)?;
        let (new_parent_ino, new_name_bytes) = self.resolve_parent_and_name(new_path)?;
        let new_parent = self
            .ramfs
            .inode_by_number(new_parent_ino)
            .ok_or(Error::NotFound)?;
        let new_name = core::str::from_utf8(new_name_bytes).map_err(|_| Error::InvalidArgument)?;
        self.ramfs.link(&target, &new_parent, new_name)
    }

    /// Resolve `path` to its inode WITHOUT following a terminal symlink.
    ///
    /// Intermediate components are resolved normally (following), but the
    /// final component is returned as-is — so a symlink yields the link
    /// inode itself. Backs `lstat(2)`. Returns `NotFound` if absent.
    pub fn lookup_path_nofollow(&self, path: &[u8]) -> Result<Inode> {
        // Root has no parent/name; return it directly.
        if path == b"/" {
            return Ok(self.root_inode());
        }
        let (parent_ino, name_bytes) = self.resolve_parent_and_name(path)?;
        let parent = self
            .ramfs
            .inode_by_number(parent_ino)
            .ok_or(Error::NotFound)?;
        let name = core::str::from_utf8(name_bytes).map_err(|_| Error::InvalidArgument)?;
        self.ramfs.lookup(&parent, name)
    }

    /// Create a named pipe (FIFO) at `path`.
    ///
    /// POSIX.1-2024 `mkfifo(2)` (ramfs subset, create-only). Returns
    /// `AlreadyExists` if the path exists, `NotFound` if the parent does
    /// not, `InvalidArgument` for a malformed path.
    pub fn mkfifo_path(&mut self, path: &[u8], mode: u32) -> Result<()> {
        let (parent_ino, name_bytes) = self.resolve_parent_and_name(path)?;
        let parent = self
            .ramfs
            .inode_by_number(parent_ino)
            .ok_or(Error::NotFound)?;
        let name = core::str::from_utf8(name_bytes).map_err(|_| Error::InvalidArgument)?;
        self.ramfs
            .mknod_fifo(&parent, name, FileMode(mode as u16))
            .map(|_| ())
    }

    /// Remove the empty directory at `path`.
    ///
    /// POSIX.1-2024 `rmdir(2)`: fails with `InvalidArgument` if `path`
    /// is not a directory or is non-empty, `NotFound` if it does not
    /// exist.
    pub fn rmdir_path(&mut self, path: &[u8]) -> Result<()> {
        let (parent_ino, name_bytes) = self.resolve_parent_and_name(path)?;
        let parent = self
            .ramfs
            .inode_by_number(parent_ino)
            .ok_or(Error::NotFound)?;
        let name = core::str::from_utf8(name_bytes).map_err(|_| Error::InvalidArgument)?;
        self.ramfs.rmdir(&parent, name)
    }

    /// Set the length of the file at `path` to `length` bytes.
    ///
    /// POSIX.1-2024 `truncate(2)` (ramfs subset): shrinking discards the
    /// tail, growing zero-fills. Follows symlinks (resolves `path`).
    /// Returns `NotFound` if the path does not exist, `InvalidArgument`
    /// if it is not a regular file.
    pub fn truncate_path(&mut self, path: &[u8], length: u64) -> Result<()> {
        let inode = self.lookup_path(path)?;
        self.ramfs.truncate(&inode, length)
    }

    /// Truncate the regular file identified by `ino` to `length` bytes.
    ///
    /// The fd-keyed counterpart of [`truncate_path`], for `ftruncate(2)`.
    /// Returns `NotFound` if no inode with that number exists,
    /// `InvalidArgument` if the inode is not a regular file.
    pub fn truncate_ino(&mut self, ino: InodeNumber, length: u64) -> Result<()> {
        let inode = self.ramfs.inode_by_number(ino).ok_or(Error::NotFound)?;
        self.ramfs.truncate(&inode, length)
    }

    /// Create a symbolic link at `link_path` whose target is `target`.
    ///
    /// POSIX.1-2024 `symlink(2)` (ramfs subset). The target is stored
    /// verbatim and not yet followed by path resolution. Returns
    /// `AlreadyExists` if `link_path` exists, `InvalidArgument` for a
    /// malformed path or an over-long target.
    pub fn symlink_path(&mut self, target: &[u8], link_path: &[u8]) -> Result<()> {
        let (parent_ino, name_bytes) = self.resolve_parent_and_name(link_path)?;
        let parent = self
            .ramfs
            .inode_by_number(parent_ino)
            .ok_or(Error::NotFound)?;
        let name = core::str::from_utf8(name_bytes).map_err(|_| Error::InvalidArgument)?;
        self.ramfs.symlink(&parent, name, target).map(|_| ())
    }

    /// Read the target of the symbolic link at `path` into `buf`.
    ///
    /// Resolves `path` WITHOUT following its final component (so the
    /// symlink itself is returned, not its target), then reads the link.
    /// Returns the number of bytes copied. `InvalidArgument` if `path`
    /// is not a symlink, `NotFound` if it does not exist.
    pub fn readlink_path(&self, path: &[u8], buf: &mut [u8]) -> Result<usize> {
        // Resolve parent + final name and look up the final component
        // directly (`lookup` does not follow symlinks, unlike the
        // symlink-following `lookup_path`).
        let (parent_ino, name_bytes) = self.resolve_parent_and_name(path)?;
        let parent = self
            .ramfs
            .inode_by_number(parent_ino)
            .ok_or(Error::NotFound)?;
        let name = core::str::from_utf8(name_bytes).map_err(|_| Error::InvalidArgument)?;
        let inode = self.ramfs.lookup(&parent, name)?;
        self.ramfs.read_link(inode.ino, buf)
    }

    /// Change the owner/group of the file at `path`.
    ///
    /// POSIX.1-2024 `chown(2)` (ramfs subset): `u32::MAX` leaves the
    /// corresponding id unchanged. Returns `NotFound` if the path does
    /// not exist.
    pub fn chown_path(&mut self, path: &[u8], uid: u32, gid: u32) -> Result<()> {
        let inode = self.lookup_path(path)?;
        self.ramfs.set_owner(inode.ino, uid, gid)
    }

    /// Change the permission bits of the file at `path`.
    ///
    /// POSIX.1-2024 `chmod(2)` (ramfs subset): updates the inode mode
    /// bits only. Returns `NotFound` if the path does not exist.
    pub fn chmod_path(&mut self, path: &[u8], mode: u32) -> Result<()> {
        let inode = self.lookup_path(path)?;
        self.ramfs.set_mode(inode.ino, FileMode(mode as u16))
    }

    /// List the contents of the directory at `path`.
    ///
    /// Returns a `Vec<DirEntry>` with one element per child entry.
    /// Returns `Err(NotFound)` if the path does not exist.
    /// Returns `Err(InvalidArgument)` if the path names a regular file.
    pub fn list_dir(&self, path: &[u8]) -> Result<Vec<DirEntry>> {
        let inode = self.lookup_path(path)?;
        if inode.file_type != FileType::Directory {
            return Err(Error::InvalidArgument);
        }
        let children = self.ramfs.list_children(&inode);
        let mut entries = Vec::with_capacity(children.len());
        for c in children {
            entries.push(DirEntry {
                name: c.name,
                kind: c.kind,
                ino: c.ino.0,
            });
        }
        Ok(entries)
    }

    /// Split `path` into the parent directory inode number and the final
    /// name component as a byte slice borrowed from `path`.
    ///
    /// For example `/etc/foo` returns `(ino_of_etc, b"foo")`.
    /// The root path `/` returns `Err(InvalidArgument)`.
    pub fn resolve_parent_and_name<'a>(&self, path: &'a [u8]) -> Result<(InodeNumber, &'a [u8])> {
        if path.is_empty() || path[0] != b'/' {
            return Err(Error::InvalidArgument);
        }

        // Find last '/' to split parent path from final component.
        let last_slash = path
            .iter()
            .rposition(|&b| b == b'/')
            .ok_or(Error::InvalidArgument)?;

        let name = &path[last_slash + 1..];
        if name.is_empty() {
            return Err(Error::InvalidArgument);
        }

        let parent_path = if last_slash == 0 {
            b"/" as &[u8]
        } else {
            &path[..last_slash]
        };
        let parent_inode = self.lookup_path(parent_path)?;
        Ok((parent_inode.ino, name))
    }

    /// Create a regular file at `path`, creating parent components only if
    /// they already exist.
    ///
    /// Returns the new inode on success.
    fn create_file_inode(&mut self, path: &[u8], mode: FileMode) -> Result<Inode> {
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

    /// Return the pipe-ring index backing the FIFO `ino`, if allocated.
    ///
    /// `Ok(None)` means the FIFO exists but has not yet been opened.
    /// Returns `Err(InvalidArgument)` if `ino` is not a FIFO, `NotFound`
    /// if no such inode exists. Backs lazy FIFO ring wiring in the fd layer.
    pub fn fifo_ring_id(&self, ino: InodeNumber) -> Result<Option<u32>> {
        self.ramfs.fifo_ring_id(ino)
    }

    /// Record the pipe-ring index backing the FIFO `ino`.
    ///
    /// Returns `Err(InvalidArgument)` if `ino` is not a FIFO, `NotFound`
    /// if no such inode exists.
    pub fn set_fifo_ring_id(&mut self, ino: InodeNumber, id: u32) -> Result<()> {
        self.ramfs.set_fifo_ring_id(ino, id)
    }

    /// Read the entire contents of the file at `path` into a `Vec<u8>`.
    ///
    /// `path` must be absolute (start with `b'/'`). The root path `b"/"`
    /// alone is rejected with `InvalidArgument` as it is a directory.
    ///
    /// Returns `Err(NotFound)` if any path component does not exist, and
    /// `Err(InvalidArgument)` for empty or non-absolute paths.
    pub fn read_file_bytes(&self, path: &[u8]) -> Result<Vec<u8>> {
        if path.is_empty() || path[0] != b'/' {
            return Err(Error::InvalidArgument);
        }
        // Reject bare "/" — it is a directory, not a readable file.
        if path == b"/" {
            return Err(Error::InvalidArgument);
        }

        let inode = self.lookup_path(path)?;

        let size = inode.size as usize;
        let capacity = size.max(64);
        let mut buf: Vec<u8> = vec![0u8; capacity];

        let n = self.ramfs.read(&inode, 0, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Read a `/proc/<name>` virtual file by name.
    ///
    /// Resolves the name against the procfs entry table, generates
    /// content via [`crate::procfs::ProcFs`], copies at most
    /// `buf.len()` bytes starting at `offset`, and returns the
    /// number of bytes copied.
    ///
    /// Returns `Err(NotFound)` when no entry matches `name`.
    pub fn procfs_read(&self, name: &[u8], offset: usize, buf: &mut [u8]) -> Result<usize> {
        let fs = crate::procfs::ProcFs::new();
        let name_str = core::str::from_utf8(name).map_err(|_| Error::InvalidArgument)?;
        let entry = fs.find_by_name(name_str).ok_or(Error::NotFound)?;
        let generator = entry.generator;
        let mut tmp = [0u8; 256];
        let total = fs.generate(generator, &mut tmp)?;
        if offset >= total {
            return Ok(0);
        }
        let available = total - offset;
        let to_copy = buf.len().min(available);
        buf[..to_copy].copy_from_slice(&tmp[offset..offset + to_copy]);
        Ok(to_copy)
    }
}

impl Default for KernelVfs {
    fn default() -> Self {
        Self::new()
    }
}
