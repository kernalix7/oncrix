// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Inode — the core metadata object for files and directories.
//!
//! Every file, directory, symlink, device node, etc. is represented
//! by an inode containing its metadata and a reference to the
//! filesystem-specific operations.

use core::fmt;
use oncrix_lib::Result;

/// Inode number (unique within a filesystem).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct InodeNumber(pub u64);

impl fmt::Display for InodeNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ino:{}", self.0)
    }
}

/// File type stored in an inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    /// Regular file.
    Regular,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
    /// Character device.
    CharDevice,
    /// Block device.
    BlockDevice,
    /// Named pipe (FIFO).
    Fifo,
    /// Unix domain socket.
    Socket,
}

impl fmt::Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Regular => write!(f, "regular"),
            Self::Directory => write!(f, "directory"),
            Self::Symlink => write!(f, "symlink"),
            Self::CharDevice => write!(f, "chardev"),
            Self::BlockDevice => write!(f, "blkdev"),
            Self::Fifo => write!(f, "fifo"),
            Self::Socket => write!(f, "socket"),
        }
    }
}

/// POSIX file permission bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct FileMode(pub u16);

impl FileMode {
    /// Owner read/write/execute.
    pub const OWNER_RWX: Self = Self(0o700);
    /// Group read/write/execute.
    pub const GROUP_RWX: Self = Self(0o070);
    /// Others read/write/execute.
    pub const OTHER_RWX: Self = Self(0o007);
    /// Default directory permissions (rwxr-xr-x).
    pub const DIR_DEFAULT: Self = Self(0o755);
    /// Default file permissions (rw-r--r--).
    pub const FILE_DEFAULT: Self = Self(0o644);
}

impl fmt::Display for FileMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04o}", self.0)
    }
}

/// Inode metadata.
#[derive(Debug, Clone, Copy)]
pub struct Inode {
    /// Inode number (unique within a single filesystem / superblock).
    pub ino: InodeNumber,
    /// Superblock identifier — disambiguates inodes across mounted filesystems.
    ///
    /// Defaults to `0` (the root/single filesystem).  Callers that manage
    /// multiple mount points should set this to the mount's superblock ID so
    /// that root-boundary comparisons of the form
    /// `(ino == root.ino) && (sb_id == root.sb_id)` are unambiguous even when
    /// two different filesystems happen to share an inode number.
    pub sb_id: u64,
    /// File type.
    pub file_type: FileType,
    /// Permission bits.
    pub mode: FileMode,
    /// Size in bytes.
    pub size: u64,
    /// Hard link count.
    pub nlink: u32,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
}

impl Inode {
    /// Create a new inode with default metadata.
    ///
    /// `sb_id` is initialised to `0` (root / single-filesystem context).
    /// Assign `inode.sb_id` explicitly when the inode belongs to a specific
    /// mounted filesystem.
    pub const fn new(ino: InodeNumber, file_type: FileType, mode: FileMode) -> Self {
        Self {
            ino,
            sb_id: 0,
            file_type,
            mode,
            size: 0,
            nlink: 1,
            uid: 0,
            gid: 0,
        }
    }
}

/// Filesystem-specific inode operations.
///
/// Each filesystem implements this trait to provide its own logic
/// for looking up children, creating files, reading data, etc.
pub trait InodeOps {
    /// Look up a child entry by name.
    fn lookup(&self, parent: &Inode, name: &str) -> Result<Inode>;

    /// Create a new file in the given directory.
    fn create(&mut self, parent: &Inode, name: &str, mode: FileMode) -> Result<Inode>;

    /// Create a new directory.
    fn mkdir(&mut self, parent: &Inode, name: &str, mode: FileMode) -> Result<Inode>;

    /// Remove a file.
    fn unlink(&mut self, parent: &Inode, name: &str) -> Result<()>;

    /// Remove a directory.
    fn rmdir(&mut self, parent: &Inode, name: &str) -> Result<()>;

    /// Read data from a file.
    fn read(&self, inode: &Inode, offset: u64, buf: &mut [u8]) -> Result<usize>;

    /// Write data to a file.
    fn write(&mut self, inode: &Inode, offset: u64, data: &[u8]) -> Result<usize>;

    /// Truncate a file to the given size.
    fn truncate(&mut self, inode: &Inode, size: u64) -> Result<()>;

    /// Read a symbolic-link target into `buf`, returning the byte count.
    ///
    /// Default implementation returns `InvalidArgument` (the inode is not
    /// a symlink). Filesystems that support symlinks override this.
    fn readlink(&self, _inode: &Inode, _buf: &mut [u8]) -> Result<usize> {
        Err(oncrix_lib::Error::InvalidArgument)
    }
}
