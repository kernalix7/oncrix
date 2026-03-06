// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Namespace filesystem (nsfs) — pseudo-filesystem for namespace inodes.
//!
//! Linux exposes each process namespace as a file under `/proc/<pid>/ns/`.
//! Those files are inodes in `nsfs`, a pseudo-filesystem similar to sockfs.
//! Holding a file descriptor open on a namespace file prevents the namespace
//! from being destroyed, enabling "pinning" of namespaces across `unshare(2)`
//! and `setns(2)` calls.
//!
//! Each namespace type (mount, PID, UTS, IPC, network, user, cgroup, time)
//! gets a separate inode with a unique device/inode pair that identifies the
//! namespace globally (used by `ioctl(NS_GET_NSTYPE)` etc.).
//!
//! # Linux reference
//! `fs/nsfs.c` — `ns_fs_type`, `ns_get_path()`, `nsfs_evict_inode()`
//! `include/linux/ns_common.h` — `struct ns_common`
//!
//! # POSIX reference
//! POSIX.1-2024 does not specify namespaces; this is a Linux extension.

use crate::inode::{FileMode, FileType, InodeNumber};
use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Magic number identifying the namespace filesystem.
pub const NSFS_MAGIC: u32 = 0x6E73_6673;

/// Maximum number of namespace inodes that can be pinned simultaneously.
const MAX_NS_INODES: usize = 512;

/// Maximum length of a namespace type name (e.g., `"mnt"`, `"pid_for_children"`).
const NS_TYPE_NAME_LEN: usize = 24;

// ── Namespace types ───────────────────────────────────────────────────────────

/// Enumeration of Linux namespace types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NsType {
    /// Mount namespace (`CLONE_NEWNS`).
    Mnt = 0x0002_0000,
    /// UTS/hostname namespace (`CLONE_NEWUTS`).
    Uts = 0x0400_0000,
    /// IPC namespace (`CLONE_NEWIPC`).
    Ipc = 0x0800_0000,
    /// User namespace (`CLONE_NEWUSER`).
    User = 0x1000_0000,
    /// PID namespace (`CLONE_NEWPID`).
    Pid = 0x2000_0000,
    /// Network namespace (`CLONE_NEWNET`).
    Net = 0x4000_0000,
    /// Cgroup namespace (`CLONE_NEWCGROUP`).
    Cgroup = 0x0200_0000,
    /// Time namespace (`CLONE_NEWTIME`).
    Time = 0x0000_0080,
}

impl NsType {
    /// Parse a `CLONE_NEW*` constant.
    pub fn from_clone_flag(flag: u32) -> Result<Self> {
        match flag {
            0x0002_0000 => Ok(Self::Mnt),
            0x0400_0000 => Ok(Self::Uts),
            0x0800_0000 => Ok(Self::Ipc),
            0x1000_0000 => Ok(Self::User),
            0x2000_0000 => Ok(Self::Pid),
            0x4000_0000 => Ok(Self::Net),
            0x0200_0000 => Ok(Self::Cgroup),
            0x0000_0080 => Ok(Self::Time),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Returns the canonical name used in `/proc/<pid>/ns/`.
    pub fn proc_name(self) -> &'static str {
        match self {
            Self::Mnt => "mnt",
            Self::Uts => "uts",
            Self::Ipc => "ipc",
            Self::User => "user",
            Self::Pid => "pid",
            Self::Net => "net",
            Self::Cgroup => "cgroup",
            Self::Time => "time",
        }
    }

    /// Returns the `CLONE_NEW*` flag value.
    pub fn clone_flag(self) -> u32 {
        self as u32
    }
}

// ── Namespace identity ────────────────────────────────────────────────────────

/// A unique identifier for a namespace instance.
///
/// Two processes share a namespace if and only if their `NsId` values
/// are equal for that namespace type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NsId {
    /// Monotonically increasing counter; unique per namespace instance.
    pub seq: u64,
    /// Namespace type.
    pub ns_type: u32,
}

impl NsId {
    /// Construct a namespace identifier.
    pub const fn new(seq: u64, ns_type: NsType) -> Self {
        Self {
            seq,
            ns_type: ns_type as u32,
        }
    }
}

// ── Namespace inode ───────────────────────────────────────────────────────────

/// A pinned namespace — one inode entry in nsfs.
pub struct NsInode {
    /// VFS inode number (unique within nsfs).
    pub ino: InodeNumber,
    /// Namespace type.
    pub ns_type: NsType,
    /// Namespace identity (used for equality checks across processes).
    pub ns_id: NsId,
    /// Reference count: number of open file descriptors on this inode.
    ref_count: u32,
    /// Whether the owning namespace has been freed (orphaned inode).
    pub orphaned: bool,
    /// Namespace type name (null-padded ASCII).
    type_name: [u8; NS_TYPE_NAME_LEN],
    /// Type name length.
    type_name_len: usize,
}

impl NsInode {
    /// Construct a new namespace inode.
    pub fn new(ino: InodeNumber, ns_type: NsType, seq: u64) -> Self {
        let name = ns_type.proc_name().as_bytes();
        let name_len = name.len().min(NS_TYPE_NAME_LEN);
        let mut type_name = [0u8; NS_TYPE_NAME_LEN];
        type_name[..name_len].copy_from_slice(&name[..name_len]);
        Self {
            ino,
            ns_type,
            ns_id: NsId::new(seq, ns_type),
            ref_count: 1,
            orphaned: false,
            type_name,
            type_name_len: name_len,
        }
    }

    /// Returns the namespace type name as a `&str`.
    pub fn type_name(&self) -> &str {
        // SAFETY: type_name is always valid ASCII from NsType::proc_name().
        core::str::from_utf8(&self.type_name[..self.type_name_len]).unwrap_or("unknown")
    }

    /// Increment the reference count (e.g., on `dup(2)` or `open(2)`).
    pub fn get(&mut self) {
        self.ref_count = self.ref_count.saturating_add(1);
    }

    /// Decrement the reference count.
    ///
    /// Returns `true` when the count reaches zero and the inode can be freed.
    pub fn put(&mut self) -> bool {
        if self.ref_count > 0 {
            self.ref_count -= 1;
        }
        self.ref_count == 0
    }

    /// Current reference count.
    pub fn ref_count(&self) -> u32 {
        self.ref_count
    }
}

// ── Nsfs superblock ───────────────────────────────────────────────────────────

/// The namespace filesystem superblock.
///
/// Owns the table of all currently-pinned namespace inodes.
pub struct NsFs {
    /// Table of pinned namespace inodes.
    inodes: [Option<NsInode>; MAX_NS_INODES],
    /// Next inode number to assign.
    next_ino: u64,
    /// Monotonically increasing namespace sequence counter.
    next_seq: u64,
    /// Total inode count.
    inode_count: usize,
}

impl NsFs {
    /// Initialise an empty nsfs.
    pub const fn new() -> Self {
        Self {
            inodes: [const { None }; MAX_NS_INODES],
            next_ino: 1,
            next_seq: 1,
            inode_count: 0,
        }
    }

    /// Allocate a new namespace inode for the given type.
    ///
    /// Returns the inode number of the newly created entry, or `OutOfMemory`
    /// if the inode table is full.
    pub fn alloc_ns_inode(&mut self, ns_type: NsType) -> Result<InodeNumber> {
        if self.inode_count >= MAX_NS_INODES {
            return Err(Error::OutOfMemory);
        }
        let ino = InodeNumber(self.next_ino);
        self.next_ino += 1;
        let seq = self.next_seq;
        self.next_seq += 1;
        let slot = self
            .inodes
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;
        *slot = Some(NsInode::new(ino, ns_type, seq));
        self.inode_count += 1;
        Ok(ino)
    }

    /// Look up an inode by number (immutable).
    pub fn get(&self, ino: InodeNumber) -> Option<&NsInode> {
        self.inodes
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|n| n.ino == ino)
    }

    /// Look up an inode by number (mutable).
    pub fn get_mut(&mut self, ino: InodeNumber) -> Option<&mut NsInode> {
        self.inodes
            .iter_mut()
            .filter_map(|s| s.as_mut())
            .find(|n| n.ino == ino)
    }

    /// Find an existing pinned inode for the given namespace ID.
    ///
    /// Used to deduplicate: when two processes share a namespace, `open(2)`
    /// on their `/proc/<pid>/ns/<type>` files should yield inodes with the
    /// same `NsId`.
    pub fn find_by_ns_id(&self, ns_id: &NsId) -> Option<&NsInode> {
        self.inodes
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|n| n.ns_id == *ns_id)
    }

    /// Release a reference to a namespace inode.
    ///
    /// When the reference count reaches zero the slot is freed.
    /// Returns `NotFound` if the inode does not exist.
    pub fn release(&mut self, ino: InodeNumber) -> Result<()> {
        for slot in &mut self.inodes {
            if let Some(ns_ino) = slot {
                if ns_ino.ino == ino {
                    let free = ns_ino.put();
                    if free {
                        *slot = None;
                        self.inode_count -= 1;
                    }
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Mark a namespace inode as orphaned (owning namespace has been destroyed).
    ///
    /// The inode will still persist until all file descriptors are closed.
    pub fn mark_orphaned(&mut self, ino: InodeNumber) -> Result<()> {
        let ns_ino = self.get_mut(ino).ok_or(Error::NotFound)?;
        ns_ino.orphaned = true;
        Ok(())
    }

    /// Build a VFS-compatible inode view for a namespace inode.
    ///
    /// Namespace files appear as regular files (`S_IFREG | 0o444`) in the
    /// VFS, even though they are special objects.
    pub fn make_inode(ino: InodeNumber) -> NsfsInodeView {
        NsfsInodeView {
            ino,
            mode: FileMode(0o100_444),
            file_type: FileType::Regular,
        }
    }

    /// Total number of pinned namespace inodes.
    pub fn inode_count(&self) -> usize {
        self.inode_count
    }

    /// Filesystem magic number.
    pub fn magic() -> u32 {
        NSFS_MAGIC
    }
}

// ── VFS inode view ────────────────────────────────────────────────────────────

/// Lightweight inode descriptor for integration with the VFS layer.
#[derive(Debug, Clone, Copy)]
pub struct NsfsInodeView {
    /// Inode number.
    pub ino: InodeNumber,
    /// File mode (`S_IFREG | 0o444`).
    pub mode: FileMode,
    /// File type.
    pub file_type: FileType,
}

// ── ioctl(2) constants ────────────────────────────────────────────────────────

/// `ioctl` command: get the namespace type of the open namespace file.
///
/// Returns one of the `NsType` clone-flag constants.
pub const NS_GET_NSTYPE: u32 = 0xb701;

/// `ioctl` command: get a file descriptor for the parent user namespace.
pub const NS_GET_USERNS: u32 = 0xb702;

/// `ioctl` command: get a file descriptor for the parent namespace.
pub const NS_GET_PARENT: u32 = 0xb703;

/// `ioctl` command: get UID/GID info for a user namespace.
pub const NS_GET_OWNER_UID: u32 = 0xb704;

/// Handle an `ioctl(2)` on a namespace file descriptor.
///
/// Returns the clone-flag value for `NS_GET_NSTYPE`, or `NotImplemented`
/// for unrecognised commands.
pub fn ns_ioctl(ns_ino: &NsInode, cmd: u32) -> Result<u64> {
    match cmd {
        NS_GET_NSTYPE => Ok(u64::from(ns_ino.ns_type.clone_flag())),
        NS_GET_USERNS | NS_GET_PARENT | NS_GET_OWNER_UID => {
            // Full implementation requires cross-namespace FD passing; not yet
            // supported in this layer.
            Err(Error::NotImplemented)
        }
        _ => Err(Error::InvalidArgument),
    }
}

// ── `/proc/<pid>/ns/` path helpers ────────────────────────────────────────────

/// Maximum length of a rendered `/proc/<pid>/ns/<type>` path.
const PROC_NS_PATH_LEN: usize = 64;

/// A rendered `/proc/<pid>/ns/<type>` path.
#[derive(Debug, Clone, Copy)]
pub struct ProcNsPath {
    buf: [u8; PROC_NS_PATH_LEN],
    len: usize,
}

impl ProcNsPath {
    /// Build the path for `pid` and `ns_type`, e.g., `/proc/1234/ns/mnt`.
    pub fn build(pid: u32, ns_type: NsType) -> Self {
        let mut buf = [0u8; PROC_NS_PATH_LEN];
        let type_name = ns_type.proc_name().as_bytes();
        // Write "/proc/" prefix.
        let prefix = b"/proc/";
        let mut pos = prefix.len().min(PROC_NS_PATH_LEN);
        buf[..pos].copy_from_slice(&prefix[..pos]);
        // Write PID digits.
        let mut pid_tmp = pid;
        let pid_start = pos;
        let mut pid_digits = [0u8; 10];
        let mut ndigits = 0usize;
        if pid_tmp == 0 {
            pid_digits[0] = b'0';
            ndigits = 1;
        } else {
            while pid_tmp > 0 && ndigits < 10 {
                pid_digits[ndigits] = b'0' + (pid_tmp % 10) as u8;
                pid_tmp /= 10;
                ndigits += 1;
            }
            pid_digits[..ndigits].reverse();
        }
        for &d in &pid_digits[..ndigits] {
            if pos < PROC_NS_PATH_LEN {
                buf[pos] = d;
                pos += 1;
            }
        }
        let _ = pid_start;
        // Write "/ns/".
        for &b in b"/ns/" {
            if pos < PROC_NS_PATH_LEN {
                buf[pos] = b;
                pos += 1;
            }
        }
        // Write type name.
        for &b in type_name {
            if pos < PROC_NS_PATH_LEN {
                buf[pos] = b;
                pos += 1;
            }
        }
        Self { buf, len: pos }
    }

    /// Returns the path as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

// ── setns / unshare helpers ───────────────────────────────────────────────────

/// Validate that a `setns(2)` call can switch the caller to the target namespace.
///
/// Performs basic sanity checks:
/// - The target namespace must not be orphaned.
/// - `PID` namespace switches require the caller to be privileged (uid 0).
pub fn validate_setns(ns_ino: &NsInode, caller_uid: u32) -> Result<()> {
    if ns_ino.orphaned {
        return Err(Error::InvalidArgument);
    }
    // PID namespace switches require privilege.
    if ns_ino.ns_type == NsType::Pid && caller_uid != 0 {
        return Err(Error::PermissionDenied);
    }
    Ok(())
}

/// Validate that a `unshare(2)` call can create a new namespace of the given type.
///
/// User namespaces may be created unprivileged; all others require uid 0.
pub fn validate_unshare(ns_type: NsType, caller_uid: u32) -> Result<()> {
    match ns_type {
        NsType::User => Ok(()), // unprivileged
        _ => {
            if caller_uid == 0 {
                Ok(())
            } else {
                Err(Error::PermissionDenied)
            }
        }
    }
}
