// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `open_by_handle_at(2)` syscall handler — open a file using a file handle.
//!
//! `open_by_handle_at` is the complement of `name_to_handle_at`.  Given a
//! persistent file handle (produced by `name_to_handle_at`) and a mount file
//! descriptor identifying the target filesystem, the kernel decodes the handle,
//! looks up the inode, and opens the file.
//!
//! # Syscall signature
//!
//! ```text
//! int open_by_handle_at(int mount_fd, struct file_handle *handle, int flags);
//! ```
//!
//! # Permission model
//!
//! The caller must hold `CAP_DAC_READ_SEARCH` unless the mount is accessible
//! by the effective UID.  This prevents unprivileged processes from bypassing
//! directory permission checks.
//!
//! # O_PATH support
//!
//! When `flags` includes `O_PATH`, the resulting file descriptor can only be
//! used for operations that do not require full file access (e.g., `fstat`,
//! `readlink`, passing to `*at` syscalls).
//!
//! # POSIX conformance
//!
//! `open_by_handle_at` is a Linux extension (since Linux 2.6.39).  Not part
//! of POSIX.1-2024.
//!
//! # References
//!
//! - Linux: `fs/fhandle.c`
//! - `open_by_handle_at(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Open flags
// ---------------------------------------------------------------------------

/// Open file for reading only.
pub const O_RDONLY: u32 = 0;
/// Open file for writing only.
pub const O_WRONLY: u32 = 1;
/// Open file for reading and writing.
pub const O_RDWR: u32 = 2;
/// Open only a path; no actual read/write permitted.
pub const O_PATH: u32 = 0o10000000;
/// Set close-on-exec flag.
pub const O_CLOEXEC: u32 = 0o2000000;
/// Open in non-blocking mode.
pub const O_NONBLOCK: u32 = 0o4000;

/// Mask for the access-mode bits.
const O_ACCMODE: u32 = 3;

// ---------------------------------------------------------------------------
// Capability constants
// ---------------------------------------------------------------------------

/// Linux capability: bypass file read/search permission checks.
const CAP_DAC_READ_SEARCH: u32 = 2;

// ---------------------------------------------------------------------------
// Handle geometry (must match sys_name_to_handle)
// ---------------------------------------------------------------------------

/// Maximum handle payload in bytes.
pub const MAX_HANDLE_BYTES: usize = 128;

/// Handle type for inode+generation handles.
const FILEID_INO32_GEN: u32 = 1;

// ---------------------------------------------------------------------------
// OpenFileHandle — a handle presented to open_by_handle_at
// ---------------------------------------------------------------------------

/// File handle as presented by the caller of `open_by_handle_at`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenFileHandle {
    /// Size of the handle payload in `bytes`.
    pub handle_bytes: u32,
    /// Filesystem-specific handle type.
    pub handle_type: u32,
    /// Opaque handle payload.
    pub bytes: [u8; MAX_HANDLE_BYTES],
}

impl OpenFileHandle {
    /// Decode the inode number from the handle payload.
    pub fn decode_inode(&self) -> Result<u64> {
        if self.handle_bytes < 8 {
            return Err(Error::InvalidArgument);
        }
        if self.handle_type != FILEID_INO32_GEN {
            return Err(Error::InvalidArgument);
        }
        let arr: [u8; 8] = self.bytes[..8]
            .try_into()
            .map_err(|_| Error::InvalidArgument)?;
        Ok(u64::from_le_bytes(arr))
    }

    /// Decode the generation counter from the handle payload.
    pub fn decode_generation(&self) -> Result<u32> {
        if self.handle_bytes < 12 {
            return Err(Error::InvalidArgument);
        }
        let arr: [u8; 4] = self.bytes[8..12]
            .try_into()
            .map_err(|_| Error::InvalidArgument)?;
        Ok(u32::from_le_bytes(arr))
    }

    /// Build a handle from an inode number and generation counter.
    pub fn from_inode(ino: u64, generation: u32) -> Self {
        let mut bytes = [0u8; MAX_HANDLE_BYTES];
        bytes[..8].copy_from_slice(&ino.to_le_bytes());
        bytes[8..12].copy_from_slice(&generation.to_le_bytes());
        Self {
            handle_bytes: 12,
            handle_type: FILEID_INO32_GEN,
            bytes,
        }
    }
}

impl Default for OpenFileHandle {
    fn default() -> Self {
        Self {
            handle_bytes: 0,
            handle_type: 0,
            bytes: [0u8; MAX_HANDLE_BYTES],
        }
    }
}

// ---------------------------------------------------------------------------
// MountEntry — simulated filesystem mount
// ---------------------------------------------------------------------------

/// Maximum number of mounts tracked by the subsystem.
const MAX_MOUNTS: usize = 64;

/// Maximum number of inodes per mount.
const MAX_INODES_PER_MOUNT: usize = 256;

/// One inode record within a mount.
#[derive(Debug, Clone, Copy)]
pub struct InodeRecord {
    /// Inode number.
    pub ino: u64,
    /// Generation counter (used for stale-handle detection).
    pub generation: u32,
    /// Simulated fd value that would be returned to user-space.
    pub virtual_fd: u32,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl InodeRecord {
    const fn empty() -> Self {
        Self {
            ino: 0,
            generation: 0,
            virtual_fd: 0,
            active: false,
        }
    }
}

impl Default for InodeRecord {
    fn default() -> Self {
        Self::empty()
    }
}

/// A mounted filesystem tracked by the subsystem.
pub struct MountEntry {
    /// File descriptor representing this mount (the `mount_fd` argument).
    pub mount_fd: i32,
    /// Mount ID (from `name_to_handle_at`).
    pub mount_id: i32,
    /// UID that owns this mount (for unprivileged access checks).
    pub owner_uid: u32,
    /// Inode records for this mount.
    pub inodes: [InodeRecord; MAX_INODES_PER_MOUNT],
    /// Number of active inode records.
    pub inode_count: usize,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl MountEntry {
    /// Create an inactive entry.
    pub const fn empty() -> Self {
        Self {
            mount_fd: -1,
            mount_id: -1,
            owner_uid: 0,
            inodes: [const { InodeRecord::empty() }; MAX_INODES_PER_MOUNT],
            inode_count: 0,
            active: false,
        }
    }

    /// Register an inode in this mount.
    pub fn add_inode(&mut self, rec: InodeRecord) -> Result<()> {
        let slot = self
            .inodes
            .iter()
            .position(|r| !r.active)
            .ok_or(Error::OutOfMemory)?;
        self.inodes[slot] = rec;
        self.inodes[slot].active = true;
        self.inode_count += 1;
        Ok(())
    }

    /// Look up an inode by number and generation counter.
    ///
    /// Returns `None` if the inode is not found or if the generation counter
    /// does not match (stale handle).
    pub fn find_inode(&self, ino: u64, generation: u32) -> Option<&InodeRecord> {
        self.inodes
            .iter()
            .find(|r| r.active && r.ino == ino && r.generation == generation)
    }
}

// ---------------------------------------------------------------------------
// OpenByHandleContext — subsystem state
// ---------------------------------------------------------------------------

/// Global state for `open_by_handle_at`.
pub struct OpenByHandleContext {
    mounts: [Option<MountEntry>; MAX_MOUNTS],
    /// Caller capability bitmask.
    pub caller_caps: u64,
    /// Caller effective UID.
    pub caller_uid: u32,
}

impl OpenByHandleContext {
    /// Construct an empty context.
    pub fn new() -> Self {
        Self {
            mounts: [const { None }; MAX_MOUNTS],
            caller_caps: 0,
            caller_uid: 0,
        }
    }

    /// Configure caller credentials.
    pub fn set_caller(&mut self, caps: u64, uid: u32) {
        self.caller_caps = caps;
        self.caller_uid = uid;
    }

    /// Register a mount.
    pub fn add_mount(&mut self, entry: MountEntry) -> Result<()> {
        let slot = self
            .mounts
            .iter()
            .position(|m| m.is_none())
            .ok_or(Error::OutOfMemory)?;
        self.mounts[slot] = Some(entry);
        Ok(())
    }

    fn find_mount_by_fd(&self, mount_fd: i32) -> Result<&MountEntry> {
        self.mounts
            .iter()
            .filter_map(|m| m.as_ref())
            .find(|m| m.mount_fd == mount_fd)
            .ok_or(Error::NotFound)
    }

    fn has_cap_dac_read_search(&self) -> bool {
        self.caller_caps & (1u64 << CAP_DAC_READ_SEARCH) != 0
    }

    fn check_mount_access(&self, mount: &MountEntry) -> Result<()> {
        if self.has_cap_dac_read_search() {
            return Ok(());
        }
        if mount.owner_uid == self.caller_uid {
            return Ok(());
        }
        Err(Error::PermissionDenied)
    }
}

impl Default for OpenByHandleContext {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// OpenResult — what the syscall returns
// ---------------------------------------------------------------------------

/// The result of a successful `open_by_handle_at` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenResult {
    /// Virtual file descriptor number.
    pub fd: u32,
    /// Whether the fd was opened O_PATH (limited operations only).
    pub is_path_only: bool,
    /// Whether the O_CLOEXEC flag is set on the fd.
    pub cloexec: bool,
}

// ---------------------------------------------------------------------------
// sys_open_by_handle_handler — main entry point
// ---------------------------------------------------------------------------

/// Handle the `open_by_handle_at(2)` syscall.
///
/// Decodes `handle`, resolves the inode on the filesystem identified by
/// `mount_fd`, verifies the generation counter (stale-handle detection),
/// and returns an [`OpenResult`] representing the opened file descriptor.
///
/// # Arguments
///
/// * `ctx`      — Global context with mount table and caller credentials.
/// * `mount_fd` — File descriptor for the target mount root.
/// * `handle`   — Persistent file handle from `name_to_handle_at`.
/// * `flags`    — Open flags (`O_RDONLY`, `O_PATH`, `O_CLOEXEC`, etc.).
///
/// # Returns
///
/// [`OpenResult`] on success.
///
/// # Errors
///
/// * [`Error::PermissionDenied`] — caller lacks `CAP_DAC_READ_SEARCH` and
///   does not own the mount.
/// * [`Error::InvalidArgument`]  — malformed handle or bad open flags.
/// * [`Error::NotFound`]         — mount or inode not found, or stale handle.
pub fn sys_open_by_handle_handler(
    ctx: &OpenByHandleContext,
    mount_fd: i32,
    handle: &OpenFileHandle,
    flags: u32,
) -> Result<OpenResult> {
    // Decode handle — validates format and extracts inode + generation.
    let ino = handle.decode_inode()?;
    let generation = handle.decode_generation()?;

    // Locate the mount.
    let mount = ctx.find_mount_by_fd(mount_fd)?;

    // Permission check.
    ctx.check_mount_access(mount)?;

    // Locate inode (also validates generation counter — stale handle detection).
    let rec = mount.find_inode(ino, generation).ok_or(Error::NotFound)?;

    let is_path_only = flags & O_PATH != 0;
    let cloexec = flags & O_CLOEXEC != 0;

    // Validate access mode when not O_PATH.
    if !is_path_only {
        let mode = flags & O_ACCMODE;
        if mode != O_RDONLY && mode != O_WRONLY && mode != O_RDWR {
            return Err(Error::InvalidArgument);
        }
    }

    Ok(OpenResult {
        fd: rec.virtual_fd,
        is_path_only,
        cloexec,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx() -> OpenByHandleContext {
        let mut ctx = OpenByHandleContext::new();
        ctx.set_caller(1u64 << CAP_DAC_READ_SEARCH, 0);

        let mut mount = MountEntry::empty();
        mount.mount_fd = 5;
        mount.mount_id = 1;
        mount.owner_uid = 0;
        mount.active = true;
        mount
            .add_inode(InodeRecord {
                ino: 42,
                generation: 7,
                virtual_fd: 100,
                active: true,
            })
            .unwrap();
        ctx.add_mount(mount).unwrap();
        ctx
    }

    #[test]
    fn basic_open_succeeds() {
        let ctx = make_ctx();
        let handle = OpenFileHandle::from_inode(42, 7);
        let r = sys_open_by_handle_handler(&ctx, 5, &handle, O_RDONLY).unwrap();
        assert_eq!(r.fd, 100);
        assert!(!r.is_path_only);
        assert!(!r.cloexec);
    }

    #[test]
    fn o_path_open() {
        let ctx = make_ctx();
        let handle = OpenFileHandle::from_inode(42, 7);
        let r = sys_open_by_handle_handler(&ctx, 5, &handle, O_PATH).unwrap();
        assert!(r.is_path_only);
    }

    #[test]
    fn o_cloexec_flag_propagated() {
        let ctx = make_ctx();
        let handle = OpenFileHandle::from_inode(42, 7);
        let r = sys_open_by_handle_handler(&ctx, 5, &handle, O_RDONLY | O_CLOEXEC).unwrap();
        assert!(r.cloexec);
    }

    #[test]
    fn stale_generation_rejected() {
        let ctx = make_ctx();
        let handle = OpenFileHandle::from_inode(42, 99); // wrong generation counter
        assert_eq!(
            sys_open_by_handle_handler(&ctx, 5, &handle, O_RDONLY),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn unknown_mount_rejected() {
        let ctx = make_ctx();
        let handle = OpenFileHandle::from_inode(42, 7);
        assert_eq!(
            sys_open_by_handle_handler(&ctx, 99, &handle, O_RDONLY),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn no_cap_no_owner_permission_denied() {
        let mut ctx = make_ctx();
        ctx.set_caller(0, 1000); // no caps, different uid
        let handle = OpenFileHandle::from_inode(42, 7);
        assert_eq!(
            sys_open_by_handle_handler(&ctx, 5, &handle, O_RDONLY),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn same_uid_allowed_without_cap() {
        let mut ctx = OpenByHandleContext::new();
        ctx.set_caller(0, 500);

        let mut mount = MountEntry::empty();
        mount.mount_fd = 10;
        mount.mount_id = 2;
        mount.owner_uid = 500;
        mount.active = true;
        mount
            .add_inode(InodeRecord {
                ino: 1,
                generation: 0,
                virtual_fd: 7,
                active: true,
            })
            .unwrap();
        ctx.add_mount(mount).unwrap();

        let handle = OpenFileHandle::from_inode(1, 0);
        let r = sys_open_by_handle_handler(&ctx, 10, &handle, O_RDONLY).unwrap();
        assert_eq!(r.fd, 7);
    }

    #[test]
    fn malformed_handle_rejected() {
        let ctx = make_ctx();
        let bad = OpenFileHandle {
            handle_bytes: 4, // too short for inode
            handle_type: FILEID_INO32_GEN,
            bytes: [0u8; MAX_HANDLE_BYTES],
        };
        assert_eq!(
            sys_open_by_handle_handler(&ctx, 5, &bad, O_RDONLY),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn inode_not_registered_rejected() {
        let ctx = make_ctx();
        let handle = OpenFileHandle::from_inode(999, 0);
        assert_eq!(
            sys_open_by_handle_handler(&ctx, 5, &handle, O_RDONLY),
            Err(Error::NotFound)
        );
    }
}
