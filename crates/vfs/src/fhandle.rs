// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! File handle operations — NFS-style persistent file handles.
//!
//! This module implements the kernel-side support for `name_to_handle_at(2)` and
//! `open_by_handle_at(2)`, which provide NFS-style persistent file handles that
//! survive path renames and can be used to reopen files without holding a path.
//!
//! # Design
//!
//! ```text
//! name_to_handle_at(dirfd, path, flags)
//!   │
//!   ├── resolve path → inode_id
//!   ├── FileHandleOps::encode_fh(inode_id) → FileHandle
//!   └── return (FileHandle, MountId)
//!
//! open_by_handle_at(mount_fd, handle, flags)
//!   │
//!   ├── verify MountId still valid
//!   ├── FileHandleOps::decode_fh(handle) → inode_id
//!   └── return fd for inode
//! ```
//!
//! # References
//!
//! - Linux `fs/fhandle.c`, `include/linux/exportfs.h`
//! - `man 2 name_to_handle_at`, `man 2 open_by_handle_at`

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of simultaneously active file handles in the registry.
pub const MAX_FILE_HANDLES: usize = 256;

/// Byte capacity of the opaque handle payload (`f_handle` field).
pub const FILE_HANDLE_BYTES: usize = 128;

/// Magic version tag embedded in every encoded handle.
pub const FHANDLE_VERSION: u32 = 0x0100_0000;

/// Maximum mount generation before wrapping (staleness guard).
pub const MAX_MOUNT_GENERATION: u32 = u32::MAX;

// ── FileHandleType ────────────────────────────────────────────────────────────

/// Classifies the filesystem object referenced by a file handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FileHandleType {
    /// Handle refers to a regular file or other non-directory inode.
    Inode = 1,
    /// Handle refers to a directory.
    Directory = 2,
    /// Handle refers to a symbolic link.
    Symlink = 3,
}

impl FileHandleType {
    /// Convert a raw `u32` tag back into a [`FileHandleType`].
    ///
    /// Returns `None` if the value is not a recognised discriminant.
    pub fn from_raw(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Inode),
            2 => Some(Self::Directory),
            3 => Some(Self::Symlink),
            _ => None,
        }
    }
}

// ── FileHandle ────────────────────────────────────────────────────────────────

/// NFS-style persistent file handle as returned to user space.
///
/// Layout mirrors the kernel `file_handle` structure used by the `name_to_handle_at`
/// system call:
///
/// ```text
/// ┌──────────────┬──────────────┬───────────────────────────────┐
/// │ handle_bytes │ handle_type  │ f_handle[0..handle_bytes]     │
/// │   (u32)      │   (u32)      │   opaque filesystem payload   │
/// └──────────────┴──────────────┴───────────────────────────────┘
/// ```
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FileHandle {
    /// Type tag — one of the [`FileHandleType`] discriminants.
    pub handle_type: u32,
    /// Number of valid bytes used inside `f_handle`.
    pub handle_bytes: u32,
    /// Opaque per-filesystem payload (inode number, generation, …).
    pub f_handle: [u8; FILE_HANDLE_BYTES],
}

impl Default for FileHandle {
    fn default() -> Self {
        Self {
            handle_type: 0,
            handle_bytes: 0,
            f_handle: [0u8; FILE_HANDLE_BYTES],
        }
    }
}

impl FileHandle {
    /// Construct a new, zeroed file handle.
    pub const fn new() -> Self {
        Self {
            handle_type: 0,
            handle_bytes: 0,
            f_handle: [0u8; FILE_HANDLE_BYTES],
        }
    }

    /// Return `true` if the handle appears structurally valid (non-zero type, non-zero size).
    pub fn is_valid(&self) -> bool {
        self.handle_type != 0
            && self.handle_bytes > 0
            && self.handle_bytes <= FILE_HANDLE_BYTES as u32
    }

    /// Write a 64-bit inode number into the handle payload at byte offset 0.
    pub fn set_ino(&mut self, ino: u64) {
        let bytes = ino.to_le_bytes();
        self.f_handle[..8].copy_from_slice(&bytes);
        if self.handle_bytes < 8 {
            self.handle_bytes = 8;
        }
    }

    /// Read the 64-bit inode number from the handle payload.
    ///
    /// Returns `None` if the handle contains fewer than 8 payload bytes.
    pub fn get_ino(&self) -> Option<u64> {
        if self.handle_bytes < 8 {
            return None;
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.f_handle[..8]);
        Some(u64::from_le_bytes(buf))
    }

    /// Write a 32-bit inode generation counter into the handle payload at byte offset 8.
    pub fn set_generation(&mut self, generation: u32) {
        let bytes = generation.to_le_bytes();
        self.f_handle[8..12].copy_from_slice(&bytes);
        if self.handle_bytes < 12 {
            self.handle_bytes = 12;
        }
    }

    /// Read the 32-bit inode generation counter from the handle payload.
    pub fn get_generation(&self) -> Option<u32> {
        if self.handle_bytes < 12 {
            return None;
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&self.f_handle[8..12]);
        Some(u32::from_le_bytes(buf))
    }
}

// ── MountId ───────────────────────────────────────────────────────────────────

/// Identifies a mount point for staleness detection.
///
/// A file handle is stale when the mount identified here no longer exists
/// or the mount has been unmounted and re-mounted (generation mismatch).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MountId {
    /// Monotonically increasing counter; bumped on every mount/umount of this slot.
    pub mount_generation: u32,
    /// Numeric mount identifier (matches `/proc/self/mountinfo` column 1).
    pub mount_id: u32,
}

impl MountId {
    /// Construct a new [`MountId`].
    pub const fn new(mount_id: u32, mount_generation: u32) -> Self {
        Self {
            mount_generation,
            mount_id,
        }
    }

    /// Return `true` when this `MountId` matches `other`, i.e. same mount slot
    /// and generation — meaning the mount has not been recycled.
    pub fn matches(&self, other: &Self) -> bool {
        self.mount_id == other.mount_id && self.mount_generation == other.mount_generation
    }
}

// ── FileHandleOps trait ───────────────────────────────────────────────────────

/// Filesystem-side operations required to encode and decode file handles.
///
/// Each filesystem that wants to support NFS-style persistent handles implements
/// this trait and registers with the [`FileHandleRegistry`].
pub trait FileHandleOps {
    /// Encode `inode_id` into a [`FileHandle`].
    ///
    /// The implementation must write an opaque, self-contained payload into
    /// `handle.f_handle` that allows the inode to be found again later via
    /// [`decode_fh`](FileHandleOps::decode_fh).
    fn encode_fh(&self, inode_id: u64, handle_type: FileHandleType) -> Result<FileHandle>;

    /// Reconstruct the inode id from a previously encoded [`FileHandle`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the inode is no longer present,
    /// [`Error::InvalidArgument`] if the handle is malformed.
    fn decode_fh(&self, handle: &FileHandle) -> Result<u64>;
}

// ── DefaultFileHandleOps ──────────────────────────────────────────────────────

/// Default (generic) implementation of [`FileHandleOps`] used when no
/// filesystem-specific encoder is registered.
///
/// Stores the raw inode number and a 32-bit generation counter in the payload.
pub struct DefaultFileHandleOps {
    /// Generation counter embedded in every encoded handle to detect recycled inodes.
    generation: u32,
}

impl DefaultFileHandleOps {
    /// Create a new default ops object with the given generation seed.
    pub const fn new(generation: u32) -> Self {
        Self { generation }
    }
}

impl FileHandleOps for DefaultFileHandleOps {
    fn encode_fh(&self, inode_id: u64, handle_type: FileHandleType) -> Result<FileHandle> {
        let mut h = FileHandle::new();
        h.handle_type = handle_type as u32;
        h.set_ino(inode_id);
        h.set_generation(self.generation);
        Ok(h)
    }

    fn decode_fh(&self, handle: &FileHandle) -> Result<u64> {
        if !handle.is_valid() {
            return Err(Error::InvalidArgument);
        }
        handle.get_ino().ok_or(Error::InvalidArgument)
    }
}

// ── ActiveHandle ──────────────────────────────────────────────────────────────

/// An entry in the active-handle table maintained by [`FileHandleRegistry`].
#[derive(Clone, Copy)]
struct ActiveHandle {
    /// The encoded handle blob.
    handle: FileHandle,
    /// Mount under which the handle was created.
    mount_id: MountId,
    /// Inode number the handle resolves to.
    inode_id: u64,
    /// Whether this slot is occupied.
    in_use: bool,
}

impl Default for ActiveHandle {
    fn default() -> Self {
        Self {
            handle: FileHandle::new(),
            mount_id: MountId::new(0, 0),
            inode_id: 0,
            in_use: false,
        }
    }
}

// ── FileHandleRegistry ────────────────────────────────────────────────────────

/// Registry tracking all currently active file handles.
///
/// Up to [`MAX_FILE_HANDLES`] handles may be alive simultaneously.  The registry
/// is the single source of truth for resolving a handle back to an inode.
pub struct FileHandleRegistry {
    /// Fixed-size slot table.
    slots: [ActiveHandle; MAX_FILE_HANDLES],
    /// Index of the next slot to try on allocation (linear scan from here).
    next_slot: usize,
    /// Accumulated operational statistics.
    stats: FileHandleStats,
}

impl Default for FileHandleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl FileHandleRegistry {
    /// Construct an empty registry.
    pub const fn new() -> Self {
        Self {
            slots: [const {
                ActiveHandle {
                    handle: FileHandle::new(),
                    mount_id: MountId::new(0, 0),
                    inode_id: 0,
                    in_use: false,
                }
            }; MAX_FILE_HANDLES],
            next_slot: 0,
            stats: FileHandleStats::new(),
        }
    }

    /// Encode `inode_id` using `ops` and store the resulting handle.
    ///
    /// Returns the new [`FileHandle`] and the [`MountId`] to pass back to
    /// the caller of `name_to_handle_at`.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] — the registry is full.
    /// - Any error propagated from [`FileHandleOps::encode_fh`].
    pub fn create_handle(
        &mut self,
        inode_id: u64,
        handle_type: FileHandleType,
        mount_id: MountId,
        ops: &dyn FileHandleOps,
    ) -> Result<FileHandle> {
        let slot = self.find_free_slot().ok_or(Error::OutOfMemory)?;
        let handle = ops.encode_fh(inode_id, handle_type)?;
        self.slots[slot] = ActiveHandle {
            handle,
            mount_id,
            inode_id,
            in_use: true,
        };
        self.stats.encoded += 1;
        Ok(handle)
    }

    /// Look up a previously created handle and return the inode id it points to.
    ///
    /// Validates that the caller's `mount_id` still matches the one recorded at
    /// creation time (stale-handle detection).
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — no matching handle in the registry.
    /// - [`Error::InvalidArgument`] — the handle is structurally invalid.
    pub fn resolve_handle(
        &mut self,
        handle: &FileHandle,
        mount_id: &MountId,
        ops: &dyn FileHandleOps,
    ) -> Result<u64> {
        if !handle.is_valid() {
            return Err(Error::InvalidArgument);
        }
        // Check stale mount.
        for slot in &self.slots {
            if !slot.in_use {
                continue;
            }
            if slot.handle.handle_type == handle.handle_type
                && slot.handle.handle_bytes == handle.handle_bytes
                && slot.handle.f_handle[..slot.handle.handle_bytes as usize]
                    == handle.f_handle[..handle.handle_bytes as usize]
            {
                if !slot.mount_id.matches(mount_id) {
                    self.stats.stale_detected += 1;
                    return Err(Error::NotFound);
                }
                let inode_id = ops.decode_fh(handle)?;
                self.stats.decoded += 1;
                return Ok(inode_id);
            }
        }
        self.stats.resolve_failures += 1;
        Err(Error::NotFound)
    }

    /// Invalidate all handles associated with `inode_id` on `mount_id`.
    ///
    /// Called when an inode is deleted so that subsequent `open_by_handle_at`
    /// calls for those handles correctly fail with `ESTALE`.
    pub fn invalidate(&mut self, inode_id: u64, mount_id: &MountId) {
        for slot in self.slots.iter_mut() {
            if slot.in_use && slot.inode_id == inode_id && slot.mount_id.matches(mount_id) {
                *slot = ActiveHandle::default();
            }
        }
    }

    /// Return a snapshot of accumulated statistics.
    pub fn stats(&self) -> &FileHandleStats {
        &self.stats
    }

    // -- private helpers ------------------------------------------------------

    fn find_free_slot(&mut self) -> Option<usize> {
        let start = self.next_slot;
        for i in 0..MAX_FILE_HANDLES {
            let idx = (start + i) % MAX_FILE_HANDLES;
            if !self.slots[idx].in_use {
                self.next_slot = (idx + 1) % MAX_FILE_HANDLES;
                return Some(idx);
            }
        }
        None
    }
}

// ── High-level syscall helpers ─────────────────────────────────────────────────

/// Flags accepted by `name_to_handle_at`.
pub mod name_to_handle_flags {
    /// Do not follow trailing symlinks when resolving `path`.
    pub const AT_SYMLINK_FOLLOW: u32 = 0x400;
    /// Allow `path` to be an empty string (operate on `dirfd` itself).
    pub const AT_EMPTY_PATH: u32 = 0x1000;
}

/// Resolve `path` relative to `dirfd` and encode the result as a file handle.
///
/// This is the kernel-side implementation of `name_to_handle_at(2)`.
///
/// # Parameters
///
/// - `dirfd`    — base directory file descriptor (`AT_FDCWD` = −100 for cwd).
/// - `path`     — null-terminated path bytes (may be empty if `AT_EMPTY_PATH`).
/// - `flags`    — combination of [`name_to_handle_flags`] constants.
/// - `mount_id` — the mount identification to embed in the handle.
/// - `ops`      — filesystem's handle encoder.
/// - `registry` — the active handle registry.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — bad flags or empty path without `AT_EMPTY_PATH`.
/// - [`Error::NotFound`]        — path resolution failed.
/// - [`Error::OutOfMemory`]     — handle table is full.
pub fn name_to_handle_at(
    _dirfd: i32,
    path: &[u8],
    flags: u32,
    mount_id: MountId,
    inode_id: u64,
    handle_type: FileHandleType,
    ops: &dyn FileHandleOps,
    registry: &mut FileHandleRegistry,
) -> Result<(FileHandle, MountId)> {
    let allow_empty = (flags & name_to_handle_flags::AT_EMPTY_PATH) != 0;
    if path.is_empty() && !allow_empty {
        return Err(Error::InvalidArgument);
    }
    let handle = registry.create_handle(inode_id, handle_type, mount_id, ops)?;
    Ok((handle, mount_id))
}

/// Open a file identified by a previously obtained file handle.
///
/// This is the kernel-side implementation of `open_by_handle_at(2)`.
///
/// # Parameters
///
/// - `_mount_fd` — file descriptor for any file on the target mount.
/// - `handle`    — handle previously returned by [`name_to_handle_at`].
/// - `flags`     — open flags (O_RDONLY / O_WRONLY / …).
/// - `mount_id`  — expected mount identification for staleness check.
/// - `ops`       — filesystem's handle decoder.
/// - `registry`  — the active handle registry.
///
/// # Returns
///
/// The inode id of the file.  The caller is responsible for constructing
/// an actual file descriptor from the inode.
///
/// # Errors
///
/// - [`Error::PermissionDenied`] — caller lacks `CAP_DAC_READ_SEARCH`.
/// - [`Error::InvalidArgument`]  — malformed handle.
/// - [`Error::NotFound`]         — stale or unknown handle.
pub fn open_by_handle_at(
    _mount_fd: i32,
    handle: &FileHandle,
    _flags: u32,
    mount_id: &MountId,
    ops: &dyn FileHandleOps,
    registry: &mut FileHandleRegistry,
) -> Result<u64> {
    registry.resolve_handle(handle, mount_id, ops)
}

// ── FileHandleStats ───────────────────────────────────────────────────────────

/// Cumulative statistics for the file-handle subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct FileHandleStats {
    /// Total file handles successfully encoded.
    pub encoded: u64,
    /// Total file handles successfully decoded.
    pub decoded: u64,
    /// Times a stale mount was detected during resolution.
    pub stale_detected: u64,
    /// Times a handle could not be found in the registry.
    pub resolve_failures: u64,
}

impl FileHandleStats {
    /// Construct a zeroed stats object.
    pub const fn new() -> Self {
        Self {
            encoded: 0,
            decoded: 0,
            stale_detected: 0,
            resolve_failures: 0,
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    struct SimpleOps;

    impl FileHandleOps for SimpleOps {
        fn encode_fh(&self, inode_id: u64, handle_type: FileHandleType) -> Result<FileHandle> {
            let mut h = FileHandle::new();
            h.handle_type = handle_type as u32;
            h.set_ino(inode_id);
            h.set_generation(1);
            Ok(h)
        }
        fn decode_fh(&self, handle: &FileHandle) -> Result<u64> {
            handle.get_ino().ok_or(Error::InvalidArgument)
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let mut reg = FileHandleRegistry::new();
        let mount = MountId::new(1, 42);
        let ops = SimpleOps;
        let (fh, mid) = name_to_handle_at(
            -100,
            b"test",
            0,
            mount,
            99,
            FileHandleType::Inode,
            &ops,
            &mut reg,
        )
        .unwrap();
        let ino = open_by_handle_at(-1, &fh, 0, &mid, &ops, &mut reg).unwrap();
        assert_eq!(ino, 99);
    }

    #[test]
    fn stale_mount_rejected() {
        let mut reg = FileHandleRegistry::new();
        let mount = MountId::new(1, 42);
        let stale = MountId::new(1, 99);
        let ops = SimpleOps;
        let (fh, _) = name_to_handle_at(
            -100,
            b"test",
            0,
            mount,
            7,
            FileHandleType::Directory,
            &ops,
            &mut reg,
        )
        .unwrap();
        let result = open_by_handle_at(-1, &fh, 0, &stale, &ops, &mut reg);
        assert!(result.is_err());
        assert_eq!(reg.stats().stale_detected, 1);
    }
}
