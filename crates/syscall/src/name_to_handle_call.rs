// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `name_to_handle_at(2)` and `open_by_handle_at(2)` syscall handlers.
//!
//! These Linux-specific syscalls convert a file path to a persistent file
//! handle and open files by handle, respectively.  The primary use case is
//! NFS-style stateless file access where a server can hand out opaque handles
//! to clients, which can later re-open the file without repeating a full path
//! lookup.
//!
//! # Syscall summary
//!
//! | Syscall               | Handler                     | Purpose                         |
//! |-----------------------|-----------------------------|---------------------------------|
//! | `name_to_handle_at`   | [`sys_name_to_handle_at`]   | Path -> persistent file handle  |
//! | `open_by_handle_at`   | [`sys_open_by_handle_at`]   | Handle -> open file descriptor  |
//!
//! # Handle format
//!
//! ```text
//! +--------+--------+----------------------------+
//! | mount  | handle | handle bytes               |
//! | id     | type   | (up to MAX_HANDLE_BYTES)   |
//! +--------+--------+----------------------------+
//! ```
//!
//! The handle embeds enough information to uniquely identify a file on a
//! given filesystem mount.  Typically this includes the inode number and a
//! generation counter so that stale handles can be detected.
//!
//! # POSIX conformance
//!
//! `name_to_handle_at` and `open_by_handle_at` are Linux extensions (since
//! Linux 2.6.39).  POSIX.1-2024 does not define these syscalls.  The inode
//! and generation number concepts align with POSIX filesystem semantics.
//!
//! # References
//!
//! - Linux `fs/fhandle.c`
//! - man: `name_to_handle_at(2)`, `open_by_handle_at(2)`

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum size of the opaque handle bytes.
pub const MAX_HANDLE_BYTES: usize = 128;

/// Maximum path length accepted by `name_to_handle_at`.
pub const MAX_PATH_LEN: usize = 4096;

/// Maximum number of cached handle entries in the handle table.
pub const MAX_HANDLE_ENTRIES: usize = 256;

/// Sentinel value for "current working directory" when `dirfd` is `AT_FDCWD`.
pub const AT_FDCWD: i32 = -100;

/// Follow terminal symlinks during path lookup (default).
pub const AT_SYMLINK_FOLLOW: u32 = 0x0400;

/// Do not follow terminal symlinks.
pub const AT_EMPTY_PATH: u32 = 0x1000;

/// Mask of all recognised `name_to_handle_at` flags.
const FLAGS_KNOWN: u32 = AT_SYMLINK_FOLLOW | AT_EMPTY_PATH;

/// Syscall number for `name_to_handle_at` (x86_64 Linux ABI).
pub const SYS_NAME_TO_HANDLE_AT: u64 = 303;

/// Syscall number for `open_by_handle_at` (x86_64 Linux ABI).
pub const SYS_OPEN_BY_HANDLE_AT: u64 = 304;

// ---------------------------------------------------------------------------
// HandleType — classification of file handles
// ---------------------------------------------------------------------------

/// Classification of the filesystem object the handle refers to.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleType {
    /// Handle for a regular file.
    File = 0,
    /// Handle for a directory.
    Directory = 1,
    /// Handle for a symbolic link.
    Symlink = 2,
    /// Handle for a device node.
    Device = 3,
    /// Handle for a named pipe (FIFO).
    Fifo = 4,
    /// Handle for a socket.
    Socket = 5,
}

impl HandleType {
    /// Parse from a raw `u32`.
    pub fn from_raw(raw: u32) -> Result<Self> {
        match raw {
            0 => Ok(Self::File),
            1 => Ok(Self::Directory),
            2 => Ok(Self::Symlink),
            3 => Ok(Self::Device),
            4 => Ok(Self::Fifo),
            5 => Ok(Self::Socket),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Return the raw `u32` representation.
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

// ---------------------------------------------------------------------------
// MountId — filesystem mount identifier
// ---------------------------------------------------------------------------

/// Unique identifier for a filesystem mount point.
///
/// In a real kernel this comes from the mount table (e.g., `mnt_id` in
/// `struct mount`).  We use a simple `u64` wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MountId(u64);

impl MountId {
    /// Create a new mount identifier.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Return the raw `u64` value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// HandleBytes — opaque handle payload
// ---------------------------------------------------------------------------

/// Opaque byte buffer carrying the filesystem-specific handle data.
///
/// Typically encodes `(inode_number, generation)` but the exact format is
/// filesystem-dependent.
#[derive(Debug, Clone)]
pub struct HandleBytes {
    /// Raw handle data.
    data: [u8; MAX_HANDLE_BYTES],
    /// Number of valid bytes in `data`.
    len: usize,
}

impl HandleBytes {
    /// Create an empty handle bytes buffer.
    pub const fn empty() -> Self {
        Self {
            data: [0u8; MAX_HANDLE_BYTES],
            len: 0,
        }
    }

    /// Create from a slice.  Returns `InvalidArgument` if `src` exceeds
    /// `MAX_HANDLE_BYTES`.
    pub fn from_slice(src: &[u8]) -> Result<Self> {
        if src.len() > MAX_HANDLE_BYTES {
            return Err(Error::InvalidArgument);
        }
        let mut hb = Self::empty();
        hb.data[..src.len()].copy_from_slice(src);
        hb.len = src.len();
        Ok(hb)
    }

    /// Return the valid portion of the handle as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Return the length of the valid handle data.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Return `true` if the handle is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for HandleBytes {
    fn default() -> Self {
        Self::empty()
    }
}

// ---------------------------------------------------------------------------
// FileHandle — the complete file handle structure
// ---------------------------------------------------------------------------

/// Complete file handle returned by `name_to_handle_at`.
///
/// Contains the mount identifier, the handle type, and the opaque handle
/// bytes.  This structure is what the kernel returns to user space and what
/// `open_by_handle_at` accepts to re-open the file.
#[derive(Debug, Clone)]
pub struct FileHandle {
    /// Filesystem mount identifier.
    pub mount_id: MountId,
    /// Type of the filesystem object.
    pub handle_type: HandleType,
    /// Opaque handle bytes.
    pub handle_bytes: HandleBytes,
    /// Inode number encoded in the handle (for fast validation).
    pub inode: u64,
    /// Generation counter for stale-handle detection.
    pub generation: u64,
}

impl FileHandle {
    /// Create a new file handle.
    pub const fn new(
        mount_id: MountId,
        handle_type: HandleType,
        inode: u64,
        generation: u64,
    ) -> Self {
        Self {
            mount_id,
            handle_type,
            handle_bytes: HandleBytes::empty(),
            inode,
            generation,
        }
    }

    /// Return `true` if this handle matches the given mount and inode.
    pub const fn matches(&self, mount_id: MountId, inode: u64) -> bool {
        self.mount_id.as_u64() == mount_id.as_u64() && self.inode == inode
    }

    /// Return `true` if the generation counter matches.
    pub const fn generation_matches(&self, generation: u64) -> bool {
        self.generation == generation
    }
}

// ---------------------------------------------------------------------------
// HandleTable — kernel-internal handle cache
// ---------------------------------------------------------------------------

/// Entry in the handle table.
#[derive(Debug, Clone)]
struct HandleEntry {
    handle: FileHandle,
    in_use: bool,
}

impl HandleEntry {
    const fn empty() -> Self {
        Self {
            handle: FileHandle::new(MountId::new(0), HandleType::File, 0, 0),
            in_use: false,
        }
    }
}

/// Kernel-internal file handle cache.
///
/// Stores recently created handles so that `open_by_handle_at` can validate
/// and resolve them.  In a real kernel this would be per-mount or per-superblock;
/// here we use a single global table for simplicity.
pub struct HandleTable {
    entries: [HandleEntry; MAX_HANDLE_ENTRIES],
    count: usize,
    next_generation: u64,
}

impl HandleTable {
    /// Create an empty handle table.
    pub const fn new() -> Self {
        Self {
            entries: [const { HandleEntry::empty() }; MAX_HANDLE_ENTRIES],
            count: 0,
            next_generation: 1,
        }
    }

    /// Allocate the next generation counter.
    fn alloc_generation(&mut self) -> u64 {
        let g = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        g
    }

    /// Insert a handle into the table.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfMemory`] if the table is full.
    pub fn insert(&mut self, handle: FileHandle) -> Result<()> {
        for entry in self.entries.iter_mut() {
            if !entry.in_use {
                entry.handle = handle;
                entry.in_use = true;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up a handle by mount ID and inode.
    pub fn find(&self, mount_id: MountId, inode: u64) -> Option<&FileHandle> {
        self.entries
            .iter()
            .find(|e| e.in_use && e.handle.matches(mount_id, inode))
            .map(|e| &e.handle)
    }

    /// Look up a handle by mount ID, inode, and generation (strict match).
    pub fn find_exact(
        &self,
        mount_id: MountId,
        inode: u64,
        generation: u64,
    ) -> Option<&FileHandle> {
        self.entries
            .iter()
            .find(|e| {
                e.in_use
                    && e.handle.matches(mount_id, inode)
                    && e.handle.generation_matches(generation)
            })
            .map(|e| &e.handle)
    }

    /// Remove a handle entry by mount ID and inode.
    pub fn remove(&mut self, mount_id: MountId, inode: u64) {
        for entry in self.entries.iter_mut() {
            if entry.in_use && entry.handle.matches(mount_id, inode) {
                entry.in_use = false;
                entry.handle = FileHandle::new(MountId::new(0), HandleType::File, 0, 0);
                self.count = self.count.saturating_sub(1);
                return;
            }
        }
    }

    /// Return the number of active entries.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return the next generation counter value (without allocating it).
    pub const fn peek_generation(&self) -> u64 {
        self.next_generation
    }
}

impl Default for HandleTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// HandleStats — statistics
// ---------------------------------------------------------------------------

/// Accumulated statistics for the handle subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct HandleStats {
    /// Total `name_to_handle_at` calls.
    pub name_to_handle_calls: u64,
    /// Total `open_by_handle_at` calls.
    pub open_by_handle_calls: u64,
    /// Number of stale handle rejections.
    pub stale_handle_errors: u64,
    /// Number of handles successfully created.
    pub handles_created: u64,
    /// Number of handles successfully opened.
    pub handles_opened: u64,
}

impl HandleStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            name_to_handle_calls: 0,
            open_by_handle_calls: 0,
            stale_handle_errors: 0,
            handles_created: 0,
            handles_opened: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate `name_to_handle_at` flags.
fn validate_flags(flags: u32) -> Result<()> {
    if flags & !FLAGS_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate a path length.
fn validate_path_len(len: usize) -> Result<()> {
    if len == 0 {
        return Err(Error::InvalidArgument);
    }
    if len > MAX_PATH_LEN {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate a `dirfd` argument.
fn validate_dirfd(dirfd: i32) -> Result<()> {
    if dirfd != AT_FDCWD && dirfd < 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// encode_handle — encode inode + generation into handle bytes
// ---------------------------------------------------------------------------

/// Encode an inode number and generation counter into opaque handle bytes.
///
/// The encoding layout is:
/// ```text
/// [0..8)  — inode number (little-endian u64)
/// [8..16) — generation counter (little-endian u64)
/// ```
///
/// # Returns
///
/// A [`HandleBytes`] containing the 16-byte encoding.
pub fn encode_handle(inode: u64, generation: u64) -> HandleBytes {
    let mut hb = HandleBytes::empty();
    let inode_bytes = inode.to_le_bytes();
    let gen_bytes = generation.to_le_bytes();
    hb.data[..8].copy_from_slice(&inode_bytes);
    hb.data[8..16].copy_from_slice(&gen_bytes);
    hb.len = 16;
    hb
}

/// Decode inode number and generation counter from opaque handle bytes.
///
/// # Errors
///
/// [`Error::InvalidArgument`] if the handle bytes are too short (< 16 bytes).
pub fn decode_handle(hb: &HandleBytes) -> Result<(u64, u64)> {
    if hb.len() < 16 {
        return Err(Error::InvalidArgument);
    }
    let mut inode_buf = [0u8; 8];
    let mut gen_buf = [0u8; 8];
    inode_buf.copy_from_slice(&hb.as_bytes()[..8]);
    gen_buf.copy_from_slice(&hb.as_bytes()[8..16]);
    Ok((u64::from_le_bytes(inode_buf), u64::from_le_bytes(gen_buf)))
}

// ---------------------------------------------------------------------------
// PathInfo — stub path resolution result
// ---------------------------------------------------------------------------

/// Result of resolving a file path (stub).
///
/// In a real kernel this would come from the VFS path-walk.
#[derive(Debug, Clone, Copy)]
pub struct PathInfo {
    /// Mount identifier of the filesystem containing the file.
    pub mount_id: MountId,
    /// Inode number on the filesystem.
    pub inode: u64,
    /// Type of the filesystem object.
    pub handle_type: HandleType,
    /// Current generation counter for the inode.
    pub generation: u64,
}

// ---------------------------------------------------------------------------
// sys_name_to_handle_at
// ---------------------------------------------------------------------------

/// `name_to_handle_at(2)` — convert a path to a persistent file handle.
///
/// Resolves the given path relative to `dirfd` and produces an opaque
/// [`FileHandle`] that can later be passed to [`sys_open_by_handle_at`].
///
/// # Arguments
///
/// * `table`     — Handle table for caching.
/// * `stats`     — Statistics accumulator.
/// * `dirfd`     — Directory file descriptor for relative paths (`AT_FDCWD`
///                 for the current working directory).
/// * `path_len`  — Length of the path in bytes.
/// * `path_info` — Pre-resolved path information (in a real kernel, the VFS
///                 would resolve this internally).
/// * `flags`     — `AT_SYMLINK_FOLLOW` or `AT_EMPTY_PATH`.
///
/// # Returns
///
/// A [`FileHandle`] on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Unknown flags, zero or too-long path,
///   bad `dirfd`.
/// * [`Error::NotFound`]        — File does not exist (stub: never returned
///   since `path_info` is pre-resolved).
/// * [`Error::OutOfMemory`]     — Handle table is full.
pub fn sys_name_to_handle_at(
    table: &mut HandleTable,
    stats: &mut HandleStats,
    dirfd: i32,
    path_len: usize,
    path_info: &PathInfo,
    flags: u32,
) -> Result<FileHandle> {
    stats.name_to_handle_calls += 1;

    validate_dirfd(dirfd)?;
    validate_path_len(path_len)?;
    validate_flags(flags)?;

    let generation = table.alloc_generation();

    let handle_bytes = encode_handle(path_info.inode, generation);

    let handle = FileHandle {
        mount_id: path_info.mount_id,
        handle_type: path_info.handle_type,
        handle_bytes,
        inode: path_info.inode,
        generation,
    };

    table.insert(handle.clone())?;
    stats.handles_created += 1;

    Ok(handle)
}

// ---------------------------------------------------------------------------
// sys_open_by_handle_at
// ---------------------------------------------------------------------------

/// `open_by_handle_at(2)` — open a file by its persistent handle.
///
/// Looks up the file handle in the kernel handle table and, if valid,
/// returns a synthetic file descriptor number.  The caller must have
/// `CAP_DAC_READ_SEARCH` in a real kernel; here we simulate it with
/// `requires_cap`.
///
/// # Arguments
///
/// * `table`        — Handle table.
/// * `stats`        — Statistics accumulator.
/// * `mount_fd`     — File descriptor identifying the mount (or `AT_FDCWD`).
/// * `mount_id`     — Mount identifier to match.
/// * `inode`        — Inode number from the handle.
/// * `generation`   — Generation counter from the handle.
/// * `open_flags`   — Open flags (`O_RDONLY`, etc.) — not validated in stub.
/// * `requires_cap` — Whether the caller has `CAP_DAC_READ_SEARCH`.
///
/// # Returns
///
/// A synthetic file descriptor number (the inode cast to `i32`) on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Bad `mount_fd`.
/// * [`Error::PermissionDenied`] — Caller lacks required capability.
/// * [`Error::NotFound`]         — Handle not found in the table.
/// * [`Error::IoError`]          — Stale handle (generation mismatch).
pub fn sys_open_by_handle_at(
    table: &HandleTable,
    stats: &mut HandleStats,
    mount_fd: i32,
    mount_id: MountId,
    inode: u64,
    generation: u64,
    _open_flags: u32,
    requires_cap: bool,
) -> Result<i32> {
    stats.open_by_handle_calls += 1;

    validate_dirfd(mount_fd)?;

    if !requires_cap {
        return Err(Error::PermissionDenied);
    }

    // Look up by mount + inode first.
    let handle = table.find(mount_id, inode).ok_or(Error::NotFound)?;

    // Verify generation counter (stale handle detection).
    if !handle.generation_matches(generation) {
        stats.stale_handle_errors += 1;
        return Err(Error::IoError);
    }

    stats.handles_opened += 1;

    // In a real kernel we would allocate an fd; here we return a synthetic
    // value derived from the inode.
    let fd = (inode & 0x7FFF_FFFF) as i32;
    Ok(fd.max(3)) // Never return stdin/stdout/stderr
}

// ---------------------------------------------------------------------------
// Convenience: resolve_and_create_handle
// ---------------------------------------------------------------------------

/// Combined path-resolution and handle-creation helper.
///
/// Convenience wrapper that takes a [`PathInfo`] (simulating VFS lookup)
/// and creates a handle in one step.
pub fn resolve_and_create_handle(
    table: &mut HandleTable,
    stats: &mut HandleStats,
    dirfd: i32,
    path_len: usize,
    path_info: &PathInfo,
    flags: u32,
) -> Result<FileHandle> {
    sys_name_to_handle_at(table, stats, dirfd, path_len, path_info, flags)
}

// ---------------------------------------------------------------------------
// Convenience: validate_and_open_handle
// ---------------------------------------------------------------------------

/// Combined handle-validation and file-open helper.
///
/// Decodes the handle bytes and calls [`sys_open_by_handle_at`].
pub fn validate_and_open_handle(
    table: &HandleTable,
    stats: &mut HandleStats,
    mount_fd: i32,
    mount_id: MountId,
    handle_bytes: &HandleBytes,
    open_flags: u32,
    has_cap: bool,
) -> Result<i32> {
    let (inode, generation) = decode_handle(handle_bytes)?;
    sys_open_by_handle_at(
        table, stats, mount_fd, mount_id, inode, generation, open_flags, has_cap,
    )
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_path_info(inode: u64) -> PathInfo {
        PathInfo {
            mount_id: MountId::new(1),
            inode,
            handle_type: HandleType::File,
            generation: 42,
        }
    }

    // --- HandleType ---

    #[test]
    fn handle_type_roundtrip() {
        for raw in 0..=5u32 {
            let ht = HandleType::from_raw(raw).unwrap();
            assert_eq!(ht.as_u32(), raw);
        }
    }

    #[test]
    fn handle_type_invalid() {
        assert_eq!(HandleType::from_raw(99), Err(Error::InvalidArgument));
    }

    // --- MountId ---

    #[test]
    fn mount_id_roundtrip() {
        let m = MountId::new(0xDEAD_BEEF);
        assert_eq!(m.as_u64(), 0xDEAD_BEEF);
    }

    // --- HandleBytes ---

    #[test]
    fn handle_bytes_from_slice() {
        let data = [1u8, 2, 3, 4];
        let hb = HandleBytes::from_slice(&data).unwrap();
        assert_eq!(hb.len(), 4);
        assert_eq!(hb.as_bytes(), &[1, 2, 3, 4]);
    }

    #[test]
    fn handle_bytes_empty() {
        let hb = HandleBytes::empty();
        assert!(hb.is_empty());
        assert_eq!(hb.len(), 0);
    }

    #[test]
    fn handle_bytes_too_large() {
        let data = [0u8; MAX_HANDLE_BYTES + 1];
        assert_eq!(HandleBytes::from_slice(&data), Err(Error::InvalidArgument));
    }

    // --- encode_handle / decode_handle ---

    #[test]
    fn encode_decode_roundtrip() {
        let hb = encode_handle(12345, 67890);
        let (inode, generation) = decode_handle(&hb).unwrap();
        assert_eq!(inode, 12345);
        assert_eq!(generation, 67890);
    }

    #[test]
    fn decode_too_short() {
        let hb = HandleBytes::from_slice(&[1, 2, 3]).unwrap();
        assert_eq!(decode_handle(&hb), Err(Error::InvalidArgument));
    }

    // --- validate_flags ---

    #[test]
    fn valid_flags_accepted() {
        assert!(validate_flags(0).is_ok());
        assert!(validate_flags(AT_SYMLINK_FOLLOW).is_ok());
        assert!(validate_flags(AT_EMPTY_PATH).is_ok());
        assert!(validate_flags(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH).is_ok());
    }

    #[test]
    fn unknown_flags_rejected() {
        assert_eq!(validate_flags(0xFFFF_0000), Err(Error::InvalidArgument));
    }

    // --- validate_path_len ---

    #[test]
    fn zero_path_len_rejected() {
        assert_eq!(validate_path_len(0), Err(Error::InvalidArgument));
    }

    #[test]
    fn too_long_path_rejected() {
        assert_eq!(
            validate_path_len(MAX_PATH_LEN + 1),
            Err(Error::InvalidArgument)
        );
    }

    // --- validate_dirfd ---

    #[test]
    fn at_fdcwd_accepted() {
        assert!(validate_dirfd(AT_FDCWD).is_ok());
    }

    #[test]
    fn positive_dirfd_accepted() {
        assert!(validate_dirfd(3).is_ok());
    }

    #[test]
    fn negative_dirfd_rejected() {
        assert_eq!(validate_dirfd(-1), Err(Error::InvalidArgument));
    }

    // --- HandleTable ---

    #[test]
    fn table_insert_and_find() {
        let mut table = HandleTable::new();
        let handle = FileHandle::new(MountId::new(1), HandleType::File, 100, 1);
        table.insert(handle).unwrap();
        assert_eq!(table.count(), 1);
        assert!(table.find(MountId::new(1), 100).is_some());
    }

    #[test]
    fn table_find_exact_generation() {
        let mut table = HandleTable::new();
        let handle = FileHandle::new(MountId::new(1), HandleType::File, 100, 5);
        table.insert(handle).unwrap();
        assert!(table.find_exact(MountId::new(1), 100, 5).is_some());
        assert!(table.find_exact(MountId::new(1), 100, 99).is_none());
    }

    #[test]
    fn table_remove() {
        let mut table = HandleTable::new();
        let handle = FileHandle::new(MountId::new(1), HandleType::File, 100, 1);
        table.insert(handle).unwrap();
        table.remove(MountId::new(1), 100);
        assert_eq!(table.count(), 0);
        assert!(table.find(MountId::new(1), 100).is_none());
    }

    #[test]
    fn table_generation_allocation() {
        let mut table = HandleTable::new();
        let g1 = table.alloc_generation();
        let g2 = table.alloc_generation();
        assert_eq!(g1 + 1, g2);
    }

    // --- sys_name_to_handle_at ---

    #[test]
    fn name_to_handle_success() {
        let mut table = HandleTable::new();
        let mut stats = HandleStats::new();
        let info = sample_path_info(42);

        let handle = sys_name_to_handle_at(&mut table, &mut stats, AT_FDCWD, 10, &info, 0).unwrap();

        assert_eq!(handle.mount_id, MountId::new(1));
        assert_eq!(handle.inode, 42);
        assert_eq!(handle.handle_type, HandleType::File);
        assert_eq!(stats.name_to_handle_calls, 1);
        assert_eq!(stats.handles_created, 1);
        assert_eq!(table.count(), 1);
    }

    #[test]
    fn name_to_handle_bad_flags() {
        let mut table = HandleTable::new();
        let mut stats = HandleStats::new();
        let info = sample_path_info(42);

        let result = sys_name_to_handle_at(&mut table, &mut stats, AT_FDCWD, 10, &info, 0xDEAD);
        assert_eq!(result, Err(Error::InvalidArgument));
    }

    #[test]
    fn name_to_handle_zero_path() {
        let mut table = HandleTable::new();
        let mut stats = HandleStats::new();
        let info = sample_path_info(42);

        let result = sys_name_to_handle_at(&mut table, &mut stats, AT_FDCWD, 0, &info, 0);
        assert_eq!(result, Err(Error::InvalidArgument));
    }

    #[test]
    fn name_to_handle_bad_dirfd() {
        let mut table = HandleTable::new();
        let mut stats = HandleStats::new();
        let info = sample_path_info(42);

        let result = sys_name_to_handle_at(&mut table, &mut stats, -5, 10, &info, 0);
        assert_eq!(result, Err(Error::InvalidArgument));
    }

    #[test]
    fn name_to_handle_with_symlink_follow() {
        let mut table = HandleTable::new();
        let mut stats = HandleStats::new();
        let info = sample_path_info(77);

        let handle = sys_name_to_handle_at(
            &mut table,
            &mut stats,
            AT_FDCWD,
            5,
            &info,
            AT_SYMLINK_FOLLOW,
        )
        .unwrap();
        assert_eq!(handle.inode, 77);
    }

    #[test]
    fn name_to_handle_with_empty_path() {
        let mut table = HandleTable::new();
        let mut stats = HandleStats::new();
        let info = sample_path_info(88);

        let handle =
            sys_name_to_handle_at(&mut table, &mut stats, 3, 1, &info, AT_EMPTY_PATH).unwrap();
        assert_eq!(handle.inode, 88);
    }

    // --- sys_open_by_handle_at ---

    #[test]
    fn open_by_handle_success() {
        let mut table = HandleTable::new();
        let mut stats = HandleStats::new();
        let info = sample_path_info(42);

        let handle = sys_name_to_handle_at(&mut table, &mut stats, AT_FDCWD, 10, &info, 0).unwrap();
        let handle_gen = handle.generation;

        let fd = sys_open_by_handle_at(
            &table,
            &mut stats,
            AT_FDCWD,
            MountId::new(1),
            42,
            handle_gen,
            0,
            true,
        )
        .unwrap();

        assert!(fd >= 3);
        assert_eq!(stats.open_by_handle_calls, 1);
        assert_eq!(stats.handles_opened, 1);
    }

    #[test]
    fn open_by_handle_no_cap() {
        let table = HandleTable::new();
        let mut stats = HandleStats::new();

        let result = sys_open_by_handle_at(
            &table,
            &mut stats,
            AT_FDCWD,
            MountId::new(1),
            42,
            1,
            0,
            false, // no capability
        );
        assert_eq!(result, Err(Error::PermissionDenied));
    }

    #[test]
    fn open_by_handle_not_found() {
        let table = HandleTable::new();
        let mut stats = HandleStats::new();

        let result = sys_open_by_handle_at(
            &table,
            &mut stats,
            AT_FDCWD,
            MountId::new(1),
            999,
            1,
            0,
            true,
        );
        assert_eq!(result, Err(Error::NotFound));
    }

    #[test]
    fn open_by_handle_stale_generation() {
        let mut table = HandleTable::new();
        let mut stats = HandleStats::new();
        let info = sample_path_info(42);

        let handle = sys_name_to_handle_at(&mut table, &mut stats, AT_FDCWD, 10, &info, 0).unwrap();
        let _handle_gen = handle.generation;

        // Use wrong generation.
        let result = sys_open_by_handle_at(
            &table,
            &mut stats,
            AT_FDCWD,
            MountId::new(1),
            42,
            0xBAD,
            0,
            true,
        );
        assert_eq!(result, Err(Error::IoError));
        assert_eq!(stats.stale_handle_errors, 1);
    }

    #[test]
    fn open_by_handle_bad_mount_fd() {
        let table = HandleTable::new();
        let mut stats = HandleStats::new();

        let result = sys_open_by_handle_at(
            &table,
            &mut stats,
            -5, // bad dirfd
            MountId::new(1),
            42,
            1,
            0,
            true,
        );
        assert_eq!(result, Err(Error::InvalidArgument));
    }

    // --- validate_and_open_handle ---

    #[test]
    fn validate_and_open_roundtrip() {
        let mut table = HandleTable::new();
        let mut stats = HandleStats::new();
        let info = sample_path_info(200);

        let handle = sys_name_to_handle_at(&mut table, &mut stats, AT_FDCWD, 4, &info, 0).unwrap();

        let fd = validate_and_open_handle(
            &table,
            &mut stats,
            AT_FDCWD,
            MountId::new(1),
            &handle.handle_bytes,
            0,
            true,
        )
        .unwrap();
        assert!(fd >= 3);
    }

    #[test]
    fn validate_and_open_bad_bytes() {
        let table = HandleTable::new();
        let mut stats = HandleStats::new();
        let bad_bytes = HandleBytes::from_slice(&[1, 2]).unwrap();

        let result = validate_and_open_handle(
            &table,
            &mut stats,
            AT_FDCWD,
            MountId::new(1),
            &bad_bytes,
            0,
            true,
        );
        assert_eq!(result, Err(Error::InvalidArgument));
    }

    // --- resolve_and_create_handle ---

    #[test]
    fn resolve_and_create_works() {
        let mut table = HandleTable::new();
        let mut stats = HandleStats::new();
        let info = sample_path_info(500);

        let handle =
            resolve_and_create_handle(&mut table, &mut stats, AT_FDCWD, 8, &info, 0).unwrap();
        assert_eq!(handle.inode, 500);
        assert_eq!(table.count(), 1);
    }

    // --- FileHandle ---

    #[test]
    fn file_handle_matches() {
        let h = FileHandle::new(MountId::new(5), HandleType::Directory, 100, 3);
        assert!(h.matches(MountId::new(5), 100));
        assert!(!h.matches(MountId::new(5), 200));
        assert!(!h.matches(MountId::new(6), 100));
    }

    #[test]
    fn file_handle_generation_matches() {
        let h = FileHandle::new(MountId::new(1), HandleType::File, 10, 7);
        assert!(h.generation_matches(7));
        assert!(!h.generation_matches(8));
    }

    // --- Multiple handles ---

    #[test]
    fn multiple_handles_independent() {
        let mut table = HandleTable::new();
        let mut stats = HandleStats::new();

        let info1 = sample_path_info(100);
        let info2 = PathInfo {
            mount_id: MountId::new(2),
            inode: 200,
            handle_type: HandleType::Directory,
            generation: 10,
        };

        let h1 = sys_name_to_handle_at(&mut table, &mut stats, AT_FDCWD, 5, &info1, 0).unwrap();
        let h2 = sys_name_to_handle_at(&mut table, &mut stats, AT_FDCWD, 3, &info2, 0).unwrap();

        assert_ne!(h1.inode, h2.inode);
        assert_ne!(h1.mount_id, h2.mount_id);
        assert_eq!(table.count(), 2);
        assert_eq!(stats.handles_created, 2);
    }

    // --- HandleStats ---

    #[test]
    fn stats_accumulate() {
        let mut table = HandleTable::new();
        let mut stats = HandleStats::new();
        let info = sample_path_info(42);

        for _ in 0..5 {
            let _ = sys_name_to_handle_at(&mut table, &mut stats, AT_FDCWD, 10, &info, 0);
        }
        assert_eq!(stats.name_to_handle_calls, 5);
    }
}
