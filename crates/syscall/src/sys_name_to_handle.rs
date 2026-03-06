// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `name_to_handle_at(2)` syscall handler — convert pathname to file handle.
//!
//! `name_to_handle_at` translates a pathname into a filesystem-specific,
//! persistent file handle that can later be used with `open_by_handle_at` to
//! re-open the file without repeating a full path lookup.  The primary use
//! case is NFS-style stateless servers and checkpoint-restore tools.
//!
//! # Syscall signature
//!
//! ```text
//! int name_to_handle_at(int dirfd, const char *pathname,
//!                       struct file_handle *handle,
//!                       int *mount_id, int flags);
//! ```
//!
//! # Handle negotiation
//!
//! The kernel writes the actual handle size into `handle->handle_bytes`.  If
//! the caller-supplied buffer is too small, the syscall returns `EOVERFLOW`
//! (mapped to `Error::InvalidArgument` here) but still writes the required
//! size so the caller can retry with a larger buffer.
//!
//! # Flags
//!
//! | Flag | Value | Effect |
//! |------|-------|--------|
//! | `AT_EMPTY_PATH` | 0x1000 | Allow empty pathname (operate on dirfd itself) |
//! | `AT_SYMLINK_FOLLOW` | 0x400 | Follow symlinks (default is to not follow) |
//!
//! # POSIX conformance
//!
//! `name_to_handle_at` is a Linux extension (since Linux 2.6.39).  It is not
//! part of POSIX.1-2024.  The inode / generation number semantics align with
//! POSIX filesystem semantics described in `<sys/stat.h>`.
//!
//! # References
//!
//! - Linux: `fs/fhandle.c`
//! - `name_to_handle_at(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flag constants
// ---------------------------------------------------------------------------

/// Allow `pathname` to be empty; operate on `dirfd` itself.
pub const AT_EMPTY_PATH: u32 = 0x1000;

/// Follow symbolic links when resolving `pathname`.
pub const AT_SYMLINK_FOLLOW: u32 = 0x0400;

/// Valid flag bits for `name_to_handle_at`.
const FLAGS_MASK: u32 = AT_EMPTY_PATH | AT_SYMLINK_FOLLOW;

// ---------------------------------------------------------------------------
// Handle parameters
// ---------------------------------------------------------------------------

/// Maximum bytes a file handle can carry.
pub const MAX_HANDLE_BYTES: usize = 128;

/// Handle type for a synthetic inode-based filesystem handle.
pub const FILEID_INO32_GEN: u32 = 1;

/// Handle type indicating an invalid / unknown filesystem.
pub const FILEID_INVALID: u32 = 0xFF;

// ---------------------------------------------------------------------------
// FileHandle — the kernel's file_handle structure
// ---------------------------------------------------------------------------

/// Kernel file handle produced by `name_to_handle_at`.
///
/// Encodes the inode number and a generation counter so that stale handles
/// (where the inode has been recycled) can be detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileHandle {
    /// Actual number of bytes stored in `bytes`.
    pub handle_bytes: u32,
    /// Filesystem-specific handle type.
    pub handle_type: u32,
    /// Opaque handle payload (inode number + generation counter).
    pub bytes: [u8; MAX_HANDLE_BYTES],
}

impl FileHandle {
    /// Construct a handle from inode number and generation counter.
    ///
    /// The generation counter is stored at bytes 8–11 of the payload.
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

    /// Decode the inode number from the handle payload.
    pub fn inode(&self) -> Option<u64> {
        if self.handle_bytes < 8 {
            return None;
        }
        let arr: [u8; 8] = self.bytes[..8].try_into().ok()?;
        Some(u64::from_le_bytes(arr))
    }

    /// Decode the generation counter from the handle payload.
    pub fn generation(&self) -> Option<u32> {
        if self.handle_bytes < 12 {
            return None;
        }
        let arr: [u8; 4] = self.bytes[8..12].try_into().ok()?;
        Some(u32::from_le_bytes(arr))
    }
}

impl Default for FileHandle {
    fn default() -> Self {
        Self {
            handle_bytes: 0,
            handle_type: FILEID_INVALID,
            bytes: [0u8; MAX_HANDLE_BYTES],
        }
    }
}

// ---------------------------------------------------------------------------
// FsEntry — simulated filesystem inode table entry
// ---------------------------------------------------------------------------

/// Maximum number of inodes the simulated filesystem tracks.
const MAX_INODES: usize = 256;

/// A single entry in the simulated inode table.
#[derive(Debug, Clone, Copy)]
pub struct FsEntry {
    /// Inode number.
    pub ino: u64,
    /// Generation counter (incremented on inode re-use).
    pub generation: u32,
    /// Mount ID of the containing filesystem.
    pub mount_id: i32,
    /// Whether this slot is occupied.
    pub active: bool,
    /// Whether this entry is a symbolic link.
    pub is_symlink: bool,
}

impl FsEntry {
    const fn empty() -> Self {
        Self {
            ino: 0,
            generation: 0,
            mount_id: 0,
            active: false,
            is_symlink: false,
        }
    }
}

impl Default for FsEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// ---------------------------------------------------------------------------
// NameToHandleContext — subsystem state
// ---------------------------------------------------------------------------

/// State for the `name_to_handle_at` subsystem.
pub struct NameToHandleContext {
    inodes: [FsEntry; MAX_INODES],
    inode_count: usize,
    /// Required handle size in bytes (written on EOVERFLOW so caller can retry).
    pub required_size: u32,
}

impl NameToHandleContext {
    /// Construct an empty context.
    pub const fn new() -> Self {
        Self {
            inodes: [const { FsEntry::empty() }; MAX_INODES],
            inode_count: 0,
            required_size: 12,
        }
    }

    /// Register an inode entry.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfMemory`] — inode table is full.
    pub fn register_inode(&mut self, entry: FsEntry) -> Result<()> {
        let slot = self
            .inodes
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;
        self.inodes[slot] = entry;
        self.inodes[slot].active = true;
        self.inode_count += 1;
        Ok(())
    }

    /// Look up a registered inode by number.
    pub fn find_inode(&self, ino: u64) -> Option<&FsEntry> {
        self.inodes.iter().find(|e| e.active && e.ino == ino)
    }

    /// Resolve a simulated path token.
    ///
    /// In this stub the path is the decimal string representation of the
    /// inode number.  A real implementation would perform a full VFS lookup.
    fn resolve_path(&self, path: &str, flags: u32) -> Result<&FsEntry> {
        let ino: u64 = path.trim().parse().map_err(|_| Error::NotFound)?;
        let entry = self.find_inode(ino).ok_or(Error::NotFound)?;
        if entry.is_symlink && (flags & AT_SYMLINK_FOLLOW == 0) {
            // When symlink follow is not requested the symlink inode itself
            // is returned; a real kernel might return a different error here.
        }
        Ok(entry)
    }
}

impl Default for NameToHandleContext {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// sys_name_to_handle_handler — main entry point
// ---------------------------------------------------------------------------

/// Handle the `name_to_handle_at(2)` syscall.
///
/// Converts `pathname` to a [`FileHandle`] and writes the associated
/// mount identifier into the `mount_id` out parameter.
///
/// # Arguments
///
/// * `ctx`         — Subsystem state containing the inode table.
/// * `pathname`    — Path to resolve (stub: decimal inode number string).
/// * `user_buf_sz` — Bytes the caller allocated for the handle payload.
/// * `flags`       — `AT_EMPTY_PATH` and/or `AT_SYMLINK_FOLLOW`.
///
/// # Returns
///
/// `(FileHandle, mount_id)` on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Unknown flags or buffer too small (EOVERFLOW);
///   `ctx.required_size` is updated so the caller can retry.
/// * [`Error::NotFound`]        — Pathname could not be resolved.
pub fn sys_name_to_handle_handler(
    ctx: &mut NameToHandleContext,
    pathname: &str,
    user_buf_sz: u32,
    flags: u32,
) -> Result<(FileHandle, i32)> {
    // Validate flags — reject any unknown bits.
    if flags & !FLAGS_MASK != 0 {
        return Err(Error::InvalidArgument);
    }

    // Resolve the path to an inode entry.
    let entry = ctx.resolve_path(pathname, flags)?;
    let ino = entry.ino;
    let generation = entry.generation;
    let mount_id = entry.mount_id;

    // Handle size negotiation: if the user buffer is too small, update the
    // required_size field (caller reads it back) and return EOVERFLOW.
    let required = ctx.required_size;
    if user_buf_sz < required {
        ctx.required_size = required;
        return Err(Error::InvalidArgument); // EOVERFLOW
    }

    let handle = FileHandle::from_inode(ino, generation);
    Ok((handle, mount_id))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> NameToHandleContext {
        let mut ctx = NameToHandleContext::new();
        ctx.register_inode(FsEntry {
            ino: 42,
            generation: 7,
            mount_id: 3,
            active: true,
            is_symlink: false,
        })
        .unwrap();
        ctx
    }

    #[test]
    fn basic_lookup() {
        let mut ctx = setup();
        let (handle, mnt) = sys_name_to_handle_handler(&mut ctx, "42", 128, 0).unwrap();
        assert_eq!(mnt, 3);
        assert_eq!(handle.inode(), Some(42));
        assert_eq!(handle.generation(), Some(7));
    }

    #[test]
    fn buffer_too_small_returns_error() {
        let mut ctx = setup();
        let err = sys_name_to_handle_handler(&mut ctx, "42", 4, 0).unwrap_err();
        assert_eq!(err, Error::InvalidArgument);
        assert_eq!(ctx.required_size, 12); // required size preserved
    }

    #[test]
    fn unknown_flags_rejected() {
        let mut ctx = setup();
        assert_eq!(
            sys_name_to_handle_handler(&mut ctx, "42", 128, 0xFFFF),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn path_not_found() {
        let mut ctx = setup();
        assert_eq!(
            sys_name_to_handle_handler(&mut ctx, "9999", 128, 0),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn at_symlink_follow_flag_accepted() {
        let mut ctx = setup();
        let r = sys_name_to_handle_handler(&mut ctx, "42", 128, AT_SYMLINK_FOLLOW);
        assert!(r.is_ok());
    }

    #[test]
    fn at_empty_path_flag_accepted() {
        let mut ctx = setup();
        let r = sys_name_to_handle_handler(&mut ctx, "42", 128, AT_EMPTY_PATH);
        assert!(r.is_ok());
    }

    #[test]
    fn handle_inode_roundtrip() {
        let h = FileHandle::from_inode(12345, 99);
        assert_eq!(h.inode(), Some(12345));
        assert_eq!(h.generation(), Some(99));
        assert_eq!(h.handle_type, FILEID_INO32_GEN);
    }

    #[test]
    fn handle_default_invalid() {
        let h = FileHandle::default();
        assert_eq!(h.handle_type, FILEID_INVALID);
        assert_eq!(h.handle_bytes, 0);
    }

    #[test]
    fn multiple_inodes_different_mounts() {
        let mut ctx = NameToHandleContext::new();
        ctx.register_inode(FsEntry {
            ino: 1,
            generation: 0,
            mount_id: 10,
            active: true,
            is_symlink: false,
        })
        .unwrap();
        ctx.register_inode(FsEntry {
            ino: 2,
            generation: 0,
            mount_id: 20,
            active: true,
            is_symlink: false,
        })
        .unwrap();

        let (_, mnt1) = sys_name_to_handle_handler(&mut ctx, "1", 128, 0).unwrap();
        let (_, mnt2) = sys_name_to_handle_handler(&mut ctx, "2", 128, 0).unwrap();
        assert_eq!(mnt1, 10);
        assert_eq!(mnt2, 20);
    }
}
