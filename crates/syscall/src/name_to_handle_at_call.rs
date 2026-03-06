// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `name_to_handle_at` syscall implementation.
//!
//! Converts a pathname to a persistent file handle that can be passed to
//! `open_by_handle_at`. The handle is opaque and filesystem-specific;
//! it survives close/open cycles and is used by NFS servers and other
//! file-serving daemons.
//!
//! Linux-specific. Not in POSIX.

use oncrix_lib::{Error, Result};

/// Maximum file handle payload size in bytes.
pub const FILE_HANDLE_MAX_SIZE: usize = 128;

/// AT_FDCWD: use the current working directory as the directory fd.
pub const AT_FDCWD: i32 = -100;

/// Flag: do not follow symbolic links.
pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;

/// Flag: handle is relative to the empty path (fd refers to the file itself).
pub const AT_EMPTY_PATH: i32 = 0x1000;

/// File handle as passed between user space and the kernel.
///
/// `handle_bytes` on entry is the buffer size; on return it holds the
/// actual size needed. If it was too small, the kernel returns EOVERFLOW.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileHandle {
    /// Buffer size (in) / required size (out).
    pub handle_bytes: u32,
    /// Filesystem-specific handle type identifier.
    pub handle_type: i32,
    /// Opaque handle data.
    pub f_handle: [u8; FILE_HANDLE_MAX_SIZE],
}

impl FileHandle {
    /// Create an empty file handle.
    pub fn new() -> Self {
        Self {
            handle_bytes: 0,
            handle_type: 0,
            f_handle: [0u8; FILE_HANDLE_MAX_SIZE],
        }
    }

    /// Return the populated payload slice.
    pub fn payload(&self) -> &[u8] {
        let len = (self.handle_bytes as usize).min(FILE_HANDLE_MAX_SIZE);
        &self.f_handle[..len]
    }

    /// Check whether the handle carries valid data.
    pub fn is_populated(&self) -> bool {
        self.handle_bytes > 0 && (self.handle_bytes as usize) <= FILE_HANDLE_MAX_SIZE
    }
}

impl Default for FileHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// Arguments for the `name_to_handle_at` syscall.
#[derive(Debug)]
pub struct NameToHandleAtArgs {
    /// Directory fd (AT_FDCWD or open directory).
    pub dirfd: i32,
    /// Pointer to null-terminated pathname in user space.
    pub pathname_ptr: usize,
    /// Pointer to user-space `FileHandle`.
    pub handle_ptr: usize,
    /// Pointer to user-space `i32` to receive the mount ID.
    pub mount_id_ptr: usize,
    /// Flags (AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH).
    pub flags: i32,
}

/// Validate `name_to_handle_at` arguments.
pub fn validate_name_to_handle_at_args(args: &NameToHandleAtArgs) -> Result<()> {
    if args.handle_ptr == 0 || args.mount_id_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if args.pathname_ptr == 0 && (args.flags & AT_EMPTY_PATH) == 0 {
        return Err(Error::InvalidArgument);
    }
    let known_flags = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;
    if args.flags & !known_flags != 0 {
        return Err(Error::InvalidArgument);
    }
    if args.dirfd != AT_FDCWD && args.dirfd < 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Handle the `name_to_handle_at` syscall.
///
/// Looks up the file at `dirfd`/`pathname` and writes the opaque file
/// handle to `handle_ptr` and the mount ID to `mount_id_ptr`.
///
/// If the user-supplied buffer is too small, the kernel writes the
/// required size and returns EOVERFLOW.
///
/// Returns 0 on success, or an error.
pub fn sys_name_to_handle_at(args: &NameToHandleAtArgs) -> Result<i64> {
    validate_name_to_handle_at_args(args)?;
    // Stub: real implementation would:
    // 1. Resolve pathname relative to dirfd (following or not following symlinks).
    // 2. copy_from_user the handle header to read the user buffer size.
    // 3. Call exportfs_encode_fh to fill the handle payload.
    // 4. If payload > user buffer: copy required size, return EOVERFLOW.
    // 5. copy_to_user the full handle.
    // 6. copy_to_user the mount ID.
    Err(Error::NotImplemented)
}

/// Encode an inode-based file handle (inode + generation = 12 bytes).
pub fn encode_inode_handle(ino: u64, generation: u32) -> [u8; 12] {
    let mut buf = [0u8; 12];
    buf[..8].copy_from_slice(&ino.to_le_bytes());
    buf[8..12].copy_from_slice(&generation.to_le_bytes());
    buf
}

/// Decode an inode-based file handle produced by `encode_inode_handle`.
///
/// Returns `(inode_number, generation)` or `Err(InvalidArgument)` if
/// the payload is too short.
pub fn decode_inode_handle(payload: &[u8]) -> Result<(u64, u32)> {
    if payload.len() < 12 {
        return Err(Error::InvalidArgument);
    }
    let ino = u64::from_le_bytes(
        payload[..8]
            .try_into()
            .map_err(|_| Error::InvalidArgument)?,
    );
    let generation = u32::from_le_bytes(
        payload[8..12]
            .try_into()
            .map_err(|_| Error::InvalidArgument)?,
    );
    Ok((ino, generation))
}
