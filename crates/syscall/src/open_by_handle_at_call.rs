// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `open_by_handle_at` syscall implementation.
//!
//! Opens a file identified by an opaque file handle previously obtained
//! from `name_to_handle_at`. Requires `CAP_DAC_READ_SEARCH` capability.
//! Used by NFS servers and privileged daemons to reopen files by handle.
//!
//! Linux-specific. Not in POSIX.

use oncrix_lib::{Error, Result};

/// Maximum file handle payload size in bytes.
pub const FILE_HANDLE_MAX_SIZE: usize = 128;

/// O_RDONLY open flag.
pub const O_RDONLY: i32 = 0;
/// O_WRONLY open flag.
pub const O_WRONLY: i32 = 1;
/// O_RDWR open flag.
pub const O_RDWR: i32 = 2;
/// O_CLOEXEC flag: close-on-exec.
pub const O_CLOEXEC: i32 = 0o2000000;
/// O_PATH flag: open path-only descriptor.
pub const O_PATH: i32 = 0o10000000;

/// File handle structure as received from user space.
///
/// Must have been populated by a prior `name_to_handle_at` call.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileHandle {
    /// Payload size in bytes.
    pub handle_bytes: u32,
    /// Filesystem-specific handle type.
    pub handle_type: i32,
    /// Opaque handle payload.
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

    /// Return the active payload slice.
    pub fn payload(&self) -> &[u8] {
        let len = (self.handle_bytes as usize).min(FILE_HANDLE_MAX_SIZE);
        &self.f_handle[..len]
    }

    /// Validate that handle_bytes fits in the allocated array.
    pub fn is_valid(&self) -> bool {
        self.handle_bytes > 0 && (self.handle_bytes as usize) <= FILE_HANDLE_MAX_SIZE
    }
}

impl Default for FileHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// Arguments for the `open_by_handle_at` syscall.
#[derive(Debug)]
pub struct OpenByHandleAtArgs {
    /// Mount fd: must be open on the filesystem containing the target file.
    pub mount_fd: i32,
    /// Pointer to user-space `FileHandle`.
    pub handle_ptr: usize,
    /// Open flags (O_RDONLY, O_RDWR, O_CLOEXEC, etc.).
    pub flags: i32,
}

/// Validated open_by_handle_at request.
pub struct OpenByHandleAtRequest {
    /// Mount fd.
    pub mount_fd: i32,
    /// Pointer to handle in user space.
    pub handle_ptr: usize,
    /// Access mode (O_RDONLY / O_WRONLY / O_RDWR).
    pub access_mode: i32,
    /// Full open flags.
    pub flags: i32,
    /// Whether O_CLOEXEC is set.
    pub cloexec: bool,
    /// Whether O_PATH is set.
    pub path_only: bool,
}

/// Validate `open_by_handle_at` arguments.
pub fn validate_open_by_handle_at_args(args: &OpenByHandleAtArgs) -> Result<OpenByHandleAtRequest> {
    if args.mount_fd < 0 {
        return Err(Error::InvalidArgument);
    }
    if args.handle_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let access_mode = args.flags & 0o3;
    if access_mode > O_RDWR {
        return Err(Error::InvalidArgument);
    }
    Ok(OpenByHandleAtRequest {
        mount_fd: args.mount_fd,
        handle_ptr: args.handle_ptr,
        access_mode,
        flags: args.flags,
        cloexec: (args.flags & O_CLOEXEC) != 0,
        path_only: (args.flags & O_PATH) != 0,
    })
}

/// Check that the caller has `CAP_DAC_READ_SEARCH`.
///
/// `open_by_handle_at` is a privileged operation restricted to processes
/// with this capability.
pub fn check_dac_read_search_cap() -> Result<()> {
    // Stub: real check queries current task's effective capability set.
    Err(Error::PermissionDenied)
}

/// Handle the `open_by_handle_at` syscall.
///
/// Opens the file identified by `handle_ptr` on the filesystem mounted
/// at `mount_fd`. The caller must hold `CAP_DAC_READ_SEARCH`.
///
/// Returns a non-negative file descriptor on success, or an error.
pub fn sys_open_by_handle_at(args: &OpenByHandleAtArgs) -> Result<i64> {
    let req = validate_open_by_handle_at_args(args)?;
    check_dac_read_search_cap()?;
    // Stub: real implementation would:
    // 1. Resolve mount_fd to a vfsmount.
    // 2. copy_from_user the FileHandle.
    // 3. Validate handle_bytes <= FILE_HANDLE_MAX_SIZE.
    // 4. Call exportfs_decode_fh to look up the dentry.
    // 5. Open the dentry with the requested flags.
    // 6. Allocate fd, install file, return fd.
    let _ = req;
    Err(Error::NotImplemented)
}

/// Convert an access mode value to a human-readable string.
pub fn access_mode_str(flags: i32) -> &'static str {
    match flags & 0o3 {
        0 => "read-only",
        1 => "write-only",
        2 => "read-write",
        _ => "unknown",
    }
}

/// Decode the mount ID from a mount fd for validation purposes.
///
/// The mount ID must match the one returned by the prior `name_to_handle_at`.
pub fn mount_fd_to_id(mount_fd: i32) -> Result<u64> {
    if mount_fd < 0 {
        return Err(Error::InvalidArgument);
    }
    // Stub: real lookup queries the file table and vfsmount.
    Err(Error::NotImplemented)
}
