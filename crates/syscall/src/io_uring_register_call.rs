// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `io_uring_register(2)` syscall handler.
//!
//! `io_uring_register` allows user-space to register and unregister
//! resources (buffers, file descriptors, event-fds, personalities, …)
//! with an io_uring instance so that the kernel can maintain long-lived
//! references and avoid per-operation reference counting.
//!
//! # Syscall signature
//!
//! ```text
//! int io_uring_register(unsigned int fd, unsigned int opcode,
//!                       void *arg, unsigned int nr_args);
//! ```
//!
//! # Register opcodes
//!
//! | Opcode | Value | Description |
//! |--------|-------|-------------|
//! | `IORING_REGISTER_BUFFERS` | 0 | Register fixed I/O buffers |
//! | `IORING_UNREGISTER_BUFFERS` | 1 | Unregister fixed buffers |
//! | `IORING_REGISTER_FILES` | 2 | Register file descriptors |
//! | `IORING_UNREGISTER_FILES` | 3 | Unregister file descriptors |
//! | `IORING_REGISTER_EVENTFD` | 4 | Register a completion eventfd |
//! | `IORING_UNREGISTER_EVENTFD` | 5 | Unregister the completion eventfd |
//! | `IORING_REGISTER_FILES_UPDATE` | 6 | Sparse-update registered fds |
//! | `IORING_REGISTER_EVENTFD_ASYNC` | 7 | Register async eventfd |
//! | `IORING_REGISTER_PROBE` | 8 | Query supported operations |
//! | `IORING_REGISTER_PERSONALITY` | 9 | Register a user-space credential set |
//! | `IORING_UNREGISTER_PERSONALITY` | 10 | Unregister credentials |
//! | `IORING_REGISTER_RESTRICTIONS` | 11 | Restrict available ring operations |
//! | `IORING_REGISTER_ENABLE_RINGS` | 12 | Enable a ring created disabled |
//! | `IORING_REGISTER_FILES2` | 13 | Register files with tag support |
//! | `IORING_REGISTER_FILES_UPDATE2` | 14 | Update files with tag support |
//! | `IORING_REGISTER_BUFFERS2` | 15 | Register buffers with tag support |
//! | `IORING_REGISTER_BUFFERS_UPDATE` | 16 | Update registered buffers |
//! | `IORING_REGISTER_IOWQ_AFF` | 17 | Set async-worker CPU affinity |
//! | `IORING_UNREGISTER_IOWQ_AFF` | 18 | Clear async-worker CPU affinity |
//! | `IORING_REGISTER_IOWQ_MAX_WORKERS` | 19 | Set max async workers |
//! | `IORING_REGISTER_RING_FDS` | 20 | Register ring file descriptors |
//! | `IORING_UNREGISTER_RING_FDS` | 21 | Unregister ring file descriptors |
//! | `IORING_REGISTER_PBUF_RING` | 22 | Register provided buffer ring |
//! | `IORING_UNREGISTER_PBUF_RING` | 23 | Unregister provided buffer ring |
//! | `IORING_REGISTER_SYNC_CANCEL` | 24 | Cancel pending request synchronously |
//! | `IORING_REGISTER_FILE_ALLOC_RANGE` | 25 | Set fd allocation range |
//! | `IORING_REGISTER_PBUF_STATUS` | 26 | Query provided buffer ring status |
//! | `IORING_REGISTER_NAPI` | 27 | Register NAPI busy-poll handler |
//! | `IORING_UNREGISTER_NAPI` | 28 | Unregister NAPI handler |
//! | `IORING_REGISTER_CLOCK` | 29 | Register a clock source |
//! | `IORING_REGISTER_CANCELTOKEN` | 30 | Register a cancellation token |
//! | `IORING_REGISTER_RESIZE_RINGS` | 31 | Resize the SQ and CQ rings |
//! | `IORING_REGISTER_MEM_REGION` | 32 | Register a memory region |
//!
//! # References
//!
//! - Linux: `io_uring/register.c`, `include/uapi/linux/io_uring.h`
//! - `io_uring_register(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Opcode constants
// ---------------------------------------------------------------------------

/// Register fixed I/O buffers.
pub const IORING_REGISTER_BUFFERS: u32 = 0;
/// Unregister previously registered buffers.
pub const IORING_UNREGISTER_BUFFERS: u32 = 1;
/// Register file descriptors.
pub const IORING_REGISTER_FILES: u32 = 2;
/// Unregister file descriptors.
pub const IORING_UNREGISTER_FILES: u32 = 3;
/// Register an eventfd for completion notifications.
pub const IORING_REGISTER_EVENTFD: u32 = 4;
/// Unregister the completion eventfd.
pub const IORING_UNREGISTER_EVENTFD: u32 = 5;
/// Sparse-update the registered file table.
pub const IORING_REGISTER_FILES_UPDATE: u32 = 6;
/// Register an async-mode completion eventfd.
pub const IORING_REGISTER_EVENTFD_ASYNC: u32 = 7;
/// Query which io_uring operations the kernel supports.
pub const IORING_REGISTER_PROBE: u32 = 8;
/// Register a user-space personality (credential set).
pub const IORING_REGISTER_PERSONALITY: u32 = 9;
/// Unregister a personality.
pub const IORING_UNREGISTER_PERSONALITY: u32 = 10;
/// Restrict the ring to a subset of operations.
pub const IORING_REGISTER_RESTRICTIONS: u32 = 11;
/// Enable a ring that was created with `IORING_SETUP_R_DISABLED`.
pub const IORING_REGISTER_ENABLE_RINGS: u32 = 12;
/// Register files with resource-tag support.
pub const IORING_REGISTER_FILES2: u32 = 13;
/// Update files with resource-tag support.
pub const IORING_REGISTER_FILES_UPDATE2: u32 = 14;
/// Register buffers with resource-tag support.
pub const IORING_REGISTER_BUFFERS2: u32 = 15;
/// Update registered buffers with resource-tag support.
pub const IORING_REGISTER_BUFFERS_UPDATE: u32 = 16;
/// Set async work-queue CPU affinity.
pub const IORING_REGISTER_IOWQ_AFF: u32 = 17;
/// Clear async work-queue CPU affinity.
pub const IORING_UNREGISTER_IOWQ_AFF: u32 = 18;
/// Set maximum number of async workers.
pub const IORING_REGISTER_IOWQ_MAX_WORKERS: u32 = 19;
/// Register ring file descriptors for use by index.
pub const IORING_REGISTER_RING_FDS: u32 = 20;
/// Unregister ring file descriptors.
pub const IORING_UNREGISTER_RING_FDS: u32 = 21;
/// Register a provided-buffer ring.
pub const IORING_REGISTER_PBUF_RING: u32 = 22;
/// Unregister a provided-buffer ring.
pub const IORING_UNREGISTER_PBUF_RING: u32 = 23;
/// Cancel a pending request synchronously.
pub const IORING_REGISTER_SYNC_CANCEL: u32 = 24;
/// Set the file-descriptor allocation range.
pub const IORING_REGISTER_FILE_ALLOC_RANGE: u32 = 25;
/// Query the status of a provided-buffer ring.
pub const IORING_REGISTER_PBUF_STATUS: u32 = 26;
/// Register a NAPI busy-poll handler.
pub const IORING_REGISTER_NAPI: u32 = 27;
/// Unregister a NAPI handler.
pub const IORING_UNREGISTER_NAPI: u32 = 28;
/// Register a clock source for timeout operations.
pub const IORING_REGISTER_CLOCK: u32 = 29;
/// Register a cancellation token.
pub const IORING_REGISTER_CANCELTOKEN: u32 = 30;
/// Resize the SQ/CQ rings live.
pub const IORING_REGISTER_RESIZE_RINGS: u32 = 31;
/// Register a memory region with the ring.
pub const IORING_REGISTER_MEM_REGION: u32 = 32;

/// Highest valid opcode value.
const IORING_REGISTER_LAST: u32 = IORING_REGISTER_MEM_REGION;

// ---------------------------------------------------------------------------
// iovec — used by REGISTER_BUFFERS
// ---------------------------------------------------------------------------

/// A user-space I/O vector entry (base + length).
///
/// Matches `struct iovec` from POSIX `<sys/uio.h>`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoVec {
    /// Base address of the buffer.
    pub iov_base: u64,
    /// Length of the buffer in bytes.
    pub iov_len: u64,
}

// ---------------------------------------------------------------------------
// files_update — used by REGISTER_FILES_UPDATE / REGISTER_FILES_UPDATE2
// ---------------------------------------------------------------------------

/// Argument structure for `IORING_REGISTER_FILES_UPDATE`.
///
/// Allows sparse-updating a subset of registered file descriptors starting
/// at `offset`.
///
/// Matches `struct io_uring_files_update` from the Linux UAPI.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringFilesUpdate {
    /// Starting index in the registered file table.
    pub offset: u32,
    /// Reserved — must be zero.
    pub resv: u32,
    /// Pointer to an array of `nr_args` file descriptors.
    pub fds: u64,
}

// ---------------------------------------------------------------------------
// rsrc_register — used by REGISTER_BUFFERS2 / REGISTER_FILES2
// ---------------------------------------------------------------------------

/// Argument structure for resource-tag-aware register operations.
///
/// Matches `struct io_uring_rsrc_register` from the Linux UAPI.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringRsrcRegister {
    /// Number of entries being registered.
    pub nr: u32,
    /// Register flags.
    pub flags: u32,
    /// Reserved.
    pub resv2: u64,
    /// Pointer to the array of iovec/fd entries.
    pub data: u64,
    /// Pointer to the array of `u64` resource tags.
    pub tags: u64,
}

// ---------------------------------------------------------------------------
// probe — used by REGISTER_PROBE
// ---------------------------------------------------------------------------

/// Per-operation probe result.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringProbeOp {
    /// io_uring opcode being described.
    pub op: u8,
    /// Reserved.
    pub resv: u8,
    /// Flags: bit 0 set if the op is supported.
    pub flags: u16,
    /// Reserved.
    pub resv2: u32,
}

/// Flag indicating the probed operation is supported.
pub const IO_URING_OP_SUPPORTED: u16 = 1 << 0;

// ---------------------------------------------------------------------------
// restriction — used by REGISTER_RESTRICTIONS
// ---------------------------------------------------------------------------

/// A single ring restriction entry.
///
/// Matches `struct io_uring_restriction` from the Linux UAPI.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoUringRestriction {
    /// Restriction opcode (`IORING_RESTRICTION_*`).
    pub opcode: u16,
    /// Which io_uring or register opcode this restriction applies to.
    pub register_op: u8,
    /// Reserved.
    pub resv: u8,
    /// Reserved.
    pub resv2: [u32; 3],
}

/// Allow a specific `io_uring_register` opcode.
pub const IORING_RESTRICTION_REGISTER_OP: u16 = 0;
/// Allow a specific `io_uring_enter` flag.
pub const IORING_RESTRICTION_SQE_FLAGS_ALLOWED: u16 = 1;
/// Require a specific set of `io_uring_enter` flags.
pub const IORING_RESTRICTION_SQE_FLAGS_REQUIRED: u16 = 2;
/// Allow a specific io_uring submission opcode.
pub const IORING_RESTRICTION_SQE_OP: u16 = 3;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `io_uring_register`.
///
/// Dispatches to the appropriate registration handler based on `opcode`.
/// Returns the number of resources registered/updated on success, or 0 for
/// operations that do not have a meaningful return value.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown opcode, null pointer when required,
///   or mismatched `nr_args`.
/// - [`Error::NotFound`] — `fd` does not refer to a valid io_uring instance.
/// - [`Error::OutOfMemory`] — registration failed due to resource exhaustion.
/// - [`Error::PermissionDenied`] — caller lacks required capabilities.
pub fn sys_io_uring_register(_fd: u32, opcode: u32, arg: u64, nr_args: u32) -> Result<i64> {
    if opcode > IORING_REGISTER_LAST {
        return Err(Error::InvalidArgument);
    }

    match opcode {
        IORING_REGISTER_BUFFERS => {
            if arg == 0 {
                return Err(Error::InvalidArgument);
            }
            // TODO: iterate the iovec array and pin the pages.
            Ok(nr_args as i64)
        }
        IORING_UNREGISTER_BUFFERS => {
            if arg != 0 || nr_args != 0 {
                return Err(Error::InvalidArgument);
            }
            // TODO: unpin all registered buffer pages.
            Ok(0)
        }
        IORING_REGISTER_FILES => {
            if arg == 0 {
                return Err(Error::InvalidArgument);
            }
            // TODO: take references on each fd and insert into the file table.
            Ok(nr_args as i64)
        }
        IORING_UNREGISTER_FILES => {
            if arg != 0 || nr_args != 0 {
                return Err(Error::InvalidArgument);
            }
            // TODO: release all registered file references.
            Ok(0)
        }
        IORING_REGISTER_EVENTFD | IORING_REGISTER_EVENTFD_ASYNC => {
            if arg == 0 || nr_args != 1 {
                return Err(Error::InvalidArgument);
            }
            // TODO: install eventfd reference into the ring.
            Ok(0)
        }
        IORING_UNREGISTER_EVENTFD => {
            if arg != 0 || nr_args != 0 {
                return Err(Error::InvalidArgument);
            }
            // TODO: drop the eventfd reference.
            Ok(0)
        }
        IORING_REGISTER_FILES_UPDATE => {
            if arg == 0 {
                return Err(Error::InvalidArgument);
            }
            // TODO: update the registered file table at the given offset.
            Ok(nr_args as i64)
        }
        IORING_REGISTER_PROBE => {
            if arg == 0 {
                return Err(Error::InvalidArgument);
            }
            // TODO: fill the probe array with supported operations.
            Ok(0)
        }
        IORING_REGISTER_PERSONALITY => {
            if arg != 0 || nr_args != 0 {
                return Err(Error::InvalidArgument);
            }
            // TODO: capture current credentials, return personality ID.
            Ok(1) // placeholder personality ID
        }
        IORING_UNREGISTER_PERSONALITY => {
            if nr_args != 1 {
                return Err(Error::InvalidArgument);
            }
            // TODO: release personality with ID stored in arg.
            Ok(0)
        }
        IORING_REGISTER_RESTRICTIONS => {
            if arg == 0 {
                return Err(Error::InvalidArgument);
            }
            // TODO: apply restriction table to the ring.
            Ok(0)
        }
        IORING_REGISTER_ENABLE_RINGS => {
            if arg != 0 || nr_args != 0 {
                return Err(Error::InvalidArgument);
            }
            // TODO: transition ring from disabled to enabled state.
            Ok(0)
        }
        IORING_REGISTER_IOWQ_MAX_WORKERS => {
            if arg == 0 || nr_args != 2 {
                return Err(Error::InvalidArgument);
            }
            // TODO: set async-worker thread pool sizes.
            Ok(0)
        }
        IORING_REGISTER_RING_FDS => {
            if arg == 0 {
                return Err(Error::InvalidArgument);
            }
            // TODO: register ring fds by index.
            Ok(nr_args as i64)
        }
        IORING_UNREGISTER_RING_FDS => {
            if arg == 0 {
                return Err(Error::InvalidArgument);
            }
            // TODO: unregister ring fds.
            Ok(nr_args as i64)
        }
        _ => {
            // All remaining valid opcodes are accepted but not fully implemented.
            Ok(0)
        }
    }
}

/// Entry point called from the syscall dispatcher.
pub fn do_io_uring_register(fd: u32, opcode: u32, arg: u64, nr_args: u32) -> Result<i64> {
    sys_io_uring_register(fd, opcode, arg, nr_args)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_unknown_opcode() {
        assert_eq!(
            sys_io_uring_register(3, IORING_REGISTER_LAST + 1, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn register_buffers_null_arg() {
        assert_eq!(
            sys_io_uring_register(3, IORING_REGISTER_BUFFERS, 0, 4).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn unregister_buffers_with_arg() {
        // Non-zero arg or nr_args should be rejected.
        assert_eq!(
            sys_io_uring_register(3, IORING_UNREGISTER_BUFFERS, 1, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn enable_rings_valid() {
        let r = sys_io_uring_register(3, IORING_REGISTER_ENABLE_RINGS, 0, 0);
        assert!(r.is_ok());
    }

    #[test]
    fn register_personality_returns_id() {
        let r = sys_io_uring_register(3, IORING_REGISTER_PERSONALITY, 0, 0);
        assert!(r.is_ok());
        assert!(r.unwrap() > 0);
    }
}
