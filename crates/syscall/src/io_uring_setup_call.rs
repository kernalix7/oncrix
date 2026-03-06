// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `io_uring_setup(2)` syscall handler.
//!
//! The `io_uring_setup` syscall creates a new io_uring instance and returns
//! a file descriptor through which the caller can submit and receive I/O
//! completions.  The ring parameters are communicated through a
//! [`IoUringParams`] structure that is both an input and an output.
//!
//! # Syscall signature
//!
//! ```text
//! int io_uring_setup(unsigned int entries, struct io_uring_params *params);
//! ```
//!
//! # Setup flags
//!
//! | Flag                            | Value  | Description                               |
//! |---------------------------------|--------|-------------------------------------------|
//! | `IORING_SETUP_IOPOLL`           | 1 << 0 | Busy-poll I/O completions                 |
//! | `IORING_SETUP_SQPOLL`           | 1 << 1 | Kernel SQ polling thread                  |
//! | `IORING_SETUP_SQ_AFF`           | 1 << 2 | Pin SQ thread to `sq_thread_cpu`          |
//! | `IORING_SETUP_CQSIZE`           | 1 << 3 | Override default CQ size                  |
//! | `IORING_SETUP_CLAMP`            | 1 << 4 | Clamp `entries` to system limits          |
//! | `IORING_SETUP_ATTACH_WQ`        | 1 << 5 | Share async work queue with `wq_fd`       |
//! | `IORING_SETUP_R_DISABLED`       | 1 << 6 | Start in disabled state                   |
//! | `IORING_SETUP_SUBMIT_ALL`       | 1 << 7 | Continue submitting on error              |
//! | `IORING_SETUP_COOP_TASKRUN`     | 1 << 8 | Cooperative task-level completion run     |
//! | `IORING_SETUP_TASKRUN_FLAG`     | 1 << 9 | User-space cooperative completion flag    |
//! | `IORING_SETUP_SQE128`           | 1 << 10| Use 128-byte SQEs                         |
//! | `IORING_SETUP_CQE32`            | 1 << 11| Use 32-byte CQEs                          |
//! | `IORING_SETUP_SINGLE_ISSUER`    | 1 << 12| Only one submitter thread                 |
//! | `IORING_SETUP_DEFER_TASKRUN`    | 1 << 13| Defer task-level completion run           |
//! | `IORING_SETUP_NO_MMAP`          | 1 << 14| Don't mmap ring — caller provides buffers |
//! | `IORING_SETUP_REGISTERED_FD_ONLY` | 1 << 15| Return a registered fd index            |
//! | `IORING_SETUP_NO_SQARRAY`       | 1 << 16| Don't expose the SQ indirection array     |
//!
//! # References
//!
//! - Linux: `io_uring/io_uring.c`, `include/uapi/linux/io_uring.h`
//! - `io_uring_setup(2)` man page, liburing documentation

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Minimum number of SQ/CQ entries (must be a power of two).
pub const IORING_MIN_ENTRIES: u32 = 1;
/// Maximum number of SQ entries accepted by setup.
pub const IORING_MAX_ENTRIES: u32 = 32768;
/// Maximum number of CQ entries when `IORING_SETUP_CQSIZE` is used.
pub const IORING_MAX_CQ_ENTRIES: u32 = 65536;

// ---------------------------------------------------------------------------
// Setup flags
// ---------------------------------------------------------------------------

/// Busy-poll I/O completions (no IRQ).
pub const IORING_SETUP_IOPOLL: u32 = 1 << 0;
/// Spawn a kernel thread to poll the SQ ring.
pub const IORING_SETUP_SQPOLL: u32 = 1 << 1;
/// Bind the SQ poll thread to `sq_thread_cpu`.
pub const IORING_SETUP_SQ_AFF: u32 = 1 << 2;
/// Allow the caller to specify `cq_entries`.
pub const IORING_SETUP_CQSIZE: u32 = 1 << 3;
/// Clamp `entries` to the system-allowed maximum.
pub const IORING_SETUP_CLAMP: u32 = 1 << 4;
/// Attach to the work-queue of `wq_fd`.
pub const IORING_SETUP_ATTACH_WQ: u32 = 1 << 5;
/// Create the ring in a disabled state.
pub const IORING_SETUP_R_DISABLED: u32 = 1 << 6;
/// Continue submitting remaining SQEs after any error.
pub const IORING_SETUP_SUBMIT_ALL: u32 = 1 << 7;
/// Run completions cooperatively in the submitting task.
pub const IORING_SETUP_COOP_TASKRUN: u32 = 1 << 8;
/// Expose a user-space flag for cooperative task runs.
pub const IORING_SETUP_TASKRUN_FLAG: u32 = 1 << 9;
/// Use 128-byte SQEs (for NVMe passthrough etc.).
pub const IORING_SETUP_SQE128: u32 = 1 << 10;
/// Use 32-byte CQEs.
pub const IORING_SETUP_CQE32: u32 = 1 << 11;
/// Only one thread will submit requests.
pub const IORING_SETUP_SINGLE_ISSUER: u32 = 1 << 12;
/// Defer cooperative task-run until `io_uring_enter`.
pub const IORING_SETUP_DEFER_TASKRUN: u32 = 1 << 13;
/// Do not mmap the ring; caller supplies buffers.
pub const IORING_SETUP_NO_MMAP: u32 = 1 << 14;
/// Return a registered fd index rather than a real fd.
pub const IORING_SETUP_REGISTERED_FD_ONLY: u32 = 1 << 15;
/// Do not create the SQ indirection array.
pub const IORING_SETUP_NO_SQARRAY: u32 = 1 << 16;

/// All valid setup flag bits.
const IORING_SETUP_FLAGS_MASK: u32 = IORING_SETUP_IOPOLL
    | IORING_SETUP_SQPOLL
    | IORING_SETUP_SQ_AFF
    | IORING_SETUP_CQSIZE
    | IORING_SETUP_CLAMP
    | IORING_SETUP_ATTACH_WQ
    | IORING_SETUP_R_DISABLED
    | IORING_SETUP_SUBMIT_ALL
    | IORING_SETUP_COOP_TASKRUN
    | IORING_SETUP_TASKRUN_FLAG
    | IORING_SETUP_SQE128
    | IORING_SETUP_CQE32
    | IORING_SETUP_SINGLE_ISSUER
    | IORING_SETUP_DEFER_TASKRUN
    | IORING_SETUP_NO_MMAP
    | IORING_SETUP_REGISTERED_FD_ONLY
    | IORING_SETUP_NO_SQARRAY;

// ---------------------------------------------------------------------------
// Feature flags (output only)
// ---------------------------------------------------------------------------

/// Kernel supports single-mmap rings.
pub const IORING_FEAT_SINGLE_MMAP: u32 = 1 << 0;
/// Kernel supports non-fixed file operations.
pub const IORING_FEAT_NODROP: u32 = 1 << 1;
/// Kernel submits requests in stable order.
pub const IORING_FEAT_SUBMIT_STABLE: u32 = 1 << 2;
/// Kernel supports read/write with RWF flags.
pub const IORING_FEAT_RW_CUR_POS: u32 = 1 << 3;
/// Kernel supports current-user-cred operations.
pub const IORING_FEAT_CUR_PERSONALITY: u32 = 1 << 4;
/// Kernel supports fast-poll for non-blocking I/O.
pub const IORING_FEAT_FAST_POLL: u32 = 1 << 5;
/// Kernel supports 32-bit SQE buffer indices.
pub const IORING_FEAT_POLL_32BITS: u32 = 1 << 6;
/// Kernel supports SQPOLL CPU affinity.
pub const IORING_FEAT_SQPOLL_NONFIXED: u32 = 1 << 7;
/// Kernel supports `io_uring_enter` extended args.
pub const IORING_FEAT_EXT_ARG: u32 = 1 << 8;
/// Kernel supports native workers.
pub const IORING_FEAT_NATIVE_WORKERS: u32 = 1 << 9;
/// Kernel supports resource-tag API.
pub const IORING_FEAT_RSRC_TAGS: u32 = 1 << 10;
/// Kernel supports skipping non-retried CQE overflow.
pub const IORING_FEAT_CQE_SKIP: u32 = 1 << 11;
/// Kernel supports linked file operations.
pub const IORING_FEAT_LINKED_FILE: u32 = 1 << 12;
/// Kernel supports registered ring fd.
pub const IORING_FEAT_REG_REG_RING: u32 = 1 << 13;

// ---------------------------------------------------------------------------
// sq_off / cq_off field offsets
// ---------------------------------------------------------------------------

/// SQ ring field offsets written into `sq_off` by the kernel.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoSqringOffsets {
    /// Byte offset of the head pointer.
    pub head: u32,
    /// Byte offset of the tail pointer.
    pub tail: u32,
    /// Byte offset of the ring-size mask.
    pub ring_mask: u32,
    /// Byte offset of the ring-entry count.
    pub ring_entries: u32,
    /// Byte offset of the flags field.
    pub flags: u32,
    /// Byte offset of the dropped count.
    pub dropped: u32,
    /// Byte offset of the SQE indirection array.
    pub array: u32,
    /// Reserved.
    pub resv1: u32,
    /// Byte offset of the user-event-fd CQ wakeup descriptor.
    pub user_addr: u64,
}

/// CQ ring field offsets written into `cq_off` by the kernel.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoCqringOffsets {
    /// Byte offset of the head pointer.
    pub head: u32,
    /// Byte offset of the tail pointer.
    pub tail: u32,
    /// Byte offset of the ring-size mask.
    pub ring_mask: u32,
    /// Byte offset of the ring-entry count.
    pub ring_entries: u32,
    /// Byte offset of the overflow counter.
    pub overflow: u32,
    /// Byte offset of the CQE array.
    pub cqes: u32,
    /// Flags field offset.
    pub flags: u32,
    /// Reserved.
    pub resv1: u32,
    /// Byte offset of the user-event-fd CQ wakeup descriptor.
    pub user_addr: u64,
}

// ---------------------------------------------------------------------------
// io_uring_params
// ---------------------------------------------------------------------------

/// Parameters structure for `io_uring_setup`.
///
/// The caller fills in `flags`, `sq_thread_cpu`, `sq_thread_idle`, and
/// `cq_entries` (if `IORING_SETUP_CQSIZE` is set).  The kernel fills in the
/// remaining fields and the two offset structures before returning.
///
/// Matches `struct io_uring_params` from `include/uapi/linux/io_uring.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IoUringParams {
    /// Number of SQ ring entries (power of two, at least `entries`).
    pub sq_entries: u32,
    /// Number of CQ ring entries.
    pub cq_entries: u32,
    /// Setup flags (see `IORING_SETUP_*`).
    pub flags: u32,
    /// CPU index for the SQ polling thread.
    pub sq_thread_cpu: u32,
    /// Idle time in milliseconds before the SQ thread sleeps.
    pub sq_thread_idle: u32,
    /// Feature flags set by the kernel on return.
    pub features: u32,
    /// fd of the ring to share the async work-queue with.
    pub wq_fd: u32,
    /// Reserved — must be zero.
    pub resv: [u32; 3],
    /// SQ ring field offsets (filled by kernel).
    pub sq_off: IoSqringOffsets,
    /// CQ ring field offsets (filled by kernel).
    pub cq_off: IoCqringOffsets,
}

impl IoUringParams {
    /// Create a default-initialised params structure.
    pub const fn new() -> Self {
        Self {
            sq_entries: 0,
            cq_entries: 0,
            flags: 0,
            sq_thread_cpu: 0,
            sq_thread_idle: 0,
            features: 0,
            wq_fd: 0,
            resv: [0u32; 3],
            sq_off: IoSqringOffsets {
                head: 0,
                tail: 0,
                ring_mask: 0,
                ring_entries: 0,
                flags: 0,
                dropped: 0,
                array: 0,
                resv1: 0,
                user_addr: 0,
            },
            cq_off: IoCqringOffsets {
                head: 0,
                tail: 0,
                ring_mask: 0,
                ring_entries: 0,
                overflow: 0,
                cqes: 0,
                flags: 0,
                resv1: 0,
                user_addr: 0,
            },
        }
    }
}

impl Default for IoUringParams {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Result returned by [`sys_io_uring_setup`].
#[derive(Debug)]
pub struct IoUringSetupResult {
    /// File descriptor for the new io_uring instance.
    pub fd: u32,
    /// Filled-in parameters (sq_entries, cq_entries, features, offsets).
    pub params: IoUringParams,
}

/// Validate setup arguments and create an io_uring instance.
///
/// `entries` must be a non-zero power of two no larger than
/// [`IORING_MAX_ENTRIES`].  `params` is validated and then completed
/// (kernel-filled fields) before the ring is created.
///
/// Returns a [`IoUringSetupResult`] containing the fd and completed params.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — entries out of range, unknown flags,
///   conflicting flags, or reserved fields non-zero.
/// - [`Error::OutOfMemory`] — insufficient memory to allocate the ring.
pub fn sys_io_uring_setup(entries: u32, params: &mut IoUringParams) -> Result<IoUringSetupResult> {
    if entries == 0 {
        return Err(Error::InvalidArgument);
    }
    if params.flags & !IORING_SETUP_FLAGS_MASK != 0 {
        return Err(Error::InvalidArgument);
    }
    if params.resv != [0u32; 3] {
        return Err(Error::InvalidArgument);
    }
    // SQ_AFF requires SQPOLL.
    if params.flags & IORING_SETUP_SQ_AFF != 0 && params.flags & IORING_SETUP_SQPOLL == 0 {
        return Err(Error::InvalidArgument);
    }
    // DEFER_TASKRUN requires SINGLE_ISSUER and COOP_TASKRUN.
    if params.flags & IORING_SETUP_DEFER_TASKRUN != 0 {
        if params.flags & IORING_SETUP_SINGLE_ISSUER == 0 {
            return Err(Error::InvalidArgument);
        }
        if params.flags & IORING_SETUP_COOP_TASKRUN == 0 {
            return Err(Error::InvalidArgument);
        }
    }

    // Clamp or reject oversized requests.
    let sq_entries = if params.flags & IORING_SETUP_CLAMP != 0 {
        entries.min(IORING_MAX_ENTRIES)
    } else {
        if entries > IORING_MAX_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        entries
    };

    // Round up to next power of two.
    let sq_entries = sq_entries.next_power_of_two();

    let cq_entries = if params.flags & IORING_SETUP_CQSIZE != 0 {
        if params.cq_entries < sq_entries || params.cq_entries > IORING_MAX_CQ_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        params.cq_entries.next_power_of_two()
    } else {
        sq_entries * 2
    };

    // Fill in kernel-set output fields.
    params.sq_entries = sq_entries;
    params.cq_entries = cq_entries;
    params.features = IORING_FEAT_SINGLE_MMAP
        | IORING_FEAT_NODROP
        | IORING_FEAT_SUBMIT_STABLE
        | IORING_FEAT_EXT_ARG
        | IORING_FEAT_NATIVE_WORKERS
        | IORING_FEAT_RSRC_TAGS
        | IORING_FEAT_REG_REG_RING;

    // In a real kernel: allocate ring memory, create fd, mmap setup.
    // Return a placeholder fd of 3 for testing.
    Ok(IoUringSetupResult {
        fd: 3,
        params: *params,
    })
}

/// Entry point called from the syscall dispatcher.
pub fn do_io_uring_setup(entries: u32, params_ptr: u64) -> Result<u32> {
    if params_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    // SAFETY: Caller is expected to validate the pointer is user-accessible.
    let params = unsafe { &mut *(params_ptr as *mut IoUringParams) };
    let result = sys_io_uring_setup(entries, params)?;
    Ok(result.fd)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_basic_valid() {
        let mut p = IoUringParams::new();
        let r = sys_io_uring_setup(8, &mut p);
        assert!(r.is_ok());
        assert_eq!(p.sq_entries, 8);
        assert_eq!(p.cq_entries, 16);
    }

    #[test]
    fn setup_zero_entries() {
        let mut p = IoUringParams::new();
        assert_eq!(
            sys_io_uring_setup(0, &mut p).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn setup_unknown_flags() {
        let mut p = IoUringParams::new();
        p.flags = 0xFFFF_FFFF;
        assert_eq!(
            sys_io_uring_setup(8, &mut p).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn setup_clamp() {
        let mut p = IoUringParams::new();
        p.flags = IORING_SETUP_CLAMP;
        let r = sys_io_uring_setup(IORING_MAX_ENTRIES + 1, &mut p);
        assert!(r.is_ok());
        assert!(p.sq_entries <= IORING_MAX_ENTRIES);
    }

    #[test]
    fn setup_sq_aff_without_sqpoll() {
        let mut p = IoUringParams::new();
        p.flags = IORING_SETUP_SQ_AFF;
        assert_eq!(
            sys_io_uring_setup(8, &mut p).unwrap_err(),
            Error::InvalidArgument
        );
    }
}
