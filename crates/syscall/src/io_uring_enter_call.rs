// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `io_uring_enter(2)` syscall handler.
//!
//! The `io_uring_enter` syscall submits I/O requests and optionally waits
//! for completions on an io_uring instance.  It is the primary mechanism
//! for driving asynchronous I/O through the io_uring subsystem.
//!
//! # Syscall signature
//!
//! ```text
//! int io_uring_enter(unsigned int fd, unsigned int to_submit,
//!                    unsigned int min_complete, unsigned int flags,
//!                    const void *arg, size_t argsz);
//! ```
//!
//! # Flags
//!
//! | Flag                      | Value  | Description                                  |
//! |---------------------------|--------|----------------------------------------------|
//! | `IORING_ENTER_GETEVENTS`  | 1 << 0 | Wait for `min_complete` completions          |
//! | `IORING_ENTER_SQ_WAKEUP`  | 1 << 1 | Wake up the SQ polling thread               |
//! | `IORING_ENTER_SQ_WAIT`    | 1 << 2 | Wait until there is space in the SQ         |
//! | `IORING_ENTER_EXT_ARG`    | 1 << 3 | `arg` points to `io_uring_getevents_arg`    |
//! | `IORING_ENTER_REGISTERED_RING` | 1 << 4 | Use registered ring fd               |
//!
//! # References
//!
//! - Linux: `io_uring/io_uring.c`, `include/uapi/linux/io_uring.h`
//! - `io_uring_enter(2)` man page
//! - liburing: `src/include/liburing.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// User-pointer safety
// ---------------------------------------------------------------------------

/// Inclusive upper bound of the canonical user-space lower half (x86_64).
///
/// Any pointer supplied by the caller must satisfy `ptr <= USER_PTR_MAX`.
/// A pointer above this value is either a kernel-half address or a
/// non-canonical VA; dereferencing it in ring 0 causes a kernel fault.
///
/// Mirrors `oncrix_mm::address_space::USER_SPACE_END`.
const USER_PTR_MAX: u64 = 0x0000_7FFF_FFFF_FFFF;

/// Validate that the half-open range `[ptr, ptr + len)` is entirely within
/// the canonical user-space lower half.
///
/// Returns `Err(InvalidArgument)` (→ `EFAULT` at the syscall boundary) if:
/// - `ptr` is zero (null pointer).
/// - `ptr` is not a multiple of `align` (a `core::ptr::read` of an
///   under-aligned pointer is undefined behaviour).
/// - `ptr + len` wraps around (overflow).
/// - any byte of the range exceeds `USER_PTR_MAX`.
fn validate_user_ptr_range(ptr: u64, len: u64, align: u64) -> Result<()> {
    if ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if align != 0 && ptr % align != 0 {
        return Err(Error::InvalidArgument);
    }
    let end = ptr.checked_add(len).ok_or(Error::InvalidArgument)?;
    // `end` is the exclusive end; the last accessible byte is `end - 1`.
    // Use `end - 1 <= USER_PTR_MAX`, i.e. `end <= USER_PTR_MAX + 1`.
    if end > USER_PTR_MAX.saturating_add(1) {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Flag constants
// ---------------------------------------------------------------------------

/// Wait for `min_complete` events before returning.
pub const IORING_ENTER_GETEVENTS: u32 = 1 << 0;
/// Wake the SQ poll thread if it is asleep.
pub const IORING_ENTER_SQ_WAKEUP: u32 = 1 << 1;
/// Block until there is free space in the SQ ring.
pub const IORING_ENTER_SQ_WAIT: u32 = 1 << 2;
/// Interpret `arg` as `struct io_uring_getevents_arg`.
pub const IORING_ENTER_EXT_ARG: u32 = 1 << 3;
/// `fd` is a registered ring file-descriptor index.
pub const IORING_ENTER_REGISTERED_RING: u32 = 1 << 4;

/// All valid `io_uring_enter` flag bits.
const IORING_ENTER_FLAGS_MASK: u32 = IORING_ENTER_GETEVENTS
    | IORING_ENTER_SQ_WAKEUP
    | IORING_ENTER_SQ_WAIT
    | IORING_ENTER_EXT_ARG
    | IORING_ENTER_REGISTERED_RING;

// ---------------------------------------------------------------------------
// Extended-argument structure
// ---------------------------------------------------------------------------

/// Extended argument passed when `IORING_ENTER_EXT_ARG` is set.
///
/// Replaces the bare `sigset_t *` argument and carries both a completion
/// timeout and a signal mask that are applied atomically.
///
/// Matches `struct io_uring_getevents_arg` from the Linux UAPI.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoUringGeteventsArg {
    /// Pointer to a `sigset_t`; 0 means use the calling thread's current mask.
    pub sigmask: u64,
    /// Size of the sigmask pointed to by `sigmask`.
    pub sigmask_sz: u32,
    /// Reserved — must be zero.
    pub pad: u32,
    /// Pointer to a `struct __kernel_timespec` completion timeout; 0 = none.
    pub ts: u64,
}

impl IoUringGeteventsArg {
    /// Create a zeroed instance (no sigmask, no timeout).
    pub const fn new() -> Self {
        Self {
            sigmask: 0,
            sigmask_sz: 0,
            pad: 0,
            ts: 0,
        }
    }
}

impl Default for IoUringGeteventsArg {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Enter arguments
// ---------------------------------------------------------------------------

/// Validated arguments for `io_uring_enter`.
#[derive(Debug, Clone, Copy)]
pub struct IoUringEnterArgs {
    /// File descriptor referencing the io_uring instance (or registered index).
    pub fd: u32,
    /// Number of SQEs to submit.
    pub to_submit: u32,
    /// Minimum number of CQEs to wait for (only if `GETEVENTS` is set).
    pub min_complete: u32,
    /// Validated flags bitmask.
    pub flags: u32,
    /// Optional pointer to extended argument structure.
    pub ext_arg: Option<IoUringGeteventsArg>,
}

impl IoUringEnterArgs {
    /// Construct and validate an [`IoUringEnterArgs`] from raw syscall parameters.
    ///
    /// Returns `Err(InvalidArgument)` if:
    /// - Unknown flag bits are set.
    /// - `IORING_ENTER_EXT_ARG` is set but `argp` is null or not in the
    ///   canonical user-space range.
    /// - `IORING_ENTER_EXT_ARG` is set but `argsz` does not match
    ///   `size_of::<IoUringGeteventsArg>()`.
    /// - The `pad` field of the extended arg is non-zero.
    pub fn from_raw(
        fd: u32,
        to_submit: u32,
        min_complete: u32,
        flags: u32,
        argp: u64,
        argsz: usize,
    ) -> Result<Self> {
        if flags & !IORING_ENTER_FLAGS_MASK != 0 {
            return Err(Error::InvalidArgument);
        }

        let ext_arg = if flags & IORING_ENTER_EXT_ARG != 0 {
            // Validate size before touching the pointer so we never deref with
            // a wrong stride.
            if argsz != core::mem::size_of::<IoUringGeteventsArg>() {
                return Err(Error::InvalidArgument);
            }
            // SECURITY: validate the canonical user-space range before any
            // dereference.  A kernel-half or non-canonical address would cause
            // a ring-0 fault.  This check mirrors the crate-wide convention
            // (see copy_file_range_ext_call, mseal) and must precede any read.
            validate_user_ptr_range(
                argp,
                argsz as u64,
                core::mem::align_of::<IoUringGeteventsArg>() as u64,
            )?;
            // SAFETY: `validate_user_ptr_range` has confirmed the range is
            // within the canonical user lower-half, correctly aligned for
            // `IoUringGeteventsArg`, and cannot overflow.
            // `IoUringGeteventsArg` is `repr(C)` and fully initialized by the
            // caller.  We copy by value into a kernel-local binding so that
            // no subsequent code touches the user pointer directly.
            let arg = unsafe { core::ptr::read(argp as *const IoUringGeteventsArg) };
            if arg.pad != 0 {
                return Err(Error::InvalidArgument);
            }
            Some(arg)
        } else {
            None
        };

        Ok(Self {
            fd,
            to_submit,
            min_complete,
            flags,
            ext_arg,
        })
    }
}

// ---------------------------------------------------------------------------
// Ring state
// ---------------------------------------------------------------------------

/// State tracked per io_uring instance for the enter path.
#[derive(Debug)]
pub struct IoUringEnterState {
    /// Number of SQEs submitted in this enter call.
    pub submitted: u32,
    /// Number of CQEs available at the time of the call.
    pub cqes_available: u32,
    /// Whether the SQ thread was woken.
    pub sq_thread_woken: bool,
}

impl IoUringEnterState {
    /// Create a zeroed enter-state record.
    pub const fn new() -> Self {
        Self {
            submitted: 0,
            cqes_available: 0,
            sq_thread_woken: false,
        }
    }
}

impl Default for IoUringEnterState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handle the `io_uring_enter` syscall.
///
/// Submits up to `args.to_submit` SQEs from the submission ring and
/// optionally waits for at least `args.min_complete` CQEs to appear in the
/// completion ring.
///
/// Returns the number of SQEs successfully submitted on success.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — invalid flags or malformed extended arg.
/// - [`Error::NotFound`] — `fd` does not refer to a valid io_uring instance.
/// - [`Error::WouldBlock`] — `IORING_ENTER_SQ_WAIT` set and ring was full
///   but the wait was interrupted.
/// - [`Error::Interrupted`] — signal received while waiting for completions.
pub fn sys_io_uring_enter(args: IoUringEnterArgs) -> Result<u32> {
    // In a full implementation this would:
    // 1. Look up the io_uring context from the fd table.
    // 2. Optionally wake the SQ poll thread.
    // 3. Drain the SQ ring, creating and queuing internal requests.
    // 4. If GETEVENTS, wait on the CQ wait-queue until min_complete arrive.
    // 5. Return the number of SQEs consumed.

    if args.flags & IORING_ENTER_SQ_WAKEUP != 0 {
        // TODO: signal the SQ poll thread's wait-queue.
    }

    if args.flags & IORING_ENTER_SQ_WAIT != 0 && args.to_submit > 0 {
        // TODO: block until SQ has space for `to_submit` entries.
    }

    // Simulate submitting to_submit requests.
    let submitted = args.to_submit;

    if args.flags & IORING_ENTER_GETEVENTS != 0 && args.min_complete > 0 {
        // TODO: wait on the CQ wait-queue.
    }

    Ok(submitted)
}

/// Validate raw `io_uring_enter` arguments and dispatch to [`sys_io_uring_enter`].
///
/// This is the entry point called from the syscall dispatcher.
pub fn do_io_uring_enter(
    fd: u32,
    to_submit: u32,
    min_complete: u32,
    flags: u32,
    argp: u64,
    argsz: usize,
) -> Result<u32> {
    let args = IoUringEnterArgs::from_raw(fd, to_submit, min_complete, flags, argp, argsz)?;
    sys_io_uring_enter(args)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enter_no_flags_valid() {
        let result = do_io_uring_enter(3, 4, 0, 0, 0, 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 4);
    }

    #[test]
    fn enter_invalid_flags() {
        let result = do_io_uring_enter(3, 1, 0, 0xFFFF_FFFF, 0, 0);
        assert_eq!(result.unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn enter_ext_arg_null_ptr() {
        // argp == 0, argsz == 0: size check fires first (0 != 16).
        let result = do_io_uring_enter(3, 1, 1, IORING_ENTER_EXT_ARG, 0, 0);
        assert_eq!(result.unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn enter_ext_arg_wrong_size() {
        // Size mismatch is caught before the pointer range check — no deref occurs.
        // Use a plausible user address so the test clearly exercises the size path.
        let user_addr: u64 = 0x0000_4000_0000_0000;
        let result = do_io_uring_enter(3, 1, 1, IORING_ENTER_EXT_ARG, user_addr, 4);
        assert_eq!(result.unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn enter_ext_arg_kernel_addr_rejected() {
        // A kernel-half address (above USER_PTR_MAX) must be rejected even
        // when the size is correct.  No deref should ever occur.
        let kernel_addr: u64 = 0xffff_8000_0000_0000u64;
        let sz = core::mem::size_of::<IoUringGeteventsArg>();
        let result = do_io_uring_enter(3, 1, 1, IORING_ENTER_EXT_ARG, kernel_addr, sz);
        assert_eq!(result.unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn getevents_arg_default() {
        let a = IoUringGeteventsArg::default();
        assert_eq!(a.sigmask, 0);
        assert_eq!(a.ts, 0);
    }
}
