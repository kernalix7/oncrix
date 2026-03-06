// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! io_uring enter and register extended wrappers.
//!
//! Provides higher-level typed interfaces over the raw
//! `io_uring_enter(2)` and `io_uring_register(2)` syscalls,
//! including support for `IORING_ENTER_EXT_ARG` extended arguments
//! and structured register opcode dispatch.
//!
//! The underlying ring management lives in [`crate::io_uring_setup`].
//! This module adds:
//!
//! * [`IoUringEnterArgs`] — typed, validated wrapper around the six
//!   arguments to `io_uring_enter`.
//! * [`IoUringGeteventsArg`] — extended argument structure passed when
//!   `IORING_ENTER_EXT_ARG` is set (carries timeout + sigmask).
//! * [`IoUringRegisterOp`] — typed register opcode enum with
//!   payload-aware dispatch.
//! * [`sys_io_uring_enter2`] — extended enter handler.
//! * [`sys_io_uring_register2`] — typed register handler.
//!
//! # Syscall signatures
//!
//! ```text
//! int io_uring_enter(unsigned int fd, unsigned int to_submit,
//!                    unsigned int min_complete, unsigned int flags,
//!                    const void *argp, size_t argsz);
//!
//! int io_uring_register(unsigned int fd, unsigned int opcode,
//!                       void *arg, unsigned int nr_args);
//! ```

#[allow(dead_code)]
use oncrix_lib::{Error, Result};

use crate::io_uring_setup::{
    IORING_ENTER_EXT_ARG, IORING_ENTER_GETEVENTS, IORING_ENTER_SQ_WAIT, IORING_ENTER_SQ_WAKEUP,
    IORING_REGISTER_BUFFERS, IORING_REGISTER_BUFFERS_UPDATE, IORING_REGISTER_BUFFERS2,
    IORING_REGISTER_ENABLE_RINGS, IORING_REGISTER_EVENTFD, IORING_REGISTER_EVENTFD_ASYNC,
    IORING_REGISTER_FILES, IORING_REGISTER_FILES_UPDATE, IORING_REGISTER_FILES_UPDATE2,
    IORING_REGISTER_FILES2, IORING_REGISTER_PERSONALITY, IORING_UNREGISTER_BUFFERS,
    IORING_UNREGISTER_EVENTFD, IORING_UNREGISTER_FILES, IORING_UNREGISTER_PERSONALITY,
    sys_io_uring_enter, sys_io_uring_register,
};

// ---------------------------------------------------------------------------
// Extended-enter argument structure
// ---------------------------------------------------------------------------

/// Extended argument block passed with `IORING_ENTER_EXT_ARG`.
///
/// When the `IORING_ENTER_EXT_ARG` flag is set, `argp` points to this
/// structure instead of a bare `sigset_t *`.  It carries both a timeout
/// and a signal mask so the caller can atomically block with a deadline.
///
/// Corresponds to `struct io_uring_getevents_arg` in the Linux UAPI.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IoUringGeteventsArg {
    /// Pointer to a `sigset_t` (user address).  0 means no signal mask.
    pub sigmask: u64,
    /// Size of the signal mask structure pointed to by `sigmask`.
    pub sigmask_sz: u32,
    /// Padding (must be 0).
    pub pad: u32,
    /// Pointer to a `struct __kernel_timespec` (user address).
    /// 0 means no timeout (wait indefinitely).
    pub ts: u64,
}

impl IoUringGeteventsArg {
    /// Returns `true` if a signal mask is attached.
    pub const fn has_sigmask(&self) -> bool {
        self.sigmask != 0
    }

    /// Returns `true` if a timeout is attached.
    pub const fn has_timeout(&self) -> bool {
        self.ts != 0
    }

    /// Validate the argument structure.
    ///
    /// The padding word must be zero to reserve it for future use.
    pub fn validate(&self) -> Result<()> {
        if self.pad != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Typed enter flags
// ---------------------------------------------------------------------------

/// Validated flags for `io_uring_enter`.
///
/// Wraps the raw `u32` flag word with checked construction so that
/// callers cannot supply unknown bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IoUringEnterFlags(u32);

/// Mask of all defined enter flags.
const ENTER_FLAGS_VALID: u32 =
    IORING_ENTER_GETEVENTS | IORING_ENTER_SQ_WAKEUP | IORING_ENTER_SQ_WAIT | IORING_ENTER_EXT_ARG;

impl IoUringEnterFlags {
    /// Construct from a raw `u32`, rejecting unknown bits.
    pub fn from_raw(raw: u32) -> Result<Self> {
        if raw & !ENTER_FLAGS_VALID != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Return the raw bit pattern.
    pub const fn bits(&self) -> u32 {
        self.0
    }

    /// `IORING_ENTER_GETEVENTS` is set.
    pub const fn getevents(&self) -> bool {
        self.0 & IORING_ENTER_GETEVENTS != 0
    }

    /// `IORING_ENTER_SQ_WAKEUP` is set.
    pub const fn sq_wakeup(&self) -> bool {
        self.0 & IORING_ENTER_SQ_WAKEUP != 0
    }

    /// `IORING_ENTER_SQ_WAIT` is set.
    pub const fn sq_wait(&self) -> bool {
        self.0 & IORING_ENTER_SQ_WAIT != 0
    }

    /// `IORING_ENTER_EXT_ARG` is set.
    pub const fn ext_arg(&self) -> bool {
        self.0 & IORING_ENTER_EXT_ARG != 0
    }
}

// ---------------------------------------------------------------------------
// IoUringEnterArgs — validated bundle for io_uring_enter
// ---------------------------------------------------------------------------

/// Full, validated argument bundle for `io_uring_enter`.
///
/// Constructed from the raw register values by
/// [`IoUringEnterArgs::from_regs`], which validates all fields
/// before any ring state is touched.
#[derive(Debug, Clone, Copy)]
pub struct IoUringEnterArgs {
    /// File descriptor (ring index).
    pub fd: i32,
    /// Number of SQEs the caller wishes to submit.
    pub to_submit: u32,
    /// Minimum completions to wait for when `GETEVENTS` is set.
    pub min_complete: u32,
    /// Validated flags.
    pub flags: IoUringEnterFlags,
    /// Extended argument (only present when `EXT_ARG` flag is set).
    pub ext: Option<IoUringGeteventsArg>,
}

impl IoUringEnterArgs {
    /// Build from raw syscall register values.
    ///
    /// `ext` is `Some(…)` when `flags & IORING_ENTER_EXT_ARG != 0`,
    /// otherwise it is ignored and stored as `None`.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if `fd` is negative, `flags` contains
    /// unknown bits, or the extended argument fails its own validation.
    pub fn from_regs(
        fd: i32,
        to_submit: u32,
        min_complete: u32,
        raw_flags: u32,
        ext: Option<IoUringGeteventsArg>,
    ) -> Result<Self> {
        if fd < 0 {
            return Err(Error::InvalidArgument);
        }
        let flags = IoUringEnterFlags::from_raw(raw_flags)?;

        let ext = if flags.ext_arg() {
            let arg = ext.ok_or(Error::InvalidArgument)?;
            arg.validate()?;
            Some(arg)
        } else {
            None
        };

        Ok(Self {
            fd,
            to_submit,
            min_complete,
            flags,
            ext,
        })
    }
}

// ---------------------------------------------------------------------------
// IoUringRegisterOp — typed register opcode
// ---------------------------------------------------------------------------

/// Typed register opcode for `io_uring_register`.
///
/// Each variant carries the information needed to process the
/// corresponding opcode without further runtime dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoUringRegisterOp {
    /// Register `nr_bufs` fixed buffers.
    RegisterBuffers { nr_bufs: u32 },
    /// Unregister all previously registered fixed buffers.
    UnregisterBuffers,
    /// Register `nr_files` fixed file descriptors.
    RegisterFiles { nr_files: u32 },
    /// Unregister all previously registered fixed files.
    UnregisterFiles,
    /// Update `nr_files` entries in the registered-files table.
    UpdateFiles { nr_files: u32 },
    /// Register `nr_bufs` fixed buffers (v2 API with tags).
    RegisterBuffers2 { nr_bufs: u32 },
    /// Update `nr_bufs` entries in the registered-buffers table.
    UpdateBuffers { nr_bufs: u32 },
    /// Register `nr_files` fixed file descriptors (v2 API with tags).
    RegisterFiles2 { nr_files: u32 },
    /// Update `nr_files` entries in the registered-files table (v2).
    UpdateFiles2 { nr_files: u32 },
    /// Register an eventfd for completion notification.
    RegisterEventfd,
    /// Register an eventfd for async completion notification.
    RegisterEventfdAsync,
    /// Unregister the previously registered eventfd.
    UnregisterEventfd,
    /// Register a credential set for personality switching.
    RegisterPersonality,
    /// Unregister a previously registered personality.
    UnregisterPersonality { personality_id: u32 },
    /// Enable a ring previously created with `IORING_SETUP_R_DISABLED`.
    EnableRings,
}

impl IoUringRegisterOp {
    /// Construct from a raw opcode and `nr_args`, validating the combination.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` for unknown opcodes or when `nr_args` is
    /// zero for opcodes that require a non-zero count.
    pub fn from_raw(opcode: u32, nr_args: u32) -> Result<Self> {
        match opcode {
            IORING_REGISTER_BUFFERS => {
                if nr_args == 0 {
                    return Err(Error::InvalidArgument);
                }
                Ok(Self::RegisterBuffers { nr_bufs: nr_args })
            }
            IORING_UNREGISTER_BUFFERS => Ok(Self::UnregisterBuffers),
            IORING_REGISTER_FILES => {
                if nr_args == 0 {
                    return Err(Error::InvalidArgument);
                }
                Ok(Self::RegisterFiles { nr_files: nr_args })
            }
            IORING_UNREGISTER_FILES => Ok(Self::UnregisterFiles),
            IORING_REGISTER_FILES_UPDATE => {
                if nr_args == 0 {
                    return Err(Error::InvalidArgument);
                }
                Ok(Self::UpdateFiles { nr_files: nr_args })
            }
            IORING_REGISTER_BUFFERS2 => {
                if nr_args == 0 {
                    return Err(Error::InvalidArgument);
                }
                Ok(Self::RegisterBuffers2 { nr_bufs: nr_args })
            }
            IORING_REGISTER_BUFFERS_UPDATE => {
                if nr_args == 0 {
                    return Err(Error::InvalidArgument);
                }
                Ok(Self::UpdateBuffers { nr_bufs: nr_args })
            }
            IORING_REGISTER_FILES2 => {
                if nr_args == 0 {
                    return Err(Error::InvalidArgument);
                }
                Ok(Self::RegisterFiles2 { nr_files: nr_args })
            }
            IORING_REGISTER_FILES_UPDATE2 => {
                if nr_args == 0 {
                    return Err(Error::InvalidArgument);
                }
                Ok(Self::UpdateFiles2 { nr_files: nr_args })
            }
            IORING_REGISTER_EVENTFD => Ok(Self::RegisterEventfd),
            IORING_REGISTER_EVENTFD_ASYNC => Ok(Self::RegisterEventfdAsync),
            IORING_UNREGISTER_EVENTFD => Ok(Self::UnregisterEventfd),
            IORING_REGISTER_PERSONALITY => Ok(Self::RegisterPersonality),
            IORING_UNREGISTER_PERSONALITY => {
                if nr_args == 0 {
                    return Err(Error::InvalidArgument);
                }
                Ok(Self::UnregisterPersonality {
                    personality_id: nr_args,
                })
            }
            IORING_REGISTER_ENABLE_RINGS => Ok(Self::EnableRings),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Return the raw opcode value for this operation.
    pub const fn opcode(&self) -> u32 {
        match self {
            Self::RegisterBuffers { .. } => IORING_REGISTER_BUFFERS,
            Self::UnregisterBuffers => IORING_UNREGISTER_BUFFERS,
            Self::RegisterFiles { .. } => IORING_REGISTER_FILES,
            Self::UnregisterFiles => IORING_UNREGISTER_FILES,
            Self::UpdateFiles { .. } => IORING_REGISTER_FILES_UPDATE,
            Self::RegisterBuffers2 { .. } => IORING_REGISTER_BUFFERS2,
            Self::UpdateBuffers { .. } => IORING_REGISTER_BUFFERS_UPDATE,
            Self::RegisterFiles2 { .. } => IORING_REGISTER_FILES2,
            Self::UpdateFiles2 { .. } => IORING_REGISTER_FILES_UPDATE2,
            Self::RegisterEventfd => IORING_REGISTER_EVENTFD,
            Self::RegisterEventfdAsync => IORING_REGISTER_EVENTFD_ASYNC,
            Self::UnregisterEventfd => IORING_UNREGISTER_EVENTFD,
            Self::RegisterPersonality => IORING_REGISTER_PERSONALITY,
            Self::UnregisterPersonality { .. } => IORING_UNREGISTER_PERSONALITY,
            Self::EnableRings => IORING_REGISTER_ENABLE_RINGS,
        }
    }

    /// Return the `nr_args` field to pass to the underlying register syscall.
    pub const fn nr_args(&self) -> u32 {
        match self {
            Self::RegisterBuffers { nr_bufs } => *nr_bufs,
            Self::UnregisterBuffers => 0,
            Self::RegisterFiles { nr_files } => *nr_files,
            Self::UnregisterFiles => 0,
            Self::UpdateFiles { nr_files } => *nr_files,
            Self::RegisterBuffers2 { nr_bufs } => *nr_bufs,
            Self::UpdateBuffers { nr_bufs } => *nr_bufs,
            Self::RegisterFiles2 { nr_files } => *nr_files,
            Self::UpdateFiles2 { nr_files } => *nr_files,
            Self::RegisterEventfd => 1,
            Self::RegisterEventfdAsync => 1,
            Self::UnregisterEventfd => 0,
            Self::RegisterPersonality => 0,
            Self::UnregisterPersonality { personality_id } => *personality_id,
            Self::EnableRings => 0,
        }
    }
}

// ---------------------------------------------------------------------------
// sys_io_uring_enter2 — extended enter handler
// ---------------------------------------------------------------------------

/// Extended `io_uring_enter` handler supporting `IORING_ENTER_EXT_ARG`.
///
/// Validates the full argument bundle and dispatches to the underlying
/// ring implementation.  The `ext` argument is inspected when
/// `IORING_ENTER_EXT_ARG` is set; its timeout and sigmask fields are
/// recorded (stub: timeout is noted but not actually enforced).
///
/// # Arguments
///
/// * `fd`           — io_uring file descriptor (ring index)
/// * `to_submit`    — number of SQEs to submit
/// * `min_complete` — minimum completions to wait for
/// * `raw_flags`    — raw `IORING_ENTER_*` flags
/// * `ext`          — extended argument (required when `EXT_ARG` set)
///
/// # Returns
///
/// Number of SQEs submitted.
///
/// # Errors
///
/// * `InvalidArgument` — invalid fd, unknown flags, or bad extended arg
/// * `Busy` — ring is disabled
pub fn sys_io_uring_enter2(
    fd: i32,
    to_submit: u32,
    min_complete: u32,
    raw_flags: u32,
    ext: Option<IoUringGeteventsArg>,
) -> Result<i32> {
    let args = IoUringEnterArgs::from_regs(fd, to_submit, min_complete, raw_flags, ext)?;

    // If a timeout was provided via ext_arg, record it.  A full
    // implementation would arm a hrtimer and wake the caller when it
    // fires or min_complete completions arrive.
    if let Some(ext_arg) = args.ext {
        let _has_timeout = ext_arg.has_timeout();
        let _has_sigmask = ext_arg.has_sigmask();
        // Stub: timeout/sigmask handling would be implemented here.
    }

    sys_io_uring_enter(
        args.fd,
        args.to_submit,
        args.min_complete,
        args.flags.bits(),
    )
}

// ---------------------------------------------------------------------------
// sys_io_uring_register2 — typed register handler
// ---------------------------------------------------------------------------

/// Typed `io_uring_register` handler.
///
/// Converts the raw `(opcode, nr_args)` pair into a [`IoUringRegisterOp`]
/// and dispatches to the underlying register implementation.
///
/// # Arguments
///
/// * `fd`      — io_uring file descriptor (ring index)
/// * `opcode`  — raw `IORING_REGISTER_*` / `IORING_UNREGISTER_*` opcode
/// * `nr_args` — number of items (buffers, files, etc.)
///
/// # Returns
///
/// `0` on success, or a positive personality ID for
/// `IORING_REGISTER_PERSONALITY`.
///
/// # Errors
///
/// * `InvalidArgument` — unknown opcode, zero `nr_args` where required,
///   or invalid fd
/// * `AlreadyExists` — resource already registered
/// * `NotFound` — unregister when nothing was registered
/// * `OutOfMemory` — too many registered resources
pub fn sys_io_uring_register2(fd: i32, opcode: u32, nr_args: u32) -> Result<i32> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    let op = IoUringRegisterOp::from_raw(opcode, nr_args)?;
    sys_io_uring_register(fd, op.opcode(), op.nr_args())
}

// ---------------------------------------------------------------------------
// Batch-enter helper
// ---------------------------------------------------------------------------

/// Submit multiple batches of SQEs across successive `io_uring_enter` calls.
///
/// Splits `total` SQEs into chunks of at most `batch_size` and submits
/// each chunk, accumulating the total submitted count.  Useful when the
/// caller holds more pending SQEs than the ring's SQ capacity.
///
/// # Arguments
///
/// * `fd`         — io_uring file descriptor
/// * `total`      — total number of SQEs to submit
/// * `batch_size` — maximum SQEs per `io_uring_enter` call
/// * `flags`      — `IORING_ENTER_*` flags (applied to every call)
///
/// # Returns
///
/// Total number of SQEs submitted across all calls.
///
/// # Errors
///
/// Propagates any error from the underlying enter call.
pub fn batch_enter(fd: i32, total: u32, batch_size: u32, flags: u32) -> Result<u32> {
    if batch_size == 0 {
        return Err(Error::InvalidArgument);
    }
    let flags = IoUringEnterFlags::from_raw(flags)?;
    let mut remaining = total;
    let mut submitted = 0u32;

    while remaining > 0 {
        let chunk = remaining.min(batch_size);
        let n = sys_io_uring_enter(fd, chunk, 0, flags.bits())?;
        submitted = submitted.saturating_add(n as u32);
        remaining = remaining.saturating_sub(chunk);
    }

    Ok(submitted)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io_uring_setup::{IoUringParams, sys_io_uring_destroy, sys_io_uring_setup};

    fn make_ring() -> i32 {
        let mut params = IoUringParams::default();
        sys_io_uring_setup(8, &mut params).expect("setup failed")
    }

    #[test]
    fn test_enter_flags_valid() {
        let f = IoUringEnterFlags::from_raw(0).unwrap();
        assert!(!f.getevents());

        let f = IoUringEnterFlags::from_raw(IORING_ENTER_GETEVENTS).unwrap();
        assert!(f.getevents());
    }

    #[test]
    fn test_enter_flags_invalid_bits() {
        assert!(IoUringEnterFlags::from_raw(0x8000_0000).is_err());
    }

    #[test]
    fn test_getevents_arg_valid() {
        let arg = IoUringGeteventsArg {
            sigmask: 0,
            sigmask_sz: 8,
            pad: 0,
            ts: 0,
        };
        assert!(arg.validate().is_ok());
    }

    #[test]
    fn test_getevents_arg_bad_pad() {
        let arg = IoUringGeteventsArg {
            sigmask: 0,
            sigmask_sz: 8,
            pad: 1,
            ts: 0,
        };
        assert!(arg.validate().is_err());
    }

    #[test]
    fn test_enter_args_from_regs_bad_fd() {
        assert!(IoUringEnterArgs::from_regs(-1, 0, 0, 0, None).is_err());
    }

    #[test]
    fn test_enter_args_ext_arg_required() {
        // EXT_ARG set but no ext struct provided.
        assert!(IoUringEnterArgs::from_regs(3, 0, 0, IORING_ENTER_EXT_ARG, None).is_err());
    }

    #[test]
    fn test_enter2_basic_submit() {
        let fd = make_ring();
        let n = sys_io_uring_enter2(fd, 4, 0, 0, None).unwrap();
        assert_eq!(n, 4);
        sys_io_uring_destroy(fd).unwrap();
    }

    #[test]
    fn test_enter2_ext_arg() {
        let fd = make_ring();
        let ext = IoUringGeteventsArg {
            sigmask: 0,
            sigmask_sz: 0,
            pad: 0,
            ts: 0x1000, // fake timeout address
        };
        let n = sys_io_uring_enter2(fd, 2, 0, IORING_ENTER_EXT_ARG, Some(ext)).unwrap();
        assert_eq!(n, 2);
        sys_io_uring_destroy(fd).unwrap();
    }

    #[test]
    fn test_register_op_roundtrip() {
        let op = IoUringRegisterOp::from_raw(IORING_REGISTER_BUFFERS, 4).unwrap();
        assert_eq!(op.opcode(), IORING_REGISTER_BUFFERS);
        assert_eq!(op.nr_args(), 4);
    }

    #[test]
    fn test_register_op_zero_nr_args_rejected() {
        assert!(IoUringRegisterOp::from_raw(IORING_REGISTER_BUFFERS, 0).is_err());
    }

    #[test]
    fn test_register_op_unknown_opcode() {
        assert!(IoUringRegisterOp::from_raw(0xDEAD, 1).is_err());
    }

    #[test]
    fn test_register2_buffers() {
        let fd = make_ring();
        assert!(sys_io_uring_register2(fd, IORING_REGISTER_BUFFERS, 4).is_ok());
        sys_io_uring_destroy(fd).unwrap();
    }

    #[test]
    fn test_register2_bad_fd() {
        assert!(sys_io_uring_register2(-1, IORING_REGISTER_BUFFERS, 4).is_err());
    }

    #[test]
    fn test_batch_enter() {
        let fd = make_ring();
        let submitted = batch_enter(fd, 10, 3, 0).unwrap();
        assert!(submitted <= 10);
        sys_io_uring_destroy(fd).unwrap();
    }

    #[test]
    fn test_batch_enter_zero_batch_size() {
        let fd = make_ring();
        assert!(batch_enter(fd, 4, 0, 0).is_err());
        sys_io_uring_destroy(fd).unwrap();
    }

    #[test]
    fn test_register_unregister_buffers() {
        let fd = make_ring();
        sys_io_uring_register2(fd, IORING_REGISTER_BUFFERS, 8).unwrap();
        sys_io_uring_register2(fd, IORING_UNREGISTER_BUFFERS, 0).unwrap();
        sys_io_uring_destroy(fd).unwrap();
    }

    #[test]
    fn test_enable_rings_opcode() {
        let op = IoUringRegisterOp::from_raw(IORING_REGISTER_ENABLE_RINGS, 0).unwrap();
        assert_eq!(op, IoUringRegisterOp::EnableRings);
    }
}
