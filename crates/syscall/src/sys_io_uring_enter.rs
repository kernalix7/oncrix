// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `io_uring_enter(2)` syscall handler — submit SQEs and wait for CQEs.
//!
//! `io_uring_enter` is the primary syscall for driving an io_uring instance.
//! It submits I/O requests from the submission queue (SQ) and optionally waits
//! for completions to appear in the completion queue (CQ).
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
//! | Flag                       | Value  | Effect                                             |
//! |----------------------------|--------|----------------------------------------------------|
//! | `IORING_ENTER_GETEVENTS`   |  1     | Wait until `min_complete` CQEs are available.      |
//! | `IORING_ENTER_SQ_WAKEUP`   |  2     | Wake the SQ poll thread if sleeping.               |
//! | `IORING_ENTER_SQ_WAIT`     |  4     | Block until SQ ring has room for `to_submit` SQEs. |
//! | `IORING_ENTER_EXT_ARG`     |  8     | `arg` is `struct io_uring_getevents_arg`.          |
//! | `IORING_ENTER_REGISTERED_RING` | 16 | `fd` is a registered ring index.                   |
//!
//! # SQ/CQ ring model
//!
//! The SQ ring is a fixed-size circular buffer of SQE indices.
//! The CQ ring is a fixed-size circular buffer of CQEs.
//! Submission consumes SQEs; completion produces CQEs.
//!
//! # Linux reference
//!
//! `io_uring/io_uring.c` — `io_uring_enter()`, `io_submit_sqes()`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flag constants
// ---------------------------------------------------------------------------

/// Wait for `min_complete` completions before returning.
pub const IORING_ENTER_GETEVENTS: u32 = 1 << 0;
/// Wake the SQ poll thread.
pub const IORING_ENTER_SQ_WAKEUP: u32 = 1 << 1;
/// Block until the SQ ring has space.
pub const IORING_ENTER_SQ_WAIT: u32 = 1 << 2;
/// `arg` is a `struct io_uring_getevents_arg`.
pub const IORING_ENTER_EXT_ARG: u32 = 1 << 3;
/// `fd` is a registered ring index, not an actual fd.
pub const IORING_ENTER_REGISTERED_RING: u32 = 1 << 4;

/// All valid `io_uring_enter` flag bits.
const FLAGS_MASK: u32 = IORING_ENTER_GETEVENTS
    | IORING_ENTER_SQ_WAKEUP
    | IORING_ENTER_SQ_WAIT
    | IORING_ENTER_EXT_ARG
    | IORING_ENTER_REGISTERED_RING;

// ---------------------------------------------------------------------------
// SQE — Submission Queue Entry
// ---------------------------------------------------------------------------

/// Opcode field values for an SQE.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqeOpcode {
    /// No operation (useful for flushing).
    Nop = 0,
    /// Vectored read.
    Readv = 1,
    /// Vectored write.
    Writev = 2,
    /// `fsync`.
    Fsync = 3,
    /// Fixed-buffer read.
    ReadFixed = 4,
    /// Fixed-buffer write.
    WriteFixed = 5,
    /// `poll_add`.
    PollAdd = 6,
    /// `send`.
    Send = 9,
    /// `recv`.
    Recv = 10,
    /// Linked timeout.
    LinkTimeout = 14,
    /// Async cancel.
    AsyncCancel = 15,
}

impl SqeOpcode {
    /// Parse from a raw `u8`.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Nop),
            1 => Some(Self::Readv),
            2 => Some(Self::Writev),
            3 => Some(Self::Fsync),
            4 => Some(Self::ReadFixed),
            5 => Some(Self::WriteFixed),
            6 => Some(Self::PollAdd),
            9 => Some(Self::Send),
            10 => Some(Self::Recv),
            14 => Some(Self::LinkTimeout),
            15 => Some(Self::AsyncCancel),
            _ => None,
        }
    }
}

/// A stub submission queue entry.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Sqe {
    /// Operation code.
    pub opcode: u8,
    /// Flags (SQE-level flags, not enter flags).
    pub flags: u8,
    /// I/O priority.
    pub ioprio: u16,
    /// File descriptor for the operation.
    pub fd: i32,
    /// Offset or address (operation-specific).
    pub off: u64,
    /// Buffer pointer (operation-specific).
    pub addr: u64,
    /// Length of the buffer.
    pub len: u32,
    /// Operation-specific flags.
    pub op_flags: u32,
    /// User-specified token returned in the CQE.
    pub user_data: u64,
    /// Buffer index / group.
    pub buf_index: u16,
    /// Personality ID.
    pub personality: u16,
    /// File index for fixed-file operations.
    pub file_index: u32,
}

// ---------------------------------------------------------------------------
// CQE — Completion Queue Entry
// ---------------------------------------------------------------------------

/// A stub completion queue entry.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Cqe {
    /// Token echoed from the corresponding SQE.
    pub user_data: u64,
    /// Result of the operation (negative errno on failure).
    pub res: i32,
    /// CQE flags.
    pub flags: u32,
}

// ---------------------------------------------------------------------------
// RingState — per-ring state for the enter path
// ---------------------------------------------------------------------------

/// Maximum ring size (number of entries).
const RING_SIZE: usize = 256;

/// State of an io_uring instance's SQ/CQ rings.
///
/// In a real kernel this lives in shared memory mapped by both user-space
/// and the kernel.  Here it is modelled as a fixed-size in-kernel structure.
pub struct RingState {
    /// Submission queue entries.
    sqes: [Sqe; RING_SIZE],
    /// Completion queue entries.
    cqes: [Cqe; RING_SIZE],
    /// SQ head (consumer pointer — next SQE to process).
    sq_head: u32,
    /// SQ tail (producer pointer — next free SQE slot).
    sq_tail: u32,
    /// CQ head (consumer pointer — next CQE to read).
    cq_head: u32,
    /// CQ tail (producer pointer — next free CQE slot).
    cq_tail: u32,
    /// Ring capacity.
    capacity: u32,
}

impl RingState {
    /// Create an empty ring with default capacity.
    pub const fn new() -> Self {
        Self {
            sqes: [const {
                Sqe {
                    opcode: 0,
                    flags: 0,
                    ioprio: 0,
                    fd: 0,
                    off: 0,
                    addr: 0,
                    len: 0,
                    op_flags: 0,
                    user_data: 0,
                    buf_index: 0,
                    personality: 0,
                    file_index: 0,
                }
            }; RING_SIZE],
            cqes: [const {
                Cqe {
                    user_data: 0,
                    res: 0,
                    flags: 0,
                }
            }; RING_SIZE],
            sq_head: 0,
            sq_tail: 0,
            cq_head: 0,
            cq_tail: 0,
            capacity: RING_SIZE as u32,
        }
    }

    /// Return the number of pending SQEs.
    pub fn sq_pending(&self) -> u32 {
        self.sq_tail.wrapping_sub(self.sq_head)
    }

    /// Return the number of available CQEs.
    pub fn cq_available(&self) -> u32 {
        self.cq_tail.wrapping_sub(self.cq_head)
    }

    /// Return available SQ slots.
    pub fn sq_free_slots(&self) -> u32 {
        self.capacity.saturating_sub(self.sq_pending())
    }

    /// Enqueue a CQE (for testing / stub completion).
    pub fn push_cqe(&mut self, cqe: Cqe) -> bool {
        if self.cq_available() >= self.capacity {
            return false;
        }
        let idx = (self.cq_tail as usize) % RING_SIZE;
        self.cqes[idx] = cqe;
        self.cq_tail = self.cq_tail.wrapping_add(1);
        true
    }

    /// Dequeue a CQE.
    pub fn pop_cqe(&mut self) -> Option<Cqe> {
        if self.cq_available() == 0 {
            return None;
        }
        let idx = (self.cq_head as usize) % RING_SIZE;
        let cqe = self.cqes[idx];
        self.cq_head = self.cq_head.wrapping_add(1);
        Some(cqe)
    }

    /// Process (consume) up to `count` pending SQEs.
    ///
    /// For each SQE, a synthetic CQE is generated immediately.
    /// Returns the number of SQEs processed.
    fn process_sqes(&mut self, count: u32) -> u32 {
        let pending = self.sq_pending();
        let to_process = count.min(pending);

        for _ in 0..to_process {
            let idx = (self.sq_head as usize) % RING_SIZE;
            let sqe = self.sqes[idx];
            self.sq_head = self.sq_head.wrapping_add(1);

            // Stub: synthesise a successful CQE.
            let cqe = Cqe {
                user_data: sqe.user_data,
                res: 0, // Success.
                flags: 0,
            };
            self.push_cqe(cqe);
        }

        to_process
    }
}

impl Default for RingState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Extended argument
// ---------------------------------------------------------------------------

/// Extended argument for `IORING_ENTER_EXT_ARG`.
///
/// Matches `struct io_uring_getevents_arg` from the Linux UAPI.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeteventsArg {
    /// Pointer to sigset_t (0 = use current mask).
    pub sigmask: u64,
    /// Size of the sigset_t.
    pub sigmask_sz: u32,
    /// Reserved (must be 0).
    pub pad: u32,
    /// Pointer to completion timeout `struct __kernel_timespec` (0 = none).
    pub ts: u64,
}

impl GeteventsArg {
    /// Create an empty, zeroed argument.
    pub const fn new() -> Self {
        Self {
            sigmask: 0,
            sigmask_sz: 0,
            pad: 0,
            ts: 0,
        }
    }
}

impl Default for GeteventsArg {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// EnterResult
// ---------------------------------------------------------------------------

/// Outcome of a single `io_uring_enter` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnterResult {
    /// Number of SQEs submitted.
    pub submitted: u32,
    /// Number of CQEs available after submission.
    pub cqes_ready: u32,
    /// Whether the SQ poll thread was woken.
    pub sq_woken: bool,
}

// ---------------------------------------------------------------------------
// do_sys_io_uring_enter — primary handler
// ---------------------------------------------------------------------------

/// `io_uring_enter(2)` syscall handler.
///
/// Submits up to `to_submit` SQEs and optionally waits for `min_complete`
/// CQEs to be available before returning.
///
/// # Arguments
///
/// * `ring`         — Mutable ring state.
/// * `to_submit`    — Number of SQEs to submit.
/// * `min_complete` — Minimum CQEs to wait for (only if `GETEVENTS` set).
/// * `flags`        — Enter flags.
/// * `ext_arg`      — Extended argument when `IORING_ENTER_EXT_ARG` is set.
///
/// # Returns
///
/// [`EnterResult`] with submission/completion counts.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Unknown flags or malformed `ext_arg`.
/// * [`Error::WouldBlock`]      — SQ ring full and `SQ_WAIT` timed out.
pub fn do_sys_io_uring_enter(
    ring: &mut RingState,
    to_submit: u32,
    min_complete: u32,
    flags: u32,
    ext_arg: Option<&GeteventsArg>,
) -> Result<EnterResult> {
    if flags & !FLAGS_MASK != 0 {
        return Err(Error::InvalidArgument);
    }

    // Validate ext_arg when EXT_ARG is set.
    if flags & IORING_ENTER_EXT_ARG != 0 {
        match ext_arg {
            None => return Err(Error::InvalidArgument),
            Some(a) if a.pad != 0 => return Err(Error::InvalidArgument),
            _ => {}
        }
    }

    // Optionally wake the SQ poll thread.
    let sq_woken = flags & IORING_ENTER_SQ_WAKEUP != 0;
    if sq_woken {
        // Stub: signal SQ poll thread wait-queue.
    }

    // If SQ_WAIT is set and the ring is full, we would block.
    // Model as a no-op (space always available in stub).
    if flags & IORING_ENTER_SQ_WAIT != 0 && ring.sq_free_slots() == 0 {
        return Err(Error::WouldBlock);
    }

    // Process submitted SQEs.
    let submitted = ring.process_sqes(to_submit);

    // If GETEVENTS is set, wait for min_complete CQEs.
    // In a real kernel this sleeps on the CQ wait-queue.
    // Stub: CQEs are generated synchronously above so no sleep needed.
    if flags & IORING_ENTER_GETEVENTS != 0 && min_complete > 0 {
        if ring.cq_available() < min_complete {
            // Would block waiting for completions.
            // Return what we have rather than modelling the sleep.
        }
    }

    Ok(EnterResult {
        submitted,
        cqes_ready: ring.cq_available(),
        sq_woken,
    })
}

/// Raw-argument entry point for the `io_uring_enter` syscall.
///
/// Accepts raw `u64` register values from the syscall dispatcher.
pub fn sys_io_uring_enter(
    ring: &mut RingState,
    to_submit: u64,
    min_complete: u64,
    flags: u64,
) -> Result<EnterResult> {
    let ts = u32::try_from(to_submit).map_err(|_| Error::InvalidArgument)?;
    let mc = u32::try_from(min_complete).map_err(|_| Error::InvalidArgument)?;
    let fl = u32::try_from(flags).map_err(|_| Error::InvalidArgument)?;
    do_sys_io_uring_enter(ring, ts, mc, fl, None)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_flags_submit_zero() {
        let mut ring = RingState::new();
        let r = do_sys_io_uring_enter(&mut ring, 0, 0, 0, None).unwrap();
        assert_eq!(r.submitted, 0);
        assert_eq!(r.cqes_ready, 0);
        assert!(!r.sq_woken);
    }

    #[test]
    fn invalid_flags_rejected() {
        let mut ring = RingState::new();
        assert_eq!(
            do_sys_io_uring_enter(&mut ring, 1, 0, 0xFFFF_FFFF, None),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn ext_arg_none_when_flag_set_rejected() {
        let mut ring = RingState::new();
        assert_eq!(
            do_sys_io_uring_enter(&mut ring, 0, 0, IORING_ENTER_EXT_ARG, None),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn ext_arg_nonzero_pad_rejected() {
        let mut ring = RingState::new();
        let bad = GeteventsArg {
            sigmask: 0,
            sigmask_sz: 0,
            pad: 1,
            ts: 0,
        };
        assert_eq!(
            do_sys_io_uring_enter(&mut ring, 0, 0, IORING_ENTER_EXT_ARG, Some(&bad)),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn ext_arg_valid() {
        let mut ring = RingState::new();
        let arg = GeteventsArg::new();
        let r = do_sys_io_uring_enter(&mut ring, 0, 0, IORING_ENTER_EXT_ARG, Some(&arg)).unwrap();
        assert_eq!(r.submitted, 0);
    }

    #[test]
    fn submit_generates_cqes() {
        let mut ring = RingState::new();
        // Manually push SQEs by advancing sq_tail.
        ring.sqes[0] = Sqe {
            opcode: 0,
            user_data: 42,
            ..Default::default()
        };
        ring.sq_tail = 1;

        let r = do_sys_io_uring_enter(&mut ring, 1, 0, 0, None).unwrap();
        assert_eq!(r.submitted, 1);
        assert_eq!(r.cqes_ready, 1);

        let cqe = ring.pop_cqe().unwrap();
        assert_eq!(cqe.user_data, 42);
        assert_eq!(cqe.res, 0);
    }

    #[test]
    fn sq_wakeup_flag() {
        let mut ring = RingState::new();
        let r = do_sys_io_uring_enter(&mut ring, 0, 0, IORING_ENTER_SQ_WAKEUP, None).unwrap();
        assert!(r.sq_woken);
    }

    #[test]
    fn getevents_flag_with_cqes() {
        let mut ring = RingState::new();
        // Push a synthetic CQE.
        ring.push_cqe(Cqe {
            user_data: 1,
            res: 0,
            flags: 0,
        });

        let r = do_sys_io_uring_enter(&mut ring, 0, 1, IORING_ENTER_GETEVENTS, None).unwrap();
        assert_eq!(r.cqes_ready, 1);
    }

    #[test]
    fn sq_wait_full_ring_returns_wouldblock() {
        let mut ring = RingState::new();
        // Fill the SQ ring completely.
        ring.sq_head = 0;
        ring.sq_tail = ring.capacity;

        assert_eq!(
            do_sys_io_uring_enter(&mut ring, 1, 0, IORING_ENTER_SQ_WAIT, None),
            Err(Error::WouldBlock)
        );
    }

    #[test]
    fn ring_state_pending_and_available() {
        let mut ring = RingState::new();
        assert_eq!(ring.sq_pending(), 0);
        assert_eq!(ring.cq_available(), 0);

        ring.sq_tail = 3;
        assert_eq!(ring.sq_pending(), 3);

        ring.push_cqe(Cqe::default());
        assert_eq!(ring.cq_available(), 1);
    }

    #[test]
    fn sqe_opcode_parse() {
        assert_eq!(SqeOpcode::from_u8(0), Some(SqeOpcode::Nop));
        assert_eq!(SqeOpcode::from_u8(1), Some(SqeOpcode::Readv));
        assert_eq!(SqeOpcode::from_u8(255), None);
    }
}
