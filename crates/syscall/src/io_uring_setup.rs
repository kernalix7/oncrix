// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! io_uring syscall handlers.
//!
//! Implements the Linux io_uring asynchronous I/O interface via three
//! syscalls: `io_uring_setup`, `io_uring_enter`, and `io_uring_register`.
//! io_uring provides a high-performance, kernel-bypass I/O submission and
//! completion mechanism using shared memory ring buffers between user space
//! and the kernel.
//!
//! The submission queue (SQ) and completion queue (CQ) are memory-mapped
//! ring buffers that allow batched, zero-copy I/O operations with minimal
//! system call overhead.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Setup flags — IORING_SETUP_*
// ---------------------------------------------------------------------------

/// Use I/O polling for completions instead of IRQ-driven.
/// The kernel will actively poll for I/O completions, reducing latency
/// at the cost of CPU utilization.
pub const IORING_SETUP_IOPOLL: u32 = 1 << 0;

/// Create a kernel-side submission queue polling thread.
/// The kernel thread will continuously poll the SQ for new entries,
/// eliminating the need for `io_uring_enter` calls to submit I/O.
pub const IORING_SETUP_SQPOLL: u32 = 1 << 1;

/// Bind the SQ polling thread to a specific CPU.
/// Requires `IORING_SETUP_SQPOLL`.  The `sq_thread_cpu` field in
/// [`IoUringParams`] specifies the target CPU.
pub const IORING_SETUP_SQ_AFF: u32 = 1 << 2;

/// Start the io_uring instance with a pre-sized CQ ring.
/// The `cq_entries` field in [`IoUringParams`] specifies the desired
/// completion queue size (must be a power of two).
pub const IORING_SETUP_CQSIZE: u32 = 1 << 3;

/// Clamp ring sizes to implementation limits rather than returning
/// `EINVAL` for oversized requests.
pub const IORING_SETUP_CLAMP: u32 = 1 << 4;

/// Attach this io_uring instance to an existing instance's work queue,
/// sharing the async worker thread pool.
pub const IORING_SETUP_ATTACH_WQ: u32 = 1 << 5;

/// Disable the ring entirely; must be re-enabled via
/// `IORING_REGISTER_ENABLE_RINGS` before use.
pub const IORING_SETUP_R_DISABLED: u32 = 1 << 6;

/// Allow submission from any task sharing the same memory context,
/// not just the task that created the ring.
pub const IORING_SETUP_SUBMIT_ALL: u32 = 1 << 7;

/// Use cooperative task scheduling for SQPOLL threads.
pub const IORING_SETUP_COOP_TASKRUN: u32 = 1 << 8;

/// Defer task work to the `io_uring_enter` call with
/// `IORING_ENTER_GETEVENTS` rather than signalling asynchronously.
pub const IORING_SETUP_TASKRUN_FLAG: u32 = 1 << 9;

/// Use a single issuer model — only one task submits to this ring.
pub const IORING_SETUP_SINGLE_ISSUER: u32 = 1 << 10;

/// Defer completion events until `io_uring_enter(GETEVENTS)`.
pub const IORING_SETUP_DEFER_TASKRUN: u32 = 1 << 11;

/// Mask of all valid setup flags.
const IORING_SETUP_VALID: u32 = IORING_SETUP_IOPOLL
    | IORING_SETUP_SQPOLL
    | IORING_SETUP_SQ_AFF
    | IORING_SETUP_CQSIZE
    | IORING_SETUP_CLAMP
    | IORING_SETUP_ATTACH_WQ
    | IORING_SETUP_R_DISABLED
    | IORING_SETUP_SUBMIT_ALL
    | IORING_SETUP_COOP_TASKRUN
    | IORING_SETUP_TASKRUN_FLAG
    | IORING_SETUP_SINGLE_ISSUER
    | IORING_SETUP_DEFER_TASKRUN;

// ---------------------------------------------------------------------------
// Feature flags — IORING_FEAT_*
// ---------------------------------------------------------------------------

/// Kernel supports single mmap for both SQ and CQ rings.
pub const IORING_FEAT_SINGLE_MMAP: u32 = 1 << 0;

/// Kernel supports non-default workers.
pub const IORING_FEAT_NODROP: u32 = 1 << 1;

/// Application can submit from mapped memory.
pub const IORING_FEAT_SUBMIT_STABLE: u32 = 1 << 2;

/// Supports read/write with non-registered fds.
pub const IORING_FEAT_RW_CUR_POS: u32 = 1 << 3;

/// Supports `IORING_OP_WRITE` with `O_APPEND`.
pub const IORING_FEAT_CUR_PERSONALITY: u32 = 1 << 4;

/// Supports fast poll.
pub const IORING_FEAT_FAST_POLL: u32 = 1 << 5;

/// Kernel supports poll-based 32-bit events.
pub const IORING_FEAT_POLL_32BITS: u32 = 1 << 6;

/// Features advertised by this implementation.
const ONCRIX_FEATURES: u32 = IORING_FEAT_SINGLE_MMAP
    | IORING_FEAT_NODROP
    | IORING_FEAT_SUBMIT_STABLE
    | IORING_FEAT_RW_CUR_POS
    | IORING_FEAT_FAST_POLL
    | IORING_FEAT_POLL_32BITS;

// ---------------------------------------------------------------------------
// Enter flags — IORING_ENTER_*
// ---------------------------------------------------------------------------

/// Wait for completions when entering.
pub const IORING_ENTER_GETEVENTS: u32 = 1 << 0;

/// Wake up the SQ polling thread.
pub const IORING_ENTER_SQ_WAKEUP: u32 = 1 << 1;

/// Wait for the SQ ring to have available entries.
pub const IORING_ENTER_SQ_WAIT: u32 = 1 << 2;

/// Use a registered ring fd.
pub const IORING_ENTER_EXT_ARG: u32 = 1 << 3;

/// Mask of all valid enter flags.
const IORING_ENTER_VALID: u32 =
    IORING_ENTER_GETEVENTS | IORING_ENTER_SQ_WAKEUP | IORING_ENTER_SQ_WAIT | IORING_ENTER_EXT_ARG;

// ---------------------------------------------------------------------------
// Register opcodes — IORING_REGISTER_*
// ---------------------------------------------------------------------------

/// Register user buffers for zero-copy I/O.
pub const IORING_REGISTER_BUFFERS: u32 = 0;

/// Unregister previously registered buffers.
pub const IORING_UNREGISTER_BUFFERS: u32 = 1;

/// Register file descriptors for indexed access.
pub const IORING_REGISTER_FILES: u32 = 2;

/// Unregister previously registered file descriptors.
pub const IORING_UNREGISTER_FILES: u32 = 3;

/// Register an eventfd for completion notification.
pub const IORING_REGISTER_EVENTFD: u32 = 4;

/// Unregister eventfd.
pub const IORING_UNREGISTER_EVENTFD: u32 = 5;

/// Register an eventfd for async completion notification.
pub const IORING_REGISTER_EVENTFD_ASYNC: u32 = 6;

/// Update registered file descriptors at specific indices.
pub const IORING_REGISTER_FILES_UPDATE: u32 = 7;

/// Register credentials for personality switching.
pub const IORING_REGISTER_PERSONALITY: u32 = 9;

/// Unregister a personality.
pub const IORING_UNREGISTER_PERSONALITY: u32 = 10;

/// Enable a disabled io_uring instance.
pub const IORING_REGISTER_ENABLE_RINGS: u32 = 11;

/// Register a range of fixed buffers.
pub const IORING_REGISTER_BUFFERS2: u32 = 15;

/// Update a range of fixed buffers.
pub const IORING_REGISTER_BUFFERS_UPDATE: u32 = 16;

/// Register file descriptors (v2 with tags).
pub const IORING_REGISTER_FILES2: u32 = 17;

/// Update file descriptors (v2).
pub const IORING_REGISTER_FILES_UPDATE2: u32 = 18;

// ---------------------------------------------------------------------------
// SQ ring offsets
// ---------------------------------------------------------------------------

/// Offsets into the submission queue ring mmap region.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IoSqringOffsets {
    /// Offset to the head counter.
    pub head: u32,
    /// Offset to the tail counter.
    pub tail: u32,
    /// Offset to the ring mask.
    pub ring_mask: u32,
    /// Offset to the ring entry count.
    pub ring_entries: u32,
    /// Offset to the SQ flags word.
    pub flags: u32,
    /// Offset to the dropped counter.
    pub dropped: u32,
    /// Offset to the SQE array.
    pub array: u32,
    /// Reserved for future use.
    pub resv1: u32,
    /// User address of the SQEs mmap region.
    pub user_addr: u64,
}

// ---------------------------------------------------------------------------
// CQ ring offsets
// ---------------------------------------------------------------------------

/// Offsets into the completion queue ring mmap region.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IoCqringOffsets {
    /// Offset to the head counter.
    pub head: u32,
    /// Offset to the tail counter.
    pub tail: u32,
    /// Offset to the ring mask.
    pub ring_mask: u32,
    /// Offset to the ring entry count.
    pub ring_entries: u32,
    /// Offset to the overflow counter.
    pub overflow: u32,
    /// Offset to the CQE array.
    pub cqes: u32,
    /// Offset to the CQ flags word.
    pub flags: u32,
    /// Reserved for future use.
    pub resv1: u32,
    /// User address of the CQEs mmap region.
    pub user_addr: u64,
}

// ---------------------------------------------------------------------------
// IoUringParams
// ---------------------------------------------------------------------------

/// Parameters for `io_uring_setup`.
///
/// Passed as input (desired configuration) and returned with kernel-filled
/// values (offsets, features, ring sizes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IoUringParams {
    /// Desired number of submission queue entries (must be power of 2).
    pub sq_entries: u32,
    /// Desired number of completion queue entries (must be power of 2).
    pub cq_entries: u32,
    /// Setup flags (`IORING_SETUP_*`).
    pub flags: u32,
    /// CPU to bind the SQ polling thread to (with `IORING_SETUP_SQ_AFF`).
    pub sq_thread_cpu: u32,
    /// Idle timeout in milliseconds for the SQ polling thread.
    pub sq_thread_idle: u32,
    /// Feature flags reported by the kernel (`IORING_FEAT_*`).
    pub features: u32,
    /// File descriptor of an existing ring to share its work queue.
    pub wq_fd: u32,
    /// Reserved words for future extension.
    pub resv: [u32; 3],
    /// Submission queue ring mmap offsets.
    pub sq_off: IoSqringOffsets,
    /// Completion queue ring mmap offsets.
    pub cq_off: IoCqringOffsets,
}

// ---------------------------------------------------------------------------
// SQE — Submission Queue Entry
// ---------------------------------------------------------------------------

/// Size of a single SQE in bytes.
pub const SQE_SIZE: usize = 64;

/// A submission queue entry describing one I/O operation.
///
/// The union-like layout encodes different operations; we use a flat
/// `#[repr(C)]` struct with the common fields.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IoUringSqe {
    /// Operation code (`IORING_OP_*`).
    pub opcode: u8,
    /// Flags for the SQE (`IOSQE_*`).
    pub flags: u8,
    /// I/O priority class.
    pub ioprio: u16,
    /// File descriptor (or fixed-file index).
    pub fd: i32,
    /// Offset into the file (or address for certain ops).
    pub off: u64,
    /// User-space buffer address (or splice offset).
    pub addr: u64,
    /// Length of the I/O operation in bytes.
    pub len: u32,
    /// Per-operation flags (e.g., `RWF_*`, open flags).
    pub op_flags: u32,
    /// Opaque user data returned in the CQE.
    pub user_data: u64,
    /// Buffer group / fixed-buffer index.
    pub buf_index: u16,
    /// Registered personality to use.
    pub personality: u16,
    /// Splice fd / file index for linked ops.
    pub splice_fd_in: i32,
    /// Padding to reach 64 bytes.
    pub _pad: [u64; 1],
}

// ---------------------------------------------------------------------------
// CQE — Completion Queue Entry
// ---------------------------------------------------------------------------

/// A completion queue entry reporting the result of an I/O operation.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IoUringCqe {
    /// User data from the corresponding SQE.
    pub user_data: u64,
    /// Result (number of bytes transferred, or negative errno).
    pub res: i32,
    /// Flags (e.g., `IORING_CQE_F_BUFFER`).
    pub flags: u32,
}

// ---------------------------------------------------------------------------
// Instance state
// ---------------------------------------------------------------------------

/// Maximum number of concurrent io_uring instances.
const MAX_RINGS: usize = 16;

/// Minimum SQ/CQ ring entries.
const MIN_ENTRIES: u32 = 1;

/// Maximum SQ entries.
const MAX_SQ_ENTRIES: u32 = 4096;

/// Maximum CQ entries.
const MAX_CQ_ENTRIES: u32 = 2 * MAX_SQ_ENTRIES;

/// Maximum registered buffers per ring.
const MAX_FIXED_BUFS: usize = 64;

/// Maximum registered files per ring.
const MAX_FIXED_FILES: usize = 64;

/// Internal state of a single io_uring instance.
#[derive(Debug, Clone, Copy)]
struct IoUringInstance {
    /// Whether this slot is in use.
    active: bool,
    /// Whether the ring is currently enabled (can accept submissions).
    enabled: bool,
    /// Setup flags from creation.
    flags: u32,
    /// Actual SQ entries (power of two).
    sq_entries: u32,
    /// Actual CQ entries (power of two).
    cq_entries: u32,
    /// SQ head pointer (kernel-side consumer).
    sq_head: u32,
    /// SQ tail pointer (user-side producer; cached here).
    sq_tail: u32,
    /// CQ head pointer (user-side consumer; cached here).
    cq_head: u32,
    /// CQ tail pointer (kernel-side producer).
    cq_tail: u32,
    /// Number of submissions pending processing.
    pending_submissions: u32,
    /// Number of completions ready for reaping.
    pending_completions: u32,
    /// Count of registered fixed buffers.
    nr_fixed_bufs: usize,
    /// Count of registered fixed files.
    nr_fixed_files: usize,
    /// Whether an eventfd is registered for notifications.
    eventfd_registered: bool,
    /// Registered eventfd descriptor.
    eventfd_fd: i32,
    /// Total submissions processed.
    total_submitted: u64,
    /// Total completions produced.
    total_completed: u64,
    /// Number of CQ overflows (completions dropped).
    cq_overflow: u64,
}

impl Default for IoUringInstance {
    fn default() -> Self {
        Self {
            active: false,
            enabled: false,
            flags: 0,
            sq_entries: 0,
            cq_entries: 0,
            sq_head: 0,
            sq_tail: 0,
            cq_head: 0,
            cq_tail: 0,
            pending_submissions: 0,
            pending_completions: 0,
            nr_fixed_bufs: 0,
            nr_fixed_files: 0,
            eventfd_registered: false,
            eventfd_fd: -1,
            total_submitted: 0,
            total_completed: 0,
            cq_overflow: 0,
        }
    }
}

/// Global registry of io_uring instances.
static mut RINGS: [IoUringInstance; MAX_RINGS] = {
    const EMPTY: IoUringInstance = IoUringInstance {
        active: false,
        enabled: false,
        flags: 0,
        sq_entries: 0,
        cq_entries: 0,
        sq_head: 0,
        sq_tail: 0,
        cq_head: 0,
        cq_tail: 0,
        pending_submissions: 0,
        pending_completions: 0,
        nr_fixed_bufs: 0,
        nr_fixed_files: 0,
        eventfd_registered: false,
        eventfd_fd: -1,
        total_submitted: 0,
        total_completed: 0,
        cq_overflow: 0,
    };
    [EMPTY; MAX_RINGS]
};

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Round `n` up to the next power of two.  Returns `n` unchanged if
/// it is already a power of two.  Returns `0` when `n == 0`.
fn next_power_of_two(n: u32) -> u32 {
    if n == 0 {
        return 0;
    }
    if n & (n - 1) == 0 {
        return n;
    }
    1u32 << (32 - (n - 1).leading_zeros())
}

/// Validate and clamp SQ entries.  If the `CLAMP` flag is set, oversized
/// values are clamped to the maximum.  Otherwise an error is returned.
fn validate_sq_entries(entries: u32, clamp: bool) -> Result<u32> {
    if entries < MIN_ENTRIES {
        return Err(Error::InvalidArgument);
    }
    if entries > MAX_SQ_ENTRIES {
        if clamp {
            return Ok(MAX_SQ_ENTRIES);
        }
        return Err(Error::InvalidArgument);
    }
    Ok(next_power_of_two(entries))
}

/// Validate and clamp CQ entries.  CQ must be at least as large as SQ.
fn validate_cq_entries(entries: u32, sq: u32, clamp: bool) -> Result<u32> {
    let want = if entries == 0 { 2 * sq } else { entries };
    if want < sq {
        return Err(Error::InvalidArgument);
    }
    if want > MAX_CQ_ENTRIES {
        if clamp {
            return Ok(MAX_CQ_ENTRIES);
        }
        return Err(Error::InvalidArgument);
    }
    Ok(next_power_of_two(want))
}

/// Locate a free slot in the ring registry.
fn alloc_ring_slot() -> Result<usize> {
    // SAFETY: single-threaded kernel init; no concurrent mutation.
    let rings = unsafe { &mut *core::ptr::addr_of_mut!(RINGS) };
    for (idx, ring) in rings.iter().enumerate() {
        if !ring.active {
            return Ok(idx);
        }
    }
    Err(Error::OutOfMemory)
}

/// Look up an active ring by fd (index).
fn get_ring(fd: i32) -> Result<&'static mut IoUringInstance> {
    if fd < 0 || (fd as usize) >= MAX_RINGS {
        return Err(Error::InvalidArgument);
    }
    // SAFETY: single-threaded kernel; bounds checked above.
    let rings = unsafe { &mut *core::ptr::addr_of_mut!(RINGS) };
    let ring = &mut rings[fd as usize];
    if !ring.active {
        return Err(Error::InvalidArgument);
    }
    Ok(ring)
}

/// Fill the SQ/CQ ring offsets in [`IoUringParams`] based on the
/// negotiated sizes.  These offsets describe where ring metadata
/// lives in the mmap'd region.
fn fill_offsets(params: &mut IoUringParams) {
    // SQ ring offsets (all relative to the SQ mmap base).
    params.sq_off = IoSqringOffsets {
        head: 0,
        tail: 4,
        ring_mask: 8,
        ring_entries: 12,
        flags: 16,
        dropped: 20,
        array: 24,
        resv1: 0,
        user_addr: 0,
    };

    // CQ ring offsets (all relative to the CQ mmap base).
    params.cq_off = IoCqringOffsets {
        head: 0,
        tail: 4,
        ring_mask: 8,
        ring_entries: 12,
        overflow: 16,
        cqes: 20,
        flags: 24,
        resv1: 0,
        user_addr: 0,
    };
}

// ---------------------------------------------------------------------------
// io_uring_setup
// ---------------------------------------------------------------------------

/// `io_uring_setup` — create a new io_uring instance.
///
/// Allocates an io_uring instance with the requested SQ and CQ ring
/// sizes.  On success the `params` structure is updated with negotiated
/// ring sizes, feature flags, and mmap offsets.
///
/// # Arguments
///
/// * `entries` — desired number of SQ entries (rounded up to power of 2)
/// * `params`  — in/out parameters structure
///
/// # Returns
///
/// A non-negative file descriptor (ring index) on success.
///
/// # Errors
///
/// * `InvalidArgument` — zero entries, invalid flags, or entries exceed
///   maximum (when `IORING_SETUP_CLAMP` is not set)
/// * `OutOfMemory` — no free io_uring slots available
pub fn sys_io_uring_setup(entries: u32, params: &mut IoUringParams) -> Result<i32> {
    // Reject unknown flags.
    if params.flags & !IORING_SETUP_VALID != 0 {
        return Err(Error::InvalidArgument);
    }

    // SQ_AFF without SQPOLL is meaningless.
    if params.flags & IORING_SETUP_SQ_AFF != 0 && params.flags & IORING_SETUP_SQPOLL == 0 {
        return Err(Error::InvalidArgument);
    }

    // DEFER_TASKRUN requires SINGLE_ISSUER.
    if params.flags & IORING_SETUP_DEFER_TASKRUN != 0
        && params.flags & IORING_SETUP_SINGLE_ISSUER == 0
    {
        return Err(Error::InvalidArgument);
    }

    let clamp = params.flags & IORING_SETUP_CLAMP != 0;
    let sq = validate_sq_entries(entries, clamp)?;

    let cq_requested = if params.flags & IORING_SETUP_CQSIZE != 0 {
        params.cq_entries
    } else {
        0
    };
    let cq = validate_cq_entries(cq_requested, sq, clamp)?;

    let slot = alloc_ring_slot()?;

    // SAFETY: slot is within bounds; single-threaded mutation.
    let rings = unsafe { &mut *core::ptr::addr_of_mut!(RINGS) };
    let ring = &mut rings[slot];

    ring.active = true;
    ring.enabled = params.flags & IORING_SETUP_R_DISABLED == 0;
    ring.flags = params.flags;
    ring.sq_entries = sq;
    ring.cq_entries = cq;
    ring.sq_head = 0;
    ring.sq_tail = 0;
    ring.cq_head = 0;
    ring.cq_tail = 0;
    ring.pending_submissions = 0;
    ring.pending_completions = 0;
    ring.nr_fixed_bufs = 0;
    ring.nr_fixed_files = 0;
    ring.eventfd_registered = false;
    ring.eventfd_fd = -1;
    ring.total_submitted = 0;
    ring.total_completed = 0;
    ring.cq_overflow = 0;

    // Fill output parameters.
    params.sq_entries = sq;
    params.cq_entries = cq;
    params.features = ONCRIX_FEATURES;
    fill_offsets(params);

    Ok(slot as i32)
}

// ---------------------------------------------------------------------------
// io_uring_enter
// ---------------------------------------------------------------------------

/// `io_uring_enter` — submit I/O requests and/or wait for completions.
///
/// # Arguments
///
/// * `fd`         — io_uring file descriptor (ring index)
/// * `to_submit`  — number of SQEs to submit from the SQ ring
/// * `min_complete` — minimum completions to wait for (when `GETEVENTS`)
/// * `flags`      — `IORING_ENTER_*` flags
///
/// # Returns
///
/// Number of SQEs successfully submitted.
///
/// # Errors
///
/// * `InvalidArgument` — invalid fd, invalid flags, or ring not enabled
/// * `Busy` — ring is disabled and cannot accept submissions
pub fn sys_io_uring_enter(fd: i32, to_submit: u32, min_complete: u32, flags: u32) -> Result<i32> {
    if flags & !IORING_ENTER_VALID != 0 {
        return Err(Error::InvalidArgument);
    }

    let ring = get_ring(fd)?;

    if !ring.enabled {
        return Err(Error::Busy);
    }

    let mut submitted = 0u32;

    // Process submissions.
    if to_submit > 0 {
        let available = ring.sq_entries.wrapping_sub(ring.pending_submissions);
        let count = if to_submit > available {
            available
        } else {
            to_submit
        };

        ring.sq_tail = ring.sq_tail.wrapping_add(count);
        ring.pending_submissions = ring.pending_submissions.wrapping_add(count);
        ring.total_submitted = ring.total_submitted.wrapping_add(count as u64);
        submitted = count;

        // Simulate immediate completion of submitted entries (stub).
        // A real implementation would queue the SQEs for async processing.
        let completable = count.min(ring.cq_entries.wrapping_sub(ring.pending_completions));
        ring.cq_tail = ring.cq_tail.wrapping_add(completable);
        ring.pending_completions = ring.pending_completions.wrapping_add(completable);
        ring.total_completed = ring.total_completed.wrapping_add(completable as u64);

        // Track overflows.
        let overflowed = count.saturating_sub(completable);
        ring.cq_overflow = ring.cq_overflow.wrapping_add(overflowed as u64);

        // Advance SQ head to indicate consumed entries.
        ring.sq_head = ring.sq_head.wrapping_add(count);
        ring.pending_submissions = ring.pending_submissions.saturating_sub(count);
    }

    // Handle GETEVENTS — wait for completions.
    if flags & IORING_ENTER_GETEVENTS != 0 {
        // Stub: reap available completions immediately.
        let reapable = ring.pending_completions.min(if min_complete > 0 {
            min_complete
        } else {
            ring.pending_completions
        });
        ring.cq_head = ring.cq_head.wrapping_add(reapable);
        ring.pending_completions = ring.pending_completions.saturating_sub(reapable);
    }

    // Handle SQ_WAKEUP — wake the SQPOLL thread.
    if flags & IORING_ENTER_SQ_WAKEUP != 0 {
        if ring.flags & IORING_SETUP_SQPOLL == 0 {
            return Err(Error::InvalidArgument);
        }
        // Stub: SQPOLL thread wake would happen here.
    }

    Ok(submitted as i32)
}

// ---------------------------------------------------------------------------
// io_uring_register
// ---------------------------------------------------------------------------

/// `io_uring_register` — register resources with an io_uring instance.
///
/// Registers or unregisters buffers, files, eventfds, or personalities
/// with the specified io_uring instance.
///
/// # Arguments
///
/// * `fd`     — io_uring file descriptor (ring index)
/// * `opcode` — `IORING_REGISTER_*` or `IORING_UNREGISTER_*` opcode
/// * `nr_args` — number of items (buffers, files) to register
///
/// # Returns
///
/// `0` on success, or a positive value for personality registration.
///
/// # Errors
///
/// * `InvalidArgument` — invalid fd, unknown opcode, or invalid nr_args
/// * `AlreadyExists` — resource already registered (e.g., duplicate eventfd)
/// * `NotFound` — unregister when nothing was registered
/// * `OutOfMemory` — too many registered resources
pub fn sys_io_uring_register(fd: i32, opcode: u32, nr_args: u32) -> Result<i32> {
    let ring = get_ring(fd)?;

    match opcode {
        IORING_REGISTER_BUFFERS => {
            if ring.nr_fixed_bufs > 0 {
                return Err(Error::AlreadyExists);
            }
            let count = nr_args as usize;
            if count == 0 || count > MAX_FIXED_BUFS {
                return Err(Error::InvalidArgument);
            }
            ring.nr_fixed_bufs = count;
            Ok(0)
        }
        IORING_UNREGISTER_BUFFERS => {
            if ring.nr_fixed_bufs == 0 {
                return Err(Error::NotFound);
            }
            ring.nr_fixed_bufs = 0;
            Ok(0)
        }
        IORING_REGISTER_FILES | IORING_REGISTER_FILES2 => {
            if ring.nr_fixed_files > 0 {
                return Err(Error::AlreadyExists);
            }
            let count = nr_args as usize;
            if count == 0 || count > MAX_FIXED_FILES {
                return Err(Error::InvalidArgument);
            }
            ring.nr_fixed_files = count;
            Ok(0)
        }
        IORING_UNREGISTER_FILES => {
            if ring.nr_fixed_files == 0 {
                return Err(Error::NotFound);
            }
            ring.nr_fixed_files = 0;
            Ok(0)
        }
        IORING_REGISTER_FILES_UPDATE | IORING_REGISTER_FILES_UPDATE2 => {
            if ring.nr_fixed_files == 0 {
                return Err(Error::NotFound);
            }
            if nr_args as usize > ring.nr_fixed_files {
                return Err(Error::InvalidArgument);
            }
            Ok(0)
        }
        IORING_REGISTER_BUFFERS2 => {
            if ring.nr_fixed_bufs > 0 {
                return Err(Error::AlreadyExists);
            }
            let count = nr_args as usize;
            if count == 0 || count > MAX_FIXED_BUFS {
                return Err(Error::InvalidArgument);
            }
            ring.nr_fixed_bufs = count;
            Ok(0)
        }
        IORING_REGISTER_BUFFERS_UPDATE => {
            if ring.nr_fixed_bufs == 0 {
                return Err(Error::NotFound);
            }
            if nr_args as usize > ring.nr_fixed_bufs {
                return Err(Error::InvalidArgument);
            }
            Ok(0)
        }
        IORING_REGISTER_EVENTFD | IORING_REGISTER_EVENTFD_ASYNC => {
            if ring.eventfd_registered {
                return Err(Error::AlreadyExists);
            }
            if nr_args != 1 {
                return Err(Error::InvalidArgument);
            }
            ring.eventfd_registered = true;
            ring.eventfd_fd = 0; // Placeholder fd.
            Ok(0)
        }
        IORING_UNREGISTER_EVENTFD => {
            if !ring.eventfd_registered {
                return Err(Error::NotFound);
            }
            ring.eventfd_registered = false;
            ring.eventfd_fd = -1;
            Ok(0)
        }
        IORING_REGISTER_PERSONALITY => {
            // Return a personality ID (stub: always 1).
            Ok(1)
        }
        IORING_UNREGISTER_PERSONALITY => {
            if nr_args == 0 {
                return Err(Error::InvalidArgument);
            }
            Ok(0)
        }
        IORING_REGISTER_ENABLE_RINGS => {
            if ring.enabled {
                return Err(Error::AlreadyExists);
            }
            ring.enabled = true;
            Ok(0)
        }
        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// Teardown
// ---------------------------------------------------------------------------

/// Destroy an io_uring instance and release its slot.
///
/// # Arguments
///
/// * `fd` — io_uring file descriptor (ring index) to destroy
///
/// # Errors
///
/// * `InvalidArgument` — invalid or inactive ring fd
pub fn sys_io_uring_destroy(fd: i32) -> Result<()> {
    let ring = get_ring(fd)?;
    ring.active = false;
    ring.enabled = false;
    ring.flags = 0;
    ring.sq_entries = 0;
    ring.cq_entries = 0;
    ring.sq_head = 0;
    ring.sq_tail = 0;
    ring.cq_head = 0;
    ring.cq_tail = 0;
    ring.pending_submissions = 0;
    ring.pending_completions = 0;
    ring.nr_fixed_bufs = 0;
    ring.nr_fixed_files = 0;
    ring.eventfd_registered = false;
    ring.eventfd_fd = -1;
    ring.total_submitted = 0;
    ring.total_completed = 0;
    ring.cq_overflow = 0;
    Ok(())
}

// ---------------------------------------------------------------------------
// Query helpers
// ---------------------------------------------------------------------------

/// Query the current state of an io_uring instance.
///
/// Returns `(pending_submissions, pending_completions, cq_overflow)`.
///
/// # Errors
///
/// * `InvalidArgument` — invalid or inactive ring fd
pub fn sys_io_uring_query(fd: i32) -> Result<(u32, u32, u64)> {
    let ring = get_ring(fd)?;
    Ok((
        ring.pending_submissions,
        ring.pending_completions,
        ring.cq_overflow,
    ))
}

/// Query total submission and completion counts.
///
/// Returns `(total_submitted, total_completed)`.
///
/// # Errors
///
/// * `InvalidArgument` — invalid or inactive ring fd
pub fn sys_io_uring_stats(fd: i32) -> Result<(u64, u64)> {
    let ring = get_ring(fd)?;
    Ok((ring.total_submitted, ring.total_completed))
}
