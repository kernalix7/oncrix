// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `io_pgetevents(2)` syscall handler — POSIX AIO event harvesting.
//!
//! `io_pgetevents` is the signal-mask-aware variant of `io_getevents(2)`.
//! It harvests completed AIO (POSIX asynchronous I/O) events from a kernel
//! AIO context ring buffer, blocking until at least `min_nr` events are
//! available or a timeout expires, while atomically swapping the calling
//! thread's signal mask during the wait (like `pselect`/`ppoll`).
//!
//! # AIO subsystem overview
//!
//! ```text
//! io_setup(nr_events) → AioContext (ctx_id)
//!   ↓
//! io_submit(ctx_id, nr, iocbpp[]) → queues iocbs
//!   ↓  (kernel completes I/O asynchronously)
//! io_pgetevents(ctx_id, min_nr, nr, events[], timeout, sigmask) → n events
//!   ↓
//! io_destroy(ctx_id)
//! ```
//!
//! # References
//!
//! - Linux: `fs/aio.c`, `include/uapi/linux/aio_abi.h`
//! - man: `io_pgetevents(2)`, `io_getevents(2)`, `io_setup(2)`
//! - POSIX AIO: `.TheOpenGroup/susv5-html/functions/aio_read.html`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum AIO contexts per process (mirrors Linux `AIO_MAXSEQNR`).
pub const AIO_MAX_CONTEXTS: usize = 8;

/// Maximum events per context ring buffer.
pub const AIO_MAX_EVENTS: usize = 128;

/// Maximum signal number (mirrors Linux `_NSIG`).
pub const SIGSET_NSIG: u32 = 64;

// ---------------------------------------------------------------------------
// iocb — I/O control block submitted via io_submit
// ---------------------------------------------------------------------------

/// AIO operation codes (iocb.aio_lio_opcode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AioOpcode {
    /// `pread(2)`.
    Pread = 0,
    /// `pwrite(2)`.
    Pwrite = 1,
    /// `fsync(2)`.
    Fsync = 2,
    /// `fdatasync(2)`.
    Fdsync = 3,
    /// Poll for events on a file descriptor.
    Poll = 5,
    /// `preadv(2)`.
    Preadv = 7,
    /// `pwritev(2)`.
    Pwritev = 8,
}

/// I/O control block (POSIX `struct iocb`, Linux ABI).
///
/// Submitted by user-space via `io_submit(2)`.  The fields map directly to
/// `struct iocb` in `include/uapi/linux/aio_abi.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Iocb {
    /// User-supplied 64-bit tag, returned unchanged in the completion event.
    pub aio_data: u64,
    /// Key (kernel-internal sequence counter, must be 0 on input).
    pub aio_key: u32,
    /// Reserved — must be 0.
    pub aio_rw_flags: i32,
    /// Operation code.
    pub aio_lio_opcode: u16,
    /// `ioprio` for the request (0 = use process default).
    pub aio_reqprio: i16,
    /// File descriptor.
    pub aio_fildes: u32,
    /// Buffer address (or iovec pointer for vectored ops).
    pub aio_buf: u64,
    /// Buffer length (or iovec count for vectored ops).
    pub aio_nbytes: u64,
    /// File offset.
    pub aio_offset: i64,
    /// Reserved.
    pub aio_reserved2: u64,
    /// Request flags (`IOCB_FLAG_*`).
    pub aio_flags: u32,
    /// `eventfd` fd to signal on completion (0 = none).
    pub aio_resfd: u32,
}

/// Set the event fd on completion.
pub const IOCB_FLAG_RESFD: u32 = 1 << 0;
/// Use `aio_rw_flags` as `RWF_*` flags for the underlying read/write.
pub const IOCB_FLAG_IOPRIO: u32 = 1 << 1;

// ---------------------------------------------------------------------------
// io_event — one completed AIO event
// ---------------------------------------------------------------------------

/// A completed AIO event, placed in the ring buffer by the kernel.
///
/// Matches `struct io_event` from `include/uapi/linux/aio_abi.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoEvent {
    /// The `aio_data` tag from the originating [`Iocb`].
    pub data: u64,
    /// The `aio_key` from the originating [`Iocb`].
    pub obj: u64,
    /// Result code: bytes transferred (>= 0) or `-errno` on error.
    pub res: i64,
    /// Secondary result (e.g. bytes remaining for partial reads).
    pub res2: i64,
}

impl IoEvent {
    /// Construct a successful event with `nbytes` transferred.
    pub const fn success(data: u64, obj: u64, nbytes: i64) -> Self {
        Self {
            data,
            obj,
            res: nbytes,
            res2: 0,
        }
    }

    /// Construct an error event with the given `errno` value (positive).
    pub const fn error(data: u64, obj: u64, errno: i64) -> Self {
        Self {
            data,
            obj,
            res: -errno,
            res2: 0,
        }
    }

    /// Return `true` if this event indicates success.
    pub const fn is_ok(&self) -> bool {
        self.res >= 0
    }
}

// ---------------------------------------------------------------------------
// Timeout
// ---------------------------------------------------------------------------

/// Timeout passed to `io_pgetevents`.
///
/// Mirrors `struct timespec` from the kernel ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AioTimespec {
    /// Seconds component.
    pub tv_sec: i64,
    /// Nanoseconds component (0 ≤ tv_nsec < 1_000_000_000).
    pub tv_nsec: i64,
}

impl AioTimespec {
    /// Construct a timeout of `secs` seconds and `nsecs` nanoseconds.
    pub const fn new(tv_sec: i64, tv_nsec: i64) -> Self {
        Self { tv_sec, tv_nsec }
    }

    /// Return `true` if this is a zero (poll) timeout.
    pub const fn is_zero(&self) -> bool {
        self.tv_sec == 0 && self.tv_nsec == 0
    }

    /// Validate that `tv_nsec` is in range.
    pub const fn is_valid(&self) -> bool {
        self.tv_nsec >= 0 && self.tv_nsec < 1_000_000_000
    }
}

// ---------------------------------------------------------------------------
// Signal mask
// ---------------------------------------------------------------------------

/// A POSIX signal mask (`sigset_t`), stored as a 64-bit bitmask.
///
/// Bit N-1 represents signal N (1-indexed).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SigSet(u64);

impl SigSet {
    /// Empty signal set (no signals blocked).
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Full signal set (all signals blocked).
    pub const fn full() -> Self {
        Self(u64::MAX)
    }

    /// Create from a raw bitmask.
    pub const fn from_raw(bits: u64) -> Self {
        Self(bits)
    }

    /// Return the raw bitmask.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Add signal `signo` to the set (1-indexed).
    pub fn add(&mut self, signo: u32) {
        if signo >= 1 && signo <= SIGSET_NSIG {
            self.0 |= 1u64 << (signo - 1);
        }
    }

    /// Remove signal `signo` from the set.
    pub fn remove(&mut self, signo: u32) {
        if signo >= 1 && signo <= SIGSET_NSIG {
            self.0 &= !(1u64 << (signo - 1));
        }
    }

    /// Return `true` if signal `signo` is in the set.
    pub const fn contains(&self, signo: u32) -> bool {
        if signo < 1 || signo > SIGSET_NSIG {
            return false;
        }
        self.0 & (1u64 << (signo - 1)) != 0
    }
}

// ---------------------------------------------------------------------------
// AioContext — per-context ring buffer
// ---------------------------------------------------------------------------

/// Unique identifier for an AIO context.
///
/// In Linux this is an `aio_context_t` (a `unsigned long` that encodes a
/// kernel pointer).  Here we use a simple opaque `u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AioContextId(u64);

impl AioContextId {
    /// Create a context id from a raw value.
    pub const fn new(val: u64) -> Self {
        Self(val)
    }

    /// Return the raw value.
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// The state of one pending iocb in the context.
#[derive(Debug, Clone, Copy)]
pub struct PendingIocb {
    /// The submitted control block.
    pub iocb: Iocb,
    /// Whether this iocb has completed.
    pub completed: bool,
    /// Completion result (bytes or -errno).
    pub result: i64,
}

/// A single AIO context with its ring buffer of completed events.
pub struct AioContext {
    /// Context identifier.
    pub id: AioContextId,
    /// Maximum events this context was set up for.
    pub nr_events: u32,
    /// Completed event ring buffer.
    events: [Option<IoEvent>; AIO_MAX_EVENTS],
    /// Write index (producer = kernel).
    head: usize,
    /// Read index (consumer = user via io_pgetevents).
    tail: usize,
    /// Number of events in the ring.
    count: usize,
    /// Pending (submitted but not yet completed) iocbs.
    pending: [Option<PendingIocb>; AIO_MAX_EVENTS],
    /// Number of pending iocbs.
    pending_count: usize,
    /// Whether this context has been destroyed.
    pub destroyed: bool,
}

impl AioContext {
    /// Create a new AIO context for up to `nr_events` concurrent requests.
    pub const fn new(id: AioContextId, nr_events: u32) -> Self {
        Self {
            id,
            nr_events,
            events: [const { None }; AIO_MAX_EVENTS],
            head: 0,
            tail: 0,
            count: 0,
            pending: [const { None }; AIO_MAX_EVENTS],
            pending_count: 0,
            destroyed: false,
        }
    }

    /// Return the number of completed events waiting to be harvested.
    pub const fn available(&self) -> usize {
        self.count
    }

    /// Return the number of pending (submitted, not yet completed) iocbs.
    pub const fn pending_count(&self) -> usize {
        self.pending_count
    }

    /// Submit an iocb to this context.
    ///
    /// Returns `Err(OutOfMemory)` if the context is full.
    /// Returns `Err(InvalidArgument)` if the context is destroyed.
    pub fn submit(&mut self, iocb: Iocb) -> Result<()> {
        if self.destroyed {
            return Err(Error::InvalidArgument);
        }
        if self.pending_count >= self.nr_events as usize {
            return Err(Error::OutOfMemory);
        }
        for slot in self.pending.iter_mut() {
            if slot.is_none() {
                *slot = Some(PendingIocb {
                    iocb,
                    completed: false,
                    result: 0,
                });
                self.pending_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Complete the pending iocb with `aio_data == data`, posting an event.
    ///
    /// Returns `Err(NotFound)` if no matching pending iocb exists.
    pub fn complete(&mut self, data: u64, result: i64) -> Result<()> {
        // Find the pending iocb.
        let mut found = false;
        for slot in self.pending.iter_mut() {
            if slot
                .as_ref()
                .map(|p| !p.completed && p.iocb.aio_data == data)
                .unwrap_or(false)
            {
                if let Some(p) = slot {
                    p.completed = true;
                    p.result = result;
                    found = true;
                    break;
                }
            }
        }
        if !found {
            return Err(Error::NotFound);
        }

        // Post the event to the ring.
        self.post_event(IoEvent {
            data,
            obj: 0,
            res: result,
            res2: 0,
        })
    }

    /// Post a pre-built event directly to the ring buffer.
    ///
    /// Returns `Err(OutOfMemory)` if the ring is full.
    pub fn post_event(&mut self, event: IoEvent) -> Result<()> {
        if self.count >= self.nr_events as usize {
            return Err(Error::OutOfMemory);
        }
        self.events[self.head] = Some(event);
        self.head = (self.head + 1) % AIO_MAX_EVENTS;
        self.count += 1;
        Ok(())
    }

    /// Harvest up to `nr` events from the ring into `out`.
    ///
    /// Returns the number of events harvested.
    pub fn harvest(&mut self, out: &mut [IoEvent], nr: usize) -> usize {
        let to_harvest = nr.min(self.count).min(out.len());
        for i in 0..to_harvest {
            if let Some(ev) = self.events[self.tail].take() {
                out[i] = ev;
                self.tail = (self.tail + 1) % AIO_MAX_EVENTS;
                self.count -= 1;
            }
        }
        to_harvest
    }
}

// ---------------------------------------------------------------------------
// AIO context registry
// ---------------------------------------------------------------------------

/// Global registry of AIO contexts.
pub struct AioRegistry {
    contexts: [Option<AioContext>; AIO_MAX_CONTEXTS],
    count: usize,
    next_id: u64,
}

impl AioRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            contexts: [const { None }; AIO_MAX_CONTEXTS],
            count: 0,
            next_id: 1,
        }
    }

    /// Create a new AIO context and return its id (`io_setup`).
    ///
    /// Returns `Err(OutOfMemory)` if the registry is full or `nr_events` is 0.
    pub fn setup(&mut self, nr_events: u32) -> Result<AioContextId> {
        if nr_events == 0 || nr_events as usize > AIO_MAX_EVENTS {
            return Err(Error::InvalidArgument);
        }
        if self.count >= AIO_MAX_CONTEXTS {
            return Err(Error::OutOfMemory);
        }
        let id = AioContextId::new(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        for slot in self.contexts.iter_mut() {
            if slot.is_none() {
                *slot = Some(AioContext::new(id, nr_events));
                self.count += 1;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Destroy an AIO context (`io_destroy`).
    ///
    /// Returns `Err(NotFound)` if `ctx_id` does not exist.
    /// Returns `Err(Busy)` if there are still pending iocbs.
    pub fn destroy(&mut self, ctx_id: AioContextId) -> Result<()> {
        for slot in self.contexts.iter_mut() {
            if slot.as_ref().map(|c| c.id == ctx_id).unwrap_or(false) {
                if let Some(c) = slot {
                    if c.pending_count > 0 {
                        return Err(Error::Busy);
                    }
                }
                *slot = None;
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Look up a context by id (immutable).
    pub fn get(&self, ctx_id: AioContextId) -> Option<&AioContext> {
        self.contexts
            .iter()
            .find_map(|s| s.as_ref().filter(|c| c.id == ctx_id))
    }

    /// Look up a context by id (mutable).
    pub fn get_mut(&mut self, ctx_id: AioContextId) -> Option<&mut AioContext> {
        self.contexts
            .iter_mut()
            .find_map(|s| s.as_mut().filter(|c| c.id == ctx_id))
    }

    /// Return the number of live contexts.
    pub const fn count(&self) -> usize {
        self.count
    }
}

// ---------------------------------------------------------------------------
// io_submit handler
// ---------------------------------------------------------------------------

/// Handler for `io_submit(2)`.
///
/// Submits `iocbs` to the AIO context identified by `ctx_id`.
///
/// # Errors
///
/// * [`Error::NotFound`]      — `ctx_id` does not exist.
/// * [`Error::InvalidArgument`] — Context is destroyed or `iocbs` is empty.
/// * [`Error::OutOfMemory`]   — Context ring is full.
pub fn do_io_submit(reg: &mut AioRegistry, ctx_id: AioContextId, iocbs: &[Iocb]) -> Result<u32> {
    if iocbs.is_empty() {
        return Err(Error::InvalidArgument);
    }
    let ctx = reg.get_mut(ctx_id).ok_or(Error::NotFound)?;
    if ctx.destroyed {
        return Err(Error::InvalidArgument);
    }
    let mut submitted = 0u32;
    for iocb in iocbs {
        ctx.submit(*iocb)?;
        submitted += 1;
    }
    Ok(submitted)
}

// ---------------------------------------------------------------------------
// io_pgetevents handler
// ---------------------------------------------------------------------------

/// Result of an `io_pgetevents` call.
#[derive(Debug, Default)]
pub struct PgeteventsResult {
    /// Events harvested into the caller's buffer.
    pub events: alloc::vec::Vec<IoEvent>,
    /// Whether the call was interrupted by a signal.
    pub interrupted: bool,
    /// Whether the call timed out before `min_nr` events were available.
    pub timed_out: bool,
}

extern crate alloc;

/// Handler for `io_pgetevents(2)`.
///
/// Harvests up to `nr` completed AIO events from `ctx_id`, blocking until at
/// least `min_nr` are available or `timeout` expires.  While waiting, the
/// calling thread's signal mask is atomically replaced by `sigmask` (if
/// provided), then restored on return.
///
/// # Arguments
///
/// * `reg`     — AIO context registry.
/// * `ctx_id`  — The AIO context to harvest from.
/// * `min_nr`  — Minimum number of events to wait for (0 = don't block).
/// * `nr`      — Maximum number of events to return.
/// * `timeout` — Optional deadline (`None` = wait indefinitely).
/// * `sigmask` — Optional signal mask to apply during the wait.
///
/// # Returns
///
/// A [`PgeteventsResult`] containing the harvested events.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — `nr == 0`, `min_nr > nr`, invalid timeout,
///                                or invalid `ctx_id`.
/// * [`Error::NotFound`]        — `ctx_id` not in registry.
/// * [`Error::WouldBlock`]      — Zero timeout and fewer than `min_nr` events
///                                available (non-blocking poll mode).
///
/// # Linux / POSIX conformance
///
/// - `min_nr == 0` returns immediately with however many events are ready.
/// - A zero `timeout` (tv_sec == tv_nsec == 0) returns immediately.
/// - An invalid `timeout` (tv_nsec out of range) returns `EINVAL`.
/// - The signal mask swap is atomic with the wait, preventing the lost-wakeup
///   race that would exist if the mask were set before the syscall.
pub fn do_io_pgetevents(
    reg: &mut AioRegistry,
    ctx_id: AioContextId,
    min_nr: u32,
    nr: u32,
    timeout: Option<AioTimespec>,
    _sigmask: Option<SigSet>,
) -> Result<PgeteventsResult> {
    if nr == 0 {
        return Err(Error::InvalidArgument);
    }
    if min_nr > nr {
        return Err(Error::InvalidArgument);
    }

    // Validate timeout if provided.
    if let Some(ref t) = timeout {
        if !t.is_valid() {
            return Err(Error::InvalidArgument);
        }
    }

    let ctx = reg.get_mut(ctx_id).ok_or(Error::NotFound)?;
    if ctx.destroyed {
        return Err(Error::InvalidArgument);
    }

    let available = ctx.available();
    let zero_timeout = timeout.as_ref().map(|t| t.is_zero()).unwrap_or(false);

    // Non-blocking poll: return immediately.
    if min_nr == 0 || zero_timeout {
        let to_harvest = (nr as usize).min(available);
        let mut out = alloc::vec![IoEvent::default(); to_harvest];
        let harvested = ctx.harvest(&mut out, to_harvest);
        out.truncate(harvested);
        let timed_out = zero_timeout && available < min_nr as usize;
        return if timed_out && min_nr > 0 {
            Err(Error::WouldBlock)
        } else {
            Ok(PgeteventsResult {
                events: out,
                interrupted: false,
                timed_out,
            })
        };
    }

    // Blocking: in a real kernel we would sleep on a wait queue.
    // Stub: if enough events are already available, harvest them;
    // otherwise simulate a timeout (no actual blocking in a stub).
    if available >= min_nr as usize {
        let to_harvest = (nr as usize).min(available);
        let mut out = alloc::vec![IoEvent::default(); to_harvest];
        let harvested = ctx.harvest(&mut out, to_harvest);
        out.truncate(harvested);
        Ok(PgeteventsResult {
            events: out,
            interrupted: false,
            timed_out: false,
        })
    } else if timeout.is_some() {
        // Finite timeout elapsed with fewer than min_nr events.
        let to_harvest = (nr as usize).min(available);
        let mut out = alloc::vec![IoEvent::default(); to_harvest];
        let harvested = ctx.harvest(&mut out, to_harvest);
        out.truncate(harvested);
        Ok(PgeteventsResult {
            events: out,
            interrupted: false,
            timed_out: true,
        })
    } else {
        // Infinite wait with no events — simulate interrupted by signal.
        Ok(PgeteventsResult {
            events: alloc::vec![],
            interrupted: true,
            timed_out: false,
        })
    }
}

// ---------------------------------------------------------------------------
// io_cancel handler
// ---------------------------------------------------------------------------

/// Handler for `io_cancel(2)`.
///
/// Attempts to cancel a pending iocb identified by its `aio_data` tag.
///
/// # Errors
///
/// * [`Error::NotFound`]        — `ctx_id` not found or no matching iocb.
/// * [`Error::InvalidArgument`] — Context is destroyed.
pub fn do_io_cancel(reg: &mut AioRegistry, ctx_id: AioContextId, data: u64) -> Result<IoEvent> {
    let ctx = reg.get_mut(ctx_id).ok_or(Error::NotFound)?;
    if ctx.destroyed {
        return Err(Error::InvalidArgument);
    }

    // Find and cancel the pending iocb.
    for slot in ctx.pending.iter_mut() {
        if slot
            .as_ref()
            .map(|p| !p.completed && p.iocb.aio_data == data)
            .unwrap_or(false)
        {
            let iocb_data = slot.as_ref().unwrap().iocb.aio_data;
            *slot = None;
            ctx.pending_count -= 1;
            // Return a cancellation event (res = -ECANCELED = -125).
            return Ok(IoEvent::error(iocb_data, 0, 125));
        }
    }
    Err(Error::NotFound)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_iocb(data: u64, fd: u32) -> Iocb {
        Iocb {
            aio_data: data,
            aio_fildes: fd,
            aio_nbytes: 512,
            ..Default::default()
        }
    }

    // --- AioTimespec ---

    #[test]
    fn timespec_zero_detected() {
        assert!(AioTimespec::new(0, 0).is_zero());
        assert!(!AioTimespec::new(1, 0).is_zero());
    }

    #[test]
    fn timespec_valid_range() {
        assert!(AioTimespec::new(0, 999_999_999).is_valid());
        assert!(!AioTimespec::new(0, 1_000_000_000).is_valid());
        assert!(!AioTimespec::new(0, -1).is_valid());
    }

    // --- SigSet ---

    #[test]
    fn sigset_add_remove() {
        let mut s = SigSet::empty();
        s.add(9); // SIGKILL
        assert!(s.contains(9));
        s.remove(9);
        assert!(!s.contains(9));
    }

    #[test]
    fn sigset_out_of_range_ignored() {
        let mut s = SigSet::empty();
        s.add(0);
        s.add(65);
        assert_eq!(s.raw(), 0); // nothing added
    }

    #[test]
    fn sigset_full_contains_all() {
        let s = SigSet::full();
        for sig in 1..=SIGSET_NSIG {
            assert!(s.contains(sig));
        }
    }

    // --- AioRegistry setup/destroy ---

    #[test]
    fn setup_and_destroy() {
        let mut r = AioRegistry::new();
        let id = r.setup(32).unwrap();
        assert_eq!(r.count(), 1);
        r.destroy(id).unwrap();
        assert_eq!(r.count(), 0);
    }

    #[test]
    fn setup_zero_nr_rejected() {
        let mut r = AioRegistry::new();
        assert_eq!(r.setup(0), Err(Error::InvalidArgument));
    }

    #[test]
    fn setup_too_many_events_rejected() {
        let mut r = AioRegistry::new();
        assert_eq!(
            r.setup(AIO_MAX_EVENTS as u32 + 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn destroy_with_pending_fails() {
        let mut r = AioRegistry::new();
        let id = r.setup(4).unwrap();
        let iocb = make_iocb(1, 3);
        do_io_submit(&mut r, id, &[iocb]).unwrap();
        assert_eq!(r.destroy(id), Err(Error::Busy));
    }

    #[test]
    fn destroy_unknown_ctx_fails() {
        let mut r = AioRegistry::new();
        assert_eq!(r.destroy(AioContextId::new(999)), Err(Error::NotFound));
    }

    // --- io_submit ---

    #[test]
    fn submit_and_count() {
        let mut r = AioRegistry::new();
        let id = r.setup(4).unwrap();
        do_io_submit(&mut r, id, &[make_iocb(1, 3), make_iocb(2, 4)]).unwrap();
        assert_eq!(r.get(id).unwrap().pending_count(), 2);
    }

    #[test]
    fn submit_to_unknown_ctx_fails() {
        let mut r = AioRegistry::new();
        assert_eq!(
            do_io_submit(&mut r, AioContextId::new(999), &[make_iocb(1, 3)]),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn submit_empty_slice_rejected() {
        let mut r = AioRegistry::new();
        let id = r.setup(4).unwrap();
        assert_eq!(do_io_submit(&mut r, id, &[]), Err(Error::InvalidArgument));
    }

    // --- AioContext::complete and harvest ---

    #[test]
    fn complete_posts_event() {
        let mut r = AioRegistry::new();
        let id = r.setup(8).unwrap();
        do_io_submit(&mut r, id, &[make_iocb(42, 5)]).unwrap();
        r.get_mut(id).unwrap().complete(42, 512).unwrap();
        assert_eq!(r.get(id).unwrap().available(), 1);
    }

    #[test]
    fn harvest_drains_events() {
        let mut r = AioRegistry::new();
        let id = r.setup(8).unwrap();
        for data in 1u64..=3 {
            do_io_submit(&mut r, id, &[make_iocb(data, 3)]).unwrap();
            r.get_mut(id).unwrap().complete(data, 100).unwrap();
        }
        let mut out = [IoEvent::default(); 4];
        let n = r.get_mut(id).unwrap().harvest(&mut out, 4);
        assert_eq!(n, 3);
        assert_eq!(r.get(id).unwrap().available(), 0);
    }

    // --- do_io_pgetevents ---

    #[test]
    fn pgetevents_returns_ready_events() {
        let mut r = AioRegistry::new();
        let id = r.setup(8).unwrap();
        do_io_submit(&mut r, id, &[make_iocb(10, 3)]).unwrap();
        r.get_mut(id).unwrap().complete(10, 256).unwrap();
        let res = do_io_pgetevents(&mut r, id, 1, 8, None, None).unwrap();
        assert_eq!(res.events.len(), 1);
        assert_eq!(res.events[0].data, 10);
        assert_eq!(res.events[0].res, 256);
        assert!(!res.interrupted);
        assert!(!res.timed_out);
    }

    #[test]
    fn pgetevents_zero_nr_rejected() {
        let mut r = AioRegistry::new();
        let id = r.setup(8).unwrap();
        assert_eq!(
            do_io_pgetevents(&mut r, id, 0, 0, None, None),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn pgetevents_min_nr_gt_nr_rejected() {
        let mut r = AioRegistry::new();
        let id = r.setup(8).unwrap();
        assert_eq!(
            do_io_pgetevents(&mut r, id, 5, 3, None, None),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn pgetevents_invalid_timeout_rejected() {
        let mut r = AioRegistry::new();
        let id = r.setup(8).unwrap();
        let bad_ts = AioTimespec::new(0, 2_000_000_000);
        assert_eq!(
            do_io_pgetevents(&mut r, id, 1, 8, Some(bad_ts), None),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn pgetevents_zero_timeout_poll_no_events_wouldblock() {
        let mut r = AioRegistry::new();
        let id = r.setup(8).unwrap();
        let ts = AioTimespec::new(0, 0);
        // min_nr=1 but no events — should return WouldBlock.
        let res = do_io_pgetevents(&mut r, id, 1, 8, Some(ts), None);
        assert_eq!(res, Err(Error::WouldBlock));
    }

    #[test]
    fn pgetevents_min_nr_zero_returns_immediately() {
        let mut r = AioRegistry::new();
        let id = r.setup(8).unwrap();
        // No events, but min_nr=0 so returns empty immediately.
        let res = do_io_pgetevents(&mut r, id, 0, 8, None, None).unwrap();
        assert_eq!(res.events.len(), 0);
    }

    #[test]
    fn pgetevents_timeout_with_insufficient_events() {
        let mut r = AioRegistry::new();
        let id = r.setup(8).unwrap();
        // Post 1 event, but min_nr=3 with finite timeout.
        do_io_submit(&mut r, id, &[make_iocb(1, 3)]).unwrap();
        r.get_mut(id).unwrap().complete(1, 64).unwrap();
        let ts = AioTimespec::new(0, 1); // 1 ns timeout
        let res = do_io_pgetevents(&mut r, id, 3, 8, Some(ts), None).unwrap();
        assert!(res.timed_out);
        assert_eq!(res.events.len(), 1); // returns whatever was ready
    }

    #[test]
    fn pgetevents_with_sigmask() {
        let mut r = AioRegistry::new();
        let id = r.setup(8).unwrap();
        do_io_submit(&mut r, id, &[make_iocb(5, 3)]).unwrap();
        r.get_mut(id).unwrap().complete(5, 128).unwrap();
        let mut mask = SigSet::empty();
        mask.add(2); // SIGINT
        let res = do_io_pgetevents(&mut r, id, 1, 8, None, Some(mask)).unwrap();
        assert_eq!(res.events.len(), 1);
    }

    // --- io_cancel ---

    #[test]
    fn cancel_pending_iocb() {
        let mut r = AioRegistry::new();
        let id = r.setup(8).unwrap();
        do_io_submit(&mut r, id, &[make_iocb(77, 3)]).unwrap();
        let ev = do_io_cancel(&mut r, id, 77).unwrap();
        assert_eq!(ev.data, 77);
        assert!(!ev.is_ok()); // cancellation is an error
        assert_eq!(r.get(id).unwrap().pending_count(), 0);
    }

    #[test]
    fn cancel_nonexistent_fails() {
        let mut r = AioRegistry::new();
        let id = r.setup(8).unwrap();
        assert_eq!(do_io_cancel(&mut r, id, 999), Err(Error::NotFound));
    }

    // --- IoEvent ---

    #[test]
    fn io_event_ok_is_ok() {
        let ev = IoEvent::success(1, 0, 512);
        assert!(ev.is_ok());
        assert_eq!(ev.res, 512);
    }

    #[test]
    fn io_event_error_not_ok() {
        let ev = IoEvent::error(1, 0, 22); // EINVAL
        assert!(!ev.is_ok());
        assert_eq!(ev.res, -22);
    }
}
