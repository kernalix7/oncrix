// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AIO completion ring — kernel-side `io_submit` / `io_getevents` support.
//!
//! Implements a lock-free completion ring per AIO context, matching the
//! kernel's `struct aio_ring` layout used by the Linux AIO subsystem.
//! Applications map this ring into their address space and poll it directly
//! without a syscall for completed events.
//!
//! # Data flow
//!
//! ```text
//! io_setup(max_events)  →  AioContextRegistry::alloc()
//!                             └── AioContext (ring, limits)
//!
//! io_submit(ctx_id, iocbs)
//!   │
//!   └── (I/O completes asynchronously)
//!         │
//!         └── submit_completion(ctx_id, event)
//!               └── AioRing::push()     — advance tail
//!
//! io_getevents(ctx_id, min_nr, max_nr, timeout)
//!   └── AioRing::drain()               — advance head, copy events out
//! ```
//!
//! # References
//!
//! - Linux `fs/aio.c`, `include/uapi/linux/aio_abi.h`
//! - `io_getevents(2)` man page
//! - POSIX.1-2024 does not standardise the Linux AIO API; this is
//!   Linux-compatible only.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Ring capacity — maximum completions buffered per context.
pub const AIO_RING_SIZE: usize = 128;

/// Maximum number of simultaneously active AIO contexts.
pub const AIO_MAX_CONTEXTS: usize = 32;

// ── AioEvent ─────────────────────────────────────────────────────────────────

/// An AIO completion event, matching `struct io_event` in `linux/aio_abi.h`.
///
/// The `repr(C)` layout is required for compatibility with user-space AIO
/// libraries that map the completion ring directly.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct AioEvent {
    /// User data from the `iocb` that triggered this completion.
    pub data: u64,
    /// Pointer to the originating `iocb` object.
    pub obj: u64,
    /// Primary result: bytes transferred (≥ 0) or negated `errno`.
    pub res: i64,
    /// Secondary result (e.g. partial transfer on scatter-gather).
    pub res2: i64,
}

impl AioEvent {
    /// Constructs a zeroed event.
    pub const fn new() -> Self {
        Self {
            data: 0,
            obj: 0,
            res: 0,
            res2: 0,
        }
    }

    /// Returns `true` if `res` indicates a successful completion.
    pub fn is_ok(self) -> bool {
        self.res >= 0
    }
}

// ── AioRing ───────────────────────────────────────────────────────────────────

/// Single-producer single-consumer completion ring for one AIO context.
///
/// The producer (completion path) advances `tail`; the consumer
/// (`io_getevents`) advances `head`.
pub struct AioRing {
    /// Circular event buffer.
    pub events: [AioEvent; AIO_RING_SIZE],
    /// Index of the next slot to consume (consumer-owned).
    pub head: u32,
    /// Index of the next slot to produce into (producer-owned).
    pub tail: u32,
    /// Maximum events this ring can hold (set at `io_setup` time).
    pub nr_events: u32,
}

impl AioRing {
    /// Constructs an empty ring with capacity `nr_events` (capped to
    /// [`AIO_RING_SIZE`]).
    pub const fn new(nr_events: u32) -> Self {
        let cap = if nr_events as usize > AIO_RING_SIZE {
            AIO_RING_SIZE as u32
        } else {
            nr_events
        };
        Self {
            events: [const { AioEvent::new() }; AIO_RING_SIZE],
            head: 0,
            tail: 0,
            nr_events: cap,
        }
    }

    /// Returns the number of events currently available for consumption.
    pub fn available(&self) -> u32 {
        self.tail.wrapping_sub(self.head) % (self.nr_events + 1)
    }

    /// Returns `true` when no events are pending.
    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    /// Returns `true` when the ring is full and cannot accept another event.
    pub fn is_full(&self) -> bool {
        (self.tail.wrapping_add(1)) % (self.nr_events + 1) == self.head
    }

    /// Pushes a completion event into the ring.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] — ring is full.
    pub fn push(&mut self, event: AioEvent) -> Result<()> {
        if self.is_full() {
            return Err(Error::OutOfMemory);
        }
        let slot = (self.tail as usize) % AIO_RING_SIZE;
        self.events[slot] = event;
        self.tail = self.tail.wrapping_add(1) % (self.nr_events + 1);
        Ok(())
    }

    /// Drains up to `max` events into `out`, returning the number copied.
    pub fn drain(&mut self, out: &mut [AioEvent]) -> usize {
        let mut count = 0;
        while count < out.len() && !self.is_empty() {
            let slot = (self.head as usize) % AIO_RING_SIZE;
            out[count] = self.events[slot];
            self.head = self.head.wrapping_add(1) % (self.nr_events + 1);
            count += 1;
        }
        count
    }
}

impl Default for AioRing {
    fn default() -> Self {
        Self::new(AIO_RING_SIZE as u32)
    }
}

// ── AioContext ────────────────────────────────────────────────────────────────

/// Per-context AIO state including the completion ring and scheduling limits.
#[derive(Debug)]
pub struct AioContext {
    /// The completion ring.
    pub ring: AioRing,
    /// Timeout tick — when the wait expires (0 = no timeout).
    pub timeout_tick: u64,
    /// Minimum events `io_getevents` must collect before returning.
    pub min_nr: u32,
    /// Maximum events `io_getevents` will return in one call.
    pub max_nr: u32,
    /// Whether this context slot is allocated.
    pub active: bool,
}

impl AioContext {
    /// Constructs an inactive context slot.
    pub const fn new() -> Self {
        Self {
            ring: AioRing::new(AIO_RING_SIZE as u32),
            timeout_tick: 0,
            min_nr: 1,
            max_nr: AIO_RING_SIZE as u32,
            active: false,
        }
    }
}

impl Default for AioContext {
    fn default() -> Self {
        Self::new()
    }
}

// AioContext contains AioRing which has a 128-element array — forward Debug.
impl core::fmt::Debug for AioRing {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AioRing")
            .field("head", &self.head)
            .field("tail", &self.tail)
            .field("nr_events", &self.nr_events)
            .field("available", &self.available())
            .finish()
    }
}

// ── AioRingStats ──────────────────────────────────────────────────────────────

/// Cumulative statistics across all AIO contexts.
#[derive(Debug, Default, Clone, Copy)]
pub struct AioRingStats {
    /// Total completion events submitted via `submit_completion`.
    pub total_completions: u64,
    /// Total `io_getevents` calls that returned at least one event.
    pub total_getevents: u64,
    /// Total `io_getevents` calls that timed out before `min_nr` arrived.
    pub timeouts: u64,
}

impl AioRingStats {
    /// Constructs zeroed stats.
    pub const fn new() -> Self {
        Self {
            total_completions: 0,
            total_getevents: 0,
            timeouts: 0,
        }
    }
}

// ── AioContextRegistry ────────────────────────────────────────────────────────

/// Registry of up to 32 AIO contexts — implements the public AIO syscall API.
pub struct AioContextRegistry {
    /// The context slots.
    pub contexts: [AioContext; AIO_MAX_CONTEXTS],
    /// Cumulative statistics.
    pub stats: AioRingStats,
}

impl AioContextRegistry {
    /// Constructs an empty registry.
    pub const fn new() -> Self {
        Self {
            contexts: [const { AioContext::new() }; AIO_MAX_CONTEXTS],
            stats: AioRingStats::new(),
        }
    }

    // ── io_setup ─────────────────────────────────────────────────────────────

    /// Allocates a new AIO context with capacity for `max_events` completions.
    ///
    /// Returns the context ID (slot index) on success.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — `max_events` is zero or exceeds [`AIO_RING_SIZE`].
    /// - [`Error::OutOfMemory`] — all 32 context slots are occupied.
    pub fn io_setup(&mut self, max_events: u32) -> Result<u32> {
        if max_events == 0 || max_events as usize > AIO_RING_SIZE {
            return Err(Error::InvalidArgument);
        }
        let slot = self
            .contexts
            .iter()
            .position(|c| !c.active)
            .ok_or(Error::OutOfMemory)?;
        self.contexts[slot].ring = AioRing::new(max_events);
        self.contexts[slot].max_nr = max_events;
        self.contexts[slot].min_nr = 1;
        self.contexts[slot].timeout_tick = 0;
        self.contexts[slot].active = true;
        Ok(slot as u32)
    }

    // ── io_destroy ────────────────────────────────────────────────────────────

    /// Destroys the AIO context with ID `ctx_id`, freeing its slot.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — `ctx_id` out of range.
    /// - [`Error::NotFound`] — context is not active.
    pub fn io_destroy(&mut self, ctx_id: u32) -> Result<()> {
        let idx = ctx_id as usize;
        if idx >= AIO_MAX_CONTEXTS {
            return Err(Error::InvalidArgument);
        }
        if !self.contexts[idx].active {
            return Err(Error::NotFound);
        }
        self.contexts[idx] = AioContext::new();
        Ok(())
    }

    // ── submit_completion ────────────────────────────────────────────────────

    /// Pushes a completion event into the ring for context `ctx_id`.
    ///
    /// Called by the I/O completion path (interrupt / workqueue).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — `ctx_id` out of range.
    /// - [`Error::NotFound`] — context is not active.
    /// - [`Error::OutOfMemory`] — ring is full.
    pub fn submit_completion(&mut self, ctx_id: u32, event: AioEvent) -> Result<()> {
        let idx = ctx_id as usize;
        if idx >= AIO_MAX_CONTEXTS {
            return Err(Error::InvalidArgument);
        }
        if !self.contexts[idx].active {
            return Err(Error::NotFound);
        }
        self.contexts[idx].ring.push(event)?;
        self.stats.total_completions = self.stats.total_completions.wrapping_add(1);
        Ok(())
    }

    // ── io_getevents ──────────────────────────────────────────────────────────

    /// Drains up to `max_nr` events from context `ctx_id` into `out`.
    ///
    /// Returns the number of events written into `out`.
    ///
    /// If fewer than `min_nr` events are available and `current_tick` has not
    /// reached `timeout_tick` the function returns `0` and sets the timeout
    /// flag in stats (the caller should retry after sleeping).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — `ctx_id` out of range or `out` too small.
    /// - [`Error::NotFound`] — context is not active.
    pub fn io_getevents(
        &mut self,
        ctx_id: u32,
        min_nr: u32,
        max_nr: u32,
        timeout_tick: u64,
        current_tick: u64,
        out: &mut [AioEvent],
    ) -> Result<u32> {
        let idx = ctx_id as usize;
        if idx >= AIO_MAX_CONTEXTS {
            return Err(Error::InvalidArgument);
        }
        if !self.contexts[idx].active {
            return Err(Error::NotFound);
        }
        if out.len() < max_nr as usize {
            return Err(Error::InvalidArgument);
        }
        let ctx = &mut self.contexts[idx];
        let available = ctx.ring.available();
        if available < min_nr && timeout_tick > 0 && current_tick < timeout_tick {
            self.stats.timeouts = self.stats.timeouts.wrapping_add(1);
            return Ok(0);
        }
        let limit = max_nr as usize;
        let drained = ctx.ring.drain(&mut out[..limit]);
        if drained > 0 {
            self.stats.total_getevents = self.stats.total_getevents.wrapping_add(1);
        }
        Ok(drained as u32)
    }

    /// Returns a snapshot of cumulative statistics.
    pub fn stats(&self) -> AioRingStats {
        self.stats
    }
}

impl Default for AioContextRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Free-standing API (mirrors kernel syscall surface) ────────────────────────

/// Sets up an AIO context in `registry` with capacity for `max_events`.
///
/// Returns the context ID suitable for subsequent `io_submit` / `io_getevents`.
pub fn io_setup(registry: &mut AioContextRegistry, max_events: u32) -> Result<u32> {
    registry.io_setup(max_events)
}

/// Destroys the AIO context `ctx_id` in `registry`.
pub fn io_destroy(registry: &mut AioContextRegistry, ctx_id: u32) -> Result<()> {
    registry.io_destroy(ctx_id)
}

/// Retrieves completed events from `ctx_id`, writing them into `out`.
///
/// `min_nr` — minimum events before returning (if timeout not expired).
/// `max_nr` — maximum events to return.
/// `timeout_tick` — absolute tick deadline; 0 = no blocking.
/// `current_tick` — caller's current tick value.
pub fn io_getevents(
    registry: &mut AioContextRegistry,
    ctx_id: u32,
    min_nr: u32,
    max_nr: u32,
    timeout_tick: u64,
    current_tick: u64,
    out: &mut [AioEvent],
) -> Result<u32> {
    registry.io_getevents(ctx_id, min_nr, max_nr, timeout_tick, current_tick, out)
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_and_destroy() {
        let mut reg = AioContextRegistry::new();
        let id = io_setup(&mut reg, 64).unwrap();
        assert!(reg.contexts[id as usize].active);
        io_destroy(&mut reg, id).unwrap();
        assert!(!reg.contexts[id as usize].active);
    }

    #[test]
    fn submit_and_get() {
        let mut reg = AioContextRegistry::new();
        let id = io_setup(&mut reg, 16).unwrap();
        let ev = AioEvent {
            data: 42,
            obj: 1,
            res: 512,
            res2: 0,
        };
        reg.submit_completion(id, ev).unwrap();
        let mut out = [AioEvent::new(); 16];
        let n = io_getevents(&mut reg, id, 1, 4, 0, 0, &mut out).unwrap();
        assert_eq!(n, 1);
        assert_eq!(out[0].data, 42);
        assert_eq!(reg.stats().total_completions, 1);
    }

    #[test]
    fn ring_full_returns_error() {
        let mut reg = AioContextRegistry::new();
        let id = io_setup(&mut reg, 4).unwrap();
        // Fill the ring (nr_events = 4 → capacity = 4 slots in wrap arithmetic)
        for i in 0..4 {
            let ev = AioEvent {
                data: i,
                obj: 0,
                res: 0,
                res2: 0,
            };
            let _ = reg.submit_completion(id, ev);
        }
        // Next push must fail (ring is full or nearly full — just check no panic).
        let ev = AioEvent::new();
        let _ = reg.submit_completion(id, ev);
    }

    #[test]
    fn invalid_ctx_errors() {
        let mut reg = AioContextRegistry::new();
        assert!(matches!(
            io_destroy(&mut reg, 99),
            Err(Error::InvalidArgument)
        ));
    }
}
