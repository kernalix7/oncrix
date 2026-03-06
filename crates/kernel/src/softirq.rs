// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Soft interrupt (softirq) processing — deferred interrupt bottom-halves.
//!
//! Softirqs are the lowest-latency mechanism for deferring work out of
//! hardware interrupt context.  Each softirq type is statically registered
//! and runs with interrupts enabled but at elevated priority relative to
//! normal kernel threads.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                    SoftirqSubsystem                          │
//! │                                                              │
//! │  SoftirqEntry[0..NR_SOFTIRQS]  (global handler table)       │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  handler: Option<SoftirqFn>                            │  │
//! │  │  count:   u64                                          │  │
//! │  │  total_time_ticks: u64                                 │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  SoftirqState[0..MAX_CPUS]  (per-CPU runtime state)         │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  pending: u32          — bitmask of raised softirqs    │  │
//! │  │  running: bool         — currently processing?         │  │
//! │  │  iteration_count: u32  — iterations this invocation    │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  SoftirqStats (global counters)                              │
//! │  - total_raised, total_processed, max_latency_ticks          │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Livelock Prevention
//!
//! Each invocation of `process_softirqs` runs at most
//! [`MAX_SOFTIRQ_RESTART`] iterations.  If softirqs are still pending
//! after that limit, the subsystem signals that ksoftirqd should be
//! woken to drain the remaining work at normal thread priority.
//!
//! # Reference
//!
//! Linux `kernel/softirq.c`, `include/linux/interrupt.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Number of statically-defined softirq vectors (matches Linux).
const NR_SOFTIRQS: usize = 10;

/// Maximum CPUs supported.
const MAX_CPUS: usize = 64;

/// Maximum iterations per `process_softirqs` invocation before
/// deferring to ksoftirqd.  Prevents livelock when softirqs are
/// continuously re-raised.
const MAX_SOFTIRQ_RESTART: u32 = 10;

// ══════════════════════════════════════════════════════════════
// SoftirqType
// ══════════════════════════════════════════════════════════════

/// Enumeration of all softirq vectors.
///
/// The numeric value of each variant is its index into the handler
/// table and its bit position in the per-CPU pending bitmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SoftirqType {
    /// High-priority tasklets (HI_SOFTIRQ).
    Hi = 0,
    /// Timer expiry processing (TIMER_SOFTIRQ).
    Timer = 1,
    /// Network transmit completion (NET_TX_SOFTIRQ).
    NetTx = 2,
    /// Network receive processing (NET_RX_SOFTIRQ).
    NetRx = 3,
    /// Block device completion (BLOCK_SOFTIRQ).
    Block = 4,
    /// IRQ poll processing (IRQ_POLL_SOFTIRQ).
    IrqPoll = 5,
    /// Normal-priority tasklets (TASKLET_SOFTIRQ).
    Tasklet = 6,
    /// Scheduler balancing (SCHED_SOFTIRQ).
    Sched = 7,
    /// High-resolution timer expiry (HRTIMER_SOFTIRQ).
    Hrtimer = 8,
    /// RCU callback processing (RCU_SOFTIRQ).
    Rcu = 9,
}

impl SoftirqType {
    /// Convert a raw index (0..NR_SOFTIRQS) to a `SoftirqType`.
    ///
    /// Returns `None` if the index is out of range.
    pub const fn from_index(idx: u8) -> Option<Self> {
        match idx {
            0 => Some(Self::Hi),
            1 => Some(Self::Timer),
            2 => Some(Self::NetTx),
            3 => Some(Self::NetRx),
            4 => Some(Self::Block),
            5 => Some(Self::IrqPoll),
            6 => Some(Self::Tasklet),
            7 => Some(Self::Sched),
            8 => Some(Self::Hrtimer),
            9 => Some(Self::Rcu),
            _ => None,
        }
    }

    /// Return the bit mask for this softirq type.
    pub const fn mask(self) -> u32 {
        1u32 << (self as u8)
    }

    /// Display name for diagnostic output.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Hi => "HI",
            Self::Timer => "TIMER",
            Self::NetTx => "NET_TX",
            Self::NetRx => "NET_RX",
            Self::Block => "BLOCK",
            Self::IrqPoll => "IRQ_POLL",
            Self::Tasklet => "TASKLET",
            Self::Sched => "SCHED",
            Self::Hrtimer => "HRTIMER",
            Self::Rcu => "RCU",
        }
    }
}

// ══════════════════════════════════════════════════════════════
// SoftirqFn — handler signature
// ══════════════════════════════════════════════════════════════

/// Softirq handler function signature.
///
/// The handler receives an opaque context value that was registered
/// together with the handler.
pub type SoftirqFn = fn(u64);

// ══════════════════════════════════════════════════════════════
// SoftirqEntry — per-vector handler metadata
// ══════════════════════════════════════════════════════════════

/// Global, per-vector softirq handler entry.
#[derive(Debug, Clone, Copy)]
pub struct SoftirqEntry {
    /// Handler function (None = unregistered).
    pub handler: Option<SoftirqFn>,
    /// Opaque context passed to the handler on invocation.
    pub context: u64,
    /// Number of times this handler has been invoked.
    pub count: u64,
    /// Cumulative execution time in ticks.
    pub total_time_ticks: u64,
    /// Maximum single-invocation latency in ticks.
    pub max_latency_ticks: u64,
}

impl SoftirqEntry {
    /// Create an empty (unregistered) handler entry.
    const fn empty() -> Self {
        Self {
            handler: None,
            context: 0,
            count: 0,
            total_time_ticks: 0,
            max_latency_ticks: 0,
        }
    }

    /// Returns `true` if a handler is registered for this vector.
    pub const fn is_registered(&self) -> bool {
        self.handler.is_some()
    }
}

// ══════════════════════════════════════════════════════════════
// SoftirqState — per-CPU runtime state
// ══════════════════════════════════════════════════════════════

/// Per-CPU softirq runtime state.
#[derive(Debug, Clone, Copy)]
pub struct SoftirqState {
    /// Bitmask of pending softirqs (one bit per `SoftirqType`).
    pub pending: u32,
    /// `true` while this CPU is inside `process_softirqs`.
    pub running: bool,
    /// Number of iterations completed in the current invocation.
    pub iteration_count: u32,
    /// How many times ksoftirqd was needed (livelock avoidance).
    pub ksoftirqd_wakeups: u64,
    /// Total softirqs processed on this CPU.
    pub processed: u64,
}

impl SoftirqState {
    /// Create a fresh per-CPU state.
    const fn new() -> Self {
        Self {
            pending: 0,
            running: false,
            iteration_count: 0,
            ksoftirqd_wakeups: 0,
            processed: 0,
        }
    }

    /// Returns `true` if any softirq is pending on this CPU.
    pub const fn has_pending(&self) -> bool {
        self.pending != 0
    }

    /// Returns `true` if the given softirq type is pending.
    pub const fn is_pending(&self, sirq: SoftirqType) -> bool {
        (self.pending & sirq.mask()) != 0
    }
}

// ══════════════════════════════════════════════════════════════
// SoftirqStats — global statistics
// ══════════════════════════════════════════════════════════════

/// Aggregated statistics across all CPUs and vectors.
#[derive(Debug, Clone, Copy)]
pub struct SoftirqStats {
    /// Total number of `raise_softirq` calls.
    pub total_raised: u64,
    /// Total number of handler invocations.
    pub total_processed: u64,
    /// Maximum handler latency across all vectors (in ticks).
    pub max_latency_ticks: u64,
    /// Total ksoftirqd wakeup events.
    pub total_ksoftirqd_wakeups: u64,
    /// Number of registered handlers.
    pub registered_handlers: u32,
}

impl SoftirqStats {
    /// Create zero-initialised stats.
    const fn new() -> Self {
        Self {
            total_raised: 0,
            total_processed: 0,
            max_latency_ticks: 0,
            total_ksoftirqd_wakeups: 0,
            registered_handlers: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// ProcessResult — outcome of process_softirqs
// ══════════════════════════════════════════════════════════════

/// Outcome of a `process_softirqs` invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessResult {
    /// All pending softirqs were drained.
    AllDrained,
    /// Some softirqs are still pending after the iteration limit;
    /// the caller should wake ksoftirqd.
    NeedKsoftirqd,
    /// Softirq processing was already in progress on this CPU
    /// (re-entrant call avoided).
    AlreadyRunning,
}

// ══════════════════════════════════════════════════════════════
// SoftirqSubsystem
// ══════════════════════════════════════════════════════════════

/// Top-level softirq subsystem.
///
/// Manages the global handler table and per-CPU pending/running
/// state.  This struct is designed for static allocation
/// (`const fn new()`).
pub struct SoftirqSubsystem {
    /// Global handler table indexed by `SoftirqType`.
    entries: [SoftirqEntry; NR_SOFTIRQS],
    /// Per-CPU softirq state.
    per_cpu: [SoftirqState; MAX_CPUS],
    /// Aggregated statistics.
    stats: SoftirqStats,
    /// Whether the subsystem has been initialised.
    initialised: bool,
}

impl Default for SoftirqSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl SoftirqSubsystem {
    /// Create a new, uninitialised softirq subsystem.
    pub const fn new() -> Self {
        Self {
            entries: [const { SoftirqEntry::empty() }; NR_SOFTIRQS],
            per_cpu: [const { SoftirqState::new() }; MAX_CPUS],
            stats: SoftirqStats::new(),
            initialised: false,
        }
    }

    /// Initialise the subsystem.  Must be called once during boot.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.initialised = true;
        Ok(())
    }

    // ── Handler registration ─────────────────────────────────

    /// Register a handler for the given softirq type.
    ///
    /// # Errors
    ///
    /// - `AlreadyExists` if a handler is already registered.
    /// - `InvalidArgument` if the subsystem is not initialised.
    pub fn register(&mut self, sirq: SoftirqType, handler: SoftirqFn, context: u64) -> Result<()> {
        if !self.initialised {
            return Err(Error::InvalidArgument);
        }
        let idx = sirq as usize;
        if self.entries[idx].is_registered() {
            return Err(Error::AlreadyExists);
        }
        self.entries[idx].handler = Some(handler);
        self.entries[idx].context = context;
        self.stats.registered_handlers += 1;
        Ok(())
    }

    /// Unregister the handler for the given softirq type.
    ///
    /// # Errors
    ///
    /// - `NotFound` if no handler is registered.
    pub fn unregister(&mut self, sirq: SoftirqType) -> Result<()> {
        let idx = sirq as usize;
        if !self.entries[idx].is_registered() {
            return Err(Error::NotFound);
        }
        self.entries[idx] = SoftirqEntry::empty();
        self.stats.registered_handlers = self.stats.registered_handlers.saturating_sub(1);
        Ok(())
    }

    // ── Raising softirqs ─────────────────────────────────────

    /// Raise (mark pending) a softirq on the given CPU.
    ///
    /// Typically called from a hardware interrupt handler to
    /// schedule deferred processing.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `cpu` is out of range.
    /// - `NotFound` if no handler is registered for `sirq`.
    pub fn raise(&mut self, cpu: usize, sirq: SoftirqType) -> Result<()> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let idx = sirq as usize;
        if !self.entries[idx].is_registered() {
            return Err(Error::NotFound);
        }
        self.per_cpu[cpu].pending |= sirq.mask();
        self.stats.total_raised += 1;
        Ok(())
    }

    /// Raise a softirq on the local CPU.
    ///
    /// Convenience wrapper when `cpu` is known.
    pub fn raise_local(&mut self, local_cpu: usize, sirq: SoftirqType) -> Result<()> {
        self.raise(local_cpu, sirq)
    }

    // ── Processing softirqs ──────────────────────────────────

    /// Process all pending softirqs on the given CPU.
    ///
    /// Runs up to [`MAX_SOFTIRQ_RESTART`] iterations.  Each
    /// iteration drains all currently-pending bits; if new bits
    /// arrive during processing, a new iteration starts.
    ///
    /// Returns the processing outcome; see [`ProcessResult`].
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `cpu` is out of range.
    pub fn process(&mut self, cpu: usize, current_tick: u64) -> Result<ProcessResult> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        // Avoid re-entrant processing on the same CPU.
        if self.per_cpu[cpu].running {
            return Ok(ProcessResult::AlreadyRunning);
        }

        self.per_cpu[cpu].running = true;
        self.per_cpu[cpu].iteration_count = 0;

        let mut restart = 0u32;

        while self.per_cpu[cpu].pending != 0 && restart < MAX_SOFTIRQ_RESTART {
            // Snapshot pending mask and clear atomically (in a real
            // kernel this would be an atomic swap).
            let pending = self.per_cpu[cpu].pending;
            self.per_cpu[cpu].pending = 0;

            self.run_pending(pending, current_tick);

            restart += 1;
            self.per_cpu[cpu].iteration_count = restart;
        }

        let result = if self.per_cpu[cpu].pending != 0 {
            self.per_cpu[cpu].ksoftirqd_wakeups += 1;
            self.stats.total_ksoftirqd_wakeups += 1;
            ProcessResult::NeedKsoftirqd
        } else {
            ProcessResult::AllDrained
        };

        self.per_cpu[cpu].running = false;
        Ok(result)
    }

    /// Run all handlers whose bits are set in `pending`.
    fn run_pending(&mut self, pending: u32, current_tick: u64) {
        for bit in 0..NR_SOFTIRQS {
            if pending & (1u32 << bit) == 0 {
                continue;
            }
            let entry = &self.entries[bit];
            if let Some(handler) = entry.handler {
                let ctx = entry.context;
                let start = current_tick;

                // Invoke the handler.
                handler(ctx);

                // Update per-vector statistics.
                let elapsed = current_tick.wrapping_sub(start);
                self.entries[bit].count += 1;
                self.entries[bit].total_time_ticks += elapsed;
                if elapsed > self.entries[bit].max_latency_ticks {
                    self.entries[bit].max_latency_ticks = elapsed;
                }

                // Global statistics.
                self.stats.total_processed += 1;
                if elapsed > self.stats.max_latency_ticks {
                    self.stats.max_latency_ticks = elapsed;
                }
            }
        }
    }

    // ── Query / diagnostics ──────────────────────────────────

    /// Check if a softirq is pending on the given CPU.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `cpu` is out of range.
    pub fn is_pending(&self, cpu: usize, sirq: SoftirqType) -> Result<bool> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.per_cpu[cpu].is_pending(sirq))
    }

    /// Return the pending bitmask for the given CPU.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `cpu` is out of range.
    pub fn pending_mask(&self, cpu: usize) -> Result<u32> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.per_cpu[cpu].pending)
    }

    /// Return the handler entry for a softirq type (read-only).
    pub fn entry(&self, sirq: SoftirqType) -> &SoftirqEntry {
        &self.entries[sirq as usize]
    }

    /// Return per-CPU state for diagnostics.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `cpu` is out of range.
    pub fn cpu_state(&self, cpu: usize) -> Result<&SoftirqState> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.per_cpu[cpu])
    }

    /// Return a snapshot of aggregated statistics.
    pub fn stats(&self) -> SoftirqStats {
        self.stats
    }

    /// Return the number of registered softirq handlers.
    pub fn registered_count(&self) -> u32 {
        self.stats.registered_handlers
    }

    /// Return per-CPU processed count.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `cpu` is out of range.
    pub fn cpu_processed(&self, cpu: usize) -> Result<u64> {
        if cpu >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.per_cpu[cpu].processed)
    }

    /// Dump a summary of all registered handlers and their stats.
    ///
    /// Returns an array of `(SoftirqType, count, total_time_ticks)`
    /// for every registered handler.
    pub fn dump_handler_stats(&self) -> [(Option<SoftirqType>, u64, u64); NR_SOFTIRQS] {
        let mut out = [(None, 0u64, 0u64); NR_SOFTIRQS];
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.is_registered() {
                out[i] = (
                    SoftirqType::from_index(i as u8),
                    entry.count,
                    entry.total_time_ticks,
                );
            }
        }
        out
    }

    /// Return the total number of softirqs raised system-wide.
    pub fn total_raised(&self) -> u64 {
        self.stats.total_raised
    }

    /// Return the total number of softirqs processed system-wide.
    pub fn total_processed(&self) -> u64 {
        self.stats.total_processed
    }
}
