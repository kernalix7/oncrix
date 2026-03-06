// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Softirq handler framework.
//!
//! Softirqs are the highest-priority deferred work mechanism in the
//! kernel. Unlike tasklets or workqueues, softirq handlers can run
//! concurrently on different CPUs. There are a fixed number of
//! softirq vectors (10), each with a registered handler.
//!
//! # Softirq Vectors
//!
//! | Index | Name | Purpose |
//! |-------|------|---------|
//! | 0 | HI_SOFTIRQ | High-priority tasklets |
//! | 1 | TIMER_SOFTIRQ | Timer callbacks |
//! | 2 | NET_TX_SOFTIRQ | Network transmit |
//! | 3 | NET_RX_SOFTIRQ | Network receive |
//! | 4 | BLOCK_SOFTIRQ | Block device completion |
//! | 5 | IRQ_POLL_SOFTIRQ | IRQ polling |
//! | 6 | TASKLET_SOFTIRQ | Normal-priority tasklets |
//! | 7 | SCHED_SOFTIRQ | Scheduler IPI |
//! | 8 | HRTIMER_SOFTIRQ | High-res timer |
//! | 9 | RCU_SOFTIRQ | RCU callbacks |
//!
//! # Flow
//!
//! ```text
//! Hardware IRQ → raise_softirq(vec) → sets pending bit
//!     ↓
//! irq_exit() / ksoftirqd → do_softirq()
//!     ↓
//! for each pending vector: handler(cpu)
//!     ↓
//! clear pending bit
//! ```
//!
//! # Reference
//!
//! Linux `kernel/softirq.c`, `include/linux/interrupt.h`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────

/// Number of softirq vectors.
pub const NR_SOFTIRQS: usize = 10;

/// Maximum number of CPUs.
const MAX_CPUS: usize = 256;

/// Maximum iterations of do_softirq before deferring to ksoftirqd.
const MAX_SOFTIRQ_RESTART: u32 = 10;

/// Maximum time (ns) to spend in a single do_softirq invocation.
const MAX_SOFTIRQ_TIME_NS: u64 = 2_000_000;

// ── SoftirqVec ──────────────────────────────────────────────

/// Softirq vector identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SoftirqVec {
    /// High-priority tasklets.
    Hi = 0,
    /// Timer callbacks.
    Timer = 1,
    /// Network transmit completion.
    NetTx = 2,
    /// Network receive processing.
    NetRx = 3,
    /// Block device I/O completion.
    Block = 4,
    /// IRQ polling mode.
    IrqPoll = 5,
    /// Normal-priority tasklets.
    Tasklet = 6,
    /// Scheduler load balancing IPI.
    Sched = 7,
    /// High-resolution timer.
    Hrtimer = 8,
    /// RCU callback processing.
    Rcu = 9,
}

impl SoftirqVec {
    /// Convert from index to vector.
    pub fn from_index(idx: u32) -> Option<Self> {
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

    /// Human-readable name.
    pub fn name(self) -> &'static str {
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

    /// Get the index.
    pub fn index(self) -> usize {
        self as usize
    }
}

// ── SoftirqHandler ──────────────────────────────────────────

/// Function type for softirq handlers.
///
/// Called with the CPU ID that is processing the softirq.
pub type SoftirqHandlerFn = fn(u32);

/// A registered softirq handler.
#[derive(Clone, Copy)]
struct SoftirqHandler {
    /// The handler function.
    func: Option<SoftirqHandlerFn>,
    /// Whether this handler is registered.
    registered: bool,
    /// Total invocations.
    invocations: u64,
    /// Total time spent (ns) — approximate.
    total_time_ns: u64,
}

impl SoftirqHandler {
    /// Create an empty handler.
    const fn empty() -> Self {
        Self {
            func: None,
            registered: false,
            invocations: 0,
            total_time_ns: 0,
        }
    }
}

// ── PerCpuSoftirq ───────────────────────────────────────────

/// Per-CPU softirq state.
struct PerCpuSoftirq {
    /// Pending softirq bitmask (one bit per vector).
    pending: u32,
    /// Whether currently in do_softirq.
    in_softirq: bool,
    /// Number of times do_softirq was called.
    do_softirq_count: u64,
    /// Number of times ksoftirqd was woken.
    ksoftirqd_wakeups: u64,
    /// Whether this CPU is initialized.
    initialized: bool,
    /// Per-vector invocation counts for this CPU.
    per_vec_count: [u64; NR_SOFTIRQS],
}

impl PerCpuSoftirq {
    /// Create empty per-CPU state.
    const fn new() -> Self {
        Self {
            pending: 0,
            in_softirq: false,
            do_softirq_count: 0,
            ksoftirqd_wakeups: 0,
            initialized: false,
            per_vec_count: [0; NR_SOFTIRQS],
        }
    }

    /// Check if a vector is pending.
    fn is_pending(&self, vec: SoftirqVec) -> bool {
        (self.pending & (1u32 << vec.index())) != 0
    }

    /// Raise a softirq vector.
    fn raise(&mut self, vec: SoftirqVec) {
        self.pending |= 1u32 << vec.index();
    }

    /// Clear a vector's pending bit.
    fn clear(&mut self, vec: SoftirqVec) {
        self.pending &= !(1u32 << vec.index());
    }

    /// Whether any softirqs are pending.
    fn any_pending(&self) -> bool {
        self.pending != 0
    }
}

// ── SoftirqStats ────────────────────────────────────────────

/// Global softirq statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct SoftirqStats {
    /// Total raises across all CPUs.
    pub total_raised: u64,
    /// Total do_softirq invocations.
    pub total_processed: u64,
    /// Total individual handler invocations.
    pub total_handler_calls: u64,
    /// Total ksoftirqd wakeups.
    pub total_ksoftirqd_wakeups: u64,
    /// Per-vector total invocations.
    pub per_vec_total: [u64; NR_SOFTIRQS],
}

// ── SoftirqSubsystem ────────────────────────────────────────

/// Global softirq subsystem.
///
/// Manages softirq handler registration, per-CPU pending state,
/// and the do_softirq processing loop.
pub struct SoftirqSubsystem {
    /// Registered handlers (one per vector).
    handlers: [SoftirqHandler; NR_SOFTIRQS],
    /// Per-CPU state.
    per_cpu: [PerCpuSoftirq; MAX_CPUS],
    /// Number of initialized CPUs.
    cpu_count: u32,
    /// Whether initialized.
    initialized: bool,
    /// Total raises.
    total_raised: u64,
}

impl SoftirqSubsystem {
    /// Create a new softirq subsystem.
    pub const fn new() -> Self {
        Self {
            handlers: [SoftirqHandler::empty(); NR_SOFTIRQS],
            per_cpu: [const { PerCpuSoftirq::new() }; MAX_CPUS],
            cpu_count: 0,
            initialized: false,
            total_raised: 0,
        }
    }

    /// Initialize the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        self.initialized = true;
        Ok(())
    }

    /// Register a CPU.
    pub fn register_cpu(&mut self, cpu_id: u32) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[idx].initialized = true;
        self.cpu_count += 1;
        Ok(())
    }

    /// Register a softirq handler for a vector.
    pub fn register_handler(&mut self, vec: SoftirqVec, handler: SoftirqHandlerFn) -> Result<()> {
        let idx = vec.index();
        if idx >= NR_SOFTIRQS {
            return Err(Error::InvalidArgument);
        }
        if self.handlers[idx].registered {
            return Err(Error::AlreadyExists);
        }
        self.handlers[idx] = SoftirqHandler {
            func: Some(handler),
            registered: true,
            invocations: 0,
            total_time_ns: 0,
        };
        Ok(())
    }

    /// Unregister a softirq handler.
    pub fn unregister_handler(&mut self, vec: SoftirqVec) -> Result<()> {
        let idx = vec.index();
        if idx >= NR_SOFTIRQS {
            return Err(Error::InvalidArgument);
        }
        if !self.handlers[idx].registered {
            return Err(Error::NotFound);
        }
        self.handlers[idx] = SoftirqHandler::empty();
        Ok(())
    }

    /// Raise a softirq on a specific CPU.
    ///
    /// Sets the pending bit for the given vector. The softirq will
    /// be processed on the next call to `do_softirq` on that CPU.
    pub fn raise_softirq(&mut self, cpu: u32, vec: SoftirqVec) -> Result<()> {
        let idx = cpu as usize;
        if idx >= MAX_CPUS || !self.per_cpu[idx].initialized {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[idx].raise(vec);
        self.total_raised += 1;
        Ok(())
    }

    /// Raise a softirq on the local CPU.
    pub fn raise_softirq_local(&mut self, local_cpu: u32, vec: SoftirqVec) -> Result<()> {
        self.raise_softirq(local_cpu, vec)
    }

    /// Process pending softirqs on a CPU.
    ///
    /// Called from irq_exit() or ksoftirqd. Processes each pending
    /// vector in priority order (lowest index first).
    ///
    /// Returns the number of handlers invoked.
    pub fn do_softirq(&mut self, cpu: u32) -> Result<u32> {
        let idx = cpu as usize;
        if idx >= MAX_CPUS || !self.per_cpu[idx].initialized {
            return Err(Error::InvalidArgument);
        }
        if self.per_cpu[idx].in_softirq {
            return Ok(0); // Nested — skip.
        }
        if !self.per_cpu[idx].any_pending() {
            return Ok(0);
        }

        self.per_cpu[idx].in_softirq = true;
        self.per_cpu[idx].do_softirq_count += 1;
        let mut handled = 0u32;
        let mut restarts = 0u32;

        loop {
            let pending = self.per_cpu[idx].pending;
            if pending == 0 || restarts >= MAX_SOFTIRQ_RESTART {
                break;
            }

            for vec_idx in 0..NR_SOFTIRQS {
                if (pending & (1u32 << vec_idx)) == 0 {
                    continue;
                }
                if let Some(vec) = SoftirqVec::from_index(vec_idx as u32) {
                    self.per_cpu[idx].clear(vec);

                    if let Some(func) = self.handlers[vec_idx].func {
                        func(cpu);
                        self.handlers[vec_idx].invocations += 1;
                        self.per_cpu[idx].per_vec_count[vec_idx] += 1;
                        handled += 1;
                    }
                }
            }

            restarts += 1;
        }

        // If still pending after max restarts, wake ksoftirqd.
        if self.per_cpu[idx].any_pending() {
            self.per_cpu[idx].ksoftirqd_wakeups += 1;
        }

        self.per_cpu[idx].in_softirq = false;
        Ok(handled)
    }

    /// Check if any softirqs are pending on a CPU.
    pub fn pending(&self, cpu: u32) -> Result<bool> {
        let idx = cpu as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.per_cpu[idx].any_pending())
    }

    /// Check if a specific vector is pending on a CPU.
    pub fn is_vec_pending(&self, cpu: u32, vec: SoftirqVec) -> Result<bool> {
        let idx = cpu as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.per_cpu[idx].is_pending(vec))
    }

    /// Get the raw pending mask for a CPU.
    pub fn pending_mask(&self, cpu: u32) -> Result<u32> {
        let idx = cpu as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.per_cpu[idx].pending)
    }

    /// Whether a handler is registered for a vector.
    pub fn is_handler_registered(&self, vec: SoftirqVec) -> bool {
        let idx = vec.index();
        idx < NR_SOFTIRQS && self.handlers[idx].registered
    }

    /// Get statistics.
    pub fn stats(&self) -> SoftirqStats {
        let mut stats = SoftirqStats::default();
        stats.total_raised = self.total_raised;

        for cpu in &self.per_cpu {
            if !cpu.initialized {
                continue;
            }
            stats.total_processed += cpu.do_softirq_count;
            stats.total_ksoftirqd_wakeups += cpu.ksoftirqd_wakeups;
            for (i, &count) in cpu.per_vec_count.iter().enumerate() {
                stats.per_vec_total[i] += count;
                stats.total_handler_calls += count;
            }
        }
        stats
    }

    /// Number of initialized CPUs.
    pub fn cpu_count(&self) -> u32 {
        self.cpu_count
    }
}

impl Default for SoftirqSubsystem {
    fn default() -> Self {
        Self::new()
    }
}
