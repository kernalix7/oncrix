// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Ksoftirqd — per-CPU softirq processing kernel threads.
//!
//! When softirqs accumulate faster than they can be processed in
//! interrupt context, ksoftirqd threads take over to avoid live-lock.
//! Each CPU has a dedicated ksoftirqd thread that runs at a low
//! priority to drain pending softirqs.
//!
//! # Architecture
//!
//! ```text
//! KsoftirqdManager
//!  ├── threads[MAX_CPUS]
//!  │    ├── cpu, state: ThreadState
//!  │    ├── pending_mask: u32
//!  │    ├── iterations, softirqs_processed
//!  │    └── wakeup_count
//!  └── stats: KsoftirqdStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/softirq.c` — `run_ksoftirqd()`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum CPUs.
const MAX_CPUS: usize = 64;

/// Maximum softirq vectors (matches Linux NR_SOFTIRQS).
const NR_SOFTIRQS: usize = 10;

/// Maximum iterations per ksoftirqd wakeup before yielding.
const MAX_ITERATIONS: u32 = 10;

// ══════════════════════════════════════════════════════════════
// SoftirqVec — softirq vector identifiers
// ══════════════════════════════════════════════════════════════

/// Standard softirq vector numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SoftirqVec {
    /// High-priority tasklet.
    HiSoftirq = 0,
    /// Timer softirq.
    TimerSoftirq = 1,
    /// Network TX.
    NetTxSoftirq = 2,
    /// Network RX.
    NetRxSoftirq = 3,
    /// Block device.
    BlockSoftirq = 4,
    /// IRQ poll.
    IrqPollSoftirq = 5,
    /// Regular tasklet.
    TaskletSoftirq = 6,
    /// Scheduler.
    SchedSoftirq = 7,
    /// High-resolution timer.
    HrtimerSoftirq = 8,
    /// RCU.
    RcuSoftirq = 9,
}

// ══════════════════════════════════════════════════════════════
// ThreadState
// ══════════════════════════════════════════════════════════════

/// State of a ksoftirqd thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ThreadState {
    /// Not created.
    None = 0,
    /// Sleeping (no pending softirqs).
    Sleeping = 1,
    /// Running (draining softirqs).
    Running = 2,
    /// Parked (CPU offline).
    Parked = 3,
}

// ══════════════════════════════════════════════════════════════
// KsoftirqdThread — per-CPU thread state
// ══════════════════════════════════════════════════════════════

/// Per-CPU ksoftirqd thread state.
#[derive(Debug, Clone, Copy)]
pub struct KsoftirqdThread {
    /// CPU this thread is bound to.
    pub cpu: u32,
    /// Current thread state.
    pub state: ThreadState,
    /// Bitmask of pending softirq vectors.
    pub pending_mask: u32,
    /// Per-vector processing counts.
    pub vec_counts: [u64; NR_SOFTIRQS],
    /// Total iterations (loop passes).
    pub iterations: u64,
    /// Total softirqs processed.
    pub softirqs_processed: u64,
    /// Total wakeups.
    pub wakeup_count: u64,
}

impl KsoftirqdThread {
    /// Create an uninitialised thread state.
    const fn empty() -> Self {
        Self {
            cpu: 0,
            state: ThreadState::None,
            pending_mask: 0,
            vec_counts: [0u64; NR_SOFTIRQS],
            iterations: 0,
            softirqs_processed: 0,
            wakeup_count: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// KsoftirqdStats
// ══════════════════════════════════════════════════════════════

/// Global ksoftirqd statistics.
#[derive(Debug, Clone, Copy)]
pub struct KsoftirqdStats {
    /// Total wakeups across all CPUs.
    pub total_wakeups: u64,
    /// Total softirqs drained by ksoftirqd.
    pub total_processed: u64,
    /// Total iterations.
    pub total_iterations: u64,
    /// Times ksoftirqd hit the iteration limit.
    pub throttle_count: u64,
}

impl KsoftirqdStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            total_wakeups: 0,
            total_processed: 0,
            total_iterations: 0,
            throttle_count: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// KsoftirqdManager
// ══════════════════════════════════════════════════════════════

/// Manages per-CPU ksoftirqd threads.
pub struct KsoftirqdManager {
    /// Per-CPU thread state.
    threads: [KsoftirqdThread; MAX_CPUS],
    /// Number of online CPUs with ksoftirqd.
    nr_cpus: u32,
    /// Statistics.
    stats: KsoftirqdStats,
}

impl KsoftirqdManager {
    /// Create a new ksoftirqd manager.
    pub const fn new() -> Self {
        Self {
            threads: [const { KsoftirqdThread::empty() }; MAX_CPUS],
            nr_cpus: 0,
            stats: KsoftirqdStats::new(),
        }
    }

    /// Initialise the ksoftirqd thread for a CPU.
    pub fn init_cpu(&mut self, cpu: u32) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.threads[c].cpu = cpu;
        self.threads[c].state = ThreadState::Sleeping;
        if cpu >= self.nr_cpus {
            self.nr_cpus = cpu + 1;
        }
        Ok(())
    }

    /// Park the ksoftirqd thread (CPU going offline).
    pub fn park_cpu(&mut self, cpu: u32) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.threads[c].state = ThreadState::Parked;
        Ok(())
    }

    /// Raise a softirq vector on a CPU.
    ///
    /// If the pending mask transitions from zero, the ksoftirqd
    /// thread is woken up.
    pub fn raise_softirq(&mut self, cpu: u32, vec: SoftirqVec) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if matches!(
            self.threads[c].state,
            ThreadState::None | ThreadState::Parked
        ) {
            return Err(Error::InvalidArgument);
        }
        let was_empty = self.threads[c].pending_mask == 0;
        self.threads[c].pending_mask |= 1 << (vec as u32);
        if was_empty {
            self.threads[c].state = ThreadState::Running;
            self.threads[c].wakeup_count += 1;
            self.stats.total_wakeups += 1;
        }
        Ok(())
    }

    /// Run one iteration of the ksoftirqd loop for a CPU.
    ///
    /// Processes all pending softirqs up to `MAX_ITERATIONS` loops.
    /// Returns the number of softirqs processed.
    pub fn run_ksoftirqd(&mut self, cpu: u32) -> Result<u32> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if !matches!(self.threads[c].state, ThreadState::Running) {
            return Ok(0);
        }

        let mut total = 0u32;
        let mut loops = 0u32;

        while self.threads[c].pending_mask != 0 && loops < MAX_ITERATIONS {
            let pending = self.threads[c].pending_mask;
            self.threads[c].pending_mask = 0;

            for vec_nr in 0..NR_SOFTIRQS {
                if pending & (1 << vec_nr) != 0 {
                    self.threads[c].vec_counts[vec_nr] += 1;
                    total += 1;
                }
            }
            loops += 1;
            self.threads[c].iterations += 1;
            self.stats.total_iterations += 1;
        }

        if self.threads[c].pending_mask != 0 {
            self.stats.throttle_count += 1;
        } else {
            self.threads[c].state = ThreadState::Sleeping;
        }

        self.threads[c].softirqs_processed += total as u64;
        self.stats.total_processed += total as u64;
        Ok(total)
    }

    /// Return per-CPU thread state.
    pub fn get_thread(&self, cpu: u32) -> Result<&KsoftirqdThread> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.threads[c])
    }

    /// Return statistics.
    pub fn stats(&self) -> KsoftirqdStats {
        self.stats
    }
}
