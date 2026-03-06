// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Tick-less (NO_HZ) kernel — dynamic tick suppression.
//!
//! When a CPU is idle (or running a single task in full-dyntick mode),
//! periodic timer interrupts are suppressed to save power and reduce
//! overhead. The next tick is programmed only when needed.
//!
//! # Modes
//!
//! - **NO_HZ_IDLE**: Suppress ticks when CPU is idle.
//! - **NO_HZ_FULL**: Suppress ticks even with one runnable task
//!   (reduces OS noise for latency-sensitive workloads).
//!
//! # Architecture
//!
//! ```text
//! TickNohzManager
//!  ├── per_cpu[MAX_CPUS]
//!  │    ├── mode: NohzMode
//!  │    ├── tick_stopped: bool
//!  │    ├── idle_sleeps, idle_exits
//!  │    └── last_tick_ns
//!  └── stats: NohzStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/time/tick-sched.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum CPUs.
const MAX_CPUS: usize = 64;

// ══════════════════════════════════════════════════════════════
// NohzMode
// ══════════════════════════════════════════════════════════════

/// Tick suppression mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NohzMode {
    /// Ticks always active (legacy).
    Active = 0,
    /// Suppress ticks when CPU is idle.
    Idle = 1,
    /// Suppress ticks with zero or one runnable task.
    Full = 2,
}

// ══════════════════════════════════════════════════════════════
// PerCpuNohz
// ══════════════════════════════════════════════════════════════

/// Per-CPU tick-nohz state.
#[derive(Debug, Clone, Copy)]
pub struct PerCpuNohz {
    /// Configured mode for this CPU.
    pub mode: NohzMode,
    /// Whether ticks are currently stopped.
    pub tick_stopped: bool,
    /// Last tick timestamp (monotonic ns).
    pub last_tick_ns: u64,
    /// Next programmed tick (monotonic ns, 0 = none).
    pub next_tick_ns: u64,
    /// Number of times the CPU entered idle with ticks stopped.
    pub idle_sleeps: u64,
    /// Number of idle exits.
    pub idle_exits: u64,
    /// Total time spent in tickless idle (ns).
    pub idle_ns: u64,
    /// Number of runnable tasks.
    pub nr_running: u32,
    /// Whether this CPU is online.
    pub online: bool,
}

impl PerCpuNohz {
    /// Create an offline CPU entry.
    const fn new() -> Self {
        Self {
            mode: NohzMode::Active,
            tick_stopped: false,
            last_tick_ns: 0,
            next_tick_ns: 0,
            idle_sleeps: 0,
            idle_exits: 0,
            idle_ns: 0,
            nr_running: 0,
            online: false,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// NohzStats
// ══════════════════════════════════════════════════════════════

/// Global nohz statistics.
#[derive(Debug, Clone, Copy)]
pub struct NohzStats {
    /// Total tick-stop events.
    pub total_stops: u64,
    /// Total tick-restart events.
    pub total_restarts: u64,
    /// Total idle entries across all CPUs.
    pub total_idle_entries: u64,
    /// Total idle exits across all CPUs.
    pub total_idle_exits: u64,
}

impl NohzStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            total_stops: 0,
            total_restarts: 0,
            total_idle_entries: 0,
            total_idle_exits: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// TickNohzManager
// ══════════════════════════════════════════════════════════════

/// Manages tick-less operation per CPU.
pub struct TickNohzManager {
    /// Per-CPU state.
    cpus: [PerCpuNohz; MAX_CPUS],
    /// Number of online CPUs.
    nr_cpus: u32,
    /// Statistics.
    stats: NohzStats,
}

impl TickNohzManager {
    /// Create a new tick-nohz manager.
    pub const fn new() -> Self {
        Self {
            cpus: [const { PerCpuNohz::new() }; MAX_CPUS],
            nr_cpus: 0,
            stats: NohzStats::new(),
        }
    }

    /// Bring a CPU online with a given nohz mode.
    pub fn cpu_online(&mut self, cpu: u32, mode: NohzMode) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.cpus[c].online = true;
        self.cpus[c].mode = mode;
        if cpu >= self.nr_cpus {
            self.nr_cpus = cpu + 1;
        }
        Ok(())
    }

    /// Notify idle entry on a CPU. Stops the tick if conditions allow.
    pub fn idle_enter(&mut self, cpu: u32, now_ns: u64) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS || !self.cpus[c].online {
            return Err(Error::InvalidArgument);
        }
        self.stats.total_idle_entries += 1;
        match self.cpus[c].mode {
            NohzMode::Active => {
                // Ticks remain active.
            }
            NohzMode::Idle | NohzMode::Full => {
                if !self.cpus[c].tick_stopped {
                    self.cpus[c].tick_stopped = true;
                    self.cpus[c].last_tick_ns = now_ns;
                    self.cpus[c].idle_sleeps += 1;
                    self.stats.total_stops += 1;
                }
            }
        }
        Ok(())
    }

    /// Notify idle exit on a CPU. Restarts the tick.
    pub fn idle_exit(&mut self, cpu: u32, now_ns: u64) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS || !self.cpus[c].online {
            return Err(Error::InvalidArgument);
        }
        self.stats.total_idle_exits += 1;
        self.cpus[c].idle_exits += 1;
        if self.cpus[c].tick_stopped {
            let idle_duration = now_ns.saturating_sub(self.cpus[c].last_tick_ns);
            self.cpus[c].idle_ns += idle_duration;
            self.cpus[c].tick_stopped = false;
            self.cpus[c].last_tick_ns = now_ns;
            self.stats.total_restarts += 1;
        }
        Ok(())
    }

    /// Update the number of runnable tasks for NO_HZ_FULL logic.
    pub fn update_nr_running(&mut self, cpu: u32, nr_running: u32, now_ns: u64) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS || !self.cpus[c].online {
            return Err(Error::InvalidArgument);
        }
        self.cpus[c].nr_running = nr_running;
        if matches!(self.cpus[c].mode, NohzMode::Full) {
            if nr_running <= 1 && !self.cpus[c].tick_stopped {
                self.cpus[c].tick_stopped = true;
                self.cpus[c].last_tick_ns = now_ns;
                self.stats.total_stops += 1;
            } else if nr_running > 1 && self.cpus[c].tick_stopped {
                self.cpus[c].tick_stopped = false;
                self.stats.total_restarts += 1;
            }
        }
        Ok(())
    }

    /// Program the next tick for a CPU.
    pub fn set_next_tick(&mut self, cpu: u32, next_ns: u64) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.cpus[c].next_tick_ns = next_ns;
        Ok(())
    }

    /// Return per-CPU state.
    pub fn per_cpu(&self, cpu: u32) -> Result<&PerCpuNohz> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.cpus[c])
    }

    /// Return statistics.
    pub fn stats(&self) -> NohzStats {
        self.stats
    }
}
