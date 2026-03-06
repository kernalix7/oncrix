// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Idle task scheduler.
//!
//! Manages per-CPU idle states, the idle task loop, and idle-time
//! load balancing. When no runnable tasks exist on a CPU, the idle
//! scheduler selects an appropriate idle state (halt, mwait, or
//! poll) and enters it until an interrupt arrives.
//!
//! # Architecture
//!
//! ```text
//! IdleScheduler
//!  ├── IdleCpuState[MAX_CPUS]   (per-CPU idle tracking)
//!  │    ├── is_idle / idle_since
//!  │    ├── idle_state_idx (current C-state)
//!  │    └── cumulative statistics
//!  ├── IdleBalancer (cross-CPU migration)
//!  └── IdleStats (global counters)
//! ```

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum CPUs.
const MAX_CPUS: usize = 64;

/// Maximum idle states per CPU (C0..C6+).
const MAX_IDLE_STATES: usize = 8;

/// Idle balance interval in nanoseconds (4 ms).
const IDLE_BALANCE_INTERVAL_NS: u64 = 4_000_000;

// ======================================================================
// Types
// ======================================================================

/// Method used to enter idle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleMethod {
    /// Busy poll loop (lowest latency, highest power).
    Poll,
    /// x86 HLT instruction.
    Halt,
    /// x86 MWAIT instruction with hint.
    Mwait,
    /// ARM WFI instruction.
    Wfi,
    /// Deep platform sleep.
    PlatformSleep,
}

/// Description of a single idle state (C-state).
#[derive(Clone, Copy)]
pub struct IdleStateDesc {
    /// Human-readable name (truncated to 16 bytes).
    pub name: [u8; 16],
    /// Exit latency in nanoseconds.
    pub exit_latency_ns: u64,
    /// Target residency in nanoseconds (minimum time to be
    /// worthwhile entering this state).
    pub target_residency_ns: u64,
    /// Power consumption in microwatts.
    pub power_uw: u32,
    /// Method to enter this state.
    pub method: IdleMethod,
    /// Whether this state is enabled.
    pub enabled: bool,
}

impl IdleStateDesc {
    /// Creates a default (poll) idle state.
    pub const fn new() -> Self {
        Self {
            name: [0u8; 16],
            exit_latency_ns: 0,
            target_residency_ns: 0,
            power_uw: 0,
            method: IdleMethod::Poll,
            enabled: false,
        }
    }

    /// Creates a named idle state.
    pub fn with_params(
        name: &[u8],
        exit_latency_ns: u64,
        target_residency_ns: u64,
        power_uw: u32,
        method: IdleMethod,
    ) -> Self {
        let mut s = Self::new();
        let len = name.len().min(16);
        s.name[..len].copy_from_slice(&name[..len]);
        s.exit_latency_ns = exit_latency_ns;
        s.target_residency_ns = target_residency_ns;
        s.power_uw = power_uw;
        s.method = method;
        s.enabled = true;
        s
    }
}

/// Per-CPU idle state tracking.
pub struct IdleCpuState {
    /// Whether this CPU is currently idle.
    pub is_idle: bool,
    /// Timestamp when CPU entered idle (nanoseconds).
    pub idle_since: u64,
    /// Current idle state index (into `idle_states`).
    pub idle_state_idx: usize,
    /// Available idle states for this CPU.
    idle_states: [IdleStateDesc; MAX_IDLE_STATES],
    /// Number of registered idle states.
    pub nr_idle_states: usize,
    /// Total time spent in idle (nanoseconds).
    pub total_idle_time_ns: u64,
    /// Number of times we entered idle.
    pub nr_idle_entries: u64,
    /// Last time idle balance was attempted (nanoseconds).
    pub last_balance_time: u64,
    /// Whether this CPU is online.
    pub online: bool,
}

impl IdleCpuState {
    /// Creates an idle CPU state.
    pub const fn new() -> Self {
        Self {
            is_idle: false,
            idle_since: 0,
            idle_state_idx: 0,
            idle_states: [const { IdleStateDesc::new() }; MAX_IDLE_STATES],
            nr_idle_states: 0,
            total_idle_time_ns: 0,
            nr_idle_entries: 0,
            last_balance_time: 0,
            online: false,
        }
    }

    /// Registers a new idle state. Returns the state index.
    pub fn register_idle_state(&mut self, desc: IdleStateDesc) -> Result<usize> {
        if self.nr_idle_states >= MAX_IDLE_STATES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.nr_idle_states;
        self.idle_states[idx] = desc;
        self.nr_idle_states += 1;
        Ok(idx)
    }

    /// Enters idle at the given state index.
    pub fn enter_idle(&mut self, state_idx: usize, now_ns: u64) -> Result<IdleMethod> {
        if state_idx >= self.nr_idle_states {
            return Err(Error::InvalidArgument);
        }
        if !self.idle_states[state_idx].enabled {
            return Err(Error::InvalidArgument);
        }
        self.is_idle = true;
        self.idle_since = now_ns;
        self.idle_state_idx = state_idx;
        self.nr_idle_entries += 1;
        Ok(self.idle_states[state_idx].method)
    }

    /// Exits idle, updating accounting.
    pub fn exit_idle(&mut self, now_ns: u64) {
        if !self.is_idle {
            return;
        }
        let duration = now_ns.saturating_sub(self.idle_since);
        self.total_idle_time_ns += duration;
        self.is_idle = false;
    }

    /// Selects the deepest idle state whose exit latency is within
    /// the given constraint.
    pub fn select_idle_state(&self, max_latency_ns: u64) -> Option<usize> {
        let mut best_idx = None;
        let mut best_power = u32::MAX;

        for i in 0..self.nr_idle_states {
            let st = &self.idle_states[i];
            if !st.enabled {
                continue;
            }
            if st.exit_latency_ns > max_latency_ns {
                continue;
            }
            if st.power_uw < best_power {
                best_power = st.power_uw;
                best_idx = Some(i);
            }
        }
        best_idx
    }

    /// Returns the idle state descriptor at the given index.
    pub fn idle_state(&self, idx: usize) -> Option<&IdleStateDesc> {
        if idx < self.nr_idle_states {
            Some(&self.idle_states[idx])
        } else {
            None
        }
    }
}

// ======================================================================
// Idle balancer
// ======================================================================

/// Cross-CPU idle balancing: pulls tasks from busy CPUs to idle ones.
pub struct IdleBalancer {
    /// CPUs that are currently idle (bitmap).
    idle_cpus_bitmap: [u64; 2],
    /// Number of idle CPUs.
    pub nr_idle_cpus: u32,
}

impl IdleBalancer {
    /// Creates a new idle balancer.
    pub const fn new() -> Self {
        Self {
            idle_cpus_bitmap: [0u64; 2],
            nr_idle_cpus: 0,
        }
    }

    /// Marks a CPU as idle.
    pub fn set_idle(&mut self, cpu: u32) {
        let c = cpu as usize;
        let word = c / 64;
        let bit = c % 64;
        if word < 2 {
            if self.idle_cpus_bitmap[word] & (1u64 << bit) == 0 {
                self.idle_cpus_bitmap[word] |= 1u64 << bit;
                self.nr_idle_cpus += 1;
            }
        }
    }

    /// Marks a CPU as busy.
    pub fn clear_idle(&mut self, cpu: u32) {
        let c = cpu as usize;
        let word = c / 64;
        let bit = c % 64;
        if word < 2 {
            if self.idle_cpus_bitmap[word] & (1u64 << bit) != 0 {
                self.idle_cpus_bitmap[word] &= !(1u64 << bit);
                self.nr_idle_cpus = self.nr_idle_cpus.saturating_sub(1);
            }
        }
    }

    /// Returns whether a CPU is idle.
    pub fn is_idle(&self, cpu: u32) -> bool {
        let c = cpu as usize;
        let word = c / 64;
        let bit = c % 64;
        if word < 2 {
            self.idle_cpus_bitmap[word] & (1u64 << bit) != 0
        } else {
            false
        }
    }

    /// Selects an idle CPU, preferring the given CPU.
    pub fn select_idle_cpu(&self, preferred: u32, nr_cpus: u32) -> Option<u32> {
        // Try preferred first.
        if self.is_idle(preferred) {
            return Some(preferred);
        }
        // Scan for any idle CPU.
        for c in 0..nr_cpus {
            if self.is_idle(c) {
                return Some(c);
            }
        }
        None
    }

    /// Checks if idle balance should run based on timing.
    pub fn should_balance(&self, last_balance: u64, now_ns: u64) -> bool {
        now_ns.saturating_sub(last_balance) >= IDLE_BALANCE_INTERVAL_NS
    }
}

// ======================================================================
// IdleStats
// ======================================================================

/// Global idle statistics.
pub struct IdleStats {
    /// Total idle time across all CPUs (nanoseconds).
    pub total_idle_time_ns: u64,
    /// Number of idle balance attempts.
    pub nr_balance_attempts: u64,
    /// Number of successful migrations from idle balance.
    pub nr_balance_migrations: u64,
}

impl IdleStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_idle_time_ns: 0,
            nr_balance_attempts: 0,
            nr_balance_migrations: 0,
        }
    }
}

// ======================================================================
// IdleScheduler — top-level
// ======================================================================

/// Top-level idle scheduler managing per-CPU idle states.
pub struct IdleScheduler {
    /// Per-CPU idle state.
    cpus: [IdleCpuState; MAX_CPUS],
    /// Idle balancer.
    pub balancer: IdleBalancer,
    /// Global statistics.
    pub stats: IdleStats,
    /// Number of online CPUs.
    pub nr_cpus: u32,
}

impl IdleScheduler {
    /// Creates an idle scheduler.
    pub const fn new() -> Self {
        Self {
            cpus: [const { IdleCpuState::new() }; MAX_CPUS],
            balancer: IdleBalancer::new(),
            stats: IdleStats::new(),
            nr_cpus: 1,
        }
    }

    /// Brings a CPU online.
    pub fn cpu_online(&mut self, cpu: u32) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.cpus[c].online = true;
        if cpu >= self.nr_cpus {
            self.nr_cpus = cpu + 1;
        }
        Ok(())
    }

    /// Enters the idle loop on the given CPU.
    pub fn play_idle(&mut self, cpu: u32, max_latency_ns: u64, now_ns: u64) -> Result<IdleMethod> {
        let c = cpu as usize;
        if c >= MAX_CPUS || !self.cpus[c].online {
            return Err(Error::InvalidArgument);
        }

        let state_idx = self.cpus[c].select_idle_state(max_latency_ns).unwrap_or(0);

        // If no valid state found, use poll.
        if self.cpus[c].nr_idle_states == 0 {
            self.cpus[c].is_idle = true;
            self.cpus[c].idle_since = now_ns;
            self.balancer.set_idle(cpu);
            return Ok(IdleMethod::Poll);
        }

        let method = self.cpus[c].enter_idle(state_idx, now_ns)?;
        self.balancer.set_idle(cpu);
        Ok(method)
    }

    /// Exits the idle loop on the given CPU.
    pub fn exit_idle(&mut self, cpu: u32, now_ns: u64) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.cpus[c].exit_idle(now_ns);
        self.balancer.clear_idle(cpu);
        self.stats.total_idle_time_ns += now_ns.saturating_sub(self.cpus[c].idle_since);
        Ok(())
    }

    /// Performs idle balance: attempts to pull work to idle CPUs.
    /// Returns the number of CPUs that should be woken.
    pub fn idle_balance(&mut self, now_ns: u64) -> u32 {
        self.stats.nr_balance_attempts += 1;
        let mut wakeups = 0u32;

        for c in 0..self.nr_cpus {
            if !self.balancer.is_idle(c) {
                continue;
            }
            let ci = c as usize;
            if !self
                .balancer
                .should_balance(self.cpus[ci].last_balance_time, now_ns)
            {
                continue;
            }
            self.cpus[ci].last_balance_time = now_ns;
            // In a real system this would pull tasks from busy CPUs.
            // Here we signal that the CPU should check for work.
            wakeups += 1;
        }

        if wakeups > 0 {
            self.stats.nr_balance_migrations += wakeups as u64;
        }
        wakeups
    }

    /// Selects an idle CPU for task placement.
    pub fn select_idle_cpu(&self, preferred: u32) -> Option<u32> {
        self.balancer.select_idle_cpu(preferred, self.nr_cpus)
    }

    /// Returns per-CPU idle state info.
    pub fn cpu_state(&self, cpu: u32) -> Option<&IdleCpuState> {
        let c = cpu as usize;
        if c < MAX_CPUS {
            Some(&self.cpus[c])
        } else {
            None
        }
    }

    /// Returns mutable per-CPU idle state.
    pub fn cpu_state_mut(&mut self, cpu: u32) -> Option<&mut IdleCpuState> {
        let c = cpu as usize;
        if c < MAX_CPUS {
            Some(&mut self.cpus[c])
        } else {
            None
        }
    }
}
