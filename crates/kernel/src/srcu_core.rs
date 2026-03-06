// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Sleepable RCU (SRCU) core implementation.
//!
//! SRCU extends classic RCU by allowing readers to sleep inside
//! critical sections. Each SRCU domain maintains per-CPU
//! read-side counters split into two alternating slots, enabling
//! grace-period detection without blocking readers.
//!
//! # Architecture
//!
//! ```text
//! SrcuDomain
//! ├── per_cpu: [SrcuPerCpu; MAX_CPUS]
//! │   └── counters: [u64; 2]   ← two alternating slots
//! ├── generation: u64          ← current active slot (0 or 1)
//! ├── gp_seq: u64              ← grace period sequence
//! ├── gp_state: GracePeriodState
//! ├── callbacks: [SrcuCallback; MAX_CBS]
//! └── state: DomainState
//!
//! SrcuManager
//! ├── domains: [SrcuDomain; MAX_DOMAINS]
//! └── stats: SrcuStats
//! ```
//!
//! # Read-Side Protocol
//!
//! ```text
//! idx = srcu_read_lock(domain, cpu)
//!   → increments per_cpu[cpu].counters[generation]
//!   → returns generation snapshot
//!
//! srcu_read_unlock(domain, cpu, idx)
//!   → decrements per_cpu[cpu].counters[idx]
//! ```
//!
//! # Grace Period Detection
//!
//! ```text
//! synchronize_srcu(domain)
//!   1. Flip generation (0→1 or 1→0)
//!   2. Wait until sum of counters[old_gen] across all
//!      CPUs reaches zero
//!   3. Advance gp_seq, invoke pending callbacks
//! ```
//!
//! # Expedited vs Normal
//!
//! | Mode | Behaviour |
//! |------|-----------|
//! | Normal | Deferred check, batches callbacks |
//! | Expedited | Immediate cross-CPU check via IPI |
//!
//! Reference: Linux `kernel/rcu/srcutree.c`,
//! `include/linux/srcu.h`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────

/// Maximum CPUs supported per SRCU domain.
const MAX_CPUS: usize = 64;

/// Number of counter slots per CPU (alternating generations).
const NR_SLOTS: usize = 2;

/// Maximum SRCU domains.
const MAX_DOMAINS: usize = 32;

/// Maximum pending callbacks per domain.
const MAX_CALLBACKS: usize = 128;

/// Maximum domain name length.
const MAX_NAME_LEN: usize = 32;

// ── DomainState ────────────────────────────────────────────────

/// Lifecycle state of an SRCU domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DomainState {
    /// Domain is not initialised.
    #[default]
    Uninit,
    /// Domain is active and accepting readers.
    Active,
    /// Domain is being shut down (draining readers).
    Draining,
}

// ── GracePeriodState ───────────────────────────────────────────

/// State of the grace-period state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GracePeriodState {
    /// No grace period in progress.
    #[default]
    Idle,
    /// Waiting for old-generation readers to finish.
    WaitReaders,
    /// Grace period complete, invoking callbacks.
    Callbacks,
}

// ── GracePeriodMode ────────────────────────────────────────────

/// How aggressively to detect grace periods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GracePeriodMode {
    /// Deferred / lazy checking.
    #[default]
    Normal,
    /// Immediate cross-CPU notification.
    Expedited,
}

// ── SrcuPerCpu ─────────────────────────────────────────────────

/// Per-CPU read-side counters for an SRCU domain.
#[derive(Debug, Clone, Copy)]
pub struct SrcuPerCpu {
    /// Alternating lock counters indexed by generation.
    pub counters: [u64; NR_SLOTS],
    /// Whether this CPU entry is initialised.
    pub active: bool,
}

impl SrcuPerCpu {
    /// Creates uninitialised per-CPU data.
    pub const fn new() -> Self {
        Self {
            counters: [0u64; NR_SLOTS],
            active: false,
        }
    }
}

// ── SrcuCallback ───────────────────────────────────────────────

/// A callback deferred until after a grace period.
#[derive(Clone, Copy)]
pub struct SrcuCallback {
    /// Application-defined identifier.
    pub id: u64,
    /// Associated data.
    pub data: u64,
    /// Grace-period sequence after which this fires.
    pub gp_seq: u64,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl SrcuCallback {
    /// Creates an empty callback slot.
    pub const fn new() -> Self {
        Self {
            id: 0,
            data: 0,
            gp_seq: 0,
            active: false,
        }
    }
}

// ── SrcuDomain ─────────────────────────────────────────────────

/// A single SRCU domain with per-CPU counters and callbacks.
pub struct SrcuDomain {
    /// Domain name (NUL-padded).
    name: [u8; MAX_NAME_LEN],
    /// Per-CPU read-side data.
    per_cpu: [SrcuPerCpu; MAX_CPUS],
    /// Number of initialised CPUs.
    nr_cpus: usize,
    /// Current active generation slot (0 or 1).
    generation: usize,
    /// Grace-period sequence counter.
    gp_seq: u64,
    /// Grace-period state machine.
    gp_state: GracePeriodState,
    /// Grace-period mode (normal vs expedited).
    gp_mode: GracePeriodMode,
    /// Deferred callbacks.
    callbacks: [SrcuCallback; MAX_CALLBACKS],
    /// Number of pending callbacks.
    cb_count: usize,
    /// Domain lifecycle state.
    state: DomainState,
}

impl SrcuDomain {
    /// Creates an uninitialised domain.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            per_cpu: [const { SrcuPerCpu::new() }; MAX_CPUS],
            nr_cpus: 0,
            generation: 0,
            gp_seq: 0,
            gp_state: GracePeriodState::Idle,
            gp_mode: GracePeriodMode::Normal,
            callbacks: [const { SrcuCallback::new() }; MAX_CALLBACKS],
            cb_count: 0,
            state: DomainState::Uninit,
        }
    }

    /// Initialises the domain for the given number of CPUs.
    pub fn init(&mut self, name: &[u8], nr_cpus: usize) -> Result<()> {
        if nr_cpus == 0 || nr_cpus > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.state != DomainState::Uninit {
            return Err(Error::AlreadyExists);
        }
        let nlen = name.len().min(MAX_NAME_LEN);
        self.name[..nlen].copy_from_slice(&name[..nlen]);
        for cpu in self.per_cpu.iter_mut().take(nr_cpus) {
            cpu.active = true;
            cpu.counters = [0u64; NR_SLOTS];
        }
        self.nr_cpus = nr_cpus;
        self.generation = 0;
        self.gp_seq = 0;
        self.state = DomainState::Active;
        Ok(())
    }

    /// Acquires an SRCU read lock on the given CPU. Returns the
    /// generation index that must be passed to `read_unlock`.
    pub fn read_lock(&mut self, cpu: usize) -> Result<usize> {
        if self.state != DomainState::Active {
            return Err(Error::InvalidArgument);
        }
        if cpu >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }
        let idx = self.generation;
        self.per_cpu[cpu].counters[idx] += 1;
        Ok(idx)
    }

    /// Releases an SRCU read lock on the given CPU with the
    /// generation obtained from `read_lock`.
    pub fn read_unlock(&mut self, cpu: usize, idx: usize) -> Result<()> {
        if cpu >= self.nr_cpus || idx >= NR_SLOTS {
            return Err(Error::InvalidArgument);
        }
        if self.per_cpu[cpu].counters[idx] == 0 {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[cpu].counters[idx] -= 1;
        Ok(())
    }

    /// Waits for a grace period — all readers that held locks
    /// in the old generation must have released them.
    /// Returns the new grace-period sequence number.
    pub fn synchronize(&mut self) -> Result<u64> {
        if self.state != DomainState::Active {
            return Err(Error::InvalidArgument);
        }
        let old_gen = self.generation;
        // Flip generation.
        self.generation = 1 - old_gen;
        self.gp_state = GracePeriodState::WaitReaders;
        // Check whether all old-generation readers have
        // completed (sum of counters[old_gen] == 0).
        let old_sum: u64 = self.per_cpu[..self.nr_cpus]
            .iter()
            .map(|pc| pc.counters[old_gen])
            .sum();
        if old_sum > 0 {
            // In a real implementation we would block or poll.
            return Err(Error::WouldBlock);
        }
        // Grace period complete.
        self.gp_seq += 1;
        self.gp_state = GracePeriodState::Callbacks;
        self.invoke_callbacks()?;
        self.gp_state = GracePeriodState::Idle;
        Ok(self.gp_seq)
    }

    /// Registers a callback to be invoked after the next grace
    /// period.
    pub fn call_srcu(&mut self, id: u64, data: u64) -> Result<()> {
        if self.state != DomainState::Active {
            return Err(Error::InvalidArgument);
        }
        let pos = self
            .callbacks
            .iter()
            .position(|cb| !cb.active)
            .ok_or(Error::OutOfMemory)?;
        self.callbacks[pos] = SrcuCallback {
            id,
            data,
            gp_seq: self.gp_seq + 1,
            active: true,
        };
        self.cb_count += 1;
        Ok(())
    }

    /// Sets the grace-period mode.
    pub fn set_mode(&mut self, mode: GracePeriodMode) {
        self.gp_mode = mode;
    }

    /// Returns the current grace-period mode.
    pub fn mode(&self) -> GracePeriodMode {
        self.gp_mode
    }

    /// Returns the current grace-period sequence number.
    pub fn gp_seq(&self) -> u64 {
        self.gp_seq
    }

    /// Returns the number of pending callbacks.
    pub fn pending_callbacks(&self) -> usize {
        self.cb_count
    }

    /// Returns the domain state.
    pub fn state(&self) -> DomainState {
        self.state
    }

    /// Invokes all callbacks whose gp_seq has been reached.
    fn invoke_callbacks(&mut self) -> Result<()> {
        let current_seq = self.gp_seq;
        for cb in &mut self.callbacks {
            if cb.active && cb.gp_seq <= current_seq {
                // In a real kernel we would invoke the
                // callback function. Here we just clear it.
                *cb = SrcuCallback::new();
                self.cb_count = self.cb_count.saturating_sub(1);
            }
        }
        Ok(())
    }
}

// ── SrcuStats ──────────────────────────────────────────────────

/// Global SRCU statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct SrcuStats {
    /// Total domains initialised.
    pub domains_init: u64,
    /// Total read locks acquired.
    pub read_locks: u64,
    /// Total grace periods completed.
    pub grace_periods: u64,
    /// Total callbacks invoked.
    pub callbacks_invoked: u64,
}

// ── SrcuManager ────────────────────────────────────────────────

/// Manager for all SRCU domains.
pub struct SrcuManager {
    /// Domain pool.
    domains: [SrcuDomain; MAX_DOMAINS],
    /// Number of initialised domains.
    domain_count: usize,
    /// Global statistics.
    stats: SrcuStats,
}

impl SrcuManager {
    /// Creates an empty manager.
    pub const fn new() -> Self {
        Self {
            domains: [const { SrcuDomain::new() }; MAX_DOMAINS],
            domain_count: 0,
            stats: SrcuStats {
                domains_init: 0,
                read_locks: 0,
                grace_periods: 0,
                callbacks_invoked: 0,
            },
        }
    }

    /// Creates and initialises a new SRCU domain.
    /// Returns its index.
    pub fn create_domain(&mut self, name: &[u8], nr_cpus: usize) -> Result<usize> {
        let pos = self
            .domains
            .iter()
            .position(|d| d.state == DomainState::Uninit)
            .ok_or(Error::OutOfMemory)?;
        self.domains[pos].init(name, nr_cpus)?;
        self.domain_count += 1;
        self.stats.domains_init += 1;
        Ok(pos)
    }

    /// Returns a mutable reference to a domain.
    pub fn domain_mut(&mut self, idx: usize) -> Result<&mut SrcuDomain> {
        if idx >= MAX_DOMAINS {
            return Err(Error::InvalidArgument);
        }
        if self.domains[idx].state == DomainState::Uninit {
            return Err(Error::NotFound);
        }
        Ok(&mut self.domains[idx])
    }

    /// Returns a reference to a domain.
    pub fn domain(&self, idx: usize) -> Result<&SrcuDomain> {
        if idx >= MAX_DOMAINS {
            return Err(Error::InvalidArgument);
        }
        if self.domains[idx].state == DomainState::Uninit {
            return Err(Error::NotFound);
        }
        Ok(&self.domains[idx])
    }

    /// Returns global statistics.
    pub fn stats(&self) -> &SrcuStats {
        &self.stats
    }

    /// Returns the number of active domains.
    pub fn domain_count(&self) -> usize {
        self.domain_count
    }
}
