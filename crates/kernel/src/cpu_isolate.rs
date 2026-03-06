// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU isolation and nohz_full management.
//!
//! Provides mechanisms to isolate CPUs from general kernel
//! interference, including timer tick suppression (nohz_full),
//! workqueue affinity, RCU callback offloading, and IRQ
//! steering. Isolated CPUs are ideal for latency-sensitive
//! real-time workloads.

use oncrix_lib::{Error, Result};

/// Maximum number of CPUs.
const MAX_CPUS: usize = 256;

/// Maximum number of isolation groups.
const MAX_ISOLATION_GROUPS: usize = 32;

/// CPU isolation flags.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IsolationFlags {
    /// Raw flag bits.
    bits: u32,
}

impl IsolationFlags {
    /// No isolation.
    pub const NONE: Self = Self { bits: 0 };
    /// Isolate from timer ticks (nohz_full).
    pub const NOHZ_FULL: Self = Self { bits: 1 << 0 };
    /// Isolate from unbound workqueues.
    pub const NO_WORKQUEUE: Self = Self { bits: 1 << 1 };
    /// Offload RCU callbacks to other CPUs.
    pub const RCU_NOCB: Self = Self { bits: 1 << 2 };
    /// Isolate from managed IRQs.
    pub const NO_MANAGED_IRQ: Self = Self { bits: 1 << 3 };
    /// Domain isolation (no load balancing).
    pub const NO_LOAD_BALANCE: Self = Self { bits: 1 << 4 };

    /// Creates empty flags.
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    /// Returns the raw flag bits.
    pub const fn bits(&self) -> u32 {
        self.bits
    }

    /// Checks if a specific flag is set.
    pub const fn contains(&self, other: Self) -> bool {
        (self.bits & other.bits) == other.bits
    }

    /// Sets a flag.
    pub fn insert(&mut self, other: Self) {
        self.bits |= other.bits;
    }

    /// Clears a flag.
    pub fn remove(&mut self, other: Self) {
        self.bits &= !other.bits;
    }
}

impl Default for IsolationFlags {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-CPU isolation state.
#[derive(Clone, Copy)]
pub struct CpuIsolationState {
    /// CPU identifier.
    cpu_id: u32,
    /// Current isolation flags.
    flags: IsolationFlags,
    /// Whether this CPU is currently isolated.
    isolated: bool,
    /// Whether nohz_full tick is suppressed.
    tick_suppressed: bool,
    /// Number of tasks currently pinned to this CPU.
    pinned_tasks: u32,
    /// Last tick timestamp in nanoseconds.
    last_tick_ns: u64,
    /// Isolation group this CPU belongs to.
    group_id: i32,
}

impl CpuIsolationState {
    /// Creates a new CPU isolation state.
    pub const fn new() -> Self {
        Self {
            cpu_id: 0,
            flags: IsolationFlags::NONE,
            isolated: false,
            tick_suppressed: false,
            pinned_tasks: 0,
            last_tick_ns: 0,
            group_id: -1,
        }
    }

    /// Returns the CPU identifier.
    pub const fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Returns whether this CPU is isolated.
    pub const fn is_isolated(&self) -> bool {
        self.isolated
    }

    /// Returns the isolation flags.
    pub const fn flags(&self) -> IsolationFlags {
        self.flags
    }

    /// Returns whether the tick is suppressed.
    pub const fn is_tick_suppressed(&self) -> bool {
        self.tick_suppressed
    }

    /// Returns the number of pinned tasks.
    pub const fn pinned_tasks(&self) -> u32 {
        self.pinned_tasks
    }

    /// Checks if tick can be suppressed (at most 1 task).
    pub const fn can_suppress_tick(&self) -> bool {
        self.isolated && self.flags.contains(IsolationFlags::NOHZ_FULL) && self.pinned_tasks <= 1
    }
}

impl Default for CpuIsolationState {
    fn default() -> Self {
        Self::new()
    }
}

/// Group of isolated CPUs sharing common configuration.
#[derive(Clone, Copy)]
pub struct IsolationGroup {
    /// Group identifier.
    id: u32,
    /// Common isolation flags for this group.
    flags: IsolationFlags,
    /// Number of CPUs in this group.
    cpu_count: u32,
    /// First CPU in this group.
    first_cpu: u32,
    /// Whether this group is active.
    active: bool,
    /// Description tag for debugging.
    tag: [u8; 32],
    /// Length of the tag string.
    tag_len: usize,
}

impl IsolationGroup {
    /// Creates a new isolation group.
    pub const fn new() -> Self {
        Self {
            id: 0,
            flags: IsolationFlags::NONE,
            cpu_count: 0,
            first_cpu: 0,
            active: false,
            tag: [0u8; 32],
            tag_len: 0,
        }
    }

    /// Returns the group identifier.
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Returns the isolation flags.
    pub const fn flags(&self) -> IsolationFlags {
        self.flags
    }

    /// Returns the number of CPUs in this group.
    pub const fn cpu_count(&self) -> u32 {
        self.cpu_count
    }

    /// Returns whether this group is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }
}

impl Default for IsolationGroup {
    fn default() -> Self {
        Self::new()
    }
}

/// CPU isolation manager.
pub struct CpuIsolationManager {
    /// Per-CPU isolation state.
    cpus: [CpuIsolationState; MAX_CPUS],
    /// Number of managed CPUs.
    cpu_count: usize,
    /// Isolation groups.
    groups: [IsolationGroup; MAX_ISOLATION_GROUPS],
    /// Number of groups.
    group_count: usize,
    /// Number of currently isolated CPUs.
    isolated_count: usize,
    /// Housekeeping CPU (must never be isolated).
    housekeeping_cpu: u32,
}

impl CpuIsolationManager {
    /// Creates a new CPU isolation manager.
    pub const fn new() -> Self {
        Self {
            cpus: [const { CpuIsolationState::new() }; MAX_CPUS],
            cpu_count: 0,
            groups: [const { IsolationGroup::new() }; MAX_ISOLATION_GROUPS],
            group_count: 0,
            isolated_count: 0,
            housekeeping_cpu: 0,
        }
    }

    /// Registers a CPU with the isolation manager.
    pub fn register_cpu(&mut self, cpu_id: u32) -> Result<()> {
        if self.cpu_count >= MAX_CPUS {
            return Err(Error::OutOfMemory);
        }
        self.cpus[self.cpu_count].cpu_id = cpu_id;
        self.cpu_count += 1;
        Ok(())
    }

    /// Sets the housekeeping CPU.
    pub fn set_housekeeping_cpu(&mut self, cpu_id: u32) -> Result<()> {
        // Verify CPU exists
        let found = self.cpus[..self.cpu_count]
            .iter()
            .any(|c| c.cpu_id == cpu_id);
        if !found {
            return Err(Error::NotFound);
        }
        self.housekeeping_cpu = cpu_id;
        Ok(())
    }

    /// Isolates a CPU with the given flags.
    pub fn isolate_cpu(&mut self, cpu_id: u32, flags: IsolationFlags) -> Result<()> {
        if cpu_id == self.housekeeping_cpu {
            return Err(Error::PermissionDenied);
        }
        for i in 0..self.cpu_count {
            if self.cpus[i].cpu_id == cpu_id {
                self.cpus[i].flags = flags;
                self.cpus[i].isolated = true;
                if flags.contains(IsolationFlags::NOHZ_FULL) && self.cpus[i].can_suppress_tick() {
                    self.cpus[i].tick_suppressed = true;
                }
                self.isolated_count += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Removes isolation from a CPU.
    pub fn deisolate_cpu(&mut self, cpu_id: u32) -> Result<()> {
        for i in 0..self.cpu_count {
            if self.cpus[i].cpu_id == cpu_id {
                self.cpus[i].flags = IsolationFlags::NONE;
                self.cpus[i].isolated = false;
                self.cpus[i].tick_suppressed = false;
                if self.isolated_count > 0 {
                    self.isolated_count -= 1;
                }
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Creates an isolation group.
    pub fn create_group(&mut self, flags: IsolationFlags) -> Result<u32> {
        if self.group_count >= MAX_ISOLATION_GROUPS {
            return Err(Error::OutOfMemory);
        }
        let id = self.group_count as u32;
        self.groups[self.group_count].id = id;
        self.groups[self.group_count].flags = flags;
        self.groups[self.group_count].active = true;
        self.group_count += 1;
        Ok(id)
    }

    /// Returns the number of isolated CPUs.
    pub const fn isolated_count(&self) -> usize {
        self.isolated_count
    }

    /// Returns the housekeeping CPU.
    pub const fn housekeeping_cpu(&self) -> u32 {
        self.housekeeping_cpu
    }

    /// Returns the total number of managed CPUs.
    pub const fn cpu_count(&self) -> usize {
        self.cpu_count
    }

    /// Returns whether a CPU is isolated.
    pub fn is_cpu_isolated(&self, cpu_id: u32) -> bool {
        self.cpus[..self.cpu_count]
            .iter()
            .any(|c| c.cpu_id == cpu_id && c.isolated)
    }
}

impl Default for CpuIsolationManager {
    fn default() -> Self {
        Self::new()
    }
}
