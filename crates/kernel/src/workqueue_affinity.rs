// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Workqueue CPU affinity management.
//!
//! Controls how workqueue work items are dispatched to CPUs.
//! Supports per-workqueue CPU affinity masks, NUMA-aware placement,
//! and dynamic rebalancing when CPUs are added or removed.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum workqueues managed.
const MAX_WORKQUEUES: usize = 64;

/// Maximum CPUs.
const MAX_CPUS: usize = 128;

/// CPU mask word count.
const CPU_MASK_WORDS: usize = (MAX_CPUS + 63) / 64;

/// Maximum affinity change log entries.
const MAX_CHANGE_LOG: usize = 128;

// ── Types ────────────────────────────────────────────────────────────

/// Identifies a workqueue in the affinity system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WqAffinityId(u32);

impl WqAffinityId {
    /// Creates a new workqueue affinity identifier.
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Returns the raw identifier.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// CPU affinity mask.
#[derive(Debug, Clone)]
pub struct AffinityMask {
    /// Bitmask words.
    bits: [u64; CPU_MASK_WORDS],
}

impl AffinityMask {
    /// Creates an empty affinity mask.
    pub const fn new() -> Self {
        Self {
            bits: [0u64; CPU_MASK_WORDS],
        }
    }

    /// Creates a mask with all CPUs set.
    pub const fn all() -> Self {
        Self {
            bits: [u64::MAX; CPU_MASK_WORDS],
        }
    }

    /// Sets a CPU in the mask.
    pub fn set(&mut self, cpu: u32) -> Result<()> {
        let idx = (cpu as usize) / 64;
        let bit = (cpu as usize) % 64;
        if idx >= CPU_MASK_WORDS {
            return Err(Error::InvalidArgument);
        }
        self.bits[idx] |= 1u64 << bit;
        Ok(())
    }

    /// Clears a CPU from the mask.
    pub fn clear(&mut self, cpu: u32) -> Result<()> {
        let idx = (cpu as usize) / 64;
        let bit = (cpu as usize) % 64;
        if idx >= CPU_MASK_WORDS {
            return Err(Error::InvalidArgument);
        }
        self.bits[idx] &= !(1u64 << bit);
        Ok(())
    }

    /// Tests whether a CPU is set.
    pub fn test(&self, cpu: u32) -> bool {
        let idx = (cpu as usize) / 64;
        let bit = (cpu as usize) % 64;
        if idx >= CPU_MASK_WORDS {
            return false;
        }
        self.bits[idx] & (1u64 << bit) != 0
    }

    /// Counts set CPUs.
    pub fn count(&self) -> u32 {
        self.bits.iter().map(|w| w.count_ones()).sum()
    }

    /// Returns whether the mask is empty.
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|&w| w == 0)
    }
}

impl Default for AffinityMask {
    fn default() -> Self {
        Self::new()
    }
}

/// Affinity scope controlling how work items are placed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AffinityScope {
    /// Work items run on any allowed CPU.
    System,
    /// Prefer the NUMA node of the submitter.
    Numa,
    /// Prefer the same physical die.
    Die,
    /// Prefer the same core (SMT siblings).
    Core,
    /// Strictly run on the submitting CPU.
    Cpu,
}

impl Default for AffinityScope {
    fn default() -> Self {
        Self::System
    }
}

/// Per-workqueue affinity configuration.
#[derive(Debug)]
pub struct WqAffinityConfig {
    /// Workqueue identifier.
    id: WqAffinityId,
    /// Allowed CPU mask.
    allowed_cpus: AffinityMask,
    /// Effective CPU mask (after online/offline adjustments).
    effective_cpus: AffinityMask,
    /// Affinity scope.
    scope: AffinityScope,
    /// Whether this workqueue is NUMA-aware.
    numa_aware: bool,
    /// Preferred NUMA node (-1 for any).
    preferred_node: i32,
    /// Total work items dispatched.
    dispatch_count: u64,
    /// Number of affinity changes.
    change_count: u64,
}

impl WqAffinityConfig {
    /// Creates a new workqueue affinity configuration.
    pub const fn new(id: WqAffinityId) -> Self {
        Self {
            id,
            allowed_cpus: AffinityMask::new(),
            effective_cpus: AffinityMask::new(),
            scope: AffinityScope::System,
            numa_aware: false,
            preferred_node: -1,
            dispatch_count: 0,
            change_count: 0,
        }
    }

    /// Returns the affinity scope.
    pub const fn scope(&self) -> AffinityScope {
        self.scope
    }

    /// Returns the dispatch count.
    pub const fn dispatch_count(&self) -> u64 {
        self.dispatch_count
    }
}

/// Affinity change log entry.
#[derive(Debug, Clone)]
pub struct AffinityChangeEntry {
    /// Workqueue identifier.
    wq_id: WqAffinityId,
    /// Reason for the change.
    reason: AffinityChangeReason,
    /// New CPU count after change.
    new_cpu_count: u32,
    /// Timestamp.
    timestamp_ns: u64,
}

/// Reason for an affinity change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AffinityChangeReason {
    /// User requested change.
    UserRequest,
    /// CPU came online.
    CpuOnline,
    /// CPU went offline.
    CpuOffline,
    /// NUMA topology change.
    NumaChange,
}

impl AffinityChangeEntry {
    /// Creates a new change entry.
    pub const fn new(
        wq_id: WqAffinityId,
        reason: AffinityChangeReason,
        new_cpu_count: u32,
    ) -> Self {
        Self {
            wq_id,
            reason,
            new_cpu_count,
            timestamp_ns: 0,
        }
    }
}

/// Workqueue affinity statistics.
#[derive(Debug, Clone)]
pub struct WqAffinityStats {
    /// Total managed workqueues.
    pub total_workqueues: u32,
    /// Total affinity changes.
    pub total_changes: u64,
    /// Total dispatches.
    pub total_dispatches: u64,
    /// NUMA-aware workqueues.
    pub numa_aware_count: u32,
}

impl Default for WqAffinityStats {
    fn default() -> Self {
        Self::new()
    }
}

impl WqAffinityStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_workqueues: 0,
            total_changes: 0,
            total_dispatches: 0,
            numa_aware_count: 0,
        }
    }
}

/// Central workqueue affinity manager.
#[derive(Debug)]
pub struct WqAffinityManager {
    /// Per-workqueue affinity configs.
    configs: [Option<WqAffinityConfig>; MAX_WORKQUEUES],
    /// Change log.
    change_log: [Option<AffinityChangeEntry>; MAX_CHANGE_LOG],
    /// Log write position.
    log_pos: usize,
    /// Number of managed workqueues.
    wq_count: usize,
    /// Next identifier.
    next_id: u32,
    /// Total changes.
    total_changes: u64,
}

impl Default for WqAffinityManager {
    fn default() -> Self {
        Self::new()
    }
}

impl WqAffinityManager {
    /// Creates a new workqueue affinity manager.
    pub const fn new() -> Self {
        Self {
            configs: [const { None }; MAX_WORKQUEUES],
            change_log: [const { None }; MAX_CHANGE_LOG],
            log_pos: 0,
            wq_count: 0,
            next_id: 1,
            total_changes: 0,
        }
    }

    /// Registers a workqueue for affinity management.
    pub fn register_workqueue(&mut self, scope: AffinityScope) -> Result<WqAffinityId> {
        if self.wq_count >= MAX_WORKQUEUES {
            return Err(Error::OutOfMemory);
        }
        let id = WqAffinityId::new(self.next_id);
        self.next_id += 1;
        let mut config = WqAffinityConfig::new(id);
        config.scope = scope;
        if let Some(slot) = self.configs.iter_mut().find(|s| s.is_none()) {
            *slot = Some(config);
            self.wq_count += 1;
            Ok(id)
        } else {
            Err(Error::OutOfMemory)
        }
    }

    /// Sets the allowed CPU mask for a workqueue.
    pub fn set_allowed_cpus(&mut self, wq_id: WqAffinityId, cpus: &[u32]) -> Result<()> {
        let config = self
            .configs
            .iter_mut()
            .flatten()
            .find(|c| c.id == wq_id)
            .ok_or(Error::NotFound)?;
        config.allowed_cpus = AffinityMask::new();
        for &cpu in cpus {
            config.allowed_cpus.set(cpu)?;
        }
        config.effective_cpus = config.allowed_cpus.clone();
        config.change_count += 1;
        self.total_changes += 1;
        Ok(())
    }

    /// Handles a CPU coming online.
    pub fn cpu_online(&mut self, cpu: u32) -> Result<u32> {
        let mut updated = 0u32;
        for config in self.configs.iter_mut().flatten() {
            if config.allowed_cpus.test(cpu) {
                config.effective_cpus.set(cpu)?;
                config.change_count += 1;
                updated += 1;
            }
        }
        self.total_changes += updated as u64;
        Ok(updated)
    }

    /// Handles a CPU going offline.
    pub fn cpu_offline(&mut self, cpu: u32) -> Result<u32> {
        let mut updated = 0u32;
        for config in self.configs.iter_mut().flatten() {
            if config.effective_cpus.test(cpu) {
                config.effective_cpus.clear(cpu)?;
                config.change_count += 1;
                updated += 1;
            }
        }
        self.total_changes += updated as u64;
        Ok(updated)
    }

    /// Records a dispatch for a workqueue.
    pub fn record_dispatch(&mut self, wq_id: WqAffinityId) -> Result<()> {
        let config = self
            .configs
            .iter_mut()
            .flatten()
            .find(|c| c.id == wq_id)
            .ok_or(Error::NotFound)?;
        config.dispatch_count += 1;
        Ok(())
    }

    /// Unregisters a workqueue.
    pub fn unregister_workqueue(&mut self, wq_id: WqAffinityId) -> Result<()> {
        let slot = self
            .configs
            .iter_mut()
            .find(|s| s.as_ref().map_or(false, |c| c.id == wq_id))
            .ok_or(Error::NotFound)?;
        *slot = None;
        self.wq_count -= 1;
        Ok(())
    }

    /// Returns statistics.
    pub fn stats(&self) -> WqAffinityStats {
        let mut s = WqAffinityStats::new();
        s.total_workqueues = self.wq_count as u32;
        s.total_changes = self.total_changes;
        for config in self.configs.iter().flatten() {
            s.total_dispatches += config.dispatch_count;
            if config.numa_aware {
                s.numa_aware_count += 1;
            }
        }
        s
    }

    /// Returns the number of managed workqueues.
    pub const fn wq_count(&self) -> usize {
        self.wq_count
    }
}
