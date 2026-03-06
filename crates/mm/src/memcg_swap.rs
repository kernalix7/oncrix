// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory cgroup swap accounting subsystem.
//!
//! Extends the base memcg controller with per-cgroup swap usage
//! tracking, swap limits, and swap-in/swap-out event accounting.
//! This ensures that containers and cgroups cannot exhaust system
//! swap by enforcing per-group swap limits independently of memory
//! limits.
//!
//! Inspired by Linux `mm/memcontrol.c` swap accounting and the
//! `memory.swap.max` / `memory.swap.current` cgroup v2 files.
//!
//! Key components:
//! - [`SwapChargeResult`] — outcome of a swap charge attempt
//! - [`SwapAccountEntry`] — per-page swap charge record
//! - [`SwapCgroupCounters`] — per-cgroup swap usage counters
//! - [`SwapCgroupConfig`] — per-cgroup swap configuration
//! - [`SwapCgroup`] — a single cgroup's swap accounting state
//! - [`SwapEventType`] — swap event types for accounting
//! - [`SwapEvent`] — recorded swap event
//! - [`SwapCgroupRegistry`] — registry of all swap cgroups
//! - [`SwapCgroupStats`] — aggregate swap statistics
//!
//! Reference: Linux `mm/memcontrol.c`, `mm/swap_cgroup.c`,
//! kernel cgroup v2 docs `memory.swap.*`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of swap cgroups in the registry.
const MAX_SWAP_CGROUPS: usize = 64;

/// Maximum length of a cgroup name.
const MAX_CGROUP_NAME_LEN: usize = 32;

/// Sentinel value meaning "no swap limit".
const SWAP_NO_LIMIT: u64 = u64::MAX;

/// Maximum number of PIDs per cgroup for swap tracking.
const MAX_PIDS_PER_CGROUP: usize = 64;

/// Maximum swap charge records tracked globally.
const MAX_SWAP_CHARGES: usize = 4096;

/// Maximum swap events retained per cgroup.
const MAX_SWAP_EVENTS: usize = 128;

/// Maximum number of swap event records in global log.
const MAX_GLOBAL_EVENTS: usize = 256;

/// Swap-out event counter weight for scoring.
const _SWAPOUT_WEIGHT: u64 = 1;

/// Swap-in event counter weight for scoring.
const _SWAPIN_WEIGHT: u64 = 2;

// -------------------------------------------------------------------
// SwapChargeResult
// -------------------------------------------------------------------

/// Outcome of a swap charge attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SwapChargeResult {
    /// Charge was accepted; usage increased.
    #[default]
    Charged,
    /// Charge was rejected because swap limit was exceeded.
    LimitExceeded,
    /// Charge was rejected because the cgroup is frozen.
    Frozen,
    /// Charge was rejected because accounting is disabled.
    Disabled,
}

// -------------------------------------------------------------------
// SwapAccountEntry
// -------------------------------------------------------------------

/// Per-page swap charge record.
///
/// Tracks which cgroup "owns" a swap slot so that uncharges go
/// back to the correct cgroup even after process migration.
#[derive(Debug, Clone, Copy)]
pub struct SwapAccountEntry {
    /// Swap area index.
    pub swap_area: u8,
    /// Slot offset within the swap area.
    pub slot_offset: u32,
    /// Cgroup ID that was charged.
    pub cgroup_id: u32,
    /// Number of pages charged (usually 1).
    pub nr_pages: u32,
    /// Timestamp of the charge (nanoseconds).
    pub charge_ns: u64,
    /// Whether this entry is active.
    active: bool,
}

impl SwapAccountEntry {
    /// Create an empty entry.
    const fn empty() -> Self {
        Self {
            swap_area: 0,
            slot_offset: 0,
            cgroup_id: 0,
            nr_pages: 0,
            charge_ns: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// SwapCgroupCounters
// -------------------------------------------------------------------

/// Per-cgroup swap usage counters.
#[derive(Debug, Clone, Copy, Default)]
pub struct SwapCgroupCounters {
    /// Current swap usage in bytes.
    pub usage: u64,
    /// Peak swap usage in bytes.
    pub max_usage: u64,
    /// Swap limit in bytes.
    pub limit: u64,
    /// Number of failed charge attempts due to limit.
    pub failcnt: u64,
    /// Total bytes swapped out.
    pub total_swapout: u64,
    /// Total bytes swapped in.
    pub total_swapin: u64,
    /// Number of swap-out events.
    pub swapout_events: u64,
    /// Number of swap-in events.
    pub swapin_events: u64,
    /// Number of successful charges.
    pub charge_success: u64,
    /// Number of uncharges.
    pub uncharge_count: u64,
}

// -------------------------------------------------------------------
// SwapCgroupConfig
// -------------------------------------------------------------------

/// Per-cgroup swap configuration.
#[derive(Debug, Clone, Copy)]
pub struct SwapCgroupConfig {
    /// Swap limit in bytes (`SWAP_NO_LIMIT` for unlimited).
    pub swap_limit: u64,
    /// Whether swap accounting is enabled for this cgroup.
    pub accounting_enabled: bool,
    /// Whether to reclaim swap on limit hit (vs. fail).
    pub reclaim_on_limit: bool,
    /// Whether to account swap to ancestors (hierarchical).
    pub hierarchical: bool,
}

impl Default for SwapCgroupConfig {
    fn default() -> Self {
        Self {
            swap_limit: SWAP_NO_LIMIT,
            accounting_enabled: true,
            reclaim_on_limit: false,
            hierarchical: true,
        }
    }
}

// -------------------------------------------------------------------
// SwapCgroupState
// -------------------------------------------------------------------

/// State of a swap cgroup entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SwapCgroupState {
    /// Cgroup is active and accepting charges.
    #[default]
    Active,
    /// Cgroup is frozen — no new charges.
    Frozen,
    /// Cgroup has been removed.
    Offline,
}

// -------------------------------------------------------------------
// SwapEventType
// -------------------------------------------------------------------

/// Types of swap events for accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SwapEventType {
    /// Page swapped out (written to swap area).
    #[default]
    SwapOut,
    /// Page swapped in (read from swap area).
    SwapIn,
    /// Swap charge applied.
    Charge,
    /// Swap uncharge applied.
    Uncharge,
    /// Swap limit exceeded.
    LimitHit,
    /// Swap reclaim triggered.
    Reclaim,
}

// -------------------------------------------------------------------
// SwapEvent
// -------------------------------------------------------------------

/// A recorded swap event.
#[derive(Debug, Clone, Copy)]
pub struct SwapEvent {
    /// Event type.
    pub event_type: SwapEventType,
    /// Cgroup ID.
    pub cgroup_id: u32,
    /// Number of pages involved.
    pub nr_pages: u32,
    /// Timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Whether this slot is occupied.
    active: bool,
}

impl SwapEvent {
    /// Create an empty event.
    const fn empty() -> Self {
        Self {
            event_type: SwapEventType::SwapOut,
            cgroup_id: 0,
            nr_pages: 0,
            timestamp_ns: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// SwapCgroup
// -------------------------------------------------------------------

/// A single cgroup's swap accounting state.
#[derive(Debug)]
pub struct SwapCgroup {
    /// Cgroup identifier.
    id: u32,
    /// Cgroup name.
    name: [u8; MAX_CGROUP_NAME_LEN],
    /// Length of valid bytes in `name`.
    name_len: usize,
    /// Parent cgroup ID (0 = root).
    parent_id: u32,
    /// Current state.
    state: SwapCgroupState,
    /// Swap counters.
    counters: SwapCgroupCounters,
    /// Configuration.
    config: SwapCgroupConfig,
    /// Attached PIDs.
    pids: [u32; MAX_PIDS_PER_CGROUP],
    /// Number of attached PIDs.
    pid_count: usize,
    /// Per-cgroup event log.
    events: [SwapEvent; MAX_SWAP_EVENTS],
    /// Number of recorded events.
    event_count: usize,
    /// Write head for event ring buffer.
    event_head: usize,
    /// Whether this slot is active.
    active: bool,
}

impl SwapCgroup {
    /// Create an empty, inactive swap cgroup.
    fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_CGROUP_NAME_LEN],
            name_len: 0,
            parent_id: 0,
            state: SwapCgroupState::Active,
            counters: SwapCgroupCounters {
                usage: 0,
                max_usage: 0,
                limit: SWAP_NO_LIMIT,
                failcnt: 0,
                total_swapout: 0,
                total_swapin: 0,
                swapout_events: 0,
                swapin_events: 0,
                charge_success: 0,
                uncharge_count: 0,
            },
            config: SwapCgroupConfig::default(),
            pids: [0u32; MAX_PIDS_PER_CGROUP],
            pid_count: 0,
            events: [const { SwapEvent::empty() }; MAX_SWAP_EVENTS],
            event_count: 0,
            event_head: 0,
            active: false,
        }
    }

    /// Record a swap event in this cgroup's ring buffer.
    fn record_event(&mut self, event_type: SwapEventType, nr_pages: u32, now_ns: u64) {
        let idx = self.event_head % MAX_SWAP_EVENTS;
        self.events[idx] = SwapEvent {
            event_type,
            cgroup_id: self.id,
            nr_pages,
            timestamp_ns: now_ns,
            active: true,
        };
        self.event_head = (self.event_head + 1) % MAX_SWAP_EVENTS;
        if self.event_count < MAX_SWAP_EVENTS {
            self.event_count += 1;
        }
    }
}

// -------------------------------------------------------------------
// SwapCgroupStats
// -------------------------------------------------------------------

/// Aggregate swap cgroup statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct SwapCgroupStats {
    /// Total active cgroups.
    pub active_cgroups: usize,
    /// Total swap usage across all cgroups (bytes).
    pub total_swap_usage: u64,
    /// Total swap limit hit events.
    pub total_limit_hits: u64,
    /// Total swap-out events across all cgroups.
    pub total_swapout_events: u64,
    /// Total swap-in events across all cgroups.
    pub total_swapin_events: u64,
    /// Total charge successes.
    pub total_charges: u64,
    /// Total uncharges.
    pub total_uncharges: u64,
    /// Active swap charge entries.
    pub active_charge_entries: usize,
}

// -------------------------------------------------------------------
// SwapCgroupRegistry
// -------------------------------------------------------------------

/// Registry of all swap cgroups with global charge tracking.
///
/// Manages creation, lookup, charging/uncharging, and statistics
/// for per-cgroup swap accounting.
///
/// # Example (conceptual)
///
/// ```ignore
/// let mut reg = SwapCgroupRegistry::new();
/// reg.create_cgroup(1, b"container-A", 0)?;
/// reg.set_swap_limit(1, 100 * 1024 * 1024)?; // 100 MiB
/// reg.attach_pid(1, 42)?;
/// let result = reg.charge_swap(1, 0, 100, 1, now_ns)?;
/// assert_eq!(result, SwapChargeResult::Charged);
/// ```
pub struct SwapCgroupRegistry {
    /// Cgroup slots.
    cgroups: [SwapCgroup; MAX_SWAP_CGROUPS],
    /// Global swap charge tracking.
    charges: [SwapAccountEntry; MAX_SWAP_CHARGES],
    /// Number of active charge entries.
    charge_count: usize,
    /// Global event log.
    global_events: [SwapEvent; MAX_GLOBAL_EVENTS],
    /// Number of global events.
    global_event_count: usize,
    /// Global event write head.
    global_event_head: usize,
    /// Next cgroup ID to assign.
    next_id: u32,
}

impl SwapCgroupRegistry {
    /// Create a new, empty swap cgroup registry.
    pub fn new() -> Self {
        // SwapCgroup is too large for [const { ... }], init manually.
        let mut cgroups: [SwapCgroup; MAX_SWAP_CGROUPS] =
            core::array::from_fn(|_| SwapCgroup::empty());
        // Ensure all are inactive.
        for cg in &mut cgroups {
            cg.active = false;
        }
        Self {
            cgroups,
            charges: [const { SwapAccountEntry::empty() }; MAX_SWAP_CHARGES],
            charge_count: 0,
            global_events: [const { SwapEvent::empty() }; MAX_GLOBAL_EVENTS],
            global_event_count: 0,
            global_event_head: 0,
            next_id: 1,
        }
    }

    // ── cgroup lifecycle ─────────────────────────────────────────

    /// Create a new swap cgroup.
    pub fn create_cgroup(&mut self, id: u32, name: &[u8], parent_id: u32) -> Result<()> {
        // Check for duplicate ID.
        if self.find_cgroup(id).is_some() {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .cgroups
            .iter_mut()
            .find(|cg| !cg.active)
            .ok_or(Error::OutOfMemory)?;
        *slot = SwapCgroup::empty();
        slot.id = id;
        slot.parent_id = parent_id;
        slot.active = true;
        let copy_len = name.len().min(MAX_CGROUP_NAME_LEN);
        slot.name[..copy_len].copy_from_slice(&name[..copy_len]);
        slot.name_len = copy_len;
        if id >= self.next_id {
            self.next_id = id + 1;
        }
        Ok(())
    }

    /// Remove a swap cgroup and uncharge all its swap entries.
    pub fn remove_cgroup(&mut self, id: u32) -> Result<()> {
        let idx = self.find_cgroup(id).ok_or(Error::NotFound)?;
        self.cgroups[idx].state = SwapCgroupState::Offline;
        self.cgroups[idx].active = false;
        // Release all charges belonging to this cgroup.
        for charge in &mut self.charges {
            if charge.active && charge.cgroup_id == id {
                charge.active = false;
                self.charge_count = self.charge_count.saturating_sub(1);
            }
        }
        Ok(())
    }

    /// Find a cgroup slot index by ID.
    fn find_cgroup(&self, id: u32) -> Option<usize> {
        self.cgroups.iter().position(|cg| cg.active && cg.id == id)
    }

    /// Get a reference to a cgroup by ID.
    fn get_cgroup(&self, id: u32) -> Result<&SwapCgroup> {
        let idx = self.find_cgroup(id).ok_or(Error::NotFound)?;
        Ok(&self.cgroups[idx])
    }

    /// Get a mutable reference to a cgroup by ID.
    fn get_cgroup_mut(&mut self, id: u32) -> Result<&mut SwapCgroup> {
        let idx = self.find_cgroup(id).ok_or(Error::NotFound)?;
        Ok(&mut self.cgroups[idx])
    }

    // ── configuration ────────────────────────────────────────────

    /// Set the swap limit for a cgroup.
    pub fn set_swap_limit(&mut self, id: u32, limit_bytes: u64) -> Result<()> {
        let cg = self.get_cgroup_mut(id)?;
        cg.config.swap_limit = limit_bytes;
        cg.counters.limit = limit_bytes;
        Ok(())
    }

    /// Enable or disable swap accounting for a cgroup.
    pub fn set_accounting_enabled(&mut self, id: u32, enabled: bool) -> Result<()> {
        let cg = self.get_cgroup_mut(id)?;
        cg.config.accounting_enabled = enabled;
        Ok(())
    }

    /// Freeze a cgroup (prevent new charges).
    pub fn freeze_cgroup(&mut self, id: u32) -> Result<()> {
        let cg = self.get_cgroup_mut(id)?;
        cg.state = SwapCgroupState::Frozen;
        Ok(())
    }

    /// Thaw a frozen cgroup.
    pub fn thaw_cgroup(&mut self, id: u32) -> Result<()> {
        let cg = self.get_cgroup_mut(id)?;
        if cg.state == SwapCgroupState::Frozen {
            cg.state = SwapCgroupState::Active;
        }
        Ok(())
    }

    // ── PID management ───────────────────────────────────────────

    /// Attach a PID to a swap cgroup.
    pub fn attach_pid(&mut self, cgroup_id: u32, pid: u32) -> Result<()> {
        let cg = self.get_cgroup_mut(cgroup_id)?;
        if cg.pid_count >= MAX_PIDS_PER_CGROUP {
            return Err(Error::OutOfMemory);
        }
        // Check duplicate.
        for i in 0..cg.pid_count {
            if cg.pids[i] == pid {
                return Err(Error::AlreadyExists);
            }
        }
        cg.pids[cg.pid_count] = pid;
        cg.pid_count += 1;
        Ok(())
    }

    /// Detach a PID from a swap cgroup.
    pub fn detach_pid(&mut self, cgroup_id: u32, pid: u32) -> Result<()> {
        let cg = self.get_cgroup_mut(cgroup_id)?;
        let pos = (0..cg.pid_count)
            .find(|&i| cg.pids[i] == pid)
            .ok_or(Error::NotFound)?;
        // Swap with last and shrink.
        cg.pid_count -= 1;
        if pos < cg.pid_count {
            cg.pids[pos] = cg.pids[cg.pid_count];
        }
        cg.pids[cg.pid_count] = 0;
        Ok(())
    }

    /// Find the cgroup ID for a given PID.
    pub fn cgroup_for_pid(&self, pid: u32) -> Option<u32> {
        for cg in &self.cgroups {
            if !cg.active {
                continue;
            }
            for i in 0..cg.pid_count {
                if cg.pids[i] == pid {
                    return Some(cg.id);
                }
            }
        }
        None
    }

    // ── charge / uncharge ────────────────────────────────────────

    /// Charge swap usage to a cgroup.
    ///
    /// Records the swap charge and updates counters.  Returns
    /// the charge result indicating success or rejection reason.
    pub fn charge_swap(
        &mut self,
        cgroup_id: u32,
        swap_area: u8,
        slot_offset: u32,
        nr_pages: u32,
        now_ns: u64,
    ) -> Result<SwapChargeResult> {
        let idx = self.find_cgroup(cgroup_id).ok_or(Error::NotFound)?;

        // Check state.
        if !self.cgroups[idx].config.accounting_enabled {
            return Ok(SwapChargeResult::Disabled);
        }
        if self.cgroups[idx].state == SwapCgroupState::Frozen {
            return Ok(SwapChargeResult::Frozen);
        }

        let charge_bytes = nr_pages as u64 * PAGE_SIZE;
        let new_usage = self.cgroups[idx].counters.usage + charge_bytes;

        // Check limit.
        if new_usage > self.cgroups[idx].counters.limit {
            self.cgroups[idx].counters.failcnt += 1;
            self.cgroups[idx].record_event(SwapEventType::LimitHit, nr_pages, now_ns);
            self.record_global_event(SwapEventType::LimitHit, cgroup_id, nr_pages, now_ns);
            return Ok(SwapChargeResult::LimitExceeded);
        }

        // Apply charge.
        self.cgroups[idx].counters.usage = new_usage;
        if new_usage > self.cgroups[idx].counters.max_usage {
            self.cgroups[idx].counters.max_usage = new_usage;
        }
        self.cgroups[idx].counters.total_swapout += charge_bytes;
        self.cgroups[idx].counters.swapout_events += 1;
        self.cgroups[idx].counters.charge_success += 1;

        // Record charge entry.
        self.record_charge(swap_area, slot_offset, cgroup_id, nr_pages, now_ns)?;

        self.cgroups[idx].record_event(SwapEventType::Charge, nr_pages, now_ns);
        self.record_global_event(SwapEventType::SwapOut, cgroup_id, nr_pages, now_ns);

        // Hierarchical charging.
        if self.cgroups[idx].config.hierarchical {
            let parent_id = self.cgroups[idx].parent_id;
            if parent_id != 0 {
                self.charge_parent(parent_id, charge_bytes);
            }
        }

        Ok(SwapChargeResult::Charged)
    }

    /// Uncharge swap usage from a cgroup.
    pub fn uncharge_swap(
        &mut self,
        cgroup_id: u32,
        swap_area: u8,
        slot_offset: u32,
        nr_pages: u32,
        now_ns: u64,
    ) -> Result<()> {
        let idx = self.find_cgroup(cgroup_id).ok_or(Error::NotFound)?;
        let uncharge_bytes = nr_pages as u64 * PAGE_SIZE;

        self.cgroups[idx].counters.usage = self.cgroups[idx]
            .counters
            .usage
            .saturating_sub(uncharge_bytes);
        self.cgroups[idx].counters.total_swapin += uncharge_bytes;
        self.cgroups[idx].counters.swapin_events += 1;
        self.cgroups[idx].counters.uncharge_count += 1;

        // Remove charge entry.
        self.remove_charge(swap_area, slot_offset);

        self.cgroups[idx].record_event(SwapEventType::Uncharge, nr_pages, now_ns);
        self.record_global_event(SwapEventType::SwapIn, cgroup_id, nr_pages, now_ns);

        // Hierarchical uncharging.
        if self.cgroups[idx].config.hierarchical {
            let parent_id = self.cgroups[idx].parent_id;
            if parent_id != 0 {
                self.uncharge_parent(parent_id, uncharge_bytes);
            }
        }

        Ok(())
    }

    /// Charge parent cgroup (hierarchical).
    fn charge_parent(&mut self, parent_id: u32, bytes: u64) {
        if let Some(idx) = self.find_cgroup(parent_id) {
            self.cgroups[idx].counters.usage += bytes;
            if self.cgroups[idx].counters.usage > self.cgroups[idx].counters.max_usage {
                self.cgroups[idx].counters.max_usage = self.cgroups[idx].counters.usage;
            }
        }
    }

    /// Uncharge parent cgroup (hierarchical).
    fn uncharge_parent(&mut self, parent_id: u32, bytes: u64) {
        if let Some(idx) = self.find_cgroup(parent_id) {
            self.cgroups[idx].counters.usage =
                self.cgroups[idx].counters.usage.saturating_sub(bytes);
        }
    }

    /// Record a charge entry in the global charge table.
    fn record_charge(
        &mut self,
        swap_area: u8,
        slot_offset: u32,
        cgroup_id: u32,
        nr_pages: u32,
        now_ns: u64,
    ) -> Result<()> {
        let slot = self
            .charges
            .iter_mut()
            .find(|c| !c.active)
            .ok_or(Error::OutOfMemory)?;
        *slot = SwapAccountEntry {
            swap_area,
            slot_offset,
            cgroup_id,
            nr_pages,
            charge_ns: now_ns,
            active: true,
        };
        self.charge_count += 1;
        Ok(())
    }

    /// Remove a charge entry by swap area and offset.
    fn remove_charge(&mut self, swap_area: u8, slot_offset: u32) {
        for charge in &mut self.charges {
            if charge.active && charge.swap_area == swap_area && charge.slot_offset == slot_offset {
                charge.active = false;
                self.charge_count = self.charge_count.saturating_sub(1);
                return;
            }
        }
    }

    /// Record a global swap event.
    fn record_global_event(
        &mut self,
        event_type: SwapEventType,
        cgroup_id: u32,
        nr_pages: u32,
        now_ns: u64,
    ) {
        let idx = self.global_event_head;
        self.global_events[idx] = SwapEvent {
            event_type,
            cgroup_id,
            nr_pages,
            timestamp_ns: now_ns,
            active: true,
        };
        self.global_event_head = (self.global_event_head + 1) % MAX_GLOBAL_EVENTS;
        if self.global_event_count < MAX_GLOBAL_EVENTS {
            self.global_event_count += 1;
        }
    }

    // ── queries ──────────────────────────────────────────────────

    /// Get swap counters for a cgroup.
    pub fn get_counters(&self, id: u32) -> Result<SwapCgroupCounters> {
        let cg = self.get_cgroup(id)?;
        Ok(cg.counters)
    }

    /// Get swap configuration for a cgroup.
    pub fn get_config(&self, id: u32) -> Result<SwapCgroupConfig> {
        let cg = self.get_cgroup(id)?;
        Ok(cg.config)
    }

    /// Get the current swap usage in bytes for a cgroup.
    pub fn swap_usage(&self, id: u32) -> Result<u64> {
        let cg = self.get_cgroup(id)?;
        Ok(cg.counters.usage)
    }

    /// Get the swap limit in bytes for a cgroup.
    pub fn swap_limit(&self, id: u32) -> Result<u64> {
        let cg = self.get_cgroup(id)?;
        Ok(cg.counters.limit)
    }

    /// Check whether swap usage is near the limit (> 90%).
    pub fn is_near_limit(&self, id: u32) -> Result<bool> {
        let cg = self.get_cgroup(id)?;
        if cg.counters.limit == SWAP_NO_LIMIT {
            return Ok(false);
        }
        let threshold = cg.counters.limit / 10 * 9;
        Ok(cg.counters.usage > threshold)
    }

    /// Number of active cgroups.
    pub fn active_count(&self) -> usize {
        self.cgroups.iter().filter(|cg| cg.active).count()
    }

    /// Aggregate statistics.
    pub fn stats(&self) -> SwapCgroupStats {
        let mut stats = SwapCgroupStats::default();
        for cg in &self.cgroups {
            if !cg.active {
                continue;
            }
            stats.active_cgroups += 1;
            stats.total_swap_usage += cg.counters.usage;
            stats.total_limit_hits += cg.counters.failcnt;
            stats.total_swapout_events += cg.counters.swapout_events;
            stats.total_swapin_events += cg.counters.swapin_events;
            stats.total_charges += cg.counters.charge_success;
            stats.total_uncharges += cg.counters.uncharge_count;
        }
        stats.active_charge_entries = self.charge_count;
        stats
    }

    /// Reset all counters for a cgroup (keep config and PIDs).
    pub fn reset_counters(&mut self, id: u32) -> Result<()> {
        let cg = self.get_cgroup_mut(id)?;
        let limit = cg.counters.limit;
        cg.counters = SwapCgroupCounters::default();
        cg.counters.limit = limit;
        Ok(())
    }

    /// Reset the entire registry.
    pub fn reset(&mut self) {
        for cg in &mut self.cgroups {
            *cg = SwapCgroup::empty();
        }
        for charge in &mut self.charges {
            *charge = SwapAccountEntry::empty();
        }
        self.charge_count = 0;
        self.global_event_count = 0;
        self.global_event_head = 0;
        self.next_id = 1;
    }
}

impl Default for SwapCgroupRegistry {
    fn default() -> Self {
        Self::new()
    }
}
