// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Pressure Stall Information (PSI) subsystem.
//!
//! Tracks resource pressure (CPU, memory, I/O) using exponential
//! moving averages over 10-second, 60-second, and 300-second
//! windows. Supports per-cgroup pressure groups and poll-able
//! threshold triggers.
//!
//! # Architecture
//!
//! | Component       | Purpose                                       |
//! |-----------------|-----------------------------------------------|
//! | [`PsiResource`] | Resource type enum (CPU, Memory, I/O)         |
//! | [`PsiState`]    | Per-resource exponential moving averages       |
//! | [`PsiGroup`]    | Per-cgroup pressure tracking                  |
//! | [`PsiTrigger`]  | Threshold-based pressure notification trigger  |
//! | [`PsiRegistry`] | System-wide registry of PSI groups + triggers  |
//!
//! # Exponential Moving Average
//!
//! PSI computes averages using fixed-point arithmetic (Q32.32).
//! On each accounting tick, the stall ratio for the elapsed window
//! is blended into the running average:
//!
//! ```text
//! avg = avg * decay + sample * (1 - decay)
//! ```
//!
//! Decay factors are chosen so that the half-life matches the
//! window name (avg10 decays over ~10 s, etc.).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of PSI groups (cgroups + system-wide root).
const MAX_PSI_GROUPS: usize = 64;

/// Maximum number of PSI triggers across all groups.
const MAX_PSI_TRIGGERS: usize = 64;

/// Maximum name length in bytes.
const MAX_NAME_LEN: usize = 64;

/// Fixed-point shift for Q32.32 arithmetic.
const FP_SHIFT: u64 = 32;

/// Fixed-point unit (1.0 in Q32.32).
const FP_ONE: u64 = 1u64 << FP_SHIFT;

/// Decay factor for 10-second window (~0.92 in Q32.32).
///
/// Chosen so that after 10 one-second samples the contribution
/// of the oldest sample is roughly 50 % of its original weight.
const EMA_DECAY_10: u64 = 3_951_369_912; // ~0.92

/// Decay factor for 60-second window (~0.9835 in Q32.32).
const EMA_DECAY_60: u64 = 4_223_667_068; // ~0.9835

/// Decay factor for 300-second window (~0.9967 in Q32.32).
const EMA_DECAY_300: u64 = 4_280_354_406; // ~0.9967

/// Percentage scale — PSI averages are stored as basis points
/// (0..10_000) so that 100.00 % = 10 000.
const _PERCENT_SCALE: u64 = 10_000;

// ---------------------------------------------------------------------------
// PsiResource
// ---------------------------------------------------------------------------

/// Resource type tracked by PSI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PsiResource {
    /// CPU pressure — tasks waiting for CPU time.
    Cpu = 0,
    /// Memory pressure — tasks stalled on reclaim / swap.
    Memory = 1,
    /// I/O pressure — tasks waiting on block I/O.
    Io = 2,
}

/// Number of distinct resource types.
const NUM_RESOURCES: usize = 3;

impl PsiResource {
    /// Convert from a raw `u8` value.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Cpu),
            1 => Some(Self::Memory),
            2 => Some(Self::Io),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// PsiState — per-resource exponential moving averages
// ---------------------------------------------------------------------------

/// Per-resource pressure state with exponential moving averages.
///
/// Averages are stored in Q32.32 fixed-point. Use
/// [`avg10_percent`](Self::avg10_percent),
/// [`avg60_percent`](Self::avg60_percent), and
/// [`avg300_percent`](Self::avg300_percent) to read them as
/// integer basis points (0..10 000).
#[derive(Debug, Clone, Copy)]
pub struct PsiState {
    /// 10-second EMA (Q32.32 fixed-point, range 0..FP_ONE).
    avg10: u64,
    /// 60-second EMA (Q32.32).
    avg60: u64,
    /// 300-second EMA (Q32.32).
    avg300: u64,
    /// Total stall time in microseconds.
    total_us: u64,
    /// Stall time accumulated in the current sampling window.
    window_stall_us: u64,
    /// Total time elapsed in the current sampling window.
    window_elapsed_us: u64,
}

impl PsiState {
    /// Create a zero-initialised pressure state.
    pub const fn new() -> Self {
        Self {
            avg10: 0,
            avg60: 0,
            avg300: 0,
            total_us: 0,
            window_stall_us: 0,
            window_elapsed_us: 0,
        }
    }

    /// Record stall time for the current window.
    pub fn record_stall(&mut self, stall_us: u64) {
        self.window_stall_us = self.window_stall_us.saturating_add(stall_us);
        self.total_us = self.total_us.saturating_add(stall_us);
    }

    /// Record elapsed time for the current window.
    pub fn record_elapsed(&mut self, elapsed_us: u64) {
        self.window_elapsed_us = self.window_elapsed_us.saturating_add(elapsed_us);
    }

    /// Advance the EMA computation at the end of a sampling window.
    ///
    /// Computes the stall ratio for the window, then blends it into
    /// each of the three running averages. Resets the per-window
    /// accumulators.
    pub fn update(&mut self) {
        let sample = if self.window_elapsed_us > 0 {
            // sample in Q32.32: (stall / elapsed) * FP_ONE
            (self.window_stall_us << FP_SHIFT) / self.window_elapsed_us
        } else {
            0
        };

        self.avg10 = ema_update(self.avg10, sample, EMA_DECAY_10);
        self.avg60 = ema_update(self.avg60, sample, EMA_DECAY_60);
        self.avg300 = ema_update(self.avg300, sample, EMA_DECAY_300);

        self.window_stall_us = 0;
        self.window_elapsed_us = 0;
    }

    /// 10-second average as basis points (0..10 000).
    pub fn avg10_percent(&self) -> u64 {
        fp_to_basis_points(self.avg10)
    }

    /// 60-second average as basis points (0..10 000).
    pub fn avg60_percent(&self) -> u64 {
        fp_to_basis_points(self.avg60)
    }

    /// 300-second average as basis points (0..10 000).
    pub fn avg300_percent(&self) -> u64 {
        fp_to_basis_points(self.avg300)
    }

    /// Total accumulated stall time in microseconds.
    pub fn total_us(&self) -> u64 {
        self.total_us
    }
}

impl Default for PsiState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PsiGroup — per-cgroup pressure group
// ---------------------------------------------------------------------------

/// Per-cgroup (or system-wide) pressure group.
///
/// Tracks `some` and `full` stall metrics for each resource type.
/// - **some**: at least one task is stalled.
/// - **full**: all runnable tasks are stalled (complete stall).
#[derive(Debug, Clone, Copy)]
pub struct PsiGroup {
    /// Unique group identifier.
    pub id: u64,
    /// Group name (UTF-8 bytes, null-padded).
    pub name: [u8; MAX_NAME_LEN],
    /// Name length in bytes.
    name_len: usize,
    /// "Some" pressure per resource.
    pub some: [PsiState; NUM_RESOURCES],
    /// "Full" pressure per resource.
    pub full: [PsiState; NUM_RESOURCES],
    /// Whether this group slot is active.
    pub in_use: bool,
}

impl PsiGroup {
    /// Creates an empty (inactive) group.
    const fn empty() -> Self {
        const ZERO: PsiState = PsiState::new();
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            some: [ZERO; NUM_RESOURCES],
            full: [ZERO; NUM_RESOURCES],
            in_use: false,
        }
    }

    /// Record partial stall ("some") for the given resource.
    pub fn record_some(&mut self, resource: PsiResource, stall_us: u64) {
        self.some[resource as usize].record_stall(stall_us);
    }

    /// Record full stall ("full") for the given resource.
    pub fn record_full(&mut self, resource: PsiResource, stall_us: u64) {
        self.full[resource as usize].record_stall(stall_us);
    }

    /// Record elapsed time for all resources.
    pub fn record_elapsed(&mut self, elapsed_us: u64) {
        for state in &mut self.some {
            state.record_elapsed(elapsed_us);
        }
        for state in &mut self.full {
            state.record_elapsed(elapsed_us);
        }
    }

    /// Advance all EMAs at the end of a sampling window.
    pub fn update(&mut self) {
        for state in &mut self.some {
            state.update();
        }
        for state in &mut self.full {
            state.update();
        }
    }

    /// Get the "some" state for a resource.
    pub fn get_some(&self, resource: PsiResource) -> &PsiState {
        &self.some[resource as usize]
    }

    /// Get the "full" state for a resource.
    pub fn get_full(&self, resource: PsiResource) -> &PsiState {
        &self.full[resource as usize]
    }
}

// ---------------------------------------------------------------------------
// PsiTrigger — poll-able threshold trigger
// ---------------------------------------------------------------------------

/// Threshold type for PSI triggers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsiTriggerType {
    /// Trigger when "some" pressure exceeds threshold.
    Some,
    /// Trigger when "full" pressure exceeds threshold.
    Full,
}

/// A poll-able PSI pressure trigger.
///
/// Fires when the pressure for a given resource and stall type
/// exceeds `threshold_us` within a rolling `window_us` window.
#[derive(Debug, Clone, Copy)]
pub struct PsiTrigger {
    /// Trigger ID (unique across all triggers).
    pub id: u32,
    /// Group this trigger belongs to.
    pub group_id: u64,
    /// Resource being monitored.
    pub resource: PsiResource,
    /// Whether monitoring "some" or "full" stall.
    pub trigger_type: PsiTriggerType,
    /// Stall threshold in microseconds (within the window).
    pub threshold_us: u64,
    /// Rolling window length in microseconds.
    pub window_us: u64,
    /// Accumulated stall time in the current window.
    window_stall_us: u64,
    /// Elapsed time in the current window.
    window_elapsed_us: u64,
    /// Number of times this trigger has fired.
    pub event_count: u64,
    /// Whether this trigger slot is active.
    pub active: bool,
}

impl PsiTrigger {
    /// Creates an empty (inactive) trigger.
    const fn empty() -> Self {
        Self {
            id: 0,
            group_id: 0,
            resource: PsiResource::Cpu,
            trigger_type: PsiTriggerType::Some,
            threshold_us: 0,
            window_us: 0,
            window_stall_us: 0,
            window_elapsed_us: 0,
            event_count: 0,
            active: false,
        }
    }

    /// Feed stall and elapsed time into the trigger window.
    ///
    /// Returns `true` if the trigger fires (threshold exceeded).
    pub fn feed(&mut self, stall_us: u64, elapsed_us: u64) -> bool {
        self.window_stall_us = self.window_stall_us.saturating_add(stall_us);
        self.window_elapsed_us = self.window_elapsed_us.saturating_add(elapsed_us);

        if self.window_elapsed_us >= self.window_us {
            let fired = self.window_stall_us >= self.threshold_us;
            if fired {
                self.event_count = self.event_count.saturating_add(1);
            }
            // Reset window.
            self.window_stall_us = 0;
            self.window_elapsed_us = 0;
            fired
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// PsiRegistry — system-wide registry
// ---------------------------------------------------------------------------

/// System-wide registry of PSI pressure groups and triggers.
pub struct PsiRegistry {
    /// Pressure groups.
    groups: [PsiGroup; MAX_PSI_GROUPS],
    /// Pressure triggers.
    triggers: [PsiTrigger; MAX_PSI_TRIGGERS],
    /// Next group ID.
    next_group_id: u64,
    /// Next trigger ID.
    next_trigger_id: u32,
    /// Number of active groups.
    group_count: usize,
    /// Number of active triggers.
    trigger_count: usize,
}

impl PsiRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const EMPTY_GROUP: PsiGroup = PsiGroup::empty();
        const EMPTY_TRIGGER: PsiTrigger = PsiTrigger::empty();
        Self {
            groups: [EMPTY_GROUP; MAX_PSI_GROUPS],
            triggers: [EMPTY_TRIGGER; MAX_PSI_TRIGGERS],
            next_group_id: 1,
            next_trigger_id: 1,
            group_count: 0,
            trigger_count: 0,
        }
    }

    /// Number of active groups.
    pub fn group_count(&self) -> usize {
        self.group_count
    }

    /// Number of active triggers.
    pub fn trigger_count(&self) -> usize {
        self.trigger_count
    }

    // -- Group management ---------------------------------------------------

    /// Create a new PSI group with the given name.
    ///
    /// Returns the group ID.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — name is empty or too long.
    /// - [`Error::OutOfMemory`] — no free group slots.
    pub fn create_group(&mut self, name: &[u8]) -> Result<u64> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .groups
            .iter()
            .position(|g| !g.in_use)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_group_id;
        self.next_group_id = self.next_group_id.wrapping_add(1);

        let group = &mut self.groups[slot];
        *group = PsiGroup::empty();
        group.id = id;
        group.in_use = true;
        group.name_len = name.len();
        group.name[..name.len()].copy_from_slice(name);

        self.group_count += 1;
        Ok(id)
    }

    /// Destroy a PSI group.
    ///
    /// All triggers belonging to this group are deactivated.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the group does not exist.
    pub fn destroy_group(&mut self, id: u64) -> Result<()> {
        let slot = self.group_index(id)?;
        self.groups[slot].in_use = false;
        self.group_count = self.group_count.saturating_sub(1);

        // Deactivate triggers belonging to this group.
        for trigger in &mut self.triggers {
            if trigger.active && trigger.group_id == id {
                trigger.active = false;
                self.trigger_count = self.trigger_count.saturating_sub(1);
            }
        }
        Ok(())
    }

    /// Look up a group by ID (immutable).
    pub fn get_group(&self, id: u64) -> Option<&PsiGroup> {
        self.groups.iter().find(|g| g.in_use && g.id == id)
    }

    /// Look up a group by ID (mutable).
    pub fn get_group_mut(&mut self, id: u64) -> Option<&mut PsiGroup> {
        self.groups.iter_mut().find(|g| g.in_use && g.id == id)
    }

    /// Record partial ("some") stall for a group and resource.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the group does not exist.
    pub fn record_some(
        &mut self,
        group_id: u64,
        resource: PsiResource,
        stall_us: u64,
    ) -> Result<()> {
        let idx = self.group_index(group_id)?;
        self.groups[idx].record_some(resource, stall_us);
        Ok(())
    }

    /// Record full stall for a group and resource.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the group does not exist.
    pub fn record_full(
        &mut self,
        group_id: u64,
        resource: PsiResource,
        stall_us: u64,
    ) -> Result<()> {
        let idx = self.group_index(group_id)?;
        self.groups[idx].record_full(resource, stall_us);
        Ok(())
    }

    // -- Trigger management -------------------------------------------------

    /// Create a new pressure trigger.
    ///
    /// Returns the trigger ID.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — group does not exist.
    /// - [`Error::InvalidArgument`] — zero threshold or window.
    /// - [`Error::OutOfMemory`] — no free trigger slots.
    pub fn create_trigger(
        &mut self,
        group_id: u64,
        resource: PsiResource,
        trigger_type: PsiTriggerType,
        threshold_us: u64,
        window_us: u64,
    ) -> Result<u32> {
        // Validate group exists.
        let _ = self.group_index(group_id)?;

        if threshold_us == 0 || window_us == 0 {
            return Err(Error::InvalidArgument);
        }
        if threshold_us > window_us {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .triggers
            .iter()
            .position(|t| !t.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_trigger_id;
        self.next_trigger_id = self.next_trigger_id.wrapping_add(1);

        self.triggers[slot] = PsiTrigger {
            id,
            group_id,
            resource,
            trigger_type,
            threshold_us,
            window_us,
            window_stall_us: 0,
            window_elapsed_us: 0,
            event_count: 0,
            active: true,
        };
        self.trigger_count += 1;
        Ok(id)
    }

    /// Destroy a trigger by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the trigger does not exist.
    pub fn destroy_trigger(&mut self, id: u32) -> Result<()> {
        let trigger = self
            .triggers
            .iter_mut()
            .find(|t| t.active && t.id == id)
            .ok_or(Error::NotFound)?;
        trigger.active = false;
        self.trigger_count = self.trigger_count.saturating_sub(1);
        Ok(())
    }

    /// Read the event count for a trigger.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the trigger does not exist.
    pub fn read_trigger(&self, id: u32) -> Result<u64> {
        let trigger = self
            .triggers
            .iter()
            .find(|t| t.active && t.id == id)
            .ok_or(Error::NotFound)?;
        Ok(trigger.event_count)
    }

    // -- Periodic accounting ------------------------------------------------

    /// Periodic accounting tick.
    ///
    /// Called once per sampling interval (typically 1 second).
    /// `elapsed_us` is the wall-clock time since the last tick.
    ///
    /// 1. Records elapsed time into all active groups.
    /// 2. Updates EMAs for all active groups.
    /// 3. Feeds stall data into triggers and fires as needed.
    pub fn tick(&mut self, elapsed_us: u64) {
        // Phase 1: record elapsed time into groups.
        for group in &mut self.groups {
            if group.in_use {
                group.record_elapsed(elapsed_us);
            }
        }

        // Phase 2: update EMAs.
        for group in &mut self.groups {
            if group.in_use {
                group.update();
            }
        }

        // Phase 3: feed triggers.
        //
        // For each trigger, extract the stall total from the
        // appropriate group/resource/type, then feed.
        // We must avoid borrowing groups and triggers at the
        // same time, so we read stall values first.
        for i in 0..MAX_PSI_TRIGGERS {
            if !self.triggers[i].active {
                continue;
            }
            let group_id = self.triggers[i].group_id;
            let resource = self.triggers[i].resource;
            let ttype = self.triggers[i].trigger_type;

            let stall_us = self
                .groups
                .iter()
                .find(|g| g.in_use && g.id == group_id)
                .map(|g| {
                    let state = match ttype {
                        PsiTriggerType::Some => &g.some[resource as usize],
                        PsiTriggerType::Full => &g.full[resource as usize],
                    };
                    state.total_us()
                })
                .unwrap_or(0);

            // Feed the stall delta (simplified: use total as
            // a proxy since we track in window accumulators).
            self.triggers[i].feed(stall_us, elapsed_us);
        }
    }

    // -- Internal helpers ---------------------------------------------------

    /// Returns the index of an active group by ID.
    fn group_index(&self, id: u64) -> Result<usize> {
        self.groups
            .iter()
            .position(|g| g.in_use && g.id == id)
            .ok_or(Error::NotFound)
    }
}

impl Default for PsiRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Fixed-point helpers
// ---------------------------------------------------------------------------

/// Compute one EMA step: `avg = avg * decay + sample * (1 - decay)`.
///
/// All values are in Q32.32 fixed-point.
fn ema_update(avg: u64, sample: u64, decay: u64) -> u64 {
    // avg * decay / FP_ONE + sample * (FP_ONE - decay) / FP_ONE
    // Use u128 intermediate to avoid overflow.
    let a = (avg as u128 * decay as u128) >> FP_SHIFT;
    let b = (sample as u128 * (FP_ONE - decay) as u128) >> FP_SHIFT;
    (a + b) as u64
}

/// Convert a Q32.32 fixed-point fraction to basis points (0..10 000).
fn fp_to_basis_points(fp: u64) -> u64 {
    // (fp / FP_ONE) * 10_000
    ((fp as u128 * 10_000) >> FP_SHIFT) as u64
}
