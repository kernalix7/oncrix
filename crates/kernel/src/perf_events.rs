// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hardware and software performance event counters.
//!
//! Provides PMU configuration, event scheduling, and sample
//! collection for profiling. Extends the basic perf framework in
//! [`crate::perf`] with event grouping, multiplexing, and overflow
//! handling, modeled after Linux's `kernel/events/core.c`.
//!
//! # Event Groups
//!
//! Events can be grouped so they are scheduled together on the
//! PMU. A group has a leader event; when the leader is enabled
//! all member events are enabled atomically. When PMU counters
//! are insufficient, the group is multiplexed as a unit.
//!
//! # Multiplexing
//!
//! When the number of enabled events exceeds available hardware
//! counters, the scheduler rotates event groups onto the PMU in
//! round-robin fashion. Scaled counter values account for the
//! fraction of time each event was actually running.
//!
//! # Sample Collection
//!
//! Events configured in sampling mode generate
//! [`SampleRecord`] entries in a per-event ring buffer. Samples
//! contain configurable fields (IP, TID, timestamp, etc.).

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────

/// Maximum number of performance events.
const MAX_PERF_EVENTS: usize = 64;

/// Maximum number of event groups.
const MAX_EVENT_GROUPS: usize = 16;

/// Maximum events per group.
const MAX_GROUP_MEMBERS: usize = 8;

/// Sample ring buffer capacity.
const SAMPLE_RING_SIZE: usize = 512;

/// Maximum number of hardware PMU counters modeled.
const MAX_PMU_COUNTERS: usize = 8;

// ── PerfEventType ────────────────────────────────────────────

/// Classification of a performance event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PerfEventType {
    /// Hardware counter (CPU cycles, cache misses, etc.).
    #[default]
    Hardware,
    /// Software counter (context switches, page faults, etc.).
    Software,
    /// Tracepoint event (static kernel instrumentation).
    Tracepoint,
    /// Hardware breakpoint / watchpoint.
    Breakpoint,
    /// Raw PMU event (vendor-specific encoding).
    Raw,
}

impl PerfEventType {
    /// Create from a raw u32 value.
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::Hardware),
            1 => Some(Self::Software),
            2 => Some(Self::Tracepoint),
            3 => Some(Self::Breakpoint),
            4 => Some(Self::Raw),
            _ => None,
        }
    }
}

// ── HwEventId ────────────────────────────────────────────────

/// Hardware performance counter identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum HwEventId {
    /// Total CPU cycles.
    #[default]
    CpuCycles = 0,
    /// Retired instructions.
    Instructions = 1,
    /// Cache references.
    CacheRefs = 2,
    /// Cache misses.
    CacheMisses = 3,
    /// Branch instructions.
    Branches = 4,
    /// Branch mispredictions.
    BranchMisses = 5,
    /// Bus cycles.
    BusCycles = 6,
    /// Stalled cycles in the frontend.
    StalledFrontend = 7,
    /// Stalled cycles in the backend.
    StalledBackend = 8,
}

impl HwEventId {
    /// Create from a raw u32 value.
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::CpuCycles),
            1 => Some(Self::Instructions),
            2 => Some(Self::CacheRefs),
            3 => Some(Self::CacheMisses),
            4 => Some(Self::Branches),
            5 => Some(Self::BranchMisses),
            6 => Some(Self::BusCycles),
            7 => Some(Self::StalledFrontend),
            8 => Some(Self::StalledBackend),
            _ => None,
        }
    }
}

// ── SwEventId ────────────────────────────────────────────────

/// Software performance counter identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum SwEventId {
    /// Context switches.
    #[default]
    ContextSwitches = 0,
    /// CPU migrations.
    CpuMigrations = 1,
    /// Page faults (minor + major).
    PageFaults = 2,
    /// Minor page faults.
    MinorFaults = 3,
    /// Major page faults.
    MajorFaults = 4,
    /// Task clock (CPU time in nanoseconds).
    TaskClock = 5,
    /// CPU clock (wall-clock nanoseconds on-CPU).
    CpuClock = 6,
}

impl SwEventId {
    /// Create from a raw u32 value.
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::ContextSwitches),
            1 => Some(Self::CpuMigrations),
            2 => Some(Self::PageFaults),
            3 => Some(Self::MinorFaults),
            4 => Some(Self::MajorFaults),
            5 => Some(Self::TaskClock),
            6 => Some(Self::CpuClock),
            _ => None,
        }
    }
}

// ── PmuConfig ────────────────────────────────────────────────

/// PMU (Performance Monitoring Unit) configuration.
///
/// Describes the hardware counter resources available on this
/// CPU.
#[derive(Debug, Clone, Copy)]
pub struct PmuConfig {
    /// Number of general-purpose counters available.
    pub num_counters: u32,
    /// Number of fixed-function counters.
    pub num_fixed: u32,
    /// Counter bit width (e.g. 48 for Intel).
    pub counter_width: u32,
    /// Whether the PMU supports event grouping.
    pub supports_groups: bool,
    /// Whether the PMU supports sampling / overflow interrupts.
    pub supports_sampling: bool,
    /// Current counter assignments (event ID per slot, 0 = free).
    pub assignments: [u32; MAX_PMU_COUNTERS],
}

impl PmuConfig {
    /// Create a default PMU configuration.
    pub const fn new() -> Self {
        Self {
            num_counters: 4,
            num_fixed: 3,
            counter_width: 48,
            supports_groups: true,
            supports_sampling: true,
            assignments: [0u32; MAX_PMU_COUNTERS],
        }
    }

    /// Return the total number of usable counters.
    pub fn total_counters(&self) -> u32 {
        self.num_counters.saturating_add(self.num_fixed)
    }

    /// Return the number of free (unassigned) counter slots.
    pub fn free_counters(&self) -> u32 {
        let total = self.total_counters() as usize;
        let used = self
            .assignments
            .iter()
            .take(total.min(MAX_PMU_COUNTERS))
            .filter(|&&a| a != 0)
            .count();
        (total - used) as u32
    }

    /// Assign an event to a free counter slot.
    ///
    /// Returns the slot index, or `None` if no slot is free.
    pub fn assign(&mut self, event_id: u32) -> Option<usize> {
        let total = self.total_counters() as usize;
        let limit = total.min(MAX_PMU_COUNTERS);
        let slot = self.assignments.iter().take(limit).position(|&a| a == 0)?;
        self.assignments[slot] = event_id;
        Some(slot)
    }

    /// Release a counter slot.
    pub fn release(&mut self, slot: usize) {
        if slot < MAX_PMU_COUNTERS {
            self.assignments[slot] = 0;
        }
    }

    /// Release all counter assignments for a given event ID.
    pub fn release_event(&mut self, event_id: u32) {
        for assignment in &mut self.assignments {
            if *assignment == event_id {
                *assignment = 0;
            }
        }
    }
}

impl Default for PmuConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ── PerfCounter ──────────────────────────────────────────────

/// A single performance event counter.
#[derive(Debug, Clone, Copy)]
pub struct PerfCounter {
    /// Unique counter ID.
    pub id: u32,
    /// Event type.
    pub event_type: PerfEventType,
    /// Event-specific configuration value.
    pub config: u64,
    /// Current counter value.
    pub count: u64,
    /// Time this counter has been enabled (ns).
    pub time_enabled: u64,
    /// Time this counter has been running on hardware (ns).
    pub time_running: u64,
    /// Sample period (0 = counting mode only).
    pub sample_period: u64,
    /// Number of overflows / sample triggers.
    pub overflow_count: u64,
    /// Group ID (0 = standalone).
    pub group_id: u32,
    /// Whether this counter is currently enabled.
    pub enabled: bool,
    /// Whether this counter is currently on hardware.
    pub on_pmu: bool,
    /// PMU counter slot index (valid only when on_pmu is true).
    pub pmu_slot: u32,
    /// Process ID filter (0 = all).
    pub pid_filter: u64,
    /// CPU filter (u32::MAX = all CPUs).
    pub cpu_filter: u32,
    /// Whether to exclude kernel-mode events.
    pub exclude_kernel: bool,
    /// Whether to exclude user-mode events.
    pub exclude_user: bool,
    /// Whether this slot is active.
    pub active: bool,
}

impl PerfCounter {
    /// Create an empty counter for array initialisation.
    const fn empty() -> Self {
        Self {
            id: 0,
            event_type: PerfEventType::Hardware,
            config: 0,
            count: 0,
            time_enabled: 0,
            time_running: 0,
            sample_period: 0,
            overflow_count: 0,
            group_id: 0,
            enabled: false,
            on_pmu: false,
            pmu_slot: 0,
            pid_filter: 0,
            cpu_filter: u32::MAX,
            exclude_kernel: false,
            exclude_user: false,
            active: false,
        }
    }

    /// Compute the scaled counter value to account for
    /// multiplexing.
    ///
    /// When `time_running < time_enabled`, the counter was not
    /// on hardware for the full period. The scaled value
    /// estimates the true count:
    /// `count * time_enabled / time_running`.
    pub fn scaled_value(&self) -> u64 {
        if self.time_running == 0 || self.time_running >= self.time_enabled {
            self.count
        } else {
            self.count.saturating_mul(self.time_enabled) / self.time_running
        }
    }

    /// Reset the counter value and time accounting.
    pub fn reset(&mut self) {
        self.count = 0;
        self.time_enabled = 0;
        self.time_running = 0;
        self.overflow_count = 0;
    }
}

impl Default for PerfCounter {
    fn default() -> Self {
        Self::empty()
    }
}

// ── SampleRecord ─────────────────────────────────────────────

/// A single performance sample captured on overflow or period
/// expiry.
#[derive(Debug, Clone, Copy, Default)]
pub struct SampleRecord {
    /// Instruction pointer.
    pub ip: u64,
    /// Process ID.
    pub pid: u64,
    /// Thread ID.
    pub tid: u64,
    /// Timestamp (nanoseconds).
    pub timestamp: u64,
    /// Data address (for address-based sampling).
    pub addr: u64,
    /// CPU number.
    pub cpu: u32,
    /// Event ID that generated this sample.
    pub event_id: u32,
    /// Counter value at sample time.
    pub counter_value: u64,
    /// Sample period.
    pub period: u64,
}

impl SampleRecord {
    /// Create an empty sample record.
    pub const fn empty() -> Self {
        Self {
            ip: 0,
            pid: 0,
            tid: 0,
            timestamp: 0,
            addr: 0,
            cpu: 0,
            event_id: 0,
            counter_value: 0,
            period: 0,
        }
    }
}

// ── SampleRingBuffer ─────────────────────────────────────────

/// Ring buffer for storing performance samples.
pub struct SampleRingBuffer {
    /// Sample entries.
    entries: [SampleRecord; SAMPLE_RING_SIZE],
    /// Write position.
    head: usize,
    /// Read position.
    tail: usize,
    /// Number of stored samples.
    count: usize,
    /// Number of dropped samples (buffer full).
    lost: u64,
}

impl SampleRingBuffer {
    /// Create an empty ring buffer.
    pub const fn new() -> Self {
        Self {
            entries: [SampleRecord::empty(); SAMPLE_RING_SIZE],
            head: 0,
            tail: 0,
            count: 0,
            lost: 0,
        }
    }

    /// Push a sample into the buffer.
    ///
    /// If the buffer is full the sample is lost.
    pub fn push(&mut self, sample: SampleRecord) {
        if self.count >= SAMPLE_RING_SIZE {
            self.lost += 1;
            return;
        }
        self.entries[self.head] = sample;
        self.head = (self.head + 1) % SAMPLE_RING_SIZE;
        self.count += 1;
    }

    /// Pop the oldest sample from the buffer.
    pub fn pop(&mut self) -> Option<SampleRecord> {
        if self.count == 0 {
            return None;
        }
        let sample = self.entries[self.tail];
        self.tail = (self.tail + 1) % SAMPLE_RING_SIZE;
        self.count -= 1;
        Some(sample)
    }

    /// Return the number of stored samples.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return the number of lost samples.
    pub fn lost(&self) -> u64 {
        self.lost
    }

    /// Clear the buffer.
    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.count = 0;
    }
}

impl Default for SampleRingBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// ── EventGroup ───────────────────────────────────────────────

/// A group of related performance events scheduled together.
///
/// Events in a group are enabled and disabled atomically. The
/// group leader determines scheduling; member events follow.
#[derive(Debug, Clone, Copy)]
pub struct EventGroup {
    /// Unique group ID.
    pub id: u32,
    /// Event IDs in this group (leader is index 0).
    pub members: [u32; MAX_GROUP_MEMBERS],
    /// Number of events in the group.
    pub member_count: usize,
    /// Whether the group is currently enabled.
    pub enabled: bool,
    /// Whether the group is currently scheduled on the PMU.
    pub on_pmu: bool,
    /// Whether this group slot is active.
    pub active: bool,
}

impl EventGroup {
    /// Create an empty group for array initialisation.
    const fn empty() -> Self {
        Self {
            id: 0,
            members: [0u32; MAX_GROUP_MEMBERS],
            member_count: 0,
            enabled: false,
            on_pmu: false,
            active: false,
        }
    }

    /// Return the group leader event ID.
    pub fn leader(&self) -> Option<u32> {
        if self.member_count > 0 {
            Some(self.members[0])
        } else {
            None
        }
    }

    /// Add a member event to the group.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the group is full.
    pub fn add_member(&mut self, event_id: u32) -> Result<()> {
        if self.member_count >= MAX_GROUP_MEMBERS {
            return Err(Error::OutOfMemory);
        }
        self.members[self.member_count] = event_id;
        self.member_count += 1;
        Ok(())
    }

    /// Remove a member event from the group.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the event is not in the
    /// group.
    pub fn remove_member(&mut self, event_id: u32) -> Result<()> {
        let pos = self
            .members
            .iter()
            .take(self.member_count)
            .position(|&m| m == event_id)
            .ok_or(Error::NotFound)?;

        // Shift remaining members.
        let mut i = pos + 1;
        while i < self.member_count {
            self.members[i - 1] = self.members[i];
            i += 1;
        }
        self.member_count -= 1;
        self.members[self.member_count] = 0;
        Ok(())
    }
}

impl Default for EventGroup {
    fn default() -> Self {
        Self::empty()
    }
}

// ── PerfEventManager ─────────────────────────────────────────

/// Central manager for performance events, groups, and
/// samples.
///
/// Provides the kernel-facing API for creating events, managing
/// groups, scheduling events onto the PMU, and collecting
/// samples.
pub struct PerfEventManager {
    /// Registered performance counters.
    counters: [PerfCounter; MAX_PERF_EVENTS],
    /// Event groups.
    groups: [EventGroup; MAX_EVENT_GROUPS],
    /// PMU configuration.
    pmu: PmuConfig,
    /// Sample ring buffer.
    samples: SampleRingBuffer,
    /// Number of active counters.
    counter_count: usize,
    /// Number of active groups.
    group_count: usize,
    /// Next counter ID.
    next_counter_id: u32,
    /// Next group ID.
    next_group_id: u32,
    /// Multiplexing rotation index.
    mux_rotation: usize,
}

impl PerfEventManager {
    /// Create a new event manager with default PMU config.
    pub const fn new() -> Self {
        Self {
            counters: [PerfCounter::empty(); MAX_PERF_EVENTS],
            groups: [EventGroup::empty(); MAX_EVENT_GROUPS],
            pmu: PmuConfig::new(),
            samples: SampleRingBuffer::new(),
            counter_count: 0,
            group_count: 0,
            next_counter_id: 1,
            next_group_id: 1,
            mux_rotation: 0,
        }
    }

    /// Set the PMU configuration.
    pub fn set_pmu_config(&mut self, config: PmuConfig) {
        self.pmu = config;
    }

    /// Return a reference to the current PMU configuration.
    pub fn pmu_config(&self) -> &PmuConfig {
        &self.pmu
    }

    /// Create a new performance event.
    ///
    /// Returns the event counter ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the event table is
    /// full.
    pub fn create_event(
        &mut self,
        event_type: PerfEventType,
        config: u64,
        sample_period: u64,
    ) -> Result<u32> {
        let slot = self
            .counters
            .iter()
            .position(|c| !c.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_counter_id;
        self.next_counter_id = self.next_counter_id.wrapping_add(1);

        self.counters[slot] = PerfCounter {
            id,
            event_type,
            config,
            sample_period,
            active: true,
            ..PerfCounter::empty()
        };
        self.counter_count += 1;
        Ok(id)
    }

    /// Close (destroy) a performance event.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no event with the given
    /// ID exists.
    pub fn close_event(&mut self, id: u32) -> Result<()> {
        let counter = self
            .counters
            .iter_mut()
            .find(|c| c.active && c.id == id)
            .ok_or(Error::NotFound)?;

        // Release PMU slot if assigned.
        if counter.on_pmu {
            self.pmu.release(counter.pmu_slot as usize);
        }
        counter.active = false;
        self.counter_count = self.counter_count.saturating_sub(1);
        Ok(())
    }

    /// Enable a performance event.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no event with the given
    /// ID exists.
    pub fn enable(&mut self, id: u32) -> Result<()> {
        let counter = self
            .counters
            .iter_mut()
            .find(|c| c.active && c.id == id)
            .ok_or(Error::NotFound)?;
        counter.enabled = true;
        Ok(())
    }

    /// Disable a performance event.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no event with the given
    /// ID exists.
    pub fn disable(&mut self, id: u32) -> Result<()> {
        let counter = self
            .counters
            .iter_mut()
            .find(|c| c.active && c.id == id)
            .ok_or(Error::NotFound)?;
        counter.enabled = false;
        if counter.on_pmu {
            self.pmu.release(counter.pmu_slot as usize);
            counter.on_pmu = false;
        }
        Ok(())
    }

    /// Read the current counter value.
    ///
    /// Returns the raw count, time enabled, and time running.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no event with the given
    /// ID exists.
    pub fn read_counter(&self, id: u32) -> Result<CounterReading> {
        let counter = self
            .counters
            .iter()
            .find(|c| c.active && c.id == id)
            .ok_or(Error::NotFound)?;
        Ok(CounterReading {
            id: counter.id,
            count: counter.count,
            time_enabled: counter.time_enabled,
            time_running: counter.time_running,
            scaled: counter.scaled_value(),
        })
    }

    /// Reset a counter to zero.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no event with the given
    /// ID exists.
    pub fn reset_counter(&mut self, id: u32) -> Result<()> {
        let counter = self
            .counters
            .iter_mut()
            .find(|c| c.active && c.id == id)
            .ok_or(Error::NotFound)?;
        counter.reset();
        Ok(())
    }

    /// Create an event group.
    ///
    /// Returns the group ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the group table is
    /// full.
    pub fn create_group(&mut self) -> Result<u32> {
        let slot = self
            .groups
            .iter()
            .position(|g| !g.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_group_id;
        self.next_group_id = self.next_group_id.wrapping_add(1);

        self.groups[slot] = EventGroup {
            id,
            active: true,
            ..EventGroup::empty()
        };
        self.group_count += 1;
        Ok(id)
    }

    /// Add an event to a group.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the group or event does
    /// not exist.
    /// Returns [`Error::OutOfMemory`] if the group is full.
    pub fn add_to_group(&mut self, group_id: u32, event_id: u32) -> Result<()> {
        // Verify event exists.
        let has_event = self.counters.iter().any(|c| c.active && c.id == event_id);
        if !has_event {
            return Err(Error::NotFound);
        }

        let group = self
            .groups
            .iter_mut()
            .find(|g| g.active && g.id == group_id)
            .ok_or(Error::NotFound)?;
        group.add_member(event_id)?;

        // Update the event's group_id.
        if let Some(counter) = self
            .counters
            .iter_mut()
            .find(|c| c.active && c.id == event_id)
        {
            counter.group_id = group_id;
        }
        Ok(())
    }

    /// Schedule enabled events onto available PMU counters.
    ///
    /// Performs round-robin multiplexing when more events are
    /// enabled than counters are available. Returns the number
    /// of events scheduled.
    pub fn schedule_events(&mut self) -> usize {
        // First, unschedule all events.
        for counter in &mut self.counters {
            if counter.active && counter.on_pmu {
                self.pmu.release(counter.pmu_slot as usize);
                counter.on_pmu = false;
            }
        }

        // Collect enabled event IDs with rotation offset.
        let mut enabled_ids = [0u32; MAX_PERF_EVENTS];
        let mut enabled_count = 0usize;
        for counter in &self.counters {
            if counter.active && counter.enabled {
                enabled_ids[enabled_count] = counter.id;
                enabled_count += 1;
            }
        }

        if enabled_count == 0 {
            return 0;
        }

        // Apply rotation for fair multiplexing.
        let rotation = self.mux_rotation % enabled_count;
        let mut scheduled = 0usize;

        // Try to schedule starting from the rotation offset.
        let mut attempt = 0;
        while attempt < enabled_count {
            let idx = (rotation + attempt) % enabled_count;
            let eid = enabled_ids[idx];

            if self.pmu.free_counters() == 0 {
                break;
            }

            if let Some(slot) = self.pmu.assign(eid) {
                // Find the counter and mark it on-PMU.
                if let Some(counter) = self.counters.iter_mut().find(|c| c.active && c.id == eid) {
                    counter.on_pmu = true;
                    counter.pmu_slot = slot as u32;
                    scheduled += 1;
                }
            }
            attempt += 1;
        }

        self.mux_rotation = self.mux_rotation.wrapping_add(1);
        scheduled
    }

    /// Update time accounting for all active events.
    ///
    /// Call this from the timer interrupt with the elapsed time
    /// in nanoseconds.
    pub fn tick(&mut self, elapsed_ns: u64) {
        for counter in &mut self.counters {
            if counter.active && counter.enabled {
                counter.time_enabled = counter.time_enabled.wrapping_add(elapsed_ns);
                if counter.on_pmu {
                    counter.time_running = counter.time_running.wrapping_add(elapsed_ns);
                }
            }
        }
    }

    /// Increment a software event counter.
    ///
    /// Called by the kernel when a software event occurs.
    pub fn record_sw_event(&mut self, config: u64, delta: u64) {
        for counter in &mut self.counters {
            if counter.active
                && counter.enabled
                && counter.event_type == PerfEventType::Software
                && counter.config == config
            {
                counter.count = counter.count.wrapping_add(delta);
            }
        }
    }

    /// Record a sample from an overflow or period expiry.
    pub fn record_sample(&mut self, sample: SampleRecord) {
        self.samples.push(sample);
    }

    /// Pop the oldest sample from the buffer.
    pub fn pop_sample(&mut self) -> Option<SampleRecord> {
        self.samples.pop()
    }

    /// Return the number of pending samples.
    pub fn pending_samples(&self) -> usize {
        self.samples.len()
    }

    /// Return the number of lost samples.
    pub fn lost_samples(&self) -> u64 {
        self.samples.lost()
    }

    /// Return the number of active counters.
    pub fn counter_count(&self) -> usize {
        self.counter_count
    }

    /// Return the number of active groups.
    pub fn group_count(&self) -> usize {
        self.group_count
    }

    /// Return `true` if no events are active.
    pub fn is_empty(&self) -> bool {
        self.counter_count == 0
    }
}

impl Default for PerfEventManager {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for PerfEventManager {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PerfEventManager")
            .field("counter_count", &self.counter_count)
            .field("group_count", &self.group_count)
            .field("pending_samples", &self.samples.len())
            .field("lost_samples", &self.samples.lost())
            .finish()
    }
}

// ── CounterReading ───────────────────────────────────────────

/// Result of reading a performance counter.
#[derive(Debug, Clone, Copy, Default)]
pub struct CounterReading {
    /// Counter ID.
    pub id: u32,
    /// Raw counter value.
    pub count: u64,
    /// Time enabled in nanoseconds.
    pub time_enabled: u64,
    /// Time running in nanoseconds.
    pub time_running: u64,
    /// Scaled counter value (accounting for multiplexing).
    pub scaled: u64,
}
