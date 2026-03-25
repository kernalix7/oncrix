// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! perf_event infrastructure for performance monitoring.
//!
//! Implements the core `perf_event` subsystem inspired by Linux's
//! `kernel/events/core.c`. Provides hardware, software, and
//! tracepoint performance counters with support for event groups,
//! ring buffer output, sampling, and overflow handling.
//!
//! # Event Types
//!
//! | Category   | Examples                                  |
//! |------------|-------------------------------------------|
//! | Hardware   | CPU cycles, instructions, cache refs/miss |
//! | Software   | Context switches, page faults, task clock |
//! | Tracepoint | Syscall entry/exit, sched switch          |
//! | Breakpoint | Hardware watchpoints                      |
//!
//! # Event Groups
//!
//! Events can be organized into groups for correlated measurement.
//! A group leader schedules its members together — either all events
//! in the group are active, or none are. This ensures counters can
//! be meaningfully compared.
//!
//! # Ring Buffer
//!
//! Sample data is written to a per-event ring buffer that can be
//! mmap'd into user space. The ring buffer uses a producer/consumer
//! model with a data head (written by kernel) and data tail (read
//! by user).
//!
//! # Overflow Handling
//!
//! When a counter overflows (reaches the sample period), the kernel
//! records a sample and optionally sends a signal (SIGIO) to the
//! owning process.
//!
//! Reference: Linux `kernel/events/core.c`,
//! `include/uapi/linux/perf_event.h`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum number of perf events system-wide.
const MAX_EVENTS: usize = 256;

/// Maximum events per group.
const MAX_GROUP_SIZE: usize = 8;

/// Maximum event groups.
const MAX_GROUPS: usize = 64;

/// Ring buffer size in entries.
const RING_BUFFER_SIZE: usize = 512;

/// Maximum sample data size in bytes.
const MAX_SAMPLE_SIZE: usize = 64;

/// Default sample period (every N events trigger a sample).
const DEFAULT_SAMPLE_PERIOD: u64 = 100_000;

/// Maximum CPUs for per-CPU event tracking.
const MAX_CPUS: usize = 64;

// ── Event Type ─────────────────────────────────────────────────────

/// Top-level perf event type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PerfEventType {
    /// Hardware performance counter (PMU-driven).
    Hardware = 0,
    /// Software performance counter (kernel-driven).
    Software = 1,
    /// Tracepoint event (static trace hook).
    Tracepoint = 2,
    /// Hardware cache event (cache hierarchy counters).
    HwCache = 3,
    /// Raw PMU event (architecture-specific encoding).
    Raw = 4,
    /// Hardware breakpoint (watchpoint).
    Breakpoint = 5,
}

impl PerfEventType {
    /// Convert from raw u32.
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::Hardware),
            1 => Some(Self::Software),
            2 => Some(Self::Tracepoint),
            3 => Some(Self::HwCache),
            4 => Some(Self::Raw),
            5 => Some(Self::Breakpoint),
            _ => None,
        }
    }
}

// ── Hardware Event IDs ─────────────────────────────────────────────

/// Hardware performance counter event identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum HwEventId {
    /// Total CPU cycles.
    CpuCycles = 0,
    /// Retired instructions.
    Instructions = 1,
    /// Last-level cache references.
    CacheReferences = 2,
    /// Last-level cache misses.
    CacheMisses = 3,
    /// Branch instructions retired.
    BranchInstructions = 4,
    /// Branch prediction misses.
    BranchMisses = 5,
    /// Bus cycles.
    BusCycles = 6,
    /// Stalled cycles (frontend).
    StalledCyclesFrontend = 7,
    /// Stalled cycles (backend).
    StalledCyclesBackend = 8,
    /// Reference CPU cycles (TSC).
    RefCpuCycles = 9,
}

impl HwEventId {
    /// Convert from raw u64.
    pub fn from_u64(val: u64) -> Option<Self> {
        match val {
            0 => Some(Self::CpuCycles),
            1 => Some(Self::Instructions),
            2 => Some(Self::CacheReferences),
            3 => Some(Self::CacheMisses),
            4 => Some(Self::BranchInstructions),
            5 => Some(Self::BranchMisses),
            6 => Some(Self::BusCycles),
            7 => Some(Self::StalledCyclesFrontend),
            8 => Some(Self::StalledCyclesBackend),
            9 => Some(Self::RefCpuCycles),
            _ => None,
        }
    }
}

// ── Software Event IDs ─────────────────────────────────────────────

/// Software performance counter event identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SwEventId {
    /// CPU clock (nanoseconds).
    CpuClock = 0,
    /// Task clock (nanoseconds on-CPU).
    TaskClock = 1,
    /// Page faults (major + minor).
    PageFaults = 2,
    /// Context switches.
    ContextSwitches = 3,
    /// CPU migrations (task moved between CPUs).
    CpuMigrations = 4,
    /// Minor page faults.
    PageFaultsMin = 5,
    /// Major page faults.
    PageFaultsMaj = 6,
    /// Alignment faults.
    AlignmentFaults = 7,
    /// Emulation faults.
    EmulationFaults = 8,
}

impl SwEventId {
    /// Convert from raw u64.
    pub fn from_u64(val: u64) -> Option<Self> {
        match val {
            0 => Some(Self::CpuClock),
            1 => Some(Self::TaskClock),
            2 => Some(Self::PageFaults),
            3 => Some(Self::ContextSwitches),
            4 => Some(Self::CpuMigrations),
            5 => Some(Self::PageFaultsMin),
            6 => Some(Self::PageFaultsMaj),
            7 => Some(Self::AlignmentFaults),
            8 => Some(Self::EmulationFaults),
            _ => None,
        }
    }
}

// ── Event State ────────────────────────────────────────────────────

/// Operational state of a perf event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PerfEventState {
    /// Event is not active (created but not enabled).
    #[default]
    Inactive,
    /// Event is actively counting.
    Active,
    /// Event is in error state (hardware resource conflict).
    Error,
    /// Event has been destroyed.
    Dead,
}

// ── Sample Type Flags ──────────────────────────────────────────────

/// Bitmask flags indicating what data to include in samples.
#[derive(Debug, Clone, Copy)]
pub struct SampleTypeFlags {
    /// Include instruction pointer.
    pub ip: bool,
    /// Include process/thread ID.
    pub tid: bool,
    /// Include timestamp.
    pub time: bool,
    /// Include CPU number.
    pub cpu: bool,
    /// Include counter value.
    pub read: bool,
    /// Include callchain (stack trace).
    pub callchain: bool,
    /// Include period.
    pub period: bool,
    /// Include raw data.
    pub raw: bool,
}

impl SampleTypeFlags {
    /// Default sample flags (IP + TID + time).
    pub const fn default_flags() -> Self {
        Self {
            ip: true,
            tid: true,
            time: true,
            cpu: false,
            read: false,
            callchain: false,
            period: false,
            raw: false,
        }
    }
}

// ── Event Attributes ───────────────────────────────────────────────

/// Configuration attributes for a perf event.
///
/// Specifies what to count, how to count, and sampling parameters.
#[derive(Debug, Clone, Copy)]
pub struct PerfEventAttr {
    /// Event type.
    pub event_type: PerfEventType,
    /// Event-type-specific configuration (event ID).
    pub config: u64,
    /// Sample period (0 = counting mode, >0 = sampling mode).
    pub sample_period: u64,
    /// Sample type flags.
    pub sample_type: SampleTypeFlags,
    /// Whether to exclude kernel-mode events.
    pub exclude_kernel: bool,
    /// Whether to exclude user-mode events.
    pub exclude_user: bool,
    /// Whether to exclude hypervisor events.
    pub exclude_hv: bool,
    /// Whether to exclude idle task.
    pub exclude_idle: bool,
    /// Whether to enable on exec.
    pub enable_on_exec: bool,
    /// Whether this is a per-task (vs per-CPU) event.
    pub per_task: bool,
    /// Whether to inherit to child tasks.
    pub inherit: bool,
    /// Whether to pin this event to a specific PMC.
    pub pinned: bool,
    /// Whether this event is exclusive (no other events on PMC).
    pub exclusive: bool,
}

impl PerfEventAttr {
    /// Create default attributes for a hardware event.
    pub const fn hw(event_id: u64) -> Self {
        Self {
            event_type: PerfEventType::Hardware,
            config: event_id,
            sample_period: 0,
            sample_type: SampleTypeFlags::default_flags(),
            exclude_kernel: false,
            exclude_user: false,
            exclude_hv: true,
            exclude_idle: false,
            enable_on_exec: false,
            per_task: false,
            inherit: false,
            pinned: false,
            exclusive: false,
        }
    }

    /// Create default attributes for a software event.
    pub const fn sw(event_id: u64) -> Self {
        Self {
            event_type: PerfEventType::Software,
            config: event_id,
            sample_period: 0,
            sample_type: SampleTypeFlags::default_flags(),
            exclude_kernel: false,
            exclude_user: false,
            exclude_hv: true,
            exclude_idle: false,
            enable_on_exec: false,
            per_task: false,
            inherit: false,
            pinned: false,
            exclusive: false,
        }
    }
}

// ── Sample Record ──────────────────────────────────────────────────

/// A single sample record written to the ring buffer.
#[derive(Debug, Clone, Copy)]
pub struct PerfSampleRecord {
    /// Event ID that generated this sample.
    pub event_id: u64,
    /// Instruction pointer at sample time.
    pub ip: u64,
    /// Process ID.
    pub pid: u64,
    /// Thread ID.
    pub tid: u64,
    /// Timestamp (nanoseconds since boot).
    pub time_ns: u64,
    /// CPU number.
    pub cpu: u32,
    /// Counter value at sample time.
    pub counter_value: u64,
    /// Sample period that triggered this sample.
    pub period: u64,
    /// Whether this record is valid.
    pub valid: bool,
}

impl PerfSampleRecord {
    /// Create an empty sample record.
    const fn empty() -> Self {
        Self {
            event_id: 0,
            ip: 0,
            pid: 0,
            tid: 0,
            time_ns: 0,
            cpu: 0,
            counter_value: 0,
            period: 0,
            valid: false,
        }
    }
}

// ── Ring Buffer ────────────────────────────────────────────────────

/// Per-event ring buffer for sample output.
///
/// Implements a single-producer (kernel), single-consumer (userspace)
/// ring buffer. The kernel advances `head`; userspace advances `tail`.
struct PerfRingBuffer {
    /// Sample records.
    data: [PerfSampleRecord; RING_BUFFER_SIZE],
    /// Write position (kernel updates).
    head: usize,
    /// Read position (userspace updates).
    tail: usize,
    /// Total samples written (including overflows).
    total_written: u64,
    /// Samples lost due to buffer full.
    lost: u64,
}

impl PerfRingBuffer {
    /// Create a new empty ring buffer.
    const fn new() -> Self {
        Self {
            data: [PerfSampleRecord::empty(); RING_BUFFER_SIZE],
            head: 0,
            tail: 0,
            total_written: 0,
            lost: 0,
        }
    }

    /// Write a sample record to the ring buffer.
    ///
    /// Returns `true` if the sample was written, `false` if the
    /// buffer is full (sample lost).
    fn write(&mut self, record: PerfSampleRecord) -> bool {
        let next_head = (self.head + 1) % RING_BUFFER_SIZE;
        if next_head == self.tail {
            // Buffer full
            self.lost += 1;
            return false;
        }
        self.data[self.head] = record;
        self.head = next_head;
        self.total_written += 1;
        true
    }

    /// Read a sample record from the ring buffer.
    ///
    /// Returns `None` if the buffer is empty.
    fn read(&mut self) -> Option<PerfSampleRecord> {
        if self.head == self.tail {
            return None;
        }
        let record = self.data[self.tail];
        self.tail = (self.tail + 1) % RING_BUFFER_SIZE;
        Some(record)
    }

    /// Number of samples available for reading.
    fn available(&self) -> usize {
        if self.head >= self.tail {
            self.head - self.tail
        } else {
            RING_BUFFER_SIZE - self.tail + self.head
        }
    }

    /// Reset the ring buffer.
    fn reset(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.total_written = 0;
        self.lost = 0;
    }
}

// ── Perf Event ─────────────────────────────────────────────────────

/// A single perf event instance.
///
/// Represents one performance counter with its configuration,
/// current state, counter value, and sample ring buffer.
pub struct PerfEvent {
    /// Unique event ID.
    event_id: u64,
    /// Event attributes (type, config, sampling).
    attr: PerfEventAttr,
    /// Current operational state.
    state: PerfEventState,
    /// Current counter value.
    count: u64,
    /// Running time (nanoseconds this event was active).
    time_running: u64,
    /// Enabled time (nanoseconds since enable, including inactive).
    time_enabled: u64,
    /// Owning process ID (-1 for system-wide).
    owner_pid: i64,
    /// Target CPU (-1 for any CPU).
    cpu: i32,
    /// Group leader event ID (0 if this is a leader or standalone).
    group_leader_id: u64,
    /// Ring buffer for sample output.
    ring_buffer: PerfRingBuffer,
    /// Sample period counter (counts down to 0).
    period_counter: u64,
    /// Number of overflow events (sample triggers).
    overflow_count: u64,
    /// Last sample timestamp.
    last_sample_time: u64,
    /// Whether this event slot is active.
    active: bool,
}

impl PerfEvent {
    /// Create an empty (inactive) perf event.
    const fn empty() -> Self {
        Self {
            event_id: 0,
            attr: PerfEventAttr::hw(0),
            state: PerfEventState::Inactive,
            count: 0,
            time_running: 0,
            time_enabled: 0,
            owner_pid: -1,
            cpu: -1,
            group_leader_id: 0,
            ring_buffer: PerfRingBuffer::new(),
            period_counter: 0,
            overflow_count: 0,
            last_sample_time: 0,
            active: false,
        }
    }
}

// ── Event Group ────────────────────────────────────────────────────

/// A perf event group for correlated measurement.
///
/// All events in a group are scheduled together on the PMU. The
/// group leader is the first event; member events are added
/// subsequently.
#[derive(Debug, Clone, Copy)]
pub struct PerfEventGroup {
    /// Group ID (same as leader event ID).
    pub group_id: u64,
    /// Leader event ID.
    pub leader_id: u64,
    /// Member event IDs (including leader at index 0).
    pub members: [u64; MAX_GROUP_SIZE],
    /// Number of members.
    pub member_count: usize,
    /// Whether the group is currently on the PMU.
    pub on_pmu: bool,
    /// Whether this group slot is active.
    pub active: bool,
}

impl PerfEventGroup {
    /// Create an empty (inactive) group.
    const fn empty() -> Self {
        Self {
            group_id: 0,
            leader_id: 0,
            members: [0u64; MAX_GROUP_SIZE],
            member_count: 0,
            on_pmu: false,
            active: false,
        }
    }
}

// ── Overflow Action ────────────────────────────────────────────────

/// Action to take when a sampled event overflows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OverflowAction {
    /// Write a sample to the ring buffer (default).
    #[default]
    Sample,
    /// Send a signal (SIGIO) to the owning process.
    Signal,
    /// Write sample and send signal.
    SampleAndSignal,
    /// Do nothing (count only).
    None,
}

// ── Statistics ─────────────────────────────────────────────────────

/// Aggregate perf_event subsystem statistics.
#[derive(Debug, Clone, Copy)]
pub struct PerfEventStats {
    /// Total events created.
    pub events_created: u64,
    /// Total events destroyed.
    pub events_destroyed: u64,
    /// Total samples recorded.
    pub samples_recorded: u64,
    /// Total samples lost (ring buffer full).
    pub samples_lost: u64,
    /// Total overflow events.
    pub overflow_events: u64,
    /// Currently active events.
    pub active_events: u64,
    /// Currently active groups.
    pub active_groups: u64,
}

impl PerfEventStats {
    /// Create zeroed statistics.
    const fn new() -> Self {
        Self {
            events_created: 0,
            events_destroyed: 0,
            samples_recorded: 0,
            samples_lost: 0,
            overflow_events: 0,
            active_events: 0,
            active_groups: 0,
        }
    }
}

// ── Perf Event Manager ─────────────────────────────────────────────

/// System-wide perf_event manager.
///
/// Manages all perf events, groups, and provides the API for
/// creating, enabling, disabling, reading, and sampling events.
pub struct PerfEventManager {
    /// All perf events.
    events: [PerfEvent; MAX_EVENTS],
    /// Event groups.
    groups: [PerfEventGroup; MAX_GROUPS],
    /// Number of active events.
    event_count: usize,
    /// Number of active groups.
    group_count: usize,
    /// Next event ID to assign.
    next_event_id: u64,
    /// Subsystem statistics.
    stats: PerfEventStats,
}

impl PerfEventManager {
    /// Create a new perf event manager.
    pub const fn new() -> Self {
        Self {
            events: [const { PerfEvent::empty() }; MAX_EVENTS],
            groups: [const { PerfEventGroup::empty() }; MAX_GROUPS],
            event_count: 0,
            group_count: 0,
            next_event_id: 1,
            stats: PerfEventStats::new(),
        }
    }

    /// Create a new perf event.
    ///
    /// # Arguments
    /// * `attr` — event attributes
    /// * `pid` — target process (-1 for system-wide)
    /// * `cpu` — target CPU (-1 for any)
    /// * `group_leader_id` — group leader (0 for standalone)
    ///
    /// Returns the new event's ID.
    pub fn create_event(
        &mut self,
        attr: PerfEventAttr,
        pid: i64,
        cpu: i32,
        group_leader_id: u64,
    ) -> Result<u64> {
        if self.event_count >= MAX_EVENTS {
            return Err(Error::OutOfMemory);
        }
        let slot = self
            .events
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;

        let event_id = self.next_event_id;
        self.next_event_id += 1;

        let period = if attr.sample_period > 0 {
            attr.sample_period
        } else {
            DEFAULT_SAMPLE_PERIOD
        };

        let evt = &mut self.events[slot];
        evt.event_id = event_id;
        evt.attr = attr;
        evt.state = PerfEventState::Inactive;
        evt.count = 0;
        evt.time_running = 0;
        evt.time_enabled = 0;
        evt.owner_pid = pid;
        evt.cpu = cpu;
        evt.group_leader_id = group_leader_id;
        evt.ring_buffer.reset();
        evt.period_counter = period;
        evt.overflow_count = 0;
        evt.last_sample_time = 0;
        evt.active = true;

        self.event_count += 1;
        self.stats.events_created += 1;
        self.stats.active_events = self.event_count as u64;

        // Add to group if specified
        if group_leader_id > 0 {
            self.add_to_group(group_leader_id, event_id)?;
        }

        Ok(event_id)
    }

    /// Create a new event group with the given event as leader.
    pub fn create_group(&mut self, leader_event_id: u64) -> Result<u64> {
        if self.group_count >= MAX_GROUPS {
            return Err(Error::OutOfMemory);
        }
        // Verify leader exists
        if self.find_event(leader_event_id).is_none() {
            return Err(Error::NotFound);
        }
        let slot = self
            .groups
            .iter()
            .position(|g| !g.active)
            .ok_or(Error::OutOfMemory)?;

        let grp = &mut self.groups[slot];
        grp.group_id = leader_event_id;
        grp.leader_id = leader_event_id;
        grp.members[0] = leader_event_id;
        grp.member_count = 1;
        grp.on_pmu = false;
        grp.active = true;

        // Update event's group leader
        if let Some(idx) = self.find_event(leader_event_id) {
            self.events[idx].group_leader_id = leader_event_id;
        }

        self.group_count += 1;
        self.stats.active_groups = self.group_count as u64;
        Ok(leader_event_id)
    }

    /// Enable a perf event (start counting).
    pub fn enable_event(&mut self, event_id: u64) -> Result<()> {
        let idx = self.find_event(event_id).ok_or(Error::NotFound)?;
        if self.events[idx].state == PerfEventState::Dead {
            return Err(Error::InvalidArgument);
        }
        self.events[idx].state = PerfEventState::Active;
        Ok(())
    }

    /// Disable a perf event (pause counting).
    pub fn disable_event(&mut self, event_id: u64) -> Result<()> {
        let idx = self.find_event(event_id).ok_or(Error::NotFound)?;
        self.events[idx].state = PerfEventState::Inactive;
        Ok(())
    }

    /// Destroy a perf event.
    pub fn destroy_event(&mut self, event_id: u64) -> Result<()> {
        let idx = self.find_event(event_id).ok_or(Error::NotFound)?;
        // Remove from group if in one
        self.remove_from_group(event_id);
        self.events[idx] = PerfEvent::empty();
        self.event_count = self.event_count.saturating_sub(1);
        self.stats.events_destroyed += 1;
        self.stats.active_events = self.event_count as u64;
        Ok(())
    }

    /// Read the current counter value for an event.
    pub fn read_event(&self, event_id: u64) -> Result<u64> {
        let idx = self.find_event(event_id).ok_or(Error::NotFound)?;
        Ok(self.events[idx].count)
    }

    /// Read extended event info (count, time_enabled, time_running).
    pub fn read_event_extended(&self, event_id: u64) -> Result<(u64, u64, u64)> {
        let idx = self.find_event(event_id).ok_or(Error::NotFound)?;
        let evt = &self.events[idx];
        Ok((evt.count, evt.time_enabled, evt.time_running))
    }

    /// Update a counter (called by PMU/software event sources).
    ///
    /// Increments the event counter and checks for overflow (sample
    /// trigger). If sampling is enabled and the period expires, a
    /// sample record is written to the ring buffer.
    pub fn update_count(
        &mut self,
        event_id: u64,
        delta: u64,
        now_ns: u64,
        ip: u64,
        pid: u64,
        tid: u64,
        cpu: u32,
    ) -> Result<bool> {
        let idx = self.find_event(event_id).ok_or(Error::NotFound)?;
        let evt = &mut self.events[idx];
        if evt.state != PerfEventState::Active {
            return Ok(false);
        }

        evt.count += delta;
        evt.time_running += delta;

        // Check for overflow (sampling)
        let mut sampled = false;
        if evt.attr.sample_period > 0 {
            if delta >= evt.period_counter {
                // Overflow: record a sample
                evt.overflow_count += 1;
                evt.period_counter = evt.attr.sample_period;

                let record = PerfSampleRecord {
                    event_id: evt.event_id,
                    ip,
                    pid,
                    tid,
                    time_ns: now_ns,
                    cpu,
                    counter_value: evt.count,
                    period: evt.attr.sample_period,
                    valid: true,
                };

                if evt.ring_buffer.write(record) {
                    self.stats.samples_recorded += 1;
                } else {
                    self.stats.samples_lost += 1;
                }
                self.stats.overflow_events += 1;
                evt.last_sample_time = now_ns;
                sampled = true;
            } else {
                evt.period_counter -= delta;
            }
        }

        Ok(sampled)
    }

    /// Read a sample from an event's ring buffer.
    pub fn read_sample(&mut self, event_id: u64) -> Result<Option<PerfSampleRecord>> {
        let idx = self.find_event(event_id).ok_or(Error::NotFound)?;
        Ok(self.events[idx].ring_buffer.read())
    }

    /// Get the number of samples available in an event's ring buffer.
    pub fn sample_count(&self, event_id: u64) -> Result<usize> {
        let idx = self.find_event(event_id).ok_or(Error::NotFound)?;
        Ok(self.events[idx].ring_buffer.available())
    }

    /// Enable all events in a group.
    pub fn enable_group(&mut self, group_id: u64) -> Result<()> {
        let grp_idx = self.find_group(group_id).ok_or(Error::NotFound)?;
        let member_count = self.groups[grp_idx].member_count;
        // Collect member IDs first to avoid borrow conflicts
        let mut member_ids = [0u64; MAX_GROUP_SIZE];
        for i in 0..member_count {
            member_ids[i] = self.groups[grp_idx].members[i];
        }
        for i in 0..member_count {
            if let Some(eidx) = self.find_event(member_ids[i]) {
                self.events[eidx].state = PerfEventState::Active;
            }
        }
        self.groups[grp_idx].on_pmu = true;
        Ok(())
    }

    /// Disable all events in a group.
    pub fn disable_group(&mut self, group_id: u64) -> Result<()> {
        let grp_idx = self.find_group(group_id).ok_or(Error::NotFound)?;
        let member_count = self.groups[grp_idx].member_count;
        let mut member_ids = [0u64; MAX_GROUP_SIZE];
        for i in 0..member_count {
            member_ids[i] = self.groups[grp_idx].members[i];
        }
        for i in 0..member_count {
            if let Some(eidx) = self.find_event(member_ids[i]) {
                self.events[eidx].state = PerfEventState::Inactive;
            }
        }
        self.groups[grp_idx].on_pmu = false;
        Ok(())
    }

    /// Read all counters in a group atomically.
    ///
    /// Returns (leader_count, [(member_id, count), ...]).
    pub fn read_group(&self, group_id: u64, buf: &mut [(u64, u64)]) -> Result<usize> {
        let grp_idx = self.find_group(group_id).ok_or(Error::NotFound)?;
        let grp = &self.groups[grp_idx];
        let mut written = 0;
        for i in 0..grp.member_count {
            if written >= buf.len() {
                break;
            }
            let mid = grp.members[i];
            if let Some(eidx) = self.find_event(mid) {
                buf[written] = (mid, self.events[eidx].count);
                written += 1;
            }
        }
        Ok(written)
    }

    /// Get the event state.
    pub fn event_state(&self, event_id: u64) -> Result<PerfEventState> {
        let idx = self.find_event(event_id).ok_or(Error::NotFound)?;
        Ok(self.events[idx].state)
    }

    /// Get event overflow count.
    pub fn overflow_count(&self, event_id: u64) -> Result<u64> {
        let idx = self.find_event(event_id).ok_or(Error::NotFound)?;
        Ok(self.events[idx].overflow_count)
    }

    /// Get aggregate subsystem statistics.
    pub fn statistics(&self) -> &PerfEventStats {
        &self.stats
    }

    /// Return the number of active events.
    pub fn active_event_count(&self) -> usize {
        self.event_count
    }

    /// Return the number of active groups.
    pub fn active_group_count(&self) -> usize {
        self.group_count
    }

    // ── Internal helpers ───────────────────────────────────────────

    /// Find an event by ID.
    fn find_event(&self, event_id: u64) -> Option<usize> {
        self.events
            .iter()
            .position(|e| e.active && e.event_id == event_id)
    }

    /// Find a group by ID.
    fn find_group(&self, group_id: u64) -> Option<usize> {
        self.groups
            .iter()
            .position(|g| g.active && g.group_id == group_id)
    }

    /// Add an event to an existing group.
    fn add_to_group(&mut self, group_leader_id: u64, event_id: u64) -> Result<()> {
        let grp_idx = self.find_group(group_leader_id).ok_or(Error::NotFound)?;
        let grp = &mut self.groups[grp_idx];
        if grp.member_count >= MAX_GROUP_SIZE {
            return Err(Error::OutOfMemory);
        }
        grp.members[grp.member_count] = event_id;
        grp.member_count += 1;
        Ok(())
    }

    /// Remove an event from its group.
    fn remove_from_group(&mut self, event_id: u64) {
        for grp in &mut self.groups {
            if !grp.active {
                continue;
            }
            if let Some(pos) = grp.members[..grp.member_count]
                .iter()
                .position(|&id| id == event_id)
            {
                // Shift remaining members
                for i in pos..grp.member_count.saturating_sub(1) {
                    grp.members[i] = grp.members[i + 1];
                }
                if grp.member_count > 0 {
                    grp.members[grp.member_count - 1] = 0;
                    grp.member_count -= 1;
                }
                // If group is empty, deactivate it
                if grp.member_count == 0 {
                    grp.active = false;
                    self.group_count = self.group_count.saturating_sub(1);
                    self.stats.active_groups = self.group_count as u64;
                }
                return;
            }
        }
    }
}
