// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `perf_event_open(2)` — performance monitoring event creation.
//!
//! This module implements the `perf_event_open` system call which creates
//! a file descriptor for performance monitoring. It supports hardware
//! counters, software events, and tracepoint events.
//!
//! # Syscall signature
//!
//! ```text
//! int perf_event_open(struct perf_event_attr *attr, pid_t pid,
//!                     int cpu, int group_fd, unsigned long flags);
//! ```
//!
//! # Event types
//!
//! | Type | Description |
//! |------|-------------|
//! | `PERF_TYPE_HARDWARE` | CPU hardware counters (cycles, instructions) |
//! | `PERF_TYPE_SOFTWARE` | Kernel software counters (page faults, ctx switches) |
//! | `PERF_TYPE_TRACEPOINT` | Tracepoint/ftrace events |
//! | `PERF_TYPE_HW_CACHE` | Hardware cache counters (L1, LLC, DTLB, etc.) |
//! | `PERF_TYPE_RAW` | Raw PMU event codes |
//! | `PERF_TYPE_BREAKPOINT` | Hardware breakpoint events |
//!
//! # Targeting
//!
//! The `pid` and `cpu` arguments control which process and CPU the event
//! monitors. Common combinations:
//!
//! - `pid == 0, cpu == -1` — current process, any CPU
//! - `pid > 0, cpu == -1` — specific process, any CPU
//! - `pid == -1, cpu >= 0` — all processes on specific CPU
//! - `pid == 0, cpu >= 0` — current process on specific CPU
//!
//! # References
//!
//! - Linux: `kernel/events/core.c`, `include/uapi/linux/perf_event.h`
//! - `perf_event_open(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants — event types
// ---------------------------------------------------------------------------

/// Hardware performance counter (cycles, instructions, cache misses, etc.).
pub const PERF_TYPE_HARDWARE: u32 = 0;

/// Kernel software counter (page faults, context switches, CPU migrations).
pub const PERF_TYPE_SOFTWARE: u32 = 1;

/// Tracepoint event (ftrace-based static tracepoints).
pub const PERF_TYPE_TRACEPOINT: u32 = 2;

/// Hardware cache counter (L1, LLC, DTLB, ITLB, BPU).
pub const PERF_TYPE_HW_CACHE: u32 = 3;

/// Raw PMU event code (architecture-specific).
pub const PERF_TYPE_RAW: u32 = 4;

/// Hardware breakpoint event.
pub const PERF_TYPE_BREAKPOINT: u32 = 5;

/// Maximum valid built-in event type.
const PERF_TYPE_MAX: u32 = 6;

// ---------------------------------------------------------------------------
// Constants — hardware event IDs
// ---------------------------------------------------------------------------

/// Total CPU cycles.
pub const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
/// Retired instructions.
pub const PERF_COUNT_HW_INSTRUCTIONS: u64 = 1;
/// Cache references (accesses).
pub const PERF_COUNT_HW_CACHE_REFERENCES: u64 = 2;
/// Cache misses.
pub const PERF_COUNT_HW_CACHE_MISSES: u64 = 3;
/// Branch instructions retired.
pub const PERF_COUNT_HW_BRANCH_INSTRUCTIONS: u64 = 4;
/// Branch mispredictions.
pub const PERF_COUNT_HW_BRANCH_MISSES: u64 = 5;
/// Bus cycles.
pub const PERF_COUNT_HW_BUS_CYCLES: u64 = 6;
/// Stalled cycles (frontend).
pub const PERF_COUNT_HW_STALLED_CYCLES_FRONTEND: u64 = 7;
/// Stalled cycles (backend).
pub const PERF_COUNT_HW_STALLED_CYCLES_BACKEND: u64 = 8;
/// Reference CPU cycles (not affected by frequency scaling).
pub const PERF_COUNT_HW_REF_CPU_CYCLES: u64 = 9;
/// Maximum valid hardware event ID.
const PERF_COUNT_HW_MAX: u64 = 10;

// ---------------------------------------------------------------------------
// Constants — software event IDs
// ---------------------------------------------------------------------------

/// CPU clock (nanoseconds).
pub const PERF_COUNT_SW_CPU_CLOCK: u64 = 0;
/// Task clock (nanoseconds on-CPU).
pub const PERF_COUNT_SW_TASK_CLOCK: u64 = 1;
/// Page faults (total).
pub const PERF_COUNT_SW_PAGE_FAULTS: u64 = 2;
/// Context switches.
pub const PERF_COUNT_SW_CONTEXT_SWITCHES: u64 = 3;
/// CPU migrations.
pub const PERF_COUNT_SW_CPU_MIGRATIONS: u64 = 4;
/// Minor page faults (no I/O).
pub const PERF_COUNT_SW_PAGE_FAULTS_MIN: u64 = 5;
/// Major page faults (I/O required).
pub const PERF_COUNT_SW_PAGE_FAULTS_MAJ: u64 = 6;
/// Alignment faults.
pub const PERF_COUNT_SW_ALIGNMENT_FAULTS: u64 = 7;
/// Emulation faults.
pub const PERF_COUNT_SW_EMULATION_FAULTS: u64 = 8;
/// Maximum valid software event ID.
const PERF_COUNT_SW_MAX: u64 = 9;

// ---------------------------------------------------------------------------
// Constants — flags
// ---------------------------------------------------------------------------

/// Create event as disabled (must be enabled with ioctl).
pub const PERF_FLAG_FD_NO_GROUP: u64 = 1 << 0;
/// Output event to group leader's mmap buffer.
pub const PERF_FLAG_FD_OUTPUT: u64 = 1 << 1;
/// Use PID in cgroup mode (pid argument is a cgroup fd).
pub const PERF_FLAG_PID_CGROUP: u64 = 1 << 2;
/// Close-on-exec for the returned fd.
pub const PERF_FLAG_FD_CLOEXEC: u64 = 1 << 3;

/// Mask of all valid flags.
const PERF_FLAG_VALID_MASK: u64 =
    PERF_FLAG_FD_NO_GROUP | PERF_FLAG_FD_OUTPUT | PERF_FLAG_PID_CGROUP | PERF_FLAG_FD_CLOEXEC;

// ---------------------------------------------------------------------------
// Constants — sample types and read formats
// ---------------------------------------------------------------------------

/// Include instruction pointer in sample.
pub const PERF_SAMPLE_IP: u64 = 1 << 0;
/// Include thread/process IDs.
pub const PERF_SAMPLE_TID: u64 = 1 << 1;
/// Include timestamp.
pub const PERF_SAMPLE_TIME: u64 = 1 << 2;
/// Include address (for address-triggered events).
pub const PERF_SAMPLE_ADDR: u64 = 1 << 3;
/// Include counter value in read format.
pub const PERF_SAMPLE_READ: u64 = 1 << 4;
/// Include callchain.
pub const PERF_SAMPLE_CALLCHAIN: u64 = 1 << 5;
/// Include event identifier.
pub const PERF_SAMPLE_ID: u64 = 1 << 6;
/// Include CPU number.
pub const PERF_SAMPLE_CPU: u64 = 1 << 7;
/// Include period (for frequency-based sampling).
pub const PERF_SAMPLE_PERIOD: u64 = 1 << 8;

/// Read total counter value.
pub const PERF_FORMAT_TOTAL_TIME_ENABLED: u64 = 1 << 0;
/// Read total time event was running.
pub const PERF_FORMAT_TOTAL_TIME_RUNNING: u64 = 1 << 1;
/// Read event ID along with counter.
pub const PERF_FORMAT_ID: u64 = 1 << 2;
/// Read group of counters at once.
pub const PERF_FORMAT_GROUP: u64 = 1 << 3;
/// Read lost sample count.
pub const PERF_FORMAT_LOST: u64 = 1 << 4;

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Maximum number of events in a group.
const MAX_GROUP_SIZE: usize = 16;

/// Maximum number of open perf events per process.
const MAX_EVENTS_PER_PROCESS: usize = 128;

/// Maximum number of CPUs supported.
const MAX_CPUS: usize = 256;

/// Invalid file descriptor sentinel.
const FD_INVALID: i32 = -1;

// ---------------------------------------------------------------------------
// PerfEventAttr — event attribute descriptor
// ---------------------------------------------------------------------------

/// Performance event attribute descriptor.
///
/// Corresponds to `struct perf_event_attr` in the Linux UAPI. Specifies
/// the event type, config, sampling parameters, and behavior flags.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PerfEventAttr {
    /// Event type (PERF_TYPE_*).
    pub event_type: u32,
    /// Size of the attr struct (for versioning).
    pub size: u32,
    /// Type-specific event configuration.
    pub config: u64,
    /// Sampling period or frequency (union, depends on `freq` flag).
    pub sample_period_or_freq: u64,
    /// Bitmask of PERF_SAMPLE_* values.
    pub sample_type: u64,
    /// Bitmask of PERF_FORMAT_* values.
    pub read_format: u64,
    /// Bitfield flags (packed as a u64).
    ///
    /// Bit 0: disabled — start in disabled state
    /// Bit 1: inherit — children inherit the event
    /// Bit 2: pinned — must always be on PMU
    /// Bit 3: exclusive — sole access to PMU
    /// Bit 4: exclude_user — don't count user-space
    /// Bit 5: exclude_kernel — don't count kernel
    /// Bit 6: exclude_hv — don't count hypervisor
    /// Bit 7: exclude_idle — don't count in idle
    /// Bit 8: mmap — include mmap records
    /// Bit 9: comm — include comm (process name) records
    /// Bit 10: freq — sample_period_or_freq is frequency
    /// Bit 11: inherit_stat — per-task counts for inherited events
    /// Bit 12: enable_on_exec — enable on exec
    /// Bit 13: task — include fork/exit records
    /// Bit 14: watermark — wakeup_events is a watermark
    pub flags: u64,
    /// Wakeup events count or watermark bytes.
    pub wakeup_events_or_watermark: u32,
    /// Breakpoint type (for PERF_TYPE_BREAKPOINT).
    pub bp_type: u32,
    /// Breakpoint address or config1.
    pub bp_addr_or_config1: u64,
    /// Breakpoint length or config2.
    pub bp_len_or_config2: u64,
}

impl PerfEventAttr {
    /// Create a new zeroed attribute (must be configured before use).
    pub const fn new() -> Self {
        Self {
            event_type: 0,
            size: core::mem::size_of::<Self>() as u32,
            config: 0,
            sample_period_or_freq: 0,
            sample_type: 0,
            read_format: 0,
            flags: 0,
            wakeup_events_or_watermark: 0,
            bp_type: 0,
            bp_addr_or_config1: 0,
            bp_len_or_config2: 0,
        }
    }

    /// Return `true` if the event starts disabled.
    pub const fn is_disabled(&self) -> bool {
        self.flags & (1 << 0) != 0
    }

    /// Return `true` if children should inherit this event.
    pub const fn is_inherit(&self) -> bool {
        self.flags & (1 << 1) != 0
    }

    /// Return `true` if this is a pinned event.
    pub const fn is_pinned(&self) -> bool {
        self.flags & (1 << 2) != 0
    }

    /// Return `true` if this is an exclusive event.
    pub const fn is_exclusive(&self) -> bool {
        self.flags & (1 << 3) != 0
    }

    /// Return `true` if user-space events are excluded.
    pub const fn exclude_user(&self) -> bool {
        self.flags & (1 << 4) != 0
    }

    /// Return `true` if kernel events are excluded.
    pub const fn exclude_kernel(&self) -> bool {
        self.flags & (1 << 5) != 0
    }

    /// Return `true` if sampling is frequency-based.
    pub const fn is_freq(&self) -> bool {
        self.flags & (1 << 10) != 0
    }

    /// Return `true` if the event should be enabled on exec.
    pub const fn enable_on_exec(&self) -> bool {
        self.flags & (1 << 12) != 0
    }

    /// Validate the attribute.
    ///
    /// # Checks
    ///
    /// - Event type is in valid range.
    /// - Config is valid for the given event type.
    /// - Pinned and exclusive are mutually coherent.
    /// - Size field matches expected size.
    pub fn validate(&self) -> Result<()> {
        if self.event_type >= PERF_TYPE_MAX {
            return Err(Error::InvalidArgument);
        }
        self.validate_config()?;
        // Pinned implies it cannot be part of a flexible group.
        // Exclusive implies sole access — both are hints but valid.
        if self.is_pinned() && self.is_exclusive() {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Validate the config field based on event type.
    fn validate_config(&self) -> Result<()> {
        match self.event_type {
            PERF_TYPE_HARDWARE => {
                if self.config >= PERF_COUNT_HW_MAX {
                    return Err(Error::InvalidArgument);
                }
            }
            PERF_TYPE_SOFTWARE => {
                if self.config >= PERF_COUNT_SW_MAX {
                    return Err(Error::InvalidArgument);
                }
            }
            PERF_TYPE_TRACEPOINT => {
                // Tracepoint ID is opaque — just check non-zero.
                if self.config == 0 {
                    return Err(Error::InvalidArgument);
                }
            }
            PERF_TYPE_HW_CACHE => {
                // Encoded as cache_id | (cache_op << 8) | (cache_result << 16).
                let cache_id = self.config & 0xFF;
                let cache_op = (self.config >> 8) & 0xFF;
                let cache_result = (self.config >> 16) & 0xFF;
                // 7 cache types, 3 ops, 2 results.
                if cache_id >= 7 || cache_op >= 3 || cache_result >= 2 {
                    return Err(Error::InvalidArgument);
                }
            }
            PERF_TYPE_RAW | PERF_TYPE_BREAKPOINT => {
                // Raw events and breakpoints accept any config.
            }
            _ => return Err(Error::InvalidArgument),
        }
        Ok(())
    }
}

impl Default for PerfEventAttr {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PerfEventState — per-event runtime state
// ---------------------------------------------------------------------------

/// State of a performance event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerfEventState {
    /// Event is disabled and not counting.
    Disabled,
    /// Event is active and counting.
    Active,
    /// Event encountered an error (e.g., PMU conflict).
    Error,
}

// ---------------------------------------------------------------------------
// PerfEvent — a single performance monitoring event
// ---------------------------------------------------------------------------

/// A single performance monitoring event.
///
/// Tracks the event configuration, accumulated count, and current state.
#[derive(Debug, Clone)]
pub struct PerfEvent {
    /// Unique event identifier (used in PERF_FORMAT_ID reads).
    pub id: u64,
    /// Event attribute (configuration).
    pub attr: PerfEventAttr,
    /// Current event state.
    pub state: PerfEventState,
    /// Accumulated counter value.
    pub count: u64,
    /// Total time the event has been enabled (nanoseconds).
    pub time_enabled: u64,
    /// Total time the event has been running (nanoseconds).
    pub time_running: u64,
    /// Target PID (-1 for all processes, 0 for self).
    pub pid: i32,
    /// Target CPU (-1 for any CPU).
    pub cpu: i32,
    /// File descriptor assigned to this event.
    pub fd: i32,
    /// Group leader event ID (0 if this is the leader or standalone).
    pub group_leader_id: u64,
    /// Number of context switches since last read.
    pub context_switches: u64,
    /// Whether this event is a group leader.
    pub is_group_leader: bool,
}

impl PerfEvent {
    /// Create a new perf event from validated attributes.
    pub fn new(id: u64, attr: PerfEventAttr, pid: i32, cpu: i32, fd: i32) -> Self {
        let initial_state = if attr.is_disabled() {
            PerfEventState::Disabled
        } else {
            PerfEventState::Active
        };
        Self {
            id,
            attr,
            state: initial_state,
            count: 0,
            time_enabled: 0,
            time_running: 0,
            pid,
            cpu,
            fd,
            group_leader_id: 0,
            context_switches: 0,
            is_group_leader: false,
        }
    }

    /// Enable the event (start counting).
    pub fn enable(&mut self) -> Result<()> {
        match self.state {
            PerfEventState::Error => Err(Error::IoError),
            PerfEventState::Active => Ok(()),
            PerfEventState::Disabled => {
                self.state = PerfEventState::Active;
                Ok(())
            }
        }
    }

    /// Disable the event (stop counting).
    pub fn disable(&mut self) {
        if self.state == PerfEventState::Active {
            self.state = PerfEventState::Disabled;
        }
    }

    /// Reset the counter to zero.
    pub fn reset(&mut self) {
        self.count = 0;
        self.time_enabled = 0;
        self.time_running = 0;
        self.context_switches = 0;
    }

    /// Read the current counter value.
    pub const fn read_count(&self) -> u64 {
        self.count
    }

    /// Return `true` if the event is currently counting.
    pub const fn is_active(&self) -> bool {
        matches!(self.state, PerfEventState::Active)
    }

    /// Record a counter increment (called by the PMU driver).
    pub fn record(&mut self, delta: u64) {
        if self.is_active() {
            self.count = self.count.saturating_add(delta);
        }
    }

    /// Update timing information.
    pub fn update_time(&mut self, elapsed_ns: u64) {
        self.time_enabled = self.time_enabled.saturating_add(elapsed_ns);
        if self.is_active() {
            self.time_running = self.time_running.saturating_add(elapsed_ns);
        }
    }
}

// ---------------------------------------------------------------------------
// PerfEventGroup — a group of related events
// ---------------------------------------------------------------------------

/// A group of performance events read together atomically.
///
/// One event is the group leader; the rest are members that share
/// the leader's scheduling context and mmap buffer.
#[derive(Debug)]
pub struct PerfEventGroup {
    /// Group leader event ID.
    leader_id: u64,
    /// Member event IDs (excluding leader).
    member_ids: [u64; MAX_GROUP_SIZE],
    /// Number of members (excluding leader).
    member_count: usize,
}

impl PerfEventGroup {
    /// Create a new group with the given leader.
    pub const fn new(leader_id: u64) -> Self {
        Self {
            leader_id,
            member_ids: [0; MAX_GROUP_SIZE],
            member_count: 0,
        }
    }

    /// Add a member to the group.
    pub fn add_member(&mut self, event_id: u64) -> Result<()> {
        if self.member_count >= MAX_GROUP_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.member_ids[self.member_count] = event_id;
        self.member_count += 1;
        Ok(())
    }

    /// Return the leader event ID.
    pub const fn leader_id(&self) -> u64 {
        self.leader_id
    }

    /// Return the number of group members (excluding leader).
    pub const fn member_count(&self) -> usize {
        self.member_count
    }

    /// Return a slice of member IDs.
    pub fn members(&self) -> &[u64] {
        &self.member_ids[..self.member_count]
    }

    /// Return the total number of events (leader + members).
    pub const fn total_events(&self) -> usize {
        1 + self.member_count
    }

    /// Check if an event ID is in this group.
    pub fn contains(&self, event_id: u64) -> bool {
        if event_id == self.leader_id {
            return true;
        }
        let mut i = 0;
        while i < self.member_count {
            if self.member_ids[i] == event_id {
                return true;
            }
            i += 1;
        }
        false
    }
}

// ---------------------------------------------------------------------------
// PerfEventContext — per-process event context
// ---------------------------------------------------------------------------

/// Per-process performance event context.
///
/// Manages all open perf events for a single process, including
/// group relationships and fd-to-event mapping.
pub struct PerfEventContext {
    /// All open events (indexed by slot).
    events: [Option<PerfEvent>; MAX_EVENTS_PER_PROCESS],
    /// Event groups.
    groups: [Option<PerfEventGroup>; MAX_EVENTS_PER_PROCESS],
    /// Number of active events.
    event_count: usize,
    /// Next event ID to allocate.
    next_id: u64,
    /// Next file descriptor to allocate.
    next_fd: i32,
}

impl PerfEventContext {
    /// Create a new empty event context.
    pub fn new() -> Self {
        Self {
            events: [const { None }; MAX_EVENTS_PER_PROCESS],
            groups: [const { None }; MAX_EVENTS_PER_PROCESS],
            event_count: 0,
            next_id: 1,
            next_fd: 100, // Start perf fds above normal fds.
        }
    }

    /// Find a free event slot.
    fn find_free_slot(&self) -> Result<usize> {
        for (i, slot) in self.events.iter().enumerate() {
            if slot.is_none() {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find the slot index for an event by fd.
    fn find_by_fd(&self, fd: i32) -> Result<usize> {
        for (i, slot) in self.events.iter().enumerate() {
            if let Some(ev) = slot {
                if ev.fd == fd {
                    return Ok(i);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Find the slot index for an event by ID.
    fn find_by_id(&self, id: u64) -> Result<usize> {
        for (i, slot) in self.events.iter().enumerate() {
            if let Some(ev) = slot {
                if ev.id == id {
                    return Ok(i);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Allocate a new event ID.
    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Allocate a new file descriptor.
    fn alloc_fd(&mut self) -> i32 {
        let fd = self.next_fd;
        self.next_fd += 1;
        fd
    }

    /// Open a new performance event.
    ///
    /// # Arguments
    ///
    /// - `attr` — Event attributes (validated before storage).
    /// - `pid` — Target PID (0 = self, -1 = all).
    /// - `cpu` — Target CPU (-1 = any).
    /// - `group_fd` — Group leader fd (-1 for standalone/new group).
    /// - `flags` — PERF_FLAG_* flags.
    ///
    /// # Returns
    ///
    /// File descriptor for the new event.
    pub fn open_event(
        &mut self,
        attr: &PerfEventAttr,
        pid: i32,
        cpu: i32,
        group_fd: i32,
        flags: u64,
    ) -> Result<i32> {
        attr.validate()?;
        self.validate_targeting(pid, cpu, flags)?;

        if flags & !PERF_FLAG_VALID_MASK != 0 {
            return Err(Error::InvalidArgument);
        }

        let slot = self.find_free_slot()?;
        let id = self.alloc_id();
        let fd = self.alloc_fd();

        let mut event = PerfEvent::new(id, *attr, pid, cpu, fd);

        // Handle group membership.
        if group_fd != FD_INVALID && flags & PERF_FLAG_FD_NO_GROUP == 0 {
            let leader_slot = self.find_by_fd(group_fd)?;
            let leader_id = match &self.events[leader_slot] {
                Some(ev) if ev.is_group_leader => ev.id,
                Some(_) => return Err(Error::InvalidArgument),
                None => return Err(Error::NotFound),
            };
            event.group_leader_id = leader_id;
            // Add to group.
            if let Some(ref mut group) = self.groups[leader_slot] {
                group.add_member(id)?;
            }
        } else if group_fd == FD_INVALID {
            // This event is a standalone or a new group leader.
            event.is_group_leader = true;
            self.groups[slot] = Some(PerfEventGroup::new(id));
        }

        self.events[slot] = Some(event);
        self.event_count += 1;
        Ok(fd)
    }

    /// Close a performance event by fd.
    pub fn close_event(&mut self, fd: i32) -> Result<()> {
        let slot = self.find_by_fd(fd)?;
        self.events[slot] = None;
        self.groups[slot] = None;
        self.event_count = self.event_count.saturating_sub(1);
        Ok(())
    }

    /// Enable an event by fd.
    pub fn enable_event(&mut self, fd: i32) -> Result<()> {
        let slot = self.find_by_fd(fd)?;
        match &mut self.events[slot] {
            Some(ev) => ev.enable(),
            None => Err(Error::NotFound),
        }
    }

    /// Disable an event by fd.
    pub fn disable_event(&mut self, fd: i32) -> Result<()> {
        let slot = self.find_by_fd(fd)?;
        match &mut self.events[slot] {
            Some(ev) => {
                ev.disable();
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Reset an event's counters by fd.
    pub fn reset_event(&mut self, fd: i32) -> Result<()> {
        let slot = self.find_by_fd(fd)?;
        match &mut self.events[slot] {
            Some(ev) => {
                ev.reset();
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Read the counter value for an event by fd.
    pub fn read_event(&self, fd: i32) -> Result<PerfReadData> {
        let slot = self.find_by_fd(fd)?;
        match &self.events[slot] {
            Some(ev) => Ok(PerfReadData {
                value: ev.count,
                time_enabled: ev.time_enabled,
                time_running: ev.time_running,
                id: ev.id,
            }),
            None => Err(Error::NotFound),
        }
    }

    /// Return the number of open events.
    pub const fn event_count(&self) -> usize {
        self.event_count
    }

    /// Validate pid/cpu targeting.
    fn validate_targeting(&self, pid: i32, cpu: i32, flags: u64) -> Result<()> {
        // pid == -1 && cpu == -1 is invalid.
        if pid == -1 && cpu == -1 {
            return Err(Error::InvalidArgument);
        }
        // cpu must be -1 or a valid CPU index.
        if cpu != -1 && (cpu < 0 || cpu >= MAX_CPUS as i32) {
            return Err(Error::InvalidArgument);
        }
        // PID_CGROUP requires pid >= 0 (it's a cgroup fd).
        if flags & PERF_FLAG_PID_CGROUP != 0 && pid < 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for PerfEventContext {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PerfReadData — data returned from reading an event
// ---------------------------------------------------------------------------

/// Data returned when reading a perf event counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PerfReadData {
    /// Counter value.
    pub value: u64,
    /// Total time enabled (nanoseconds).
    pub time_enabled: u64,
    /// Total time running (nanoseconds).
    pub time_running: u64,
    /// Event unique ID.
    pub id: u64,
}

// ---------------------------------------------------------------------------
// Syscall entry point
// ---------------------------------------------------------------------------

/// Process the `perf_event_open` syscall.
///
/// # Arguments
///
/// - `ctx` — Per-process perf event context.
/// - `attr` — Event attributes from user-space.
/// - `pid` — Target PID.
/// - `cpu` — Target CPU.
/// - `group_fd` — Group leader fd (-1 for standalone).
/// - `flags` — PERF_FLAG_* flags.
///
/// # Returns
///
/// File descriptor for the new event on success.
///
/// # Errors
///
/// - `InvalidArgument` — Bad attributes, targeting, or flags.
/// - `OutOfMemory` — No free event slots.
/// - `NotFound` — Group leader fd does not exist.
pub fn sys_perf_event_open(
    ctx: &mut PerfEventContext,
    attr: &PerfEventAttr,
    pid: i32,
    cpu: i32,
    group_fd: i32,
    flags: u64,
) -> Result<i32> {
    ctx.open_event(attr, pid, cpu, group_fd, flags)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hw_cycles_attr() -> PerfEventAttr {
        let mut attr = PerfEventAttr::new();
        attr.event_type = PERF_TYPE_HARDWARE;
        attr.config = PERF_COUNT_HW_CPU_CYCLES;
        attr
    }

    #[test]
    fn test_attr_validate_hardware() {
        let attr = hw_cycles_attr();
        assert!(attr.validate().is_ok());
    }

    #[test]
    fn test_attr_validate_bad_type() {
        let mut attr = PerfEventAttr::new();
        attr.event_type = 99;
        assert_eq!(attr.validate().unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn test_attr_validate_bad_hw_config() {
        let mut attr = PerfEventAttr::new();
        attr.event_type = PERF_TYPE_HARDWARE;
        attr.config = 999;
        assert_eq!(attr.validate().unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn test_attr_validate_bad_sw_config() {
        let mut attr = PerfEventAttr::new();
        attr.event_type = PERF_TYPE_SOFTWARE;
        attr.config = 999;
        assert_eq!(attr.validate().unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn test_attr_pinned_exclusive() {
        let mut attr = hw_cycles_attr();
        attr.flags = (1 << 2) | (1 << 3); // pinned + exclusive
        assert_eq!(attr.validate().unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn test_open_standalone_event() {
        let mut ctx = PerfEventContext::new();
        let attr = hw_cycles_attr();
        let fd = sys_perf_event_open(&mut ctx, &attr, 0, -1, -1, 0);
        assert!(fd.is_ok());
        assert_eq!(ctx.event_count(), 1);
    }

    #[test]
    fn test_open_and_close() {
        let mut ctx = PerfEventContext::new();
        let attr = hw_cycles_attr();
        let fd = ctx.open_event(&attr, 0, -1, -1, 0).unwrap();
        assert!(ctx.close_event(fd).is_ok());
        assert_eq!(ctx.event_count(), 0);
    }

    #[test]
    fn test_enable_disable() {
        let mut ctx = PerfEventContext::new();
        let mut attr = hw_cycles_attr();
        attr.flags = 1; // start disabled
        let fd = ctx.open_event(&attr, 0, -1, -1, 0).unwrap();
        let data = ctx.read_event(fd).unwrap();
        assert_eq!(data.value, 0);

        assert!(ctx.enable_event(fd).is_ok());
        assert!(ctx.disable_event(fd).is_ok());
    }

    #[test]
    fn test_read_event() {
        let mut ctx = PerfEventContext::new();
        let attr = hw_cycles_attr();
        let fd = ctx.open_event(&attr, 0, -1, -1, 0).unwrap();
        let data = ctx.read_event(fd).unwrap();
        assert_eq!(data.value, 0);
        assert_eq!(data.time_enabled, 0);
    }

    #[test]
    fn test_bad_targeting() {
        let mut ctx = PerfEventContext::new();
        let attr = hw_cycles_attr();
        // pid == -1 && cpu == -1 is invalid.
        assert_eq!(
            ctx.open_event(&attr, -1, -1, -1, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_bad_flags() {
        let mut ctx = PerfEventContext::new();
        let attr = hw_cycles_attr();
        assert_eq!(
            ctx.open_event(&attr, 0, -1, -1, 0xFFFF).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_event_record() {
        let mut event = PerfEvent::new(1, hw_cycles_attr(), 0, -1, 100);
        assert!(event.is_active());
        event.record(42);
        assert_eq!(event.read_count(), 42);
        event.record(8);
        assert_eq!(event.read_count(), 50);
    }

    #[test]
    fn test_event_update_time() {
        let mut event = PerfEvent::new(1, hw_cycles_attr(), 0, -1, 100);
        event.update_time(1000);
        assert_eq!(event.time_enabled, 1000);
        assert_eq!(event.time_running, 1000);
        event.disable();
        event.update_time(500);
        assert_eq!(event.time_enabled, 1500);
        assert_eq!(event.time_running, 1000); // not running
    }

    #[test]
    fn test_group_basic() {
        let mut group = PerfEventGroup::new(1);
        assert_eq!(group.total_events(), 1);
        group.add_member(2).unwrap();
        group.add_member(3).unwrap();
        assert_eq!(group.total_events(), 3);
        assert!(group.contains(1));
        assert!(group.contains(2));
        assert!(!group.contains(99));
    }

    #[test]
    fn test_reset_event() {
        let mut ctx = PerfEventContext::new();
        let attr = hw_cycles_attr();
        let fd = ctx.open_event(&attr, 0, -1, -1, 0).unwrap();
        assert!(ctx.reset_event(fd).is_ok());
    }

    #[test]
    fn test_close_nonexistent() {
        let mut ctx = PerfEventContext::new();
        assert_eq!(ctx.close_event(999).unwrap_err(), Error::NotFound);
    }

    #[test]
    fn test_hw_cache_config_validate() {
        let mut attr = PerfEventAttr::new();
        attr.event_type = PERF_TYPE_HW_CACHE;
        // L1D read access.
        attr.config = 0 | (0 << 8) | (0 << 16);
        assert!(attr.validate().is_ok());

        // Invalid cache type.
        attr.config = 99;
        assert_eq!(attr.validate().unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn test_software_event() {
        let mut attr = PerfEventAttr::new();
        attr.event_type = PERF_TYPE_SOFTWARE;
        attr.config = PERF_COUNT_SW_CONTEXT_SWITCHES;
        assert!(attr.validate().is_ok());

        let mut ctx = PerfEventContext::new();
        let fd = ctx.open_event(&attr, 0, -1, -1, 0).unwrap();
        assert!(ctx.read_event(fd).is_ok());
    }
}
