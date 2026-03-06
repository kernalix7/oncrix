// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `perf_event_open(2)` syscall handler — create a performance monitoring event.
//!
//! `perf_event_open` creates a file descriptor used to measure hardware and
//! software performance counters, tracepoints, and breakpoints.  Events can
//! target a specific process, a specific CPU, or be system-wide.
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
//! | Type | Constant | Description |
//! |------|----------|-------------|
//! | Hardware | `PERF_TYPE_HARDWARE` | CPU cycle/instruction counters |
//! | Software | `PERF_TYPE_SOFTWARE` | Kernel sw counters (page faults, …) |
//! | Tracepoint | `PERF_TYPE_TRACEPOINT` | Ftrace-based kernel tracepoints |
//! | HW cache | `PERF_TYPE_HW_CACHE` | L1/LLC/DTLB/ITLB cache events |
//! | Raw PMU | `PERF_TYPE_RAW` | Architecture-specific PMU event codes |
//! | Breakpoint | `PERF_TYPE_BREAKPOINT` | Hardware breakpoints |
//!
//! # Targeting semantics
//!
//! | `pid`  | `cpu` | Scope |
//! |--------|-------|-------|
//! | `0`    | `-1`  | Calling process, any CPU |
//! | `> 0`  | `-1`  | Specific process, any CPU |
//! | `-1`   | `≥ 0` | All processes on a specific CPU |
//! | `0`    | `≥ 0` | Calling process on a specific CPU |
//!
//! # Flags
//!
//! | Flag | Effect |
//! |------|--------|
//! | `PERF_FLAG_FD_CLOEXEC` | Set O_CLOEXEC on the event fd |
//! | `PERF_FLAG_FD_NO_GROUP` | Do not join an event group |
//! | `PERF_FLAG_PID_CGROUP` | `pid` is a cgroup fd |
//!
//! # POSIX conformance
//!
//! `perf_event_open` is a Linux extension (since Linux 2.6.31).  Not part of
//! POSIX.1-2024.
//!
//! # References
//!
//! - Linux: `kernel/events/core.c`, `include/uapi/linux/perf_event.h`
//! - `perf_event_open(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Event type constants
// ---------------------------------------------------------------------------

/// CPU hardware performance counters (cycles, instructions, …).
pub const PERF_TYPE_HARDWARE: u32 = 0;
/// Kernel software counters (page faults, context switches, …).
pub const PERF_TYPE_SOFTWARE: u32 = 1;
/// Kernel tracepoints (ftrace-based static instrumentation).
pub const PERF_TYPE_TRACEPOINT: u32 = 2;
/// Hardware cache event counters.
pub const PERF_TYPE_HW_CACHE: u32 = 3;
/// Raw PMU event code (architecture-specific).
pub const PERF_TYPE_RAW: u32 = 4;
/// Hardware data breakpoints.
pub const PERF_TYPE_BREAKPOINT: u32 = 5;

/// One past the highest built-in type.
const PERF_TYPE_MAX_BUILTIN: u32 = 6;

// ---------------------------------------------------------------------------
// Hardware event identifiers
// ---------------------------------------------------------------------------

/// Total CPU cycles.
pub const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
/// Retired instructions.
pub const PERF_COUNT_HW_INSTRUCTIONS: u64 = 1;
/// L1 cache references.
pub const PERF_COUNT_HW_CACHE_REFERENCES: u64 = 2;
/// L1 cache misses.
pub const PERF_COUNT_HW_CACHE_MISSES: u64 = 3;
/// Branch instructions retired.
pub const PERF_COUNT_HW_BRANCH_INSTRUCTIONS: u64 = 4;
/// Branch mispredictions.
pub const PERF_COUNT_HW_BRANCH_MISSES: u64 = 5;
/// Bus cycles.
pub const PERF_COUNT_HW_BUS_CYCLES: u64 = 6;
/// Stalled cycles (front-end).
pub const PERF_COUNT_HW_STALLED_CYCLES_FRONTEND: u64 = 7;
/// One past the highest hardware event ID.
const PERF_COUNT_HW_MAX: u64 = 8;

// ---------------------------------------------------------------------------
// Software event identifiers
// ---------------------------------------------------------------------------

/// CPU clock ticks.
pub const PERF_COUNT_SW_CPU_CLOCK: u64 = 0;
/// Task (wall-clock) time.
pub const PERF_COUNT_SW_TASK_CLOCK: u64 = 1;
/// Page faults (all).
pub const PERF_COUNT_SW_PAGE_FAULTS: u64 = 2;
/// Context switches.
pub const PERF_COUNT_SW_CONTEXT_SWITCHES: u64 = 3;
/// CPU migrations.
pub const PERF_COUNT_SW_CPU_MIGRATIONS: u64 = 4;
/// Minor page faults (no I/O required).
pub const PERF_COUNT_SW_PAGE_FAULTS_MIN: u64 = 5;
/// Major page faults (I/O required).
pub const PERF_COUNT_SW_PAGE_FAULTS_MAJ: u64 = 6;
/// One past the highest software event ID.
const PERF_COUNT_SW_MAX: u64 = 7;

// ---------------------------------------------------------------------------
// perf_event_open flags
// ---------------------------------------------------------------------------

/// Set `O_CLOEXEC` on the resulting event fd.
pub const PERF_FLAG_FD_CLOEXEC: u64 = 1 << 3;

/// Do not add this event to the group identified by `group_fd`.
pub const PERF_FLAG_FD_NO_GROUP: u64 = 1 << 0;

/// Interpret `pid` as a cgroup fd.
pub const PERF_FLAG_PID_CGROUP: u64 = 1 << 2;

/// All valid flag bits.
const FLAGS_VALID: u64 = PERF_FLAG_FD_CLOEXEC | PERF_FLAG_FD_NO_GROUP | PERF_FLAG_PID_CGROUP;

// ---------------------------------------------------------------------------
// attr size and version constraints
// ---------------------------------------------------------------------------

/// Minimum valid `perf_event_attr` size (version 0).
const ATTR_SIZE_MIN: u32 = 64;

/// Maximum accepted `perf_event_attr` size.
const ATTR_SIZE_MAX: u32 = 4096;

// ---------------------------------------------------------------------------
// PerfEventAttr — the perf_event_attr structure
// ---------------------------------------------------------------------------

/// Attributes controlling the event to be monitored.
///
/// Corresponds to `struct perf_event_attr` in `<linux/perf_event.h>`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PerfEventAttr {
    /// Event type (`PERF_TYPE_*`).
    pub ty: u32,
    /// Size of this structure (versioning field).
    pub size: u32,
    /// Event config (hardware counter id, software counter id, tracepoint id, …).
    pub config: u64,
    /// Sampling period (events between samples) or sampling frequency in Hz.
    pub sample_period: u64,
    /// Bitmask of `PERF_SAMPLE_*` fields to include in samples.
    pub sample_type: u64,
    /// Bitmask of `PERF_FORMAT_*` fields to include in read() results.
    pub read_format: u64,
    /// Bitfield: disabled, inherit, pinned, exclusive, …
    pub flags: u64,
    /// Wakeup threshold (events or watermark bytes).
    pub wakeup_events: u32,
    /// Hardware breakpoint type (`HW_BREAKPOINT_*`).
    pub bp_type: u32,
    /// Breakpoint address or event extension config.
    pub config1: u64,
    /// Breakpoint length or event extension config 2.
    pub config2: u64,
}

impl PerfEventAttr {
    /// Validate the attribute structure.
    ///
    /// Checks that the size is within acceptable bounds and that the type
    /// and config values are sensible.
    pub fn validate(&self) -> Result<()> {
        if self.size < ATTR_SIZE_MIN || self.size > ATTR_SIZE_MAX {
            return Err(Error::InvalidArgument);
        }
        self.validate_type_config()
    }

    fn validate_type_config(&self) -> Result<()> {
        match self.ty {
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
            PERF_TYPE_TRACEPOINT | PERF_TYPE_HW_CACHE | PERF_TYPE_RAW | PERF_TYPE_BREAKPOINT => {
                // These types accept arbitrary config values.
            }
            t if t >= PERF_TYPE_MAX_BUILTIN => {
                // PMU dynamic types are allocated by the kernel; allow them.
            }
            _ => {}
        }
        Ok(())
    }
}

impl Default for PerfEventAttr {
    fn default() -> Self {
        Self {
            ty: PERF_TYPE_HARDWARE,
            size: ATTR_SIZE_MIN,
            config: PERF_COUNT_HW_CPU_CYCLES,
            sample_period: 0,
            sample_type: 0,
            read_format: 0,
            flags: 0,
            wakeup_events: 0,
            bp_type: 0,
            config1: 0,
            config2: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// EventTarget — resolved targeting parameters
// ---------------------------------------------------------------------------

/// Resolved targeting scope for a perf event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventTarget {
    /// Monitor a specific process on any CPU.
    ProcessAny { pid: u32 },
    /// Monitor the calling process on a specific CPU.
    SelfCpu { cpu: u32 },
    /// Monitor a specific process on a specific CPU.
    ProcessCpu { pid: u32, cpu: u32 },
    /// Monitor all processes on a specific CPU (system-wide).
    SystemCpu { cpu: u32 },
    /// Calling process, any CPU.
    SelfAny,
}

/// Resolve `pid` / `cpu` arguments into an [`EventTarget`].
///
/// # Arguments
///
/// * `pid` — process ID; `0` = self, `-1` = all processes.
/// * `cpu` — CPU index; `-1` = any CPU.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — `pid == -1` and `cpu == -1` simultaneously
///   (no valid target).
pub fn resolve_target(pid: i32, cpu: i32) -> Result<EventTarget> {
    match (pid, cpu) {
        (0, -1) => Ok(EventTarget::SelfAny),
        (p, -1) if p > 0 => Ok(EventTarget::ProcessAny { pid: p as u32 }),
        (-1, c) if c >= 0 => Ok(EventTarget::SystemCpu { cpu: c as u32 }),
        (0, c) if c >= 0 => Ok(EventTarget::SelfCpu { cpu: c as u32 }),
        (p, c) if p > 0 && c >= 0 => Ok(EventTarget::ProcessCpu {
            pid: p as u32,
            cpu: c as u32,
        }),
        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// PerfEvent — a live performance monitoring event
// ---------------------------------------------------------------------------

/// Maximum number of perf events the subsystem tracks.
const MAX_EVENTS: usize = 256;

/// A live perf event descriptor.
#[derive(Debug, Clone, Copy)]
pub struct PerfEvent {
    /// Virtual fd assigned to this event.
    pub id: u32,
    /// Validated event attributes.
    pub attr: PerfEventAttr,
    /// Resolved targeting.
    pub target: EventTarget,
    /// Group leader event id (`0` = standalone).
    pub group_leader: u32,
    /// Whether `O_CLOEXEC` is set.
    pub cloexec: bool,
    /// Whether `PERF_FLAG_PID_CGROUP` is set.
    pub cgroup_mode: bool,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl PerfEvent {
    const fn inactive() -> Self {
        Self {
            id: 0,
            attr: PerfEventAttr {
                ty: 0,
                size: 0,
                config: 0,
                sample_period: 0,
                sample_type: 0,
                read_format: 0,
                flags: 0,
                wakeup_events: 0,
                bp_type: 0,
                config1: 0,
                config2: 0,
            },
            target: EventTarget::SelfAny,
            group_leader: 0,
            cloexec: false,
            cgroup_mode: false,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// PerfEventSubsystem — global state
// ---------------------------------------------------------------------------

/// Global `perf_event_open` subsystem state.
pub struct PerfEventSubsystem {
    events: [PerfEvent; MAX_EVENTS],
    next_id: u32,
    /// Total events ever created.
    pub total_created: u64,
    /// Number of currently active events.
    pub active_count: u32,
}

impl PerfEventSubsystem {
    /// Create an empty subsystem.
    pub const fn new() -> Self {
        Self {
            events: [const { PerfEvent::inactive() }; MAX_EVENTS],
            next_id: 1,
            total_created: 0,
            active_count: 0,
        }
    }

    /// Retrieve an active event by id.
    pub fn get_event(&self, id: u32) -> Option<&PerfEvent> {
        self.events.iter().find(|e| e.active && e.id == id)
    }

    /// Close / destroy an event.
    pub fn close_event(&mut self, id: u32) {
        for ev in self.events.iter_mut() {
            if ev.active && ev.id == id {
                ev.active = false;
                self.active_count = self.active_count.saturating_sub(1);
                return;
            }
        }
    }

    fn alloc_event(&mut self, event: PerfEvent) -> Result<u32> {
        let slot = self
            .events
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.events[slot] = event;
        self.events[slot].id = id;
        self.events[slot].active = true;
        self.active_count += 1;
        self.total_created += 1;
        Ok(id)
    }
}

impl Default for PerfEventSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// sys_perf_event_open_handler — main entry point
// ---------------------------------------------------------------------------

/// Handle the `perf_event_open(2)` syscall.
///
/// # Arguments
///
/// * `sys`      — Mutable subsystem state.
/// * `attr`     — Validated event attribute structure.
/// * `pid`      — Target process ID (`0` = self, `-1` = all).
/// * `cpu`      — Target CPU (`-1` = any).
/// * `group_fd` — Leader event id for grouping (`-1` = no group / standalone).
/// * `flags`    — `PERF_FLAG_*` bitmask.
///
/// # Returns
///
/// Event identifier (simulates the fd returned by the real syscall).
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — Invalid attr, targeting, or flags.
/// * [`Error::NotFound`]         — `group_fd` does not refer to an active event.
/// * [`Error::OutOfMemory`]      — Event table is full.
pub fn sys_perf_event_open_handler(
    sys: &mut PerfEventSubsystem,
    attr: &PerfEventAttr,
    pid: i32,
    cpu: i32,
    group_fd: i32,
    flags: u64,
) -> Result<u32> {
    // Validate flags.
    if flags & !FLAGS_VALID != 0 {
        return Err(Error::InvalidArgument);
    }

    // Validate attr.
    attr.validate()?;

    // Resolve targeting.
    let target = resolve_target(pid, cpu)?;

    // Resolve group leader.
    let fd_no_group = flags & PERF_FLAG_FD_NO_GROUP != 0;
    let group_leader = if group_fd == -1 || fd_no_group {
        0
    } else {
        let leader_id = group_fd as u32;
        if sys.get_event(leader_id).is_none() {
            return Err(Error::NotFound);
        }
        leader_id
    };

    let cloexec = flags & PERF_FLAG_FD_CLOEXEC != 0;
    let cgroup_mode = flags & PERF_FLAG_PID_CGROUP != 0;

    // PID_CGROUP requires cpu >= 0 (no any-CPU mode with cgroups).
    if cgroup_mode && cpu < 0 {
        return Err(Error::InvalidArgument);
    }

    let event = PerfEvent {
        id: 0, // assigned by alloc_event
        attr: *attr,
        target,
        group_leader,
        cloexec,
        cgroup_mode,
        active: false, // set by alloc_event
    };

    sys.alloc_event(event)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hw_attr() -> PerfEventAttr {
        PerfEventAttr {
            ty: PERF_TYPE_HARDWARE,
            size: ATTR_SIZE_MIN,
            config: PERF_COUNT_HW_CPU_CYCLES,
            ..Default::default()
        }
    }

    fn sw_attr() -> PerfEventAttr {
        PerfEventAttr {
            ty: PERF_TYPE_SOFTWARE,
            size: ATTR_SIZE_MIN,
            config: PERF_COUNT_SW_PAGE_FAULTS,
            ..Default::default()
        }
    }

    #[test]
    fn create_hardware_event() {
        let mut sys = PerfEventSubsystem::new();
        let id = sys_perf_event_open_handler(&mut sys, &hw_attr(), 0, -1, -1, 0).unwrap();
        let ev = sys.get_event(id).unwrap();
        assert_eq!(ev.attr.ty, PERF_TYPE_HARDWARE);
        assert_eq!(ev.target, EventTarget::SelfAny);
        assert!(!ev.cloexec);
        assert_eq!(sys.active_count, 1);
    }

    #[test]
    fn create_software_event() {
        let mut sys = PerfEventSubsystem::new();
        let id = sys_perf_event_open_handler(&mut sys, &sw_attr(), 0, -1, -1, PERF_FLAG_FD_CLOEXEC)
            .unwrap();
        let ev = sys.get_event(id).unwrap();
        assert_eq!(ev.attr.ty, PERF_TYPE_SOFTWARE);
        assert!(ev.cloexec);
    }

    #[test]
    fn system_wide_event() {
        let mut sys = PerfEventSubsystem::new();
        let id = sys_perf_event_open_handler(&mut sys, &hw_attr(), -1, 0, -1, 0).unwrap();
        let ev = sys.get_event(id).unwrap();
        assert_eq!(ev.target, EventTarget::SystemCpu { cpu: 0 });
    }

    #[test]
    fn invalid_pid_cpu_combo() {
        let mut sys = PerfEventSubsystem::new();
        // pid=-1 and cpu=-1 is invalid
        assert_eq!(
            sys_perf_event_open_handler(&mut sys, &hw_attr(), -1, -1, -1, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn invalid_attr_size_rejected() {
        let mut sys = PerfEventSubsystem::new();
        let mut attr = hw_attr();
        attr.size = 4; // too small
        assert_eq!(
            sys_perf_event_open_handler(&mut sys, &attr, 0, -1, -1, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn invalid_hw_config_rejected() {
        let mut sys = PerfEventSubsystem::new();
        let mut attr = hw_attr();
        attr.config = PERF_COUNT_HW_MAX; // out of range
        assert_eq!(
            sys_perf_event_open_handler(&mut sys, &attr, 0, -1, -1, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unknown_flags_rejected() {
        let mut sys = PerfEventSubsystem::new();
        assert_eq!(
            sys_perf_event_open_handler(&mut sys, &hw_attr(), 0, -1, -1, 0x8000_0000),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn group_event_resolves_leader() {
        let mut sys = PerfEventSubsystem::new();
        let leader_id = sys_perf_event_open_handler(&mut sys, &hw_attr(), 0, -1, -1, 0).unwrap();
        let member_id =
            sys_perf_event_open_handler(&mut sys, &sw_attr(), 0, -1, leader_id as i32, 0).unwrap();
        let member = sys.get_event(member_id).unwrap();
        assert_eq!(member.group_leader, leader_id);
    }

    #[test]
    fn bad_group_fd_rejected() {
        let mut sys = PerfEventSubsystem::new();
        assert_eq!(
            sys_perf_event_open_handler(&mut sys, &hw_attr(), 0, -1, 9999, 0),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn cgroup_mode_requires_cpu() {
        let mut sys = PerfEventSubsystem::new();
        assert_eq!(
            sys_perf_event_open_handler(
                &mut sys,
                &hw_attr(),
                0,
                -1, // any CPU — invalid with PID_CGROUP
                -1,
                PERF_FLAG_PID_CGROUP
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn close_event_decrements_count() {
        let mut sys = PerfEventSubsystem::new();
        let id = sys_perf_event_open_handler(&mut sys, &hw_attr(), 0, -1, -1, 0).unwrap();
        assert_eq!(sys.active_count, 1);
        sys.close_event(id);
        assert_eq!(sys.active_count, 0);
        assert!(sys.get_event(id).is_none());
    }

    #[test]
    fn resolve_target_self_any() {
        assert_eq!(resolve_target(0, -1), Ok(EventTarget::SelfAny));
    }

    #[test]
    fn resolve_target_process_any() {
        assert_eq!(
            resolve_target(42, -1),
            Ok(EventTarget::ProcessAny { pid: 42 })
        );
    }

    #[test]
    fn resolve_target_self_cpu() {
        assert_eq!(resolve_target(0, 3), Ok(EventTarget::SelfCpu { cpu: 3 }));
    }
}
