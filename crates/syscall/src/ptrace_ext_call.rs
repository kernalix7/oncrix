// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended `ptrace(2)` operations.
//!
//! Provides supplementary types and validation helpers for advanced ptrace
//! requests: `PTRACE_SEIZE`, `PTRACE_INTERRUPT`, `PTRACE_LISTEN`,
//! `PTRACE_PEEKSIGINFO`, `PTRACE_GETSIGMASK`, `PTRACE_SETSIGMASK`, and the
//! `PTRACE_O_*` option flags.
//!
//! The basic attach/detach/peek/poke operations are handled by `ptrace_call`
//! and `ptrace_calls`.  This module focuses on the modern event-based API.
//!
//! # POSIX reference
//!
//! `ptrace` is not part of POSIX; it is a Linux-specific debugging interface.
//!
//! # References
//!
//! - Linux: `kernel/ptrace.c`
//! - `ptrace(2)` man page
//! - `include/uapi/linux/ptrace.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Request constants
// ---------------------------------------------------------------------------

/// Attach to the target without stopping it.
pub const PTRACE_SEIZE: u32 = 0x4206;
/// Stop the target and deliver a `PTRACE_EVENT_STOP`.
pub const PTRACE_INTERRUPT: u32 = 0x4207;
/// Allow the target to continue without delivering further stops.
pub const PTRACE_LISTEN: u32 = 0x4208;
/// Peek siginfo entries from the target's signal queue.
pub const PTRACE_PEEKSIGINFO: u32 = 0x4209;
/// Read the target's signal mask.
pub const PTRACE_GETSIGMASK: u32 = 0x420a;
/// Write the target's signal mask.
pub const PTRACE_SETSIGMASK: u32 = 0x420b;
/// Get the target's seccomp filter flags.
pub const PTRACE_SECCOMP_GET_FILTER: u32 = 0x420c;

// ---------------------------------------------------------------------------
// Option flags (PTRACE_O_*)
// ---------------------------------------------------------------------------

/// Deliver `PTRACE_EVENT_FORK` before a `fork`.
pub const PTRACE_O_TRACEFORK: u32 = 1 << 1;
/// Deliver `PTRACE_EVENT_VFORK` before a `vfork`.
pub const PTRACE_O_TRACEVFORK: u32 = 1 << 2;
/// Deliver `PTRACE_EVENT_CLONE` before a `clone`.
pub const PTRACE_O_TRACECLONE: u32 = 1 << 3;
/// Deliver `PTRACE_EVENT_EXEC` after an `execve`.
pub const PTRACE_O_TRACEEXEC: u32 = 1 << 4;
/// Deliver `PTRACE_EVENT_VFORK_DONE` when the parent resumes from vfork.
pub const PTRACE_O_TRACEVFORKDONE: u32 = 1 << 5;
/// Deliver `PTRACE_EVENT_EXIT` before `_exit`.
pub const PTRACE_O_TRACEEXIT: u32 = 1 << 6;
/// Enable seccomp event delivery.
pub const PTRACE_O_TRACESECCOMP: u32 = 1 << 7;
/// Stop when SIGKILL is delivered.
pub const PTRACE_O_EXITKILL: u32 = 1 << 20;
/// Suspend seccomp on attach.
pub const PTRACE_O_SUSPEND_SECCOMP: u32 = 1 << 21;

/// Mask of all recognised option bits.
const PTRACE_O_KNOWN: u32 = PTRACE_O_TRACEFORK
    | PTRACE_O_TRACEVFORK
    | PTRACE_O_TRACECLONE
    | PTRACE_O_TRACEEXEC
    | PTRACE_O_TRACEVFORKDONE
    | PTRACE_O_TRACEEXIT
    | PTRACE_O_TRACESECCOMP
    | PTRACE_O_EXITKILL
    | PTRACE_O_SUSPEND_SECCOMP;

// ---------------------------------------------------------------------------
// PtraceEvent — event codes delivered to the tracer
// ---------------------------------------------------------------------------

/// Event codes embedded in the wait status word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PtraceEvent {
    Fork = 1,
    Vfork = 2,
    Clone = 3,
    Exec = 4,
    VforkDone = 5,
    Exit = 6,
    Seccomp = 7,
    Stop = 128,
}

impl PtraceEvent {
    /// Parse a raw event code.
    pub fn from_raw(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Fork),
            2 => Some(Self::Vfork),
            3 => Some(Self::Clone),
            4 => Some(Self::Exec),
            5 => Some(Self::VforkDone),
            6 => Some(Self::Exit),
            7 => Some(Self::Seccomp),
            128 => Some(Self::Stop),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// PtraceOptions — validated option set
// ---------------------------------------------------------------------------

/// Validated ptrace option set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PtraceOptions {
    /// Track fork.
    pub trace_fork: bool,
    /// Track vfork.
    pub trace_vfork: bool,
    /// Track clone.
    pub trace_clone: bool,
    /// Track exec.
    pub trace_exec: bool,
    /// Track vfork-done.
    pub trace_vfork_done: bool,
    /// Track exit.
    pub trace_exit: bool,
    /// Track seccomp events.
    pub trace_seccomp: bool,
    /// Kill tracee on tracer exit.
    pub exit_kill: bool,
    /// Suspend seccomp on attach.
    pub suspend_seccomp: bool,
}

impl PtraceOptions {
    /// Parse raw option bits.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] for unrecognised bits.
    pub fn from_raw(raw: u32) -> Result<Self> {
        if raw & !PTRACE_O_KNOWN != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            trace_fork: raw & PTRACE_O_TRACEFORK != 0,
            trace_vfork: raw & PTRACE_O_TRACEVFORK != 0,
            trace_clone: raw & PTRACE_O_TRACECLONE != 0,
            trace_exec: raw & PTRACE_O_TRACEEXEC != 0,
            trace_vfork_done: raw & PTRACE_O_TRACEVFORKDONE != 0,
            trace_exit: raw & PTRACE_O_TRACEEXIT != 0,
            trace_seccomp: raw & PTRACE_O_TRACESECCOMP != 0,
            exit_kill: raw & PTRACE_O_EXITKILL != 0,
            suspend_seccomp: raw & PTRACE_O_SUSPEND_SECCOMP != 0,
        })
    }

    /// Encode back to raw bits.
    pub fn to_raw(self) -> u32 {
        let mut r = 0u32;
        if self.trace_fork {
            r |= PTRACE_O_TRACEFORK;
        }
        if self.trace_vfork {
            r |= PTRACE_O_TRACEVFORK;
        }
        if self.trace_clone {
            r |= PTRACE_O_TRACECLONE;
        }
        if self.trace_exec {
            r |= PTRACE_O_TRACEEXEC;
        }
        if self.trace_vfork_done {
            r |= PTRACE_O_TRACEVFORKDONE;
        }
        if self.trace_exit {
            r |= PTRACE_O_TRACEEXIT;
        }
        if self.trace_seccomp {
            r |= PTRACE_O_TRACESECCOMP;
        }
        if self.exit_kill {
            r |= PTRACE_O_EXITKILL;
        }
        if self.suspend_seccomp {
            r |= PTRACE_O_SUSPEND_SECCOMP;
        }
        r
    }
}

// ---------------------------------------------------------------------------
// TraceeRecord — per-tracee state
// ---------------------------------------------------------------------------

/// State of a tracee attached via `PTRACE_SEIZE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceeState {
    /// Running normally under the tracer.
    Running,
    /// Stopped (delivered a ptrace-stop).
    Stopped,
    /// In `PTRACE_LISTEN` — running but delivery of ptrace-stops is suspended.
    Listening,
}

/// Per-tracee record.
#[derive(Debug, Clone, Copy)]
pub struct TraceeRecord {
    /// Tracee PID.
    pub pid: u64,
    /// PID of the tracer.
    pub tracer_pid: u64,
    /// Current state.
    pub state: TraceeState,
    /// Active options.
    pub options: PtraceOptions,
}

// ---------------------------------------------------------------------------
// TraceeTable
// ---------------------------------------------------------------------------

/// Maximum tracees per tracer.
const MAX_TRACEES: usize = 128;

/// Ptrace tracee table.
pub struct TraceeTable {
    records: [Option<TraceeRecord>; MAX_TRACEES],
}

impl TraceeTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            records: [const { None }; MAX_TRACEES],
        }
    }

    /// Insert a new tracee record.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfMemory`] if the table is full.
    /// [`Error::AlreadyExists`] if `pid` is already traced.
    pub fn insert(&mut self, record: TraceeRecord) -> Result<()> {
        if self
            .records
            .iter()
            .any(|r| r.map(|r| r.pid) == Some(record.pid))
        {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .records
            .iter()
            .position(|r| r.is_none())
            .ok_or(Error::OutOfMemory)?;
        self.records[slot] = Some(record);
        Ok(())
    }

    /// Remove a tracee by PID.
    pub fn remove(&mut self, pid: u64) -> bool {
        for slot in &mut self.records {
            if slot.map(|r| r.pid) == Some(pid) {
                *slot = None;
                return true;
            }
        }
        false
    }

    /// Lookup a tracee by PID.
    pub fn get(&self, pid: u64) -> Option<&TraceeRecord> {
        self.records
            .iter()
            .filter_map(|r| r.as_ref())
            .find(|r| r.pid == pid)
    }

    /// Lookup a tracee mutably.
    pub fn get_mut(&mut self, pid: u64) -> Option<&mut TraceeRecord> {
        self.records
            .iter_mut()
            .filter_map(|r| r.as_mut())
            .find(|r| r.pid == pid)
    }
}

impl Default for TraceeTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// sys_ptrace_seize — PTRACE_SEIZE
// ---------------------------------------------------------------------------

/// Handle `PTRACE_SEIZE`.
///
/// Attaches to `pid` without stopping it.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — unknown option bits.
/// * [`Error::AlreadyExists`]   — `pid` is already traced.
/// * [`Error::OutOfMemory`]     — table full.
pub fn sys_ptrace_seize(
    table: &mut TraceeTable,
    tracer_pid: u64,
    pid: u64,
    options_raw: u32,
) -> Result<()> {
    let options = PtraceOptions::from_raw(options_raw)?;
    table.insert(TraceeRecord {
        pid,
        tracer_pid,
        state: TraceeState::Running,
        options,
    })
}

// ---------------------------------------------------------------------------
// sys_ptrace_interrupt — PTRACE_INTERRUPT
// ---------------------------------------------------------------------------

/// Handle `PTRACE_INTERRUPT`.
///
/// Causes the tracee to enter a ptrace-stop.
///
/// # Errors
///
/// * [`Error::NotFound`] — `pid` is not in the table or not traced by caller.
pub fn sys_ptrace_interrupt(table: &mut TraceeTable, tracer_pid: u64, pid: u64) -> Result<()> {
    let rec = table.get_mut(pid).ok_or(Error::NotFound)?;
    if rec.tracer_pid != tracer_pid {
        return Err(Error::PermissionDenied);
    }
    rec.state = TraceeState::Stopped;
    Ok(())
}

// ---------------------------------------------------------------------------
// sys_ptrace_listen — PTRACE_LISTEN
// ---------------------------------------------------------------------------

/// Handle `PTRACE_LISTEN`.
///
/// Resumes the tracee without delivering pending signals and suspends further
/// ptrace-stops.
///
/// # Errors
///
/// * [`Error::NotFound`]         — `pid` not traced.
/// * [`Error::PermissionDenied`] — caller is not the tracer.
/// * [`Error::InvalidArgument`]  — tracee is not currently stopped.
pub fn sys_ptrace_listen(table: &mut TraceeTable, tracer_pid: u64, pid: u64) -> Result<()> {
    let rec = table.get_mut(pid).ok_or(Error::NotFound)?;
    if rec.tracer_pid != tracer_pid {
        return Err(Error::PermissionDenied);
    }
    if rec.state != TraceeState::Stopped {
        return Err(Error::InvalidArgument);
    }
    rec.state = TraceeState::Listening;
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seize_and_interrupt() {
        let mut t = TraceeTable::new();
        sys_ptrace_seize(&mut t, 1, 100, 0).unwrap();
        assert_eq!(t.get(100).unwrap().state, TraceeState::Running);
        sys_ptrace_interrupt(&mut t, 1, 100).unwrap();
        assert_eq!(t.get(100).unwrap().state, TraceeState::Stopped);
    }

    #[test]
    fn listen_after_stop() {
        let mut t = TraceeTable::new();
        sys_ptrace_seize(&mut t, 1, 200, 0).unwrap();
        sys_ptrace_interrupt(&mut t, 1, 200).unwrap();
        sys_ptrace_listen(&mut t, 1, 200).unwrap();
        assert_eq!(t.get(200).unwrap().state, TraceeState::Listening);
    }

    #[test]
    fn listen_without_stop_rejected() {
        let mut t = TraceeTable::new();
        sys_ptrace_seize(&mut t, 1, 300, 0).unwrap();
        assert_eq!(
            sys_ptrace_listen(&mut t, 1, 300),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn double_seize_rejected() {
        let mut t = TraceeTable::new();
        sys_ptrace_seize(&mut t, 1, 400, 0).unwrap();
        assert_eq!(
            sys_ptrace_seize(&mut t, 1, 400, 0),
            Err(Error::AlreadyExists)
        );
    }

    #[test]
    fn interrupt_wrong_tracer() {
        let mut t = TraceeTable::new();
        sys_ptrace_seize(&mut t, 1, 500, 0).unwrap();
        assert_eq!(
            sys_ptrace_interrupt(&mut t, 9, 500),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn unknown_option_bits_rejected() {
        let mut t = TraceeTable::new();
        assert_eq!(
            sys_ptrace_seize(&mut t, 1, 600, 0xDEAD_0000),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn options_roundtrip() {
        let raw = PTRACE_O_TRACEFORK | PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL;
        let opts = PtraceOptions::from_raw(raw).unwrap();
        assert!(opts.trace_fork);
        assert!(opts.trace_exec);
        assert!(opts.exit_kill);
        assert_eq!(opts.to_raw(), raw);
    }
}
