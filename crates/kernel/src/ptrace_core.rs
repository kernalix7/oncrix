// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Process trace (ptrace) core implementation.
//!
//! Provides the kernel-side infrastructure for the `ptrace(2)` system
//! call. A tracer process can attach to a tracee to inspect and modify
//! its registers, memory, and signal delivery.
//!
//! # Operations
//!
//! - `PTRACE_ATTACH` / `PTRACE_SEIZE` — begin tracing.
//! - `PTRACE_DETACH` — stop tracing.
//! - `PTRACE_PEEKDATA` / `PTRACE_POKEDATA` — read/write tracee memory.
//! - `PTRACE_GETREGS` / `PTRACE_SETREGS` — register access.
//! - `PTRACE_CONT` / `PTRACE_SINGLESTEP` — execution control.
//! - `PTRACE_SYSCALL` — stop at syscall entry/exit.
//!
//! # Architecture
//!
//! ```text
//! PtraceManager
//!  ├── sessions: [PtraceSession; MAX_SESSIONS]
//!  └── nr_sessions: usize
//!
//! PtraceSession
//!  ├── tracer_pid / tracee_pid
//!  ├── state: PtraceState
//!  └── options: PtraceOptions
//! ```

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum concurrent ptrace sessions.
const MAX_SESSIONS: usize = 128;

/// Maximum breakpoints per session.
const MAX_BREAKPOINTS: usize = 8;

// ======================================================================
// Types
// ======================================================================

/// Ptrace request type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtraceRequest {
    /// Attach to a process (PTRACE_ATTACH).
    Attach,
    /// Seize a process without stopping (PTRACE_SEIZE).
    Seize,
    /// Detach from a process.
    Detach,
    /// Read a word from tracee memory.
    PeekData,
    /// Write a word to tracee memory.
    PokeData,
    /// Read tracee general-purpose registers.
    GetRegs,
    /// Write tracee general-purpose registers.
    SetRegs,
    /// Continue execution.
    Continue,
    /// Single-step one instruction.
    SingleStep,
    /// Stop at next syscall entry/exit.
    Syscall,
    /// Get event message (clone PID, exit status, etc.).
    GetEventMsg,
}

impl Default for PtraceRequest {
    fn default() -> Self {
        Self::Attach
    }
}

/// Current state of a ptrace session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtraceState {
    /// Session is being set up.
    Attaching,
    /// Tracee is stopped (signal-delivery-stop).
    Stopped,
    /// Tracee is running.
    Running,
    /// Tracee is in syscall-stop (entry or exit).
    SyscallStop,
    /// Tracee is single-stepping.
    SingleStepping,
    /// Session has been detached.
    Detached,
}

impl Default for PtraceState {
    fn default() -> Self {
        Self::Attaching
    }
}

/// Options controlling ptrace behaviour.
#[derive(Debug, Clone, Copy)]
pub struct PtraceOptions {
    /// Report clone/fork events.
    pub trace_clone: bool,
    /// Report exec events.
    pub trace_exec: bool,
    /// Report exit events.
    pub trace_exit: bool,
    /// Report vfork-done events.
    pub trace_vfork_done: bool,
    /// Stop at syscall entry/exit.
    pub trace_syscall: bool,
    /// Seccomp-event reporting.
    pub trace_seccomp: bool,
}

impl PtraceOptions {
    /// Creates default options (no extra events).
    pub const fn new() -> Self {
        Self {
            trace_clone: false,
            trace_exec: false,
            trace_exit: false,
            trace_vfork_done: false,
            trace_syscall: false,
            trace_seccomp: false,
        }
    }
}

impl Default for PtraceOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// A software breakpoint.
#[derive(Debug, Clone, Copy)]
pub struct Breakpoint {
    /// Address of the breakpoint.
    pub addr: u64,
    /// Original instruction byte(s) saved before patching.
    pub saved_insn: u64,
    /// Whether this breakpoint is active.
    pub active: bool,
}

impl Breakpoint {
    /// Creates an empty breakpoint.
    pub const fn new() -> Self {
        Self {
            addr: 0,
            saved_insn: 0,
            active: false,
        }
    }
}

impl Default for Breakpoint {
    fn default() -> Self {
        Self::new()
    }
}

/// A single ptrace session between a tracer and tracee.
#[derive(Debug, Clone, Copy)]
pub struct PtraceSession {
    /// PID of the tracing process.
    pub tracer_pid: u64,
    /// PID of the traced process.
    pub tracee_pid: u64,
    /// Current session state.
    pub state: PtraceState,
    /// Session options.
    pub options: PtraceOptions,
    /// Last signal delivered to tracee.
    pub last_signal: u32,
    /// Pending event message (e.g., child PID on clone).
    pub event_msg: u64,
    /// Breakpoints set in this session.
    pub breakpoints: [Breakpoint; MAX_BREAKPOINTS],
    /// Number of active breakpoints.
    pub nr_breakpoints: u8,
    /// Whether this session slot is active.
    pub active: bool,
}

impl PtraceSession {
    /// Creates an empty session.
    pub const fn new() -> Self {
        Self {
            tracer_pid: 0,
            tracee_pid: 0,
            state: PtraceState::Attaching,
            options: PtraceOptions::new(),
            last_signal: 0,
            event_msg: 0,
            breakpoints: [Breakpoint::new(); MAX_BREAKPOINTS],
            nr_breakpoints: 0,
            active: false,
        }
    }
}

impl Default for PtraceSession {
    fn default() -> Self {
        Self::new()
    }
}

/// Manages all active ptrace sessions.
pub struct PtraceManager {
    /// Array of sessions.
    sessions: [PtraceSession; MAX_SESSIONS],
    /// Number of active sessions.
    nr_sessions: usize,
}

impl PtraceManager {
    /// Creates a new ptrace manager.
    pub const fn new() -> Self {
        Self {
            sessions: [PtraceSession::new(); MAX_SESSIONS],
            nr_sessions: 0,
        }
    }

    /// Attaches a tracer to a tracee.
    pub fn attach(&mut self, tracer_pid: u64, tracee_pid: u64) -> Result<usize> {
        if tracer_pid == tracee_pid {
            return Err(Error::InvalidArgument);
        }
        // Check for existing session on this tracee.
        if self.find_by_tracee(tracee_pid).is_some() {
            return Err(Error::AlreadyExists);
        }
        if self.nr_sessions >= MAX_SESSIONS {
            return Err(Error::OutOfMemory);
        }
        for (i, session) in self.sessions.iter_mut().enumerate() {
            if !session.active {
                *session = PtraceSession {
                    tracer_pid,
                    tracee_pid,
                    state: PtraceState::Stopped,
                    options: PtraceOptions::new(),
                    last_signal: 0,
                    event_msg: 0,
                    breakpoints: [Breakpoint::new(); MAX_BREAKPOINTS],
                    nr_breakpoints: 0,
                    active: true,
                };
                self.nr_sessions += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Detaches a tracer from a tracee.
    pub fn detach(&mut self, tracee_pid: u64) -> Result<()> {
        let idx = self.find_by_tracee(tracee_pid).ok_or(Error::NotFound)?;
        self.sessions[idx].state = PtraceState::Detached;
        self.sessions[idx].active = false;
        self.nr_sessions = self.nr_sessions.saturating_sub(1);
        Ok(())
    }

    /// Processes a ptrace request.
    pub fn handle_request(
        &mut self,
        tracee_pid: u64,
        request: PtraceRequest,
    ) -> Result<PtraceState> {
        let idx = self.find_by_tracee(tracee_pid).ok_or(Error::NotFound)?;
        let session = &mut self.sessions[idx];

        match request {
            PtraceRequest::Continue => {
                session.state = PtraceState::Running;
            }
            PtraceRequest::SingleStep => {
                session.state = PtraceState::SingleStepping;
            }
            PtraceRequest::Syscall => {
                session.state = PtraceState::SyscallStop;
            }
            PtraceRequest::Detach => {
                session.state = PtraceState::Detached;
                session.active = false;
                self.nr_sessions = self.nr_sessions.saturating_sub(1);
            }
            _ => {
                // Other requests do not change state.
            }
        }
        Ok(session.state)
    }

    /// Sets ptrace options for a session.
    pub fn set_options(&mut self, tracee_pid: u64, options: PtraceOptions) -> Result<()> {
        let idx = self.find_by_tracee(tracee_pid).ok_or(Error::NotFound)?;
        self.sessions[idx].options = options;
        Ok(())
    }

    /// Adds a breakpoint to a session.
    pub fn add_breakpoint(&mut self, tracee_pid: u64, addr: u64, saved_insn: u64) -> Result<()> {
        let idx = self.find_by_tracee(tracee_pid).ok_or(Error::NotFound)?;
        let session = &mut self.sessions[idx];
        if (session.nr_breakpoints as usize) >= MAX_BREAKPOINTS {
            return Err(Error::OutOfMemory);
        }
        let bp_idx = session.nr_breakpoints as usize;
        session.breakpoints[bp_idx] = Breakpoint {
            addr,
            saved_insn,
            active: true,
        };
        session.nr_breakpoints += 1;
        Ok(())
    }

    /// Returns the number of active sessions.
    pub fn nr_sessions(&self) -> usize {
        self.nr_sessions
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    fn find_by_tracee(&self, tracee_pid: u64) -> Option<usize> {
        self.sessions
            .iter()
            .position(|s| s.active && s.tracee_pid == tracee_pid)
    }
}

impl Default for PtraceManager {
    fn default() -> Self {
        Self::new()
    }
}
