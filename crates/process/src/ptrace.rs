// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ptrace debugging interface.
//!
//! Implements the Linux-compatible `ptrace(2)` system call for process
//! tracing and debugging. Supports attaching to processes, reading and
//! writing registers and memory, single-stepping, and syscall tracing.
//!
//! # Supported Requests
//!
//! | Request       | Description                          |
//! |---------------|--------------------------------------|
//! | TRACEME       | Allow parent to trace this process   |
//! | PEEKTEXT/DATA | Read a word from tracee memory       |
//! | POKETEXT/DATA | Write a word to tracee memory        |
//! | GETREGS       | Read tracee general-purpose registers|
//! | SETREGS       | Write tracee general-purpose registers|
//! | CONT          | Continue execution                   |
//! | SINGLESTEP    | Execute one instruction              |
//! | KILL          | Kill the tracee                      |
//! | ATTACH        | Attach to a running process          |
//! | DETACH        | Detach from a traced process         |
//! | SYSCALL       | Continue and stop at next syscall    |
//! | SETOPTIONS    | Set ptrace options                   |
//! | GETEVENTMSG   | Get ptrace event data                |

use oncrix_lib::{Error, Result};

use crate::pid::Pid;

// ---------------------------------------------------------------------------
// Ptrace Request
// ---------------------------------------------------------------------------

/// Ptrace request codes (matching Linux x86_64 values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PtraceRequest {
    /// Allow parent to trace this process.
    TraceMe = 0,
    /// Read a word at the given address in tracee memory.
    PeekText = 1,
    /// Read a word at the given address in tracee memory.
    PeekData = 2,
    /// Write a word at the given address in tracee memory.
    PokeText = 4,
    /// Write a word at the given address in tracee memory.
    PokeData = 5,
    /// Continue the tracee.
    Cont = 7,
    /// Kill the tracee.
    Kill = 8,
    /// Execute a single instruction.
    SingleStep = 9,
    /// Get tracee general-purpose registers.
    GetRegs = 12,
    /// Set tracee general-purpose registers.
    SetRegs = 13,
    /// Get tracee floating-point registers.
    GetFpRegs = 14,
    /// Set tracee floating-point registers.
    SetFpRegs = 15,
    /// Attach to a running process.
    Attach = 16,
    /// Detach from a traced process.
    Detach = 17,
    /// Continue and stop at next syscall entry/exit.
    Syscall = 24,
    /// Set ptrace options.
    SetOptions = 0x4200,
    /// Get ptrace event message.
    GetEventMsg = 0x4201,
    /// Get signal information.
    GetSigInfo = 0x4202,
    /// Set signal information.
    SetSigInfo = 0x4203,
}

impl PtraceRequest {
    /// Convert a raw u32 to a PtraceRequest.
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::TraceMe),
            1 => Some(Self::PeekText),
            2 => Some(Self::PeekData),
            4 => Some(Self::PokeText),
            5 => Some(Self::PokeData),
            7 => Some(Self::Cont),
            8 => Some(Self::Kill),
            9 => Some(Self::SingleStep),
            12 => Some(Self::GetRegs),
            13 => Some(Self::SetRegs),
            14 => Some(Self::GetFpRegs),
            15 => Some(Self::SetFpRegs),
            16 => Some(Self::Attach),
            17 => Some(Self::Detach),
            24 => Some(Self::Syscall),
            0x4200 => Some(Self::SetOptions),
            0x4201 => Some(Self::GetEventMsg),
            0x4202 => Some(Self::GetSigInfo),
            0x4203 => Some(Self::SetSigInfo),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Ptrace Options
// ---------------------------------------------------------------------------

/// Ptrace options (set via PTRACE_SETOPTIONS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtraceOptions(u32);

impl PtraceOptions {
    /// No options set.
    pub const EMPTY: Self = Self(0);

    /// Report syscall-stops with (SIGTRAP | 0x80).
    pub const TRACESYSGOOD: Self = Self(1 << 0);

    /// Stop the tracee at the next fork.
    pub const TRACEFORK: Self = Self(1 << 1);

    /// Stop the tracee at the next vfork.
    pub const TRACEVFORK: Self = Self(1 << 2);

    /// Stop the tracee at the next clone.
    pub const TRACECLONE: Self = Self(1 << 3);

    /// Stop the tracee at the next exec.
    pub const TRACEEXEC: Self = Self(1 << 4);

    /// Report tracee exit via event stop.
    pub const TRACEEXIT: Self = Self(1 << 6);

    /// Create from raw bits.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Return raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Check if a specific option is set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl Default for PtraceOptions {
    fn default() -> Self {
        Self::EMPTY
    }
}

// ---------------------------------------------------------------------------
// Ptrace Event
// ---------------------------------------------------------------------------

/// Events reported via PTRACE_GETEVENTMSG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[derive(Default)]
pub enum PtraceEvent {
    /// No event.
    #[default]
    None = 0,
    /// Fork event (new child PID in event message).
    Fork = 1,
    /// Vfork event.
    VFork = 2,
    /// Clone event.
    Clone = 3,
    /// Exec event.
    Exec = 4,
    /// Exit event (exit status in event message).
    Exit = 6,
}

// ---------------------------------------------------------------------------
// User Registers (x86_64)
// ---------------------------------------------------------------------------

/// x86_64 general-purpose register set for ptrace.
///
/// Layout matches Linux `struct user_regs_struct` for
/// compatibility with debuggers like GDB.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct UserRegs {
    /// R15 register.
    pub r15: u64,
    /// R14 register.
    pub r14: u64,
    /// R13 register.
    pub r13: u64,
    /// R12 register.
    pub r12: u64,
    /// RBP (base pointer).
    pub rbp: u64,
    /// RBX register.
    pub rbx: u64,
    /// R11 register.
    pub r11: u64,
    /// R10 register.
    pub r10: u64,
    /// R9 register.
    pub r9: u64,
    /// R8 register.
    pub r8: u64,
    /// RAX register (syscall return value).
    pub rax: u64,
    /// RCX register.
    pub rcx: u64,
    /// RDX register.
    pub rdx: u64,
    /// RSI register.
    pub rsi: u64,
    /// RDI register.
    pub rdi: u64,
    /// Original RAX (syscall number before execution).
    pub orig_rax: u64,
    /// RIP (instruction pointer).
    pub rip: u64,
    /// CS segment register.
    pub cs: u64,
    /// RFLAGS register.
    pub eflags: u64,
    /// RSP (stack pointer).
    pub rsp: u64,
    /// SS segment register.
    pub ss: u64,
    /// FS base address.
    pub fs_base: u64,
    /// GS base address.
    pub gs_base: u64,
    /// DS segment register.
    pub ds: u64,
    /// ES segment register.
    pub es: u64,
    /// FS segment register.
    pub fs: u64,
    /// GS segment register.
    pub gs: u64,
}

// ---------------------------------------------------------------------------
// Ptrace State (per tracee)
// ---------------------------------------------------------------------------

/// Reason the tracee is stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StopReason {
    /// Not stopped.
    #[default]
    Running,
    /// Stopped by signal delivery.
    Signal(u8),
    /// Stopped at syscall entry.
    SyscallEntry,
    /// Stopped at syscall exit.
    SyscallExit,
    /// Stopped at event (fork/exec/exit/etc.).
    Event(PtraceEvent),
    /// Single-step completed.
    SingleStep,
}

/// Per-process ptrace state.
#[derive(Debug, Clone, Copy)]
pub struct PtraceState {
    /// PID of the tracer (0 = not traced).
    pub tracer: Pid,
    /// Current ptrace options.
    pub options: PtraceOptions,
    /// Pending event for GETEVENTMSG.
    pub pending_event: PtraceEvent,
    /// Event message data (e.g. child PID, exit status).
    pub event_msg: u64,
    /// Why the tracee is currently stopped.
    pub stop_reason: StopReason,
    /// Whether single-step is active.
    pub single_step: bool,
    /// Whether syscall tracing is active.
    pub syscall_trace: bool,
    /// Signal to inject on resume (0 = none).
    pub inject_signal: u8,
}

impl PtraceState {
    /// Create an untraced state.
    pub const fn new() -> Self {
        Self {
            tracer: Pid::new(0),
            options: PtraceOptions::EMPTY,
            pending_event: PtraceEvent::None,
            event_msg: 0,
            stop_reason: StopReason::Running,
            single_step: false,
            syscall_trace: false,
            inject_signal: 0,
        }
    }

    /// Returns `true` if this process is being traced.
    pub fn is_traced(&self) -> bool {
        self.tracer.as_u64() != 0
    }

    /// Returns `true` if the tracee is stopped.
    pub fn is_stopped(&self) -> bool {
        !matches!(self.stop_reason, StopReason::Running)
    }
}

impl Default for PtraceState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Ptrace Registry
// ---------------------------------------------------------------------------

/// Maximum number of concurrently traced processes.
const MAX_TRACED: usize = 64;

/// Entry in the ptrace registry.
#[derive(Debug, Clone, Copy)]
struct PtraceEntry {
    /// Tracee PID.
    tracee: Pid,
    /// Ptrace state for this tracee.
    state: PtraceState,
    /// Whether this slot is in use.
    active: bool,
}

impl Default for PtraceEntry {
    fn default() -> Self {
        Self {
            tracee: Pid::new(0),
            state: PtraceState::new(),
            active: false,
        }
    }
}

/// Global registry of ptrace-traced processes.
pub struct PtraceRegistry {
    /// Traced process entries.
    entries: [PtraceEntry; MAX_TRACED],
    /// Number of active entries.
    count: usize,
}

impl PtraceRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const EMPTY: PtraceEntry = PtraceEntry {
            tracee: Pid::new(0),
            state: PtraceState {
                tracer: Pid::new(0),
                options: PtraceOptions::EMPTY,
                pending_event: PtraceEvent::None,
                event_msg: 0,
                stop_reason: StopReason::Running,
                single_step: false,
                syscall_trace: false,
                inject_signal: 0,
            },
            active: false,
        };
        Self {
            entries: [EMPTY; MAX_TRACED],
            count: 0,
        }
    }

    /// Attach a tracer to a tracee.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    /// Returns [`Error::AlreadyExists`] if the tracee is already traced.
    pub fn attach(&mut self, tracer: Pid, tracee: Pid) -> Result<()> {
        // Check not already traced
        for entry in &self.entries {
            if entry.active && entry.tracee == tracee {
                return Err(Error::AlreadyExists);
            }
        }

        let idx = self
            .entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;

        self.entries[idx] = PtraceEntry {
            tracee,
            state: PtraceState {
                tracer,
                ..PtraceState::new()
            },
            active: true,
        };
        self.count += 1;
        Ok(())
    }

    /// Detach from a tracee, removing it from the registry.
    pub fn detach(&mut self, tracee: Pid) -> Result<()> {
        for entry in &mut self.entries {
            if entry.active && entry.tracee == tracee {
                entry.active = false;
                self.count = self.count.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Look up the ptrace state for a tracee.
    pub fn lookup(&self, tracee: Pid) -> Option<&PtraceState> {
        self.entries
            .iter()
            .find(|e| e.active && e.tracee == tracee)
            .map(|e| &e.state)
    }

    /// Look up the ptrace state for a tracee (mutable).
    pub fn lookup_mut(&mut self, tracee: Pid) -> Option<&mut PtraceState> {
        self.entries
            .iter_mut()
            .find(|e| e.active && e.tracee == tracee)
            .map(|e| &mut e.state)
    }

    /// Set TRACEME for the calling process (current PID becomes tracee,
    /// parent becomes tracer).
    pub fn traceme(&mut self, tracee: Pid, parent: Pid) -> Result<()> {
        self.attach(parent, tracee)
    }

    /// Returns the number of actively traced processes.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no processes are being traced.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for PtraceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Ptrace Operations
// ---------------------------------------------------------------------------

/// Stop the tracee and record the stop reason.
///
/// In a real kernel this would suspend the tracee thread and
/// send SIGCHLD to the tracer. This function updates the ptrace
/// state to reflect the stop.
pub fn ptrace_stop(registry: &mut PtraceRegistry, tracee: Pid, reason: StopReason) -> Result<()> {
    let state = registry.lookup_mut(tracee).ok_or(Error::NotFound)?;
    state.stop_reason = reason;
    Ok(())
}

/// Resume the tracee from a stopped state.
///
/// `signal` is an optional signal to inject on resume (0 = none).
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if the tracee is not stopped.
pub fn ptrace_resume(
    registry: &mut PtraceRegistry,
    tracee: Pid,
    single_step: bool,
    syscall_trace: bool,
    signal: u8,
) -> Result<()> {
    let state = registry.lookup_mut(tracee).ok_or(Error::NotFound)?;
    if !state.is_stopped() {
        return Err(Error::InvalidArgument);
    }
    state.stop_reason = StopReason::Running;
    state.single_step = single_step;
    state.syscall_trace = syscall_trace;
    state.inject_signal = signal;
    state.pending_event = PtraceEvent::None;
    state.event_msg = 0;
    Ok(())
}

/// Read a 64-bit word from tracee memory.
///
/// In a real kernel this would use `copy_from_user` on the tracee's
/// address space. This is a placeholder that validates the address.
pub fn ptrace_peek(_tracee: Pid, addr: u64) -> Result<u64> {
    // Validate user-space address range (canonical form check)
    if (0x0000_8000_0000_0000..0xffff_8000_0000_0000).contains(&addr) {
        return Err(Error::InvalidArgument);
    }
    // In a real implementation: read from tracee's address space
    // using copy_from_user/page table walk.
    Ok(0)
}

/// Write a 64-bit word to tracee memory.
///
/// In a real kernel this would use `copy_to_user` on the tracee's
/// address space. This is a placeholder that validates the address.
pub fn ptrace_poke(_tracee: Pid, addr: u64, _value: u64) -> Result<()> {
    if (0x0000_8000_0000_0000..0xffff_8000_0000_0000).contains(&addr) {
        return Err(Error::InvalidArgument);
    }
    // In a real implementation: write to tracee's address space.
    Ok(())
}

/// Main ptrace dispatcher.
///
/// Validates the request and dispatches to the appropriate handler.
///
/// # Arguments
///
/// * `registry` — the global ptrace registry
/// * `caller` — PID of the calling process (tracer)
/// * `request` — ptrace request code
/// * `tracee_pid` — PID of the target process
/// * `addr` — address argument (request-specific)
/// * `data` — data argument (request-specific)
///
/// # Returns
///
/// A `u64` result value (request-specific, 0 on success for most).
#[allow(clippy::too_many_arguments)]
pub fn do_ptrace(
    registry: &mut PtraceRegistry,
    caller: Pid,
    request: PtraceRequest,
    tracee_pid: Pid,
    addr: u64,
    data: u64,
) -> Result<u64> {
    match request {
        PtraceRequest::TraceMe => {
            // `tracee_pid` is the caller in this case, `caller`
            // is the parent.
            registry.traceme(caller, tracee_pid)?;
            Ok(0)
        }

        PtraceRequest::Attach => {
            registry.attach(caller, tracee_pid)?;
            // In real kernel: send SIGSTOP to tracee
            ptrace_stop(
                registry,
                tracee_pid,
                StopReason::Signal(19), // SIGSTOP
            )?;
            Ok(0)
        }

        PtraceRequest::Detach => {
            validate_tracer(registry, caller, tracee_pid)?;
            registry.detach(tracee_pid)?;
            Ok(0)
        }

        PtraceRequest::PeekText | PtraceRequest::PeekData => {
            validate_tracer(registry, caller, tracee_pid)?;
            ptrace_peek(tracee_pid, addr)
        }

        PtraceRequest::PokeText | PtraceRequest::PokeData => {
            validate_tracer(registry, caller, tracee_pid)?;
            ptrace_poke(tracee_pid, addr, data)?;
            Ok(0)
        }

        PtraceRequest::GetRegs => {
            validate_tracer(registry, caller, tracee_pid)?;
            // In real kernel: copy tracee's saved registers to `data`
            // address in tracer's address space.
            Ok(0)
        }

        PtraceRequest::SetRegs => {
            validate_tracer(registry, caller, tracee_pid)?;
            // In real kernel: copy registers from `data` address to
            // tracee's saved register state.
            Ok(0)
        }

        PtraceRequest::GetFpRegs => {
            validate_tracer(registry, caller, tracee_pid)?;
            Ok(0)
        }

        PtraceRequest::SetFpRegs => {
            validate_tracer(registry, caller, tracee_pid)?;
            Ok(0)
        }

        PtraceRequest::Cont => {
            validate_tracer(registry, caller, tracee_pid)?;
            let signal = data as u8;
            ptrace_resume(registry, tracee_pid, false, false, signal)?;
            Ok(0)
        }

        PtraceRequest::SingleStep => {
            validate_tracer(registry, caller, tracee_pid)?;
            let signal = data as u8;
            ptrace_resume(registry, tracee_pid, true, false, signal)?;
            Ok(0)
        }

        PtraceRequest::Syscall => {
            validate_tracer(registry, caller, tracee_pid)?;
            let signal = data as u8;
            ptrace_resume(registry, tracee_pid, false, true, signal)?;
            Ok(0)
        }

        PtraceRequest::Kill => {
            validate_tracer(registry, caller, tracee_pid)?;
            registry.detach(tracee_pid)?;
            // In real kernel: send SIGKILL to tracee.
            Ok(0)
        }

        PtraceRequest::SetOptions => {
            validate_tracer(registry, caller, tracee_pid)?;
            let state = registry.lookup_mut(tracee_pid).ok_or(Error::NotFound)?;
            state.options = PtraceOptions::from_bits(data as u32);
            Ok(0)
        }

        PtraceRequest::GetEventMsg => {
            validate_tracer(registry, caller, tracee_pid)?;
            let state = registry.lookup(tracee_pid).ok_or(Error::NotFound)?;
            Ok(state.event_msg)
        }

        PtraceRequest::GetSigInfo => {
            validate_tracer(registry, caller, tracee_pid)?;
            Ok(0)
        }

        PtraceRequest::SetSigInfo => {
            validate_tracer(registry, caller, tracee_pid)?;
            Ok(0)
        }
    }
}

/// Validate that `caller` is the registered tracer for `tracee`.
fn validate_tracer(registry: &PtraceRegistry, caller: Pid, tracee: Pid) -> Result<()> {
    let state = registry.lookup(tracee).ok_or(Error::NotFound)?;
    if state.tracer != caller {
        return Err(Error::PermissionDenied);
    }
    Ok(())
}
