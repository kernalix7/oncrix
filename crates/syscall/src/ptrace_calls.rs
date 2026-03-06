// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Ptrace syscall handlers.
//!
//! Implements the `ptrace(2)` interface for process debugging per
//! POSIX.1-2024 and the Linux ptrace extension set.  Covers attaching,
//! detaching, register inspection, memory peek/poke, single-stepping,
//! and event-tracing options.
//!
//! # POSIX Reference
//!
//! See `.TheOpenGroup/susv5-html/functions/ptrace.html` and the kernel
//! source for the full request enumeration and per-request semantics.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of simultaneously active ptrace sessions.
const PTRACE_TABLE_MAX: usize = 128;

/// Ptrace option: kill tracee when tracer exits.
pub const PTRACE_O_EXITKILL: u32 = 1 << 20;
/// Ptrace option: deliver SIGTRAP | 0x80 on syscall-stop.
pub const PTRACE_O_TRACESYSGOOD: u32 = 1 << 0;
/// Ptrace option: trace fork() calls.
pub const PTRACE_O_TRACEFORK: u32 = 1 << 1;
/// Ptrace option: trace vfork() calls.
pub const PTRACE_O_TRACEVFORK: u32 = 1 << 2;
/// Ptrace option: trace clone() calls.
pub const PTRACE_O_TRACECLONE: u32 = 1 << 3;
/// Ptrace option: trace exec() calls.
pub const PTRACE_O_TRACEEXEC: u32 = 1 << 4;
/// Ptrace option: trace process exit.
pub const PTRACE_O_TRACEEXIT: u32 = 1 << 6;
/// Ptrace option: trace seccomp events.
pub const PTRACE_O_TRACESECCOMP: u32 = 1 << 7;

/// Bitmask of all valid ptrace option bits.
const PTRACE_O_MASK: u32 = PTRACE_O_EXITKILL
    | PTRACE_O_TRACESYSGOOD
    | PTRACE_O_TRACEFORK
    | PTRACE_O_TRACEVFORK
    | PTRACE_O_TRACECLONE
    | PTRACE_O_TRACEEXEC
    | PTRACE_O_TRACEEXIT
    | PTRACE_O_TRACESECCOMP;

// ---------------------------------------------------------------------------
// PtraceRequest
// ---------------------------------------------------------------------------

/// Ptrace request codes passed as the first argument to `ptrace(2)`.
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtraceRequest {
    /// Indicate that the calling process wants to be traced.
    Traceme = 0,
    /// Read a word from the tracee's text segment.
    Peektext = 1,
    /// Read a word from the tracee's data segment.
    Peekdata = 2,
    /// Read a word from the tracee's user area.
    Peekuser = 3,
    /// Write a word to the tracee's text segment.
    Poketext = 4,
    /// Write a word to the tracee's data segment.
    Pokedata = 5,
    /// Write a word to the tracee's user area.
    Pokeuser = 6,
    /// Resume execution of a stopped tracee.
    Cont = 7,
    /// Send SIGKILL to the tracee.
    Kill = 8,
    /// Resume execution and stop after a single instruction.
    Singlestep = 9,
    /// Copy general-purpose registers from tracee.
    Getregs = 12,
    /// Set general-purpose registers in tracee.
    Setregs = 13,
    /// Copy floating-point registers from tracee.
    Getfpregs = 14,
    /// Set floating-point registers in tracee.
    Setfpregs = 15,
    /// Attach to a running process.
    Attach = 16,
    /// Detach from a tracee, resuming its execution.
    Detach = 17,
    /// Resume and stop at next syscall entry/exit.
    Syscall = 24,
    /// Set ptrace options flags.
    Setoptions = 0x4200,
    /// Retrieve the event message for the last ptrace event.
    Geteventmsg = 0x4201,
    /// Copy `siginfo_t` from the tracee.
    Getsiginfo = 0x4202,
    /// Set `siginfo_t` in the tracee.
    Setsiginfo = 0x4203,
    /// Seize a tracee without stopping it.
    Seize = 0x4206,
    /// Interrupt a seized tracee.
    Interrupt = 0x4207,
    /// Put the tracee into listen mode.
    Listen = 0x4208,
}

impl PtraceRequest {
    /// Convert a raw `u64` into a `PtraceRequest`, if valid.
    pub fn from_u64(val: u64) -> Option<Self> {
        match val {
            0 => Some(Self::Traceme),
            1 => Some(Self::Peektext),
            2 => Some(Self::Peekdata),
            3 => Some(Self::Peekuser),
            4 => Some(Self::Poketext),
            5 => Some(Self::Pokedata),
            6 => Some(Self::Pokeuser),
            7 => Some(Self::Cont),
            8 => Some(Self::Kill),
            9 => Some(Self::Singlestep),
            12 => Some(Self::Getregs),
            13 => Some(Self::Setregs),
            14 => Some(Self::Getfpregs),
            15 => Some(Self::Setfpregs),
            16 => Some(Self::Attach),
            17 => Some(Self::Detach),
            24 => Some(Self::Syscall),
            0x4200 => Some(Self::Setoptions),
            0x4201 => Some(Self::Geteventmsg),
            0x4202 => Some(Self::Getsiginfo),
            0x4203 => Some(Self::Setsiginfo),
            0x4206 => Some(Self::Seize),
            0x4207 => Some(Self::Interrupt),
            0x4208 => Some(Self::Listen),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// PtraceOptions — bitflags wrapper
// ---------------------------------------------------------------------------

/// Bitflag set controlling ptrace event delivery.
///
/// Constructed from the `PTRACE_O_*` constants and passed to
/// `PTRACE_SETOPTIONS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PtraceOptions(u32);

impl PtraceOptions {
    /// No options set.
    pub const NONE: Self = Self(0);
    /// Kill tracee when tracer exits.
    pub const EXITKILL: Self = Self(PTRACE_O_EXITKILL);
    /// Deliver SIGTRAP | 0x80 on syscall-stop.
    pub const TRACESYSGOOD: Self = Self(PTRACE_O_TRACESYSGOOD);
    /// Trace fork() events.
    pub const TRACEFORK: Self = Self(PTRACE_O_TRACEFORK);
    /// Trace vfork() events.
    pub const TRACEVFORK: Self = Self(PTRACE_O_TRACEVFORK);
    /// Trace clone() events.
    pub const TRACECLONE: Self = Self(PTRACE_O_TRACECLONE);
    /// Trace exec() events.
    pub const TRACEEXEC: Self = Self(PTRACE_O_TRACEEXEC);
    /// Trace exit events.
    pub const TRACEEXIT: Self = Self(PTRACE_O_TRACEEXIT);
    /// Trace seccomp events.
    pub const TRACESECCOMP: Self = Self(PTRACE_O_TRACESECCOMP);

    /// Create from a raw `u32` value, rejecting unknown bits.
    pub fn from_u32(val: u32) -> Result<Self> {
        if val & !PTRACE_O_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(val))
    }

    /// Return the raw bit pattern.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Test whether `other` bits are all set in `self`.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Combine two option sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

// ---------------------------------------------------------------------------
// UserRegs — x86_64 general-purpose register set
// ---------------------------------------------------------------------------

/// x86_64 general-purpose register file as seen through `PTRACE_GETREGS`.
///
/// Layout matches `struct user_regs_struct` in `<sys/user.h>`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserRegs {
    /// Callee-saved register r15.
    pub r15: u64,
    /// Callee-saved register r14.
    pub r14: u64,
    /// Callee-saved register r13.
    pub r13: u64,
    /// Callee-saved register r12.
    pub r12: u64,
    /// Base pointer (frame pointer in some ABIs).
    pub rbp: u64,
    /// Callee-saved register rbx.
    pub rbx: u64,
    /// Caller-saved register r11.
    pub r11: u64,
    /// Caller-saved register r10.
    pub r10: u64,
    /// Caller-saved / argument register r9.
    pub r9: u64,
    /// Caller-saved / argument register r8.
    pub r8: u64,
    /// Accumulator / syscall return value.
    pub rax: u64,
    /// Counter register.
    pub rcx: u64,
    /// Data register / third argument.
    pub rdx: u64,
    /// Source index / second argument.
    pub rsi: u64,
    /// Destination index / first argument.
    pub rdi: u64,
    /// Original rax (syscall number at entry).
    pub orig_rax: u64,
    /// Instruction pointer.
    pub rip: u64,
    /// Code segment selector.
    pub cs: u64,
    /// CPU flags register (RFLAGS).
    pub eflags: u64,
    /// Stack pointer.
    pub rsp: u64,
    /// Stack segment selector.
    pub ss: u64,
}

impl Default for UserRegs {
    fn default() -> Self {
        Self {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbp: 0,
            rbx: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            orig_rax: 0,
            rip: 0,
            cs: 0,
            eflags: 0,
            rsp: 0,
            ss: 0,
        }
    }
}

impl UserRegs {
    /// Create a zero-initialised register set.
    pub const fn new() -> Self {
        Self {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbp: 0,
            rbx: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            orig_rax: 0,
            rip: 0,
            cs: 0,
            eflags: 0,
            rsp: 0,
            ss: 0,
        }
    }

    /// Return the syscall number (orig_rax at syscall entry).
    pub const fn syscall_nr(&self) -> u64 {
        self.orig_rax
    }

    /// Return the syscall return value (rax after syscall return).
    pub const fn syscall_ret(&self) -> u64 {
        self.rax
    }
}

// ---------------------------------------------------------------------------
// SigInfo — signal information for GETSIGINFO / SETSIGINFO
// ---------------------------------------------------------------------------

/// Compressed `siginfo_t` representation for ptrace.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SigInfo {
    /// Signal number.
    pub si_signo: i32,
    /// Error number (often 0).
    pub si_errno: i32,
    /// Signal code (SI_USER, SI_KERNEL, etc.).
    pub si_code: i32,
    /// Sending PID (if applicable).
    pub si_pid: u32,
    /// Sending UID (if applicable).
    pub si_uid: u32,
    /// Faulting address (for SIGSEGV/SIGBUS).
    pub si_addr: u64,
}

// ---------------------------------------------------------------------------
// PtraceState — per-tracee state
// ---------------------------------------------------------------------------

/// State tracked for a single ptrace-attached tracee.
#[derive(Debug, Clone, Copy)]
pub struct PtraceState {
    /// PID of the tracer process.
    pub tracer_pid: u32,
    /// PID of the tracee process.
    pub tracee_pid: u32,
    /// Active ptrace options.
    pub options: PtraceOptions,
    /// Whether the tracee is currently stopped.
    pub stopped: bool,
    /// Pending signal to deliver on resume (0 = none).
    pub pending_signal: i32,
    /// Saved register set (valid when `stopped` is true).
    pub regs: UserRegs,
    /// Saved floating-point register state (opaque 512-byte XSAVE area).
    pub fpregs: [u8; 64],
    /// Last ptrace event message (for `PTRACE_GETEVENTMSG`).
    pub event_msg: u64,
    /// Signal info for `PTRACE_GETSIGINFO`.
    pub siginfo: SigInfo,
    /// Session in seize mode (not stopped on attach).
    pub seized: bool,
    /// Session in listen mode (awaiting group-stop).
    pub listening: bool,
}

impl PtraceState {
    /// Create a new ptrace session between `tracer_pid` and `tracee_pid`.
    pub const fn new(tracer_pid: u32, tracee_pid: u32) -> Self {
        Self {
            tracer_pid,
            tracee_pid,
            options: PtraceOptions::NONE,
            stopped: false,
            pending_signal: 0,
            regs: UserRegs::new(),
            fpregs: [0u8; 64],
            event_msg: 0,
            siginfo: SigInfo {
                si_signo: 0,
                si_errno: 0,
                si_code: 0,
                si_pid: 0,
                si_uid: 0,
                si_addr: 0,
            },
            seized: false,
            listening: false,
        }
    }
}

// ---------------------------------------------------------------------------
// PtraceTable
// ---------------------------------------------------------------------------

/// Slot in the ptrace table; holds an optional active session.
struct PtraceSlot {
    /// Active session state, or `None` if slot is free.
    state: Option<PtraceState>,
}

impl PtraceSlot {
    const fn empty() -> Self {
        Self { state: None }
    }
}

/// Kernel-wide table of active ptrace sessions.
///
/// Supports up to [`PTRACE_TABLE_MAX`] concurrent sessions.
pub struct PtraceTable {
    slots: [PtraceSlot; PTRACE_TABLE_MAX],
    /// Number of active sessions.
    count: usize,
}

impl PtraceTable {
    /// Create an empty ptrace table.
    pub const fn new() -> Self {
        Self {
            slots: [const { PtraceSlot::empty() }; PTRACE_TABLE_MAX],
            count: 0,
        }
    }

    /// Return the number of active ptrace sessions.
    pub const fn count(&self) -> usize {
        self.count
    }

    // -- Internal helpers --------------------------------------------------

    /// Find a slot index by tracee PID.
    fn find_tracee(&self, tracee_pid: u32) -> Option<usize> {
        for (i, slot) in self.slots.iter().enumerate() {
            if let Some(ref s) = slot.state {
                if s.tracee_pid == tracee_pid {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Find a free slot.
    fn find_free(&self) -> Option<usize> {
        for (i, slot) in self.slots.iter().enumerate() {
            if slot.state.is_none() {
                return Some(i);
            }
        }
        None
    }

    /// Look up the state for a tracee, returning a shared reference.
    fn get_state(&self, tracee_pid: u32) -> Result<&PtraceState> {
        let idx = self.find_tracee(tracee_pid).ok_or(Error::NotFound)?;
        self.slots[idx].state.as_ref().ok_or(Error::NotFound)
    }

    /// Look up the state for a tracee, returning a mutable reference.
    fn get_state_mut(&mut self, tracee_pid: u32) -> Result<&mut PtraceState> {
        let idx = self.find_tracee(tracee_pid).ok_or(Error::NotFound)?;
        self.slots[idx].state.as_mut().ok_or(Error::NotFound)
    }
}

impl Default for PtraceTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate that `pid` is a non-zero, plausible PID.
fn validate_pid(pid: u32) -> Result<()> {
    if pid == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate that `addr` is 8-byte aligned for register-sized reads.
fn validate_aligned(addr: u64) -> Result<()> {
    if addr % 8 != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Individual request handlers
// ---------------------------------------------------------------------------

/// Handle `PTRACE_ATTACH`: attach the calling process as tracer.
///
/// The tracee receives `SIGSTOP` and enters ptrace-stop.
/// Returns `AlreadyExists` if the tracee is already being traced.
pub fn ptrace_attach(table: &mut PtraceTable, tracer_pid: u32, tracee_pid: u32) -> Result<()> {
    validate_pid(tracer_pid)?;
    validate_pid(tracee_pid)?;

    if tracer_pid == tracee_pid {
        return Err(Error::InvalidArgument);
    }

    if table.find_tracee(tracee_pid).is_some() {
        return Err(Error::AlreadyExists);
    }

    let idx = table.find_free().ok_or(Error::OutOfMemory)?;
    let mut state = PtraceState::new(tracer_pid, tracee_pid);
    // On attach the tracee is placed into ptrace-stop.
    state.stopped = true;
    table.slots[idx].state = Some(state);
    table.count += 1;
    Ok(())
}

/// Handle `PTRACE_SEIZE`: attach without stopping the tracee.
///
/// Allows the tracer to use `PTRACE_INTERRUPT` and `PTRACE_LISTEN`.
pub fn ptrace_seize(
    table: &mut PtraceTable,
    tracer_pid: u32,
    tracee_pid: u32,
    options: u32,
) -> Result<()> {
    validate_pid(tracer_pid)?;
    validate_pid(tracee_pid)?;

    if tracer_pid == tracee_pid {
        return Err(Error::InvalidArgument);
    }

    if table.find_tracee(tracee_pid).is_some() {
        return Err(Error::AlreadyExists);
    }

    let opts = PtraceOptions::from_u32(options)?;
    let idx = table.find_free().ok_or(Error::OutOfMemory)?;
    let mut state = PtraceState::new(tracer_pid, tracee_pid);
    state.options = opts;
    state.seized = true;
    state.stopped = false; // Seized tracee is NOT stopped.
    table.slots[idx].state = Some(state);
    table.count += 1;
    Ok(())
}

/// Handle `PTRACE_DETACH`: detach from the tracee and resume it.
///
/// `signal` is delivered to the tracee on resume (0 = no signal).
pub fn ptrace_detach(table: &mut PtraceTable, tracee_pid: u32, signal: i32) -> Result<()> {
    validate_pid(tracee_pid)?;

    if signal < 0 || signal > 64 {
        return Err(Error::InvalidArgument);
    }

    let idx = table.find_tracee(tracee_pid).ok_or(Error::NotFound)?;
    table.slots[idx].state = None;
    table.count = table.count.saturating_sub(1);
    Ok(())
}

/// Handle `PTRACE_PEEKTEXT` / `PTRACE_PEEKDATA`: read a word from tracee.
///
/// `addr` must be 8-byte aligned.  Returns the word value.
pub fn ptrace_peek(table: &PtraceTable, tracee_pid: u32, addr: u64) -> Result<u64> {
    validate_pid(tracee_pid)?;
    validate_aligned(addr)?;

    let state = table.get_state(tracee_pid)?;
    if !state.stopped {
        return Err(Error::Busy);
    }

    // Stub: real implementation copies from tracee's address space.
    let _ = addr;
    Ok(0)
}

/// Handle `PTRACE_POKETEXT` / `PTRACE_POKEDATA`: write a word to tracee.
///
/// `addr` must be 8-byte aligned.
pub fn ptrace_poke(table: &mut PtraceTable, tracee_pid: u32, addr: u64, data: u64) -> Result<()> {
    validate_pid(tracee_pid)?;
    validate_aligned(addr)?;

    let state = table.get_state_mut(tracee_pid)?;
    if !state.stopped {
        return Err(Error::Busy);
    }

    // Stub: real implementation writes to tracee's address space.
    let _ = (addr, data);
    Ok(())
}

/// Handle `PTRACE_GETREGS`: copy general-purpose registers from tracee.
pub fn ptrace_getregs(table: &PtraceTable, tracee_pid: u32) -> Result<UserRegs> {
    validate_pid(tracee_pid)?;

    let state = table.get_state(tracee_pid)?;
    if !state.stopped {
        return Err(Error::Busy);
    }
    Ok(state.regs)
}

/// Handle `PTRACE_SETREGS`: overwrite general-purpose registers in tracee.
pub fn ptrace_setregs(table: &mut PtraceTable, tracee_pid: u32, regs: &UserRegs) -> Result<()> {
    validate_pid(tracee_pid)?;

    let state = table.get_state_mut(tracee_pid)?;
    if !state.stopped {
        return Err(Error::Busy);
    }
    state.regs = *regs;
    Ok(())
}

/// Handle `PTRACE_GETFPREGS`: copy floating-point register state from tracee.
pub fn ptrace_getfpregs(table: &PtraceTable, tracee_pid: u32) -> Result<[u8; 64]> {
    validate_pid(tracee_pid)?;

    let state = table.get_state(tracee_pid)?;
    if !state.stopped {
        return Err(Error::Busy);
    }
    Ok(state.fpregs)
}

/// Handle `PTRACE_SETFPREGS`: overwrite floating-point state in tracee.
pub fn ptrace_setfpregs(table: &mut PtraceTable, tracee_pid: u32, fpregs: &[u8; 64]) -> Result<()> {
    validate_pid(tracee_pid)?;

    let state = table.get_state_mut(tracee_pid)?;
    if !state.stopped {
        return Err(Error::Busy);
    }
    state.fpregs.copy_from_slice(fpregs);
    Ok(())
}

/// Handle `PTRACE_CONT`: resume the stopped tracee.
///
/// `signal` is delivered to the tracee (0 = suppress pending signal).
pub fn ptrace_cont(table: &mut PtraceTable, tracee_pid: u32, signal: i32) -> Result<()> {
    validate_pid(tracee_pid)?;

    if signal < 0 || signal > 64 {
        return Err(Error::InvalidArgument);
    }

    let state = table.get_state_mut(tracee_pid)?;
    state.stopped = false;
    state.pending_signal = signal;
    Ok(())
}

/// Handle `PTRACE_SINGLESTEP`: resume the tracee for one instruction.
///
/// `signal` is delivered to the tracee (0 = suppress).
pub fn ptrace_singlestep(table: &mut PtraceTable, tracee_pid: u32, signal: i32) -> Result<()> {
    validate_pid(tracee_pid)?;

    if signal < 0 || signal > 64 {
        return Err(Error::InvalidArgument);
    }

    let state = table.get_state_mut(tracee_pid)?;
    state.stopped = false;
    state.pending_signal = signal;
    // Stub: real implementation sets the TF (trap flag) in RFLAGS.
    Ok(())
}

/// Handle `PTRACE_SETOPTIONS`: update ptrace option flags.
pub fn ptrace_setoptions(table: &mut PtraceTable, tracee_pid: u32, options: u64) -> Result<()> {
    validate_pid(tracee_pid)?;

    if options > u32::MAX as u64 {
        return Err(Error::InvalidArgument);
    }

    let opts = PtraceOptions::from_u32(options as u32)?;
    let state = table.get_state_mut(tracee_pid)?;
    state.options = opts;
    Ok(())
}

/// Handle `PTRACE_GETEVENTMSG`: retrieve event message from last ptrace stop.
pub fn ptrace_geteventmsg(table: &PtraceTable, tracee_pid: u32) -> Result<u64> {
    validate_pid(tracee_pid)?;

    let state = table.get_state(tracee_pid)?;
    Ok(state.event_msg)
}

/// Handle `PTRACE_GETSIGINFO`: retrieve `siginfo_t` from the tracee.
pub fn ptrace_getsiginfo(table: &PtraceTable, tracee_pid: u32) -> Result<SigInfo> {
    validate_pid(tracee_pid)?;

    let state = table.get_state(tracee_pid)?;
    if !state.stopped {
        return Err(Error::Busy);
    }
    Ok(state.siginfo)
}

/// Handle `PTRACE_SETSIGINFO`: inject `siginfo_t` into the tracee.
pub fn ptrace_setsiginfo(table: &mut PtraceTable, tracee_pid: u32, info: &SigInfo) -> Result<()> {
    validate_pid(tracee_pid)?;

    let state = table.get_state_mut(tracee_pid)?;
    if !state.stopped {
        return Err(Error::Busy);
    }
    state.siginfo = *info;
    Ok(())
}

/// Handle `PTRACE_INTERRUPT`: interrupt a seized tracee.
pub fn ptrace_interrupt(table: &mut PtraceTable, tracee_pid: u32) -> Result<()> {
    validate_pid(tracee_pid)?;

    let state = table.get_state_mut(tracee_pid)?;
    if !state.seized {
        return Err(Error::InvalidArgument);
    }
    state.stopped = true;
    Ok(())
}

/// Handle `PTRACE_LISTEN`: put a seized tracee into listen mode.
pub fn ptrace_listen(table: &mut PtraceTable, tracee_pid: u32) -> Result<()> {
    validate_pid(tracee_pid)?;

    let state = table.get_state_mut(tracee_pid)?;
    if !state.seized {
        return Err(Error::InvalidArgument);
    }
    if !state.stopped {
        return Err(Error::Busy);
    }
    state.listening = true;
    state.stopped = false;
    Ok(())
}

// ---------------------------------------------------------------------------
// Main dispatcher
// ---------------------------------------------------------------------------

/// `ptrace(2)` — process trace syscall dispatcher.
///
/// Validates the request code and routes to the appropriate handler.
/// `pid` identifies the target tracee; `addr` and `data` carry
/// request-specific parameters.
///
/// Returns:
/// - `0` on success for most requests
/// - The peeked word for `PEEKTEXT`/`PEEKDATA`/`PEEKUSER`
/// - The event message for `GETEVENTMSG`
///
/// # POSIX Reference
///
/// POSIX.1-2024 does not fully specify ptrace; this follows the
/// Linux ptrace(2) extended interface.
pub fn do_ptrace(
    table: &mut PtraceTable,
    caller_pid: u32,
    request_raw: u64,
    pid: u32,
    addr: u64,
    data: u64,
) -> Result<u64> {
    let request = PtraceRequest::from_u64(request_raw).ok_or(Error::InvalidArgument)?;

    match request {
        PtraceRequest::Traceme => {
            // Mark the caller as wanting to be traced by its parent.
            // Stub: in a real kernel we set PT_TRACED in task_struct.
            let _ = caller_pid;
            Ok(0)
        }

        PtraceRequest::Attach => {
            ptrace_attach(table, caller_pid, pid)?;
            Ok(0)
        }

        PtraceRequest::Seize => {
            ptrace_seize(table, caller_pid, pid, data as u32)?;
            Ok(0)
        }

        PtraceRequest::Detach => {
            ptrace_detach(table, pid, data as i32)?;
            Ok(0)
        }

        PtraceRequest::Peektext | PtraceRequest::Peekdata | PtraceRequest::Peekuser => {
            ptrace_peek(table, pid, addr)
        }

        PtraceRequest::Poketext | PtraceRequest::Pokedata | PtraceRequest::Pokeuser => {
            ptrace_poke(table, pid, addr, data)?;
            Ok(0)
        }

        PtraceRequest::Getregs => {
            let regs = ptrace_getregs(table, pid)?;
            // Stub: in a real syscall, copy_to_user writes to addr.
            let _ = (regs, addr);
            Ok(0)
        }

        PtraceRequest::Setregs => {
            // Stub: real implementation reads UserRegs from user addr.
            let regs = UserRegs::new();
            ptrace_setregs(table, pid, &regs)?;
            Ok(0)
        }

        PtraceRequest::Getfpregs => {
            let fpregs = ptrace_getfpregs(table, pid)?;
            let _ = (fpregs, addr);
            Ok(0)
        }

        PtraceRequest::Setfpregs => {
            let fpregs = [0u8; 64];
            ptrace_setfpregs(table, pid, &fpregs)?;
            Ok(0)
        }

        PtraceRequest::Cont | PtraceRequest::Syscall => {
            ptrace_cont(table, pid, data as i32)?;
            Ok(0)
        }

        PtraceRequest::Singlestep => {
            ptrace_singlestep(table, pid, data as i32)?;
            Ok(0)
        }

        PtraceRequest::Kill => {
            ptrace_detach(table, pid, 9)?; // SIGKILL = 9
            Ok(0)
        }

        PtraceRequest::Setoptions => {
            ptrace_setoptions(table, pid, data)?;
            Ok(0)
        }

        PtraceRequest::Geteventmsg => {
            let msg = ptrace_geteventmsg(table, pid)?;
            // Stub: real implementation writes msg to *addr.
            let _ = addr;
            Ok(msg)
        }

        PtraceRequest::Getsiginfo => {
            let info = ptrace_getsiginfo(table, pid)?;
            let _ = (info, addr);
            Ok(0)
        }

        PtraceRequest::Setsiginfo => {
            let info = SigInfo::default();
            ptrace_setsiginfo(table, pid, &info)?;
            Ok(0)
        }

        PtraceRequest::Interrupt => {
            ptrace_interrupt(table, pid)?;
            Ok(0)
        }

        PtraceRequest::Listen => {
            ptrace_listen(table, pid)?;
            Ok(0)
        }
    }
}
