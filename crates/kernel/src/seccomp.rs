// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Secure computing (seccomp) BPF syscall filter.
//!
//! Seccomp restricts the system calls a process may invoke.
//! Two modes are supported:
//!
//! - **Strict mode** (`SECCOMP_MODE_STRICT`): only `read`, `write`,
//!   `exit`, and `sigreturn` are permitted. Any other syscall
//!   kills the thread.
//! - **Filter mode** (`SECCOMP_MODE_FILTER`): a classic BPF program
//!   inspects each syscall and returns an action (allow, kill,
//!   errno, trap, log).
//!
//! Filters are stackable: up to [`MAX_FILTERS`] programs can be
//! chained. When multiple filters are installed, all are evaluated
//! and the most restrictive action wins.
//!
//! Reference: Linux `kernel/seccomp.c`, `include/uapi/linux/seccomp.h`.

use oncrix_lib::{Error, Result};

// ── Mode constants ──────────────────────────────────────────────

/// Seccomp is disabled; all syscalls are permitted.
pub const SECCOMP_MODE_DISABLED: u32 = 0;

/// Strict mode: only `read`, `write`, `exit`, and `sigreturn`.
pub const SECCOMP_MODE_STRICT: u32 = 1;

/// Filter mode: syscalls are evaluated by BPF programs.
pub const SECCOMP_MODE_FILTER: u32 = 2;

// ── Action constants ────────────────────────────────────────────

/// Kill the entire process.
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

/// Kill the offending thread.
pub const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;

/// Send `SIGSYS` to the thread.
pub const SECCOMP_RET_TRAP: u32 = 0x0003_0000;

/// Return an errno to user space (low 16 bits = errno value).
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;

/// Notify a tracing process (ptrace-based).
pub const SECCOMP_RET_TRACE: u32 = 0x7FF0_0000;

/// Allow the syscall but log it.
pub const SECCOMP_RET_LOG: u32 = 0x7FFC_0000;

/// Allow the syscall unconditionally.
pub const SECCOMP_RET_ALLOW: u32 = 0x7FFF_0000;

/// Mask for the full action field (upper 16 bits).
pub const SECCOMP_RET_ACTION_FULL: u32 = 0xFFFF_0000;

/// Mask for the data field (lower 16 bits).
pub const SECCOMP_RET_DATA: u32 = 0x0000_FFFF;

// ── Limits ──────────────────────────────────────────────────────

/// Maximum number of BPF instructions per filter program.
pub const MAX_INSNS: usize = 64;

/// Maximum number of chained filter programs per process.
pub const MAX_FILTERS: usize = 8;

// ── Strict-mode allowed syscall numbers (x86_64 ABI) ────────────

/// `read(2)` syscall number (x86_64).
const STRICT_READ: u64 = 0;
/// `write(2)` syscall number (x86_64).
const STRICT_WRITE: u64 = 1;
/// `exit(2)` syscall number (x86_64).
const STRICT_EXIT: u64 = 60;
/// `exit_group(2)` syscall number (x86_64).
const STRICT_EXIT_GROUP: u64 = 231;
/// `rt_sigreturn(2)` syscall number (x86_64).
const STRICT_SIGRETURN: u64 = 15;

// ── BPF instruction ─────────────────────────────────────────────

/// A single classic BPF instruction.
///
/// This matches the `struct sock_filter` layout used by the Linux
/// seccomp interface. The fields are:
/// - `code`: operation code (load, store, jump, return, etc.)
/// - `jt`: jump-true offset (for conditional jumps)
/// - `jf`: jump-false offset (for conditional jumps)
/// - `k`: generic multi-use operand
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BpfInsn {
    /// BPF opcode.
    pub code: u16,
    /// Jump offset on true condition.
    pub jt: u8,
    /// Jump offset on false condition.
    pub jf: u8,
    /// Multi-use operand (immediate value, offset, etc.).
    pub k: u32,
}

impl BpfInsn {
    /// Create a new BPF instruction.
    pub const fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        Self { code, jt, jf, k }
    }
}

// ── BPF opcode classes and operations ───────────────────────────

/// BPF opcode class: load word into accumulator.
const BPF_LD: u16 = 0x00;
/// BPF opcode class: jump.
const BPF_JMP: u16 = 0x05;
/// BPF opcode class: return.
const BPF_RET: u16 = 0x06;
/// BPF addressing mode: absolute (offset in `k`).
const BPF_ABS: u16 = 0x20;
/// BPF operand source: immediate constant (`k`).
const BPF_K: u16 = 0x00;
/// BPF jump operation: equals.
const BPF_JEQ: u16 = 0x10;
/// BPF size: 32-bit word.
const BPF_W: u16 = 0x00;

// ── Seccomp data ────────────────────────────────────────────────

/// Data structure passed to BPF programs for evaluation.
///
/// This mirrors `struct seccomp_data` from the Linux kernel.
/// BPF load instructions reference fields by byte offset into
/// this structure.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SeccompData {
    /// System call number.
    pub nr: i32,
    /// Architecture identifier (e.g., `AUDIT_ARCH_X86_64`).
    pub arch: u32,
    /// Instruction pointer at the time of the syscall.
    pub instruction_pointer: u64,
    /// Syscall arguments (up to 6).
    pub args: [u64; 6],
}

impl SeccompData {
    /// Create a new `SeccompData` from a syscall number and arch.
    ///
    /// The instruction pointer and arguments are zeroed; callers
    /// should populate them from the actual register state.
    pub const fn new(nr: i32, arch: u32) -> Self {
        Self {
            nr,
            arch,
            instruction_pointer: 0,
            args: [0u64; 6],
        }
    }

    /// Read a 32-bit word at `offset` bytes into the structure.
    ///
    /// This emulates the BPF `LD ABS` instruction against the
    /// seccomp data. Returns `None` if the offset is out of bounds
    /// or mis-aligned.
    fn load_word(&self, offset: u32) -> Option<u32> {
        // Ensure 4-byte alignment.
        if offset & 3 != 0 {
            return None;
        }
        match offset {
            // nr: offset 0, 4 bytes
            0 => Some(self.nr as u32),
            // arch: offset 4, 4 bytes
            4 => Some(self.arch),
            // instruction_pointer: offset 8, 8 bytes (two words)
            8 => Some(self.instruction_pointer as u32),
            12 => Some((self.instruction_pointer >> 32) as u32),
            // args[0..6]: offset 16..64 (each 8 bytes, two words)
            16..=60 => {
                let arg_byte = offset.saturating_sub(16);
                let arg_idx = (arg_byte / 8) as usize;
                if arg_idx >= 6 {
                    return None;
                }
                let val = self.args[arg_idx];
                if arg_byte % 8 == 0 {
                    Some(val as u32)
                } else {
                    Some((val >> 32) as u32)
                }
            }
            _ => None,
        }
    }
}

// ── Seccomp action (kernel-side result) ─────────────────────────

/// Result of evaluating seccomp filters on a syscall.
///
/// This is the kernel-internal representation of a seccomp
/// decision. The syscall dispatcher inspects this to decide
/// whether to proceed, return an error, or terminate the thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompAction {
    /// Allow the syscall to proceed normally.
    Allow,
    /// Kill the thread (or process).
    Kill,
    /// Return an error to user space (value = errno).
    Errno(u16),
    /// Send `SIGSYS` to the thread.
    Trap,
    /// Allow the syscall but log the event.
    Log,
}

impl SeccompAction {
    /// Convert a raw BPF return value to a `SeccompAction`.
    fn from_ret(ret: u32) -> Self {
        let action = ret & SECCOMP_RET_ACTION_FULL;
        let data = (ret & SECCOMP_RET_DATA) as u16;
        match action {
            SECCOMP_RET_ALLOW => Self::Allow,
            SECCOMP_RET_LOG => Self::Log,
            SECCOMP_RET_ERRNO => Self::Errno(data),
            SECCOMP_RET_TRAP => Self::Trap,
            SECCOMP_RET_KILL_PROCESS | SECCOMP_RET_KILL_THREAD => Self::Kill,
            SECCOMP_RET_TRACE => {
                // Tracing is not yet supported; treat as allow.
                Self::Allow
            }
            _ => Self::Kill,
        }
    }

    /// Return the priority of this action (lower = more restrictive).
    ///
    /// When multiple filters are evaluated, the most restrictive
    /// action (lowest priority value) wins.
    fn priority(self) -> u32 {
        match self {
            Self::Kill => 0,
            Self::Trap => 1,
            Self::Errno(_) => 2,
            Self::Log => 3,
            Self::Allow => 4,
        }
    }
}

// ── Single filter program ───────────────────────────────────────

/// A single seccomp BPF filter program.
///
/// Contains up to [`MAX_INSNS`] BPF instructions. The program is
/// evaluated against a [`SeccompData`] structure for each syscall.
#[derive(Debug, Clone)]
pub struct SeccompFilter {
    /// BPF instruction buffer.
    instructions: [BpfInsn; MAX_INSNS],
    /// Number of valid instructions (must be 1..=[`MAX_INSNS`]).
    len: usize,
}

impl SeccompFilter {
    /// Create an empty filter (zero instructions).
    const fn empty() -> Self {
        Self {
            instructions: [BpfInsn {
                code: 0,
                jt: 0,
                jf: 0,
                k: 0,
            }; MAX_INSNS],
            len: 0,
        }
    }

    /// Initialize a filter from a slice of BPF instructions.
    ///
    /// Returns `InvalidArgument` if `prog` is empty or exceeds
    /// [`MAX_INSNS`] instructions.
    fn from_prog(prog: &[BpfInsn]) -> Result<Self> {
        if prog.is_empty() || prog.len() > MAX_INSNS {
            return Err(Error::InvalidArgument);
        }
        let mut filter = Self::empty();
        let mut i = 0;
        while i < prog.len() {
            filter.instructions[i] = prog[i];
            i = i.saturating_add(1);
        }
        filter.len = prog.len();
        Ok(filter)
    }

    /// Execute this BPF program against `data`.
    ///
    /// Returns the raw 32-bit return value. If the program is
    /// malformed (out-of-bounds jump, invalid load offset), the
    /// filter defaults to `SECCOMP_RET_KILL_THREAD`.
    fn execute(&self, data: &SeccompData) -> u32 {
        if self.len == 0 {
            return SECCOMP_RET_KILL_THREAD;
        }

        let mut accumulator: u32 = 0;
        let mut pc: usize = 0;

        while pc < self.len {
            let insn = self.instructions[pc];
            let class = insn.code & 0x07;

            match class {
                // BPF_LD: load into accumulator
                cls if cls == BPF_LD => {
                    let mode = insn.code & 0xE0;
                    let size = insn.code & 0x18;
                    if mode == BPF_ABS && size == BPF_W {
                        match data.load_word(insn.k) {
                            Some(val) => accumulator = val,
                            None => {
                                return SECCOMP_RET_KILL_THREAD;
                            }
                        }
                    } else {
                        // Unsupported load mode for seccomp.
                        return SECCOMP_RET_KILL_THREAD;
                    }
                }
                // BPF_JMP: conditional/unconditional jump
                cls if cls == BPF_JMP => {
                    let op = insn.code & 0xF0;
                    match op {
                        // JA (unconditional jump)
                        0x00 => {
                            let target = pc.saturating_add(1).saturating_add(insn.k as usize);
                            if target >= self.len {
                                return SECCOMP_RET_KILL_THREAD;
                            }
                            pc = target;
                            continue;
                        }
                        // JEQ
                        op_code if op_code == BPF_JEQ => {
                            let src = insn.code & 0x08;
                            let cmp_val = if src == BPF_K {
                                insn.k
                            } else {
                                // BPF_X (index register) not
                                // supported in seccomp.
                                return SECCOMP_RET_KILL_THREAD;
                            };
                            let offset = if accumulator == cmp_val {
                                insn.jt
                            } else {
                                insn.jf
                            };
                            let target = pc.saturating_add(1).saturating_add(offset as usize);
                            if target >= self.len {
                                return SECCOMP_RET_KILL_THREAD;
                            }
                            pc = target;
                            continue;
                        }
                        // JGT
                        0x20 => {
                            let offset = if accumulator > insn.k {
                                insn.jt
                            } else {
                                insn.jf
                            };
                            let target = pc.saturating_add(1).saturating_add(offset as usize);
                            if target >= self.len {
                                return SECCOMP_RET_KILL_THREAD;
                            }
                            pc = target;
                            continue;
                        }
                        // JGE
                        0x30 => {
                            let offset = if accumulator >= insn.k {
                                insn.jt
                            } else {
                                insn.jf
                            };
                            let target = pc.saturating_add(1).saturating_add(offset as usize);
                            if target >= self.len {
                                return SECCOMP_RET_KILL_THREAD;
                            }
                            pc = target;
                            continue;
                        }
                        // JSET (bitwise AND test)
                        0x40 => {
                            let offset = if accumulator & insn.k != 0 {
                                insn.jt
                            } else {
                                insn.jf
                            };
                            let target = pc.saturating_add(1).saturating_add(offset as usize);
                            if target >= self.len {
                                return SECCOMP_RET_KILL_THREAD;
                            }
                            pc = target;
                            continue;
                        }
                        _ => {
                            return SECCOMP_RET_KILL_THREAD;
                        }
                    }
                }
                // BPF_RET: return a value
                cls if cls == BPF_RET => {
                    let src = insn.code & 0x18;
                    if src == BPF_K {
                        return insn.k;
                    }
                    // BPF_A: return accumulator
                    if src == 0x10 {
                        return accumulator;
                    }
                    return SECCOMP_RET_KILL_THREAD;
                }
                _ => {
                    // Unsupported instruction class.
                    return SECCOMP_RET_KILL_THREAD;
                }
            }

            pc = pc.saturating_add(1);
        }

        // Fell off the end of the program without returning.
        SECCOMP_RET_KILL_THREAD
    }
}

// ── Per-process seccomp state ───────────────────────────────────

/// Per-process seccomp state.
///
/// Embedded in the process control block (PCB). Tracks the current
/// seccomp mode and up to [`MAX_FILTERS`] chained BPF filter
/// programs.
#[derive(Debug, Clone)]
pub struct SeccompState {
    /// Current seccomp mode.
    mode: u32,
    /// Installed filter programs (evaluated in order).
    filters: [Option<SeccompFilter>; MAX_FILTERS],
    /// Number of installed filters.
    filter_count: usize,
}

impl Default for SeccompState {
    fn default() -> Self {
        Self::new()
    }
}

impl SeccompState {
    /// Create a new `SeccompState` with seccomp disabled.
    pub const fn new() -> Self {
        // `const fn` cannot use `[None; N]` for non-Copy types,
        // so we spell it out.
        Self {
            mode: SECCOMP_MODE_DISABLED,
            filters: [None, None, None, None, None, None, None, None],
            filter_count: 0,
        }
    }

    /// Get the current seccomp mode.
    pub fn mode(&self) -> u32 {
        self.mode
    }

    /// Get the number of installed filters.
    pub fn filter_count(&self) -> usize {
        self.filter_count
    }

    /// Enable strict seccomp mode.
    ///
    /// After this call, only `read(2)`, `write(2)`, `exit(2)`,
    /// `exit_group(2)`, and `rt_sigreturn(2)` are permitted.
    /// Any other syscall causes the thread to be killed.
    ///
    /// Returns `InvalidArgument` if seccomp is already in filter
    /// mode (downgrade from filter to strict is forbidden).
    pub fn set_strict(&mut self) -> Result<()> {
        if self.mode == SECCOMP_MODE_FILTER {
            return Err(Error::InvalidArgument);
        }
        self.mode = SECCOMP_MODE_STRICT;
        Ok(())
    }

    /// Install a BPF filter program.
    ///
    /// The filter is appended to the chain of existing filters.
    /// The seccomp mode is set to `SECCOMP_MODE_FILTER` (or
    /// remains so if already set).
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `prog` is empty, exceeds
    ///   [`MAX_INSNS`], or would exceed [`MAX_FILTERS`] total
    ///   filters.
    /// - `InvalidArgument` if seccomp is in strict mode
    ///   (strict-to-filter transition is forbidden).
    pub fn add_filter(&mut self, prog: &[BpfInsn]) -> Result<()> {
        if self.mode == SECCOMP_MODE_STRICT {
            return Err(Error::InvalidArgument);
        }
        if self.filter_count >= MAX_FILTERS {
            return Err(Error::InvalidArgument);
        }
        let filter = SeccompFilter::from_prog(prog)?;
        self.filters[self.filter_count] = Some(filter);
        self.filter_count = self.filter_count.saturating_add(1);
        self.mode = SECCOMP_MODE_FILTER;
        Ok(())
    }

    /// Evaluate all seccomp filters for a syscall.
    ///
    /// In strict mode, only a small set of syscalls is allowed;
    /// everything else returns [`SeccompAction::Kill`].
    ///
    /// In filter mode, all installed BPF programs are evaluated
    /// against a [`SeccompData`] constructed from `syscall_nr` and
    /// `arch`. The most restrictive action (lowest priority) wins.
    ///
    /// If seccomp is disabled, returns [`SeccompAction::Allow`].
    pub fn check_syscall(&self, syscall_nr: u64, arch: u32) -> SeccompAction {
        match self.mode {
            SECCOMP_MODE_DISABLED => SeccompAction::Allow,
            SECCOMP_MODE_STRICT => Self::check_strict(syscall_nr),
            SECCOMP_MODE_FILTER => self.check_filters(syscall_nr, arch),
            _ => SeccompAction::Kill,
        }
    }

    /// Check a syscall against the strict-mode allow list.
    fn check_strict(syscall_nr: u64) -> SeccompAction {
        match syscall_nr {
            STRICT_READ | STRICT_WRITE | STRICT_EXIT | STRICT_EXIT_GROUP | STRICT_SIGRETURN => {
                SeccompAction::Allow
            }
            _ => SeccompAction::Kill,
        }
    }

    /// Evaluate all installed BPF filters and return the most
    /// restrictive action.
    fn check_filters(&self, syscall_nr: u64, arch: u32) -> SeccompAction {
        // Truncate syscall_nr to i32 (matching seccomp_data.nr).
        let nr = syscall_nr as i32;
        let data = SeccompData::new(nr, arch);

        let mut result = SeccompAction::Allow;

        let mut i: usize = 0;
        while i < self.filter_count {
            if let Some(ref filter) = self.filters[i] {
                let ret = filter.execute(&data);
                let action = SeccompAction::from_ret(ret);
                // Keep the most restrictive action.
                if action.priority() < result.priority() {
                    result = action;
                }
                // Short-circuit on Kill: nothing is more
                // restrictive.
                if matches!(result, SeccompAction::Kill) {
                    return result;
                }
            }
            i = i.saturating_add(1);
        }

        result
    }
}

// ── seccomp(2) operation constants ──────────────────────────────

/// `seccomp(SECCOMP_SET_MODE_STRICT, ...)`.
pub const SECCOMP_SET_MODE_STRICT: u64 = 0;

/// `seccomp(SECCOMP_SET_MODE_FILTER, ...)`.
pub const SECCOMP_SET_MODE_FILTER: u64 = 1;

/// `seccomp(SECCOMP_GET_ACTION_AVAIL, ...)`.
pub const SECCOMP_GET_ACTION_AVAIL: u64 = 2;

// ── Kernel-side dispatch ────────────────────────────────────────

/// Dispatch a `seccomp(2)` syscall.
///
/// Arguments:
/// - `state`: mutable reference to the process's seccomp state
/// - `operation`: one of `SECCOMP_SET_MODE_STRICT`,
///   `SECCOMP_SET_MODE_FILTER`, or `SECCOMP_GET_ACTION_AVAIL`
/// - `flags`: operation-specific flags (must be 0 for now)
/// - `args_ptr`: user pointer to operation-specific data
///
/// Returns `0` on success, or an error.
///
/// Stub: in a full implementation, `SECCOMP_SET_MODE_FILTER`
/// would `copy_from_user` the BPF program from `args_ptr`.
pub fn do_seccomp(
    state: &mut SeccompState,
    operation: u64,
    flags: u64,
    _args_ptr: u64,
) -> Result<u64> {
    // No flags are supported yet.
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }

    match operation {
        SECCOMP_SET_MODE_STRICT => {
            state.set_strict()?;
            Ok(0)
        }
        SECCOMP_SET_MODE_FILTER => {
            // Stub: would copy_from_user the sock_fprog struct
            // at `args_ptr`, validate the BPF program, then call
            // state.add_filter(&insns).
            //
            // For now, reject because we cannot read user memory.
            Err(Error::NotImplemented)
        }
        SECCOMP_GET_ACTION_AVAIL => {
            // Stub: would copy_from_user a u32 action value from
            // `args_ptr` and check if it is supported.
            Err(Error::NotImplemented)
        }
        _ => Err(Error::InvalidArgument),
    }
}
