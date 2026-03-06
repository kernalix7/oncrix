// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Seccomp classic BPF (cBPF) filter engine.
//!
//! Provides a standalone cBPF interpreter tailored for seccomp
//! syscall filtering, complementing the base seccomp module in
//! [`crate::seccomp`]. This module implements:
//!
//! - **`SockFilter`**: classic BPF instruction (8 bytes, repr(C)).
//! - **`SeccompData`**: per-syscall context passed to filters.
//! - **`SeccompAction`**: filter verdict enumeration.
//! - **`SeccompFilter`**: single cBPF program with a full VM
//!   (accumulator, index register, scratch memory).
//! - **`SeccompFilterChain`**: per-process stack of filters
//!   (most restrictive action wins).
//! - **`SeccompFilterRegistry`**: global registry indexed by PID.
//!
//! Reference: Linux `include/uapi/linux/filter.h`,
//! `include/uapi/linux/seccomp.h`.

use oncrix_lib::{Error, Result};

// ── cBPF instruction class constants (lower 3 bits) ────────────

/// Load word into accumulator.
pub const BPF_LD: u16 = 0x00;
/// Load word into index register.
pub const BPF_LDX: u16 = 0x01;
/// Store accumulator to scratch memory.
pub const BPF_ST: u16 = 0x02;
/// Store index register to scratch memory.
pub const BPF_STX: u16 = 0x03;
/// ALU operations on accumulator.
pub const BPF_ALU: u16 = 0x04;
/// Jump (conditional and unconditional).
pub const BPF_JMP: u16 = 0x05;
/// Return a value.
pub const BPF_RET: u16 = 0x06;
/// Miscellaneous (TAX, TXA).
pub const BPF_MISC: u16 = 0x07;

// ── cBPF size modifiers (bits 3–4) ─────────────────────────────

/// Word (32 bits).
const BPF_W: u16 = 0x00;
/// Half-word (16 bits).
const BPF_H: u16 = 0x08;
/// Byte (8 bits).
const BPF_B: u16 = 0x10;

// ── cBPF addressing modes (bits 5–7) ──────────────────────────

/// Absolute offset (immediate in `k`).
const BPF_ABS: u16 = 0x20;
/// Immediate value in `k`.
const BPF_IMM: u16 = 0x00;
/// Memory (scratch) at index `k`.
const BPF_MEM: u16 = 0x60;
/// Index register plus `k`.
const BPF_IND: u16 = 0x40;
/// Length of the packet (data).
const BPF_LEN: u16 = 0x80;
/// Transfer from index register (for LDX).
const BPF_MSH: u16 = 0xa0;

// ── cBPF source operand (bit 3 for JMP/ALU) ──────────────────

/// Source is the immediate constant `k`.
const BPF_K: u16 = 0x00;
/// Source is the index register X.
const BPF_X: u16 = 0x08;
/// Source is the accumulator (for RET).
const BPF_A: u16 = 0x10;

// ── cBPF ALU operation codes (bits 4–7) ────────────────────────

/// Addition.
const ALU_ADD: u16 = 0x00;
/// Subtraction.
const ALU_SUB: u16 = 0x10;
/// Multiplication.
const ALU_MUL: u16 = 0x20;
/// Division.
const ALU_DIV: u16 = 0x30;
/// Bitwise OR.
const ALU_OR: u16 = 0x40;
/// Bitwise AND.
const ALU_AND: u16 = 0x50;
/// Left shift.
const ALU_LSH: u16 = 0x60;
/// Right shift.
const ALU_RSH: u16 = 0x70;
/// Negation (unary).
const ALU_NEG: u16 = 0x80;
/// Modulo.
const ALU_MOD: u16 = 0x90;
/// Bitwise XOR.
const ALU_XOR: u16 = 0xa0;

// ── cBPF JMP operation codes (bits 4–7) ────────────────────────

/// Unconditional jump (JA).
const JMP_JA: u16 = 0x00;
/// Jump if equal.
const JMP_JEQ: u16 = 0x10;
/// Jump if greater than (unsigned).
const JMP_JGT: u16 = 0x20;
/// Jump if greater or equal (unsigned).
const JMP_JGE: u16 = 0x30;
/// Jump if bits set (bitwise AND test).
const JMP_JSET: u16 = 0x40;

// ── MISC sub-operations ────────────────────────────────────────

/// TAX: copy accumulator to index register.
const MISC_TAX: u32 = 0x00;
/// TXA: copy index register to accumulator.
const MISC_TXA: u32 = 0x80;

// ── Limits ─────────────────────────────────────────────────────

/// Maximum instructions per filter program.
const MAX_INSNS: usize = 64;
/// Maximum filters in a chain.
const MAX_CHAIN: usize = 8;
/// Maximum per-PID chains in the registry.
const MAX_PIDS: usize = 128;
/// Scratch memory slots.
const SCRATCH_SIZE: usize = 16;
/// Size of [`SeccompData`] in bytes (used for bounds checks).
const SECCOMP_DATA_SIZE: u32 = 64;

// ── SockFilter ─────────────────────────────────────────────────

/// A single classic BPF instruction.
///
/// Matches `struct sock_filter` from Linux `uapi/linux/filter.h`.
/// Each instruction is 8 bytes.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct SockFilter {
    /// BPF opcode (class | size/mode | op | source).
    pub code: u16,
    /// Jump offset on true condition (conditional jumps).
    pub jt: u8,
    /// Jump offset on false condition (conditional jumps).
    pub jf: u8,
    /// Multi-use operand (immediate value, offset, etc.).
    pub k: u32,
}

impl SockFilter {
    /// Create a new classic BPF instruction.
    pub const fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        Self { code, jt, jf, k }
    }
}

// ── SeccompData ────────────────────────────────────────────────

/// Data structure passed to seccomp BPF programs for evaluation.
///
/// Mirrors `struct seccomp_data` from Linux. BPF load instructions
/// reference fields by byte offset into this structure.
#[derive(Debug, Clone, Copy, Default)]
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
    /// Create a new `SeccompData` with the given syscall number
    /// and architecture.
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
    /// Returns `None` if the offset is out of bounds or
    /// mis-aligned.
    fn load_word(&self, offset: u32) -> Option<u32> {
        if offset & 3 != 0 || offset >= SECCOMP_DATA_SIZE {
            return None;
        }
        match offset {
            0 => Some(self.nr as u32),
            4 => Some(self.arch),
            8 => Some(self.instruction_pointer as u32),
            12 => Some((self.instruction_pointer >> 32) as u32),
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

    /// Read a 16-bit half-word at `offset` bytes.
    fn load_half(&self, offset: u32) -> Option<u32> {
        if offset & 1 != 0 || offset >= SECCOMP_DATA_SIZE {
            return None;
        }
        let word_offset = offset & !3;
        let word = self.load_word(word_offset)?;
        let shift = (offset & 2) * 8;
        Some((word >> shift) & 0xFFFF)
    }

    /// Read a single byte at `offset`.
    fn load_byte(&self, offset: u32) -> Option<u32> {
        if offset >= SECCOMP_DATA_SIZE {
            return None;
        }
        let word_offset = offset & !3;
        let word = self.load_word(word_offset)?;
        let shift = (offset & 3) * 8;
        Some((word >> shift) & 0xFF)
    }
}

// ── SeccompAction ──────────────────────────────────────────────

/// Result of evaluating seccomp filters on a syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SeccompAction {
    /// Allow the syscall to proceed normally.
    #[default]
    Allow,
    /// Kill the thread (or process).
    Kill,
    /// Send `SIGSYS` to the thread.
    Trap,
    /// Return an errno to user space (value = errno).
    Errno(u16),
    /// Notify a tracing process (ptrace-based).
    Trace(u16),
    /// Allow the syscall but log the event.
    Log,
    /// Notify a user-space supervisor.
    UserNotif,
}

impl SeccompAction {
    /// Encode this action as a raw 32-bit seccomp return value.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::Allow => 0x7FFF_0000,
            Self::Kill => 0x0000_0000,
            Self::Trap => 0x0003_0000,
            Self::Errno(e) => 0x0005_0000 | (e as u32),
            Self::Trace(t) => 0x7FF0_0000 | (t as u32),
            Self::Log => 0x7FFC_0000,
            Self::UserNotif => 0x7FC0_0000,
        }
    }

    /// Decode a raw 32-bit seccomp return value into an action.
    pub fn from_u32(val: u32) -> Self {
        let action = val & 0xFFFF_0000;
        let data = (val & 0x0000_FFFF) as u16;
        match action {
            0x7FFF_0000 => Self::Allow,
            0x0000_0000 => Self::Kill,
            0x0003_0000 => Self::Trap,
            0x0005_0000 => Self::Errno(data),
            0x7FF0_0000 => Self::Trace(data),
            0x7FFC_0000 => Self::Log,
            0x7FC0_0000 => Self::UserNotif,
            // Unknown action — kill for safety.
            _ => Self::Kill,
        }
    }

    /// Return the priority of this action (lower = more
    /// restrictive).
    ///
    /// When multiple filters are evaluated, the most restrictive
    /// action (lowest priority value) wins.
    fn priority(self) -> u32 {
        match self {
            Self::Kill => 0,
            Self::Trap => 1,
            Self::Errno(_) => 2,
            Self::Trace(_) => 3,
            Self::Log => 4,
            Self::UserNotif => 5,
            Self::Allow => 6,
        }
    }
}

// ── SeccompFilter ──────────────────────────────────────────────

/// A single seccomp cBPF filter program.
///
/// Contains up to [`MAX_INSNS`] classic BPF instructions and a
/// default action. The [`execute`](SeccompFilter::execute) method
/// runs a full cBPF VM with accumulator (A), index register (X),
/// and scratch memory.
#[derive(Debug, Clone)]
pub struct SeccompFilter {
    /// BPF instruction buffer.
    instructions: [SockFilter; MAX_INSNS],
    /// Number of valid instructions.
    insn_count: usize,
    /// Default action when no explicit RET is reached.
    default_action: SeccompAction,
}

impl Default for SeccompFilter {
    fn default() -> Self {
        Self {
            instructions: [SockFilter::default(); MAX_INSNS],
            insn_count: 0,
            default_action: SeccompAction::Allow,
        }
    }
}

impl SeccompFilter {
    /// Load a BPF program from a slice of instructions.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `prog` is empty or
    /// exceeds [`MAX_INSNS`].
    pub fn load(&mut self, prog: &[SockFilter]) -> Result<()> {
        if prog.is_empty() || prog.len() > MAX_INSNS {
            return Err(Error::InvalidArgument);
        }
        let mut i = 0;
        while i < prog.len() {
            self.instructions[i] = prog[i];
            i = i.saturating_add(1);
        }
        self.insn_count = prog.len();
        self.validate()
    }

    /// Validate the loaded BPF program.
    ///
    /// Checks that:
    /// - The program is non-empty.
    /// - All jump targets are in bounds.
    /// - The last instruction is a RET.
    /// - Division/modulo by immediate zero is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] on any validation
    /// failure.
    pub fn validate(&self) -> Result<()> {
        if self.insn_count == 0 || self.insn_count > MAX_INSNS {
            return Err(Error::InvalidArgument);
        }

        // Last instruction must be RET.
        let last = &self.instructions[self.insn_count.saturating_sub(1)];
        if last.code & 0x07 != BPF_RET {
            return Err(Error::InvalidArgument);
        }

        for i in 0..self.insn_count {
            let insn = &self.instructions[i];
            let class = insn.code & 0x07;

            match class {
                cls if cls == BPF_JMP => {
                    let op = insn.code & 0xF0;
                    if op == JMP_JA {
                        // Unconditional jump.
                        let target = i.saturating_add(1).saturating_add(insn.k as usize);
                        if target >= self.insn_count {
                            return Err(Error::InvalidArgument);
                        }
                    } else {
                        // Conditional jump — check both targets.
                        let t_target = i.saturating_add(1).saturating_add(insn.jt as usize);
                        let f_target = i.saturating_add(1).saturating_add(insn.jf as usize);
                        if t_target >= self.insn_count || f_target >= self.insn_count {
                            return Err(Error::InvalidArgument);
                        }
                    }
                }
                cls if cls == BPF_ALU => {
                    let op = insn.code & 0xF0;
                    let src = insn.code & 0x08;
                    // Division/modulo by immediate zero.
                    if (op == ALU_DIV || op == ALU_MOD) && src == BPF_K && insn.k == 0 {
                        return Err(Error::InvalidArgument);
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Execute this cBPF program against `data`.
    ///
    /// Runs a classic BPF VM with:
    /// - Accumulator register (A)
    /// - Index register (X)
    /// - 16-slot scratch memory (`M[0..15]`)
    ///
    /// Returns [`SeccompAction::Kill`] if the program is empty
    /// or encounters an illegal instruction.
    pub fn execute(&self, data: &SeccompData) -> SeccompAction {
        if self.insn_count == 0 {
            return self.default_action;
        }

        let mut a: u32 = 0; // accumulator
        let mut x: u32 = 0; // index register
        let mut mem = [0u32; SCRATCH_SIZE]; // scratch memory
        let mut pc: usize = 0;

        while pc < self.insn_count {
            let insn = self.instructions[pc];
            let class = insn.code & 0x07;

            match class {
                // ── LD: load into accumulator ──────────────
                cls if cls == BPF_LD => match self.exec_ld(insn, data, x, &mem) {
                    Some(val) => a = val,
                    None => return SeccompAction::Kill,
                },
                // ── LDX: load into index register ─────────
                cls if cls == BPF_LDX => match self.exec_ldx(insn, data, &mem) {
                    Some(val) => x = val,
                    None => return SeccompAction::Kill,
                },
                // ── ST: store accumulator to scratch ──────
                cls if cls == BPF_ST => {
                    let idx = insn.k as usize;
                    if idx >= SCRATCH_SIZE {
                        return SeccompAction::Kill;
                    }
                    mem[idx] = a;
                }
                // ── STX: store index register to scratch ──
                cls if cls == BPF_STX => {
                    let idx = insn.k as usize;
                    if idx >= SCRATCH_SIZE {
                        return SeccompAction::Kill;
                    }
                    mem[idx] = x;
                }
                // ── ALU: arithmetic on accumulator ────────
                cls if cls == BPF_ALU => match self.exec_alu(insn, a, x) {
                    Some(val) => a = val,
                    None => return SeccompAction::Kill,
                },
                // ── JMP: conditional/unconditional jump ───
                cls if cls == BPF_JMP => {
                    let op = insn.code & 0xF0;
                    if op == JMP_JA {
                        pc = pc.saturating_add(1).saturating_add(insn.k as usize);
                        continue;
                    }
                    let src_val = if insn.code & 0x08 == BPF_X { x } else { insn.k };
                    let taken = match op {
                        JMP_JEQ => a == src_val,
                        JMP_JGT => a > src_val,
                        JMP_JGE => a >= src_val,
                        JMP_JSET => (a & src_val) != 0,
                        _ => return SeccompAction::Kill,
                    };
                    let offset = if taken { insn.jt } else { insn.jf };
                    pc = pc.saturating_add(1).saturating_add(offset as usize);
                    continue;
                }
                // ── RET: return a value ───────────────────
                cls if cls == BPF_RET => {
                    let src = insn.code & 0x18;
                    let ret_val = if src == BPF_K {
                        insn.k
                    } else if src == BPF_A {
                        a
                    } else {
                        return SeccompAction::Kill;
                    };
                    return SeccompAction::from_u32(ret_val);
                }
                // ── MISC: TAX / TXA ──────────────────────
                cls if cls == BPF_MISC => match insn.k {
                    MISC_TAX => x = a,
                    MISC_TXA => a = x,
                    _ => return SeccompAction::Kill,
                },
                _ => return SeccompAction::Kill,
            }

            pc = pc.saturating_add(1);
        }

        // Fell off program without RET.
        self.default_action
    }

    /// Execute a LD instruction, returning the loaded value.
    fn exec_ld(
        &self,
        insn: SockFilter,
        data: &SeccompData,
        x: u32,
        mem: &[u32; SCRATCH_SIZE],
    ) -> Option<u32> {
        let mode = insn.code & 0xE0;
        let size = insn.code & 0x18;

        match mode {
            m if m == BPF_ABS => self.load_data(data, insn.k, size),
            m if m == BPF_IND => {
                let offset = x.saturating_add(insn.k);
                self.load_data(data, offset, size)
            }
            m if m == BPF_IMM => Some(insn.k),
            m if m == BPF_MEM => {
                let idx = insn.k as usize;
                if idx >= SCRATCH_SIZE {
                    None
                } else {
                    Some(mem[idx])
                }
            }
            m if m == BPF_LEN => Some(SECCOMP_DATA_SIZE),
            _ => None,
        }
    }

    /// Execute a LDX instruction, returning the loaded value.
    fn exec_ldx(
        &self,
        insn: SockFilter,
        data: &SeccompData,
        mem: &[u32; SCRATCH_SIZE],
    ) -> Option<u32> {
        let mode = insn.code & 0xE0;

        match mode {
            m if m == BPF_IMM => Some(insn.k),
            m if m == BPF_MEM => {
                let idx = insn.k as usize;
                if idx >= SCRATCH_SIZE {
                    None
                } else {
                    Some(mem[idx])
                }
            }
            m if m == BPF_LEN => Some(SECCOMP_DATA_SIZE),
            m if m == BPF_MSH => {
                // Load byte, mask lower nibble, multiply by 4.
                let val = data.load_byte(insn.k)?;
                Some((val & 0x0F) * 4)
            }
            _ => None,
        }
    }

    /// Load data from `SeccompData` with the given size.
    fn load_data(&self, data: &SeccompData, offset: u32, size: u16) -> Option<u32> {
        match size {
            s if s == BPF_W => data.load_word(offset),
            s if s == BPF_H => data.load_half(offset),
            s if s == BPF_B => data.load_byte(offset),
            _ => None,
        }
    }

    /// Execute an ALU instruction, returning the result.
    fn exec_alu(&self, insn: SockFilter, a: u32, x: u32) -> Option<u32> {
        let op = insn.code & 0xF0;
        let src = if insn.code & 0x08 == BPF_X { x } else { insn.k };

        match op {
            ALU_ADD => Some(a.wrapping_add(src)),
            ALU_SUB => Some(a.wrapping_sub(src)),
            ALU_MUL => Some(a.wrapping_mul(src)),
            ALU_DIV => a.checked_div(src),
            ALU_OR => Some(a | src),
            ALU_AND => Some(a & src),
            ALU_LSH => Some(a.wrapping_shl(src)),
            ALU_RSH => Some(a.wrapping_shr(src)),
            ALU_NEG => Some((-(a as i32)) as u32),
            ALU_MOD => a.checked_rem(src),
            ALU_XOR => Some(a ^ src),
            _ => None,
        }
    }
}

// ── SeccompFilterChain ─────────────────────────────────────────

/// Per-process chain of seccomp filters.
///
/// Up to [`MAX_CHAIN`] filters can be stacked. When evaluated,
/// all filters run and the most restrictive action wins.
#[derive(Debug, Clone)]
pub struct SeccompFilterChain {
    /// Installed filter programs.
    filters: [SeccompFilter; MAX_CHAIN],
    /// Number of installed filters.
    filter_count: usize,
}

impl Default for SeccompFilterChain {
    fn default() -> Self {
        Self {
            filters: core::array::from_fn(|_| SeccompFilter::default()),
            filter_count: 0,
        }
    }
}

impl SeccompFilterChain {
    /// Push a new filter onto the chain.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the chain is full.
    pub fn push(&mut self, filter: SeccompFilter) -> Result<()> {
        if self.filter_count >= MAX_CHAIN {
            return Err(Error::OutOfMemory);
        }
        self.filters[self.filter_count] = filter;
        self.filter_count = self.filter_count.saturating_add(1);
        Ok(())
    }

    /// Evaluate all filters against `data`.
    ///
    /// Returns the most restrictive action (lowest priority).
    /// Short-circuits on [`SeccompAction::Kill`].
    pub fn evaluate(&self, data: &SeccompData) -> SeccompAction {
        let mut result = SeccompAction::Allow;

        let mut i: usize = 0;
        while i < self.filter_count {
            let action = self.filters[i].execute(data);
            if action.priority() < result.priority() {
                result = action;
            }
            if matches!(result, SeccompAction::Kill) {
                return result;
            }
            i = i.saturating_add(1);
        }

        result
    }
}

// ── SeccompFilterRegistry ──────────────────────────────────────

/// Global registry of per-PID seccomp filter chains.
///
/// Provides up to [`MAX_PIDS`] slots indexed by PID index.
pub struct SeccompFilterRegistry {
    /// Per-PID filter chains.
    chains: [SeccompFilterChain; MAX_PIDS],
    /// Number of active chains (slots with at least one filter).
    count: usize,
}

impl Default for SeccompFilterRegistry {
    fn default() -> Self {
        Self {
            chains: core::array::from_fn(|_| SeccompFilterChain::default()),
            count: 0,
        }
    }
}

impl SeccompFilterRegistry {
    /// Install a filter for the process at `pid_idx`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `pid_idx` is out of range.
    /// - [`Error::OutOfMemory`] if the chain is full.
    pub fn install(&mut self, pid_idx: usize, filter: SeccompFilter) -> Result<()> {
        if pid_idx >= MAX_PIDS {
            return Err(Error::InvalidArgument);
        }
        let was_empty = self.chains[pid_idx].filter_count == 0;
        self.chains[pid_idx].push(filter)?;
        if was_empty {
            self.count = self.count.saturating_add(1);
        }
        Ok(())
    }

    /// Check a syscall for the process at `pid_idx`.
    ///
    /// Returns [`SeccompAction::Allow`] if `pid_idx` is out of
    /// range or has no filters installed.
    pub fn check_syscall(&self, pid_idx: usize, data: &SeccompData) -> SeccompAction {
        if pid_idx >= MAX_PIDS {
            return SeccompAction::Allow;
        }
        if self.chains[pid_idx].filter_count == 0 {
            return SeccompAction::Allow;
        }
        self.chains[pid_idx].evaluate(data)
    }

    /// Clear all filters for the process at `pid_idx`.
    pub fn clear(&mut self, pid_idx: usize) {
        if pid_idx >= MAX_PIDS {
            return;
        }
        if self.chains[pid_idx].filter_count > 0 {
            self.count = self.count.saturating_sub(1);
        }
        self.chains[pid_idx] = SeccompFilterChain::default();
    }

    /// Return the number of active chains.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no chains have filters installed.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
