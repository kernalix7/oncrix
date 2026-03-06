// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! BPF virtual machine core — interpreter and program lifecycle.
//!
//! Implements the eBPF virtual machine: instruction set, register file,
//! and interpreter loop. Works in conjunction with `bpf_verifier.rs`
//! (safety verification) and `bpf_map.rs` (map operations).
//!
//! # Architecture
//!
//! | Component           | Purpose                                             |
//! |---------------------|-----------------------------------------------------|
//! | [`BpfInsn`]         | A single eBPF instruction (64-bit encoding)         |
//! | [`BpfRegs`]         | 11-register eBPF register file (R0–R10)             |
//! | [`BpfProg`]         | A loaded eBPF program (instructions + metadata)     |
//! | [`BpfVm`]           | Interpreter that executes BPF programs              |
//! | [`BpfProgType`]     | Program type (socket filter, kprobe, tracepoint, …) |
//!
//! # Instruction Encoding
//!
//! Each instruction is 64 bits:
//! ```text
//! [63:56] imm (high) | [55:32] off | [31:24] src | [23:16] dst | [15:8] code | [7:0] class
//! ```
//! Following Linux eBPF encoding exactly.
//!
//! # Execution Model
//!
//! The interpreter runs up to `MAX_INSNS_PER_PROG` instructions. Each call
//! instruction transfers control to a helper function registered in the
//! helper table. The program terminates by executing `BPF_EXIT` with R0
//! holding the return value.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of instructions in a BPF program.
pub const MAX_INSNS_PER_PROG: usize = 4096;

/// Number of BPF registers (R0–R10).
pub const BPF_REG_COUNT: usize = 11;

/// Maximum number of loaded programs.
pub const MAX_BPF_PROGS: usize = 64;

/// Maximum number of registered helper functions.
pub const MAX_HELPERS: usize = 128;

// ---------------------------------------------------------------------------
// Instruction classes and opcodes
// ---------------------------------------------------------------------------

/// BPF instruction class (bits [2:0] of opcode byte).
pub mod class {
    pub const LD: u8 = 0x00;
    pub const LDX: u8 = 0x01;
    pub const ST: u8 = 0x02;
    pub const STX: u8 = 0x03;
    pub const ALU: u8 = 0x04;
    pub const JMP: u8 = 0x05;
    pub const JMP32: u8 = 0x06;
    pub const ALU64: u8 = 0x07;
}

/// BPF ALU operation codes (bits [7:4] of opcode byte).
pub mod alu_op {
    pub const ADD: u8 = 0x00;
    pub const SUB: u8 = 0x10;
    pub const MUL: u8 = 0x20;
    pub const DIV: u8 = 0x30;
    pub const OR: u8 = 0x40;
    pub const AND: u8 = 0x50;
    pub const LSH: u8 = 0x60;
    pub const RSH: u8 = 0x70;
    pub const NEG: u8 = 0x80;
    pub const MOD: u8 = 0x90;
    pub const XOR: u8 = 0xa0;
    pub const MOV: u8 = 0xb0;
    pub const ARSH: u8 = 0xc0;
}

/// BPF JMP operation codes (bits [7:4] of opcode byte).
pub mod jmp_op {
    pub const JA: u8 = 0x00;
    pub const JEQ: u8 = 0x10;
    pub const JGT: u8 = 0x20;
    pub const JGE: u8 = 0x30;
    pub const JSET: u8 = 0x40;
    pub const JNE: u8 = 0x50;
    pub const JSGT: u8 = 0x60;
    pub const JSGE: u8 = 0x70;
    pub const CALL: u8 = 0x80;
    pub const EXIT: u8 = 0x90;
    pub const JLT: u8 = 0xa0;
    pub const JLE: u8 = 0xb0;
    pub const JSLT: u8 = 0xc0;
    pub const JSLE: u8 = 0xd0;
}

/// Source modifier: immediate (K) or register (X).
pub const BPF_K: u8 = 0x00;
pub const BPF_X: u8 = 0x08;

// ---------------------------------------------------------------------------
// Instruction
// ---------------------------------------------------------------------------

/// A single eBPF instruction (8 bytes).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct BpfInsn {
    /// Opcode byte.
    pub code: u8,
    /// Source and destination register nibbles (dst=[3:0], src=[7:4]).
    pub regs: u8,
    /// Signed offset (for branches and memory ops).
    pub off: i16,
    /// Signed immediate value.
    pub imm: i32,
}

impl BpfInsn {
    /// Destination register (0–10).
    pub fn dst_reg(&self) -> u8 {
        self.regs & 0x0f
    }

    /// Source register (0–10).
    pub fn src_reg(&self) -> u8 {
        (self.regs >> 4) & 0x0f
    }

    /// Instruction class (bits [2:0] of code).
    pub fn class(&self) -> u8 {
        self.code & 0x07
    }

    /// Opcode sans class bits.
    pub fn op(&self) -> u8 {
        self.code & 0xf8
    }

    /// Source modifier (BPF_K or BPF_X).
    pub fn src(&self) -> u8 {
        self.code & 0x08
    }
}

// ---------------------------------------------------------------------------
// Register file
// ---------------------------------------------------------------------------

/// eBPF register file (R0–R10).
///
/// - R0: return value / scratch
/// - R1–R5: function arguments (caller-saved)
/// - R6–R9: callee-saved
/// - R10: read-only frame pointer
#[derive(Debug, Clone, Copy, Default)]
pub struct BpfRegs {
    /// Register values.
    pub regs: [u64; BPF_REG_COUNT],
}

impl BpfRegs {
    /// Create zeroed registers.
    pub const fn new() -> Self {
        Self {
            regs: [0u64; BPF_REG_COUNT],
        }
    }

    /// Read a register value.
    pub fn read(&self, reg: u8) -> Result<u64> {
        if (reg as usize) < BPF_REG_COUNT {
            Ok(self.regs[reg as usize])
        } else {
            Err(Error::InvalidArgument)
        }
    }

    /// Write a register value.
    pub fn write(&mut self, reg: u8, val: u64) -> Result<()> {
        if reg == 10 {
            // R10 is read-only frame pointer.
            return Err(Error::PermissionDenied);
        }
        if (reg as usize) < BPF_REG_COUNT {
            self.regs[reg as usize] = val;
            Ok(())
        } else {
            Err(Error::InvalidArgument)
        }
    }
}

// ---------------------------------------------------------------------------
// Program type
// ---------------------------------------------------------------------------

/// BPF program type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BpfProgType {
    /// Unspecified.
    #[default]
    Unspecified,
    /// Socket filter.
    SocketFilter,
    /// kprobe attach.
    Kprobe,
    /// Tracepoint.
    Tracepoint,
    /// XDP (eXpress Data Path).
    Xdp,
    /// Perf event.
    PerfEvent,
    /// cgroup/skb.
    CgroupSkb,
    /// cgroup/sock.
    CgroupSock,
    /// LSM hook.
    Lsm,
    /// Syscall program.
    Syscall,
}

// ---------------------------------------------------------------------------
// BPF program
// ---------------------------------------------------------------------------

/// A loaded eBPF program.
pub struct BpfProg {
    /// Program identifier.
    pub id: u32,
    /// Program type.
    pub prog_type: BpfProgType,
    /// Instructions.
    insns: [BpfInsn; MAX_INSNS_PER_PROG],
    /// Actual instruction count.
    pub insn_count: usize,
    /// Whether the program has been verified.
    pub verified: bool,
    /// UID of the process that loaded this program.
    pub owner_uid: u32,
}

impl BpfProg {
    /// Create an empty program slot.
    pub const fn new(id: u32) -> Self {
        Self {
            id,
            prog_type: BpfProgType::Unspecified,
            insns: [BpfInsn {
                code: 0,
                regs: 0,
                off: 0,
                imm: 0,
            }; MAX_INSNS_PER_PROG],
            insn_count: 0,
            verified: false,
            owner_uid: 0,
        }
    }

    /// Load instructions into the program.
    pub fn load(&mut self, insns: &[BpfInsn]) -> Result<()> {
        if insns.len() > MAX_INSNS_PER_PROG {
            return Err(Error::InvalidArgument);
        }
        self.insns[..insns.len()].copy_from_slice(insns);
        self.insn_count = insns.len();
        self.verified = false;
        Ok(())
    }

    /// Return the instruction slice.
    pub fn insns(&self) -> &[BpfInsn] {
        &self.insns[..self.insn_count]
    }
}

// ---------------------------------------------------------------------------
// Helper function signature
// ---------------------------------------------------------------------------

/// A BPF helper function.
pub type BpfHelper = fn(u64, u64, u64, u64, u64) -> u64;

// ---------------------------------------------------------------------------
// BPF VM interpreter
// ---------------------------------------------------------------------------

/// eBPF interpreter / virtual machine.
pub struct BpfVm {
    /// Stack memory (512 bytes per BPF spec).
    stack: [u8; 512],
    /// Helper function table.
    helpers: [Option<BpfHelper>; MAX_HELPERS],
    /// Instruction count limit per execution.
    insn_limit: usize,
}

impl BpfVm {
    /// Create a new BPF VM.
    pub const fn new() -> Self {
        Self {
            stack: [0u8; 512],
            helpers: [None; MAX_HELPERS],
            insn_limit: MAX_INSNS_PER_PROG * 32,
        }
    }

    /// Register a helper function at the given index.
    pub fn register_helper(&mut self, idx: usize, helper: BpfHelper) -> Result<()> {
        if idx >= MAX_HELPERS {
            return Err(Error::InvalidArgument);
        }
        self.helpers[idx] = Some(helper);
        Ok(())
    }

    /// Execute a verified BPF program with the given context value in R1.
    ///
    /// Returns the value of R0 after `BPF_EXIT`.
    pub fn run(&mut self, prog: &BpfProg, ctx: u64) -> Result<u64> {
        if !prog.verified {
            return Err(Error::PermissionDenied);
        }
        if prog.insn_count == 0 {
            return Err(Error::InvalidArgument);
        }

        let mut regs = BpfRegs::new();
        // R1 = context pointer, R10 = frame pointer (top of stack).
        regs.regs[1] = ctx;
        regs.regs[10] = self.stack.as_ptr() as u64 + self.stack.len() as u64;

        let insns = prog.insns();
        let mut pc: usize = 0;
        let mut steps: usize = 0;

        loop {
            if pc >= insns.len() {
                return Err(Error::InvalidArgument);
            }
            if steps >= self.insn_limit {
                return Err(Error::Busy);
            }
            steps += 1;

            let insn = insns[pc];
            let dst = insn.dst_reg() as usize;
            let src = insn.src_reg() as usize;
            let imm = insn.imm as i64 as u64;
            let cls = insn.class();
            let op = insn.op();
            let is_reg = insn.src() == BPF_X;

            match cls {
                c if c == class::ALU64 => {
                    let src_val = if is_reg { regs.regs[src] } else { imm };
                    match op {
                        o if o == alu_op::ADD => {
                            regs.regs[dst] = regs.regs[dst].wrapping_add(src_val)
                        }
                        o if o == alu_op::SUB => {
                            regs.regs[dst] = regs.regs[dst].wrapping_sub(src_val)
                        }
                        o if o == alu_op::MUL => {
                            regs.regs[dst] = regs.regs[dst].wrapping_mul(src_val)
                        }
                        o if o == alu_op::DIV => {
                            if src_val == 0 {
                                return Err(Error::InvalidArgument);
                            }
                            regs.regs[dst] /= src_val;
                        }
                        o if o == alu_op::OR => regs.regs[dst] |= src_val,
                        o if o == alu_op::AND => regs.regs[dst] &= src_val,
                        o if o == alu_op::LSH => regs.regs[dst] <<= src_val & 63,
                        o if o == alu_op::RSH => regs.regs[dst] >>= src_val & 63,
                        o if o == alu_op::XOR => regs.regs[dst] ^= src_val,
                        o if o == alu_op::MOV => regs.regs[dst] = src_val,
                        o if o == alu_op::MOD => {
                            if src_val == 0 {
                                return Err(Error::InvalidArgument);
                            }
                            regs.regs[dst] %= src_val;
                        }
                        o if o == alu_op::NEG => {
                            regs.regs[dst] = (regs.regs[dst] as i64).wrapping_neg() as u64;
                        }
                        _ => return Err(Error::NotImplemented),
                    }
                    pc += 1;
                }
                c if c == class::JMP => match op {
                    o if o == jmp_op::EXIT => {
                        return Ok(regs.regs[0]);
                    }
                    o if o == jmp_op::CALL => {
                        let helper_idx = insn.imm as usize;
                        if helper_idx >= MAX_HELPERS {
                            return Err(Error::InvalidArgument);
                        }
                        let helper = self.helpers[helper_idx].ok_or(Error::NotFound)?;
                        regs.regs[0] = helper(
                            regs.regs[1],
                            regs.regs[2],
                            regs.regs[3],
                            regs.regs[4],
                            regs.regs[5],
                        );
                        pc += 1;
                    }
                    o if o == jmp_op::JA => {
                        pc = (pc as isize + 1 + insn.off as isize) as usize;
                    }
                    _ => {
                        let src_val = if is_reg { regs.regs[src] } else { imm };
                        let dst_val = regs.regs[dst];
                        let taken = match op {
                            o if o == jmp_op::JEQ => dst_val == src_val,
                            o if o == jmp_op::JNE => dst_val != src_val,
                            o if o == jmp_op::JGT => dst_val > src_val,
                            o if o == jmp_op::JGE => dst_val >= src_val,
                            o if o == jmp_op::JLT => dst_val < src_val,
                            o if o == jmp_op::JLE => dst_val <= src_val,
                            o if o == jmp_op::JSET => (dst_val & src_val) != 0,
                            o if o == jmp_op::JSGT => (dst_val as i64) > (src_val as i64),
                            o if o == jmp_op::JSGE => (dst_val as i64) >= (src_val as i64),
                            o if o == jmp_op::JSLT => (dst_val as i64) < (src_val as i64),
                            o if o == jmp_op::JSLE => (dst_val as i64) <= (src_val as i64),
                            _ => return Err(Error::NotImplemented),
                        };
                        if taken {
                            pc = (pc as isize + 1 + insn.off as isize) as usize;
                        } else {
                            pc += 1;
                        }
                    }
                },
                _ => {
                    // Other instruction classes not implemented in this core.
                    return Err(Error::NotImplemented);
                }
            }
        }
    }
}

impl Default for BpfVm {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Program table
// ---------------------------------------------------------------------------

/// Global BPF program table.
pub struct BpfProgTable {
    progs: [Option<BpfProg>; MAX_BPF_PROGS],
    next_id: u32,
}

impl BpfProgTable {
    /// Create an empty program table.
    pub const fn new() -> Self {
        Self {
            progs: [const { None }; MAX_BPF_PROGS],
            next_id: 1,
        }
    }

    /// Allocate a new program slot and return its id.
    pub fn alloc(&mut self, prog_type: BpfProgType, owner_uid: u32) -> Result<u32> {
        let slot = self
            .progs
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let mut prog = BpfProg::new(id);
        prog.prog_type = prog_type;
        prog.owner_uid = owner_uid;
        *slot = Some(prog);
        Ok(id)
    }

    /// Look up a program by id.
    pub fn get(&self, id: u32) -> Option<&BpfProg> {
        self.progs.iter().flatten().find(|p| p.id == id)
    }

    /// Look up a program mutably by id.
    pub fn get_mut(&mut self, id: u32) -> Option<&mut BpfProg> {
        self.progs.iter_mut().flatten().find(|p| p.id == id)
    }

    /// Free a program by id.
    pub fn free(&mut self, id: u32) -> Result<()> {
        let slot = self
            .progs
            .iter_mut()
            .find(|s| s.as_ref().map_or(false, |p| p.id == id))
            .ok_or(Error::NotFound)?;
        *slot = None;
        Ok(())
    }
}

impl Default for BpfProgTable {
    fn default() -> Self {
        Self::new()
    }
}
