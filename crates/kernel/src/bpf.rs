// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! eBPF-style bytecode verifier and interpreter.
//!
//! Provides a minimal eBPF subsystem for the ONCRIX kernel,
//! including:
//!
//! - **Instruction encoding** ([`BpfInsn`]): compact 8-byte
//!   representation matching the Linux eBPF ISA.
//! - **Program container** ([`BpfProgram`]): holds up to 256
//!   instructions with a type tag and verification status.
//! - **Static verifier** ([`BpfVerifier`]): validates safety
//!   properties (reachability, bounds, no backward jumps,
//!   no division-by-zero with immediate zero).
//! - **Virtual machine** ([`BpfVm`]): interprets verified
//!   programs with a 10 000-instruction execution cap.
//! - **BPF map** ([`BpfMap`]): simple fixed-capacity hash map
//!   for key/value storage accessible from BPF programs.
//! - **Program registry** ([`BpfRegistry`]): tracks up to 32
//!   loaded programs.
//!
//! Reference: Linux `kernel/bpf/`, `include/uapi/linux/bpf.h`.

use oncrix_lib::{Error, Result};

// ── Opcode class constants ─────────────────────────────────────

/// Load from immediate / packet.
pub const BPF_LD: u8 = 0x00;
/// Load from register.
pub const BPF_LDX: u8 = 0x01;
/// Store immediate.
pub const BPF_ST: u8 = 0x02;
/// Store register.
pub const BPF_STX: u8 = 0x03;
/// 32-bit ALU operations.
pub const BPF_ALU: u8 = 0x04;
/// 64-bit jump operations.
pub const BPF_JMP: u8 = 0x05;
/// 64-bit ALU operations.
pub const BPF_ALU64: u8 = 0x07;
/// 32-bit jump operations.
pub const BPF_JMP32: u8 = 0x06;

// ── ALU operation codes (upper 4 bits of opcode) ──────────────

/// Addition.
pub const BPF_ADD: u8 = 0x00;
/// Subtraction.
pub const BPF_SUB: u8 = 0x10;
/// Multiplication.
pub const BPF_MUL: u8 = 0x20;
/// Division.
pub const BPF_DIV: u8 = 0x30;
/// Bitwise OR.
pub const BPF_OR: u8 = 0x40;
/// Bitwise AND.
pub const BPF_AND: u8 = 0x50;
/// Left shift.
pub const BPF_LSH: u8 = 0x60;
/// Right shift.
pub const BPF_RSH: u8 = 0x70;
/// Negation (unary).
pub const BPF_NEG: u8 = 0x80;
/// Modulo.
pub const BPF_MOD: u8 = 0x90;
/// Bitwise XOR.
pub const BPF_XOR: u8 = 0xa0;
/// Move (register copy / load immediate).
pub const BPF_MOV: u8 = 0xb0;
/// Arithmetic right shift.
pub const BPF_ARSH: u8 = 0xc0;

// ── JMP operation codes (upper 4 bits of opcode) ──────────────

/// Unconditional jump (jump always).
pub const BPF_JA: u8 = 0x00;
/// Jump if equal.
pub const BPF_JEQ: u8 = 0x10;
/// Jump if greater than (unsigned).
pub const BPF_JGT: u8 = 0x20;
/// Jump if greater or equal (unsigned).
pub const BPF_JGE: u8 = 0x30;
/// Jump if bits set.
pub const BPF_JSET: u8 = 0x40;
/// Jump if not equal.
pub const BPF_JNE: u8 = 0x50;
/// Jump if greater than (signed).
pub const BPF_JSGT: u8 = 0x60;
/// Jump if greater or equal (signed).
pub const BPF_JSGE: u8 = 0x70;
/// Call helper function.
pub const BPF_CALL: u8 = 0x80;
/// Exit program, return R0.
pub const BPF_EXIT: u8 = 0x90;

// ── Source modifiers ───────────────────────────────────────────

/// Source operand is the 32-bit immediate field.
pub const BPF_K: u8 = 0x00;
/// Source operand is a register.
pub const BPF_X: u8 = 0x08;

// ── Register indices ──────────────────────────────────────────

/// Return value register.
const _REG_R0: usize = 0;
/// Argument registers (R1 – R5).
const _REG_R1: usize = 1;
/// Frame pointer (read-only).
const REG_R10: usize = 10;
/// Total number of registers (R0 – R10).
const NUM_REGS: usize = 11;

// ── Limits ────────────────────────────────────────────────────

/// Maximum number of instructions in a BPF program.
pub const MAX_INSNS: usize = 256;
/// Maximum instructions the VM will execute before aborting.
const MAX_EXEC_INSNS: usize = 10_000;
/// BPF stack size in bytes.
const STACK_SIZE: usize = 512;
/// Maximum entries in a [`BpfMap`].
const MAX_MAP_ENTRIES: usize = 64;
/// Maximum key size in bytes.
const MAX_KEY_SIZE: usize = 32;
/// Maximum value size in bytes.
const MAX_VALUE_SIZE: usize = 64;
/// Maximum number of programs in the registry.
const MAX_PROGRAMS: usize = 32;

// ── BpfInsn ───────────────────────────────────────────────────

/// A single eBPF instruction (8 bytes, C-compatible layout).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct BpfInsn {
    /// Operation code (class | op | source).
    pub opcode: u8,
    /// Destination register (lower 4 bits) and source
    /// register (upper 4 bits), packed into one byte.
    pub regs: u8,
    /// Signed offset (used by jumps and memory ops).
    pub off: i16,
    /// Signed 32-bit immediate value.
    pub imm: i32,
}

impl BpfInsn {
    /// Create a new BPF instruction.
    pub const fn new(opcode: u8, dst_reg: u8, src_reg: u8, off: i16, imm: i32) -> Self {
        Self {
            opcode,
            regs: (src_reg << 4) | (dst_reg & 0x0f),
            off,
            imm,
        }
    }

    /// Extract the destination register index (lower 4 bits).
    #[inline]
    pub const fn dst_reg(&self) -> u8 {
        self.regs & 0x0f
    }

    /// Extract the source register index (upper 4 bits).
    #[inline]
    pub const fn src_reg(&self) -> u8 {
        self.regs >> 4
    }

    /// Extract the opcode class (lower 3 bits).
    #[inline]
    pub const fn class(&self) -> u8 {
        self.opcode & 0x07
    }

    /// Extract the ALU / JMP operation (upper 4 bits).
    #[inline]
    pub const fn op(&self) -> u8 {
        self.opcode & 0xf0
    }

    /// Extract the source modifier (bit 3).
    #[inline]
    pub const fn src(&self) -> u8 {
        self.opcode & 0x08
    }
}

// ── BpfProgType ───────────────────────────────────────────────

/// Classification of a BPF program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BpfProgType {
    /// Socket-level packet filter.
    #[default]
    SocketFilter,
    /// Kernel probe hook.
    Kprobe,
    /// Static tracepoint hook.
    Tracepoint,
    /// eXpress Data Path (XDP) hook.
    Xdp,
    /// Cgroup socket buffer filter.
    CgroupSkb,
    /// Traffic-control classifier.
    SchedCls,
}

// ── BpfProgram ────────────────────────────────────────────────

/// A loaded BPF program with up to [`MAX_INSNS`] instructions.
pub struct BpfProgram {
    /// Instruction buffer.
    pub insns: [BpfInsn; MAX_INSNS],
    /// Number of valid instructions.
    pub len: usize,
    /// Program type classification.
    pub prog_type: BpfProgType,
    /// Whether the verifier has approved this program.
    pub verified: bool,
}

impl Default for BpfProgram {
    fn default() -> Self {
        Self {
            insns: [BpfInsn::default(); MAX_INSNS],
            len: 0,
            prog_type: BpfProgType::default(),
            verified: false,
        }
    }
}

impl BpfProgram {
    /// Create a new empty program of the given type.
    pub fn new(prog_type: BpfProgType) -> Self {
        Self {
            prog_type,
            ..Default::default()
        }
    }

    /// Append an instruction to the program.
    ///
    /// Returns [`Error::OutOfMemory`] if the program is full.
    pub fn push(&mut self, insn: BpfInsn) -> Result<()> {
        if self.len >= MAX_INSNS {
            return Err(Error::OutOfMemory);
        }
        self.insns[self.len] = insn;
        self.len += 1;
        Ok(())
    }
}

// ── BpfVerifier ───────────────────────────────────────────────

/// Static verifier for BPF programs.
///
/// Performs a single pass over the program to ensure:
/// - Non-zero length (≤ 256).
/// - The last instruction is `EXIT`.
/// - All jump targets are in-bounds and forward-only.
/// - No division / modulo by immediate zero.
/// - No writes to the read-only frame pointer R10.
/// - Basic reachability (no unreachable instructions).
pub struct BpfVerifier;

impl BpfVerifier {
    /// Verify a BPF program for safety.
    ///
    /// On success the caller should set `prog.verified = true`.
    pub fn verify(prog: &BpfProgram) -> Result<()> {
        if prog.len == 0 || prog.len > MAX_INSNS {
            return Err(Error::InvalidArgument);
        }

        // Last instruction must be EXIT.
        let last = &prog.insns[prog.len - 1];
        if last.class() != BPF_JMP || last.op() != BPF_EXIT {
            return Err(Error::InvalidArgument);
        }

        // Reachability bitmap (256 bits = 4 × u64).
        let mut visited = [0u64; 4];

        // Mark instruction `idx` as reachable.
        let mark = |v: &mut [u64; 4], idx: usize| {
            v[idx / 64] |= 1u64 << (idx % 64);
        };
        let is_set = |v: &[u64; 4], idx: usize| -> bool { v[idx / 64] & (1u64 << (idx % 64)) != 0 };

        // Entry point is reachable.
        mark(&mut visited, 0);

        for i in 0..prog.len {
            let insn = &prog.insns[i];
            let class = insn.class();
            let op = insn.op();

            // Validate destination register.
            let dst = insn.dst_reg() as usize;
            if dst >= NUM_REGS {
                return Err(Error::InvalidArgument);
            }

            // R10 is read-only: reject ALU / MOV writes.
            if dst == REG_R10 && (class == BPF_ALU || class == BPF_ALU64 || class == BPF_STX) {
                return Err(Error::InvalidArgument);
            }

            // Validate source register when BPF_X.
            if insn.src() == BPF_X {
                let sr = insn.src_reg() as usize;
                if sr >= NUM_REGS {
                    return Err(Error::InvalidArgument);
                }
            }

            // Division / modulo by immediate zero.
            if (class == BPF_ALU || class == BPF_ALU64)
                && (op == BPF_DIV || op == BPF_MOD)
                && insn.src() == BPF_K
                && insn.imm == 0
            {
                return Err(Error::InvalidArgument);
            }

            // Jump target validation.
            if class == BPF_JMP || class == BPF_JMP32 {
                if op == BPF_EXIT {
                    // No fall-through after exit.
                    continue;
                }
                if op == BPF_CALL {
                    // CALL falls through to next insn.
                    if i + 1 < prog.len {
                        mark(&mut visited, i + 1);
                    }
                    continue;
                }
                if op == BPF_JA {
                    // Unconditional jump — target only.
                    let target = (i as i64) + 1 + (insn.off as i64);
                    if target < 0 || target as usize >= prog.len {
                        return Err(Error::InvalidArgument);
                    }
                    // No backward jumps.
                    if (target as usize) <= i {
                        return Err(Error::InvalidArgument);
                    }
                    mark(&mut visited, target as usize);
                    continue;
                }
                // Conditional jump: check target and
                // fall-through.
                let target = (i as i64) + 1 + (insn.off as i64);
                if target < 0 || target as usize >= prog.len {
                    return Err(Error::InvalidArgument);
                }
                if (target as usize) <= i {
                    return Err(Error::InvalidArgument);
                }
                mark(&mut visited, target as usize);
                if i + 1 < prog.len {
                    mark(&mut visited, i + 1);
                }
                continue;
            }

            // Non-jump instructions fall through.
            if i + 1 < prog.len {
                mark(&mut visited, i + 1);
            }
        }

        // Verify all instructions are reachable.
        for i in 0..prog.len {
            if !is_set(&visited, i) {
                return Err(Error::InvalidArgument);
            }
        }

        Ok(())
    }
}

// ── BpfVm ─────────────────────────────────────────────────────

/// eBPF virtual machine for executing verified programs.
pub struct BpfVm {
    /// General-purpose registers R0 – R10.
    pub regs: [u64; NUM_REGS],
    /// Program counter.
    pub pc: usize,
    /// Per-program stack.
    pub stack: [u8; STACK_SIZE],
}

impl Default for BpfVm {
    fn default() -> Self {
        Self::new()
    }
}

impl BpfVm {
    /// Create a new VM with zeroed state.
    pub fn new() -> Self {
        Self {
            regs: [0u64; NUM_REGS],
            pc: 0,
            stack: [0u8; STACK_SIZE],
        }
    }

    /// Execute a verified BPF program.
    ///
    /// `ctx` is made available to the program via R1 (as a
    /// pointer-sized integer). Returns the value left in R0
    /// on `EXIT`.
    ///
    /// # Errors
    ///
    /// - [`Error::PermissionDenied`] if the program has not
    ///   been verified.
    /// - [`Error::InvalidArgument`] on illegal instruction or
    ///   division by zero at runtime.
    /// - [`Error::Busy`] if the instruction limit is exceeded.
    pub fn run(&mut self, prog: &BpfProgram, ctx: &[u8]) -> Result<u64> {
        if !prog.verified {
            return Err(Error::PermissionDenied);
        }

        // Reset state.
        self.regs = [0u64; NUM_REGS];
        self.pc = 0;
        self.stack = [0u8; STACK_SIZE];

        // R1 = pointer to context, R10 = frame pointer.
        self.regs[1] = ctx.as_ptr() as u64;
        self.regs[REG_R10] = self.stack.as_ptr() as u64 + STACK_SIZE as u64;

        let mut insn_count: usize = 0;

        loop {
            if self.pc >= prog.len {
                return Err(Error::InvalidArgument);
            }
            if insn_count >= MAX_EXEC_INSNS {
                return Err(Error::Busy);
            }
            insn_count += 1;

            let insn = &prog.insns[self.pc];
            let class = insn.class();
            let op = insn.op();
            let dst = insn.dst_reg() as usize;
            let src_val = if insn.src() == BPF_X {
                self.regs[insn.src_reg() as usize]
            } else {
                insn.imm as u64
            };

            match class {
                BPF_ALU64 => {
                    self.exec_alu64(dst, op, src_val, insn)?;
                    self.pc += 1;
                }
                BPF_ALU => {
                    self.exec_alu32(dst, op, src_val, insn)?;
                    self.pc += 1;
                }
                BPF_JMP => {
                    if op == BPF_EXIT {
                        return Ok(self.regs[0]);
                    }
                    if op == BPF_CALL {
                        self.regs[0] = Self::call_helper(
                            insn.imm as u32,
                            self.regs[1],
                            self.regs[2],
                            self.regs[3],
                            self.regs[4],
                            self.regs[5],
                        );
                        self.pc += 1;
                        continue;
                    }
                    let taken = self.eval_jmp(op, dst, src_val);
                    if taken {
                        self.pc = ((self.pc as i64) + 1 + (insn.off as i64)) as usize;
                    } else {
                        self.pc += 1;
                    }
                }
                BPF_JMP32 => {
                    let src32 = src_val as u32;
                    let dst32 = self.regs[dst] as u32;
                    let taken = Self::eval_jmp32(op, dst32, src32);
                    if taken {
                        self.pc = ((self.pc as i64) + 1 + (insn.off as i64)) as usize;
                    } else {
                        self.pc += 1;
                    }
                }
                BPF_LD | BPF_LDX | BPF_ST | BPF_STX => {
                    // Memory ops are not fully implemented
                    // in this minimal interpreter.
                    self.pc += 1;
                }
                _ => {
                    return Err(Error::InvalidArgument);
                }
            }
        }
    }

    /// Execute a 64-bit ALU operation.
    fn exec_alu64(&mut self, dst: usize, op: u8, src: u64, insn: &BpfInsn) -> Result<()> {
        let d = self.regs[dst];
        self.regs[dst] = match op {
            BPF_ADD => d.wrapping_add(src),
            BPF_SUB => d.wrapping_sub(src),
            BPF_MUL => d.wrapping_mul(src),
            BPF_DIV => {
                if src == 0 {
                    return Err(Error::InvalidArgument);
                }
                d / src
            }
            BPF_OR => d | src,
            BPF_AND => d & src,
            BPF_LSH => d.wrapping_shl(src as u32),
            BPF_RSH => d.wrapping_shr(src as u32),
            BPF_NEG => {
                // NEG uses imm field (negate dst).
                let _ = insn;
                (-(d as i64)) as u64
            }
            BPF_MOD => {
                if src == 0 {
                    return Err(Error::InvalidArgument);
                }
                d % src
            }
            BPF_XOR => d ^ src,
            BPF_MOV => src,
            BPF_ARSH => ((d as i64).wrapping_shr(src as u32)) as u64,
            _ => return Err(Error::InvalidArgument),
        };
        Ok(())
    }

    /// Execute a 32-bit ALU operation (result is zero-extended).
    fn exec_alu32(&mut self, dst: usize, op: u8, src: u64, insn: &BpfInsn) -> Result<()> {
        let d = self.regs[dst] as u32;
        let s = src as u32;
        let result: u32 = match op {
            BPF_ADD => d.wrapping_add(s),
            BPF_SUB => d.wrapping_sub(s),
            BPF_MUL => d.wrapping_mul(s),
            BPF_DIV => {
                if s == 0 {
                    return Err(Error::InvalidArgument);
                }
                d / s
            }
            BPF_OR => d | s,
            BPF_AND => d & s,
            BPF_LSH => d.wrapping_shl(s),
            BPF_RSH => d.wrapping_shr(s),
            BPF_NEG => {
                let _ = insn;
                (-(d as i32)) as u32
            }
            BPF_MOD => {
                if s == 0 {
                    return Err(Error::InvalidArgument);
                }
                d % s
            }
            BPF_XOR => d ^ s,
            BPF_MOV => s,
            BPF_ARSH => ((d as i32).wrapping_shr(s)) as u32,
            _ => return Err(Error::InvalidArgument),
        };
        // Zero-extend to 64 bits.
        self.regs[dst] = result as u64;
        Ok(())
    }

    /// Evaluate a 64-bit conditional jump.
    fn eval_jmp(&self, op: u8, dst: usize, src: u64) -> bool {
        let d = self.regs[dst];
        match op {
            BPF_JA => true,
            BPF_JEQ => d == src,
            BPF_JGT => d > src,
            BPF_JGE => d >= src,
            BPF_JSET => (d & src) != 0,
            BPF_JNE => d != src,
            BPF_JSGT => (d as i64) > (src as i64),
            BPF_JSGE => (d as i64) >= (src as i64),
            _ => false,
        }
    }

    /// Evaluate a 32-bit conditional jump.
    fn eval_jmp32(op: u8, dst: u32, src: u32) -> bool {
        match op {
            BPF_JA => true,
            BPF_JEQ => dst == src,
            BPF_JGT => dst > src,
            BPF_JGE => dst >= src,
            BPF_JSET => (dst & src) != 0,
            BPF_JNE => dst != src,
            BPF_JSGT => (dst as i32) > (src as i32),
            BPF_JSGE => (dst as i32) >= (src as i32),
            _ => false,
        }
    }

    /// Dispatch a BPF helper function call.
    ///
    /// Currently all helpers return 0 (stub).
    fn call_helper(helper_id: u32, _r1: u64, _r2: u64, _r3: u64, _r4: u64, _r5: u64) -> u64 {
        let _ = helper_id;
        0
    }
}

// ── BpfMap ────────────────────────────────────────────────────

/// A single entry in a [`BpfMap`].
struct BpfMapEntry {
    /// Key bytes.
    key: [u8; MAX_KEY_SIZE],
    /// Value bytes.
    value: [u8; MAX_VALUE_SIZE],
    /// Whether this slot is occupied.
    occupied: bool,
}

impl Default for BpfMapEntry {
    fn default() -> Self {
        Self {
            key: [0u8; MAX_KEY_SIZE],
            value: [0u8; MAX_VALUE_SIZE],
            occupied: false,
        }
    }
}

/// Simple hash-map for BPF programs.
///
/// Keys are up to [`MAX_KEY_SIZE`] bytes, values up to
/// [`MAX_VALUE_SIZE`] bytes. At most [`MAX_MAP_ENTRIES`]
/// entries are stored. Collision resolution uses linear
/// probing.
pub struct BpfMap {
    /// Configured key size (bytes).
    key_size: usize,
    /// Configured value size (bytes).
    value_size: usize,
    /// Maximum number of entries.
    max_entries: usize,
    /// Storage slots.
    entries: [BpfMapEntry; MAX_MAP_ENTRIES],
}

impl BpfMap {
    /// Create a new BPF map.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `key_size`,
    /// `value_size`, or `max_entries` exceed the fixed limits.
    pub fn new(key_size: usize, value_size: usize, max_entries: usize) -> Result<Self> {
        if key_size == 0
            || key_size > MAX_KEY_SIZE
            || value_size == 0
            || value_size > MAX_VALUE_SIZE
            || max_entries == 0
            || max_entries > MAX_MAP_ENTRIES
        {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            key_size,
            value_size,
            max_entries,
            entries: core::array::from_fn(|_| BpfMapEntry::default()),
        })
    }

    /// Simple hash of a key slice.
    fn hash_key(&self, key: &[u8]) -> usize {
        let mut h: u64 = 5381;
        for &b in key.iter().take(self.key_size) {
            h = h.wrapping_mul(33).wrapping_add(b as u64);
        }
        h as usize % self.max_entries
    }

    /// Look up a value by key.
    ///
    /// Returns a reference to the value bytes on success, or
    /// [`Error::NotFound`] if the key is absent.
    pub fn lookup(&self, key: &[u8]) -> Result<&[u8]> {
        if key.len() < self.key_size {
            return Err(Error::InvalidArgument);
        }
        let start = self.hash_key(key);
        for i in 0..self.max_entries {
            let idx = (start + i) % self.max_entries;
            let entry = &self.entries[idx];
            if !entry.occupied {
                return Err(Error::NotFound);
            }
            if entry.key[..self.key_size] == key[..self.key_size] {
                return Ok(&entry.value[..self.value_size]);
            }
        }
        Err(Error::NotFound)
    }

    /// Insert or update a key/value pair.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the map is full and
    /// the key does not already exist.
    pub fn update(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        if key.len() < self.key_size || value.len() < self.value_size {
            return Err(Error::InvalidArgument);
        }
        let start = self.hash_key(key);
        // First pass: look for existing key or empty slot.
        for i in 0..self.max_entries {
            let idx = (start + i) % self.max_entries;
            let entry = &self.entries[idx];
            if !entry.occupied {
                // Empty slot — insert here.
                let e = &mut self.entries[idx];
                e.key[..self.key_size].copy_from_slice(&key[..self.key_size]);
                e.value[..self.value_size].copy_from_slice(&value[..self.value_size]);
                e.occupied = true;
                return Ok(());
            }
            if entry.key[..self.key_size] == key[..self.key_size] {
                // Existing key — update value.
                let e = &mut self.entries[idx];
                e.value[..self.value_size].copy_from_slice(&value[..self.value_size]);
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Delete an entry by key.
    ///
    /// Returns [`Error::NotFound`] if the key is absent.
    pub fn delete(&mut self, key: &[u8]) -> Result<()> {
        if key.len() < self.key_size {
            return Err(Error::InvalidArgument);
        }
        let start = self.hash_key(key);
        for i in 0..self.max_entries {
            let idx = (start + i) % self.max_entries;
            let entry = &self.entries[idx];
            if !entry.occupied {
                return Err(Error::NotFound);
            }
            if entry.key[..self.key_size] == key[..self.key_size] {
                self.entries[idx].occupied = false;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }
}

// ── BpfRegistry ───────────────────────────────────────────────

/// Slot for a loaded BPF program in the registry.
#[derive(Default)]
struct BpfRegistrySlot {
    /// The loaded program.
    prog: BpfProgram,
    /// Whether this slot is occupied.
    occupied: bool,
}

/// Registry that tracks up to [`MAX_PROGRAMS`] loaded BPF
/// programs.
pub struct BpfRegistry {
    /// Program slots.
    slots: [BpfRegistrySlot; MAX_PROGRAMS],
}

impl Default for BpfRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BpfRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| BpfRegistrySlot::default()),
        }
    }

    /// Load a program into the registry.
    ///
    /// Returns the slot index on success.
    ///
    /// # Errors
    ///
    /// - [`Error::PermissionDenied`] if the program is not
    ///   verified.
    /// - [`Error::OutOfMemory`] if all slots are occupied.
    pub fn load(&mut self, prog: BpfProgram) -> Result<usize> {
        if !prog.verified {
            return Err(Error::PermissionDenied);
        }
        let idx = self
            .slots
            .iter()
            .position(|s| !s.occupied)
            .ok_or(Error::OutOfMemory)?;
        self.slots[idx].prog = prog;
        self.slots[idx].occupied = true;
        Ok(idx)
    }

    /// Unload a program by slot index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the slot is empty or
    /// out of range.
    pub fn unload(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_PROGRAMS || !self.slots[idx].occupied {
            return Err(Error::NotFound);
        }
        self.slots[idx].occupied = false;
        Ok(())
    }

    /// Get a reference to a loaded program by slot index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the slot is empty or
    /// out of range.
    pub fn get(&self, idx: usize) -> Result<&BpfProgram> {
        if idx >= MAX_PROGRAMS || !self.slots[idx].occupied {
            return Err(Error::NotFound);
        }
        Ok(&self.slots[idx].prog)
    }
}
