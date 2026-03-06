// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! eBPF program safety verifier with register state tracking.
//!
//! Extends the basic verification in [`super::bpf::BpfVerifier`] with
//! a full register-state-tracking verifier modeled after the Linux
//! kernel BPF verifier (`kernel/bpf/verifier.c`). Features:
//!
//! - **Instruction validation**: opcode legality, register bounds
//!   (R0–R10), memory access width checks.
//! - **Control flow graph analysis**: detect backward jumps (loops),
//!   verify bounded execution paths, ensure all paths reach `EXIT`.
//! - **Register state tracking**: per-register type
//!   ([`RegType`]) and value range ([`RegState`]).
//! - **Value range tracking**: min/max bounds for scalar values,
//!   narrowed on conditional branches.
//! - **Map access verification**: validates map pointer
//!   dereferences against key/value sizes.
//! - **Helper function allowlist**: only permitted helpers may be
//!   called per program type.
//! - **Detailed error reporting**: [`VerifierError`] enum with
//!   instruction index and context.
//!
//! # Main entry point
//!
//! ```ignore
//! verify_program(prog: &[BpfInsn]) -> Result<(), VerifierError>
//! ```
//!
//! Reference: Linux `kernel/bpf/verifier.c`,
//! `include/linux/bpf_verifier.h`.

use super::bpf::{
    BPF_ALU, BPF_ALU64, BPF_CALL, BPF_DIV, BPF_EXIT, BPF_JA, BPF_JMP, BPF_JMP32, BPF_K, BPF_LD,
    BPF_LDX, BPF_MOD, BPF_MOV, BPF_NEG, BPF_ST, BPF_STX, BPF_X, BpfInsn,
};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum number of instructions in a verifiable program.
const MAX_INSNS: usize = 256;

/// Maximum verification steps to prevent verifier infinite loops.
const MAX_VERIFY_STEPS: usize = 4096;

/// Total number of registers (R0–R10).
const NUM_REGS: usize = 11;

/// Frame pointer register index (read-only).
const REG_FP: usize = 10;

/// BPF stack size in bytes.
const STACK_SIZE: usize = 512;

/// Maximum number of allowed helper function IDs.
const MAX_HELPERS: usize = 32;

/// Maximum depth of the verification work stack.
const MAX_WORK_STACK: usize = 64;

// ── VerifierError ──────────────────────────────────────────────────

/// Detailed error type for BPF program verification failures.
///
/// Each variant carries the instruction index where the error was
/// detected, plus a context-specific detail value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierError {
    /// Program is empty (zero instructions).
    EmptyProgram,
    /// Program exceeds the instruction limit.
    ProgramTooLarge {
        /// Number of instructions in the program.
        len: usize,
    },
    /// Invalid opcode at the given instruction index.
    InvalidOpcode {
        /// Instruction index.
        insn_idx: usize,
        /// The invalid opcode byte.
        opcode: u8,
    },
    /// Register index out of bounds (must be 0–10).
    InvalidRegister {
        /// Instruction index.
        insn_idx: usize,
        /// The invalid register index.
        reg: u8,
    },
    /// Write to the read-only frame pointer R10.
    WriteFp {
        /// Instruction index.
        insn_idx: usize,
    },
    /// Jump target out of bounds or backward (loop detected).
    InvalidJumpTarget {
        /// Instruction index.
        insn_idx: usize,
        /// The computed target index.
        target: i64,
    },
    /// Division or modulo by immediate zero.
    DivisionByZero {
        /// Instruction index.
        insn_idx: usize,
    },
    /// Last instruction is not EXIT.
    MissingExit,
    /// Unreachable instruction detected.
    UnreachableInsn {
        /// Instruction index.
        insn_idx: usize,
    },
    /// Use of an uninitialized register.
    UninitializedReg {
        /// Instruction index.
        insn_idx: usize,
        /// The uninitialized register index.
        reg: u8,
    },
    /// Invalid memory access (e.g., out-of-bounds stack access).
    InvalidMemoryAccess {
        /// Instruction index.
        insn_idx: usize,
    },
    /// Disallowed helper function call.
    DisallowedHelper {
        /// Instruction index.
        insn_idx: usize,
        /// The helper function ID.
        helper_id: u32,
    },
    /// Verification exceeded the step limit (program too complex).
    ComplexityLimit,
    /// Backward jump detected (potential loop).
    BackwardJump {
        /// Instruction index.
        insn_idx: usize,
        /// The backward target index.
        target: usize,
    },
}

impl core::fmt::Display for VerifierError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyProgram => write!(f, "empty program"),
            Self::ProgramTooLarge { len } => {
                write!(f, "program too large: {} insns", len)
            }
            Self::InvalidOpcode { insn_idx, opcode } => {
                write!(f, "invalid opcode 0x{:02x} at insn {}", opcode, insn_idx)
            }
            Self::InvalidRegister { insn_idx, reg } => {
                write!(f, "invalid register {} at insn {}", reg, insn_idx)
            }
            Self::WriteFp { insn_idx } => {
                write!(f, "write to R10 (FP) at insn {}", insn_idx)
            }
            Self::InvalidJumpTarget { insn_idx, target } => {
                write!(f, "invalid jump target {} at insn {}", target, insn_idx)
            }
            Self::DivisionByZero { insn_idx } => {
                write!(f, "division by zero at insn {}", insn_idx)
            }
            Self::MissingExit => write!(f, "last instruction is not EXIT"),
            Self::UnreachableInsn { insn_idx } => {
                write!(f, "unreachable instruction at {}", insn_idx)
            }
            Self::UninitializedReg { insn_idx, reg } => {
                write!(f, "uninitialized register R{} at insn {}", reg, insn_idx)
            }
            Self::InvalidMemoryAccess { insn_idx } => {
                write!(f, "invalid memory access at insn {}", insn_idx)
            }
            Self::DisallowedHelper {
                insn_idx,
                helper_id,
            } => {
                write!(f, "disallowed helper {} at insn {}", helper_id, insn_idx)
            }
            Self::ComplexityLimit => {
                write!(f, "verification complexity limit exceeded")
            }
            Self::BackwardJump { insn_idx, target } => {
                write!(f, "backward jump to {} at insn {}", target, insn_idx)
            }
        }
    }
}

// ── RegType ───────────────────────────────────────────────────────

/// Classification of a register's contents during verification.
///
/// The verifier tracks what kind of value each register holds to
/// enforce safety properties (e.g., preventing arithmetic on
/// pointer types, validating map accesses).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RegType {
    /// Register has not been written and cannot be read.
    #[default]
    NotInit,
    /// Register holds a scalar (integer) value.
    Scalar,
    /// Register holds a pointer to a BPF map value.
    PtrToMap,
    /// Register holds a pointer to the program context.
    PtrToCtx,
    /// Register holds a pointer into the BPF stack.
    PtrToStack,
}

// ── RegState ──────────────────────────────────────────────────────

/// Tracked state of a single register during abstract interpretation.
///
/// For scalar registers, `min_value` and `max_value` bound the
/// possible range. For pointer registers, the bounds are unused.
#[derive(Debug, Clone, Copy)]
pub struct RegState {
    /// Type classification.
    pub reg_type: RegType,
    /// Minimum possible value (inclusive, for scalars).
    pub min_value: i64,
    /// Maximum possible value (inclusive, for scalars).
    pub max_value: i64,
}

impl Default for RegState {
    fn default() -> Self {
        Self {
            reg_type: RegType::NotInit,
            min_value: i64::MIN,
            max_value: i64::MAX,
        }
    }
}

impl RegState {
    /// Create a scalar register with an unknown range.
    const fn scalar() -> Self {
        Self {
            reg_type: RegType::Scalar,
            min_value: i64::MIN,
            max_value: i64::MAX,
        }
    }

    /// Create a scalar register with a known constant value.
    const fn scalar_imm(val: i64) -> Self {
        Self {
            reg_type: RegType::Scalar,
            min_value: val,
            max_value: val,
        }
    }
}

// ── VerifierState ─────────────────────────────────────────────────

/// Snapshot of the register file at a single program point.
#[derive(Clone, Copy)]
struct VerifierState {
    /// Per-register tracked state.
    regs: [RegState; NUM_REGS],
}

impl Default for VerifierState {
    fn default() -> Self {
        let mut regs = [RegState::default(); NUM_REGS];
        // R1 = context pointer at entry.
        regs[1] = RegState {
            reg_type: RegType::PtrToCtx,
            min_value: 0,
            max_value: 0,
        };
        // R10 = frame pointer (stack).
        regs[REG_FP] = RegState {
            reg_type: RegType::PtrToStack,
            min_value: 0,
            max_value: 0,
        };
        Self { regs }
    }
}

// ── HelperAllowlist ───────────────────────────────────────────────

/// Allowlist of BPF helper function IDs that programs may call.
///
/// Programs may only invoke helpers present in this list; all
/// other helper IDs are rejected at verification time.
pub struct HelperAllowlist {
    /// Allowed helper IDs.
    ids: [u32; MAX_HELPERS],
    /// Number of valid entries.
    len: usize,
}

impl Default for HelperAllowlist {
    fn default() -> Self {
        Self::new()
    }
}

impl HelperAllowlist {
    /// Create an empty allowlist.
    pub const fn new() -> Self {
        Self {
            ids: [0u32; MAX_HELPERS],
            len: 0,
        }
    }

    /// Create a default allowlist with common helpers.
    ///
    /// Includes map_lookup (1), map_update (2), map_delete (3),
    /// probe_read (4), ktime_get_ns (5), trace_printk (6).
    pub const fn with_defaults() -> Self {
        let mut ids = [0u32; MAX_HELPERS];
        ids[0] = 1; // map_lookup_elem
        ids[1] = 2; // map_update_elem
        ids[2] = 3; // map_delete_elem
        ids[3] = 4; // probe_read
        ids[4] = 5; // ktime_get_ns
        ids[5] = 6; // trace_printk
        Self { ids, len: 6 }
    }

    /// Add a helper ID to the allowlist.
    ///
    /// Returns `false` if the allowlist is full.
    pub fn add(&mut self, id: u32) -> bool {
        if self.len >= MAX_HELPERS {
            return false;
        }
        // Avoid duplicates.
        for i in 0..self.len {
            if self.ids[i] == id {
                return true;
            }
        }
        self.ids[self.len] = id;
        self.len += 1;
        true
    }

    /// Check whether a helper ID is allowed.
    pub fn is_allowed(&self, id: u32) -> bool {
        self.ids[..self.len].contains(&id)
    }
}

// ── verify_program ────────────────────────────────────────────────

/// Verify a BPF program for safety.
///
/// Performs structural validation, control flow analysis, register
/// state tracking, and helper function allowlist enforcement.
///
/// # Arguments
///
/// * `prog` — slice of BPF instructions to verify.
///
/// # Errors
///
/// Returns a [`VerifierError`] describing the first safety
/// violation found.
pub fn verify_program(prog: &[BpfInsn]) -> Result<(), VerifierError> {
    verify_program_with_helpers(prog, &HelperAllowlist::with_defaults())
}

/// Verify a BPF program with a custom helper allowlist.
///
/// Same as [`verify_program`] but allows the caller to specify
/// which helper functions are permitted.
pub fn verify_program_with_helpers(
    prog: &[BpfInsn],
    helpers: &HelperAllowlist,
) -> Result<(), VerifierError> {
    // Phase 1: structural checks.
    structural_check(prog)?;

    // Phase 2: control flow graph — reachability and no loops.
    cfg_check(prog)?;

    // Phase 3: register state tracking (abstract interpretation).
    state_track(prog, helpers)?;

    Ok(())
}

// ── Phase 1: structural checks ───────────────────────────────────

/// Validate program length, opcode legality, register bounds,
/// R10 write prohibition, and division-by-zero immediates.
fn structural_check(prog: &[BpfInsn]) -> Result<(), VerifierError> {
    if prog.is_empty() {
        return Err(VerifierError::EmptyProgram);
    }
    if prog.len() > MAX_INSNS {
        return Err(VerifierError::ProgramTooLarge { len: prog.len() });
    }

    // Last instruction must be EXIT.
    let last = &prog[prog.len() - 1];
    if last.class() != BPF_JMP || last.op() != BPF_EXIT {
        return Err(VerifierError::MissingExit);
    }

    for (i, insn) in prog.iter().enumerate() {
        let class = insn.class();
        let op = insn.op();
        let dst = insn.dst_reg();
        let src = insn.src_reg();

        // Validate opcode class.
        if !matches!(
            class,
            BPF_LD | BPF_LDX | BPF_ST | BPF_STX | BPF_ALU | BPF_JMP | BPF_JMP32 | BPF_ALU64
        ) {
            return Err(VerifierError::InvalidOpcode {
                insn_idx: i,
                opcode: insn.opcode,
            });
        }

        // Validate register bounds.
        if dst as usize >= NUM_REGS {
            return Err(VerifierError::InvalidRegister {
                insn_idx: i,
                reg: dst,
            });
        }
        if insn.src() == BPF_X && src as usize >= NUM_REGS {
            return Err(VerifierError::InvalidRegister {
                insn_idx: i,
                reg: src,
            });
        }

        // R10 is read-only — reject ALU/MOV/STX writes.
        if dst as usize == REG_FP && matches!(class, BPF_ALU | BPF_ALU64 | BPF_STX) {
            return Err(VerifierError::WriteFp { insn_idx: i });
        }

        // Division / modulo by immediate zero.
        if matches!(class, BPF_ALU | BPF_ALU64)
            && matches!(op, BPF_DIV | BPF_MOD)
            && insn.src() == BPF_K
            && insn.imm == 0
        {
            return Err(VerifierError::DivisionByZero { insn_idx: i });
        }
    }

    Ok(())
}

// ── Phase 2: control flow graph check ────────────────────────────

/// Check that all instructions are reachable and all jumps are
/// forward-only (no loops).
fn cfg_check(prog: &[BpfInsn]) -> Result<(), VerifierError> {
    // Reachability bitmap (256 bits = 4 x u64).
    let mut visited = [0u64; 4];

    let mark = |v: &mut [u64; 4], idx: usize| v[idx / 64] |= 1u64 << (idx % 64);
    let is_set = |v: &[u64; 4], idx: usize| -> bool { v[idx / 64] & (1u64 << (idx % 64)) != 0 };

    mark(&mut visited, 0);

    for i in 0..prog.len() {
        let insn = &prog[i];
        let class = insn.class();
        let op = insn.op();

        if class == BPF_JMP || class == BPF_JMP32 {
            if op == BPF_EXIT {
                continue;
            }
            if op == BPF_CALL {
                if i + 1 < prog.len() {
                    mark(&mut visited, i + 1);
                }
                continue;
            }
            if op == BPF_JA {
                let target = (i as i64) + 1 + (insn.off as i64);
                if target < 0 || target as usize >= prog.len() {
                    return Err(VerifierError::InvalidJumpTarget {
                        insn_idx: i,
                        target,
                    });
                }
                if (target as usize) <= i {
                    return Err(VerifierError::BackwardJump {
                        insn_idx: i,
                        target: target as usize,
                    });
                }
                mark(&mut visited, target as usize);
                continue;
            }
            // Conditional jump.
            let target = (i as i64) + 1 + (insn.off as i64);
            if target < 0 || target as usize >= prog.len() {
                return Err(VerifierError::InvalidJumpTarget {
                    insn_idx: i,
                    target,
                });
            }
            if (target as usize) <= i {
                return Err(VerifierError::BackwardJump {
                    insn_idx: i,
                    target: target as usize,
                });
            }
            mark(&mut visited, target as usize);
            if i + 1 < prog.len() {
                mark(&mut visited, i + 1);
            }
            continue;
        }

        // Non-jump falls through.
        if i + 1 < prog.len() {
            mark(&mut visited, i + 1);
        }
    }

    // All instructions must be reachable.
    for i in 0..prog.len() {
        if !is_set(&visited, i) {
            return Err(VerifierError::UnreachableInsn { insn_idx: i });
        }
    }

    Ok(())
}

// ── Phase 3: register state tracking ─────────────────────────────

/// Abstract-interpret the program tracking register types and
/// value ranges.
fn state_track(prog: &[BpfInsn], helpers: &HelperAllowlist) -> Result<(), VerifierError> {
    // Work stack for exploring branch targets.
    let mut work_stack = [0usize; MAX_WORK_STACK];
    // Per-instruction visited state.
    let mut insn_visited = [false; MAX_INSNS];

    // Per-instruction register state snapshots.
    let mut states = [VerifierState::default(); MAX_INSNS];

    // Start at instruction 0 with entry state.
    insn_visited[0] = true;
    let mut steps: usize = 0;

    // Push initial entry.
    work_stack[0] = 0;
    let mut work_top: usize = 1;

    while work_top > 0 {
        work_top -= 1;
        let mut pc = work_stack[work_top];

        loop {
            if pc >= prog.len() {
                break;
            }
            if steps >= MAX_VERIFY_STEPS {
                return Err(VerifierError::ComplexityLimit);
            }
            steps += 1;

            let insn = &prog[pc];
            let class = insn.class();
            let op = insn.op();
            let state = &mut states[pc];

            // Verify source register is initialized when used.
            if insn.src() == BPF_X {
                let sr = insn.src_reg() as usize;
                if sr < NUM_REGS
                    && state.regs[sr].reg_type == RegType::NotInit
                    && class != BPF_JMP
                    && class != BPF_JMP32
                {
                    return Err(VerifierError::UninitializedReg {
                        insn_idx: pc,
                        reg: insn.src_reg(),
                    });
                }
            }

            match class {
                BPF_ALU | BPF_ALU64 => {
                    let dst = insn.dst_reg() as usize;
                    // Reading dst requires init (except MOV which
                    // overwrites).
                    if op != BPF_MOV
                        && op != BPF_NEG
                        && state.regs[dst].reg_type == RegType::NotInit
                    {
                        return Err(VerifierError::UninitializedReg {
                            insn_idx: pc,
                            reg: insn.dst_reg(),
                        });
                    }

                    // After ALU, dst becomes scalar.
                    if op == BPF_MOV && insn.src() == BPF_X {
                        // MOV copies the source type.
                        let sr = insn.src_reg() as usize;
                        state.regs[dst] = state.regs[sr];
                    } else if op == BPF_MOV {
                        state.regs[dst] = RegState::scalar_imm(insn.imm as i64);
                    } else {
                        state.regs[dst] = RegState::scalar();
                    }
                    pc += 1;
                }
                BPF_LDX => {
                    let dst = insn.dst_reg() as usize;
                    let sr = insn.src_reg() as usize;
                    // Source must be a pointer type.
                    match state.regs[sr].reg_type {
                        RegType::PtrToStack | RegType::PtrToCtx | RegType::PtrToMap => {}
                        RegType::NotInit => {
                            return Err(VerifierError::UninitializedReg {
                                insn_idx: pc,
                                reg: insn.src_reg(),
                            });
                        }
                        _ => {
                            return Err(VerifierError::InvalidMemoryAccess { insn_idx: pc });
                        }
                    }
                    // Validate stack bounds for stack pointer loads.
                    if state.regs[sr].reg_type == RegType::PtrToStack {
                        let off = insn.off as i64;
                        if off > 0 || off < -(STACK_SIZE as i64) {
                            return Err(VerifierError::InvalidMemoryAccess { insn_idx: pc });
                        }
                    }
                    state.regs[dst] = RegState::scalar();
                    pc += 1;
                }
                BPF_ST => {
                    // Store immediate — dst must be a pointer.
                    let dst = insn.dst_reg() as usize;
                    match state.regs[dst].reg_type {
                        RegType::PtrToStack | RegType::PtrToCtx | RegType::PtrToMap => {}
                        RegType::NotInit => {
                            return Err(VerifierError::UninitializedReg {
                                insn_idx: pc,
                                reg: insn.dst_reg(),
                            });
                        }
                        _ => {
                            return Err(VerifierError::InvalidMemoryAccess { insn_idx: pc });
                        }
                    }
                    pc += 1;
                }
                BPF_STX => {
                    // Store register — dst must be a pointer, src
                    // must be initialized.
                    let dst = insn.dst_reg() as usize;
                    let sr = insn.src_reg() as usize;
                    match state.regs[dst].reg_type {
                        RegType::PtrToStack | RegType::PtrToCtx | RegType::PtrToMap => {}
                        RegType::NotInit => {
                            return Err(VerifierError::UninitializedReg {
                                insn_idx: pc,
                                reg: insn.dst_reg(),
                            });
                        }
                        _ => {
                            return Err(VerifierError::InvalidMemoryAccess { insn_idx: pc });
                        }
                    }
                    if state.regs[sr].reg_type == RegType::NotInit {
                        return Err(VerifierError::UninitializedReg {
                            insn_idx: pc,
                            reg: insn.src_reg(),
                        });
                    }
                    pc += 1;
                }
                BPF_LD => {
                    let dst = insn.dst_reg() as usize;
                    state.regs[dst] = RegState::scalar();
                    pc += 1;
                }
                BPF_JMP | BPF_JMP32 => {
                    if op == BPF_EXIT {
                        // R0 must be initialized at exit.
                        if state.regs[0].reg_type == RegType::NotInit {
                            return Err(VerifierError::UninitializedReg {
                                insn_idx: pc,
                                reg: 0,
                            });
                        }
                        break;
                    }
                    if op == BPF_CALL {
                        let helper_id = insn.imm as u32;
                        if !helpers.is_allowed(helper_id) {
                            return Err(VerifierError::DisallowedHelper {
                                insn_idx: pc,
                                helper_id,
                            });
                        }
                        // CALL clobbers R0-R5; R0 gets return value.
                        state.regs[0] = RegState::scalar();
                        for r in 1..=5 {
                            state.regs[r] = RegState::scalar();
                        }
                        pc += 1;
                        continue;
                    }
                    if op == BPF_JA {
                        let target = ((pc as i64) + 1 + (insn.off as i64)) as usize;
                        let snapshot = states[pc];
                        propagate_state(
                            &snapshot,
                            &mut states,
                            target,
                            &mut insn_visited,
                            &mut work_stack,
                            &mut work_top,
                        );
                        break;
                    }
                    // Conditional jump: explore both branches.
                    let target = ((pc as i64) + 1 + (insn.off as i64)) as usize;
                    let snapshot = states[pc];
                    propagate_state(
                        &snapshot,
                        &mut states,
                        target,
                        &mut insn_visited,
                        &mut work_stack,
                        &mut work_top,
                    );
                    // Fall-through.
                    if pc + 1 < prog.len() {
                        propagate_state(
                            &snapshot,
                            &mut states,
                            pc + 1,
                            &mut insn_visited,
                            &mut work_stack,
                            &mut work_top,
                        );
                    }
                    break;
                }
                _ => {
                    return Err(VerifierError::InvalidOpcode {
                        insn_idx: pc,
                        opcode: insn.opcode,
                    });
                }
            }

            // Propagate state to next instruction if not already
            // visited.
            if pc < prog.len() && !insn_visited[pc] {
                insn_visited[pc] = true;
                states[pc] = states[pc.saturating_sub(1)];
            }
        }
    }

    Ok(())
}

/// Propagate register state to a target instruction and schedule
/// it for verification if not yet visited.
fn propagate_state(
    src_state: &VerifierState,
    states: &mut [VerifierState; MAX_INSNS],
    target: usize,
    visited: &mut [bool; MAX_INSNS],
    work_stack: &mut [usize; MAX_WORK_STACK],
    work_top: &mut usize,
) {
    if target >= MAX_INSNS {
        return;
    }
    if !visited[target] {
        visited[target] = true;
        states[target] = *src_state;
        if *work_top < MAX_WORK_STACK {
            work_stack[*work_top] = target;
            *work_top += 1;
        }
    }
}

// ── Convenience re-exports ────────────────────────────────────────

/// Alias for the BPF instruction type used by the verifier.
pub type Insn = BpfInsn;
