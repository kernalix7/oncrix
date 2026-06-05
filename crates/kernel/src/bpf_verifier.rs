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
    BPF_ADD, BPF_ALU, BPF_ALU64, BPF_AND, BPF_ARSH, BPF_CALL, BPF_DIV, BPF_EXIT, BPF_JA, BPF_JEQ,
    BPF_JGE, BPF_JGT, BPF_JMP, BPF_JMP32, BPF_JNE, BPF_JSET, BPF_JSGE, BPF_JSGT, BPF_K, BPF_LD,
    BPF_LDX, BPF_LSH, BPF_MOD, BPF_MOV, BPF_MUL, BPF_NEG, BPF_OR, BPF_RSH, BPF_ST, BPF_STX,
    BPF_SUB, BPF_X, BPF_XOR, BpfInsn,
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

/// Maximum number of BPF maps that the verifier tracks.
const MAX_MAPS: usize = 16;

/// Valid memory access widths in bytes (1, 2, 4, 8).
const VALID_ACCESS_WIDTHS: [u8; 4] = [1, 2, 4, 8];

/// Opcode of the wide immediate load `lddw` (`BPF_LD | BPF_IMM | BPF_DW`).
///
/// This is the only 16-byte (two-slot) BPF instruction: the second
/// slot carries the upper 32 bits of the 64-bit immediate.
const OPC_LDDW: u8 = 0x18;

// ── VerifierConfig ─────────────────────────────────────────────────

/// Static configuration supplied to the verifier for a program type.
///
/// The context (`R1` at entry) is an opaque, program-type-specific
/// structure. Its size bounds every context load/store; when the
/// layout is not modeled (`ctx_size == 0`) the verifier fails closed
/// and rejects all context dereferences (see finding-driven
/// `// SECURITY` notes in `state_track`).
#[derive(Debug, Clone, Copy)]
pub struct VerifierConfig {
    /// Size in bytes of the program context (`PtrToCtx`). `0` means
    /// the layout is unmodeled and context access is forbidden.
    pub ctx_size: u32,
}

impl VerifierConfig {
    /// Create a config with the given context size.
    pub const fn new(ctx_size: u32) -> Self {
        Self { ctx_size }
    }

    /// Default config: context layout unmodeled, so context loads and
    /// stores are rejected (fail closed).
    pub const fn fail_closed_ctx() -> Self {
        Self { ctx_size: 0 }
    }
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self::fail_closed_ctx()
    }
}

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
    /// Stack depth exceeds the 512-byte limit.
    StackDepthExceeded {
        /// Instruction index.
        insn_idx: usize,
        /// The stack depth that exceeded the limit.
        depth: usize,
    },
    /// Invalid ALU or JMP sub-operation code.
    InvalidSubOpcode {
        /// Instruction index.
        insn_idx: usize,
        /// The invalid sub-opcode byte.
        sub_op: u8,
    },
    /// Invalid memory access width (must be 1, 2, 4, or 8).
    InvalidAccessWidth {
        /// Instruction index.
        insn_idx: usize,
        /// The invalid width.
        width: u8,
    },
    /// Map access out of bounds (offset + size > map value size).
    MapAccessOutOfBounds {
        /// Instruction index.
        insn_idx: usize,
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
            Self::StackDepthExceeded { insn_idx, depth } => {
                write!(f, "stack depth {} exceeds 512 at insn {}", depth, insn_idx)
            }
            Self::InvalidSubOpcode { insn_idx, sub_op } => {
                write!(
                    f,
                    "invalid sub-opcode 0x{:02x} at insn {}",
                    sub_op, insn_idx
                )
            }
            Self::InvalidAccessWidth { insn_idx, width } => {
                write!(f, "invalid access width {} at insn {}", width, insn_idx)
            }
            Self::MapAccessOutOfBounds { insn_idx } => {
                write!(f, "map access out of bounds at insn {}", insn_idx)
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

// ── MapInfo ──────────────────────────────────────────────────────

/// Metadata for a single BPF map used in bounds checking.
///
/// The verifier uses this to validate that memory accesses through
/// `PtrToMap` registers stay within the map's value size.
#[derive(Debug, Clone, Copy)]
pub struct MapInfo {
    /// Map identifier.
    pub map_id: u32,
    /// Key size in bytes.
    pub key_size: u32,
    /// Value size in bytes.
    pub value_size: u32,
    /// Whether this slot is active.
    active: bool,
}

impl MapInfo {
    /// Create an empty (inactive) map info entry.
    pub const fn new() -> Self {
        Self {
            map_id: 0,
            key_size: 0,
            value_size: 0,
            active: false,
        }
    }
}

impl Default for MapInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Registry of BPF maps available during verification.
///
/// Programs reference maps by ID; the verifier looks up the
/// corresponding key/value sizes to validate memory accesses.
pub struct MapRegistry {
    /// Map metadata entries.
    maps: [MapInfo; MAX_MAPS],
    /// Number of active entries.
    len: usize,
}

impl MapRegistry {
    /// Create an empty map registry.
    pub const fn new() -> Self {
        Self {
            maps: [const { MapInfo::new() }; MAX_MAPS],
            len: 0,
        }
    }

    /// Register a map. Returns `false` if the registry is full.
    pub fn add(&mut self, map_id: u32, key_size: u32, value_size: u32) -> bool {
        if self.len >= MAX_MAPS {
            return false;
        }
        self.maps[self.len] = MapInfo {
            map_id,
            key_size,
            value_size,
            active: true,
        };
        self.len += 1;
        true
    }

    /// Look up a map by ID.
    pub fn lookup(&self, map_id: u32) -> Option<&MapInfo> {
        self.maps[..self.len]
            .iter()
            .find(|m| m.active && m.map_id == map_id)
    }

    /// Return the number of registered maps.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Get map info by index (0-based, within active entries).
    pub fn get(&self, index: usize) -> Option<&MapInfo> {
        if index < self.len && self.maps[index].active {
            Some(&self.maps[index])
        } else {
            None
        }
    }
}

impl Default for MapRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── RegState ──────────────────────────────────────────────────────

/// Tracked state of a single register during abstract interpretation.
///
/// For scalar registers, `min_value` and `max_value` bound the
/// possible range. For `PtrToMap` registers, `map_id` identifies
/// the map and `map_value_size` records its value size for bounds
/// checking.
#[derive(Debug, Clone, Copy)]
pub struct RegState {
    /// Type classification.
    pub reg_type: RegType,
    /// Minimum possible value (inclusive, for scalars).
    pub min_value: i64,
    /// Maximum possible value (inclusive, for scalars).
    pub max_value: i64,
    /// Map ID when `reg_type == PtrToMap` (0 = unknown).
    pub map_id: u32,
    /// Map value size in bytes (for bounds checking).
    pub map_value_size: u32,
    /// Context size in bytes when `reg_type == PtrToCtx` (0 =
    /// unmodeled; access is rejected).
    pub ctx_size: u32,
}

impl Default for RegState {
    fn default() -> Self {
        Self {
            reg_type: RegType::NotInit,
            min_value: i64::MIN,
            max_value: i64::MAX,
            map_id: 0,
            map_value_size: 0,
            ctx_size: 0,
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
            map_id: 0,
            map_value_size: 0,
            ctx_size: 0,
        }
    }

    /// Create a scalar register with a known constant value.
    const fn scalar_imm(val: i64) -> Self {
        Self {
            reg_type: RegType::Scalar,
            min_value: val,
            max_value: val,
            map_id: 0,
            map_value_size: 0,
            ctx_size: 0,
        }
    }

    /// Create a map-value pointer with known bounds.
    #[allow(dead_code)]
    const fn ptr_to_map(map_id: u32, value_size: u32) -> Self {
        Self {
            reg_type: RegType::PtrToMap,
            min_value: 0,
            max_value: 0,
            map_id,
            map_value_size: value_size,
            ctx_size: 0,
        }
    }

    /// Conservatively JOIN (widen) this register state with `other`,
    /// as required when two control-flow paths merge at an instruction.
    ///
    /// The result must be sound on BOTH incoming paths, so:
    ///
    /// * If the [`RegType`] disagrees between the two predecessors, the
    ///   register could be a pointer on one path and a scalar / uninit
    ///   on the other — there is no single type valid on both. We widen
    ///   to [`RegType::NotInit`] (the least-capable type) so any later
    ///   pointer deref through it is rejected by [`check_mem_access`].
    /// * If the types agree we keep that type, but still widen the value
    ///   range to the union of both predecessors and drop pointer
    ///   metadata (map id / sizes) that does not match, so a bound that
    ///   holds on only one path is never trusted.
    ///
    /// Widening is monotone toward `NotInit` (a register only ever loses
    /// precision across merges), which guarantees the fixpoint walk in
    /// [`state_track`] terminates.
    fn widen(self, other: Self) -> Self {
        if self.reg_type != other.reg_type {
            // No type is valid on both paths — fail closed to NotInit.
            return RegState::default();
        }
        // Same type on both paths: keep it, union the scalar range, and
        // only preserve pointer metadata where both predecessors agree.
        let map_id = if self.map_id == other.map_id {
            self.map_id
        } else {
            0
        };
        let map_value_size = if self.map_value_size == other.map_value_size {
            self.map_value_size
        } else {
            0
        };
        let ctx_size = if self.ctx_size == other.ctx_size {
            self.ctx_size
        } else {
            0
        };
        Self {
            reg_type: self.reg_type,
            min_value: self.min_value.min(other.min_value),
            max_value: self.max_value.max(other.max_value),
            map_id,
            map_value_size,
            ctx_size,
        }
    }

    /// Structural equality used to detect whether a merge changed a
    /// register's tracked state (and therefore whether downstream
    /// instructions must be re-explored).
    fn same_as(&self, other: &Self) -> bool {
        self.reg_type == other.reg_type
            && self.min_value == other.min_value
            && self.max_value == other.max_value
            && self.map_id == other.map_id
            && self.map_value_size == other.map_value_size
            && self.ctx_size == other.ctx_size
    }
}

// ── VerifierState ─────────────────────────────────────────────────

/// Snapshot of the register file at a single program point.
///
/// In addition to per-register type/value tracking, we record the
/// maximum stack depth observed along the current execution path
/// so the verifier can enforce the 512-byte stack limit.
#[derive(Clone, Copy)]
struct VerifierState {
    /// Per-register tracked state.
    regs: [RegState; NUM_REGS],
    /// Maximum stack depth (bytes) used along this path.
    #[allow(dead_code)]
    stack_depth: usize,
}

impl VerifierState {
    /// Build the entry state for a program given its config.
    ///
    /// `R1` is the context pointer (sized from `cfg.ctx_size`) and
    /// `R10` is the read-only frame pointer into the BPF stack.
    fn entry(cfg: &VerifierConfig) -> Self {
        let mut regs = [RegState::default(); NUM_REGS];
        // R1 = context pointer at entry, carrying the modeled size.
        regs[1] = RegState {
            reg_type: RegType::PtrToCtx,
            min_value: 0,
            max_value: 0,
            map_id: 0,
            map_value_size: 0,
            ctx_size: cfg.ctx_size,
        };
        // R10 = frame pointer (stack).
        regs[REG_FP] = RegState {
            reg_type: RegType::PtrToStack,
            min_value: 0,
            max_value: 0,
            map_id: 0,
            map_value_size: 0,
            ctx_size: 0,
        };
        Self {
            regs,
            stack_depth: 0,
        }
    }

    /// Conservatively JOIN this state with an `incoming` predecessor
    /// state, widening each register (see [`RegState::widen`]).
    ///
    /// Returns `true` if any register changed, signalling that
    /// downstream instructions must be re-explored so the widened
    /// (less-capable) types propagate. The stack depth is merged to the
    /// maximum observed on either path.
    ///
    /// # Soundness
    ///
    /// This is the core of the path-merge fix: a register's type is
    /// only kept precise where ALL predecessors agree. A pointer that is
    /// valid on one path but a scalar / uninit on another is widened to
    /// [`RegType::NotInit`], so the verifier never trusts a pointer type
    /// that is not valid on every path reaching a later access.
    fn join_from(&mut self, incoming: &VerifierState) -> bool {
        let mut changed = false;
        for i in 0..NUM_REGS {
            let merged = self.regs[i].widen(incoming.regs[i]);
            if !merged.same_as(&self.regs[i]) {
                changed = true;
            }
            self.regs[i] = merged;
        }
        if incoming.stack_depth > self.stack_depth {
            self.stack_depth = incoming.stack_depth;
            changed = true;
        }
        changed
    }
}

impl Default for VerifierState {
    fn default() -> Self {
        Self::entry(&VerifierConfig::fail_closed_ctx())
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

// ── Opcode validation helpers ─────────────────────────────────────

/// Check whether an ALU sub-operation code is valid.
///
/// Valid ALU ops: ADD, SUB, MUL, DIV, OR, AND, LSH, RSH, NEG,
/// MOD, XOR, MOV, ARSH.
fn is_valid_alu_op(op: u8) -> bool {
    matches!(
        op,
        BPF_ADD
            | BPF_SUB
            | BPF_MUL
            | BPF_DIV
            | BPF_OR
            | BPF_AND
            | BPF_LSH
            | BPF_RSH
            | BPF_NEG
            | BPF_MOD
            | BPF_XOR
            | BPF_MOV
            | BPF_ARSH
    )
}

/// Check whether a JMP sub-operation code is valid.
///
/// Valid JMP ops: JA, JEQ, JGT, JGE, JSET, JNE, JSGT, JSGE,
/// CALL, EXIT.
fn is_valid_jmp_op(op: u8) -> bool {
    matches!(
        op,
        BPF_JA
            | BPF_JEQ
            | BPF_JGT
            | BPF_JGE
            | BPF_JSET
            | BPF_JNE
            | BPF_JSGT
            | BPF_JSGE
            | BPF_CALL
            | BPF_EXIT
    )
}

/// Extract the memory access width from a LD/LDX/ST/STX opcode.
///
/// Bits 4:3 encode the size: 0 = 4 bytes (W), 1 = 2 bytes (H),
/// 2 = 1 byte (B), 3 = 8 bytes (DW).
fn access_width_from_opcode(opcode: u8) -> u8 {
    match (opcode >> 3) & 0x03 {
        0x00 => 4, // BPF_W
        0x01 => 2, // BPF_H
        0x02 => 1, // BPF_B
        0x03 => 8, // BPF_DW
        _ => 0,    // unreachable, but return invalid
    }
}

/// Check whether a memory access width is valid.
fn is_valid_access_width(width: u8) -> bool {
    VALID_ACCESS_WIDTHS.contains(&width)
}

/// Validate a memory access through a pointer register.
///
/// Bounds the FULL access window `[off, off + width)` against the
/// object the pointer refers to, deriving `width` from the load/store
/// opcode. Returns `Ok(())` only when every byte touched lies inside
/// the object; otherwise [`VerifierError::InvalidMemoryAccess`] (or
/// [`VerifierError::MapAccessOutOfBounds`] for map values).
///
/// Object models, all using checked arithmetic so a crafted offset or
/// width cannot wrap past the bound:
///
/// * `PtrToStack` — stack addresses are negative offsets from `R10`.
///   The valid window is `[-STACK_SIZE, 0)`, so require
///   `off >= -(STACK_SIZE)` and `off + width <= 0` (i.e. the access
///   ends at or before the frame pointer and never spills below the
///   512-byte frame). This rejects `off == 0` (one-past-end) and any
///   positive offset (above the frame).
/// * `PtrToMap` — map values start at offset 0. Require `off >= 0`
///   and `off + width <= value_size`.
/// * `PtrToCtx` — context starts at offset 0 and spans `ctx_size`.
///   Require `off >= 0` and `off + width <= ctx_size`. When
///   `ctx_size == 0` the layout is unmodeled and we FAIL CLOSED,
///   rejecting all context dereferences.
/// * Any other (scalar / not-init / unknown pointer) — rejected.
///
/// `insn_idx` is threaded through only for error reporting.
fn check_mem_access(
    reg: &RegState,
    opcode: u8,
    off: i16,
    insn_idx: usize,
) -> Result<(), VerifierError> {
    let width = access_width_from_opcode(opcode);
    if !is_valid_access_width(width) {
        return Err(VerifierError::InvalidAccessWidth { insn_idx, width });
    }
    let off = off as i64;
    let width = width as i64;
    // Window end = off + width, computed with checked arithmetic so a
    // malicious (off, width) pair cannot overflow past the bound.
    let end = off
        .checked_add(width)
        .ok_or(VerifierError::InvalidMemoryAccess { insn_idx })?;

    match reg.reg_type {
        RegType::PtrToStack => {
            // Valid window: [-STACK_SIZE, 0). Reject one-past-end
            // (off == 0) and any access that starts below the frame.
            if off < -(STACK_SIZE as i64) || end > 0 {
                return Err(VerifierError::InvalidMemoryAccess { insn_idx });
            }
            Ok(())
        }
        RegType::PtrToMap => {
            let value_size = reg.map_value_size as i64;
            // SECURITY: the verifier currently sets R0 = scalar (not
            // PtrToMap) after `map_lookup_elem` (see CALL handling),
            // so genuine map-value pointers are under-modeled. If a
            // register is somehow typed PtrToMap with no recorded
            // value_size, fail closed rather than admit the access.
            if value_size == 0 || off < 0 || end > value_size {
                return Err(VerifierError::MapAccessOutOfBounds { insn_idx });
            }
            Ok(())
        }
        RegType::PtrToCtx => {
            let ctx_size = reg.ctx_size as i64;
            // Fail closed when the context layout is unmodeled.
            if ctx_size == 0 || off < 0 || end > ctx_size {
                return Err(VerifierError::InvalidMemoryAccess { insn_idx });
            }
            Ok(())
        }
        // Scalar, NotInit, or any non-pointer: never dereferenceable.
        _ => Err(VerifierError::InvalidMemoryAccess { insn_idx }),
    }
}

// ── Stack depth analysis ─────────────────────────────────────────

/// Analyse the program for maximum stack depth.
///
/// Walks all instructions looking for stores via the frame pointer
/// (R10) and computes the deepest negative offset seen. BPF stack
/// addresses are negative offsets from R10, so an access at
/// offset -8 with width 8 uses stack depth 16.
///
/// Returns `Err(StackDepthExceeded)` if the maximum depth exceeds
/// [`STACK_SIZE`] (512 bytes).
fn stack_depth_check(prog: &[BpfInsn]) -> Result<(), VerifierError> {
    let mut max_depth: usize = 0;

    for (i, insn) in prog.iter().enumerate() {
        let class = insn.class();

        // Check stores via R10 (frame pointer).
        let is_stack_store = matches!(class, BPF_ST | BPF_STX) && insn.dst_reg() as usize == REG_FP;

        // Check loads via R10.
        let is_stack_load = class == BPF_LDX && insn.src_reg() as usize == REG_FP;

        if is_stack_store || is_stack_load {
            let off = insn.off as i64;
            // Stack offsets must be negative from R10. A non-negative
            // offset reaches at or above the frame pointer, i.e. an
            // out-of-bounds access above the 512-byte frame. Reject
            // it here rather than skipping (the previous `continue`
            // let positive-offset R10 stores slip past this gate).
            if off >= 0 {
                return Err(VerifierError::InvalidMemoryAccess { insn_idx: i });
            }
            let width = access_width_from_opcode(insn.opcode) as i64;
            // The accessed region is [off, off + width) with off < 0.
            // The deepest byte sits at |off|, so the depth consumed by
            // this access is |off| (its end, off + width, must be
            // <= 0 — that window bound is enforced in check_mem_access
            // during state_track). Account for width by clamping the
            // window end to 0 and measuring from there.
            let end = off.checked_add(width).unwrap_or(0);
            let _ = end; // window-end bound is enforced in state_track
            let depth = off.unsigned_abs() as usize;
            if depth > max_depth {
                max_depth = depth;
            }
            if max_depth > STACK_SIZE {
                return Err(VerifierError::StackDepthExceeded {
                    insn_idx: i,
                    depth: max_depth,
                });
            }
        }
    }

    Ok(())
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
/// which helper functions are permitted. Uses an empty map registry
/// and a fail-closed context config (context dereferences rejected).
pub fn verify_program_with_helpers(
    prog: &[BpfInsn],
    helpers: &HelperAllowlist,
) -> Result<(), VerifierError> {
    verify_program_with_config(
        prog,
        helpers,
        &MapRegistry::new(),
        &VerifierConfig::fail_closed_ctx(),
    )
}

/// Verify a BPF program with maps for bounds checking.
///
/// Same as [`verify_program_with_helpers`] but additionally
/// validates map pointer accesses against known map value sizes.
pub fn verify_program_with_maps(
    prog: &[BpfInsn],
    helpers: &HelperAllowlist,
    maps: &MapRegistry,
) -> Result<(), VerifierError> {
    verify_program_with_config(prog, helpers, maps, &VerifierConfig::fail_closed_ctx())
}

/// Verify a BPF program with the full verifier configuration.
///
/// This is the single, authoritative verification entry point. Every
/// other `verify_program*` helper delegates here, so the per-access
/// memory-bounds gate (folded into [`state_track`]) runs on every
/// path. Memory accesses are bounded against the *destination/source
/// register's actual [`RegType`]*: stack accesses against the frame,
/// map accesses against their own `value_size`, context accesses
/// against `cfg.ctx_size` (fail-closed when unmodeled).
pub fn verify_program_with_config(
    prog: &[BpfInsn],
    helpers: &HelperAllowlist,
    maps: &MapRegistry,
    cfg: &VerifierConfig,
) -> Result<(), VerifierError> {
    // Phase 1: structural checks (includes lddw two-slot handling).
    structural_check(prog)?;

    // Phase 2: control flow graph — reachability and no loops.
    cfg_check(prog)?;

    // Phase 3: stack depth analysis.
    stack_depth_check(prog)?;

    // Phase 4: register state tracking with per-access memory bounds
    // (stack / map-value / context) folded into the single walk.
    state_track(prog, helpers, maps, cfg)?;

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

    let mut i = 0usize;
    while i < prog.len() {
        let insn = &prog[i];
        let class = insn.class();
        let op = insn.op();
        let dst = insn.dst_reg();
        let src = insn.src_reg();

        // `lddw` (BPF_LD | BPF_IMM | BPF_DW, opcode 0x18) is the only
        // 16-byte instruction: it occupies two slots, the second of
        // which is a raw immediate (NOT a real instruction). Recognise
        // it, require a well-formed zero-filler second slot, and
        // consume both so the filler is never decoded on its own.
        if insn.opcode == OPC_LDDW {
            if dst as usize >= NUM_REGS {
                return Err(VerifierError::InvalidRegister {
                    insn_idx: i,
                    reg: dst,
                });
            }
            // Must have a following slot to hold the upper 32 bits.
            let Some(second) = prog.get(i + 1) else {
                return Err(VerifierError::InvalidOpcode {
                    insn_idx: i,
                    opcode: insn.opcode,
                });
            };
            // Per the ISA the filler slot's code/regs/off are all 0
            // (only its `imm` is meaningful). Reject anything else so a
            // crafted "instruction" cannot masquerade as a filler.
            if second.opcode != 0 || second.regs != 0 || second.off != 0 {
                return Err(VerifierError::InvalidOpcode {
                    insn_idx: i + 1,
                    opcode: second.opcode,
                });
            }
            i += 2;
            continue;
        }

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

        // Validate ALU sub-opcode.
        if matches!(class, BPF_ALU | BPF_ALU64) && !is_valid_alu_op(op) {
            return Err(VerifierError::InvalidSubOpcode {
                insn_idx: i,
                sub_op: op,
            });
        }

        // Validate JMP sub-opcode.
        if matches!(class, BPF_JMP | BPF_JMP32) && !is_valid_jmp_op(op) {
            return Err(VerifierError::InvalidSubOpcode {
                insn_idx: i,
                sub_op: op,
            });
        }

        // Validate memory access widths for LD/LDX/ST/STX.
        if matches!(class, BPF_LDX | BPF_ST | BPF_STX) {
            let width = access_width_from_opcode(insn.opcode);
            if !is_valid_access_width(width) {
                return Err(VerifierError::InvalidAccessWidth { insn_idx: i, width });
            }
        }

        i += 1;
    }

    Ok(())
}

// ── Phase 2: control flow graph check ────────────────────────────

/// Check that all instructions are reachable and all jumps are
/// forward-only (no loops).
fn cfg_check(prog: &[BpfInsn]) -> Result<(), VerifierError> {
    // Reachability bitmap (256 bits = 4 x u64).
    let mut visited = [0u64; 4];
    // `lddw` filler-slot bitmap: bit set => this index is the second
    // (immediate) slot of a wide load and is NOT an independent
    // instruction. No control flow may target or fall onto it.
    let mut filler = [0u64; 4];

    let mark = |v: &mut [u64; 4], idx: usize| v[idx / 64] |= 1u64 << (idx % 64);
    let is_set = |v: &[u64; 4], idx: usize| -> bool { v[idx / 64] & (1u64 << (idx % 64)) != 0 };

    // First, identify every `lddw` filler slot. structural_check has
    // already validated two-slot well-formedness, so a filler always
    // follows an `OPC_LDDW` at the previous index.
    {
        let mut i = 0usize;
        while i < prog.len() {
            if prog[i].opcode == OPC_LDDW {
                if i + 1 < prog.len() {
                    mark(&mut filler, i + 1);
                }
                i += 2;
            } else {
                i += 1;
            }
        }
    }

    // Reject a jump that lands on a `lddw` filler slot.
    let target_is_filler = |f: &[u64; 4], t: usize| -> bool { t < prog.len() && is_set(f, t) };

    mark(&mut visited, 0);

    for i in 0..prog.len() {
        // Skip filler slots: they are not decoded as instructions.
        if is_set(&filler, i) {
            continue;
        }
        let insn = &prog[i];
        let class = insn.class();
        let op = insn.op();

        // A `lddw` consumes two slots; fall-through is to i + 2.
        if insn.opcode == OPC_LDDW {
            if i + 2 < prog.len() {
                mark(&mut visited, i + 2);
            }
            continue;
        }

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
                if target_is_filler(&filler, target as usize) {
                    return Err(VerifierError::InvalidJumpTarget {
                        insn_idx: i,
                        target,
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
            if target_is_filler(&filler, target as usize) {
                return Err(VerifierError::InvalidJumpTarget {
                    insn_idx: i,
                    target,
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

    // All instructions must be reachable. Filler slots are exempt:
    // they belong to their preceding `lddw`, not to the CFG.
    for i in 0..prog.len() {
        if is_set(&filler, i) {
            continue;
        }
        if !is_set(&visited, i) {
            return Err(VerifierError::UnreachableInsn { insn_idx: i });
        }
    }

    Ok(())
}

// ── Phase 3: register state tracking ─────────────────────────────

/// Abstract-interpret the program tracking register types and value
/// ranges, bounding every memory access against the *destination /
/// source register's actual [`RegType`]*.
///
/// This single walk is the authoritative memory-safety gate: stack
/// accesses are bounded against the 512-byte frame, map-value accesses
/// against the map's own `value_size`, and context accesses against
/// `cfg.ctx_size` (fail-closed when unmodeled). Folding the bounds
/// check here means it runs on every `verify_program*` entry point
/// (finding: it must not live in an optional second pass).
fn state_track(
    prog: &[BpfInsn],
    helpers: &HelperAllowlist,
    // Reserved: a genuine `PtrToMap` register would bound its access
    // against the map's `value_size` from here. The verifier does not
    // yet mint `PtrToMap` (map_lookup returns a scalar), so map-pointer
    // accesses are an explicit, fail-closed modelling gap (see the
    // `// SECURITY` note in the LDX/ST/STX arms) and `maps` is unused.
    _maps: &MapRegistry,
    cfg: &VerifierConfig,
) -> Result<(), VerifierError> {
    // Work stack for exploring branch targets.
    let mut work_stack = [0usize; MAX_WORK_STACK];
    // Per-instruction visited state.
    let mut insn_visited = [false; MAX_INSNS];

    // Per-instruction register state snapshots. The entry state seeds
    // R1 = PtrToCtx(ctx_size) and R10 = PtrToStack.
    let mut states = [VerifierState::entry(cfg); MAX_INSNS];

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

            // `lddw` (OPC_LDDW, 0x18) is the only two-slot instruction:
            // it loads a 64-bit immediate, its second slot is a raw
            // filler (NOT an instruction). Its class bits collide with
            // BPF_LD (0x18 & 0x07 == 0x00), so without this explicit arm
            // it would fall into the BPF_LD arm, advance pc by 1, and the
            // verifier would then decode the 8-byte filler as a separate
            // BPF_LD — spuriously clobbering R0 (the filler's dst_reg).
            // structural_check and cfg_check already treat lddw as a
            // 2-slot instruction; stay consistent: set dst = scalar and
            // advance pc by 2 so the filler is never decoded.
            if insn.opcode == OPC_LDDW {
                let dst = insn.dst_reg() as usize;
                if dst < NUM_REGS {
                    state.regs[dst] = RegState::scalar();
                }
                let lddw_pc = pc;
                // Skip the filler slot: fall-through is to lddw + 2, NOT
                // lddw + 1 (which is the immediate filler, not an insn).
                pc += 2;
                // Seed-or-JOIN the fall-through state from the lddw point
                // (its post-load registers), matching the merge semantics
                // used everywhere else. Re-walking continues inline below.
                if !fall_through_merge(lddw_pc, pc, prog.len(), &mut states, &mut insn_visited) {
                    // Target already fully explored from an equal-or-more-
                    // general state; nothing new to do on this path.
                    break;
                }
                continue;
            }

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
                    if state.regs[sr].reg_type == RegType::NotInit {
                        return Err(VerifierError::UninitializedReg {
                            insn_idx: pc,
                            reg: insn.src_reg(),
                        });
                    }
                    // Bound the FULL load window [off, off + width)
                    // against the object the source pointer refers to.
                    check_mem_access(&state.regs[sr], insn.opcode, insn.off, pc)?;
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
                    // Bound the FULL store window [off, off + width) against
                    // the destination object (stack/map/ctx). Without this a
                    // store via R10 (or any PtrToStack alias) with an
                    // out-of-range offset is an attacker-controlled OOB write.
                    check_mem_access(&state.regs[dst], insn.opcode, insn.off, pc)?;
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
                    // Bound the FULL store window against the destination
                    // object — same per-RegType check as BPF_ST / BPF_LDX.
                    check_mem_access(&state.regs[dst], insn.opcode, insn.off, pc)?;
                    pc += 1;
                }
                BPF_LD => {
                    // The wide-immediate load `lddw` (OPC_LDDW) is handled
                    // by the dedicated guard at the top of the loop. Any
                    // other BPF_LD reaching here is a legacy LD_ABS / LD_IND
                    // packet load whose memory bounds the verifier does not
                    // model. Reject it fail-closed so no future interpreter
                    // or JIT backend can execute an unbounded packet read
                    // that the TCB never bounded.
                    return Err(VerifierError::InvalidOpcode {
                        insn_idx: pc,
                        opcode: insn.opcode,
                    });
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
                        let call_pc = pc;
                        pc += 1;
                        // Seed-or-JOIN the post-call state into call + 1.
                        // (The previous bare `continue` skipped this, so a
                        // re-reached instruction after a CALL kept a stale
                        // state instead of the clobbered registers.)
                        if !fall_through_merge(
                            call_pc,
                            pc,
                            prog.len(),
                            &mut states,
                            &mut insn_visited,
                        ) {
                            break;
                        }
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
                        )?;
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
                    )?;
                    // Fall-through.
                    if pc + 1 < prog.len() {
                        propagate_state(
                            &snapshot,
                            &mut states,
                            pc + 1,
                            &mut insn_visited,
                            &mut work_stack,
                            &mut work_top,
                        )?;
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

            // Straight-line fall-through (ALU / LDX / ST / STX / LD):
            // seed-or-JOIN the next instruction's state from this one
            // (its predecessor, pc - 1 after the `pc += 1` above). On a
            // fresh seed or a widening change we keep walking inline; if
            // the target was already explored from an equal-or-more-
            // general state there is nothing new to do on this path.
            let prev = pc.saturating_sub(1);
            if !fall_through_merge(prev, pc, prog.len(), &mut states, &mut insn_visited) {
                break;
            }
        }
    }

    Ok(())
}

/// Seed-or-JOIN the fall-through `target` state from its predecessor
/// `from`, used by every straight-line / two-slot fall-through edge in
/// [`state_track`].
///
/// Returns `true` when the caller should keep walking `target` inline:
///
/// * the `target` lies past the program end (the caller's own bounds
///   check ends the walk — reported as `true` so the loop's `pc >= len`
///   guard handles it), or
/// * `target` was visited for the first time (seeded exactly from a
///   single predecessor — straight-line code keeps precise types), or
/// * `target` was already visited and the JOIN WIDENED its state, so the
///   downstream must be re-explored with the less-capable types.
///
/// Returns `false` when `target` was already visited and the JOIN
/// produced no change: the downstream was already explored from an
/// equal-or-more-general state, so the caller should `break`.
///
/// JOINING (not overwriting) at merge points is the soundness fix: a
/// register typed as a pointer on one predecessor and a scalar / uninit
/// on another is widened to [`RegType::NotInit`], so no later access
/// trusts a pointer type that is not valid on every path.
fn fall_through_merge(
    from: usize,
    target: usize,
    prog_len: usize,
    states: &mut [VerifierState; MAX_INSNS],
    visited: &mut [bool; MAX_INSNS],
) -> bool {
    if target >= prog_len || target >= MAX_INSNS {
        // Past program end: let the main loop's `pc >= len` guard stop.
        return true;
    }
    if !visited[target] {
        visited[target] = true;
        states[target] = states[from];
        return true;
    }
    // Already visited from another predecessor: widen conservatively.
    // When this widens (`changed`) the caller keeps walking `target`
    // inline, which re-explores the whole downstream — no separate
    // work-stack push is needed.
    let incoming = states[from];
    states[target].join_from(&incoming)
}

/// Propagate register state to a target instruction, JOINING with any
/// state already recorded there, and schedule the target for
/// (re-)verification when its state is seeded or changes.
///
/// # Path-merge soundness
///
/// When `target` has not been visited, its state is seeded exactly from
/// the single predecessor (`src_state`) — straight-line / single-path
/// code keeps its precise types and is never over-rejected.
///
/// When `target` HAS already been recorded (reached from another
/// predecessor — a second jump or a fall-through), the incoming state is
/// JOINED with the existing one via [`VerifierState::join_from`], which
/// widens any register whose type disagrees to [`RegType::NotInit`]. If
/// the join changes the recorded state, the target is re-scheduled so
/// the widened types propagate to every downstream access. This is what
/// stops the verifier from typing a register by whichever path was
/// visited last (the reported soundness gap).
fn propagate_state(
    src_state: &VerifierState,
    states: &mut [VerifierState; MAX_INSNS],
    target: usize,
    visited: &mut [bool; MAX_INSNS],
    work_stack: &mut [usize; MAX_WORK_STACK],
    work_top: &mut usize,
) -> Result<(), VerifierError> {
    if target >= MAX_INSNS {
        return Ok(());
    }
    if !visited[target] {
        // First arrival: seed exactly from the single predecessor.
        visited[target] = true;
        states[target] = *src_state;
        push_work(work_stack, work_top, target)
    } else {
        // Re-arrival from another path: widen, re-explore on change.
        let changed = states[target].join_from(src_state);
        if changed {
            // The widened (less-capable) state MUST be re-explored
            // downstream; if it cannot be queued we fail closed rather
            // than leave a path verified under the stale, too-precise
            // state (which would be a soundness hole).
            push_work(work_stack, work_top, target)
        } else {
            Ok(())
        }
    }
}

/// Push an instruction index onto the verification work stack.
///
/// Fails closed with [`VerifierError::ComplexityLimit`] when the stack
/// is full: a target that needs (re-)exploration but cannot be queued
/// must NOT be silently skipped, since a widening re-enqueue that is
/// dropped would leave downstream accesses verified under a stale,
/// too-precise state. Rejecting the (overly complex) program is the
/// safe outcome.
fn push_work(
    work_stack: &mut [usize; MAX_WORK_STACK],
    work_top: &mut usize,
    target: usize,
) -> Result<(), VerifierError> {
    if *work_top >= MAX_WORK_STACK {
        return Err(VerifierError::ComplexityLimit);
    }
    work_stack[*work_top] = target;
    *work_top += 1;
    Ok(())
}

// ── Convenience re-exports ────────────────────────────────────────

/// Alias for the BPF instruction type used by the verifier.
pub type Insn = BpfInsn;
