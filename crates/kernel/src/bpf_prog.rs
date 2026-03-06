// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! eBPF program type classification and attachment tracking.
//!
//! Extends the core BPF subsystem with:
//! - Program type enumeration ([`BpfProgType`]) classifying the
//!   hook point a program targets
//! - Attachment type enumeration ([`BpfAttachType`]) for cgroup,
//!   XDP, and tracepoint hooks
//! - Program container ([`BpfProgram`]) with type, instructions,
//!   and attachment state
//! - Attachment point tracking ([`BpfAttachPoint`]) recording
//!   where programs are hooked
//! - Program registry ([`BpfProgRegistry`]) managing up to 64
//!   loaded programs with load/unload/attach/detach
//!
//! Reference: Linux `include/uapi/linux/bpf.h`,
//! `kernel/bpf/syscall.c`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum number of instructions per BPF program.
const MAX_INSNS: usize = 256;

/// Maximum number of programs in the registry.
const MAX_PROGRAMS: usize = 64;

/// Maximum name length in bytes for programs and attach points.
const MAX_NAME_LEN: usize = 64;

/// Maximum number of attach points per program.
const MAX_ATTACH_POINTS: usize = 4;

// ── BpfProgType ────────────────────────────────────────────────────

/// Classification of eBPF program types.
///
/// Each variant identifies the kernel hook point where the program
/// will be executed. The type determines which helper functions are
/// available and what context is passed to the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BpfProgType {
    /// Socket-level packet filter (SO_ATTACH_BPF).
    #[default]
    SocketFilter,
    /// eXpress Data Path program for high-performance packet
    /// processing at the driver level.
    XdpProgram,
    /// Static tracepoint hook for kernel instrumentation.
    TracePoint,
    /// Cgroup socket buffer filter for network traffic control
    /// within a cgroup.
    CgroupSkb,
    /// Traffic control classifier for the tc subsystem.
    SchedCls,
    /// Kprobe/kretprobe dynamic tracing hook.
    KprobeProgram,
}

impl core::fmt::Display for BpfProgType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SocketFilter => write!(f, "socket_filter"),
            Self::XdpProgram => write!(f, "xdp"),
            Self::TracePoint => write!(f, "tracepoint"),
            Self::CgroupSkb => write!(f, "cgroup_skb"),
            Self::SchedCls => write!(f, "sched_cls"),
            Self::KprobeProgram => write!(f, "kprobe"),
        }
    }
}

// ── BpfAttachType ──────────────────────────────────────────────────

/// Attachment type for BPF programs.
///
/// Specifies the exact hook point within a subsystem where the
/// program is attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfAttachType {
    /// Cgroup inet ingress filter.
    CgroupInetIngress,
    /// Cgroup inet egress filter.
    CgroupInetEgress,
    /// XDP device-map redirect.
    XdpDevMap,
    /// XDP CPU-map redirect.
    XdpCpuMap,
    /// Tracepoint raw attachment.
    TracepointRaw,
    /// Kprobe function entry attachment.
    KprobeEntry,
    /// Kretprobe function return attachment.
    KprobeReturn,
    /// tc ingress classifier.
    TcIngress,
    /// tc egress classifier.
    TcEgress,
}

impl core::fmt::Display for BpfAttachType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CgroupInetIngress => write!(f, "cgroup_inet_ingress"),
            Self::CgroupInetEgress => write!(f, "cgroup_inet_egress"),
            Self::XdpDevMap => write!(f, "xdp_devmap"),
            Self::XdpCpuMap => write!(f, "xdp_cpumap"),
            Self::TracepointRaw => write!(f, "tracepoint_raw"),
            Self::KprobeEntry => write!(f, "kprobe_entry"),
            Self::KprobeReturn => write!(f, "kprobe_return"),
            Self::TcIngress => write!(f, "tc_ingress"),
            Self::TcEgress => write!(f, "tc_egress"),
        }
    }
}

// ── BpfInstruction ─────────────────────────────────────────────────

/// A single eBPF instruction (8 bytes, C-compatible layout).
///
/// Matches the standard eBPF instruction encoding with opcode,
/// register pair, offset, and immediate fields.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct BpfInstruction {
    /// Operation code (class | op | source).
    pub opcode: u8,
    /// Packed registers: dst (lower 4 bits), src (upper 4 bits).
    pub regs: u8,
    /// Signed offset for jumps and memory operations.
    pub off: i16,
    /// Signed 32-bit immediate value.
    pub imm: i32,
}

impl BpfInstruction {
    /// Create a new instruction.
    pub const fn new(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self {
            opcode,
            regs: (src << 4) | (dst & 0x0f),
            off,
            imm,
        }
    }
}

// ── BpfProgram ─────────────────────────────────────────────────────

/// A loaded eBPF program with type classification and attachment
/// state.
///
/// Contains the program instructions, type tag, optional attach
/// type, and a flag indicating whether the program is currently
/// attached to a hook point.
pub struct BpfProgram {
    /// Unique program identifier.
    id: u64,
    /// Program name (UTF-8 bytes, null-padded).
    name: [u8; MAX_NAME_LEN],
    /// Name length in bytes.
    name_len: usize,
    /// Program type classification.
    pub prog_type: BpfProgType,
    /// Instruction buffer.
    pub insns: [BpfInstruction; MAX_INSNS],
    /// Number of valid instructions.
    pub insn_count: usize,
    /// Preferred attach type (may be overridden at attach time).
    pub attach_type: Option<BpfAttachType>,
    /// Whether the program is currently attached to at least one
    /// hook point.
    pub attached: bool,
    /// Whether this slot is actively in use.
    in_use: bool,
}

impl BpfProgram {
    /// Create an empty (inactive) program slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            prog_type: BpfProgType::SocketFilter,
            insns: [BpfInstruction {
                opcode: 0,
                regs: 0,
                off: 0,
                imm: 0,
            }; MAX_INSNS],
            insn_count: 0,
            attach_type: None,
            attached: false,
            in_use: false,
        }
    }

    /// Return the program's unique identifier.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Return the program name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the number of instructions.
    pub const fn insn_count(&self) -> usize {
        self.insn_count
    }

    /// Return whether the program is active.
    pub const fn is_active(&self) -> bool {
        self.in_use
    }

    /// Return whether the program is attached.
    pub const fn is_attached(&self) -> bool {
        self.attached
    }

    /// Append an instruction to the program.
    ///
    /// Returns `Error::OutOfMemory` if the instruction buffer is
    /// full.
    pub fn push_insn(&mut self, insn: BpfInstruction) -> Result<()> {
        if self.insn_count >= MAX_INSNS {
            return Err(Error::OutOfMemory);
        }
        self.insns[self.insn_count] = insn;
        self.insn_count += 1;
        Ok(())
    }
}

// ── BpfAttachPoint ─────────────────────────────────────────────────

/// Tracks where a BPF program is attached.
///
/// Each attach point records the program ID, the type of
/// attachment, and a target identifier (e.g., interface index,
/// cgroup ID, or tracepoint name hash).
#[derive(Debug, Clone, Copy)]
pub struct BpfAttachPoint {
    /// Program ID that is attached at this point.
    pub prog_id: u64,
    /// Attachment type.
    pub attach_type: BpfAttachType,
    /// Target identifier (interface index, cgroup ID, etc.).
    pub target_id: u64,
    /// Whether this attach point slot is in use.
    pub in_use: bool,
}

impl BpfAttachPoint {
    /// Create an empty attach point.
    const fn empty() -> Self {
        Self {
            prog_id: 0,
            attach_type: BpfAttachType::CgroupInetIngress,
            target_id: 0,
            in_use: false,
        }
    }
}

// ── BpfProgRegistry ────────────────────────────────────────────────

/// System-wide registry of eBPF programs.
///
/// Manages up to [`MAX_PROGRAMS`] programs with load, unload,
/// attach, and detach operations. Each program is identified by a
/// unique `u64` ID assigned at load time.
pub struct BpfProgRegistry {
    /// Fixed-size array of program slots.
    programs: [BpfProgram; MAX_PROGRAMS],
    /// Attach point tracking (4 per program max).
    attach_points: [BpfAttachPoint; MAX_PROGRAMS * MAX_ATTACH_POINTS],
    /// Next program ID to assign.
    next_id: u64,
    /// Number of active programs.
    count: usize,
}

impl Default for BpfProgRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BpfProgRegistry {
    /// Create a new, empty registry.
    pub const fn new() -> Self {
        const EMPTY_PROG: BpfProgram = BpfProgram::empty();
        const EMPTY_AP: BpfAttachPoint = BpfAttachPoint::empty();
        Self {
            programs: [EMPTY_PROG; MAX_PROGRAMS],
            attach_points: [EMPTY_AP; MAX_PROGRAMS * MAX_ATTACH_POINTS],
            next_id: 1,
            count: 0,
        }
    }

    /// Return the number of active programs.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return whether the registry is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Load a new BPF program into the registry.
    ///
    /// `name` is the program name, `prog_type` is its
    /// classification, `insns` is the instruction slice, and
    /// `attach_type` is the optional preferred attach type.
    ///
    /// Returns the new program's unique ID.
    ///
    /// # Errors
    ///
    /// - `Error::InvalidArgument` — name is empty/too long, or
    ///   instructions are empty/exceed the limit.
    /// - `Error::OutOfMemory` — no free slots available.
    pub fn load(
        &mut self,
        name: &[u8],
        prog_type: BpfProgType,
        insns: &[BpfInstruction],
        attach_type: Option<BpfAttachType>,
    ) -> Result<u64> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if insns.is_empty() || insns.len() > MAX_INSNS {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_PROGRAMS {
            return Err(Error::OutOfMemory);
        }

        let slot = self
            .programs
            .iter()
            .position(|p| !p.in_use)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let prog = &mut self.programs[slot];
        *prog = BpfProgram::empty();
        prog.id = id;
        prog.in_use = true;
        prog.prog_type = prog_type;
        prog.attach_type = attach_type;
        prog.name_len = name.len();
        prog.name[..name.len()].copy_from_slice(name);
        prog.insn_count = insns.len();
        prog.insns[..insns.len()].copy_from_slice(insns);

        self.count += 1;
        Ok(id)
    }

    /// Unload a BPF program by ID.
    ///
    /// The program must not be currently attached to any hook point.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — program does not exist.
    /// - `Error::Busy` — program is still attached.
    pub fn unload(&mut self, id: u64) -> Result<()> {
        let idx = self.prog_index(id)?;
        if self.programs[idx].attached {
            return Err(Error::Busy);
        }
        self.programs[idx].in_use = false;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Attach a loaded program to a target.
    ///
    /// `attach_type` specifies the hook point and `target_id` is
    /// the target identifier (e.g., interface index, cgroup ID).
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — program does not exist.
    /// - `Error::OutOfMemory` — no free attach point slots.
    /// - `Error::AlreadyExists` — program is already attached at
    ///   this exact point.
    pub fn attach(
        &mut self,
        prog_id: u64,
        attach_type: BpfAttachType,
        target_id: u64,
    ) -> Result<()> {
        // Verify program exists.
        let _ = self.prog_index(prog_id)?;

        // Check for duplicate attachment.
        for ap in &self.attach_points {
            if ap.in_use && ap.prog_id == prog_id && ap.target_id == target_id {
                // Same attach type at same target is a duplicate.
                if ap.attach_type as u8 == attach_type as u8 {
                    return Err(Error::AlreadyExists);
                }
            }
        }

        // Find a free attach point slot.
        let slot = self
            .attach_points
            .iter()
            .position(|ap| !ap.in_use)
            .ok_or(Error::OutOfMemory)?;

        self.attach_points[slot] = BpfAttachPoint {
            prog_id,
            attach_type,
            target_id,
            in_use: true,
        };

        // Mark the program as attached.
        let prog_idx = self.prog_index(prog_id)?;
        self.programs[prog_idx].attached = true;

        Ok(())
    }

    /// Detach a program from a specific target.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — program does not exist or is not
    ///   attached at the specified point.
    pub fn detach(
        &mut self,
        prog_id: u64,
        attach_type: BpfAttachType,
        target_id: u64,
    ) -> Result<()> {
        // Verify program exists.
        let _ = self.prog_index(prog_id)?;

        // Find and remove the attach point.
        let ap_idx = self
            .attach_points
            .iter()
            .position(|ap| {
                ap.in_use
                    && ap.prog_id == prog_id
                    && ap.target_id == target_id
                    && ap.attach_type as u8 == attach_type as u8
            })
            .ok_or(Error::NotFound)?;

        self.attach_points[ap_idx].in_use = false;

        // Check if the program still has any active attach points.
        let still_attached = self
            .attach_points
            .iter()
            .any(|ap| ap.in_use && ap.prog_id == prog_id);

        let prog_idx = self.prog_index(prog_id)?;
        self.programs[prog_idx].attached = still_attached;

        Ok(())
    }

    /// Return an immutable reference to a program by ID.
    pub fn get(&self, id: u64) -> Option<&BpfProgram> {
        self.programs.iter().find(|p| p.in_use && p.id == id)
    }

    /// Return the attach points for a given program ID.
    ///
    /// Returns a count of active attach points and fills the
    /// provided buffer with their details.
    pub fn get_attach_points(&self, prog_id: u64, buf: &mut [BpfAttachPoint]) -> usize {
        let mut count = 0;
        for ap in &self.attach_points {
            if ap.in_use && ap.prog_id == prog_id && count < buf.len() {
                buf[count] = *ap;
                count += 1;
            }
        }
        count
    }

    // ── Internal helpers ───────────────────────────────────────────

    /// Return the index of an active program by ID.
    fn prog_index(&self, id: u64) -> Result<usize> {
        self.programs
            .iter()
            .position(|p| p.in_use && p.id == id)
            .ok_or(Error::NotFound)
    }
}

impl core::fmt::Debug for BpfProgRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let attached = self.attach_points.iter().filter(|ap| ap.in_use).count();
        f.debug_struct("BpfProgRegistry")
            .field("active_programs", &self.count)
            .field("active_attach_points", &attached)
            .field("capacity", &MAX_PROGRAMS)
            .finish()
    }
}
