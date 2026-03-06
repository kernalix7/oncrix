// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! BPF socket operations hook points.
//!
//! Provides a framework for attaching BPF programs to socket-level
//! events such as connection establishment, retransmission, RTT
//! notification, and state changes. This enables fine-grained
//! socket-level policy enforcement and monitoring without modifying
//! the core TCP/UDP stack.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                   BpfSockOpsRegistry                         │
//! │                                                              │
//! │  BpfSockOpsProg[0..MAX_SOCKOPS_PROGS]                        │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  prog_id, attached_cgroup, ops_mask (u32)              │  │
//! │  │  active, name [u8; 32]                                 │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  BpfSockOpsCtx  (per-invocation context)                     │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  op, family, local_addr/port, remote_addr/port         │  │
//! │  │  snd_cwnd, srtt_us, reply, bpf_sock_ops_cb_flags      │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  BpfSockOpsStats (global counters)                           │
//! │  - total_runs, per_op_counts [u64; 10], errors               │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! 1. Register a BPF sock_ops program via `attach()`.
//! 2. On socket events, build a `BpfSockOpsCtx` and call
//!    `run_bpf_sockops()`.
//! 3. Programs matching the operation in their `ops_mask`
//!    are executed, and their `reply` values are collected.
//!
//! # Reference
//!
//! Linux `net/core/filter.c` (bpf_skops_*), `include/uapi/linux/bpf.h`
//! (`BPF_PROG_TYPE_SOCK_OPS`).

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum registered BPF sock_ops programs.
const MAX_SOCKOPS_PROGS: usize = 32;

/// Program name buffer length.
const PROG_NAME_LEN: usize = 32;

/// Maximum number of distinct operations.
const NUM_OPS: usize = 10;

/// Maximum replies collected per `run_bpf_sockops` invocation.
const MAX_REPLIES: usize = 32;

/// Address family: IPv4.
const AF_INET: u16 = 2;

/// Address family: IPv6.
const AF_INET6: u16 = 10;

// ══════════════════════════════════════════════════════════════
// SockOpsOp
// ══════════════════════════════════════════════════════════════

/// Socket operation types that trigger BPF callbacks.
///
/// Each variant corresponds to a specific TCP/UDP event that
/// a BPF sock_ops program can intercept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SockOpsOp {
    /// Active connection established (connect succeeded).
    ActiveEstab = 0,
    /// Passive connection established (accept completed).
    PassiveEstab = 1,
    /// Connection timed out.
    ConnTimeout = 2,
    /// TX retransmission detected.
    TxRetransmit = 3,
    /// RTO (retransmission timeout) notification.
    RtoNotify = 4,
    /// TCP state change.
    StateChange = 5,
    /// TCP connect initiated.
    TcpConnectInit = 6,
    /// TCP retransmission event.
    TcpRetrans = 7,
    /// TCP write cork notification.
    WriteCork = 8,
    /// RTT measurement notification.
    RttNotify = 9,
}

impl SockOpsOp {
    /// Convert a raw u8 to a `SockOpsOp`.
    pub fn from_u8(val: u8) -> Result<Self> {
        match val {
            0 => Ok(Self::ActiveEstab),
            1 => Ok(Self::PassiveEstab),
            2 => Ok(Self::ConnTimeout),
            3 => Ok(Self::TxRetransmit),
            4 => Ok(Self::RtoNotify),
            5 => Ok(Self::StateChange),
            6 => Ok(Self::TcpConnectInit),
            7 => Ok(Self::TcpRetrans),
            8 => Ok(Self::WriteCork),
            9 => Ok(Self::RttNotify),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Return the bit mask for this operation.
    pub fn mask(self) -> u32 {
        1u32 << (self as u8)
    }

    /// Return the index for per-op statistics.
    pub fn index(self) -> usize {
        self as usize
    }
}

// ══════════════════════════════════════════════════════════════
// BpfSockOpsCtx
// ══════════════════════════════════════════════════════════════

/// Per-invocation context passed to BPF sock_ops programs.
///
/// Contains the socket event type, connection 4-tuple, and
/// TCP state information. The `reply` field is writable by
/// the BPF program to communicate decisions back to the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct BpfSockOpsCtx {
    /// The socket operation being reported.
    pub op: SockOpsOp,
    /// Address family (AF_INET or AF_INET6).
    pub family: u16,
    /// Local IPv4 address (network byte order).
    pub local_addr: u32,
    /// Local port (host byte order).
    pub local_port: u16,
    /// Remote IPv4 address (network byte order).
    pub remote_addr: u32,
    /// Remote port (host byte order).
    pub remote_port: u16,
    /// Current send congestion window size.
    pub snd_cwnd: u32,
    /// Smoothed round-trip time in microseconds.
    pub srtt_us: u32,
    /// Reply value from BPF program (writeable).
    pub reply: i32,
    /// Callback flags controlling which events fire.
    pub bpf_sock_ops_cb_flags: u32,
    /// Current TCP state (SYN_SENT, ESTABLISHED, etc.).
    pub tcp_state: u8,
    /// Socket mark for classification.
    pub sk_mark: u32,
    /// Interface index.
    pub ifindex: u32,
}

impl BpfSockOpsCtx {
    /// Create a new context for a given operation.
    pub const fn new(op: SockOpsOp) -> Self {
        Self {
            op,
            family: AF_INET,
            local_addr: 0,
            local_port: 0,
            remote_addr: 0,
            remote_port: 0,
            snd_cwnd: 0,
            srtt_us: 0,
            reply: 0,
            bpf_sock_ops_cb_flags: 0,
            tcp_state: 0,
            sk_mark: 0,
            ifindex: 0,
        }
    }

    /// Set the local address/port pair.
    pub fn set_local(&mut self, addr: u32, port: u16) {
        self.local_addr = addr;
        self.local_port = port;
    }

    /// Set the remote address/port pair.
    pub fn set_remote(&mut self, addr: u32, port: u16) {
        self.remote_addr = addr;
        self.remote_port = port;
    }

    /// Set the address family.
    pub fn set_family(&mut self, family: u16) {
        self.family = family;
    }

    /// Set TCP metrics.
    pub fn set_tcp_metrics(&mut self, cwnd: u32, srtt_us: u32) {
        self.snd_cwnd = cwnd;
        self.srtt_us = srtt_us;
    }

    /// Validate that the address family is recognized.
    pub fn validate(&self) -> Result<()> {
        if self.family != AF_INET && self.family != AF_INET6 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ══════════════════════════════════════════════════════════════
// BpfSockOpsProg
// ══════════════════════════════════════════════════════════════

/// A registered BPF sock_ops program.
///
/// Each program is attached to a cgroup (identified by ID) and
/// has an operations mask that determines which socket events
/// it handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfSockOpsProg {
    /// Unique program identifier.
    pub prog_id: u32,
    /// Cgroup to which this program is attached.
    pub attached_cgroup: u64,
    /// Bitmask of operations this program handles.
    pub ops_mask: u32,
    /// Human-readable name.
    pub name: [u8; PROG_NAME_LEN],
    /// Name length in bytes.
    pub name_len: usize,
    /// Whether this program slot is active.
    pub active: bool,
    /// Priority for execution ordering (lower = earlier).
    pub priority: u16,
    /// Number of times this program has been invoked.
    pub run_count: u64,
    /// Number of errors from this program.
    pub error_count: u64,
}

impl BpfSockOpsProg {
    /// Create an empty (inactive) program slot.
    pub const fn new() -> Self {
        Self {
            prog_id: 0,
            attached_cgroup: 0,
            ops_mask: 0,
            name: [0u8; PROG_NAME_LEN],
            name_len: 0,
            active: false,
            priority: 0,
            run_count: 0,
            error_count: 0,
        }
    }

    /// Check whether this program handles the given operation.
    pub fn handles_op(&self, op: SockOpsOp) -> bool {
        self.active && (self.ops_mask & op.mask()) != 0
    }

    /// Execute this program against the given context.
    ///
    /// In a full implementation this would run BPF bytecode.
    /// Currently returns a deterministic reply based on the
    /// operation type (stub implementation).
    pub fn execute(&mut self, ctx: &mut BpfSockOpsCtx) -> Result<i32> {
        if !self.active {
            return Err(Error::NotFound);
        }
        self.run_count += 1;

        // Stub: set reply to 0 (OK / allow) for all operations
        let reply = match ctx.op {
            SockOpsOp::ConnTimeout => -1, // signal timeout handling
            SockOpsOp::RttNotify => ctx.srtt_us as i32,
            _ => 0,
        };
        ctx.reply = reply;
        Ok(reply)
    }
}

// ══════════════════════════════════════════════════════════════
// BpfSockOpsStats
// ══════════════════════════════════════════════════════════════

/// Global statistics for the BPF sock_ops subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfSockOpsStats {
    /// Total number of BPF sock_ops invocations.
    pub total_runs: u64,
    /// Per-operation invocation counts.
    pub per_op_counts: [u64; NUM_OPS],
    /// Total number of errors.
    pub errors: u64,
    /// Total programs attached.
    pub programs_attached: u32,
    /// Total programs detached.
    pub programs_detached: u32,
}

impl BpfSockOpsStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_runs: 0,
            per_op_counts: [0u64; NUM_OPS],
            errors: 0,
            programs_attached: 0,
            programs_detached: 0,
        }
    }

    /// Record one invocation for the given operation.
    pub fn record_run(&mut self, op: SockOpsOp) {
        self.total_runs += 1;
        let idx = op.index();
        if idx < NUM_OPS {
            self.per_op_counts[idx] += 1;
        }
    }

    /// Record an error.
    pub fn record_error(&mut self) {
        self.errors += 1;
    }

    /// Record an attach.
    pub fn record_attach(&mut self) {
        self.programs_attached += 1;
    }

    /// Record a detach.
    pub fn record_detach(&mut self) {
        self.programs_detached += 1;
    }
}

// ══════════════════════════════════════════════════════════════
// BpfSockOpsReply
// ══════════════════════════════════════════════════════════════

/// Collected reply from a single BPF program execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfSockOpsReply {
    /// Program ID that produced this reply.
    pub prog_id: u32,
    /// The reply value.
    pub reply: i32,
}

impl BpfSockOpsReply {
    /// Create a new reply.
    pub const fn new() -> Self {
        Self {
            prog_id: 0,
            reply: 0,
        }
    }
}

/// Collection of replies from a batch of BPF program executions.
pub struct BpfSockOpsReplies {
    /// Reply entries.
    replies: [BpfSockOpsReply; MAX_REPLIES],
    /// Number of valid replies.
    count: usize,
}

impl BpfSockOpsReplies {
    /// Create an empty reply collection.
    pub const fn new() -> Self {
        Self {
            replies: [const { BpfSockOpsReply::new() }; MAX_REPLIES],
            count: 0,
        }
    }

    /// Add a reply.
    pub fn push(&mut self, reply: BpfSockOpsReply) -> Result<()> {
        if self.count >= MAX_REPLIES {
            return Err(Error::OutOfMemory);
        }
        self.replies[self.count] = reply;
        self.count += 1;
        Ok(())
    }

    /// Return the number of replies collected.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Return a slice of the collected replies.
    pub fn as_slice(&self) -> &[BpfSockOpsReply] {
        &self.replies[..self.count]
    }

    /// Check whether any program returned a negative (deny) reply.
    pub fn any_denied(&self) -> bool {
        self.replies[..self.count].iter().any(|r| r.reply < 0)
    }
}

// ══════════════════════════════════════════════════════════════
// BpfSockOpsRegistry
// ══════════════════════════════════════════════════════════════

/// Registry of BPF sock_ops programs.
///
/// Manages program attachment, detachment, and dispatching
/// socket events to matching programs.
pub struct BpfSockOpsRegistry {
    /// Registered programs.
    programs: [BpfSockOpsProg; MAX_SOCKOPS_PROGS],
    /// Number of active programs.
    active_count: usize,
    /// Global statistics.
    stats: BpfSockOpsStats,
}

impl BpfSockOpsRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            programs: [const { BpfSockOpsProg::new() }; MAX_SOCKOPS_PROGS],
            active_count: 0,
            stats: BpfSockOpsStats::new(),
        }
    }

    /// Attach a BPF sock_ops program.
    ///
    /// The program will be invoked for operations matching the
    /// given `ops_mask`.
    pub fn attach(
        &mut self,
        prog_id: u32,
        cgroup_id: u64,
        ops_mask: u32,
        name: &[u8],
        priority: u16,
    ) -> Result<()> {
        if ops_mask == 0 {
            return Err(Error::InvalidArgument);
        }
        // Check for duplicate prog_id
        if self.programs[..MAX_SOCKOPS_PROGS]
            .iter()
            .any(|p| p.active && p.prog_id == prog_id)
        {
            return Err(Error::AlreadyExists);
        }
        // Find a free slot
        let slot = self
            .programs
            .iter()
            .position(|p| !p.active)
            .ok_or(Error::OutOfMemory)?;

        let prog = &mut self.programs[slot];
        prog.prog_id = prog_id;
        prog.attached_cgroup = cgroup_id;
        prog.ops_mask = ops_mask;
        prog.priority = priority;
        prog.active = true;
        prog.run_count = 0;
        prog.error_count = 0;

        let copy_len = name.len().min(PROG_NAME_LEN);
        prog.name[..copy_len].copy_from_slice(&name[..copy_len]);
        prog.name_len = copy_len;

        self.active_count += 1;
        self.stats.record_attach();
        Ok(())
    }

    /// Detach a BPF sock_ops program by program ID.
    pub fn detach(&mut self, prog_id: u32) -> Result<()> {
        let slot = self
            .programs
            .iter()
            .position(|p| p.active && p.prog_id == prog_id)
            .ok_or(Error::NotFound)?;

        self.programs[slot] = BpfSockOpsProg::new();
        self.active_count -= 1;
        self.stats.record_detach();
        Ok(())
    }

    /// Run all matching BPF sock_ops programs for the given context.
    ///
    /// Returns collected replies from all executed programs.
    pub fn run_bpf_sockops(&mut self, ctx: &mut BpfSockOpsCtx) -> Result<BpfSockOpsReplies> {
        ctx.validate()?;
        let mut replies = BpfSockOpsReplies::new();

        for i in 0..MAX_SOCKOPS_PROGS {
            if !self.programs[i].handles_op(ctx.op) {
                continue;
            }
            self.stats.record_run(ctx.op);
            match self.programs[i].execute(ctx) {
                Ok(reply_val) => {
                    let reply = BpfSockOpsReply {
                        prog_id: self.programs[i].prog_id,
                        reply: reply_val,
                    };
                    // Ignore overflow of reply buffer — best effort
                    let _ = replies.push(reply);
                }
                Err(_) => {
                    self.programs[i].error_count += 1;
                    self.stats.record_error();
                }
            }
        }

        Ok(replies)
    }

    /// Return the number of active programs.
    pub fn active_count(&self) -> usize {
        self.active_count
    }

    /// Return global statistics.
    pub fn stats(&self) -> &BpfSockOpsStats {
        &self.stats
    }

    /// Find a program by its ID.
    pub fn find_prog(&self, prog_id: u32) -> Result<&BpfSockOpsProg> {
        self.programs
            .iter()
            .find(|p| p.active && p.prog_id == prog_id)
            .ok_or(Error::NotFound)
    }

    /// List all active programs for a cgroup.
    pub fn list_by_cgroup(&self, cgroup_id: u64, out: &mut [u32]) -> usize {
        let mut count = 0;
        for prog in &self.programs {
            if prog.active && prog.attached_cgroup == cgroup_id && count < out.len() {
                out[count] = prog.prog_id;
                count += 1;
            }
        }
        count
    }

    /// Update the ops_mask for an existing program.
    pub fn update_mask(&mut self, prog_id: u32, new_mask: u32) -> Result<()> {
        if new_mask == 0 {
            return Err(Error::InvalidArgument);
        }
        let slot = self
            .programs
            .iter()
            .position(|p| p.active && p.prog_id == prog_id)
            .ok_or(Error::NotFound)?;
        self.programs[slot].ops_mask = new_mask;
        Ok(())
    }

    /// Update the priority for an existing program.
    pub fn update_priority(&mut self, prog_id: u32, priority: u16) -> Result<()> {
        let slot = self
            .programs
            .iter()
            .position(|p| p.active && p.prog_id == prog_id)
            .ok_or(Error::NotFound)?;
        self.programs[slot].priority = priority;
        Ok(())
    }
}

/// Convenience function: run BPF sockops on a registry.
///
/// Builds a context from the supplied parameters, runs all
/// matching programs, and returns the collected replies.
pub fn run_bpf_sockops(
    registry: &mut BpfSockOpsRegistry,
    op: SockOpsOp,
    local_addr: u32,
    local_port: u16,
    remote_addr: u32,
    remote_port: u16,
) -> Result<BpfSockOpsReplies> {
    let mut ctx = BpfSockOpsCtx::new(op);
    ctx.set_local(local_addr, local_port);
    ctx.set_remote(remote_addr, remote_port);
    registry.run_bpf_sockops(&mut ctx)
}
