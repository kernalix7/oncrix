// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended task_struct fields.
//!
//! Provides additional per-task state that is less frequently accessed
//! than the core task_struct fields. These extensions cover I/O
//! context, performance monitoring, memory policy, futex state,
//! rseq (restartable sequences), seccomp, and audit state.
//!
//! # Extension Categories
//!
//! ```text
//! TaskExt
//! ├── I/O context         (ioprio, io_group)
//! ├── Performance events  (perf_event context pointers)
//! ├── Memory policy       (NUMA, preferred node, migration)
//! ├── Futex state         (robust list, pi state)
//! ├── rseq                (restartable sequence registration)
//! ├── Seccomp             (filter chain reference)
//! └── Audit               (audit context, loginuid)
//! ```
//!
//! # Reference
//!
//! Linux `include/linux/sched.h` (struct task_struct),
//! various subsystem headers.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum number of extended task entries.
const MAX_TASKS: usize = 1024;

/// Maximum perf event context slots per task.
const MAX_PERF_CTX: usize = 4;

/// Maximum number of seccomp filters.
const MAX_SECCOMP_FILTERS: usize = 8;

/// Default I/O priority (best-effort, class 2, level 4).
const DEFAULT_IOPRIO: u16 = (2 << 13) | 4;

/// NUMA policy: default (follow process).
const MPOL_DEFAULT: u8 = 0;
/// NUMA policy: preferred node.
const _MPOL_PREFERRED: u8 = 1;
/// NUMA policy: bind to nodes.
const _MPOL_BIND: u8 = 2;
/// NUMA policy: interleave across nodes.
const _MPOL_INTERLEAVE: u8 = 3;
/// NUMA policy: local allocation.
const _MPOL_LOCAL: u8 = 4;

/// Maximum NUMA nodes.
const MAX_NUMA_NODES: usize = 8;

/// rseq signature value (magic number for validation).
const _RSEQ_SIG: u32 = 0x53053053;

// ======================================================================
// I/O context
// ======================================================================

/// I/O priority class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoPrioClass {
    /// No class set.
    None = 0,
    /// Real-time I/O.
    RealTime = 1,
    /// Best-effort I/O.
    BestEffort = 2,
    /// Idle I/O.
    Idle = 3,
}

/// Per-task I/O context.
#[derive(Debug, Clone, Copy)]
pub struct IoContext {
    /// I/O priority (class << 13 | level).
    ioprio: u16,
    /// I/O cgroup ID.
    io_cgroup_id: u64,
    /// Number of read I/O operations.
    read_ops: u64,
    /// Number of write I/O operations.
    write_ops: u64,
    /// Bytes read.
    read_bytes: u64,
    /// Bytes written.
    write_bytes: u64,
}

impl IoContext {
    /// Creates a default I/O context.
    pub const fn new() -> Self {
        Self {
            ioprio: DEFAULT_IOPRIO,
            io_cgroup_id: 0,
            read_ops: 0,
            write_ops: 0,
            read_bytes: 0,
            write_bytes: 0,
        }
    }

    /// Returns the I/O priority.
    pub fn ioprio(&self) -> u16 {
        self.ioprio
    }

    /// Returns the I/O priority class.
    pub fn ioprio_class(&self) -> IoPrioClass {
        match self.ioprio >> 13 {
            1 => IoPrioClass::RealTime,
            2 => IoPrioClass::BestEffort,
            3 => IoPrioClass::Idle,
            _ => IoPrioClass::None,
        }
    }

    /// Returns the I/O priority level (0-7).
    pub fn ioprio_level(&self) -> u8 {
        (self.ioprio & 0x1FFF) as u8
    }

    /// Sets the I/O priority.
    pub fn set_ioprio(&mut self, class: IoPrioClass, level: u8) {
        self.ioprio = ((class as u16) << 13) | (level.min(7) as u16);
    }

    /// Accounts a read operation.
    pub fn account_read(&mut self, bytes: u64) {
        self.read_ops = self.read_ops.saturating_add(1);
        self.read_bytes = self.read_bytes.saturating_add(bytes);
    }

    /// Accounts a write operation.
    pub fn account_write(&mut self, bytes: u64) {
        self.write_ops = self.write_ops.saturating_add(1);
        self.write_bytes = self.write_bytes.saturating_add(bytes);
    }
}

// ======================================================================
// Perf event context
// ======================================================================

/// Perf event context reference for a task.
#[derive(Debug, Clone, Copy)]
pub struct PerfEventCtx {
    /// Context ID.
    ctx_id: u64,
    /// Number of active events in this context.
    nr_events: u32,
    /// Whether this context is active.
    active: bool,
    /// Context type (software, hardware, tracepoint, etc.).
    ctx_type: u8,
}

impl PerfEventCtx {
    /// Creates an empty context.
    pub const fn new() -> Self {
        Self {
            ctx_id: 0,
            nr_events: 0,
            active: false,
            ctx_type: 0,
        }
    }

    /// Returns the context ID.
    pub fn ctx_id(&self) -> u64 {
        self.ctx_id
    }

    /// Returns whether the context is active.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

// ======================================================================
// Memory policy
// ======================================================================

/// NUMA memory policy for a task.
#[derive(Debug, Clone, Copy)]
pub struct MemPolicy {
    /// Policy mode.
    mode: u8,
    /// Preferred NUMA node (for MPOL_PREFERRED).
    preferred_node: u8,
    /// Node mask (one bit per node).
    node_mask: u8,
    /// Whether the policy is active.
    active: bool,
    /// Migration disabled flag.
    migration_disabled: bool,
}

impl MemPolicy {
    /// Creates a default memory policy.
    pub const fn new() -> Self {
        Self {
            mode: MPOL_DEFAULT,
            preferred_node: 0,
            node_mask: 0xFF, // All nodes.
            active: false,
            migration_disabled: false,
        }
    }

    /// Returns the policy mode.
    pub fn mode(&self) -> u8 {
        self.mode
    }

    /// Returns the preferred node.
    pub fn preferred_node(&self) -> u8 {
        self.preferred_node
    }

    /// Returns the node mask.
    pub fn node_mask(&self) -> u8 {
        self.node_mask
    }

    /// Sets the preferred node policy.
    pub fn set_preferred(&mut self, node: u8) -> Result<()> {
        if node as usize >= MAX_NUMA_NODES {
            return Err(Error::InvalidArgument);
        }
        self.mode = 1; // MPOL_PREFERRED
        self.preferred_node = node;
        self.active = true;
        Ok(())
    }

    /// Sets the bind policy.
    pub fn set_bind(&mut self, node_mask: u8) {
        self.mode = 2; // MPOL_BIND
        self.node_mask = node_mask;
        self.active = true;
    }

    /// Resets to default policy.
    pub fn reset(&mut self) {
        self.mode = MPOL_DEFAULT;
        self.active = false;
    }
}

// ======================================================================
// Futex state
// ======================================================================

/// Per-task futex state.
#[derive(Debug, Clone, Copy)]
pub struct FutexState {
    /// Robust list head pointer (user-space address).
    robust_list_head: u64,
    /// Robust list length.
    robust_list_len: u32,
    /// PI (priority inheritance) futex count.
    pi_state_count: u32,
    /// Whether the task owns any PI futexes.
    has_pi: bool,
}

impl FutexState {
    /// Creates a default futex state.
    pub const fn new() -> Self {
        Self {
            robust_list_head: 0,
            robust_list_len: 0,
            pi_state_count: 0,
            has_pi: false,
        }
    }

    /// Returns the robust list head address.
    pub fn robust_list_head(&self) -> u64 {
        self.robust_list_head
    }

    /// Sets the robust list head.
    pub fn set_robust_list(&mut self, head: u64, len: u32) {
        self.robust_list_head = head;
        self.robust_list_len = len;
    }

    /// Returns whether PI futexes are held.
    pub fn has_pi(&self) -> bool {
        self.has_pi
    }
}

// ======================================================================
// rseq state
// ======================================================================

/// Restartable sequences (rseq) registration.
#[derive(Debug, Clone, Copy)]
pub struct RseqState {
    /// User-space rseq structure address.
    rseq_addr: u64,
    /// rseq length.
    rseq_len: u32,
    /// Signature for validation.
    signature: u32,
    /// Whether rseq is registered.
    registered: bool,
    /// Current CPU (updated on each context switch).
    cpu_id: u32,
    /// Node ID.
    node_id: u32,
}

impl RseqState {
    /// Creates a default rseq state.
    pub const fn new() -> Self {
        Self {
            rseq_addr: 0,
            rseq_len: 0,
            signature: 0,
            registered: false,
            cpu_id: 0,
            node_id: 0,
        }
    }

    /// Returns whether rseq is registered.
    pub fn is_registered(&self) -> bool {
        self.registered
    }

    /// Returns the rseq address.
    pub fn rseq_addr(&self) -> u64 {
        self.rseq_addr
    }

    /// Registers rseq for this task.
    pub fn register(&mut self, addr: u64, len: u32, sig: u32) -> Result<()> {
        if addr == 0 {
            return Err(Error::InvalidArgument);
        }
        self.rseq_addr = addr;
        self.rseq_len = len;
        self.signature = sig;
        self.registered = true;
        Ok(())
    }

    /// Unregisters rseq.
    pub fn unregister(&mut self) {
        self.registered = false;
        self.rseq_addr = 0;
    }

    /// Updates CPU/node IDs on context switch.
    pub fn update_cpu(&mut self, cpu: u32, node: u32) {
        self.cpu_id = cpu;
        self.node_id = node;
    }
}

// ======================================================================
// Seccomp state
// ======================================================================

/// Per-task seccomp filter reference.
#[derive(Debug, Clone, Copy)]
pub struct SeccompRef {
    /// Filter IDs (chain of filters applied to this task).
    filter_ids: [u32; MAX_SECCOMP_FILTERS],
    /// Number of active filters.
    nr_filters: u8,
    /// Seccomp mode (0=disabled, 1=strict, 2=filter).
    mode: u8,
}

impl SeccompRef {
    /// Creates a default seccomp state (disabled).
    pub const fn new() -> Self {
        Self {
            filter_ids: [0; MAX_SECCOMP_FILTERS],
            nr_filters: 0,
            mode: 0,
        }
    }

    /// Returns the seccomp mode.
    pub fn mode(&self) -> u8 {
        self.mode
    }

    /// Returns the number of active filters.
    pub fn nr_filters(&self) -> u8 {
        self.nr_filters
    }

    /// Adds a filter.
    pub fn add_filter(&mut self, filter_id: u32) -> Result<()> {
        if self.nr_filters as usize >= MAX_SECCOMP_FILTERS {
            return Err(Error::OutOfMemory);
        }
        self.filter_ids[self.nr_filters as usize] = filter_id;
        self.nr_filters += 1;
        self.mode = 2; // filter mode
        Ok(())
    }

    /// Sets strict mode.
    pub fn set_strict(&mut self) {
        self.mode = 1;
    }
}

// ======================================================================
// Audit context
// ======================================================================

/// Per-task audit state.
#[derive(Debug, Clone, Copy)]
pub struct AuditCtx {
    /// Login UID (set at login, inherited by children).
    loginuid: u32,
    /// Session ID.
    sessionid: u32,
    /// Whether audit is active for this task.
    active: bool,
    /// Audit context serial number.
    serial: u64,
    /// Last syscall audited.
    last_syscall: u32,
}

impl AuditCtx {
    /// Creates a default audit context.
    pub const fn new() -> Self {
        Self {
            loginuid: u32::MAX, // AUDIT_UID_UNSET
            sessionid: u32::MAX,
            active: false,
            serial: 0,
            last_syscall: 0,
        }
    }

    /// Returns the login UID.
    pub fn loginuid(&self) -> u32 {
        self.loginuid
    }

    /// Returns the session ID.
    pub fn sessionid(&self) -> u32 {
        self.sessionid
    }

    /// Sets the login UID.
    pub fn set_loginuid(&mut self, uid: u32) {
        self.loginuid = uid;
    }
}

// ======================================================================
// Extended task struct
// ======================================================================

/// Extended task state.
pub struct TaskExt {
    /// PID of the task.
    pid: u32,
    /// I/O context.
    io_ctx: IoContext,
    /// Perf event contexts.
    perf_ctx: [PerfEventCtx; MAX_PERF_CTX],
    /// Memory policy.
    mempolicy: MemPolicy,
    /// Futex state.
    futex: FutexState,
    /// rseq state.
    rseq: RseqState,
    /// Seccomp filter reference.
    seccomp: SeccompRef,
    /// Audit context.
    audit: AuditCtx,
    /// Whether this entry is active.
    active: bool,
}

impl TaskExt {
    /// Creates a new empty task extension.
    pub const fn new() -> Self {
        Self {
            pid: 0,
            io_ctx: IoContext::new(),
            perf_ctx: [const { PerfEventCtx::new() }; MAX_PERF_CTX],
            mempolicy: MemPolicy::new(),
            futex: FutexState::new(),
            rseq: RseqState::new(),
            seccomp: SeccompRef::new(),
            audit: AuditCtx::new(),
            active: false,
        }
    }

    /// Returns the PID.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Returns the I/O context.
    pub fn io_ctx(&self) -> &IoContext {
        &self.io_ctx
    }

    /// Returns a mutable reference to the I/O context.
    pub fn io_ctx_mut(&mut self) -> &mut IoContext {
        &mut self.io_ctx
    }

    /// Returns the memory policy.
    pub fn mempolicy(&self) -> &MemPolicy {
        &self.mempolicy
    }

    /// Returns a mutable reference to the memory policy.
    pub fn mempolicy_mut(&mut self) -> &mut MemPolicy {
        &mut self.mempolicy
    }

    /// Returns the futex state.
    pub fn futex(&self) -> &FutexState {
        &self.futex
    }

    /// Returns a mutable reference to the futex state.
    pub fn futex_mut(&mut self) -> &mut FutexState {
        &mut self.futex
    }

    /// Returns the rseq state.
    pub fn rseq(&self) -> &RseqState {
        &self.rseq
    }

    /// Returns a mutable reference to the rseq state.
    pub fn rseq_mut(&mut self) -> &mut RseqState {
        &mut self.rseq
    }

    /// Returns the seccomp reference.
    pub fn seccomp(&self) -> &SeccompRef {
        &self.seccomp
    }

    /// Returns a mutable reference to the seccomp reference.
    pub fn seccomp_mut(&mut self) -> &mut SeccompRef {
        &mut self.seccomp
    }

    /// Returns the audit context.
    pub fn audit(&self) -> &AuditCtx {
        &self.audit
    }

    /// Returns a mutable reference to the audit context.
    pub fn audit_mut(&mut self) -> &mut AuditCtx {
        &mut self.audit
    }
}

// ======================================================================
// Task extension table
// ======================================================================

/// Manages extended task state for all tasks.
pub struct TaskExtTable {
    /// Task extension entries.
    entries: [TaskExt; MAX_TASKS],
    /// Number of active entries.
    count: usize,
}

impl TaskExtTable {
    /// Creates a new empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { TaskExt::new() }; MAX_TASKS],
            count: 0,
        }
    }

    /// Returns the number of active entries.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Allocates an entry for a task.
    pub fn alloc(&mut self, pid: u32) -> Result<usize> {
        let slot = self
            .entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;
        self.entries[slot] = TaskExt::new();
        self.entries[slot].pid = pid;
        self.entries[slot].active = true;
        self.count += 1;
        Ok(slot)
    }

    /// Frees an entry.
    pub fn free(&mut self, pid: u32) -> Result<()> {
        let slot = self.find(pid)?;
        self.entries[slot].active = false;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Returns a reference to a task's extension.
    pub fn get(&self, pid: u32) -> Result<&TaskExt> {
        let slot = self.find(pid)?;
        Ok(&self.entries[slot])
    }

    /// Returns a mutable reference to a task's extension.
    pub fn get_mut(&mut self, pid: u32) -> Result<&mut TaskExt> {
        let slot = self.find(pid)?;
        Ok(&mut self.entries[slot])
    }

    /// Finds a slot by PID.
    fn find(&self, pid: u32) -> Result<usize> {
        self.entries
            .iter()
            .position(|e| e.active && e.pid == pid)
            .ok_or(Error::NotFound)
    }
}
