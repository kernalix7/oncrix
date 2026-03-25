// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! BPF-based Linux Security Module (BPF LSM) hook framework.
//!
//! Provides programmable security policy via BPF programs attached to
//! LSM hook points. Programs run at security-sensitive kernel events
//! and can enforce deny/audit/allow policies without kernel recompilation.
//!
//! # Architecture
//!
//! ```text
//! LSM hook site           BPF LSM layer              BPF program
//! ─────────────           ─────────────              ───────────
//! file_open()      ──►    dispatch_hook()  ──►  prog.run(ctx) → verdict
//! bprm_check()     ──►    dispatch_hook()  ──►  prog.run(ctx) → verdict
//! socket_connect() ──►    dispatch_hook()  ──►  prog.run(ctx) → verdict
//! task_alloc()     ──►    dispatch_hook()  ──►  prog.run(ctx) → verdict
//! ```
//!
//! # Verdict Semantics
//!
//! | Return value | Meaning        |
//! |--------------|----------------|
//! | 0            | Allow          |
//! | negative     | Deny (−errno)  |
//! | 1            | Audit + allow  |
//!
//! Reference: Linux `kernel/bpf/bpf_lsm.c`, `security/security.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of BPF programs attachable per hook point.
const MAX_PROGS_PER_HOOK: usize = 8;

/// Maximum number of hook types in this implementation.
const MAX_HOOK_TYPES: usize = 16;

/// Maximum number of total registered LSM programs.
const MAX_LSM_PROGRAMS: usize = 64;

/// Maximum number of characters in a hook name.
const MAX_HOOK_NAME_LEN: usize = 48;

/// Maximum program name length.
const MAX_PROG_NAME_LEN: usize = 32;

/// BPF LSM program context maximum data size in bytes.
const MAX_CTX_DATA_LEN: usize = 128;

// ---------------------------------------------------------------------------
// Hook type enumeration
// ---------------------------------------------------------------------------

/// LSM hook point identifiers.
///
/// Each variant maps to a specific kernel security hook. BPF programs
/// are attached to one or more of these hook points and are invoked
/// at the corresponding kernel event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LsmHook {
    /// File open permission check (`security_file_open`).
    FileOpen = 0,
    /// Program execution check (`security_bprm_check`).
    BprmCheck = 1,
    /// Socket connect check (`security_socket_connect`).
    SocketConnect = 2,
    /// Socket bind check (`security_socket_bind`).
    SocketBind = 3,
    /// Socket create check (`security_socket_create`).
    SocketCreate = 4,
    /// Task (process) allocation (`security_task_alloc`).
    TaskAlloc = 5,
    /// Task free / exit (`security_task_free`).
    TaskFree = 6,
    /// Capability check (`security_capable`).
    Capable = 7,
    /// IPC permission check (`security_ipc_permission`).
    IpcPermission = 8,
    /// File permission check (`security_file_permission`).
    FilePermission = 9,
    /// Memory map check (`security_mmap_file`).
    MmapFile = 10,
    /// mprotect check (`security_file_mprotect`).
    FileMprotect = 11,
    /// setuid/setgid check (`security_task_setuid`).
    TaskSetuid = 12,
    /// kill / signal check (`security_task_kill`).
    TaskKill = 13,
    /// Kernel module load check (`security_kernel_module_request`).
    KernelModuleRequest = 15,
}

impl LsmHook {
    /// Convert from raw u32 to a hook variant.
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::FileOpen),
            1 => Some(Self::BprmCheck),
            2 => Some(Self::SocketConnect),
            3 => Some(Self::SocketBind),
            4 => Some(Self::SocketCreate),
            5 => Some(Self::TaskAlloc),
            6 => Some(Self::TaskFree),
            7 => Some(Self::Capable),
            8 => Some(Self::IpcPermission),
            9 => Some(Self::FilePermission),
            10 => Some(Self::MmapFile),
            11 => Some(Self::FileMprotect),
            12 => Some(Self::TaskSetuid),
            13 => Some(Self::TaskKill),
            15 => Some(Self::KernelModuleRequest),
            _ => None,
        }
    }

    /// Return the human-readable hook name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::FileOpen => "file_open",
            Self::BprmCheck => "bprm_check",
            Self::SocketConnect => "socket_connect",
            Self::SocketBind => "socket_bind",
            Self::SocketCreate => "socket_create",
            Self::TaskAlloc => "task_alloc",
            Self::TaskFree => "task_free",
            Self::Capable => "capable",
            Self::IpcPermission => "ipc_permission",
            Self::FilePermission => "file_permission",
            Self::MmapFile => "mmap_file",
            Self::FileMprotect => "file_mprotect",
            Self::TaskSetuid => "task_setuid",
            Self::TaskKill => "task_kill",
            Self::KernelModuleRequest => "kernel_module_request",
        }
    }

    /// Index into fixed-size hook arrays.
    pub const fn index(self) -> usize {
        self as usize % MAX_HOOK_TYPES
    }
}

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

/// Decision returned by a BPF LSM program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Allow the operation to proceed.
    Allow,
    /// Deny the operation; includes an errno-like code.
    Deny(i32),
    /// Allow and emit an audit record.
    AuditAllow,
}

impl Verdict {
    /// Convert raw BPF return value to a [`Verdict`].
    ///
    /// Matches Linux convention: 0 = allow, 1 = audit+allow, negative = deny.
    pub fn from_retval(val: i64) -> Self {
        match val {
            0 => Self::Allow,
            1 => Self::AuditAllow,
            n if n < 0 => Self::Deny(n as i32),
            _ => Self::Allow,
        }
    }

    /// Returns `true` if the operation is permitted.
    pub fn is_allow(self) -> bool {
        matches!(self, Self::Allow | Self::AuditAllow)
    }
}

// ---------------------------------------------------------------------------
// BPF LSM context
// ---------------------------------------------------------------------------

/// Context passed to a BPF LSM program at a hook point.
///
/// Carries hook-specific information that the BPF program can inspect
/// to make a policy decision. The data is opaque bytes interpreted
/// according to `hook`.
#[derive(Debug, Clone, Copy)]
pub struct LsmCtx {
    /// Hook point this context belongs to.
    pub hook: LsmHook,
    /// UID of the calling task (or 0 for kernel context).
    pub uid: u32,
    /// GID of the calling task.
    pub gid: u32,
    /// PID of the calling task.
    pub pid: u32,
    /// Hook-specific opaque data (e.g., file path hash, socket address).
    pub data: [u8; MAX_CTX_DATA_LEN],
    /// Length of valid bytes in `data`.
    pub data_len: usize,
}

impl LsmCtx {
    /// Construct a minimal context for a given hook.
    pub const fn new(hook: LsmHook, uid: u32, gid: u32, pid: u32) -> Self {
        Self {
            hook,
            uid,
            gid,
            pid,
            data: [0u8; MAX_CTX_DATA_LEN],
            data_len: 0,
        }
    }

    /// Attach opaque data to the context (capped at `MAX_CTX_DATA_LEN`).
    pub fn set_data(&mut self, src: &[u8]) {
        let len = src.len().min(MAX_CTX_DATA_LEN);
        self.data[..len].copy_from_slice(&src[..len]);
        self.data_len = len;
    }
}

// ---------------------------------------------------------------------------
// Simulated BPF program
// ---------------------------------------------------------------------------

/// A simple BPF LSM policy rule stored as a program-like structure.
///
/// In a production system this would hold verified eBPF bytecode from
/// `bpf.rs`. Here we store a declarative policy that can be evaluated
/// without a full BPF VM invocation.
#[derive(Debug, Clone, Copy)]
pub struct BpfLsmProg {
    /// Unique program ID assigned at load time.
    pub id: u32,
    /// Human-readable program name.
    pub name: [u8; MAX_PROG_NAME_LEN],
    /// Length of valid bytes in `name`.
    pub name_len: usize,
    /// Hook point this program handles.
    pub hook: LsmHook,
    /// Whether the program is currently active.
    pub enabled: bool,
    /// UID filter: if `Some(uid)`, only match this UID (0 = match all).
    pub uid_filter: Option<u32>,
    /// Default verdict when no filter matches.
    pub default_verdict: i64,
    /// Number of times this program has been invoked.
    pub invocation_count: u64,
    /// Number of deny verdicts issued.
    pub deny_count: u64,
    /// Number of audit records emitted.
    pub audit_count: u64,
}

impl BpfLsmProg {
    /// Create a new allow-all program for the given hook.
    pub fn new_allow(id: u32, name: &[u8], hook: LsmHook) -> Self {
        let mut prog = Self {
            id,
            name: [0u8; MAX_PROG_NAME_LEN],
            name_len: 0,
            hook,
            enabled: true,
            uid_filter: None,
            default_verdict: 0,
            invocation_count: 0,
            deny_count: 0,
            audit_count: 0,
        };
        let len = name.len().min(MAX_PROG_NAME_LEN);
        prog.name[..len].copy_from_slice(&name[..len]);
        prog.name_len = len;
        prog
    }

    /// Create a deny-all program for the given hook.
    pub fn new_deny(id: u32, name: &[u8], hook: LsmHook, uid_filter: Option<u32>) -> Self {
        let mut prog = Self::new_allow(id, name, hook);
        prog.uid_filter = uid_filter;
        prog.default_verdict = -1; // -EPERM
        prog
    }

    /// Execute the program against a context, returning the raw verdict value.
    pub fn run(&mut self, ctx: &LsmCtx) -> i64 {
        if !self.enabled {
            return 0; // disabled → allow
        }
        self.invocation_count += 1;

        // UID filter check
        if let Some(filter_uid) = self.uid_filter {
            if filter_uid != 0 && ctx.uid != filter_uid {
                // UID doesn't match → fall through to default
                return 0;
            }
        }

        let verdict = self.default_verdict;
        if verdict < 0 {
            self.deny_count += 1;
        } else if verdict == 1 {
            self.audit_count += 1;
        }
        verdict
    }
}

// ---------------------------------------------------------------------------
// Hook slot
// ---------------------------------------------------------------------------

/// A slot within a single hook point containing attached BPF programs.
#[derive(Debug)]
struct HookSlot {
    /// Hook point this slot belongs to.
    hook: LsmHook,
    /// Name of the hook point.
    name: [u8; MAX_HOOK_NAME_LEN],
    /// Attached program IDs (indices into the global program table).
    prog_ids: [u32; MAX_PROGS_PER_HOOK],
    /// Number of attached programs.
    prog_count: usize,
    /// Total invocations across all programs on this hook.
    total_invocations: u64,
}

impl HookSlot {
    /// Create a new, empty hook slot.
    const fn new(hook: LsmHook) -> Self {
        Self {
            hook,
            name: [0u8; MAX_HOOK_NAME_LEN],
            prog_ids: [0u32; MAX_PROGS_PER_HOOK],
            prog_count: 0,
            total_invocations: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// LSM registry
// ---------------------------------------------------------------------------

/// Global BPF LSM registry: holds all programs and hook-point tables.
///
/// Programs are registered once and referenced by ID. Multiple hooks
/// may reference the same program (though programs are hook-specific
/// by design). Programs are stored in a flat array; hook slots store
/// IDs for lookup.
pub struct BpfLsmRegistry {
    /// Flat storage of registered programs.
    programs: [Option<BpfLsmProg>; MAX_LSM_PROGRAMS],
    /// Number of registered programs.
    prog_count: usize,
    /// Per-hook-point attachment tables.
    hooks: [Option<HookSlot>; MAX_HOOK_TYPES],
    /// Next program ID to assign.
    next_id: u32,
    /// Whether the LSM subsystem is globally enabled.
    enabled: bool,
}

impl BpfLsmRegistry {
    /// Construct an empty registry.
    pub const fn new() -> Self {
        Self {
            programs: [const { None }; MAX_LSM_PROGRAMS],
            prog_count: 0,
            hooks: [const { None }; MAX_HOOK_TYPES],
            next_id: 1,
            enabled: true,
        }
    }

    /// Enable or disable the entire BPF LSM subsystem.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Returns `true` if the subsystem is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    // ── Program management ───────────────────────────────────────────────

    /// Load a BPF LSM program into the registry.
    ///
    /// Returns the assigned program ID on success.
    pub fn load_program(&mut self, mut prog: BpfLsmProg) -> Result<u32> {
        if self.prog_count >= MAX_LSM_PROGRAMS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        self.next_id += 1;
        prog.id = id;

        // Find an empty slot
        let slot = self
            .programs
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;
        *slot = Some(prog);
        self.prog_count += 1;
        Ok(id)
    }

    /// Unload (remove) a BPF LSM program by ID.
    ///
    /// Also detaches the program from any hook points it was attached to.
    pub fn unload_program(&mut self, prog_id: u32) -> Result<()> {
        // Find and remove the program
        let slot = self
            .programs
            .iter_mut()
            .find(|s| s.as_ref().map(|p| p.id) == Some(prog_id))
            .ok_or(Error::NotFound)?;
        *slot = None;
        self.prog_count -= 1;

        // Detach from all hooks
        for hook_slot in self.hooks.iter_mut().flatten() {
            hook_slot.prog_ids.iter_mut().for_each(|id| {
                if *id == prog_id {
                    *id = 0;
                }
            });
            // Compact the prog_ids array
            let mut write = 0usize;
            let mut read = 0usize;
            while read < MAX_PROGS_PER_HOOK {
                if hook_slot.prog_ids[read] != 0 {
                    hook_slot.prog_ids[write] = hook_slot.prog_ids[read];
                    write += 1;
                }
                read += 1;
            }
            while write < MAX_PROGS_PER_HOOK {
                hook_slot.prog_ids[write] = 0;
                write += 1;
            }
            hook_slot.prog_count = (0..MAX_PROGS_PER_HOOK)
                .filter(|&i| hook_slot.prog_ids[i] != 0)
                .count();
        }
        Ok(())
    }

    // ── Hook attachment ──────────────────────────────────────────────────

    /// Attach a loaded program to a hook point.
    pub fn attach(&mut self, prog_id: u32, hook: LsmHook) -> Result<()> {
        // Verify the program exists
        let prog_exists = self.programs.iter().any(|s| {
            s.as_ref()
                .map(|p| p.id == prog_id && p.hook == hook)
                .unwrap_or(false)
        });
        if !prog_exists {
            return Err(Error::NotFound);
        }

        let idx = hook.index();
        if self.hooks[idx].is_none() {
            let mut slot = HookSlot::new(hook);
            // Copy hook name bytes
            let name = hook.name().as_bytes();
            let len = name.len().min(MAX_HOOK_NAME_LEN);
            slot.name[..len].copy_from_slice(&name[..len]);
            self.hooks[idx] = Some(slot);
        }

        let slot = self.hooks[idx].as_mut().ok_or(Error::InvalidArgument)?;
        if slot.prog_count >= MAX_PROGS_PER_HOOK {
            return Err(Error::Busy);
        }
        // Check for duplicate
        if slot.prog_ids[..slot.prog_count].contains(&prog_id) {
            return Err(Error::AlreadyExists);
        }
        slot.prog_ids[slot.prog_count] = prog_id;
        slot.prog_count += 1;
        Ok(())
    }

    /// Detach a program from a hook point.
    pub fn detach(&mut self, prog_id: u32, hook: LsmHook) -> Result<()> {
        let idx = hook.index();
        let slot = self.hooks[idx].as_mut().ok_or(Error::NotFound)?;

        let pos = slot.prog_ids[..slot.prog_count]
            .iter()
            .position(|&id| id == prog_id)
            .ok_or(Error::NotFound)?;

        // Shift remaining entries down
        for i in pos..slot.prog_count - 1 {
            slot.prog_ids[i] = slot.prog_ids[i + 1];
        }
        slot.prog_ids[slot.prog_count - 1] = 0;
        slot.prog_count -= 1;
        Ok(())
    }

    // ── Hook dispatch ────────────────────────────────────────────────────

    /// Dispatch a hook invocation and evaluate all attached programs.
    ///
    /// Programs run in attachment order. The first deny verdict short-circuits
    /// the chain and is returned immediately. If all programs allow, returns
    /// `Verdict::Allow`. An audit record is triggered if any program returns
    /// `AuditAllow`.
    pub fn dispatch(&mut self, ctx: &LsmCtx) -> Verdict {
        if !self.enabled {
            return Verdict::Allow;
        }

        let idx = ctx.hook.index();
        let hook_slot = match &self.hooks[idx] {
            Some(s) => s,
            None => return Verdict::Allow,
        };

        let prog_ids: [u32; MAX_PROGS_PER_HOOK] = hook_slot.prog_ids;
        let prog_count = hook_slot.prog_count;

        // Update invocation counter
        if let Some(slot) = self.hooks[idx].as_mut() {
            slot.total_invocations += 1;
        }

        let mut audit_seen = false;

        for i in 0..prog_count {
            let prog_id = prog_ids[i];
            if prog_id == 0 {
                continue;
            }

            // Find the program by ID and run it
            let pos = self
                .programs
                .iter()
                .position(|s| s.as_ref().map(|p| p.id == prog_id).unwrap_or(false));

            if let Some(prog_pos) = pos {
                if let Some(prog) = self.programs[prog_pos].as_mut() {
                    let retval = prog.run(ctx);
                    let verdict = Verdict::from_retval(retval);
                    match verdict {
                        Verdict::Deny(_) => return verdict,
                        Verdict::AuditAllow => audit_seen = true,
                        Verdict::Allow => {}
                    }
                }
            }
        }

        if audit_seen {
            Verdict::AuditAllow
        } else {
            Verdict::Allow
        }
    }

    // ── Query / introspection ────────────────────────────────────────────

    /// Look up a program by ID.
    pub fn get_program(&self, prog_id: u32) -> Option<&BpfLsmProg> {
        self.programs
            .iter()
            .find_map(|s| s.as_ref().filter(|p| p.id == prog_id))
    }

    /// Look up a mutable program by ID.
    pub fn get_program_mut(&mut self, prog_id: u32) -> Option<&mut BpfLsmProg> {
        self.programs
            .iter_mut()
            .find_map(|s| s.as_mut().filter(|p| p.id == prog_id))
    }

    /// Number of registered programs.
    pub fn program_count(&self) -> usize {
        self.prog_count
    }

    /// Number of programs attached to a specific hook.
    pub fn hook_program_count(&self, hook: LsmHook) -> usize {
        self.hooks[hook.index()]
            .as_ref()
            .map(|s| s.prog_count)
            .unwrap_or(0)
    }

    /// Total invocations on a hook.
    pub fn hook_invocation_count(&self, hook: LsmHook) -> u64 {
        self.hooks[hook.index()]
            .as_ref()
            .map(|s| s.total_invocations)
            .unwrap_or(0)
    }

    /// Enable or disable a specific program.
    pub fn set_program_enabled(&mut self, prog_id: u32, enabled: bool) -> Result<()> {
        self.get_program_mut(prog_id)
            .ok_or(Error::NotFound)
            .map(|p| p.enabled = enabled)
    }
}

impl Default for BpfLsmRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Convenience helpers for kernel hooks
// ---------------------------------------------------------------------------

/// Evaluate the `file_open` LSM hook.
///
/// Returns `Ok(())` if all attached programs allow, or `Err(PermissionDenied)`
/// if any program denies.
pub fn check_file_open(registry: &mut BpfLsmRegistry, uid: u32, gid: u32, pid: u32) -> Result<()> {
    let ctx = LsmCtx::new(LsmHook::FileOpen, uid, gid, pid);
    let verdict = registry.dispatch(&ctx);
    if verdict.is_allow() {
        Ok(())
    } else {
        Err(Error::PermissionDenied)
    }
}

/// Evaluate the `bprm_check` LSM hook (execve security check).
pub fn check_bprm(
    registry: &mut BpfLsmRegistry,
    uid: u32,
    gid: u32,
    pid: u32,
    path_hash: u64,
) -> Result<()> {
    let mut ctx = LsmCtx::new(LsmHook::BprmCheck, uid, gid, pid);
    ctx.set_data(&path_hash.to_le_bytes());
    let verdict = registry.dispatch(&ctx);
    if verdict.is_allow() {
        Ok(())
    } else {
        Err(Error::PermissionDenied)
    }
}

/// Evaluate the `socket_connect` LSM hook.
pub fn check_socket_connect(
    registry: &mut BpfLsmRegistry,
    uid: u32,
    gid: u32,
    pid: u32,
    dest_addr: u32,
    dest_port: u16,
) -> Result<()> {
    let mut ctx = LsmCtx::new(LsmHook::SocketConnect, uid, gid, pid);
    let mut data = [0u8; 6];
    data[..4].copy_from_slice(&dest_addr.to_le_bytes());
    data[4..6].copy_from_slice(&dest_port.to_le_bytes());
    ctx.set_data(&data);
    let verdict = registry.dispatch(&ctx);
    if verdict.is_allow() {
        Ok(())
    } else {
        Err(Error::PermissionDenied)
    }
}

/// Evaluate the `task_alloc` LSM hook (new task/thread creation).
pub fn check_task_alloc(
    registry: &mut BpfLsmRegistry,
    uid: u32,
    gid: u32,
    parent_pid: u32,
) -> Result<()> {
    let ctx = LsmCtx::new(LsmHook::TaskAlloc, uid, gid, parent_pid);
    let verdict = registry.dispatch(&ctx);
    if verdict.is_allow() {
        Ok(())
    } else {
        Err(Error::PermissionDenied)
    }
}

/// Evaluate the `capable` LSM hook.
pub fn check_capable(
    registry: &mut BpfLsmRegistry,
    uid: u32,
    gid: u32,
    pid: u32,
    cap: u32,
) -> Result<()> {
    let mut ctx = LsmCtx::new(LsmHook::Capable, uid, gid, pid);
    ctx.set_data(&cap.to_le_bytes());
    let verdict = registry.dispatch(&ctx);
    if verdict.is_allow() {
        Ok(())
    } else {
        Err(Error::PermissionDenied)
    }
}

/// Evaluate the `task_kill` LSM hook.
pub fn check_task_kill(
    registry: &mut BpfLsmRegistry,
    uid: u32,
    gid: u32,
    sender_pid: u32,
    target_pid: u32,
    signal: u32,
) -> Result<()> {
    let mut ctx = LsmCtx::new(LsmHook::TaskKill, uid, gid, sender_pid);
    let mut data = [0u8; 8];
    data[..4].copy_from_slice(&target_pid.to_le_bytes());
    data[4..8].copy_from_slice(&signal.to_le_bytes());
    ctx.set_data(&data);
    let verdict = registry.dispatch(&ctx);
    if verdict.is_allow() {
        Ok(())
    } else {
        Err(Error::PermissionDenied)
    }
}

// ---------------------------------------------------------------------------
// Statistics snapshot
// ---------------------------------------------------------------------------

/// Aggregate statistics snapshot for the BPF LSM subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct LsmStats {
    /// Total number of loaded programs.
    pub total_programs: usize,
    /// Total hook invocations across all hook points.
    pub total_invocations: u64,
    /// Total deny verdicts across all programs.
    pub total_denies: u64,
    /// Total audit verdicts across all programs.
    pub total_audits: u64,
}

impl BpfLsmRegistry {
    /// Gather aggregate statistics.
    pub fn stats(&self) -> LsmStats {
        let mut stats = LsmStats::default();
        stats.total_programs = self.prog_count;
        for slot in self.hooks.iter().flatten() {
            stats.total_invocations += slot.total_invocations;
        }
        for prog in self.programs.iter().flatten() {
            stats.total_denies += prog.deny_count;
            stats.total_audits += prog.audit_count;
        }
        stats
    }
}
