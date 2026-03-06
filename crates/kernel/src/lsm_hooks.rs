// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Linux Security Module (LSM) hook dispatch layer.
//!
//! Provides the hook registration and dispatch infrastructure that allows
//! multiple security modules to stack their policies on top of each other.
//! Each kernel operation calls into this layer, which fans out to all
//! registered LSM hook implementations and returns the first denial.
//!
//! # Architecture
//!
//! | Component            | Purpose                                          |
//! |----------------------|--------------------------------------------------|
//! | [`LsmHookId`]        | Identifies a specific security hook point        |
//! | [`LsmCallback`]      | Function pointer type for hook callbacks         |
//! | [`LsmModule`]        | A registered security module with its hooks      |
//! | [`LsmRegistry`]      | Manages all registered modules and dispatches    |
//!
//! # Hook Dispatch Protocol
//!
//! 1. Kernel code calls `LsmRegistry::call_hook(hook_id, ctx)`.
//! 2. The registry iterates all registered modules in priority order.
//! 3. Each module's hook for `hook_id` is called with `ctx`.
//! 4. If any hook returns a non-zero (denied) result, dispatch stops.
//! 5. Zero means allow; the first denial wins.
//!
//! # Supported Hooks
//!
//! A representative subset of Linux LSM hooks is defined. The full set
//! is defined in `include/linux/lsm_hooks.h` in the Linux source.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of registered LSM modules.
pub const MAX_LSM_MODULES: usize = 8;

/// Maximum number of hooks per module.
pub const MAX_HOOKS_PER_MODULE: usize = 64;

// ---------------------------------------------------------------------------
// Hook identifiers
// ---------------------------------------------------------------------------

/// Identifies a specific LSM hook point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LsmHookId {
    // --- Task/Process hooks ---
    /// Task created via fork/clone.
    TaskCreate = 0,
    /// Task is about to exec.
    BprmCheckSecurity = 1,
    /// Credentials are being committed for new task.
    TaskFixSetuid = 2,
    /// Task sending a signal.
    TaskKill = 3,
    /// Task setting scheduling policy.
    TaskSetscheduler = 4,
    /// Task calling ptrace.
    TaskPtrace = 5,

    // --- File/inode hooks ---
    /// Permission check for file open.
    FileOpen = 10,
    /// Permission check before file read.
    FilePermission = 11,
    /// inode creation.
    InodeCreate = 12,
    /// inode unlink.
    InodeUnlink = 13,
    /// inode rename.
    InodeRename = 14,
    /// inode permission check.
    InodePermission = 15,
    /// Extended attribute set.
    InodeSetxattr = 16,
    /// Extended attribute get.
    InodeGetxattr = 17,

    // --- Network hooks ---
    /// Socket creation.
    SocketCreate = 20,
    /// Socket connect.
    SocketConnect = 21,
    /// Socket bind.
    SocketBind = 22,
    /// Socket accept.
    SocketAccept = 23,
    /// Socket send.
    SocketSendmsg = 24,
    /// Socket receive.
    SocketRecvmsg = 25,

    // --- IPC hooks ---
    /// Message queue receive.
    MsgQueueMsgrcv = 30,
    /// Shared memory attach.
    ShmShmat = 31,
    /// Semaphore operation.
    SemSemop = 32,

    // --- Capability hooks ---
    /// Capability check.
    Capable = 40,
    /// Set capabilities (setpcap).
    Setcap = 41,

    // --- Module hooks ---
    /// Module load.
    KernelModuleRequest = 50,
    /// BPF hook.
    BpfProg = 51,

    // --- Audit hooks ---
    /// Audit rule access.
    AuditRule = 60,

    // Sentinel — must stay last.
    #[allow(non_camel_case_types)]
    _MAX = 64,
}

impl LsmHookId {
    /// Convert to usize index.
    pub fn index(self) -> usize {
        self as usize
    }
}

// ---------------------------------------------------------------------------
// Hook context
// ---------------------------------------------------------------------------

/// Context passed to an LSM hook callback.
///
/// All fields are optional; hooks only inspect fields relevant to their hook
/// point. Using a unified struct avoids the need for generics in `no_std`.
#[derive(Debug, Clone, Copy, Default)]
pub struct LsmContext {
    /// UID of the acting process.
    pub uid: u32,
    /// GID of the acting process.
    pub gid: u32,
    /// PID of the acting process.
    pub pid: u32,
    /// Target UID (e.g., file owner).
    pub target_uid: u32,
    /// Signal number (for TaskKill hook).
    pub signum: i32,
    /// Requested permission bits.
    pub mask: u32,
    /// File descriptor or inode number.
    pub fd_or_ino: u64,
    /// Socket address family.
    pub addr_family: u16,
    /// Port number (for socket hooks).
    pub port: u16,
    /// Capability number (for Capable hook).
    pub cap: u8,
}

// ---------------------------------------------------------------------------
// Callback type
// ---------------------------------------------------------------------------

/// LSM hook callback signature.
///
/// Returns `0` to allow, or a non-zero error code to deny.
pub type LsmCallback = fn(ctx: &LsmContext) -> i32;

// ---------------------------------------------------------------------------
// LSM module
// ---------------------------------------------------------------------------

/// A registered LSM module.
pub struct LsmModule {
    /// Module name (NUL-terminated, max 31 chars).
    pub name: [u8; 32],
    /// Hook callbacks indexed by `LsmHookId` ordinal.
    hooks: [Option<LsmCallback>; MAX_HOOKS_PER_MODULE],
    /// Priority (lower value = called earlier in dispatch).
    pub priority: u8,
    /// Whether this module is active.
    pub active: bool,
}

impl LsmModule {
    /// Create a new LSM module with no hooks registered.
    pub const fn new(name: &[u8], priority: u8) -> Self {
        let mut buf = [0u8; 32];
        let len = if name.len() < 32 { name.len() } else { 31 };
        let mut i = 0;
        while i < len {
            buf[i] = name[i];
            i += 1;
        }
        Self {
            name: buf,
            hooks: [None; MAX_HOOKS_PER_MODULE],
            priority,
            active: true,
        }
    }

    /// Register a hook callback.
    pub fn set_hook(&mut self, hook: LsmHookId, cb: LsmCallback) -> Result<()> {
        let idx = hook.index();
        if idx >= MAX_HOOKS_PER_MODULE {
            return Err(Error::InvalidArgument);
        }
        self.hooks[idx] = Some(cb);
        Ok(())
    }

    /// Call the hook for the given id with the provided context.
    ///
    /// Returns `0` if no hook is registered (allow by default).
    pub fn call(&self, hook: LsmHookId, ctx: &LsmContext) -> i32 {
        let idx = hook.index();
        if idx >= MAX_HOOKS_PER_MODULE {
            return 0;
        }
        match self.hooks[idx] {
            Some(cb) => cb(ctx),
            None => 0,
        }
    }

    /// Module name as a byte slice (without trailing NUL).
    pub fn name_bytes(&self) -> &[u8] {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(32);
        &self.name[..len]
    }
}

// ---------------------------------------------------------------------------
// LSM registry
// ---------------------------------------------------------------------------

/// Registry that manages all active LSM modules and dispatches hooks.
pub struct LsmRegistry {
    modules: [Option<LsmModule>; MAX_LSM_MODULES],
    count: usize,
    /// Total hook calls dispatched.
    total_calls: u64,
    /// Total denials returned.
    total_denials: u64,
}

impl LsmRegistry {
    /// Create an empty LSM registry.
    pub const fn new() -> Self {
        Self {
            modules: [const { None }; MAX_LSM_MODULES],
            count: 0,
            total_calls: 0,
            total_denials: 0,
        }
    }

    /// Register a security module.
    ///
    /// Modules are sorted by priority (lowest first) on insertion.
    pub fn register(&mut self, module: LsmModule) -> Result<()> {
        if self.count >= MAX_LSM_MODULES {
            return Err(Error::OutOfMemory);
        }
        // Find insertion point preserving priority order.
        let mut insert_at = self.count;
        for i in 0..self.count {
            let existing_priority = self.modules[i].as_ref().map_or(u8::MAX, |m| m.priority);
            if module.priority < existing_priority {
                insert_at = i;
                break;
            }
        }
        // Shift right to make room.
        let mut i = self.count;
        while i > insert_at {
            self.modules[i] = self.modules[i - 1].take();
            i -= 1;
        }
        self.modules[insert_at] = Some(module);
        self.count += 1;
        Ok(())
    }

    /// Unregister a module by name.
    pub fn unregister(&mut self, name: &[u8]) -> Result<()> {
        let pos = self.modules[..self.count]
            .iter()
            .position(|m| m.as_ref().map_or(false, |m| m.name_bytes() == name))
            .ok_or(Error::NotFound)?;
        // Shift left to fill gap.
        self.modules[pos] = None;
        for i in pos..self.count - 1 {
            self.modules[i] = self.modules[i + 1].take();
        }
        self.count -= 1;
        Ok(())
    }

    /// Dispatch a hook to all registered modules in priority order.
    ///
    /// Returns `Ok(())` if all modules allow, or `Err(PermissionDenied)` if
    /// any module denies.
    pub fn call_hook(&mut self, hook: LsmHookId, ctx: &LsmContext) -> Result<()> {
        self.total_calls = self.total_calls.saturating_add(1);
        for i in 0..self.count {
            let ret = match &self.modules[i] {
                Some(m) if m.active => m.call(hook, ctx),
                _ => 0,
            };
            if ret != 0 {
                self.total_denials = self.total_denials.saturating_add(1);
                return Err(Error::PermissionDenied);
            }
        }
        Ok(())
    }

    /// Number of registered modules.
    pub fn module_count(&self) -> usize {
        self.count
    }

    /// Total hook calls dispatched.
    pub fn total_calls(&self) -> u64 {
        self.total_calls
    }

    /// Total denials returned.
    pub fn total_denials(&self) -> u64 {
        self.total_denials
    }

    /// Look up a module by name (immutable).
    pub fn get_module(&self, name: &[u8]) -> Option<&LsmModule> {
        self.modules[..self.count]
            .iter()
            .flatten()
            .find(|m| m.name_bytes() == name)
    }
}

impl Default for LsmRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Convenience: a no-op "allow-all" LSM
// ---------------------------------------------------------------------------

/// Construct an always-allow LSM module.
pub fn make_allow_all_module() -> LsmModule {
    LsmModule::new(b"allow_all", u8::MAX)
}
