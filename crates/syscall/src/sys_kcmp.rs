// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `kcmp(2)` syscall handler — compare kernel resources across processes.
//!
//! `kcmp` allows a caller (subject to ptrace-level permissions) to test
//! whether two processes share the same kernel-internal object.  The
//! canonical use case is checkpoint-restore (CRIU), which needs to know
//! whether two file descriptors in different processes refer to the same
//! open file description.
//!
//! # Syscall signature
//!
//! ```text
//! int kcmp(pid_t pid1, pid_t pid2, int type,
//!          unsigned long idx1, unsigned long idx2);
//! ```
//!
//! # Return value
//!
//! Returns a total ordering value:
//! - `0`  — the two resources are the same (shared) kernel object.
//! - `-1` — resource of `pid1` sorts before `pid2` (different objects).
//! - `1`  — resource of `pid1` sorts after `pid2` (different objects).
//!
//! # Comparison types
//!
//! | Constant | Value | Semantics |
//! |----------|-------|-----------|
//! | `KCMP_FILE`    | 0 | Compare file descriptors `idx1`/`idx2` across processes |
//! | `KCMP_VM`      | 1 | Compare virtual memory (mm_struct) |
//! | `KCMP_FILES`   | 2 | Compare file descriptor tables (files_struct) |
//! | `KCMP_FS`      | 3 | Compare filesystem info (fs_struct) |
//! | `KCMP_SIGHAND` | 4 | Compare signal handler tables (sighand_struct) |
//! | `KCMP_IO`      | 5 | Compare I/O contexts (io_context) |
//! | `KCMP_SYSVSEM` | 6 | Compare System V semaphore undo lists |
//! | `KCMP_EPOLL_TFD` | 7 | Compare epoll target fd association |
//!
//! # Permission model
//!
//! The caller must hold `CAP_SYS_PTRACE`, or be the same user as the
//! target processes, to perform the comparison.
//!
//! # References
//!
//! - Linux: `kernel/kcmp.c`, `include/uapi/linux/kcmp.h`
//! - `kcmp(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Type constants
// ---------------------------------------------------------------------------

/// Compare file descriptors for file-description identity.
pub const KCMP_FILE: u32 = 0;
/// Compare virtual memory (mm_struct).
pub const KCMP_VM: u32 = 1;
/// Compare file descriptor tables (files_struct).
pub const KCMP_FILES: u32 = 2;
/// Compare filesystem context (fs_struct).
pub const KCMP_FS: u32 = 3;
/// Compare signal handler table (sighand_struct).
pub const KCMP_SIGHAND: u32 = 4;
/// Compare I/O context (io_context).
pub const KCMP_IO: u32 = 5;
/// Compare System V semaphore undo state.
pub const KCMP_SYSVSEM: u32 = 6;
/// Compare epoll target file descriptor association.
pub const KCMP_EPOLL_TFD: u32 = 7;

/// One past the last valid type.
const KCMP_TYPE_LIMIT: u32 = 8;

// ---------------------------------------------------------------------------
// Capability constant
// ---------------------------------------------------------------------------

/// Linux capability number for ptrace access.
const CAP_SYS_PTRACE: u32 = 19;

// ---------------------------------------------------------------------------
// Table dimensions
// ---------------------------------------------------------------------------

/// Maximum number of processes the context tracks.
const MAX_PROCS: usize = 512;

/// Maximum open file descriptors per process (tracked in the table).
const MAX_FDS: usize = 128;

// ---------------------------------------------------------------------------
// KcmpOrd — ordering result
// ---------------------------------------------------------------------------

/// Ordering of two kernel resource pointers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KcmpOrd {
    /// Same kernel object (shared resource).
    Equal,
    /// Resource of pid1 sorts before pid2.
    Less,
    /// Resource of pid1 sorts after pid2.
    Greater,
}

impl KcmpOrd {
    /// Convert to the integer returned by the syscall.
    pub const fn as_i32(self) -> i32 {
        match self {
            KcmpOrd::Equal => 0,
            KcmpOrd::Less => -1,
            KcmpOrd::Greater => 1,
        }
    }

    /// Derive ordering from two opaque pointer values.
    pub fn from_ptrs(a: u64, b: u64) -> Self {
        match a.cmp(&b) {
            core::cmp::Ordering::Equal => KcmpOrd::Equal,
            core::cmp::Ordering::Less => KcmpOrd::Less,
            core::cmp::Ordering::Greater => KcmpOrd::Greater,
        }
    }
}

// ---------------------------------------------------------------------------
// ProcEntry — per-process resource pointers
// ---------------------------------------------------------------------------

/// Opaque kernel-object identifiers for one process.
///
/// In a real kernel these would be addresses of kernel structures.  Here
/// we store representative values that can be shared between processes to
/// model cloned or inherited resources.
#[derive(Debug, Clone, Copy)]
pub struct ProcEntry {
    /// Process ID.
    pub pid: u32,
    /// Owner UID (for same-user permission checks).
    pub uid: u32,
    /// mm_struct identifier.
    pub mm_id: u64,
    /// files_struct identifier.
    pub files_id: u64,
    /// fs_struct identifier.
    pub fs_id: u64,
    /// sighand_struct identifier.
    pub sighand_id: u64,
    /// io_context identifier.
    pub io_id: u64,
    /// sysvsem undo-list identifier.
    pub sysvsem_id: u64,
    /// Per-fd open-file-description identifiers.
    pub fds: [u64; MAX_FDS],
    /// Number of valid fd slots.
    pub fd_count: usize,
    /// Whether this slot is in use.
    pub active: bool,
}

impl ProcEntry {
    /// Create an empty, inactive entry.
    const fn empty() -> Self {
        Self {
            pid: 0,
            uid: 0,
            mm_id: 0,
            files_id: 0,
            fs_id: 0,
            sighand_id: 0,
            io_id: 0,
            sysvsem_id: 0,
            fds: [0u64; MAX_FDS],
            fd_count: 0,
            active: false,
        }
    }

    /// Return the id for a struct-level resource type.
    fn struct_id(&self, ty: u32) -> Result<u64> {
        match ty {
            KCMP_VM => Ok(self.mm_id),
            KCMP_FILES => Ok(self.files_id),
            KCMP_FS => Ok(self.fs_id),
            KCMP_SIGHAND => Ok(self.sighand_id),
            KCMP_IO => Ok(self.io_id),
            KCMP_SYSVSEM => Ok(self.sysvsem_id),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Return the file-description id for `fd`.
    pub fn fd_id(&self, fd: u64) -> Result<u64> {
        let idx = usize::try_from(fd).map_err(|_| Error::InvalidArgument)?;
        if idx >= MAX_FDS || idx >= self.fd_count {
            return Err(Error::InvalidArgument);
        }
        let id = self.fds[idx];
        if id == 0 {
            return Err(Error::NotFound);
        }
        Ok(id)
    }

    /// Set the file-description id for `fd`.
    pub fn set_fd(&mut self, fd: usize, id: u64) -> Result<()> {
        if fd >= MAX_FDS {
            return Err(Error::InvalidArgument);
        }
        self.fds[fd] = id;
        if fd >= self.fd_count {
            self.fd_count = fd + 1;
        }
        Ok(())
    }
}

impl Default for ProcEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// ---------------------------------------------------------------------------
// SysKcmpContext — system-wide kcmp context
// ---------------------------------------------------------------------------

/// System-wide context for `kcmp(2)` operations.
///
/// Stores per-process resource identifiers and caller credentials.
pub struct SysKcmpContext {
    procs: [ProcEntry; MAX_PROCS],
    proc_count: usize,
    /// Caller's capability bitmask.
    pub caller_caps: u64,
    /// Caller's UID.
    pub caller_uid: u32,
}

impl SysKcmpContext {
    /// Create an empty context with no registered processes.
    pub fn new() -> Self {
        Self {
            procs: [const { ProcEntry::empty() }; MAX_PROCS],
            proc_count: 0,
            caller_caps: 0,
            caller_uid: 0,
        }
    }

    /// Set caller credentials used for permission checks.
    pub fn set_caller(&mut self, caps: u64, uid: u32) {
        self.caller_caps = caps;
        self.caller_uid = uid;
    }

    /// Register a process entry.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfMemory`] — process table is full.
    pub fn register(&mut self, entry: ProcEntry) -> Result<()> {
        let slot = self
            .procs
            .iter()
            .position(|p| !p.active)
            .ok_or(Error::OutOfMemory)?;
        self.procs[slot] = entry;
        self.procs[slot].active = true;
        self.proc_count += 1;
        Ok(())
    }

    fn lookup(&self, pid: u32) -> Result<&ProcEntry> {
        self.procs
            .iter()
            .find(|p| p.active && p.pid == pid)
            .ok_or(Error::NotFound)
    }

    fn check_permission(&self, pid: u32) -> Result<()> {
        // CAP_SYS_PTRACE bypasses user-level checks.
        if self.caller_caps & (1u64 << CAP_SYS_PTRACE) != 0 {
            return Ok(());
        }
        let entry = self.lookup(pid)?;
        if entry.uid == self.caller_uid {
            return Ok(());
        }
        Err(Error::PermissionDenied)
    }

    /// Perform a kcmp comparison.
    pub fn compare(&self, pid1: u32, pid2: u32, ty: u32, idx1: u64, idx2: u64) -> Result<KcmpOrd> {
        if ty >= KCMP_TYPE_LIMIT {
            return Err(Error::InvalidArgument);
        }
        self.check_permission(pid1)?;
        self.check_permission(pid2)?;

        let e1 = self.lookup(pid1)?;
        let e2 = self.lookup(pid2)?;

        match ty {
            KCMP_FILE => {
                let a = e1.fd_id(idx1)?;
                let b = e2.fd_id(idx2)?;
                Ok(KcmpOrd::from_ptrs(a, b))
            }
            KCMP_VM | KCMP_FILES | KCMP_FS | KCMP_SIGHAND | KCMP_IO | KCMP_SYSVSEM => {
                let a = e1.struct_id(ty)?;
                let b = e2.struct_id(ty)?;
                Ok(KcmpOrd::from_ptrs(a, b))
            }
            KCMP_EPOLL_TFD => {
                // idx1/idx2 are epoll fds; compare the associated file descriptions.
                let a = e1.fd_id(idx1)?;
                let b = e2.fd_id(idx2)?;
                Ok(KcmpOrd::from_ptrs(a, b))
            }
            _ => Err(Error::InvalidArgument),
        }
    }
}

impl Default for SysKcmpContext {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// sys_kcmp_handler — entry point
// ---------------------------------------------------------------------------

/// Handle the `kcmp(2)` syscall.
///
/// # Arguments
///
/// * `ctx`   — System-wide kcmp context (contains process table and caller creds).
/// * `pid1`  — First target process ID.
/// * `pid2`  — Second target process ID.
/// * `ty`    — Comparison type (`KCMP_*` constant).
/// * `idx1`  — First type-specific index (e.g., fd number for `KCMP_FILE`).
/// * `idx2`  — Second type-specific index.
///
/// # Returns
///
/// Integer ordering: `0` (equal), `-1` (less), `1` (greater).
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — Unknown type or out-of-range index.
/// * [`Error::NotFound`]         — Process or fd not found.
/// * [`Error::PermissionDenied`] — Insufficient ptrace access.
pub fn sys_kcmp_handler(
    ctx: &SysKcmpContext,
    pid1: u32,
    pid2: u32,
    ty: u32,
    idx1: u64,
    idx2: u64,
) -> Result<i32> {
    let ord = ctx.compare(pid1, pid2, ty, idx1, idx2)?;
    Ok(ord.as_i32())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(pid: u32, seed: u64, uid: u32) -> ProcEntry {
        let mut e = ProcEntry::empty();
        e.pid = pid;
        e.uid = uid;
        e.active = true;
        e.mm_id = seed;
        e.files_id = seed + 1;
        e.fs_id = seed + 2;
        e.sighand_id = seed + 3;
        e.io_id = seed + 4;
        e.sysvsem_id = seed + 5;
        e
    }

    fn setup() -> SysKcmpContext {
        let mut ctx = SysKcmpContext::new();
        ctx.set_caller(1u64 << CAP_SYS_PTRACE, 0);

        let mut e1 = make_entry(1, 0x1000, 100);
        e1.set_fd(0, 0xAAAA).unwrap();
        e1.set_fd(1, 0xBBBB).unwrap();
        ctx.register(e1).unwrap();

        let mut e2 = make_entry(2, 0x2000, 100);
        e2.set_fd(0, 0xAAAA).unwrap(); // same file description as e1.fd[0]
        e2.set_fd(1, 0xCCCC).unwrap();
        ctx.register(e2).unwrap();

        ctx
    }

    #[test]
    fn kcmp_file_equal() {
        let ctx = setup();
        assert_eq!(sys_kcmp_handler(&ctx, 1, 2, KCMP_FILE, 0, 0), Ok(0));
    }

    #[test]
    fn kcmp_file_different() {
        let ctx = setup();
        assert_ne!(sys_kcmp_handler(&ctx, 1, 2, KCMP_FILE, 1, 1).unwrap(), 0);
    }

    #[test]
    fn kcmp_vm_different() {
        let ctx = setup();
        assert_ne!(sys_kcmp_handler(&ctx, 1, 2, KCMP_VM, 0, 0).unwrap(), 0);
    }

    #[test]
    fn kcmp_vm_shared() {
        let mut ctx = SysKcmpContext::new();
        ctx.set_caller(1u64 << CAP_SYS_PTRACE, 0);
        let e1 = make_entry(1, 0x100, 0);
        let mut e2 = make_entry(2, 0x200, 0);
        e2.mm_id = e1.mm_id;
        ctx.register(e1).unwrap();
        ctx.register(e2).unwrap();
        assert_eq!(sys_kcmp_handler(&ctx, 1, 2, KCMP_VM, 0, 0), Ok(0));
    }

    #[test]
    fn kcmp_invalid_type_rejected() {
        let ctx = setup();
        assert_eq!(
            sys_kcmp_handler(&ctx, 1, 2, 99, 0, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn kcmp_process_not_found() {
        let ctx = setup();
        assert_eq!(
            sys_kcmp_handler(&ctx, 1, 999, KCMP_VM, 0, 0),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn kcmp_permission_denied_different_uid() {
        let mut ctx = SysKcmpContext::new();
        ctx.set_caller(0, 100);
        let e1 = make_entry(1, 0x100, 100);
        let e2 = make_entry(2, 0x200, 200); // different uid
        ctx.register(e1).unwrap();
        ctx.register(e2).unwrap();
        assert_eq!(
            sys_kcmp_handler(&ctx, 1, 2, KCMP_VM, 0, 0),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn kcmp_same_uid_allowed_without_cap() {
        let mut ctx = SysKcmpContext::new();
        ctx.set_caller(0, 50);
        let e1 = make_entry(1, 0x100, 50);
        let e2 = make_entry(2, 0x200, 50);
        ctx.register(e1).unwrap();
        ctx.register(e2).unwrap();
        assert!(sys_kcmp_handler(&ctx, 1, 2, KCMP_VM, 0, 0).is_ok());
    }

    #[test]
    fn kcmp_ordering_values() {
        assert_eq!(KcmpOrd::Equal.as_i32(), 0);
        assert_eq!(KcmpOrd::Less.as_i32(), -1);
        assert_eq!(KcmpOrd::Greater.as_i32(), 1);
    }

    #[test]
    fn kcmp_sighand_fs_io_sysvsem() {
        let ctx = setup();
        for ty in [KCMP_SIGHAND, KCMP_FS, KCMP_IO, KCMP_SYSVSEM] {
            assert!(sys_kcmp_handler(&ctx, 1, 2, ty, 0, 0).is_ok());
        }
    }
}
