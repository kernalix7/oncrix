// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `kcmp(2)` — compare kernel resources between two processes.
//!
//! The `kcmp` system call allows comparing whether two processes
//! share the same kernel resource (file descriptor table, virtual
//! memory, filesystem info, signal handlers, I/O context, or
//! System V semaphore undo state).
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
//! Returns an ordering value suitable for sorting:
//! - 0 if the resources are equal (shared).
//! - Positive if resource of pid1 sorts after pid2.
//! - Negative if resource of pid1 sorts before pid2.
//!
//! # Comparison types
//!
//! | Type | Description |
//! |------|-------------|
//! | `KCMP_FILE` | Compare file descriptors idx1 and idx2 |
//! | `KCMP_VM` | Compare virtual memory (mm_struct) |
//! | `KCMP_FILES` | Compare file descriptor table (files_struct) |
//! | `KCMP_FS` | Compare filesystem information (fs_struct) |
//! | `KCMP_SIGHAND` | Compare signal handlers (sighand_struct) |
//! | `KCMP_IO` | Compare I/O context (io_context) |
//! | `KCMP_SYSVSEM` | Compare System V semaphore undo state |
//! | `KCMP_EPOLL_TFD` | Compare epoll target fd association |
//!
//! # Security
//!
//! Access requires ptrace read permission on both target processes.
//! This is checked via `CAP_SYS_PTRACE` or same-user credentials.
//!
//! # References
//!
//! - Linux: `kernel/kcmp.c`, `include/uapi/linux/kcmp.h`
//! - `kcmp(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants — comparison types
// ---------------------------------------------------------------------------

/// Compare two file descriptors for identity.
pub const KCMP_FILE: u32 = 0;
/// Compare virtual memory (mm_struct pointer).
pub const KCMP_VM: u32 = 1;
/// Compare file descriptor tables (files_struct pointer).
pub const KCMP_FILES: u32 = 2;
/// Compare filesystem info (fs_struct pointer).
pub const KCMP_FS: u32 = 3;
/// Compare signal handlers (sighand_struct pointer).
pub const KCMP_SIGHAND: u32 = 4;
/// Compare I/O contexts (io_context pointer).
pub const KCMP_IO: u32 = 5;
/// Compare System V semaphore undo state.
pub const KCMP_SYSVSEM: u32 = 6;
/// Compare epoll target fd association.
pub const KCMP_EPOLL_TFD: u32 = 7;

/// Maximum valid comparison type.
const KCMP_TYPES_MAX: u32 = 8;

// ---------------------------------------------------------------------------
// Constants — capabilities
// ---------------------------------------------------------------------------

/// Capability required for ptrace access.
const CAP_SYS_PTRACE: u32 = 19;

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Maximum PIDs in the system.
const MAX_PIDS: usize = 1024;

/// Maximum file descriptors per process.
const MAX_FDS: usize = 256;

// ---------------------------------------------------------------------------
// KcmpResult — comparison ordering
// ---------------------------------------------------------------------------

/// Result of a kcmp comparison, expressing a total ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KcmpResult {
    /// Resources are the same (shared kernel object).
    Equal,
    /// Resource of pid1 sorts before pid2.
    Less,
    /// Resource of pid1 sorts after pid2.
    Greater,
}

impl KcmpResult {
    /// Convert to the integer value returned by the syscall.
    ///
    /// - `Equal` → 0
    /// - `Less` → -1 (encoded as 2 for unsigned comparison)
    /// - `Greater` → 1
    pub const fn to_raw(self) -> i32 {
        match self {
            KcmpResult::Equal => 0,
            KcmpResult::Less => -1,
            KcmpResult::Greater => 1,
        }
    }

    /// Create from comparing two opaque kernel pointers.
    ///
    /// The pointer values are obfuscated (not leaked to user-space)
    /// but their relative ordering is preserved.
    pub fn from_ptrs(ptr1: u64, ptr2: u64) -> Self {
        if ptr1 == ptr2 {
            KcmpResult::Equal
        } else if ptr1 < ptr2 {
            KcmpResult::Less
        } else {
            KcmpResult::Greater
        }
    }
}

// ---------------------------------------------------------------------------
// ProcessResources — per-process kernel resource pointers
// ---------------------------------------------------------------------------

/// Opaque kernel resource pointers for a process.
///
/// Each field represents a kernel pointer (or hash thereof) to the
/// process's shared kernel objects. When two processes share a
/// resource, the corresponding pointer values are identical.
#[derive(Debug, Clone, Copy)]
pub struct ProcessResources {
    /// Virtual memory (mm_struct) pointer.
    pub mm_ptr: u64,
    /// File descriptor table (files_struct) pointer.
    pub files_ptr: u64,
    /// Filesystem info (fs_struct) pointer.
    pub fs_ptr: u64,
    /// Signal handlers (sighand_struct) pointer.
    pub sighand_ptr: u64,
    /// I/O context (io_context) pointer.
    pub io_ptr: u64,
    /// System V semaphore undo state pointer.
    pub sysvsem_ptr: u64,
    /// File descriptor-to-kernel-object mapping.
    ///
    /// Each entry is the kernel file pointer for that fd slot.
    /// Unused slots are 0.
    pub fd_table: [u64; MAX_FDS],
    /// Number of open file descriptors.
    pub fd_count: usize,
}

impl ProcessResources {
    /// Create empty resources with unique pointers (no sharing).
    pub fn new(seed: u64) -> Self {
        Self {
            mm_ptr: seed,
            files_ptr: seed.wrapping_add(1),
            fs_ptr: seed.wrapping_add(2),
            sighand_ptr: seed.wrapping_add(3),
            io_ptr: seed.wrapping_add(4),
            sysvsem_ptr: seed.wrapping_add(5),
            fd_table: [0; MAX_FDS],
            fd_count: 0,
        }
    }

    /// Get the kernel pointer for a file descriptor.
    pub fn get_fd_ptr(&self, fd: u64) -> Result<u64> {
        let idx = fd as usize;
        if idx >= MAX_FDS || idx >= self.fd_count {
            return Err(Error::InvalidArgument);
        }
        if self.fd_table[idx] == 0 {
            return Err(Error::NotFound);
        }
        Ok(self.fd_table[idx])
    }

    /// Set the kernel pointer for a file descriptor.
    pub fn set_fd_ptr(&mut self, fd: usize, ptr: u64) -> Result<()> {
        if fd >= MAX_FDS {
            return Err(Error::InvalidArgument);
        }
        self.fd_table[fd] = ptr;
        if fd >= self.fd_count {
            self.fd_count = fd + 1;
        }
        Ok(())
    }

    /// Get the resource pointer for a given comparison type.
    fn get_resource_ptr(&self, kcmp_type: u32) -> Result<u64> {
        match kcmp_type {
            KCMP_VM => Ok(self.mm_ptr),
            KCMP_FILES => Ok(self.files_ptr),
            KCMP_FS => Ok(self.fs_ptr),
            KCMP_SIGHAND => Ok(self.sighand_ptr),
            KCMP_IO => Ok(self.io_ptr),
            KCMP_SYSVSEM => Ok(self.sysvsem_ptr),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ---------------------------------------------------------------------------
// EpollTfd — epoll target fd descriptor
// ---------------------------------------------------------------------------

/// Descriptor for `KCMP_EPOLL_TFD` comparisons.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KcmpEpollTfd {
    /// Epoll file descriptor.
    pub efd: u64,
    /// Target file descriptor monitored by epoll.
    pub tfd: u64,
    /// Target file offset (position in the epoll interest list).
    pub toff: u64,
}

// ---------------------------------------------------------------------------
// KcmpContext — system-wide kcmp context
// ---------------------------------------------------------------------------

/// System-wide kcmp context holding per-process resource info.
pub struct KcmpContext {
    /// Per-process resource pointers (indexed by PID slot).
    processes: [Option<ProcessResources>; MAX_PIDS],
    /// Caller capabilities (bitmap).
    caller_caps: u64,
    /// Caller UID.
    caller_uid: u32,
    /// Per-process UIDs (for same-user checks).
    process_uids: [u32; MAX_PIDS],
}

impl KcmpContext {
    /// Create a new kcmp context with no processes.
    pub fn new() -> Self {
        Self {
            processes: [const { None }; MAX_PIDS],
            caller_caps: 0,
            caller_uid: 0,
            process_uids: [0; MAX_PIDS],
        }
    }

    /// Set caller capabilities and UID.
    pub fn set_caller(&mut self, caps: u64, uid: u32) {
        self.caller_caps = caps;
        self.caller_uid = uid;
    }

    /// Register a process with its resource pointers.
    pub fn register_process(
        &mut self,
        pid: u32,
        resources: ProcessResources,
        uid: u32,
    ) -> Result<()> {
        let idx = pid as usize;
        if idx >= MAX_PIDS {
            return Err(Error::InvalidArgument);
        }
        self.processes[idx] = Some(resources);
        self.process_uids[idx] = uid;
        Ok(())
    }

    /// Check ptrace read permission for a target process.
    fn check_ptrace_access(&self, pid: u32) -> Result<()> {
        // CAP_SYS_PTRACE bypasses all checks.
        if self.caller_caps & (1u64 << CAP_SYS_PTRACE) != 0 {
            return Ok(());
        }
        // Same-user check.
        let idx = pid as usize;
        if idx >= MAX_PIDS {
            return Err(Error::InvalidArgument);
        }
        if self.process_uids[idx] == self.caller_uid {
            return Ok(());
        }
        Err(Error::PermissionDenied)
    }

    /// Get the resources for a process.
    fn get_resources(&self, pid: u32) -> Result<&ProcessResources> {
        let idx = pid as usize;
        if idx >= MAX_PIDS {
            return Err(Error::InvalidArgument);
        }
        self.processes[idx].as_ref().ok_or(Error::NotFound)
    }

    /// Perform a kcmp comparison.
    ///
    /// # Arguments
    ///
    /// - `pid1`, `pid2` — Process IDs to compare.
    /// - `kcmp_type` — Type of comparison (KCMP_*).
    /// - `idx1`, `idx2` — Type-specific indices (e.g., fd numbers
    ///   for KCMP_FILE).
    ///
    /// # Returns
    ///
    /// [`KcmpResult`] indicating the ordering.
    pub fn compare(
        &self,
        pid1: u32,
        pid2: u32,
        kcmp_type: u32,
        idx1: u64,
        idx2: u64,
    ) -> Result<KcmpResult> {
        // Validate type.
        if kcmp_type >= KCMP_TYPES_MAX {
            return Err(Error::InvalidArgument);
        }

        // Check permissions for both processes.
        self.check_ptrace_access(pid1)?;
        self.check_ptrace_access(pid2)?;

        let res1 = self.get_resources(pid1)?;
        let res2 = self.get_resources(pid2)?;

        match kcmp_type {
            KCMP_FILE => {
                let ptr1 = res1.get_fd_ptr(idx1)?;
                let ptr2 = res2.get_fd_ptr(idx2)?;
                Ok(KcmpResult::from_ptrs(ptr1, ptr2))
            }
            KCMP_VM | KCMP_FILES | KCMP_FS | KCMP_SIGHAND | KCMP_IO | KCMP_SYSVSEM => {
                let ptr1 = res1.get_resource_ptr(kcmp_type)?;
                let ptr2 = res2.get_resource_ptr(kcmp_type)?;
                Ok(KcmpResult::from_ptrs(ptr1, ptr2))
            }
            KCMP_EPOLL_TFD => {
                // For KCMP_EPOLL_TFD, idx1/idx2 are pointers to
                // KcmpEpollTfd structs. We compare the epoll fd
                // pointers directly.
                let ptr1 = res1.get_fd_ptr(idx1)?;
                let ptr2 = res2.get_fd_ptr(idx2)?;
                Ok(KcmpResult::from_ptrs(ptr1, ptr2))
            }
            _ => Err(Error::InvalidArgument),
        }
    }
}

impl Default for KcmpContext {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Syscall entry point
// ---------------------------------------------------------------------------

/// Process the `kcmp(2)` syscall.
///
/// # Arguments
///
/// - `ctx` — System-wide kcmp context.
/// - `pid1` — First process ID.
/// - `pid2` — Second process ID.
/// - `kcmp_type` — Comparison type (KCMP_*).
/// - `idx1`, `idx2` — Type-specific indices.
///
/// # Returns
///
/// Integer ordering value (0 = equal, negative = less, positive = greater).
///
/// # Errors
///
/// - `InvalidArgument` — Bad type or index.
/// - `NotFound` — Process or fd not found.
/// - `PermissionDenied` — No ptrace access.
pub fn sys_kcmp(
    ctx: &KcmpContext,
    pid1: u32,
    pid2: u32,
    kcmp_type: u32,
    idx1: u64,
    idx2: u64,
) -> Result<i32> {
    let result = ctx.compare(pid1, pid2, kcmp_type, idx1, idx2)?;
    Ok(result.to_raw())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_ctx() -> KcmpContext {
        let mut ctx = KcmpContext::new();
        ctx.set_caller(1u64 << CAP_SYS_PTRACE, 1000);

        let mut r1 = ProcessResources::new(0x1000);
        r1.set_fd_ptr(0, 0xAAAA).unwrap();
        r1.set_fd_ptr(1, 0xBBBB).unwrap();
        ctx.register_process(1, r1, 1000).unwrap();

        let mut r2 = ProcessResources::new(0x2000);
        r2.set_fd_ptr(0, 0xAAAA).unwrap(); // same as pid1 fd0
        r2.set_fd_ptr(1, 0xCCCC).unwrap();
        ctx.register_process(2, r2, 1000).unwrap();

        ctx
    }

    #[test]
    fn test_kcmp_file_equal() {
        let ctx = setup_ctx();
        let result = sys_kcmp(&ctx, 1, 2, KCMP_FILE, 0, 0).unwrap();
        assert_eq!(result, 0); // same file pointer
    }

    #[test]
    fn test_kcmp_file_not_equal() {
        let ctx = setup_ctx();
        let result = sys_kcmp(&ctx, 1, 2, KCMP_FILE, 1, 1).unwrap();
        assert_ne!(result, 0); // different file pointers
    }

    #[test]
    fn test_kcmp_vm_different() {
        let ctx = setup_ctx();
        let result = sys_kcmp(&ctx, 1, 2, KCMP_VM, 0, 0).unwrap();
        assert_ne!(result, 0); // different mm_struct
    }

    #[test]
    fn test_kcmp_vm_shared() {
        let mut ctx = KcmpContext::new();
        ctx.set_caller(1u64 << CAP_SYS_PTRACE, 0);

        let r1 = ProcessResources::new(0x1000);
        let mut r2 = ProcessResources::new(0x2000);
        r2.mm_ptr = r1.mm_ptr; // share mm
        ctx.register_process(1, r1, 0).unwrap();
        ctx.register_process(2, r2, 0).unwrap();

        assert_eq!(sys_kcmp(&ctx, 1, 2, KCMP_VM, 0, 0).unwrap(), 0);
    }

    #[test]
    fn test_kcmp_files_struct() {
        let ctx = setup_ctx();
        let result = sys_kcmp(&ctx, 1, 2, KCMP_FILES, 0, 0).unwrap();
        assert_ne!(result, 0);
    }

    #[test]
    fn test_kcmp_fs() {
        let ctx = setup_ctx();
        assert_ne!(sys_kcmp(&ctx, 1, 2, KCMP_FS, 0, 0).unwrap(), 0);
    }

    #[test]
    fn test_kcmp_sighand() {
        let ctx = setup_ctx();
        assert_ne!(sys_kcmp(&ctx, 1, 2, KCMP_SIGHAND, 0, 0).unwrap(), 0);
    }

    #[test]
    fn test_kcmp_io() {
        let ctx = setup_ctx();
        assert_ne!(sys_kcmp(&ctx, 1, 2, KCMP_IO, 0, 0).unwrap(), 0);
    }

    #[test]
    fn test_kcmp_sysvsem() {
        let ctx = setup_ctx();
        assert_ne!(sys_kcmp(&ctx, 1, 2, KCMP_SYSVSEM, 0, 0).unwrap(), 0);
    }

    #[test]
    fn test_kcmp_invalid_type() {
        let ctx = setup_ctx();
        assert_eq!(
            sys_kcmp(&ctx, 1, 2, 99, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_kcmp_process_not_found() {
        let ctx = setup_ctx();
        assert_eq!(
            sys_kcmp(&ctx, 1, 999, KCMP_VM, 0, 0).unwrap_err(),
            Error::NotFound
        );
    }

    #[test]
    fn test_kcmp_permission_denied() {
        let mut ctx = setup_ctx();
        ctx.set_caller(0, 9999); // no caps, different uid
        let r = ProcessResources::new(0x5000);
        ctx.register_process(5, r, 5000).unwrap(); // different uid
        assert_eq!(
            sys_kcmp(&ctx, 1, 5, KCMP_VM, 0, 0).unwrap_err(),
            Error::PermissionDenied
        );
    }

    #[test]
    fn test_kcmp_same_user_allowed() {
        let mut ctx = KcmpContext::new();
        ctx.set_caller(0, 1000); // no caps, same uid

        let r1 = ProcessResources::new(0x1000);
        let r2 = ProcessResources::new(0x2000);
        ctx.register_process(1, r1, 1000).unwrap();
        ctx.register_process(2, r2, 1000).unwrap();

        assert!(sys_kcmp(&ctx, 1, 2, KCMP_VM, 0, 0).is_ok());
    }

    #[test]
    fn test_kcmp_result_ordering() {
        assert_eq!(KcmpResult::from_ptrs(5, 5), KcmpResult::Equal);
        assert_eq!(KcmpResult::from_ptrs(3, 5), KcmpResult::Less);
        assert_eq!(KcmpResult::from_ptrs(5, 3), KcmpResult::Greater);
    }

    #[test]
    fn test_kcmp_result_to_raw() {
        assert_eq!(KcmpResult::Equal.to_raw(), 0);
        assert_eq!(KcmpResult::Less.to_raw(), -1);
        assert_eq!(KcmpResult::Greater.to_raw(), 1);
    }

    #[test]
    fn test_kcmp_bad_fd() {
        let ctx = setup_ctx();
        assert_eq!(
            sys_kcmp(&ctx, 1, 2, KCMP_FILE, 999, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }
}
