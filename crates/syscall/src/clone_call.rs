// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `clone` / `clone3` syscall handlers.
//!
//! Implements `clone(2)` and `clone3(2)` per the Linux ABI.
//! `clone` creates a new process or thread, sharing resources
//! with the caller based on flags. `clone3` is the modern,
//! extensible variant that uses a `struct clone_args`.
//!
//! # References
//!
//! - Linux man pages: `clone(2)`, `clone3(2)`
//! - POSIX.1-2024: `pthread_create()` (thread semantics)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Clone flags (u64, Linux ABI)
// ---------------------------------------------------------------------------

/// Share virtual memory.
pub const CLONE_VM: u64 = 0x0000_0100;
/// Share filesystem root/cwd/umask.
pub const CLONE_FS: u64 = 0x0000_0200;
/// Share file descriptor table.
pub const CLONE_FILES: u64 = 0x0000_0400;
/// Share signal handlers.
pub const CLONE_SIGHAND: u64 = 0x0000_0800;
/// New process is in the same thread group.
pub const CLONE_THREAD: u64 = 0x0001_0000;
/// Create new mount namespace.
pub const CLONE_NEWNS: u64 = 0x0002_0000;
/// Return pidfd for the child.
pub const CLONE_PIDFD: u64 = 0x0000_1000;
/// Parent is suspended until child calls execve or _exit.
pub const CLONE_VFORK: u64 = 0x0000_4000;
/// Parent of child == caller's parent.
pub const CLONE_PARENT: u64 = 0x0000_8000;
/// Copy-on-write signal tracing.
pub const CLONE_PTRACE: u64 = 0x0000_2000;
/// New UTS namespace.
pub const CLONE_NEWUTS: u64 = 0x0400_0000;
/// New IPC namespace.
pub const CLONE_NEWIPC: u64 = 0x0800_0000;
/// New user namespace.
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
/// New PID namespace.
pub const CLONE_NEWPID: u64 = 0x2000_0000;
/// New network namespace.
pub const CLONE_NEWNET: u64 = 0x4000_0000;
/// Store child TID in child memory.
pub const CLONE_CHILD_SETTID: u64 = 0x0100_0000;
/// Clear child TID in child memory on exit.
pub const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
/// Store child TID in parent memory.
pub const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
/// Set TLS descriptor.
pub const CLONE_SETTLS: u64 = 0x0008_0000;
/// Place child in a cgroup.
pub const CLONE_INTO_CGROUP: u64 = 0x0200_0000_0000_0000;

/// All recognised clone flags.
const CLONE_FLAGS_KNOWN: u64 = CLONE_VM
    | CLONE_FS
    | CLONE_FILES
    | CLONE_SIGHAND
    | CLONE_THREAD
    | CLONE_NEWNS
    | CLONE_PIDFD
    | CLONE_VFORK
    | CLONE_PARENT
    | CLONE_PTRACE
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWUSER
    | CLONE_NEWPID
    | CLONE_NEWNET
    | CLONE_CHILD_SETTID
    | CLONE_CHILD_CLEARTID
    | CLONE_PARENT_SETTID
    | CLONE_SETTLS
    | CLONE_INTO_CGROUP;

// ---------------------------------------------------------------------------
// CloneArgs — struct clone_args (Linux 5.3+)
// ---------------------------------------------------------------------------

/// `struct clone_args` for `clone3`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CloneArgs {
    /// Clone flags bitmask.
    pub flags: u64,
    /// User pointer to store pidfd (when CLONE_PIDFD is set).
    pub pidfd: u64,
    /// User pointer to store child TID (when CLONE_CHILD_SETTID is set).
    pub child_tid: u64,
    /// User pointer to store parent TID (when CLONE_PARENT_SETTID is set).
    pub parent_tid: u64,
    /// Signal sent to parent when child exits (0 = none).
    pub exit_signal: u64,
    /// Pointer to lowest byte of the child's stack.
    pub stack: u64,
    /// Size of the child's stack in bytes.
    pub stack_size: u64,
    /// TLS descriptor (when CLONE_SETTLS is set).
    pub tls: u64,
    /// Array of TIDs to set for new PID namespace layers.
    pub set_tid: u64,
    /// Number of elements in set_tid array.
    pub set_tid_size: u64,
    /// Cgroup fd (when CLONE_INTO_CGROUP is set).
    pub cgroup: u64,
}

impl CloneArgs {
    /// Validate the `clone_args` for `clone3`.
    ///
    /// Returns `Err(InvalidArgument)` when:
    /// - Unknown flags are set.
    /// - `CLONE_THREAD` is set without `CLONE_SIGHAND`.
    /// - `CLONE_SIGHAND` is set without `CLONE_VM`.
    /// - `exit_signal` is out of range (must be 0 or 1..=64).
    /// - `CLONE_PIDFD` and `CLONE_PARENT_SETTID` are both set.
    pub fn validate(&self) -> Result<()> {
        if self.flags & !CLONE_FLAGS_KNOWN != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.flags & CLONE_THREAD != 0 && self.flags & CLONE_SIGHAND == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.flags & CLONE_SIGHAND != 0 && self.flags & CLONE_VM == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.exit_signal > 64 {
            return Err(Error::InvalidArgument);
        }
        if self.flags & CLONE_PIDFD != 0 && self.flags & CLONE_PARENT_SETTID != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Return `true` if this call creates a new thread (not a new process).
    pub const fn is_thread(&self) -> bool {
        self.flags & CLONE_THREAD != 0
    }

    /// Return `true` if the call is a vfork equivalent.
    pub const fn is_vfork(&self) -> bool {
        self.flags & CLONE_VFORK != 0
    }

    /// Return `true` if a new PID namespace is requested.
    pub const fn new_pid_ns(&self) -> bool {
        self.flags & CLONE_NEWPID != 0
    }
}

// ---------------------------------------------------------------------------
// LegacyCloneArgs — clone(2) ABI (older 5-parameter form)
// ---------------------------------------------------------------------------

/// Arguments for the legacy `clone(2)` syscall.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct LegacyCloneArgs {
    /// Clone flags (lower 32 bits) | exit signal (bits 0..7).
    pub flags_sig: u64,
    /// Stack pointer for the child.
    pub stack: u64,
    /// Pointer for parent TID storage.
    pub parent_tid: u64,
    /// TLS descriptor.
    pub tls: u64,
    /// Pointer for child TID storage.
    pub child_tid: u64,
}

impl LegacyCloneArgs {
    /// Extract the flags portion (bits 8..63).
    pub const fn flags(&self) -> u64 {
        self.flags_sig & !0xFF
    }

    /// Extract the exit signal (bits 0..7).
    pub const fn exit_signal(&self) -> u64 {
        self.flags_sig & 0xFF
    }

    /// Convert to `CloneArgs`.
    pub fn to_clone_args(&self) -> CloneArgs {
        CloneArgs {
            flags: self.flags(),
            exit_signal: self.exit_signal(),
            stack: self.stack,
            stack_size: 0, // not provided in legacy form
            parent_tid: self.parent_tid,
            tls: self.tls,
            child_tid: self.child_tid,
            ..CloneArgs::default()
        }
    }
}

// ---------------------------------------------------------------------------
// CloneResult — outcome
// ---------------------------------------------------------------------------

/// Result of a `clone` / `clone3` call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CloneResult {
    /// PID of the newly created child (0 in the child itself).
    pub child_pid: u64,
    /// TID of the new thread (for CLONE_THREAD, same as child_pid).
    pub child_tid: u64,
    /// Pidfd for the child (when CLONE_PIDFD is set).
    pub pidfd: Option<i32>,
}

// ---------------------------------------------------------------------------
// Resource sharing descriptor
// ---------------------------------------------------------------------------

/// Describes which resources are shared vs copied.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SharedResources {
    /// Virtual memory is shared (CLONE_VM).
    pub vm: bool,
    /// Filesystem info is shared (CLONE_FS).
    pub fs: bool,
    /// File descriptor table is shared (CLONE_FILES).
    pub files: bool,
    /// Signal handlers are shared (CLONE_SIGHAND).
    pub sighand: bool,
}

impl SharedResources {
    /// Derive from clone flags.
    pub const fn from_flags(flags: u64) -> Self {
        Self {
            vm: flags & CLONE_VM != 0,
            fs: flags & CLONE_FS != 0,
            files: flags & CLONE_FILES != 0,
            sighand: flags & CLONE_SIGHAND != 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Public syscall handlers
// ---------------------------------------------------------------------------

/// `clone3` — create a new process or thread (extensible API).
///
/// Validates `args` and spawns a child that shares the resources
/// indicated by the flags. Returns the child PID in the parent;
/// the child would receive 0 (handled by the scheduler on context switch).
///
/// Stub: validates args and returns a placeholder child PID.
///
/// Reference: Linux clone3(2).
pub fn do_clone3(args: &CloneArgs) -> Result<CloneResult> {
    args.validate()?;

    let shared = SharedResources::from_flags(args.flags);
    let _ = shared;

    // Stub: real implementation copies/shares mm_struct, files, sighand etc.
    // The child's entry point is set to the instruction after the syscall,
    // with return value 0.
    let child_pid = 2u64; // placeholder
    let pidfd = if args.flags & CLONE_PIDFD != 0 {
        Some(10)
    } else {
        None
    };

    Ok(CloneResult {
        child_pid,
        child_tid: child_pid,
        pidfd,
    })
}

/// `clone` — legacy process/thread creation.
///
/// Adapts the legacy `clone(2)` ABI to `clone3` semantics.
///
/// Reference: Linux clone(2).
pub fn do_clone(legacy: &LegacyCloneArgs) -> Result<CloneResult> {
    let args = legacy.to_clone_args();
    args.validate()?;
    do_clone3(&args)
}

/// Validate `clone3` arguments without creating a process.
pub fn validate_clone3_args(args: &CloneArgs) -> Result<()> {
    args.validate()
}

/// Determine the resource-sharing profile for a given set of flags.
pub fn resource_sharing(flags: u64) -> SharedResources {
    SharedResources::from_flags(flags)
}
