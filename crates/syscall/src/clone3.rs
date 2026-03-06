// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `clone3(2)` syscall handler.
//!
//! The `clone3` syscall (Linux 5.3+) is a superset of `clone(2)` that
//! takes all clone arguments via an in-memory `CloneArgs` structure rather
//! than packed register arguments.  It removes the ABI limitations of
//! `clone(2)` and adds new capabilities:
//!
//! - 64-bit flag word (vs 32-bit in `clone`)
//! - `pidfd` file descriptor for the child (`CLONE_PIDFD`)
//! - `cgroup` file descriptor for placing child in a cgroup
//! - `set_tid` array for creating processes with specific PIDs in nested namespaces
//!
//! # Kernel data flow
//!
//! ```text
//! user space                   kernel space
//! ──────────                   ─────────────
//! clone3(&clone_args, size) ─► copy_from_user(CloneArgs)
//!                              validate_clone_args()
//!                              allocate_pid()
//!                              copy_process() / kernel_clone()
//!                              wake_up_child()
//!                           ◄─ child_pid / error
//! ```
//!
//! # References
//!
//! - Linux: `kernel/fork.c` — `kernel_clone()`, `copy_process()`
//! - `include/uapi/linux/sched.h` — `struct clone_args`
//! - man-pages: `clone3(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Clone flags (u64)
// ---------------------------------------------------------------------------

/// Share virtual memory with the parent.
pub const CLONE_VM: u64 = 0x0000_0100;
/// Share the filesystem root, cwd, and umask.
pub const CLONE_FS: u64 = 0x0000_0200;
/// Share the open file descriptor table.
pub const CLONE_FILES: u64 = 0x0000_0400;
/// Share signal handlers and blocked-signal mask.
pub const CLONE_SIGHAND: u64 = 0x0000_0800;
/// Place the child in the same process group as the parent's parent.
pub const CLONE_PARENT: u64 = 0x0000_8000;
/// Place the child in the caller's thread group (creates a thread).
pub const CLONE_THREAD: u64 = 0x0001_0000;
/// Create the child in a new mount namespace.
pub const CLONE_NEWNS: u64 = 0x0002_0000;
/// Reset all SysV semaphore undo values to zero.
pub const CLONE_SYSVSEM: u64 = 0x0004_0000;
/// Set the TLS (thread-local storage) to `tls` in `CloneArgs`.
pub const CLONE_SETTLS: u64 = 0x0008_0000;
/// Store the parent thread ID in `parent_tid`.
pub const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
/// Clear the child thread ID on exit (for robust futexes).
pub const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
/// Execution of the parent is suspended until the child calls exec or exits.
pub const CLONE_VFORK: u64 = 0x0000_4000;
/// Store the child thread ID in `child_tid`.
pub const CLONE_CHILD_SETTID: u64 = 0x0100_0000;
/// Create the child in a new network namespace.
pub const CLONE_NEWNET: u64 = 0x4000_0000;
/// Allocate a pidfd file descriptor for the child.
pub const CLONE_PIDFD: u64 = 0x0000_1000;
/// Create the child in a new PID namespace.
pub const CLONE_NEWPID: u64 = 0x2000_0000;
/// Create the child in a new user namespace.
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
/// Create the child in a new IPC namespace.
pub const CLONE_NEWIPC: u64 = 0x0800_0000;
/// Create the child in a new UTS namespace.
pub const CLONE_NEWUTS: u64 = 0x0400_0000;
/// Create the child in a new cgroup namespace.
pub const CLONE_NEWCGROUP: u64 = 0x0200_0000;
/// Place child in the cgroup specified by `cgroup` fd.
pub const CLONE_INTO_CGROUP: u64 = 0x0200_0000_0000_0000;

/// All recognised `clone3` flag bits.
const CLONE_FLAGS_KNOWN: u64 = CLONE_VM
    | CLONE_FS
    | CLONE_FILES
    | CLONE_SIGHAND
    | CLONE_PARENT
    | CLONE_THREAD
    | CLONE_NEWNS
    | CLONE_SYSVSEM
    | CLONE_SETTLS
    | CLONE_PARENT_SETTID
    | CLONE_CHILD_CLEARTID
    | CLONE_VFORK
    | CLONE_CHILD_SETTID
    | CLONE_NEWNET
    | CLONE_PIDFD
    | CLONE_NEWPID
    | CLONE_NEWUSER
    | CLONE_NEWIPC
    | CLONE_NEWUTS
    | CLONE_NEWCGROUP
    | CLONE_INTO_CGROUP;

// ---------------------------------------------------------------------------
// CloneArgs — the in-memory argument structure
// ---------------------------------------------------------------------------

/// Maximum number of PIDs that can be requested via `set_tid`.
///
/// Matches `MAX_PID_NS_LEVEL` (32) in the Linux kernel.
pub const CLONE_ARGS_MAX_SET_TID: usize = 32;

/// Argument structure passed to `clone3(2)`.
///
/// Matches `struct clone_args` from `include/uapi/linux/sched.h`.
/// The caller passes a pointer to this structure and its size; the
/// kernel copies it from user space.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CloneArgs {
    /// Clone flags (combination of `CLONE_*` constants).
    pub flags: u64,
    /// If `CLONE_PIDFD` is set, write the pidfd here (user-space pointer to fd).
    pub pidfd: u64,
    /// If `CLONE_CHILD_SETTID` is set, write child TID here (user-space pointer).
    pub child_tid: u64,
    /// If `CLONE_PARENT_SETTID` is set, write parent TID here (user-space pointer).
    pub parent_tid: u64,
    /// Signal sent to the parent when the child exits (0 = no signal).
    pub exit_signal: u64,
    /// Stack base address; 0 = inherit parent stack.
    pub stack: u64,
    /// Stack size in bytes; 0 = unspecified.
    pub stack_size: u64,
    /// Thread-local storage pointer (used when `CLONE_SETTLS` is set).
    pub tls: u64,
    /// User-space pointer to `u64[]` of desired TIDs in each namespace level.
    pub set_tid: u64,
    /// Number of elements in the `set_tid` array (max [`CLONE_ARGS_MAX_SET_TID`]).
    pub set_tid_size: u64,
    /// File descriptor of a cgroup to place the child in (`CLONE_INTO_CGROUP`).
    pub cgroup: u64,
}

impl CloneArgs {
    /// Return the minimum valid size of `CloneArgs` passed from user space.
    ///
    /// `clone3` uses extensible structures: the kernel accepts any size that
    /// is at least `CLONE_ARGS_SIZE_VER0` (88 bytes, the initial version).
    pub const fn min_size() -> usize {
        // sizeof(flags..stack_size) = 8 fields × 8 bytes = 64 bytes
        // plus tls = 72, set_tid = 80, set_tid_size = 88
        88
    }
}

// ---------------------------------------------------------------------------
// CloneResult — outcome of a successful clone
// ---------------------------------------------------------------------------

/// Result of a successful `clone3` call from the parent's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloneResult {
    /// The PID of the newly created child (as seen in the parent's namespace).
    pub child_pid: u64,
    /// The pidfd file descriptor, if `CLONE_PIDFD` was requested.
    pub pidfd: Option<i32>,
}

// ---------------------------------------------------------------------------
// Flag constraint validation
// ---------------------------------------------------------------------------

/// Validate that a combination of clone flags is internally consistent.
///
/// Enforces the same constraints as `copy_process()` in `kernel/fork.c`.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] for any invalid combination.
fn validate_flag_constraints(flags: u64) -> Result<()> {
    // Unknown bits.
    if flags & !CLONE_FLAGS_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }

    // CLONE_SIGHAND requires CLONE_VM (signals share the same handlers struct).
    if flags & CLONE_SIGHAND != 0 && flags & CLONE_VM == 0 {
        return Err(Error::InvalidArgument);
    }

    // CLONE_THREAD requires CLONE_SIGHAND.
    if flags & CLONE_THREAD != 0 && flags & CLONE_SIGHAND == 0 {
        return Err(Error::InvalidArgument);
    }

    // CLONE_THREAD and CLONE_NEWPID cannot both be set.
    if flags & CLONE_THREAD != 0 && flags & CLONE_NEWPID != 0 {
        return Err(Error::InvalidArgument);
    }

    // CLONE_PIDFD and CLONE_THREAD are mutually exclusive.
    if flags & CLONE_PIDFD != 0 && flags & CLONE_THREAD != 0 {
        return Err(Error::InvalidArgument);
    }

    // CLONE_PIDFD and CLONE_PARENT_SETTID are mutually exclusive.
    if flags & CLONE_PIDFD != 0 && flags & CLONE_PARENT_SETTID != 0 {
        return Err(Error::InvalidArgument);
    }

    // CLONE_NEWUSER requires !CLONE_THREAD (cannot create user namespace inside a thread).
    if flags & CLONE_NEWUSER != 0 && flags & CLONE_THREAD != 0 {
        return Err(Error::InvalidArgument);
    }

    Ok(())
}

/// Validate the `exit_signal` field.
///
/// The exit signal must be a valid signal number (1–64) or 0 (no signal).
/// For thread creation (`CLONE_THREAD`), the exit signal must be 0.
fn validate_exit_signal(flags: u64, exit_signal: u64) -> Result<()> {
    const SIGMAX: u64 = 64;

    if exit_signal > SIGMAX {
        return Err(Error::InvalidArgument);
    }

    // Threads do not deliver a signal to the parent on exit.
    if flags & CLONE_THREAD != 0 && exit_signal != 0 {
        return Err(Error::InvalidArgument);
    }

    Ok(())
}

/// Validate the `set_tid` / `set_tid_size` fields.
fn validate_set_tid(set_tid: u64, set_tid_size: u64) -> Result<()> {
    if set_tid_size > CLONE_ARGS_MAX_SET_TID as u64 {
        return Err(Error::InvalidArgument);
    }

    // If size is non-zero, pointer must be non-null.
    if set_tid_size > 0 && set_tid == 0 {
        return Err(Error::InvalidArgument);
    }

    // If size is zero, pointer should also be zero.
    if set_tid_size == 0 && set_tid != 0 {
        return Err(Error::InvalidArgument);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// CloneArgsSize validation
// ---------------------------------------------------------------------------

/// Validate the `size` argument passed to `clone3`.
///
/// `clone3` uses extensible structures. The kernel must reject sizes
/// that are too small or too large.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `size` is below the minimum or exceeds the
///   maximum known structure size.
pub fn validate_clone_args_size(size: usize) -> Result<()> {
    let max_size = core::mem::size_of::<CloneArgs>();
    if size < CloneArgs::min_size() || size > max_size {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PID allocator stub
// ---------------------------------------------------------------------------

/// Maximum PID value supported in the stub allocator.
const PID_MAX_LIMIT: u64 = 4_194_304;

/// Simple monotonic PID counter used in the stub.
pub struct PidAllocator {
    next: u64,
}

impl PidAllocator {
    /// Create a new allocator starting at PID 2 (PID 1 is init).
    pub const fn new() -> Self {
        Self { next: 2 }
    }

    /// Allocate the next available PID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] when the PID space is exhausted.
    pub fn alloc(&mut self) -> Result<u64> {
        if self.next >= PID_MAX_LIMIT {
            return Err(Error::OutOfMemory);
        }
        let pid = self.next;
        self.next += 1;
        Ok(pid)
    }

    /// Allocate a specific PID (for `set_tid` support).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — `pid` is 0 or exceeds the limit.
    /// - [`Error::AlreadyExists`] — `pid` has already been allocated.
    pub fn alloc_specific(&mut self, pid: u64) -> Result<u64> {
        if pid == 0 || pid >= PID_MAX_LIMIT {
            return Err(Error::InvalidArgument);
        }
        if pid < self.next {
            return Err(Error::AlreadyExists);
        }
        self.next = pid + 1;
        Ok(pid)
    }
}

// ---------------------------------------------------------------------------
// Process entry for the process table stub
// ---------------------------------------------------------------------------

/// Maximum number of child processes tracked in the stub table.
pub const MAX_CLONE_CHILDREN: usize = 128;

/// State of a cloned child process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildState {
    /// The child is running.
    Running,
    /// The child has exited with the given status.
    Exited(i32),
    /// The child has been reaped by the parent.
    Zombie,
}

/// A record of a child process created by `clone3`.
#[derive(Debug, Clone, Copy)]
pub struct ChildProcess {
    /// PID of the child.
    pub pid: u64,
    /// PID of the parent.
    pub parent_pid: u64,
    /// Clone flags used at creation.
    pub flags: u64,
    /// Current state.
    pub state: ChildState,
    /// Pidfd file descriptor (if `CLONE_PIDFD` was requested; otherwise -1).
    pub pidfd: i32,
}

/// Table of all active child processes (stub).
pub struct ChildTable {
    children: [Option<ChildProcess>; MAX_CLONE_CHILDREN],
    count: usize,
}

impl ChildTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            children: [const { None }; MAX_CLONE_CHILDREN],
            count: 0,
        }
    }

    /// Insert a new child record.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfMemory`] — table is full.
    pub fn insert(&mut self, child: ChildProcess) -> Result<()> {
        for slot in self.children.iter_mut() {
            if slot.is_none() {
                *slot = Some(child);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up a child by PID.
    pub fn find(&self, pid: u64) -> Option<&ChildProcess> {
        self.children
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|c| c.pid == pid)
    }

    /// Look up a child by PID (mutable).
    pub fn find_mut(&mut self, pid: u64) -> Option<&mut ChildProcess> {
        self.children
            .iter_mut()
            .filter_map(|s| s.as_mut())
            .find(|c| c.pid == pid)
    }

    /// Remove a child record (called after reaping).
    pub fn remove(&mut self, pid: u64) {
        for slot in self.children.iter_mut() {
            if slot.as_ref().is_some_and(|c| c.pid == pid) {
                *slot = None;
                self.count = self.count.saturating_sub(1);
                return;
            }
        }
    }

    /// Return the number of active entries.
    pub const fn count(&self) -> usize {
        self.count
    }
}

// ---------------------------------------------------------------------------
// do_clone3 — main handler
// ---------------------------------------------------------------------------

/// Handler for `clone3(2)`.
///
/// Creates a new child process (or thread) with the attributes described
/// by `args`. The caller must have already copied `args` from user space.
///
/// # Arguments
///
/// * `args`       — Validated `CloneArgs` copied from user space.
/// * `args_size`  — Size the user passed (for version compatibility checks).
/// * `alloc`      — PID allocator.
/// * `table`      — Child process table.
/// * `caller_pid` — PID of the calling process.
/// * `next_fd`    — Monotonic fd counter (for synthetic pidfd allocation).
///
/// # Returns
///
/// On success, returns a [`CloneResult`] containing the child PID and
/// optional pidfd.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — Invalid flags, exit signal, or `set_tid`.
/// - [`Error::OutOfMemory`]     — No more PIDs or table is full.
pub fn do_clone3(
    args: &CloneArgs,
    args_size: usize,
    alloc: &mut PidAllocator,
    table: &mut ChildTable,
    caller_pid: u64,
    next_fd: &mut i32,
) -> Result<CloneResult> {
    // Validate structure size for version compatibility.
    validate_clone_args_size(args_size)?;

    // Validate flag constraints.
    validate_flag_constraints(args.flags)?;

    // Validate exit signal.
    validate_exit_signal(args.flags, args.exit_signal)?;

    // Validate set_tid arguments.
    validate_set_tid(args.set_tid, args.set_tid_size)?;

    // CLONE_INTO_CGROUP requires a valid cgroup fd.
    if args.flags & CLONE_INTO_CGROUP != 0 && args.cgroup == 0 {
        return Err(Error::InvalidArgument);
    }

    // Allocate PID.
    let child_pid = if args.set_tid_size > 0 {
        // Use the first element of set_tid as the requested PID.
        // (In a real kernel, each element corresponds to a namespace level.)
        alloc.alloc_specific(args.set_tid)?
    } else {
        alloc.alloc()?
    };

    // Allocate pidfd if requested.
    let pidfd = if args.flags & CLONE_PIDFD != 0 {
        let fd = *next_fd;
        *next_fd = next_fd.wrapping_add(1);
        Some(fd)
    } else {
        None
    };

    // Record the child.
    let child = ChildProcess {
        pid: child_pid,
        parent_pid: caller_pid,
        flags: args.flags,
        state: ChildState::Running,
        pidfd: pidfd.unwrap_or(-1),
    };
    table.insert(child)?;

    Ok(CloneResult { child_pid, pidfd })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_args() -> CloneArgs {
        CloneArgs {
            flags: 0,
            exit_signal: 17, // SIGCHLD
            ..CloneArgs::default()
        }
    }

    #[test]
    fn clone_basic_process() {
        let mut alloc = PidAllocator::new();
        let mut table = ChildTable::new();
        let mut next_fd = 3i32;
        let args = default_args();
        let res = do_clone3(
            &args,
            CloneArgs::min_size(),
            &mut alloc,
            &mut table,
            1,
            &mut next_fd,
        );
        assert!(res.is_ok());
        let r = res.unwrap();
        assert_eq!(r.child_pid, 2);
        assert!(r.pidfd.is_none());
        assert_eq!(table.count(), 1);
    }

    #[test]
    fn clone_with_pidfd() {
        let mut alloc = PidAllocator::new();
        let mut table = ChildTable::new();
        let mut next_fd = 3i32;
        let args = CloneArgs {
            flags: CLONE_PIDFD,
            exit_signal: 17,
            ..CloneArgs::default()
        };
        let r = do_clone3(
            &args,
            CloneArgs::min_size(),
            &mut alloc,
            &mut table,
            1,
            &mut next_fd,
        )
        .unwrap();
        assert!(r.pidfd.is_some());
        assert_eq!(r.pidfd.unwrap(), 3);
        assert_eq!(next_fd, 4);
    }

    #[test]
    fn clone_thread_requires_sighand_and_vm() {
        let mut alloc = PidAllocator::new();
        let mut table = ChildTable::new();
        let mut next_fd = 3i32;
        // CLONE_THREAD without CLONE_SIGHAND
        let args = CloneArgs {
            flags: CLONE_THREAD,
            ..CloneArgs::default()
        };
        assert_eq!(
            do_clone3(
                &args,
                CloneArgs::min_size(),
                &mut alloc,
                &mut table,
                1,
                &mut next_fd
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn clone_sighand_requires_vm() {
        let mut alloc = PidAllocator::new();
        let mut table = ChildTable::new();
        let mut next_fd = 3i32;
        let args = CloneArgs {
            flags: CLONE_SIGHAND,
            ..CloneArgs::default()
        };
        assert_eq!(
            do_clone3(
                &args,
                CloneArgs::min_size(),
                &mut alloc,
                &mut table,
                1,
                &mut next_fd
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn clone_pidfd_and_thread_exclusive() {
        let mut alloc = PidAllocator::new();
        let mut table = ChildTable::new();
        let mut next_fd = 3i32;
        let args = CloneArgs {
            flags: CLONE_PIDFD | CLONE_THREAD | CLONE_SIGHAND | CLONE_VM,
            ..CloneArgs::default()
        };
        assert_eq!(
            do_clone3(
                &args,
                CloneArgs::min_size(),
                &mut alloc,
                &mut table,
                1,
                &mut next_fd
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn clone_thread_no_exit_signal() {
        let mut alloc = PidAllocator::new();
        let mut table = ChildTable::new();
        let mut next_fd = 3i32;
        let args = CloneArgs {
            flags: CLONE_THREAD | CLONE_SIGHAND | CLONE_VM,
            exit_signal: 17, // must be 0 for threads
            ..CloneArgs::default()
        };
        assert_eq!(
            do_clone3(
                &args,
                CloneArgs::min_size(),
                &mut alloc,
                &mut table,
                1,
                &mut next_fd
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn clone_valid_thread() {
        let mut alloc = PidAllocator::new();
        let mut table = ChildTable::new();
        let mut next_fd = 3i32;
        let args = CloneArgs {
            flags: CLONE_THREAD | CLONE_SIGHAND | CLONE_VM,
            exit_signal: 0,
            ..CloneArgs::default()
        };
        let r = do_clone3(
            &args,
            CloneArgs::min_size(),
            &mut alloc,
            &mut table,
            1,
            &mut next_fd,
        );
        assert!(r.is_ok());
    }

    #[test]
    fn clone_unknown_flags_rejected() {
        let mut alloc = PidAllocator::new();
        let mut table = ChildTable::new();
        let mut next_fd = 3i32;
        let args = CloneArgs {
            flags: 0x0000_0001,
            ..CloneArgs::default()
        };
        assert_eq!(
            do_clone3(
                &args,
                CloneArgs::min_size(),
                &mut alloc,
                &mut table,
                1,
                &mut next_fd
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn clone_too_small_size_rejected() {
        let mut alloc = PidAllocator::new();
        let mut table = ChildTable::new();
        let mut next_fd = 3i32;
        let args = default_args();
        assert_eq!(
            do_clone3(&args, 8, &mut alloc, &mut table, 1, &mut next_fd),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn clone_pid_allocator_monotonic() {
        let mut alloc = PidAllocator::new();
        assert_eq!(alloc.alloc().unwrap(), 2);
        assert_eq!(alloc.alloc().unwrap(), 3);
        assert_eq!(alloc.alloc().unwrap(), 4);
    }

    #[test]
    fn clone_child_table_find_remove() {
        let mut table = ChildTable::new();
        let child = ChildProcess {
            pid: 10,
            parent_pid: 1,
            flags: 0,
            state: ChildState::Running,
            pidfd: -1,
        };
        table.insert(child).unwrap();
        assert!(table.find(10).is_some());
        table.remove(10);
        assert!(table.find(10).is_none());
        assert_eq!(table.count(), 0);
    }

    #[test]
    fn clone_into_cgroup_requires_fd() {
        let mut alloc = PidAllocator::new();
        let mut table = ChildTable::new();
        let mut next_fd = 3i32;
        let args = CloneArgs {
            flags: CLONE_INTO_CGROUP,
            cgroup: 0,
            ..CloneArgs::default()
        };
        assert_eq!(
            do_clone3(
                &args,
                CloneArgs::min_size(),
                &mut alloc,
                &mut table,
                1,
                &mut next_fd
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn clone_set_tid_zero_size_zero_ptr() {
        let mut alloc = PidAllocator::new();
        let mut table = ChildTable::new();
        let mut next_fd = 3i32;
        // set_tid_size=0, set_tid=non-null: invalid
        let args = CloneArgs {
            set_tid: 0x1000,
            set_tid_size: 0,
            exit_signal: 17,
            ..CloneArgs::default()
        };
        assert_eq!(
            do_clone3(
                &args,
                CloneArgs::min_size(),
                &mut alloc,
                &mut table,
                1,
                &mut next_fd
            ),
            Err(Error::InvalidArgument)
        );
    }
}
