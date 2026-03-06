// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `seccomp(2)` syscall handler.
//!
//! The `seccomp` syscall provides Secure Computing Mode: a mechanism for
//! restricting the syscalls a thread (and its descendants) may invoke.
//! It was introduced in Linux 3.5 and extended with BPF-based filtering
//! in Linux 3.13.
//!
//! # Operations
//!
//! | Operation                       | Constant | Description                          |
//! |---------------------------------|----------|--------------------------------------|
//! | `SECCOMP_SET_MODE_STRICT`        | 0        | Allow only `read`, `write`, `exit`, `sigreturn` |
//! | `SECCOMP_SET_MODE_FILTER`        | 1        | Install a BPF filter program          |
//! | `SECCOMP_GET_ACTION_AVAIL`       | 2        | Query if an action code is supported  |
//! | `SECCOMP_GET_NOTIF_SIZES`        | 3        | Get sizes of unotify structures       |
//!
//! # Filter chaining
//!
//! Multiple filters may be stacked.  Each is executed in LIFO (last-installed
//! first-run) order.  The most restrictive result wins: `KILL` > `TRAP` >
//! `ERRNO` > `TRACE` > `LOG` > `ALLOW`.
//!
//! # Actions
//!
//! | Action              | Constant              | Description                           |
//! |---------------------|-----------------------|---------------------------------------|
//! | `SECCOMP_RET_KILL_PROCESS` | `0x80000000` | Kill the entire process              |
//! | `SECCOMP_RET_KILL_THREAD`  | `0x00000000` | Kill only the calling thread         |
//! | `SECCOMP_RET_TRAP`         | `0x00030000` | Deliver `SIGSYS` to the process      |
//! | `SECCOMP_RET_ERRNO`        | `0x00050000` | Return a custom errno to the caller  |
//! | `SECCOMP_RET_USER_NOTIF`   | `0x7fc00000` | Notify a user-space supervisor        |
//! | `SECCOMP_RET_TRACE`        | `0x7ff00000` | Let a ptrace tracer decide           |
//! | `SECCOMP_RET_LOG`          | `0x7ffc0000` | Allow, and log to the audit log      |
//! | `SECCOMP_RET_ALLOW`        | `0x7fff0000` | Allow the syscall unconditionally    |
//!
//! # References
//!
//! - Linux: `kernel/seccomp.c`
//! - `include/uapi/linux/seccomp.h`
//! - man-pages: `seccomp(2)`, `seccomp_unotify(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Operation constants
// ---------------------------------------------------------------------------

/// Set strict seccomp mode (only `read`, `write`, `exit`, `sigreturn` allowed).
pub const SECCOMP_SET_MODE_STRICT: u32 = 0;
/// Install a BPF syscall filter.
pub const SECCOMP_SET_MODE_FILTER: u32 = 1;
/// Query whether a specific action value is supported.
pub const SECCOMP_GET_ACTION_AVAIL: u32 = 2;
/// Get sizes of user-notification structures.
pub const SECCOMP_GET_NOTIF_SIZES: u32 = 3;

// ---------------------------------------------------------------------------
// Filter flags (passed as `flags` argument to `SECCOMP_SET_MODE_FILTER`)
// ---------------------------------------------------------------------------

/// Allow the filter to be added even when the process has no `CAP_SYS_ADMIN`.
pub const SECCOMP_FILTER_FLAG_TSYNC: u32 = 1 << 0;
/// Permit the filter to use `SECCOMP_RET_LOG`.
pub const SECCOMP_FILTER_FLAG_LOG: u32 = 1 << 1;
/// Prevent child processes from gaining additional privileges.
pub const SECCOMP_FILTER_FLAG_SPEC_ALLOW: u32 = 1 << 2;
/// Enable user-space notifications.
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: u32 = 1 << 3;
/// Synchronize the filter across all threads.
pub const SECCOMP_FILTER_FLAG_TSYNC_ESRCH: u32 = 1 << 4;
/// Wait for the notifier to respond even if the thread would be killed.
pub const SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV: u32 = 1 << 5;

/// All recognised filter flag bits.
const SECCOMP_FILTER_FLAGS_KNOWN: u32 = SECCOMP_FILTER_FLAG_TSYNC
    | SECCOMP_FILTER_FLAG_LOG
    | SECCOMP_FILTER_FLAG_SPEC_ALLOW
    | SECCOMP_FILTER_FLAG_NEW_LISTENER
    | SECCOMP_FILTER_FLAG_TSYNC_ESRCH
    | SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;

// ---------------------------------------------------------------------------
// Action return values
// ---------------------------------------------------------------------------

/// Kill the entire process immediately.
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
/// Kill only the thread that triggered the filter.
pub const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
/// Deliver `SIGSYS` to the process.
pub const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
/// Return a custom errno; the errno value is in the low 16 bits.
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
/// Send a notification to user space.
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
/// Notify a ptrace tracer.
pub const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
/// Allow the syscall and log to audit.
pub const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;
/// Allow the syscall unconditionally.
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

/// Mask for the action class (upper 16 bits).
pub const SECCOMP_RET_ACTION_FULL: u32 = 0xffff_0000;
/// Mask for the action data (lower 16 bits, e.g. errno value).
pub const SECCOMP_RET_DATA: u32 = 0x0000_ffff;

// ---------------------------------------------------------------------------
// Seccomp mode constants
// ---------------------------------------------------------------------------

/// Seccomp is disabled for this thread.
pub const SECCOMP_MODE_DISABLED: u32 = 0;
/// Strict mode active.
pub const SECCOMP_MODE_STRICT: u32 = 1;
/// BPF filter mode active.
pub const SECCOMP_MODE_FILTER: u32 = 2;

// ---------------------------------------------------------------------------
// BPF filter representation (stub)
// ---------------------------------------------------------------------------

/// Maximum number of BPF instructions in a seccomp filter program.
pub const BPF_MAXINSNS: usize = 4096;

/// Maximum number of stacked seccomp filters per thread.
pub const SECCOMP_MAX_FILTERS: usize = 32;

/// A single BPF instruction (`struct sock_filter`).
///
/// Layout matches `include/uapi/linux/filter.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SockFilter {
    /// Operation code.
    pub code: u16,
    /// Jump true / false offsets.
    pub jt: u8,
    pub jf: u8,
    /// Operand / constant.
    pub k: u32,
}

/// A BPF filter program (`struct sock_fprog`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SockFprog {
    /// Number of instructions in `filter`.
    pub len: u16,
    /// User-space pointer to the instruction array.
    pub filter_ptr: u64,
}

// ---------------------------------------------------------------------------
// Seccomp filter record (installed on a thread)
// ---------------------------------------------------------------------------

/// A single installed seccomp filter entry.
#[derive(Debug, Clone, Copy)]
pub struct SeccompFilter {
    /// Unique filter ID (monotonically increasing).
    pub id: u32,
    /// Flags that were active when this filter was installed.
    pub flags: u32,
    /// Whether this filter requests user-space notification.
    pub user_notif: bool,
    /// Number of BPF instructions (stub: stored but not executed).
    pub insn_count: u16,
}

// ---------------------------------------------------------------------------
// Thread seccomp state
// ---------------------------------------------------------------------------

/// Maximum number of threads in the stub seccomp table.
pub const MAX_THREADS: usize = 128;

/// Seccomp state for a single thread.
pub struct ThreadSeccomp {
    /// Thread ID.
    pub tid: u32,
    /// Current seccomp mode.
    pub mode: u32,
    /// Installed filter stack (LIFO: index 0 = oldest, last = most recent).
    filters: [Option<SeccompFilter>; SECCOMP_MAX_FILTERS],
    /// Number of filters currently installed.
    filter_count: usize,
    /// Whether the thread has the `no_new_privs` bit set.
    pub no_new_privs: bool,
    /// Whether this slot is in use.
    pub in_use: bool,
}

impl ThreadSeccomp {
    const fn new() -> Self {
        Self {
            tid: 0,
            mode: SECCOMP_MODE_DISABLED,
            filters: [const { None }; SECCOMP_MAX_FILTERS],
            filter_count: 0,
            no_new_privs: false,
            in_use: false,
        }
    }

    /// Return the number of filters installed on this thread.
    pub const fn filter_count(&self) -> usize {
        self.filter_count
    }

    /// Push a filter onto the stack.
    fn push_filter(&mut self, f: SeccompFilter) -> Result<()> {
        if self.filter_count >= SECCOMP_MAX_FILTERS {
            return Err(Error::OutOfMemory);
        }
        self.filters[self.filter_count] = Some(f);
        self.filter_count += 1;
        Ok(())
    }
}

/// Per-thread seccomp state table.
pub struct SeccompTable {
    threads: [ThreadSeccomp; MAX_THREADS],
    count: usize,
    /// Monotonic filter ID counter.
    next_filter_id: u32,
}

impl SeccompTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            threads: [const { ThreadSeccomp::new() }; MAX_THREADS],
            count: 0,
            next_filter_id: 1,
        }
    }

    fn find_mut(&mut self, tid: u32) -> Option<&mut ThreadSeccomp> {
        self.threads.iter_mut().find(|t| t.in_use && t.tid == tid)
    }

    fn find_or_create_mut(&mut self, tid: u32) -> Result<&mut ThreadSeccomp> {
        let existing = self.threads.iter().position(|t| t.in_use && t.tid == tid);
        if let Some(idx) = existing {
            return Ok(&mut self.threads[idx]);
        }
        let free = self
            .threads
            .iter()
            .position(|t| !t.in_use)
            .ok_or(Error::OutOfMemory)?;

        self.threads[free] = ThreadSeccomp::new();
        self.threads[free].in_use = true;
        self.threads[free].tid = tid;
        self.count += 1;
        Ok(&mut self.threads[free])
    }

    /// Return the seccomp mode for `tid`.
    pub fn mode_for(&self, tid: u32) -> u32 {
        self.threads
            .iter()
            .find(|t| t.in_use && t.tid == tid)
            .map(|t| t.mode)
            .unwrap_or(SECCOMP_MODE_DISABLED)
    }

    /// Return the filter count for `tid`.
    pub fn filter_count_for(&self, tid: u32) -> usize {
        self.threads
            .iter()
            .find(|t| t.in_use && t.tid == tid)
            .map(|t| t.filter_count)
            .unwrap_or(0)
    }

    /// Return the total number of tracked threads.
    pub const fn thread_count(&self) -> usize {
        self.count
    }
}

// ---------------------------------------------------------------------------
// SeccompNotifSizes — returned by SECCOMP_GET_NOTIF_SIZES
// ---------------------------------------------------------------------------

/// Sizes of the user-notification structures.
///
/// Matches `struct seccomp_notif_sizes` from `include/uapi/linux/seccomp.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SeccompNotifSizes {
    /// Size of `struct seccomp_notif`.
    pub seccomp_notif: u16,
    /// Size of `struct seccomp_notif_resp`.
    pub seccomp_notif_resp: u16,
    /// Size of `struct seccomp_data`.
    pub seccomp_data: u16,
}

impl SeccompNotifSizes {
    /// Return the sizes used in this implementation.
    pub const fn current() -> Self {
        Self {
            seccomp_notif: 80,
            seccomp_notif_resp: 24,
            seccomp_data: 64,
        }
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Check that `flags` for `SECCOMP_SET_MODE_STRICT` is 0.
fn validate_strict_flags(flags: u32) -> Result<()> {
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Check that `flags` for `SECCOMP_SET_MODE_FILTER` contains only known bits.
fn validate_filter_flags(flags: u32) -> Result<()> {
    if flags & !SECCOMP_FILTER_FLAGS_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }
    // NEW_LISTENER and TSYNC are mutually exclusive.
    if flags & SECCOMP_FILTER_FLAG_NEW_LISTENER != 0 && flags & SECCOMP_FILTER_FLAG_TSYNC != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Check that an action value is recognised.
fn is_known_action(action: u32) -> bool {
    matches!(
        action & SECCOMP_RET_ACTION_FULL,
        SECCOMP_RET_KILL_PROCESS
            | SECCOMP_RET_KILL_THREAD
            | SECCOMP_RET_TRAP
            | SECCOMP_RET_ERRNO
            | SECCOMP_RET_USER_NOTIF
            | SECCOMP_RET_TRACE
            | SECCOMP_RET_LOG
            | SECCOMP_RET_ALLOW
    )
}

// ---------------------------------------------------------------------------
// do_seccomp_set_mode_strict
// ---------------------------------------------------------------------------

/// Handler for `seccomp(SECCOMP_SET_MODE_STRICT, 0, NULL)`.
///
/// Enables strict mode for `tid`.  Once set, the thread may only call
/// `read(2)`, `write(2)`, `_exit(2)`, and `sigreturn(2)`.  Any other
/// syscall delivers `SIGKILL`.
///
/// Strict mode cannot be downgraded.  Attempting to set strict mode on a
/// thread that is already in filter mode is rejected.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `flags` is non-zero.
/// - [`Error::PermissionDenied`] — Thread is already in filter mode.
/// - [`Error::OutOfMemory`]     — Thread table full.
pub fn do_seccomp_set_mode_strict(table: &mut SeccompTable, tid: u32, flags: u32) -> Result<()> {
    validate_strict_flags(flags)?;

    let thread = table.find_or_create_mut(tid)?;

    // Cannot downgrade from filter mode.
    if thread.mode == SECCOMP_MODE_FILTER {
        return Err(Error::PermissionDenied);
    }

    thread.mode = SECCOMP_MODE_STRICT;
    Ok(())
}

// ---------------------------------------------------------------------------
// do_seccomp_set_mode_filter
// ---------------------------------------------------------------------------

/// Handler for `seccomp(SECCOMP_SET_MODE_FILTER, flags, prog)`.
///
/// Installs a BPF syscall filter for `tid`.  Multiple calls stack filters;
/// the most restrictive result across all filters is applied at runtime.
///
/// The thread must have set `no_new_privs` (via `prctl(PR_SET_NO_NEW_PRIVS)`)
/// unless it holds `CAP_SYS_ADMIN`.  This stub assumes the caller has
/// already verified the privilege.
///
/// # Arguments
///
/// * `table`        — Seccomp state table.
/// * `tid`          — Target thread.
/// * `flags`        — Filter installation flags.
/// * `prog`         — The BPF program descriptor.
/// * `has_privilege` — Whether the caller holds `CAP_SYS_ADMIN`.
///
/// # Returns
///
/// If `SECCOMP_FILTER_FLAG_NEW_LISTENER` is set, returns a synthetic
/// listener file descriptor.  Otherwise returns `None`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`]  — Bad flags or program.
/// - [`Error::PermissionDenied`] — No `no_new_privs` and no privilege.
/// - [`Error::OutOfMemory`]      — Too many filters or thread table full.
pub fn do_seccomp_set_mode_filter(
    table: &mut SeccompTable,
    tid: u32,
    flags: u32,
    prog: &SockFprog,
    has_privilege: bool,
    next_fd: &mut i32,
) -> Result<Option<i32>> {
    validate_filter_flags(flags)?;

    // Basic program validation.
    if prog.len == 0 || prog.len as usize > BPF_MAXINSNS {
        return Err(Error::InvalidArgument);
    }
    if prog.filter_ptr == 0 {
        return Err(Error::InvalidArgument);
    }

    let thread = table.find_or_create_mut(tid)?;

    // Privilege check: must have no_new_privs or CAP_SYS_ADMIN.
    if !thread.no_new_privs && !has_privilege {
        return Err(Error::PermissionDenied);
    }

    // Cannot install filters on a strict-mode thread.
    if thread.mode == SECCOMP_MODE_STRICT {
        return Err(Error::PermissionDenied);
    }

    // Allocate filter ID.
    let filter_id = table.next_filter_id;
    table.next_filter_id = table.next_filter_id.wrapping_add(1);

    let user_notif = flags & SECCOMP_FILTER_FLAG_NEW_LISTENER != 0;

    // Re-borrow thread after next_filter_id update.
    let thread = table.find_mut(tid).ok_or(Error::NotFound)?;

    let filter = SeccompFilter {
        id: filter_id,
        flags,
        user_notif,
        insn_count: prog.len,
    };

    thread.push_filter(filter)?;
    thread.mode = SECCOMP_MODE_FILTER;

    // Return a listener fd if requested.
    if user_notif {
        let fd = *next_fd;
        *next_fd = next_fd.wrapping_add(1);
        Ok(Some(fd))
    } else {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// do_seccomp_get_action_avail
// ---------------------------------------------------------------------------

/// Handler for `seccomp(SECCOMP_GET_ACTION_AVAIL, 0, &action)`.
///
/// Returns `Ok(())` if the specified action is supported by the kernel;
/// `Err(NotFound)` otherwise.
///
/// # Arguments
///
/// * `flags`  — Must be 0.
/// * `action` — The action value to probe (one of `SECCOMP_RET_*`).
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `flags` is non-zero.
/// - [`Error::NotFound`]        — The action is not supported.
pub fn do_seccomp_get_action_avail(flags: u32, action: u32) -> Result<()> {
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }
    if is_known_action(action) {
        Ok(())
    } else {
        Err(Error::NotFound)
    }
}

// ---------------------------------------------------------------------------
// do_seccomp_get_notif_sizes
// ---------------------------------------------------------------------------

/// Handler for `seccomp(SECCOMP_GET_NOTIF_SIZES, 0, &sizes)`.
///
/// Fills in the sizes of the user-notification interface structures.
///
/// # Arguments
///
/// * `flags` — Must be 0.
///
/// # Returns
///
/// [`SeccompNotifSizes`] for this kernel implementation.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `flags` is non-zero.
pub fn do_seccomp_get_notif_sizes(flags: u32) -> Result<SeccompNotifSizes> {
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(SeccompNotifSizes::current())
}

// ---------------------------------------------------------------------------
// do_seccomp — top-level dispatcher
// ---------------------------------------------------------------------------

/// Top-level dispatcher for `seccomp(2)`.
///
/// Dispatches to the appropriate handler based on `operation`.
///
/// # Arguments
///
/// * `table`         — Per-thread seccomp state table.
/// * `operation`     — One of `SECCOMP_SET_MODE_*`, `SECCOMP_GET_ACTION_AVAIL`,
///                     `SECCOMP_GET_NOTIF_SIZES`.
/// * `flags`         — Operation-specific flags.
/// * `arg`           — Operation-specific argument (interpreted per operation).
/// * `tid`           — Calling thread ID.
/// * `has_privilege` — Whether the caller holds `CAP_SYS_ADMIN`.
/// * `next_fd`       — Monotonic fd counter (for `NEW_LISTENER`).
///
/// # Returns
///
/// A `u64` result value (0 for most operations, listener fd for `NEW_LISTENER`).
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — Unknown operation or invalid arguments.
pub fn do_seccomp(
    table: &mut SeccompTable,
    operation: u32,
    flags: u32,
    arg: &SeccompArg,
    tid: u32,
    has_privilege: bool,
    next_fd: &mut i32,
) -> Result<u64> {
    match operation {
        SECCOMP_SET_MODE_STRICT => {
            do_seccomp_set_mode_strict(table, tid, flags)?;
            Ok(0)
        }
        SECCOMP_SET_MODE_FILTER => {
            let prog = arg.as_fprog().ok_or(Error::InvalidArgument)?;
            let fd = do_seccomp_set_mode_filter(table, tid, flags, prog, has_privilege, next_fd)?;
            Ok(fd.unwrap_or(0) as u64)
        }
        SECCOMP_GET_ACTION_AVAIL => {
            let action = arg.as_action().ok_or(Error::InvalidArgument)?;
            do_seccomp_get_action_avail(flags, action)?;
            Ok(0)
        }
        SECCOMP_GET_NOTIF_SIZES => {
            let sizes = do_seccomp_get_notif_sizes(flags)?;
            // Return packed sizes as a u64 (stub: just return the notif size).
            Ok(sizes.seccomp_notif as u64)
        }
        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// SeccompArg — union-like argument type
// ---------------------------------------------------------------------------

/// Argument to the `seccomp` dispatcher.
pub enum SeccompArg<'a> {
    /// A BPF filter program (for `SECCOMP_SET_MODE_FILTER`).
    Fprog(&'a SockFprog),
    /// An action value (for `SECCOMP_GET_ACTION_AVAIL`).
    Action(u32),
    /// Null / empty argument.
    Null,
}

impl<'a> SeccompArg<'a> {
    fn as_fprog(&self) -> Option<&SockFprog> {
        match self {
            SeccompArg::Fprog(p) => Some(p),
            _ => None,
        }
    }

    fn as_action(&self) -> Option<u32> {
        match self {
            SeccompArg::Action(a) => Some(*a),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fprog(len: u16) -> SockFprog {
        SockFprog {
            len,
            filter_ptr: 0x1000,
        }
    }

    // --- strict mode ---

    #[test]
    fn strict_mode_set() {
        let mut t = SeccompTable::new();
        do_seccomp_set_mode_strict(&mut t, 1, 0).unwrap();
        assert_eq!(t.mode_for(1), SECCOMP_MODE_STRICT);
    }

    #[test]
    fn strict_flags_nonzero_rejected() {
        let mut t = SeccompTable::new();
        assert_eq!(
            do_seccomp_set_mode_strict(&mut t, 1, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn cannot_set_strict_over_filter() {
        let mut t = SeccompTable::new();
        // Set filter mode first.
        let thread = t.find_or_create_mut(1).unwrap();
        thread.no_new_privs = true;
        thread.mode = SECCOMP_MODE_FILTER;
        assert_eq!(
            do_seccomp_set_mode_strict(&mut t, 1, 0),
            Err(Error::PermissionDenied)
        );
    }

    // --- filter mode ---

    #[test]
    fn filter_installed_with_privilege() {
        let mut t = SeccompTable::new();
        let mut next_fd = 3i32;
        let prog = make_fprog(10);
        do_seccomp_set_mode_filter(&mut t, 1, 0, &prog, true, &mut next_fd).unwrap();
        assert_eq!(t.mode_for(1), SECCOMP_MODE_FILTER);
        assert_eq!(t.filter_count_for(1), 1);
    }

    #[test]
    fn filter_without_privilege_and_no_new_privs_rejected() {
        let mut t = SeccompTable::new();
        let mut next_fd = 3i32;
        let prog = make_fprog(5);
        assert_eq!(
            do_seccomp_set_mode_filter(&mut t, 1, 0, &prog, false, &mut next_fd),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn filter_with_no_new_privs_allowed() {
        let mut t = SeccompTable::new();
        let thread = t.find_or_create_mut(2).unwrap();
        thread.no_new_privs = true;
        let mut next_fd = 3i32;
        let prog = make_fprog(5);
        do_seccomp_set_mode_filter(&mut t, 2, 0, &prog, false, &mut next_fd).unwrap();
        assert_eq!(t.mode_for(2), SECCOMP_MODE_FILTER);
    }

    #[test]
    fn filter_zero_len_rejected() {
        let mut t = SeccompTable::new();
        let mut next_fd = 3i32;
        let prog = SockFprog {
            len: 0,
            filter_ptr: 0x1000,
        };
        assert_eq!(
            do_seccomp_set_mode_filter(&mut t, 1, 0, &prog, true, &mut next_fd),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn filter_null_ptr_rejected() {
        let mut t = SeccompTable::new();
        let mut next_fd = 3i32;
        let prog = SockFprog {
            len: 10,
            filter_ptr: 0,
        };
        assert_eq!(
            do_seccomp_set_mode_filter(&mut t, 1, 0, &prog, true, &mut next_fd),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn filter_new_listener_returns_fd() {
        let mut t = SeccompTable::new();
        let mut next_fd = 5i32;
        let prog = make_fprog(10);
        let fd = do_seccomp_set_mode_filter(
            &mut t,
            1,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog,
            true,
            &mut next_fd,
        )
        .unwrap();
        assert_eq!(fd, Some(5));
        assert_eq!(next_fd, 6);
    }

    #[test]
    fn filter_stacking() {
        let mut t = SeccompTable::new();
        let mut next_fd = 3i32;
        let prog = make_fprog(8);
        do_seccomp_set_mode_filter(&mut t, 1, 0, &prog, true, &mut next_fd).unwrap();
        do_seccomp_set_mode_filter(&mut t, 1, 0, &prog, true, &mut next_fd).unwrap();
        assert_eq!(t.filter_count_for(1), 2);
    }

    #[test]
    fn new_listener_and_tsync_exclusive() {
        let mut t = SeccompTable::new();
        let mut next_fd = 3i32;
        let prog = make_fprog(5);
        let flags = SECCOMP_FILTER_FLAG_NEW_LISTENER | SECCOMP_FILTER_FLAG_TSYNC;
        assert_eq!(
            do_seccomp_set_mode_filter(&mut t, 1, flags, &prog, true, &mut next_fd),
            Err(Error::InvalidArgument)
        );
    }

    // --- get_action_avail ---

    #[test]
    fn known_actions_available() {
        for &action in &[
            SECCOMP_RET_KILL_PROCESS,
            SECCOMP_RET_KILL_THREAD,
            SECCOMP_RET_TRAP,
            SECCOMP_RET_ERRNO,
            SECCOMP_RET_USER_NOTIF,
            SECCOMP_RET_TRACE,
            SECCOMP_RET_LOG,
            SECCOMP_RET_ALLOW,
        ] {
            assert_eq!(do_seccomp_get_action_avail(0, action), Ok(()));
        }
    }

    #[test]
    fn unknown_action_not_available() {
        assert_eq!(
            do_seccomp_get_action_avail(0, 0x1234_0000),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn get_action_avail_nonzero_flags_rejected() {
        assert_eq!(
            do_seccomp_get_action_avail(1, SECCOMP_RET_ALLOW),
            Err(Error::InvalidArgument)
        );
    }

    // --- get_notif_sizes ---

    #[test]
    fn notif_sizes_returned() {
        let sizes = do_seccomp_get_notif_sizes(0).unwrap();
        assert_eq!(sizes, SeccompNotifSizes::current());
    }

    #[test]
    fn notif_sizes_nonzero_flags_rejected() {
        assert_eq!(do_seccomp_get_notif_sizes(1), Err(Error::InvalidArgument));
    }

    // --- dispatcher ---

    #[test]
    fn dispatcher_strict() {
        let mut t = SeccompTable::new();
        let mut next_fd = 3i32;
        let r = do_seccomp(
            &mut t,
            SECCOMP_SET_MODE_STRICT,
            0,
            &SeccompArg::Null,
            1,
            true,
            &mut next_fd,
        )
        .unwrap();
        assert_eq!(r, 0);
        assert_eq!(t.mode_for(1), SECCOMP_MODE_STRICT);
    }

    #[test]
    fn dispatcher_unknown_op_rejected() {
        let mut t = SeccompTable::new();
        let mut next_fd = 3i32;
        assert_eq!(
            do_seccomp(&mut t, 99, 0, &SeccompArg::Null, 1, true, &mut next_fd),
            Err(Error::InvalidArgument)
        );
    }
}
