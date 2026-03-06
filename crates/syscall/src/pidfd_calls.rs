// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `pidfd_open(2)`, `pidfd_getfd(2)`, and `pidfd_send_signal(2)` syscall handlers.
//!
//! PID file descriptors (pidfds) are file descriptors that refer to a specific
//! process instance rather than a PID number.  Unlike raw PIDs, pidfds are
//! immune to PID reuse races: once the process exits the pidfd simply becomes
//! ready-to-read (pollable) but never silently refers to a new process.
//!
//! # Operations
//!
//! | Syscall               | Handler                    | Purpose                          |
//! |-----------------------|----------------------------|----------------------------------|
//! | `pidfd_open`          | [`do_pidfd_open`]          | Create a pidfd for a PID         |
//! | `pidfd_getfd`         | [`do_pidfd_getfd`]         | Duplicate an fd from another proc|
//! | `pidfd_send_signal`   | [`do_pidfd_send_signal`]   | Send a signal via pidfd          |
//!
//! # Poll / exit notification
//!
//! A pidfd becomes readable (`POLLIN | POLLHUP`) when the process it refers to
//! exits.  [`PidfdEntry::poll`] returns the current readability state.
//!
//! # References
//!
//! - Linux: `kernel/pid.c`, `kernel/signal.c`, `include/uapi/linux/pidfd.h`
//! - man: `pidfd_open(2)`, `pidfd_getfd(2)`, `pidfd_send_signal(2)`
//! - POSIX signal spec: `.TheOpenGroup/susv5-html/functions/kill.html`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Open the pidfd with `O_NONBLOCK` set on the underlying file description.
pub const PIDFD_NONBLOCK: u32 = 0x0000_0800; // == O_NONBLOCK

/// Duplicate the target fd with `O_CLOEXEC` set (passed to `pidfd_getfd`).
pub const PIDFD_GETFD_CLOEXEC: u32 = 1 << 0;

/// All recognised `pidfd_open` flag bits.
const PIDFD_OPEN_FLAGS_KNOWN: u32 = PIDFD_NONBLOCK;

/// All recognised `pidfd_getfd` flag bits.
const PIDFD_GETFD_FLAGS_KNOWN: u32 = PIDFD_GETFD_CLOEXEC;

// ---------------------------------------------------------------------------
// Signal numbers (subset — mirrors kernel/include/uapi/asm-generic/signal.h)
// ---------------------------------------------------------------------------

/// Hangup (terminal disconnect).
pub const SIGHUP: u32 = 1;
/// Interrupt from keyboard.
pub const SIGINT: u32 = 2;
/// Quit from keyboard.
pub const SIGQUIT: u32 = 3;
/// Illegal instruction.
pub const SIGILL: u32 = 4;
/// Abort signal.
pub const SIGABRT: u32 = 6;
/// Floating point exception.
pub const SIGFPE: u32 = 8;
/// Kill (cannot be caught or ignored).
pub const SIGKILL: u32 = 9;
/// Segmentation fault.
pub const SIGSEGV: u32 = 11;
/// Broken pipe.
pub const SIGPIPE: u32 = 13;
/// Timer signal from alarm(2).
pub const SIGALRM: u32 = 14;
/// Termination signal.
pub const SIGTERM: u32 = 15;
/// Child stopped or terminated.
pub const SIGCHLD: u32 = 17;
/// Continue if stopped.
pub const SIGCONT: u32 = 18;
/// Stop process (cannot be caught or ignored).
pub const SIGSTOP: u32 = 19;
/// Stop typed at terminal.
pub const SIGTSTP: u32 = 20;
/// First real-time signal.
pub const SIGRTMIN: u32 = 32;
/// Last real-time signal.
pub const SIGRTMAX: u32 = 64;

/// Validate that `signo` is a valid signal number (1–64) or 0 (no-op probe).
pub fn signal_valid(signo: u32) -> bool {
    signo == 0 || (signo >= 1 && signo <= SIGRTMAX)
}

// ---------------------------------------------------------------------------
// siginfo_t — simplified version for pidfd_send_signal
// ---------------------------------------------------------------------------

/// Simplified `siginfo_t` structure.
///
/// In the real kernel this is a 128-byte union.  Here we keep the minimum
/// fields needed for `pidfd_send_signal`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SigInfo {
    /// Signal number.
    pub si_signo: i32,
    /// Error number associated with the signal (usually 0).
    pub si_errno: i32,
    /// Signal code (SI_USER, SI_KERNEL, etc.).
    pub si_code: i32,
    /// Sender PID (for SI_USER).
    pub si_pid: u32,
    /// Sender UID.
    pub si_uid: u32,
    /// Additional value (union — e.g. fault address or timer overrun).
    pub si_value: u64,
}

/// Signal originated in user space via `kill(2)` / `pidfd_send_signal`.
pub const SI_USER: i32 = 0;
/// Signal sent by the kernel.
pub const SI_KERNEL: i32 = 0x80;
/// Signal sent by `sigqueue(3)`.
pub const SI_QUEUE: i32 = -1;

// ---------------------------------------------------------------------------
// Process state (visible to pidfd)
// ---------------------------------------------------------------------------

/// Lifecycle state of the process a pidfd refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// Process is alive and running or sleeping.
    Alive,
    /// Process has called `exit` but not yet been reaped (zombie).
    Zombie,
    /// Process has been fully reaped by `wait`.
    Dead,
}

impl ProcessState {
    /// Return `true` if the process has exited (zombie or dead).
    pub const fn has_exited(self) -> bool {
        matches!(self, ProcessState::Zombie | ProcessState::Dead)
    }
}

// ---------------------------------------------------------------------------
// PidfdInfo — metadata returned by ioctl(PIDFD_GET_INFO)
// ---------------------------------------------------------------------------

/// Information about the process a pidfd refers to.
///
/// Mirrors the upcoming `struct pidfd_info` from the Linux kernel.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PidfdInfo {
    /// PID in the caller's PID namespace.
    pub pid: u32,
    /// Thread group ID (== PID of the thread group leader).
    pub tgid: u32,
    /// PPID.
    pub ppid: u32,
    /// Real UID of the process.
    pub ruid: u32,
    /// Real GID of the process.
    pub rgid: u32,
    /// Exit code (valid only when `exited` is true).
    pub exit_code: i32,
    /// Whether the process has exited.
    pub exited: bool,
    /// Whether `O_NONBLOCK` is set on the pidfd.
    pub nonblock: bool,
    /// Reserved padding.
    pub __pad: [u8; 2],
}

// ---------------------------------------------------------------------------
// PidfdEntry — a single pidfd in the driver's table
// ---------------------------------------------------------------------------

/// A single entry in the pidfd table.
///
/// Tracks the target PID, its current state, and the flags the pidfd
/// was opened with.
#[derive(Debug, Clone)]
pub struct PidfdEntry {
    /// The fd number assigned to this pidfd.
    pub fd: u32,
    /// The PID this entry refers to.
    pub pid: u32,
    /// Thread group ID of the target.
    pub tgid: u32,
    /// UID of the target process.
    pub uid: u32,
    /// GID of the target process.
    pub gid: u32,
    /// Flags this pidfd was opened with (`PIDFD_NONBLOCK` etc.).
    pub flags: u32,
    /// Current lifecycle state of the target process.
    pub state: ProcessState,
    /// Exit code (set when `state` transitions to `Zombie`).
    pub exit_code: i32,
}

impl PidfdEntry {
    /// Create a new pidfd entry for an alive process.
    pub const fn new(fd: u32, pid: u32, tgid: u32, uid: u32, gid: u32, flags: u32) -> Self {
        Self {
            fd,
            pid,
            tgid,
            uid,
            gid,
            flags,
            state: ProcessState::Alive,
            exit_code: 0,
        }
    }

    /// Return `true` if `O_NONBLOCK` is set on this pidfd.
    pub const fn is_nonblock(&self) -> bool {
        self.flags & PIDFD_NONBLOCK != 0
    }

    /// Mark the target process as having exited with `exit_code`.
    ///
    /// Transitions `Alive → Zombie`.  A zombie becomes `Dead` after reaping.
    pub fn notify_exit(&mut self, exit_code: i32) {
        if self.state == ProcessState::Alive {
            self.state = ProcessState::Zombie;
            self.exit_code = exit_code;
        }
    }

    /// Mark the zombie as fully reaped (`Zombie → Dead`).
    pub fn mark_dead(&mut self) {
        if self.state == ProcessState::Zombie {
            self.state = ProcessState::Dead;
        }
    }

    /// Poll the pidfd for readability.
    ///
    /// Returns `true` if the process has exited (POLLIN | POLLHUP ready).
    /// This is the mechanism user-space uses to wait for process exit via
    /// `poll(2)` / `epoll(7)` without a `wait(2)` call.
    pub fn poll(&self) -> bool {
        self.state.has_exited()
    }

    /// Build a [`PidfdInfo`] snapshot from this entry.
    pub fn info(&self) -> PidfdInfo {
        PidfdInfo {
            pid: self.pid,
            tgid: self.tgid,
            ppid: 0, // not tracked in this stub
            ruid: self.uid,
            rgid: self.gid,
            exit_code: self.exit_code,
            exited: self.state.has_exited(),
            nonblock: self.is_nonblock(),
            __pad: [0u8; 2],
        }
    }
}

// ---------------------------------------------------------------------------
// Pidfd table
// ---------------------------------------------------------------------------

/// Maximum number of pidfds tracked globally.
pub const PIDFD_TABLE_SIZE: usize = 64;

/// Global pidfd table.
pub struct PidfdTable {
    entries: [Option<PidfdEntry>; PIDFD_TABLE_SIZE],
    count: usize,
    /// Monotonically increasing fd allocator.
    next_fd: u32,
}

impl PidfdTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; PIDFD_TABLE_SIZE],
            count: 0,
            next_fd: 100, // start above stdio range
        }
    }

    /// Allocate the next fd value.
    fn alloc_fd(&mut self) -> u32 {
        let fd = self.next_fd;
        self.next_fd = self.next_fd.wrapping_add(1);
        fd
    }

    /// Insert a new entry, returning `Err(OutOfMemory)` if full.
    fn insert(&mut self, entry: PidfdEntry) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(entry);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up an entry by fd (immutable).
    pub fn get(&self, fd: u32) -> Option<&PidfdEntry> {
        self.entries
            .iter()
            .find_map(|s| s.as_ref().filter(|e| e.fd == fd))
    }

    /// Look up an entry by fd (mutable).
    pub fn get_mut(&mut self, fd: u32) -> Option<&mut PidfdEntry> {
        self.entries
            .iter_mut()
            .find_map(|s| s.as_mut().filter(|e| e.fd == fd))
    }

    /// Find an entry by PID (immutable).
    pub fn find_by_pid(&self, pid: u32) -> Option<&PidfdEntry> {
        self.entries
            .iter()
            .find_map(|s| s.as_ref().filter(|e| e.pid == pid))
    }

    /// Close (remove) a pidfd entry.
    ///
    /// Returns `Err(NotFound)` if `fd` is not in the table.
    pub fn close(&mut self, fd: u32) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if slot.as_ref().map(|e| e.fd == fd).unwrap_or(false) {
                *slot = None;
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Deliver an exit notification to all pidfds referencing `pid`.
    ///
    /// Called by the process table when a process calls `exit`.
    pub fn notify_exit(&mut self, pid: u32, exit_code: i32) {
        for slot in self.entries.iter_mut() {
            if let Some(e) = slot {
                if e.pid == pid {
                    e.notify_exit(exit_code);
                }
            }
        }
    }

    /// Return the number of open pidfds.
    pub const fn count(&self) -> usize {
        self.count
    }
}

// ---------------------------------------------------------------------------
// Process registry stub
// ---------------------------------------------------------------------------

/// Maximum processes in the stub registry.
pub const PROC_REGISTRY_SIZE: usize = 64;

/// A minimal process descriptor for the stub registry.
#[derive(Debug, Clone, Copy)]
pub struct ProcEntry {
    /// Process ID.
    pub pid: u32,
    /// Thread group ID.
    pub tgid: u32,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Process state.
    pub state: ProcessState,
}

impl ProcEntry {
    /// Create a new alive process entry.
    pub const fn new(pid: u32, tgid: u32, uid: u32, gid: u32) -> Self {
        Self {
            pid,
            tgid,
            uid,
            gid,
            state: ProcessState::Alive,
        }
    }
}

/// Stub process registry used by pidfd handlers to validate PIDs.
pub struct ProcRegistry {
    procs: [Option<ProcEntry>; PROC_REGISTRY_SIZE],
}

impl ProcRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            procs: [const { None }; PROC_REGISTRY_SIZE],
        }
    }

    /// Register a process.
    pub fn register(&mut self, entry: ProcEntry) -> Result<()> {
        for slot in self.procs.iter_mut() {
            if slot.is_none() {
                *slot = Some(entry);
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up a process by PID.
    pub fn find(&self, pid: u32) -> Option<&ProcEntry> {
        self.procs
            .iter()
            .find_map(|s| s.as_ref().filter(|p| p.pid == pid))
    }
}

// ---------------------------------------------------------------------------
// do_pidfd_open
// ---------------------------------------------------------------------------

/// Handler for `pidfd_open(2)`.
///
/// Creates a file descriptor that refers to the process identified by `pid`.
/// The pidfd may be used to send signals ([`do_pidfd_send_signal`]), duplicate
/// file descriptors ([`do_pidfd_getfd`]), or wait for process exit via `poll`.
///
/// # Arguments
///
/// * `table`   — Pidfd table.
/// * `procs`   — Process registry (for PID validation).
/// * `pid`     — PID of the target process.
/// * `flags`   — `PIDFD_NONBLOCK` or 0.
/// * `caller_uid` — UID of the calling process (for permission checks).
///
/// # Returns
///
/// A new fd number (as `u32`) on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — Unknown flags or `pid == 0`.
/// * [`Error::NotFound`]         — No process with `pid` exists.
/// * [`Error::PermissionDenied`] — Caller lacks permission to observe target.
/// * [`Error::OutOfMemory`]      — Pidfd table is full.
///
/// # Linux conformance
///
/// - Only whole thread-group leaders can be referenced (`pid == tgid`).
/// - `flags` must be 0 or `PIDFD_NONBLOCK`.
/// - The pidfd remains valid even after the process exits (it becomes pollable).
pub fn do_pidfd_open(
    table: &mut PidfdTable,
    procs: &ProcRegistry,
    pid: u32,
    flags: u32,
    caller_uid: u32,
) -> Result<u32> {
    if pid == 0 {
        return Err(Error::InvalidArgument);
    }
    if flags & !PIDFD_OPEN_FLAGS_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }

    let proc = procs.find(pid).ok_or(Error::NotFound)?;

    // Only thread-group leaders can be opened as pidfds.
    if proc.pid != proc.tgid {
        return Err(Error::InvalidArgument);
    }

    // Permission check: unprivileged callers can only open processes they own
    // or their children.  uid==0 is root (always allowed).
    if caller_uid != 0 && proc.uid != caller_uid {
        return Err(Error::PermissionDenied);
    }

    let fd = table.alloc_fd();
    let entry = PidfdEntry::new(fd, proc.pid, proc.tgid, proc.uid, proc.gid, flags);
    table.insert(entry)?;
    Ok(fd)
}

// ---------------------------------------------------------------------------
// do_pidfd_getfd
// ---------------------------------------------------------------------------

/// Handler for `pidfd_getfd(2)`.
///
/// Duplicates file descriptor `targetfd` from the process referred to by
/// `pidfd` into the calling process's file descriptor table.
///
/// This implementation validates the arguments and returns a synthetic
/// new-fd value representing the duplicated descriptor.
///
/// # Arguments
///
/// * `table`      — Pidfd table.
/// * `pidfd`      — File descriptor referring to the target process.
/// * `targetfd`   — The file descriptor in the target process to duplicate.
/// * `flags`      — `PIDFD_GETFD_CLOEXEC` or 0.
/// * `caller_uid` — UID of the calling process.
///
/// # Returns
///
/// A new fd number in the caller's fd table (synthetic).
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — Unknown flags or `targetfd` is negative.
/// * [`Error::NotFound`]         — `pidfd` is not in the table.
/// * [`Error::PermissionDenied`] — Caller does not own the target process or
///                                 the target process has already exited.
///
/// # Linux conformance
///
/// Requires `ptrace` (`CAP_SYS_PTRACE`) or that the caller owns the target
/// process.  Dead processes return `ESRCH`.
pub fn do_pidfd_getfd(
    table: &PidfdTable,
    pidfd: u32,
    targetfd: u32,
    flags: u32,
    caller_uid: u32,
) -> Result<u32> {
    if flags & !PIDFD_GETFD_FLAGS_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }
    if targetfd > i32::MAX as u32 {
        return Err(Error::InvalidArgument);
    }

    let entry = table.get(pidfd).ok_or(Error::NotFound)?;

    // Dead processes cannot have fds duplicated.
    if entry.state == ProcessState::Dead {
        return Err(Error::NotFound);
    }

    // Permission: caller must own the process.
    if caller_uid != 0 && entry.uid != caller_uid {
        return Err(Error::PermissionDenied);
    }

    // Synthetic: derive new fd from targetfd + pidfd as a stable value.
    let new_fd = targetfd.wrapping_add(pidfd).wrapping_add(0x200);
    Ok(new_fd)
}

// ---------------------------------------------------------------------------
// do_pidfd_send_signal
// ---------------------------------------------------------------------------

/// Handler for `pidfd_send_signal(2)`.
///
/// Sends signal `sig` to the process referred to by `pidfd`.  Unlike
/// `kill(2)`, this is race-free with respect to PID reuse.
///
/// # Arguments
///
/// * `table`      — Pidfd table.
/// * `pidfd`      — File descriptor referring to the target process.
/// * `sig`        — Signal number (0–64); 0 performs permission check only.
/// * `info`       — Optional `siginfo_t`.  If `None`, the kernel fills it in.
/// * `flags`      — Must be 0 (reserved for future use).
/// * `caller_pid` — PID of the caller (filled into `si_pid`).
/// * `caller_uid` — UID of the caller (for permission checks).
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — Non-zero flags or invalid signal number.
/// * [`Error::NotFound`]         — `pidfd` not found or process already dead.
/// * [`Error::PermissionDenied`] — Caller lacks send permission.
///
/// # POSIX conformance
///
/// Signal 0 (`sig == 0`) performs only the existence/permission check without
/// actually delivering a signal — identical to `kill(pid, 0)`.
/// SIGKILL and SIGSTOP cannot be caught but can be sent via pidfd.
pub fn do_pidfd_send_signal(
    table: &PidfdTable,
    pidfd: u32,
    sig: u32,
    info: Option<&SigInfo>,
    flags: u32,
    caller_pid: u32,
    caller_uid: u32,
) -> Result<()> {
    // flags must be zero.
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }

    if !signal_valid(sig) {
        return Err(Error::InvalidArgument);
    }

    // Validate the siginfo if provided.
    if let Some(si) = info {
        if si.si_signo as u32 != sig && sig != 0 {
            return Err(Error::InvalidArgument);
        }
        // Only SI_USER and SI_QUEUE are valid codes from user space.
        if si.si_code != SI_USER && si.si_code != SI_QUEUE {
            return Err(Error::InvalidArgument);
        }
    }

    let entry = table.get(pidfd).ok_or(Error::NotFound)?;

    // Cannot signal a dead process.
    if entry.state == ProcessState::Dead {
        return Err(Error::NotFound);
    }

    // Zombie processes: only signal 0 (existence check) is meaningful.
    if entry.state == ProcessState::Zombie && sig != 0 {
        return Err(Error::NotFound);
    }

    // Permission check (simplified DAC):
    // - Root (uid 0) can signal any process.
    // - Otherwise caller must own the target.
    if caller_uid != 0 && entry.uid != caller_uid {
        return Err(Error::PermissionDenied);
    }

    // sig == 0: existence + permission check only, no actual signal delivery.
    let _ = (caller_pid, sig);
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_registry() -> ProcRegistry {
        let mut r = ProcRegistry::new();
        // pid 1000: thread-group leader, uid 500
        r.register(ProcEntry::new(1000, 1000, 500, 500)).unwrap();
        // pid 2000: thread (not leader), uid 500
        r.register(ProcEntry::new(2000, 1000, 500, 500)).unwrap();
        // pid 3000: owned by root
        r.register(ProcEntry::new(3000, 3000, 0, 0)).unwrap();
        r
    }

    // --- signal_valid ---

    #[test]
    fn signal_zero_valid() {
        assert!(signal_valid(0));
    }

    #[test]
    fn signal_valid_range() {
        assert!(signal_valid(SIGKILL));
        assert!(signal_valid(SIGTERM));
        assert!(signal_valid(SIGRTMAX));
    }

    #[test]
    fn signal_out_of_range_invalid() {
        assert!(!signal_valid(65));
        assert!(!signal_valid(u32::MAX));
    }

    // --- do_pidfd_open ---

    #[test]
    fn open_valid_pid() {
        let mut t = PidfdTable::new();
        let r = make_registry();
        let fd = do_pidfd_open(&mut t, &r, 1000, 0, 500).unwrap();
        assert!(fd >= 100);
        assert_eq!(t.count(), 1);
    }

    #[test]
    fn open_nonblock_flag() {
        let mut t = PidfdTable::new();
        let r = make_registry();
        let fd = do_pidfd_open(&mut t, &r, 1000, PIDFD_NONBLOCK, 500).unwrap();
        assert!(t.get(fd).unwrap().is_nonblock());
    }

    #[test]
    fn open_pid_zero_rejected() {
        let mut t = PidfdTable::new();
        let r = make_registry();
        assert_eq!(
            do_pidfd_open(&mut t, &r, 0, 0, 500),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn open_unknown_flags_rejected() {
        let mut t = PidfdTable::new();
        let r = make_registry();
        assert_eq!(
            do_pidfd_open(&mut t, &r, 1000, 0xDEAD_0000, 500),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn open_nonexistent_pid_notfound() {
        let mut t = PidfdTable::new();
        let r = make_registry();
        assert_eq!(
            do_pidfd_open(&mut t, &r, 9999, 0, 500),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn open_non_leader_rejected() {
        let mut t = PidfdTable::new();
        let r = make_registry();
        // pid 2000 has tgid 1000, so it is not a thread-group leader.
        assert_eq!(
            do_pidfd_open(&mut t, &r, 2000, 0, 500),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn open_permission_denied_different_uid() {
        let mut t = PidfdTable::new();
        let r = make_registry();
        // uid 999 trying to open uid 500's process.
        assert_eq!(
            do_pidfd_open(&mut t, &r, 1000, 0, 999),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn open_root_can_open_any() {
        let mut t = PidfdTable::new();
        let r = make_registry();
        // uid 0 (root) can open pid 1000 (uid 500).
        assert!(do_pidfd_open(&mut t, &r, 1000, 0, 0).is_ok());
    }

    // --- poll / exit notification ---

    #[test]
    fn poll_alive_returns_false() {
        let mut t = PidfdTable::new();
        let r = make_registry();
        let fd = do_pidfd_open(&mut t, &r, 1000, 0, 500).unwrap();
        assert!(!t.get(fd).unwrap().poll());
    }

    #[test]
    fn poll_after_exit_returns_true() {
        let mut t = PidfdTable::new();
        let r = make_registry();
        let fd = do_pidfd_open(&mut t, &r, 1000, 0, 500).unwrap();
        t.notify_exit(1000, 0);
        assert!(t.get(fd).unwrap().poll());
    }

    #[test]
    fn notify_exit_sets_zombie_state() {
        let mut t = PidfdTable::new();
        let r = make_registry();
        let fd = do_pidfd_open(&mut t, &r, 1000, 0, 500).unwrap();
        t.notify_exit(1000, 1);
        let e = t.get(fd).unwrap();
        assert_eq!(e.state, ProcessState::Zombie);
        assert_eq!(e.exit_code, 1);
    }

    #[test]
    fn mark_dead_transitions_zombie_to_dead() {
        let mut t = PidfdTable::new();
        let r = make_registry();
        let fd = do_pidfd_open(&mut t, &r, 1000, 0, 500).unwrap();
        t.notify_exit(1000, 0);
        t.get_mut(fd).unwrap().mark_dead();
        assert_eq!(t.get(fd).unwrap().state, ProcessState::Dead);
    }

    // --- PidfdInfo ---

    #[test]
    fn info_reflects_state() {
        let mut t = PidfdTable::new();
        let r = make_registry();
        let fd = do_pidfd_open(&mut t, &r, 1000, PIDFD_NONBLOCK, 500).unwrap();
        let info = t.get(fd).unwrap().info();
        assert_eq!(info.pid, 1000);
        assert_eq!(info.ruid, 500);
        assert!(!info.exited);
        assert!(info.nonblock);
    }

    // --- do_pidfd_getfd ---

    #[test]
    fn getfd_success() {
        let mut t = PidfdTable::new();
        let r = make_registry();
        let pidfd = do_pidfd_open(&mut t, &r, 1000, 0, 500).unwrap();
        let new_fd = do_pidfd_getfd(&t, pidfd, 3, 0, 500).unwrap();
        assert!(new_fd > 0);
    }

    #[test]
    fn getfd_unknown_flags_rejected() {
        let mut t = PidfdTable::new();
        let r = make_registry();
        let pidfd = do_pidfd_open(&mut t, &r, 1000, 0, 500).unwrap();
        assert_eq!(
            do_pidfd_getfd(&t, pidfd, 3, 0xFF, 500),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn getfd_dead_process_fails() {
        let mut t = PidfdTable::new();
        let r = make_registry();
        let pidfd = do_pidfd_open(&mut t, &r, 1000, 0, 500).unwrap();
        t.notify_exit(1000, 0);
        t.get_mut(pidfd).unwrap().mark_dead();
        assert_eq!(do_pidfd_getfd(&t, pidfd, 3, 0, 500), Err(Error::NotFound));
    }

    #[test]
    fn getfd_permission_denied() {
        let mut t = PidfdTable::new();
        let r = make_registry();
        let pidfd = do_pidfd_open(&mut t, &r, 1000, 0, 500).unwrap();
        assert_eq!(
            do_pidfd_getfd(&t, pidfd, 3, 0, 999),
            Err(Error::PermissionDenied)
        );
    }

    // --- do_pidfd_send_signal ---

    #[test]
    fn send_signal_sigterm_succeeds() {
        let mut t = PidfdTable::new();
        let r = make_registry();
        let pidfd = do_pidfd_open(&mut t, &r, 1000, 0, 500).unwrap();
        assert_eq!(
            do_pidfd_send_signal(&t, pidfd, SIGTERM, None, 0, 500, 500),
            Ok(())
        );
    }

    #[test]
    fn send_signal_zero_probe_succeeds() {
        let mut t = PidfdTable::new();
        let r = make_registry();
        let pidfd = do_pidfd_open(&mut t, &r, 1000, 0, 500).unwrap();
        assert_eq!(
            do_pidfd_send_signal(&t, pidfd, 0, None, 0, 500, 500),
            Ok(())
        );
    }

    #[test]
    fn send_signal_invalid_signo_rejected() {
        let mut t = PidfdTable::new();
        let r = make_registry();
        let pidfd = do_pidfd_open(&mut t, &r, 1000, 0, 500).unwrap();
        assert_eq!(
            do_pidfd_send_signal(&t, pidfd, 100, None, 0, 500, 500),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn send_signal_nonzero_flags_rejected() {
        let mut t = PidfdTable::new();
        let r = make_registry();
        let pidfd = do_pidfd_open(&mut t, &r, 1000, 0, 500).unwrap();
        assert_eq!(
            do_pidfd_send_signal(&t, pidfd, SIGKILL, None, 1, 500, 500),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn send_signal_to_dead_process_fails() {
        let mut t = PidfdTable::new();
        let r = make_registry();
        let pidfd = do_pidfd_open(&mut t, &r, 1000, 0, 500).unwrap();
        t.notify_exit(1000, 0);
        t.get_mut(pidfd).unwrap().mark_dead();
        assert_eq!(
            do_pidfd_send_signal(&t, pidfd, SIGTERM, None, 0, 500, 500),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn send_signal_permission_denied() {
        let mut t = PidfdTable::new();
        let r = make_registry();
        let pidfd = do_pidfd_open(&mut t, &r, 1000, 0, 500).unwrap();
        assert_eq!(
            do_pidfd_send_signal(&t, pidfd, SIGTERM, None, 0, 999, 999),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn send_signal_with_siginfo() {
        let mut t = PidfdTable::new();
        let r = make_registry();
        let pidfd = do_pidfd_open(&mut t, &r, 1000, 0, 500).unwrap();
        let si = SigInfo {
            si_signo: SIGTERM as i32,
            si_code: SI_USER,
            si_pid: 500,
            si_uid: 500,
            ..Default::default()
        };
        assert_eq!(
            do_pidfd_send_signal(&t, pidfd, SIGTERM, Some(&si), 0, 500, 500),
            Ok(())
        );
    }

    #[test]
    fn send_signal_siginfo_mismatch_rejected() {
        let mut t = PidfdTable::new();
        let r = make_registry();
        let pidfd = do_pidfd_open(&mut t, &r, 1000, 0, 500).unwrap();
        let si = SigInfo {
            si_signo: SIGKILL as i32, // mismatch: caller said SIGTERM
            si_code: SI_USER,
            ..Default::default()
        };
        assert_eq!(
            do_pidfd_send_signal(&t, pidfd, SIGTERM, Some(&si), 0, 500, 500),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn close_removes_entry() {
        let mut t = PidfdTable::new();
        let r = make_registry();
        let fd = do_pidfd_open(&mut t, &r, 1000, 0, 500).unwrap();
        assert_eq!(t.count(), 1);
        t.close(fd).unwrap();
        assert_eq!(t.count(), 0);
    }
}
