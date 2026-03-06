// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended `pidfd` syscall handlers.
//!
//! This module extends the basic pidfd operations from `pidfd_calls.rs` with
//! additional interfaces introduced in Linux 5.10+:
//!
//! | Syscall              | Handler                   | Purpose                             |
//! |----------------------|---------------------------|-------------------------------------|
//! | `pidfd_info` ioctl   | [`do_pidfd_query_info`]   | Query detailed process info via fd  |
//! | `pidfd_poll`         | [`do_pidfd_poll`]         | Poll multiple pidfds for exit       |
//! | `waitid` (WNOWAIT)   | [`do_pidfd_waitid`]       | Wait on process via pidfd           |
//! | `pidfd_getfd` batch  | [`do_pidfd_getfd_batch`]  | Duplicate multiple fds at once      |
//!
//! # Background
//!
//! The basic `pidfd_open` / `pidfd_send_signal` / `pidfd_getfd` triad was
//! introduced in Linux 5.3 – 5.6.  This module adds the higher-level query
//! and bulk operations that make pidfds practical for process supervision
//! daemons (e.g., systemd, container runtimes).
//!
//! # POSIX conformance
//!
//! PID file descriptors have no direct POSIX equivalent.  The signal-delivery
//! semantics follow POSIX kill(2) rules — see
//! `.TheOpenGroup/susv5-html/functions/kill.html`.
//!
//! # References
//!
//! - Linux `kernel/pid.c`, `kernel/signal.c`
//! - Linux `include/uapi/linux/pidfd.h`
//! - man: `pidfd_open(2)`, `pidfd_getfd(2)`, `waitid(2)`

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

// Re-use types from the base pidfd_calls module.
use crate::pidfd_calls::{PidfdInfo, PidfdTable, ProcessState};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of pidfds in a single batch `getfd` call.
pub const PIDFD_GETFD_BATCH_MAX: usize = 16;

/// `waitid` flag: do not remove the child from the wait queue.
pub const WNOWAIT: u32 = 0x0100_0000;

/// `waitid` flag: wait for children in any state.
pub const WALL: u32 = 0x4000_0000;

/// `waitid` flag: also wait for stopped (but not terminated) children.
pub const WSTOPPED: u32 = 0x0000_0002;

/// `waitid` flag: also wait for continued children.
pub const WCONTINUED: u32 = 0x0000_0008;

/// `waitid` flag: return immediately even if nothing has changed.
pub const WNOHANG: u32 = 0x0000_0001;

/// `waitid` flag: wait for children that have exited.
pub const WEXITED: u32 = 0x0000_0004;

/// Mask of all recognised `waitid` flags for pidfd-based wait.
const WAITID_FLAGS_KNOWN: u32 = WNOWAIT | WALL | WSTOPPED | WCONTINUED | WNOHANG | WEXITED;

/// All known poll-event bits for a pidfd.
pub const POLLIN: u32 = 0x0001;
/// Peer half of a connection closed.
pub const POLLHUP: u32 = 0x0010;
/// An error occurred on the fd.
pub const POLLERR: u32 = 0x0008;

// ---------------------------------------------------------------------------
// PidfdPollEntry — input/output element for do_pidfd_poll
// ---------------------------------------------------------------------------

/// One element of a pidfd poll request.
///
/// Before the call, `fd` identifies the pidfd and `events` specifies which
/// events the caller is interested in.  After the call, `revents` is filled
/// with the events that are currently ready.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PidfdPollEntry {
    /// The pidfd to check.
    pub fd: u32,
    /// Requested event mask (combination of `POLLIN`, `POLLHUP`, `POLLERR`).
    pub events: u32,
    /// Filled on return — bitmask of ready events.
    pub revents: u32,
}

// ---------------------------------------------------------------------------
// WaitidResult — result of a waitid-via-pidfd call
// ---------------------------------------------------------------------------

/// Result returned by [`do_pidfd_waitid`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitidResult {
    /// A child matching the pidfd was found and it has exited.
    Exited {
        /// PID of the child.
        pid: u32,
        /// Exit status as returned by `waitid`.
        status: i32,
    },
    /// `WNOHANG` was set and no child has changed state yet.
    NotReady,
    /// `WNOWAIT` was set: status was returned but the child was not reaped.
    Peek {
        /// PID of the child.
        pid: u32,
        /// Exit status.
        status: i32,
    },
}

// ---------------------------------------------------------------------------
// PidfdGetfdBatchArgs — argument block for do_pidfd_getfd_batch
// ---------------------------------------------------------------------------

/// Arguments for a batch `pidfd_getfd` operation.
///
/// Duplicates up to [`PIDFD_GETFD_BATCH_MAX`] file descriptors from the
/// process referenced by `pidfd` in a single call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PidfdGetfdBatchArgs {
    /// Pidfd referring to the source process.
    pub pidfd: u32,
    /// Source file descriptors to duplicate (up to `count` entries).
    pub src_fds: [u32; PIDFD_GETFD_BATCH_MAX],
    /// Destination fd values on success (filled by the handler).
    pub dst_fds: [u32; PIDFD_GETFD_BATCH_MAX],
    /// Number of entries in `src_fds` / `dst_fds` to process.
    pub count: usize,
    /// Flags (must be 0 for now).
    pub flags: u32,
}

impl Default for PidfdGetfdBatchArgs {
    fn default() -> Self {
        Self {
            pidfd: 0,
            src_fds: [0u32; PIDFD_GETFD_BATCH_MAX],
            dst_fds: [0u32; PIDFD_GETFD_BATCH_MAX],
            count: 0,
            flags: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Extended PidfdInfo with namespace context
// ---------------------------------------------------------------------------

/// Extended process information returned by [`do_pidfd_query_info`].
///
/// Extends [`PidfdInfo`] with namespace and resource data that is not
/// available from the basic `ioctl(PIDFD_GET_INFO)`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PidfdExtInfo {
    /// Core identity information (mirrors `struct pidfd_info`).
    pub core: PidfdInfo,
    /// PID namespace depth (0 = init namespace).
    pub ns_depth: u32,
    /// Mount namespace ID.
    pub mnt_ns_id: u64,
    /// Network namespace ID.
    pub net_ns_id: u64,
    /// Number of open file descriptors in the process.
    pub open_fds: u32,
    /// Number of threads in the thread group.
    pub thread_count: u32,
    /// Padding for 8-byte alignment.
    pub __pad: [u8; 4],
}

// ---------------------------------------------------------------------------
// do_pidfd_query_info
// ---------------------------------------------------------------------------

/// Query extended information about the process referred to by `pidfd`.
///
/// Combines [`PidfdInfo`] with namespace and resource counters into an
/// [`PidfdExtInfo`] structure.
///
/// # Arguments
///
/// * `table`      — Pidfd table.
/// * `pidfd`      — File descriptor referring to the target process.
/// * `caller_uid` — UID of the calling process (for permission checks).
///
/// # Errors
///
/// * [`Error::NotFound`]         — `pidfd` is not in the table or the process
///                                 is already dead.
/// * [`Error::PermissionDenied`] — Caller does not own the target process.
pub fn do_pidfd_query_info(
    table: &PidfdTable,
    pidfd: u32,
    caller_uid: u32,
) -> Result<PidfdExtInfo> {
    let entry = table.get(pidfd).ok_or(Error::NotFound)?;

    if entry.state == ProcessState::Dead {
        return Err(Error::NotFound);
    }

    if caller_uid != 0 && entry.uid != caller_uid {
        return Err(Error::PermissionDenied);
    }

    let core = entry.info();

    Ok(PidfdExtInfo {
        core,
        // Stub values — a real implementation would query the process's
        // namespace structures and fd table.
        ns_depth: 0,
        mnt_ns_id: entry.pid as u64 * 0x1000,
        net_ns_id: entry.pid as u64 * 0x2000,
        open_fds: 3, // stdin/stdout/stderr minimum
        thread_count: 1,
        __pad: [0u8; 4],
    })
}

// ---------------------------------------------------------------------------
// do_pidfd_poll
// ---------------------------------------------------------------------------

/// Poll a slice of pidfds for readability (exit notification).
///
/// For each [`PidfdPollEntry`] in `entries`, fills `revents` with:
/// * `POLLIN | POLLHUP` — the process has exited (zombie or dead).
/// * `POLLERR` — the pidfd is not found in the table.
/// * `0` — the process is still alive (not ready).
///
/// Unknown pidfds set `POLLERR` so the caller can identify stale entries
/// without aborting the entire poll.
///
/// # Arguments
///
/// * `table`   — Pidfd table.
/// * `entries` — Slice of poll entries (modified in place).
///
/// # Returns
///
/// The number of pidfds with non-zero `revents`.
pub fn do_pidfd_poll(table: &PidfdTable, entries: &mut [PidfdPollEntry]) -> usize {
    let mut ready = 0usize;

    for pe in entries.iter_mut() {
        let interested_events = pe.events & (POLLIN | POLLHUP | POLLERR);

        match table.get(pe.fd) {
            None => {
                // Unknown fd — report error if caller asked for it.
                if interested_events & POLLERR != 0 {
                    pe.revents = POLLERR;
                    ready += 1;
                }
            }
            Some(entry) => {
                let exit_ready = entry.poll();
                let mut revents = 0u32;

                if exit_ready && interested_events & (POLLIN | POLLHUP) != 0 {
                    revents |= POLLIN | POLLHUP;
                }

                pe.revents = revents;
                if revents != 0 {
                    ready += 1;
                }
            }
        }
    }

    ready
}

// ---------------------------------------------------------------------------
// do_pidfd_waitid
// ---------------------------------------------------------------------------

/// Wait for a process referred to by `pidfd` to change state.
///
/// Implements the `waitid(P_PIDFD, pidfd, ...)` variant.  Returns the
/// current status of the child without racing on PID reuse.
///
/// # Arguments
///
/// * `table`      — Pidfd table.
/// * `pidfd`      — File descriptor referring to the child.
/// * `flags`      — Combination of `WNOHANG`, `WNOWAIT`, `WEXITED`, etc.
/// * `caller_uid` — UID of the calling process.
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — Unknown flags or `flags == 0`.
/// * [`Error::NotFound`]         — `pidfd` not in table.
/// * [`Error::PermissionDenied`] — Caller does not own the child.
/// * [`Error::WouldBlock`]       — `WNOHANG` set and child not yet exited.
pub fn do_pidfd_waitid(
    table: &PidfdTable,
    pidfd: u32,
    flags: u32,
    caller_uid: u32,
) -> Result<WaitidResult> {
    if flags & !WAITID_FLAGS_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }
    // At least one wait condition must be specified.
    if flags & (WEXITED | WSTOPPED | WCONTINUED) == 0 {
        return Err(Error::InvalidArgument);
    }

    let entry = table.get(pidfd).ok_or(Error::NotFound)?;

    if caller_uid != 0 && entry.uid != caller_uid {
        return Err(Error::PermissionDenied);
    }

    let exited = entry.state.has_exited();

    if !exited {
        if flags & WNOHANG != 0 {
            return Ok(WaitidResult::NotReady);
        }
        // In a real kernel we would block here.  In this stub we return
        // WouldBlock so the caller can retry.
        return Err(Error::WouldBlock);
    }

    let status = entry.exit_code;
    let pid = entry.pid;

    if flags & WNOWAIT != 0 {
        // Peek: return info without consuming the zombie.
        Ok(WaitidResult::Peek { pid, status })
    } else {
        Ok(WaitidResult::Exited { pid, status })
    }
}

// ---------------------------------------------------------------------------
// do_pidfd_getfd_batch
// ---------------------------------------------------------------------------

/// Duplicate multiple file descriptors from a process in a single call.
///
/// Validates the pidfd and permission, then derives synthetic new-fd values
/// for each entry in `args.src_fds[..args.count]`.
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — `args.flags != 0`, `args.count == 0`, or
///                                 `args.count > PIDFD_GETFD_BATCH_MAX`.
/// * [`Error::NotFound`]         — `pidfd` not in table or process is dead.
/// * [`Error::PermissionDenied`] — Caller does not own the target process.
pub fn do_pidfd_getfd_batch(
    table: &PidfdTable,
    args: &mut PidfdGetfdBatchArgs,
    caller_uid: u32,
) -> Result<usize> {
    if args.flags != 0 {
        return Err(Error::InvalidArgument);
    }
    if args.count == 0 || args.count > PIDFD_GETFD_BATCH_MAX {
        return Err(Error::InvalidArgument);
    }

    let entry = table.get(args.pidfd).ok_or(Error::NotFound)?;

    if entry.state == ProcessState::Dead {
        return Err(Error::NotFound);
    }

    if caller_uid != 0 && entry.uid != caller_uid {
        return Err(Error::PermissionDenied);
    }

    let pidfd = args.pidfd;
    for i in 0..args.count {
        let src = args.src_fds[i];
        // Derive a stable synthetic fd — same formula as do_pidfd_getfd.
        args.dst_fds[i] = src.wrapping_add(pidfd).wrapping_add(0x200);
    }

    Ok(args.count)
}

// ---------------------------------------------------------------------------
// Convenience wrappers — raw syscall dispatch entries
// ---------------------------------------------------------------------------

/// Dispatch entry for extended pidfd info query.
pub fn sys_pidfd_query_info(
    table: &PidfdTable,
    pidfd: u32,
    caller_uid: u32,
) -> Result<PidfdExtInfo> {
    do_pidfd_query_info(table, pidfd, caller_uid)
}

/// Dispatch entry for pidfd poll.
pub fn sys_pidfd_poll(table: &PidfdTable, entries: &mut [PidfdPollEntry]) -> usize {
    do_pidfd_poll(table, entries)
}

/// Dispatch entry for pidfd-based waitid.
pub fn sys_pidfd_waitid(
    table: &PidfdTable,
    pidfd: u32,
    flags: u32,
    caller_uid: u32,
) -> Result<WaitidResult> {
    do_pidfd_waitid(table, pidfd, flags, caller_uid)
}

/// Dispatch entry for batch pidfd getfd.
pub fn sys_pidfd_getfd_batch(
    table: &PidfdTable,
    args: &mut PidfdGetfdBatchArgs,
    caller_uid: u32,
) -> Result<usize> {
    do_pidfd_getfd_batch(table, args, caller_uid)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pidfd_calls::{
        PIDFD_NONBLOCK, PidfdEntry, ProcEntry, ProcRegistry, SIGRTMAX, do_pidfd_open, signal_valid,
    };

    fn make_table_and_fd() -> (PidfdTable, ProcRegistry, u32) {
        let mut table = PidfdTable::new();
        let mut procs = ProcRegistry::new();
        procs
            .register(ProcEntry::new(1000, 1000, 500, 500))
            .unwrap();
        let fd = do_pidfd_open(&mut table, &procs, 1000, 0, 500).unwrap();
        (table, procs, fd)
    }

    // --- do_pidfd_query_info ---

    #[test]
    fn query_info_success() {
        let (table, _procs, fd) = make_table_and_fd();
        let info = do_pidfd_query_info(&table, fd, 500).unwrap();
        assert_eq!(info.core.pid, 1000);
        assert_eq!(info.core.ruid, 500);
        assert!(!info.core.exited);
        assert_eq!(info.thread_count, 1);
        assert_eq!(info.open_fds, 3);
    }

    #[test]
    fn query_info_not_found() {
        let (table, _procs, _fd) = make_table_and_fd();
        assert_eq!(do_pidfd_query_info(&table, 9999, 500), Err(Error::NotFound));
    }

    #[test]
    fn query_info_permission_denied() {
        let (table, _procs, fd) = make_table_and_fd();
        assert_eq!(
            do_pidfd_query_info(&table, fd, 999),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn query_info_root_can_query_any() {
        let (table, _procs, fd) = make_table_and_fd();
        assert!(do_pidfd_query_info(&table, fd, 0).is_ok());
    }

    // --- do_pidfd_poll ---

    #[test]
    fn poll_alive_no_revents() {
        let (table, _procs, fd) = make_table_and_fd();
        let mut entries = [PidfdPollEntry {
            fd,
            events: POLLIN | POLLHUP,
            revents: 0,
        }];
        let ready = do_pidfd_poll(&table, &mut entries);
        assert_eq!(ready, 0);
        assert_eq!(entries[0].revents, 0);
    }

    #[test]
    fn poll_exited_process_returns_pollin_pollhup() {
        let (mut table, _procs, fd) = make_table_and_fd();
        table.notify_exit(1000, 42);
        let mut entries = [PidfdPollEntry {
            fd,
            events: POLLIN | POLLHUP,
            revents: 0,
        }];
        let ready = do_pidfd_poll(&table, &mut entries);
        assert_eq!(ready, 1);
        assert_eq!(entries[0].revents, POLLIN | POLLHUP);
    }

    #[test]
    fn poll_unknown_fd_sets_pollerr() {
        let (table, _procs, _fd) = make_table_and_fd();
        let mut entries = [PidfdPollEntry {
            fd: 9999,
            events: POLLERR,
            revents: 0,
        }];
        let ready = do_pidfd_poll(&table, &mut entries);
        assert_eq!(ready, 1);
        assert_eq!(entries[0].revents, POLLERR);
    }

    #[test]
    fn poll_multiple_entries() {
        let (mut table, mut procs, fd1) = make_table_and_fd();
        procs
            .register(ProcEntry::new(2000, 2000, 500, 500))
            .unwrap();
        let fd2 = do_pidfd_open(&mut table, &procs, 2000, 0, 500).unwrap();
        // Only pid 1000 exits.
        table.notify_exit(1000, 0);
        let mut entries = [
            PidfdPollEntry {
                fd: fd1,
                events: POLLIN,
                revents: 0,
            },
            PidfdPollEntry {
                fd: fd2,
                events: POLLIN,
                revents: 0,
            },
        ];
        let ready = do_pidfd_poll(&table, &mut entries);
        assert_eq!(ready, 1);
        assert_eq!(entries[0].revents, POLLIN | POLLHUP);
        assert_eq!(entries[1].revents, 0);
    }

    // --- do_pidfd_waitid ---

    #[test]
    fn waitid_wnohang_alive_returns_not_ready() {
        let (table, _procs, fd) = make_table_and_fd();
        assert_eq!(
            do_pidfd_waitid(&table, fd, WNOHANG | WEXITED, 500),
            Ok(WaitidResult::NotReady)
        );
    }

    #[test]
    fn waitid_blocking_alive_returns_wouldblock() {
        let (table, _procs, fd) = make_table_and_fd();
        assert_eq!(
            do_pidfd_waitid(&table, fd, WEXITED, 500),
            Err(Error::WouldBlock)
        );
    }

    #[test]
    fn waitid_exited_returns_status() {
        let (mut table, _procs, fd) = make_table_and_fd();
        table.notify_exit(1000, 7);
        let result = do_pidfd_waitid(&table, fd, WEXITED, 500).unwrap();
        assert_eq!(
            result,
            WaitidResult::Exited {
                pid: 1000,
                status: 7
            }
        );
    }

    #[test]
    fn waitid_wnowait_returns_peek() {
        let (mut table, _procs, fd) = make_table_and_fd();
        table.notify_exit(1000, 3);
        let result = do_pidfd_waitid(&table, fd, WEXITED | WNOWAIT, 500).unwrap();
        assert_eq!(
            result,
            WaitidResult::Peek {
                pid: 1000,
                status: 3
            }
        );
    }

    #[test]
    fn waitid_zero_conditions_rejected() {
        let (table, _procs, fd) = make_table_and_fd();
        assert_eq!(
            do_pidfd_waitid(&table, fd, WNOHANG, 500),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn waitid_unknown_flags_rejected() {
        let (table, _procs, fd) = make_table_and_fd();
        assert_eq!(
            do_pidfd_waitid(&table, fd, 0xDEAD_BEEF, 500),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn waitid_permission_denied() {
        let (table, _procs, fd) = make_table_and_fd();
        assert_eq!(
            do_pidfd_waitid(&table, fd, WEXITED | WNOHANG, 999),
            Err(Error::PermissionDenied)
        );
    }

    // --- do_pidfd_getfd_batch ---

    #[test]
    fn getfd_batch_success() {
        let (table, _procs, fd) = make_table_and_fd();
        let mut args = PidfdGetfdBatchArgs {
            pidfd: fd,
            src_fds: {
                let mut a = [0u32; PIDFD_GETFD_BATCH_MAX];
                a[0] = 1;
                a[1] = 2;
                a
            },
            dst_fds: [0u32; PIDFD_GETFD_BATCH_MAX],
            count: 2,
            flags: 0,
        };
        let n = do_pidfd_getfd_batch(&table, &mut args, 500).unwrap();
        assert_eq!(n, 2);
        // dst_fds must be non-zero (derived from src + pidfd).
        assert!(args.dst_fds[0] > 0);
        assert!(args.dst_fds[1] > 0);
        assert_ne!(args.dst_fds[0], args.dst_fds[1]);
    }

    #[test]
    fn getfd_batch_zero_count_rejected() {
        let (table, _procs, fd) = make_table_and_fd();
        let mut args = PidfdGetfdBatchArgs {
            pidfd: fd,
            count: 0,
            ..Default::default()
        };
        assert_eq!(
            do_pidfd_getfd_batch(&table, &mut args, 500),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn getfd_batch_too_large_rejected() {
        let (table, _procs, fd) = make_table_and_fd();
        let mut args = PidfdGetfdBatchArgs {
            pidfd: fd,
            count: PIDFD_GETFD_BATCH_MAX + 1,
            ..Default::default()
        };
        assert_eq!(
            do_pidfd_getfd_batch(&table, &mut args, 500),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn getfd_batch_nonzero_flags_rejected() {
        let (table, _procs, fd) = make_table_and_fd();
        let mut args = PidfdGetfdBatchArgs {
            pidfd: fd,
            count: 1,
            flags: 1,
            ..Default::default()
        };
        assert_eq!(
            do_pidfd_getfd_batch(&table, &mut args, 500),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn getfd_batch_permission_denied() {
        let (table, _procs, fd) = make_table_and_fd();
        let mut args = PidfdGetfdBatchArgs {
            pidfd: fd,
            count: 1,
            flags: 0,
            ..Default::default()
        };
        assert_eq!(
            do_pidfd_getfd_batch(&table, &mut args, 999),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn getfd_batch_dead_process_fails() {
        let (mut table, _procs, fd) = make_table_and_fd();
        table.notify_exit(1000, 0);
        table.get_mut(fd).unwrap().mark_dead();
        let mut args = PidfdGetfdBatchArgs {
            pidfd: fd,
            count: 1,
            flags: 0,
            ..Default::default()
        };
        assert_eq!(
            do_pidfd_getfd_batch(&table, &mut args, 500),
            Err(Error::NotFound)
        );
    }

    // --- signal_valid re-export smoke test ---

    #[test]
    fn signal_valid_smoke() {
        assert!(signal_valid(0));
        assert!(signal_valid(SIGRTMAX));
        assert!(!signal_valid(65));
    }

    // --- PIDFD_NONBLOCK re-export ---
    #[test]
    fn pidfd_nonblock_const_accessible() {
        // Ensures the re-exported constant is reachable.
        assert_ne!(PIDFD_NONBLOCK, 0);
    }
}
