// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! signalfd file implementation.
//!
//! Implements the signalfd(2) interface:
//! - [`Signalfd`] — kernel object (sigmask, flags)
//! - [`signalfd_create`] — allocate a signalfd with a signal mask
//! - [`signalfd_read`] — dequeue the next pending signal, return
//!   [`SignalfdSiginfo`]
//! - Poll support: report readability when a masked signal is pending
//! - `SFD_NONBLOCK`: return `Err(WouldBlock)` when no signals are pending
//! - `SFD_CLOEXEC`: close-on-exec flag
//!
//! # Signal Mask
//!
//! `sigmask` is a 64-bit bitmask where bit `n` corresponds to signal `n+1`.
//! Only signals set in the mask are consumed by `signalfd_read`.
//!
//! # References
//! - Linux `fs/signalfd.c`
//! - POSIX.1-2024 signalfd(2)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// SFD flags
// ---------------------------------------------------------------------------

/// Non-blocking mode.
pub const SFD_NONBLOCK: u32 = 1 << 11;
/// Close-on-exec.
pub const SFD_CLOEXEC: u32 = 1 << 19;

/// Maximum signalfd objects.
const MAX_SIGNALFDS: usize = 128;

/// Maximum queued signals per signalfd.
const MAX_QUEUED_SIGNALS: usize = 64;

// ---------------------------------------------------------------------------
// Signal numbers (subset)
// ---------------------------------------------------------------------------

pub const SIGHUP: u32 = 1;
pub const SIGINT: u32 = 2;
pub const SIGQUIT: u32 = 3;
pub const SIGILL: u32 = 4;
pub const SIGTRAP: u32 = 5;
pub const SIGABRT: u32 = 6;
pub const SIGKILL: u32 = 9;
pub const SIGSEGV: u32 = 11;
pub const SIGTERM: u32 = 15;
pub const SIGUSR1: u32 = 10;
pub const SIGUSR2: u32 = 12;
pub const SIGCHLD: u32 = 17;

// ---------------------------------------------------------------------------
// SignalfdSiginfo
// ---------------------------------------------------------------------------

/// The siginfo structure returned by `signalfd_read`.
///
/// Matches `struct signalfd_siginfo` from `<sys/signalfd.h>`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SignalfdSiginfo {
    /// Signal number.
    pub ssi_signo: u32,
    /// Error number (si_errno).
    pub ssi_errno: i32,
    /// Signal code (si_code).
    pub ssi_code: i32,
    /// PID of sending process.
    pub ssi_pid: u32,
    /// UID of sending process.
    pub ssi_uid: u32,
    /// File descriptor (for SIGIO).
    pub ssi_fd: i32,
    /// Timer ID (for POSIX timers).
    pub ssi_tid: u32,
    /// Band event (for SIGIO).
    pub ssi_band: u32,
    /// POSIX timer overrun count.
    pub ssi_overrun: u32,
    /// Trap number (SIGTRAP).
    pub ssi_trapno: u32,
    /// Exit status or signal (SIGCHLD).
    pub ssi_status: i32,
    /// Integer sent by sigqueue.
    pub ssi_int: i32,
    /// Pointer sent by sigqueue.
    pub ssi_ptr: u64,
    /// User time consumed (SIGCHLD).
    pub ssi_utime: u64,
    /// System time consumed (SIGCHLD).
    pub ssi_stime: u64,
    /// Address that caused fault (SIGILL/SIGSEGV/SIGFPE/SIGBUS).
    pub ssi_addr: u64,
    /// Address bound to POSIX.1b timer via timer_settime.
    pub ssi_addr_lsb: u16,
    /// Padding.
    pub _pad: u16,
}

impl SignalfdSiginfo {
    /// Build a minimal siginfo for the given signal number.
    pub fn from_signo(signo: u32) -> Self {
        Self {
            ssi_signo: signo,
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Signalfd
// ---------------------------------------------------------------------------

/// Kernel object backing a signalfd file descriptor.
pub struct Signalfd {
    /// Signal mask: bit `n` set means signal `n+1` is monitored.
    pub sigmask: u64,
    /// Creation flags.
    pub flags: u32,
    /// Unique identifier.
    pub id: u32,
    /// Queued signals waiting to be read.
    queue: [Option<SignalfdSiginfo>; MAX_QUEUED_SIGNALS],
    queue_count: usize,
}

impl Signalfd {
    /// Return true if non-blocking mode is set.
    pub fn is_nonblock(&self) -> bool {
        self.flags & SFD_NONBLOCK != 0
    }

    /// Return true if `signo` is in this fd's mask.
    pub fn masks_signal(&self, signo: u32) -> bool {
        if signo == 0 || signo > 64 {
            return false;
        }
        self.sigmask & (1u64 << (signo - 1)) != 0
    }

    /// Queue a signal for delivery if it is in the mask.
    fn enqueue(&mut self, info: SignalfdSiginfo) -> bool {
        if !self.masks_signal(info.ssi_signo) {
            return false;
        }
        if self.queue_count >= MAX_QUEUED_SIGNALS {
            return false; // Signal dropped.
        }
        self.queue[self.queue_count] = Some(info);
        self.queue_count += 1;
        true
    }

    /// Dequeue the oldest signal. Returns None if queue is empty.
    fn dequeue(&mut self) -> Option<SignalfdSiginfo> {
        if self.queue_count == 0 {
            return None;
        }
        let info = self.queue[0].take();
        // Shift queue left.
        for i in 0..self.queue_count - 1 {
            self.queue.swap(i, i + 1);
        }
        self.queue[self.queue_count - 1] = None;
        self.queue_count -= 1;
        info
    }

    /// Return true if any signals are pending.
    pub fn has_pending(&self) -> bool {
        self.queue_count > 0
    }
}

// ---------------------------------------------------------------------------
// SignalfdTable
// ---------------------------------------------------------------------------

/// Registry of signalfd objects.
pub struct SignalfdTable {
    fds: [Option<Signalfd>; MAX_SIGNALFDS],
    count: usize,
    next_id: u32,
}

impl SignalfdTable {
    /// Create an empty table.
    pub fn new() -> Self {
        Self {
            fds: core::array::from_fn(|_| None),
            count: 0,
            next_id: 1,
        }
    }

    fn find(&self, id: u32) -> Option<usize> {
        for (i, slot) in self.fds[..self.count].iter().enumerate() {
            if let Some(fd) = slot {
                if fd.id == id {
                    return Some(i);
                }
            }
        }
        None
    }
}

impl Default for SignalfdTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// signalfd_create
// ---------------------------------------------------------------------------

/// Create a new signalfd monitoring `sigmask`.
///
/// Returns the signalfd id. Returns `Err(OutOfMemory)` if the table is full.
pub fn signalfd_create(table: &mut SignalfdTable, sigmask: u64, flags: u32) -> Result<u32> {
    if table.count >= MAX_SIGNALFDS {
        return Err(Error::OutOfMemory);
    }
    let id = table.next_id;
    table.next_id += 1;
    table.fds[table.count] = Some(Signalfd {
        sigmask,
        flags,
        id,
        queue: core::array::from_fn(|_| None),
        queue_count: 0,
    });
    table.count += 1;
    Ok(id)
}

// ---------------------------------------------------------------------------
// signalfd_deliver
// ---------------------------------------------------------------------------

/// Deliver a signal to all signalfds that monitor it.
///
/// Called when the kernel sends a signal to a process. Each signalfd whose
/// mask includes `signo` receives the signal in its queue.
pub fn signalfd_deliver(table: &mut SignalfdTable, info: SignalfdSiginfo) {
    for slot in table.fds[..table.count].iter_mut().flatten() {
        slot.enqueue(info);
    }
}

// ---------------------------------------------------------------------------
// signalfd_read
// ---------------------------------------------------------------------------

/// Read the next pending signal from a signalfd.
///
/// Returns `Err(WouldBlock)` if no signals are pending and
/// `EFD_NONBLOCK` is set (or always in this simulation).
pub fn signalfd_read(table: &mut SignalfdTable, id: u32) -> Result<SignalfdSiginfo> {
    let idx = table.find(id).ok_or(Error::NotFound)?;
    let fd = table.fds[idx].as_mut().ok_or(Error::NotFound)?;
    fd.dequeue().ok_or(Error::WouldBlock)
}

// ---------------------------------------------------------------------------
// signalfd_poll
// ---------------------------------------------------------------------------

/// Check whether a signalfd is readable (has pending signals).
///
/// Returns `POLL_IN` if readable, 0 otherwise.
pub fn signalfd_poll(table: &SignalfdTable, id: u32) -> Result<u32> {
    let idx = table.find(id).ok_or(Error::NotFound)?;
    let fd = table.fds[idx].as_ref().ok_or(Error::NotFound)?;
    Ok(if fd.has_pending() {
        0x0001 /* POLL_IN */
    } else {
        0
    })
}

// ---------------------------------------------------------------------------
// signalfd_setmask
// ---------------------------------------------------------------------------

/// Update the signal mask of an existing signalfd.
pub fn signalfd_setmask(table: &mut SignalfdTable, id: u32, sigmask: u64) -> Result<()> {
    let idx = table.find(id).ok_or(Error::NotFound)?;
    if let Some(fd) = table.fds[idx].as_mut() {
        fd.sigmask = sigmask;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// signalfd_close
// ---------------------------------------------------------------------------

/// Close a signalfd.
pub fn signalfd_close(table: &mut SignalfdTable, id: u32) -> Result<()> {
    let idx = table.find(id).ok_or(Error::NotFound)?;
    if idx < table.count - 1 {
        table.fds.swap(idx, table.count - 1);
    }
    table.fds[table.count - 1] = None;
    table.count -= 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_delivery_and_read() {
        let mut table = SignalfdTable::new();
        // Monitor SIGINT (bit 1) and SIGTERM (bit 14).
        let mask = (1u64 << (SIGINT - 1)) | (1u64 << (SIGTERM - 1));
        let id = signalfd_create(&mut table, mask, SFD_NONBLOCK).unwrap();

        signalfd_deliver(&mut table, SignalfdSiginfo::from_signo(SIGINT));
        let info = signalfd_read(&mut table, id).unwrap();
        assert_eq!(info.ssi_signo, SIGINT);

        // No more pending.
        assert!(matches!(
            signalfd_read(&mut table, id),
            Err(Error::WouldBlock)
        ));
    }

    #[test]
    fn test_unmasked_signal_ignored() {
        let mut table = SignalfdTable::new();
        let mask = 1u64 << (SIGTERM - 1); // only SIGTERM
        let id = signalfd_create(&mut table, mask, SFD_NONBLOCK).unwrap();

        // Deliver SIGUSR1 — should be ignored.
        signalfd_deliver(&mut table, SignalfdSiginfo::from_signo(SIGUSR1));
        assert_eq!(signalfd_poll(&table, id).unwrap(), 0);
    }

    #[test]
    fn test_poll_readiness() {
        let mut table = SignalfdTable::new();
        let mask = 1u64 << (SIGHUP - 1);
        let id = signalfd_create(&mut table, mask, 0).unwrap();
        assert_eq!(signalfd_poll(&table, id).unwrap(), 0);
        signalfd_deliver(&mut table, SignalfdSiginfo::from_signo(SIGHUP));
        assert_ne!(signalfd_poll(&table, id).unwrap(), 0);
    }
}
