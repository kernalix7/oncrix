// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! signalfd file descriptor.
//!
//! Implements the signalfd(2) interface, which allows a process to receive
//! signals via a file descriptor. Signals in the mask are diverted from
//! the normal signal delivery path to a queue readable via read().

use oncrix_lib::{Error, Result};

/// signalfd creation flags.
pub const SFD_NONBLOCK: u32 = 0x0004;
pub const SFD_CLOEXEC: u32 = 0x0002;

/// Maximum number of pending signals in the queue.
pub const SIGNALFD_QUEUE_MAX: usize = 32;

/// signalfd_siginfo as returned by read().
///
/// Mirrors the Linux `signalfd_siginfo` structure.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SignalfdSiginfo {
    /// Signal number.
    pub ssi_signo: u32,
    /// Error number (for some signals).
    pub ssi_errno: i32,
    /// Signal code (SI_* values).
    pub ssi_code: i32,
    /// Sending PID.
    pub ssi_pid: u32,
    /// Sending UID.
    pub ssi_uid: u32,
    /// File descriptor (for SIGIO).
    pub ssi_fd: i32,
    /// Timer ID (SIGALRM etc.).
    pub ssi_tid: u32,
    /// Band event (SIGIO).
    pub ssi_band: u32,
    /// Timer overrun count.
    pub ssi_overrun: u32,
    /// Trap number.
    pub ssi_trapno: u32,
    /// Exit status or signal.
    pub ssi_status: i32,
    /// Integer signal value.
    pub ssi_int: i32,
    /// Pointer signal value.
    pub ssi_ptr: u64,
    /// User CPU time consumed.
    pub ssi_utime: u64,
    /// System CPU time consumed.
    pub ssi_stime: u64,
    /// Address that caused fault.
    pub ssi_addr: u64,
    /// Flags for SIGSYS.
    pub ssi_addr_lsb: u16,
    /// Padding.
    pub _pad: [u8; 46],
}

impl Default for SignalfdSiginfo {
    fn default() -> Self {
        Self {
            ssi_signo: 0,
            ssi_errno: 0,
            ssi_code: 0,
            ssi_pid: 0,
            ssi_uid: 0,
            ssi_fd: 0,
            ssi_tid: 0,
            ssi_band: 0,
            ssi_overrun: 0,
            ssi_trapno: 0,
            ssi_status: 0,
            ssi_int: 0,
            ssi_ptr: 0,
            ssi_utime: 0,
            ssi_stime: 0,
            ssi_addr: 0,
            ssi_addr_lsb: 0,
            _pad: [0u8; 46],
        }
    }
}

/// Size of signalfd_siginfo.
pub const SIGNALFD_SIGINFO_SIZE: usize = core::mem::size_of::<SignalfdSiginfo>();

/// A 64-bit signal mask (POSIX sigset_t representation).
#[derive(Debug, Clone, Copy, Default)]
pub struct SigSet(pub u64);

impl SigSet {
    /// Create an empty signal set.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Create a full signal set.
    pub const fn full() -> Self {
        Self(u64::MAX)
    }

    /// Add signal `signo` (1-based) to the set.
    pub fn add(&mut self, signo: u32) -> Result<()> {
        if signo == 0 || signo > 64 {
            return Err(Error::InvalidArgument);
        }
        self.0 |= 1u64 << (signo - 1);
        Ok(())
    }

    /// Remove signal `signo` from the set.
    pub fn remove(&mut self, signo: u32) -> Result<()> {
        if signo == 0 || signo > 64 {
            return Err(Error::InvalidArgument);
        }
        self.0 &= !(1u64 << (signo - 1));
        Ok(())
    }

    /// Test whether signal `signo` is in the set.
    pub fn has(&self, signo: u32) -> bool {
        if signo == 0 || signo > 64 {
            return false;
        }
        self.0 & (1u64 << (signo - 1)) != 0
    }

    /// Return the raw mask value.
    pub fn raw(&self) -> u64 {
        self.0
    }
}

/// signalfd object.
#[derive(Debug)]
pub struct SignalFd {
    /// Signal mask — signals in this set are delivered to the fd.
    pub mask: SigSet,
    /// Creation flags.
    pub flags: u32,
    /// Queued signal infos.
    queue: [Option<SignalfdSiginfo>; SIGNALFD_QUEUE_MAX],
    /// Number of enqueued signals.
    pub queue_len: usize,
}

impl SignalFd {
    /// Create a new signalfd with the given mask.
    pub const fn new(mask: SigSet, flags: u32) -> Self {
        Self {
            mask,
            flags,
            queue: [const { None }; SIGNALFD_QUEUE_MAX],
            queue_len: 0,
        }
    }

    /// Return true if non-blocking mode is set.
    pub fn is_nonblock(&self) -> bool {
        self.flags & SFD_NONBLOCK != 0
    }

    /// Update the signal mask (signalfd4 SFD_* semantics).
    pub fn set_mask(&mut self, mask: SigSet) {
        self.mask = mask;
    }

    /// Deliver a signal to this signalfd.
    ///
    /// The signal is accepted only if it is in the mask and the queue is not full.
    pub fn deliver(&mut self, info: SignalfdSiginfo) -> Result<()> {
        if !self.mask.has(info.ssi_signo) {
            return Err(Error::InvalidArgument);
        }
        if self.queue_len >= SIGNALFD_QUEUE_MAX {
            // Queue full: drop oldest (overrun).
            for i in 0..self.queue_len - 1 {
                self.queue[i] = self.queue[i + 1];
            }
            self.queue[self.queue_len - 1] = Some(info);
        } else {
            self.queue[self.queue_len] = Some(info);
            self.queue_len += 1;
        }
        Ok(())
    }

    /// Read one signalfd_siginfo from the queue into `buf`.
    ///
    /// Returns the number of bytes written (SIGNALFD_SIGINFO_SIZE).
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < SIGNALFD_SIGINFO_SIZE {
            return Err(Error::InvalidArgument);
        }
        if self.queue_len == 0 {
            if self.is_nonblock() {
                return Err(Error::WouldBlock);
            }
            return Err(Error::WouldBlock);
        }

        let info = self.queue[0].take().unwrap_or_default();
        // Shift queue.
        for i in 0..self.queue_len - 1 {
            self.queue[i] = self.queue[i + 1];
        }
        self.queue[self.queue_len - 1] = None;
        self.queue_len -= 1;

        // Serialize into buf.
        // SAFETY: SignalfdSiginfo is #[repr(C)] and buf is large enough.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &info as *const SignalfdSiginfo as *const u8,
                SIGNALFD_SIGINFO_SIZE,
            )
        };
        buf[..SIGNALFD_SIGINFO_SIZE].copy_from_slice(bytes);
        Ok(SIGNALFD_SIGINFO_SIZE)
    }

    /// Poll readiness: returns true if a read would not block.
    pub fn poll_readable(&self) -> bool {
        self.queue_len > 0
    }

    /// Flush all queued signals.
    pub fn flush(&mut self) {
        for slot in &mut self.queue {
            *slot = None;
        }
        self.queue_len = 0;
    }
}

/// signalfd file with an fd number.
#[derive(Debug)]
pub struct SignalFdFile {
    /// The signalfd state.
    pub sfd: SignalFd,
    /// File descriptor number.
    pub fd: i32,
}

impl SignalFdFile {
    /// Create a new signalfd file.
    pub const fn new(fd: i32, mask: SigSet, flags: u32) -> Self {
        Self {
            sfd: SignalFd::new(mask, flags),
            fd,
        }
    }

    /// Deliver a signal.
    pub fn deliver(&mut self, info: SignalfdSiginfo) -> Result<()> {
        self.sfd.deliver(info)
    }

    /// Read one signal info.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.sfd.read(buf)
    }
}
