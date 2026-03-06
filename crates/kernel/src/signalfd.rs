// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! signalfd signal notification subsystem.
//!
//! Provides a file-descriptor-based interface for receiving signals,
//! compatible with the Linux `signalfd` API. A [`SignalFd`] accepts
//! a signal mask and allows user space to read signal information
//! as structured [`SignalFdInfo`] records instead of using
//! traditional asynchronous signal handlers.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │             SignalFdRegistry                 │
//! │  (up to MAX_SIGNALFDS signalfd instances)    │
//! │  ┌────────┐ ┌────────┐       ┌────────┐    │
//! │  │ sfd 0  │ │ sfd 1  │  ...  │ sfd N  │    │
//! │  └────────┘ └────────┘       └────────┘    │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! # POSIX Reference
//!
//! While signalfd is a Linux extension (not POSIX), ONCRIX
//! provides it for compatibility with event-loop frameworks
//! that prefer synchronous signal consumption (systemd,
//! libuv, etc.).

use oncrix_lib::{Error, Result};

// ── Flags ──────────────────────────────────────────────────────

/// Non-blocking mode: `read` returns `WouldBlock` if no signal
/// is pending instead of blocking.
pub const SFD_NONBLOCK: u32 = 0x800;

/// Close-on-exec flag: the file descriptor is automatically
/// closed across `execve`.
pub const SFD_CLOEXEC: u32 = 0x80000;

/// Bitmask of all valid signalfd flags.
const SFD_VALID_FLAGS: u32 = SFD_NONBLOCK | SFD_CLOEXEC;

// ── SignalFdInfo ───────────────────────────────────────────────

/// Signal information record read from a signalfd.
///
/// This structure is returned by reading from a signalfd file
/// descriptor. It mirrors the Linux `struct signalfd_siginfo`
/// layout (128 bytes, naturally padded).
///
/// Only the most commonly used fields are exposed; the rest
/// are reserved padding for future extensions.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SignalFdInfo {
    /// Signal number (e.g., `SIGTERM` = 15).
    pub ssi_signo: u32,
    /// Error number associated with the signal (usually 0).
    pub ssi_errno: i32,
    /// Signal code (e.g., `SI_USER`, `SI_KERNEL`).
    pub ssi_code: i32,
    /// PID of the sending process.
    pub ssi_pid: u32,
    /// Real UID of the sending process.
    pub ssi_uid: u32,
    /// File descriptor (for `SIGIO`).
    pub ssi_fd: i32,
    /// Exit status or signal (for `SIGCHLD`).
    pub ssi_status: i32,
    /// Padding to reach the full 128-byte structure size.
    ///
    /// Reserved for future fields (`ssi_overrun`, `ssi_tid`,
    /// `ssi_addr`, etc.).
    pub _pad: [u8; 96],
}

impl SignalFdInfo {
    /// Size of the structure in bytes (128).
    pub const SIZE: usize = 128;

    /// Create a zeroed info structure.
    pub const fn zeroed() -> Self {
        Self {
            ssi_signo: 0,
            ssi_errno: 0,
            ssi_code: 0,
            ssi_pid: 0,
            ssi_uid: 0,
            ssi_fd: 0,
            ssi_status: 0,
            _pad: [0u8; 96],
        }
    }
}

// ── SignalFd ───────────────────────────────────────────────────

/// A signalfd instance that converts pending signals into
/// readable [`SignalFdInfo`] records.
///
/// Created via [`SignalFd::new`] with a signal mask and flags.
/// The mask can be updated later with [`update_mask`].
///
/// [`update_mask`]: SignalFd::update_mask
pub struct SignalFd {
    /// Bitmask of signals this signalfd accepts.
    ///
    /// Bit N corresponds to signal number N+1 (bit 0 = signal 1,
    /// bit 14 = signal 15 = `SIGTERM`, etc.).
    mask: u64,
    /// Creation flags (combination of `SFD_*` constants).
    flags: u32,
    /// Whether this slot is in use.
    in_use: bool,
}

impl SignalFd {
    /// Create a new signalfd with the given mask and flags.
    pub const fn new(mask: u64, flags: u32) -> Self {
        Self {
            mask,
            flags,
            in_use: false,
        }
    }

    /// Return the current signal mask.
    pub const fn mask(&self) -> u64 {
        self.mask
    }

    /// Return the current flags.
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Whether this signalfd is in non-blocking mode.
    pub const fn is_nonblock(&self) -> bool {
        self.flags & SFD_NONBLOCK != 0
    }

    /// Update the signal mask.
    ///
    /// Replaces the current mask with `new_mask`. Signals not
    /// in the new mask will no longer be delivered via this fd.
    pub fn update_mask(&mut self, new_mask: u64) {
        self.mask = new_mask;
    }

    /// Check whether a given signal number is in the mask.
    ///
    /// Signal numbers are 1-based; bit 0 of the mask corresponds
    /// to signal 1. Returns `false` for signal 0 or signals
    /// beyond bit 63.
    pub const fn accepts_signal(&self, signo: u32) -> bool {
        if signo == 0 || signo > 64 {
            return false;
        }
        let bit = signo - 1;
        self.mask & (1u64 << bit) != 0
    }

    /// Construct a [`SignalFdInfo`] from a delivered signal number.
    ///
    /// Populates `ssi_signo` and `ssi_code` with default values.
    /// In a full implementation, additional fields (`ssi_pid`,
    /// `ssi_uid`, etc.) would be filled from the kernel's
    /// pending-signal queue.
    pub const fn read_signal(&self, signo: u32) -> SignalFdInfo {
        SignalFdInfo {
            ssi_signo: signo,
            ssi_errno: 0,
            // SI_USER = 0: sent by kill(2) or similar.
            ssi_code: 0,
            ssi_pid: 0,
            ssi_uid: 0,
            ssi_fd: -1,
            ssi_status: 0,
            _pad: [0u8; 96],
        }
    }
}

// ── SignalFdRegistry ───────────────────────────────────────────

/// Maximum number of concurrent signalfd instances system-wide.
const MAX_SIGNALFDS: usize = 32;

/// Global registry of signalfd instances.
///
/// Manages the creation, lookup, and destruction of [`SignalFd`]
/// objects. Each instance is identified by a numeric ID returned
/// by [`create`](SignalFdRegistry::create).
pub struct SignalFdRegistry {
    /// Fixed array of signalfd slots.
    fds: [SignalFd; MAX_SIGNALFDS],
}

impl Default for SignalFdRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SignalFdRegistry {
    /// Create an empty registry with no active signalfds.
    pub const fn new() -> Self {
        Self {
            fds: [const { SignalFd::new(0, 0) }; MAX_SIGNALFDS],
        }
    }

    /// Allocate a new signalfd instance.
    ///
    /// Returns the instance ID on success, or `Err(OutOfMemory)`
    /// if all slots are occupied. Returns `Err(InvalidArgument)`
    /// if `flags` contains unknown bits.
    pub fn create(&mut self, mask: u64, flags: u32) -> Result<usize> {
        if flags & !SFD_VALID_FLAGS != 0 {
            return Err(Error::InvalidArgument);
        }
        for (id, sfd) in self.fds.iter_mut().enumerate() {
            if !sfd.in_use {
                *sfd = SignalFd::new(mask, flags);
                sfd.in_use = true;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Get a shared reference to a signalfd by ID.
    ///
    /// Returns `Err(InvalidArgument)` if the ID is out of range,
    /// or `Err(NotFound)` if the slot is not in use.
    pub fn get(&self, id: usize) -> Result<&SignalFd> {
        let sfd = self.fds.get(id).ok_or(Error::InvalidArgument)?;
        if !sfd.in_use {
            return Err(Error::NotFound);
        }
        Ok(sfd)
    }

    /// Get a mutable reference to a signalfd by ID.
    ///
    /// Returns `Err(InvalidArgument)` if the ID is out of range,
    /// or `Err(NotFound)` if the slot is not in use.
    pub fn get_mut(&mut self, id: usize) -> Result<&mut SignalFd> {
        let sfd = self.fds.get_mut(id).ok_or(Error::InvalidArgument)?;
        if !sfd.in_use {
            return Err(Error::NotFound);
        }
        Ok(sfd)
    }

    /// Destroy a signalfd instance, freeing its slot.
    ///
    /// Returns `Err(InvalidArgument)` if the ID is out of range,
    /// or `Err(NotFound)` if the slot is not in use.
    pub fn close(&mut self, id: usize) -> Result<()> {
        let sfd = self.fds.get_mut(id).ok_or(Error::InvalidArgument)?;
        if !sfd.in_use {
            return Err(Error::NotFound);
        }
        *sfd = SignalFd::new(0, 0);
        Ok(())
    }
}
