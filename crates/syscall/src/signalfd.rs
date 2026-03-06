// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `signalfd` and `timerfd` — file-descriptor-based signal and timer delivery.
//!
//! Implements Linux-compatible `signalfd` and `timerfd` interfaces that allow
//! signal and timer events to be consumed via readable file descriptors.
//! Signals are delivered as 128-byte `SignalfdSiginfo` structures; timers
//! expose an expiration counter that can be read as a `u64`.

use crate::clock::{Itimerspec, Timespec};
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of signalfd instances in the registry.
const MAX_SIGNALFDS: usize = 32;

/// Maximum number of timerfd instances in the registry.
const MAX_TIMERFDS: usize = 64;

/// Maximum pending signals per signalfd.
const MAX_PENDING: usize = 16;

// ---------------------------------------------------------------------------
// SignalfdFlags
// ---------------------------------------------------------------------------

/// Flags for `signalfd` / `signalfd4`.
pub struct SignalfdFlags;

impl SignalfdFlags {
    /// Enable non-blocking reads.
    pub const SFD_NONBLOCK: u32 = 0x800;
    /// Set close-on-exec on the descriptor.
    pub const SFD_CLOEXEC: u32 = 0x80000;
}

/// All valid signalfd flag bits.
const SFD_VALID: u32 = SignalfdFlags::SFD_NONBLOCK | SignalfdFlags::SFD_CLOEXEC;

// ---------------------------------------------------------------------------
// SignalfdSiginfo
// ---------------------------------------------------------------------------

/// Signal information structure read from a signalfd.
///
/// Each read on a signalfd returns one or more of these 128-byte structures,
/// matching the Linux `struct signalfd_siginfo` layout.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SignalfdSiginfo {
    /// Signal number.
    pub ssi_signo: u32,
    /// Error number (unused for most signals).
    pub ssi_errno: i32,
    /// Signal code.
    pub ssi_code: i32,
    /// PID of the sender.
    pub ssi_pid: u32,
    /// Real UID of the sender.
    pub ssi_uid: u32,
    /// File descriptor (for SIGIO).
    pub ssi_fd: i32,
    /// Kernel timer ID (for POSIX timers).
    pub ssi_tid: u32,
    /// Band event (for SIGPOLL).
    pub ssi_band: u32,
    /// Timer overrun count.
    pub ssi_overrun: u32,
    /// Trap number.
    pub ssi_trapno: u32,
    /// Exit status or signal (for SIGCHLD).
    pub ssi_status: i32,
    /// Padding to reach 128 bytes.
    pub _pad: [u32; 16],
}

// ---------------------------------------------------------------------------
// Signalfd
// ---------------------------------------------------------------------------

/// A single signalfd instance.
///
/// Holds a bitmask of signals to intercept and a ring of pending
/// `SignalfdSiginfo` structures that can be read by user space.
pub struct Signalfd {
    /// Unique identifier.
    id: u64,
    /// Bitmask of signals this fd is listening for.
    mask: u64,
    /// Creation flags.
    flags: u32,
    /// Ring buffer of pending signal info structures.
    pending: [SignalfdSiginfo; MAX_PENDING],
    /// Number of pending signals in the ring.
    pending_count: usize,
    /// PID of the owning process.
    owner_pid: u64,
    /// Whether this slot is in use.
    in_use: bool,
}

impl Signalfd {
    /// Create an inactive signalfd with zeroed fields.
    const fn new() -> Self {
        Self {
            id: 0,
            mask: 0,
            flags: 0,
            pending: [SignalfdSiginfo {
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
                _pad: [0; 16],
            }; MAX_PENDING],
            pending_count: 0,
            owner_pid: 0,
            in_use: false,
        }
    }

    /// Return the signalfd identifier.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Return the signal mask.
    pub const fn mask(&self) -> u64 {
        self.mask
    }

    /// Return the flags.
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Return the number of pending signals.
    pub const fn pending_count(&self) -> usize {
        self.pending_count
    }

    /// Return the owner PID.
    pub const fn owner_pid(&self) -> u64 {
        self.owner_pid
    }

    /// Return whether this slot is in use.
    pub const fn in_use(&self) -> bool {
        self.in_use
    }
}

// ---------------------------------------------------------------------------
// TimerfdClockId
// ---------------------------------------------------------------------------

/// Clock identifier for timerfd.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimerfdClockId {
    /// Wall-clock time; settable.
    Realtime = 0,
    /// Monotonic clock; not affected by system time changes.
    #[default]
    Monotonic = 1,
    /// Time since boot, including suspend.
    BootTime = 7,
}

impl TimerfdClockId {
    /// Convert a raw `u32` to a `TimerfdClockId`, if valid.
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::Realtime),
            1 => Some(Self::Monotonic),
            7 => Some(Self::BootTime),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// TimerfdFlags
// ---------------------------------------------------------------------------

/// Flags for `timerfd_create`.
pub struct TimerfdFlags;

impl TimerfdFlags {
    /// Enable non-blocking reads.
    pub const TFD_NONBLOCK: u32 = 0x800;
    /// Set close-on-exec on the descriptor.
    pub const TFD_CLOEXEC: u32 = 0x80000;
}

/// All valid timerfd flag bits.
const TFD_VALID: u32 = TimerfdFlags::TFD_NONBLOCK | TimerfdFlags::TFD_CLOEXEC;

// ---------------------------------------------------------------------------
// Timerfd
// ---------------------------------------------------------------------------

/// A single timerfd instance.
///
/// Represents a timer that fires according to an `Itimerspec` and
/// accumulates an expiration counter readable as a `u64`.
pub struct Timerfd {
    /// Unique identifier.
    id: u64,
    /// Clock source for this timer.
    clock_id: TimerfdClockId,
    /// Creation flags.
    flags: u32,
    /// Current timer interval and initial expiration.
    interval: Itimerspec,
    /// Number of expirations since last read.
    expiration_count: u64,
    /// Whether the timer is armed (actively counting).
    armed: bool,
    /// PID of the owning process.
    owner_pid: u64,
    /// Whether this slot is in use.
    in_use: bool,
    /// Remaining nanoseconds until next expiration.
    remaining_ns: u64,
}

impl Timerfd {
    /// Create an inactive timerfd with zeroed fields.
    const fn new() -> Self {
        Self {
            id: 0,
            clock_id: TimerfdClockId::Monotonic,
            flags: 0,
            interval: Itimerspec {
                it_interval: Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                it_value: Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
            },
            expiration_count: 0,
            armed: false,
            owner_pid: 0,
            in_use: false,
            remaining_ns: 0,
        }
    }

    /// Return the timerfd identifier.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Return the clock source.
    pub const fn clock_id(&self) -> TimerfdClockId {
        self.clock_id
    }

    /// Return the flags.
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Return the current timer specification.
    pub const fn interval(&self) -> &Itimerspec {
        &self.interval
    }

    /// Return the number of expirations since last read.
    pub const fn expiration_count(&self) -> u64 {
        self.expiration_count
    }

    /// Return whether the timer is armed.
    pub const fn armed(&self) -> bool {
        self.armed
    }

    /// Return the owner PID.
    pub const fn owner_pid(&self) -> u64 {
        self.owner_pid
    }

    /// Return whether this slot is in use.
    pub const fn in_use(&self) -> bool {
        self.in_use
    }
}

// ---------------------------------------------------------------------------
// SignalTimerFdRegistry
// ---------------------------------------------------------------------------

/// Registry managing signalfd and timerfd instances.
///
/// Holds up to [`MAX_SIGNALFDS`] signalfd slots and [`MAX_TIMERFDS`]
/// timerfd slots. Each is identified by a unique `u64` ID.
pub struct SignalTimerFdRegistry {
    /// Signalfd slot array.
    signalfds: [Signalfd; MAX_SIGNALFDS],
    /// Timerfd slot array.
    timerfds: [Timerfd; MAX_TIMERFDS],
    /// Number of active signalfds.
    sfd_count: usize,
    /// Number of active timerfds.
    tfd_count: usize,
    /// Next signalfd ID to assign.
    next_sfd_id: u64,
    /// Next timerfd ID to assign.
    next_tfd_id: u64,
}

impl SignalTimerFdRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            signalfds: [const { Signalfd::new() }; MAX_SIGNALFDS],
            timerfds: [const { Timerfd::new() }; MAX_TIMERFDS],
            sfd_count: 0,
            tfd_count: 0,
            next_sfd_id: 1,
            next_tfd_id: 1,
        }
    }

    /// Return the total number of active signalfd and timerfd entries.
    pub const fn len(&self) -> usize {
        self.sfd_count + self.tfd_count
    }

    /// Return `true` if no signalfd or timerfd entries are active.
    pub const fn is_empty(&self) -> bool {
        self.sfd_count == 0 && self.tfd_count == 0
    }

    // ---------------------------------------------------------------
    // signalfd operations
    // ---------------------------------------------------------------

    /// Create a new signalfd listening for the given signal mask.
    ///
    /// Returns the assigned signalfd ID on success, or `OutOfMemory`
    /// if the registry is full, or `InvalidArgument` for bad flags.
    pub fn signalfd_create(&mut self, mask: u64, flags: u32, pid: u64) -> Result<u64> {
        if (flags & !SFD_VALID) != 0 {
            return Err(Error::InvalidArgument);
        }

        let slot_idx = self
            .signalfds
            .iter()
            .position(|s| !s.in_use)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_sfd_id;
        self.next_sfd_id = self.next_sfd_id.wrapping_add(1);

        let slot = &mut self.signalfds[slot_idx];
        slot.id = id;
        slot.mask = mask;
        slot.flags = flags;
        slot.pending_count = 0;
        slot.owner_pid = pid;
        slot.in_use = true;

        self.sfd_count += 1;
        Ok(id)
    }

    /// Read one pending signal from a signalfd.
    ///
    /// Returns `Some(info)` if a signal was pending, or `None` if no
    /// signals are queued. Returns `WouldBlock` if non-blocking and
    /// the queue is empty.
    pub fn signalfd_read(&mut self, id: u64) -> Result<Option<SignalfdSiginfo>> {
        let fd = self.find_sfd_mut(id)?;

        if fd.pending_count == 0 {
            if fd.flags & SignalfdFlags::SFD_NONBLOCK != 0 {
                return Err(Error::WouldBlock);
            }
            return Ok(None);
        }

        // Dequeue the first pending signal (FIFO).
        let info = fd.pending[0];
        // Shift remaining entries left by one.
        let count = fd.pending_count;
        let pending = &mut fd.pending;
        let mut i = 1;
        while i < count {
            pending[i - 1] = pending[i];
            i += 1;
        }
        pending[count - 1] = SignalfdSiginfo::default();
        fd.pending_count -= 1;

        Ok(Some(info))
    }

    /// Deliver a signal to a signalfd.
    ///
    /// The signal info is appended to the pending queue if the signal
    /// number matches the mask and the queue is not full.
    pub fn signalfd_deliver(&mut self, id: u64, siginfo: &SignalfdSiginfo) -> Result<()> {
        let fd = self.find_sfd_mut(id)?;

        // Check that the signal is in the mask (bit position = signo - 1).
        if siginfo.ssi_signo == 0 {
            return Err(Error::InvalidArgument);
        }
        let bit = 1u64 << (siginfo.ssi_signo - 1);
        if fd.mask & bit == 0 {
            return Err(Error::InvalidArgument);
        }

        if fd.pending_count >= MAX_PENDING {
            return Err(Error::OutOfMemory);
        }

        fd.pending[fd.pending_count] = *siginfo;
        fd.pending_count += 1;

        Ok(())
    }

    /// Close (deactivate) a signalfd by ID.
    pub fn signalfd_close(&mut self, id: u64) -> Result<()> {
        let fd = self.find_sfd_mut(id)?;
        fd.in_use = false;
        fd.mask = 0;
        fd.pending_count = 0;
        self.sfd_count = self.sfd_count.saturating_sub(1);
        Ok(())
    }

    // ---------------------------------------------------------------
    // timerfd operations
    // ---------------------------------------------------------------

    /// Create a new timerfd with the given clock source.
    ///
    /// Returns the assigned timerfd ID on success, or `OutOfMemory`
    /// if the registry is full, or `InvalidArgument` for bad flags
    /// or clock ID.
    pub fn timerfd_create(&mut self, clock_id: u32, flags: u32, pid: u64) -> Result<u64> {
        if (flags & !TFD_VALID) != 0 {
            return Err(Error::InvalidArgument);
        }

        let clk = TimerfdClockId::from_u32(clock_id).ok_or(Error::InvalidArgument)?;

        let slot_idx = self
            .timerfds
            .iter()
            .position(|t| !t.in_use)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_tfd_id;
        self.next_tfd_id = self.next_tfd_id.wrapping_add(1);

        let slot = &mut self.timerfds[slot_idx];
        slot.id = id;
        slot.clock_id = clk;
        slot.flags = flags;
        slot.interval = Itimerspec::default();
        slot.expiration_count = 0;
        slot.armed = false;
        slot.owner_pid = pid;
        slot.in_use = true;
        slot.remaining_ns = 0;

        self.tfd_count += 1;
        Ok(id)
    }

    /// Set the timer on a timerfd.
    ///
    /// Arms the timer with `new_value` and returns the previous
    /// timer specification.
    pub fn timerfd_settime(&mut self, id: u64, new_value: &Itimerspec) -> Result<Itimerspec> {
        let fd = self.find_tfd_mut(id)?;

        let old = fd.interval;
        fd.interval = *new_value;

        // Determine whether the timer should be armed.
        let value_nanos = new_value.it_value.to_nanos();
        if let Some(ns) = value_nanos {
            if ns > 0 {
                fd.armed = true;
                fd.remaining_ns = ns as u64;
            } else {
                // Disarm: it_value is zero.
                fd.armed = false;
                fd.remaining_ns = 0;
            }
        } else {
            fd.armed = false;
            fd.remaining_ns = 0;
        }

        fd.expiration_count = 0;
        Ok(old)
    }

    /// Get the current timer specification for a timerfd.
    ///
    /// The returned `it_value` reflects the time remaining until
    /// the next expiration. If the timer is disarmed, both fields
    /// are zero.
    pub fn timerfd_gettime(&self, id: u64) -> Result<Itimerspec> {
        let fd = self.find_tfd(id)?;

        if !fd.armed {
            return Ok(Itimerspec::default());
        }

        Ok(Itimerspec {
            it_interval: fd.interval.it_interval,
            it_value: Timespec::from_nanos(fd.remaining_ns as i64),
        })
    }

    /// Read the expiration count from a timerfd.
    ///
    /// Returns the number of expirations since the last read and
    /// resets the counter to zero. Returns `WouldBlock` if no
    /// expirations have occurred and the fd is non-blocking.
    pub fn timerfd_read(&mut self, id: u64) -> Result<u64> {
        let fd = self.find_tfd_mut(id)?;

        if fd.expiration_count == 0 {
            if fd.flags & TimerfdFlags::TFD_NONBLOCK != 0 {
                return Err(Error::WouldBlock);
            }
            // In a real kernel, we would block here.
            return Err(Error::WouldBlock);
        }

        let count = fd.expiration_count;
        fd.expiration_count = 0;
        Ok(count)
    }

    /// Close (deactivate) a timerfd by ID.
    pub fn timerfd_close(&mut self, id: u64) -> Result<()> {
        let fd = self.find_tfd_mut(id)?;
        fd.in_use = false;
        fd.armed = false;
        fd.expiration_count = 0;
        fd.remaining_ns = 0;
        self.tfd_count = self.tfd_count.saturating_sub(1);
        Ok(())
    }

    /// Advance all armed timers by `elapsed_ns` nanoseconds.
    ///
    /// Any timer whose remaining time reaches zero increments its
    /// expiration counter. If the timer has a non-zero interval, it
    /// is re-armed; otherwise it is disarmed (one-shot).
    pub fn timerfd_tick(&mut self, elapsed_ns: u64) {
        for slot in &mut self.timerfds {
            if !slot.in_use || !slot.armed {
                continue;
            }

            if elapsed_ns >= slot.remaining_ns {
                // Timer expired.
                slot.expiration_count = slot.expiration_count.saturating_add(1);

                // Check for periodic re-arm.
                let interval_nanos = slot.interval.it_interval.to_nanos();
                match interval_nanos {
                    Some(ns) if ns > 0 => {
                        // Re-arm with the interval period.
                        // Account for any overshoot.
                        let overshoot = elapsed_ns - slot.remaining_ns;
                        let period = ns as u64;
                        if overshoot >= period {
                            // Multiple expirations in one tick.
                            let extra = overshoot / period;
                            slot.expiration_count = slot.expiration_count.saturating_add(extra);
                            slot.remaining_ns = period - (overshoot % period);
                        } else {
                            slot.remaining_ns = period - overshoot;
                        }
                    }
                    _ => {
                        // One-shot: disarm.
                        slot.armed = false;
                        slot.remaining_ns = 0;
                    }
                }
            } else {
                slot.remaining_ns -= elapsed_ns;
            }
        }
    }

    // ---------------------------------------------------------------
    // helpers
    // ---------------------------------------------------------------

    /// Find an active signalfd by ID (mutable reference).
    fn find_sfd_mut(&mut self, id: u64) -> Result<&mut Signalfd> {
        self.signalfds
            .iter_mut()
            .find(|s| s.in_use && s.id == id)
            .ok_or(Error::NotFound)
    }

    /// Find an active timerfd by ID (shared reference).
    fn find_tfd(&self, id: u64) -> Result<&Timerfd> {
        self.timerfds
            .iter()
            .find(|t| t.in_use && t.id == id)
            .ok_or(Error::NotFound)
    }

    /// Find an active timerfd by ID (mutable reference).
    fn find_tfd_mut(&mut self, id: u64) -> Result<&mut Timerfd> {
        self.timerfds
            .iter_mut()
            .find(|t| t.in_use && t.id == id)
            .ok_or(Error::NotFound)
    }
}

impl Default for SignalTimerFdRegistry {
    fn default() -> Self {
        Self::new()
    }
}
