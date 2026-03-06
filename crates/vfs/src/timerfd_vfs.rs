// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! timerfd VFS integration layer.
//!
//! Provides VFS-level integration for timerfd file descriptors, connecting
//! timerfd timer management to VFS file operations. timerfd fds are readable
//! when the timer has expired and integrate with poll/select/epoll.

use oncrix_lib::{Error, Result};

/// Clock IDs supported by timerfd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TimerfdClock {
    /// Settable system-wide clock.
    Realtime = 0,
    /// Non-settable monotonic clock.
    Monotonic = 1,
    /// Boot-based monotonic clock.
    BootTime = 7,
    /// Alarm-capable realtime clock.
    RealtimeAlarm = 8,
    /// Alarm-capable boottime clock.
    BootTimeAlarm = 9,
}

impl TimerfdClock {
    /// Convert from raw clock ID.
    pub fn from_raw(id: u32) -> Result<Self> {
        match id {
            0 => Ok(Self::Realtime),
            1 => Ok(Self::Monotonic),
            7 => Ok(Self::BootTime),
            8 => Ok(Self::RealtimeAlarm),
            9 => Ok(Self::BootTimeAlarm),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// Flags for timerfd_create.
#[derive(Debug, Clone, Copy, Default)]
pub struct TimerfdFlags(pub u32);

impl TimerfdFlags {
    /// Set close-on-exec flag.
    pub const TFD_CLOEXEC: u32 = 0o2000000;
    /// Set non-blocking flag.
    pub const TFD_NONBLOCK: u32 = 0o4000;

    /// Check if close-on-exec is set.
    pub fn is_cloexec(self) -> bool {
        self.0 & Self::TFD_CLOEXEC != 0
    }

    /// Check if non-blocking is set.
    pub fn is_nonblock(self) -> bool {
        self.0 & Self::TFD_NONBLOCK != 0
    }

    /// Validate flags.
    pub fn is_valid(self) -> bool {
        self.0 & !(Self::TFD_CLOEXEC | Self::TFD_NONBLOCK) == 0
    }
}

/// Flags for timerfd_settime.
#[derive(Debug, Clone, Copy, Default)]
pub struct SetTimeFlags(pub u32);

impl SetTimeFlags {
    /// Use absolute time (relative to clock epoch).
    pub const TFD_TIMER_ABSTIME: u32 = 1 << 0;
    /// Cancel on clock change.
    pub const TFD_TIMER_CANCEL_ON_SET: u32 = 1 << 1;

    /// Check if absolute time is requested.
    pub fn is_abstime(self) -> bool {
        self.0 & Self::TFD_TIMER_ABSTIME != 0
    }
}

/// Timer specification: initial expiry and interval.
#[derive(Debug, Clone, Copy, Default)]
pub struct ITimerSpec {
    /// Timer interval (0 = one-shot).
    pub it_interval_ns: u64,
    /// Initial expiry time (0 = disarm timer).
    pub it_value_ns: u64,
}

impl ITimerSpec {
    /// Create a one-shot timer.
    pub const fn one_shot(value_ns: u64) -> Self {
        ITimerSpec {
            it_interval_ns: 0,
            it_value_ns: value_ns,
        }
    }

    /// Create a periodic timer.
    pub const fn periodic(interval_ns: u64) -> Self {
        ITimerSpec {
            it_interval_ns: interval_ns,
            it_value_ns: interval_ns,
        }
    }

    /// Check if the timer is disarmed (value == 0).
    pub fn is_disarmed(&self) -> bool {
        self.it_value_ns == 0
    }
}

/// State of a single timerfd VFS instance.
#[derive(Debug, Clone, Copy)]
pub struct TimerfdVfs {
    /// Inode number for this timerfd.
    pub ino: u64,
    /// Clock source.
    pub clock: TimerfdClock,
    /// Current timer specification.
    pub spec: ITimerSpec,
    /// Absolute expiry time in nanoseconds (0 = disarmed).
    pub next_expiry_ns: u64,
    /// Number of accumulated expirations (readable count).
    pub expirations: u64,
    /// Non-blocking mode.
    pub nonblock: bool,
    /// Close-on-exec.
    pub cloexec: bool,
}

impl TimerfdVfs {
    /// Create a new timerfd instance.
    pub const fn new(ino: u64, clock: TimerfdClock, flags: TimerfdFlags) -> Self {
        TimerfdVfs {
            ino,
            clock,
            spec: ITimerSpec {
                it_interval_ns: 0,
                it_value_ns: 0,
            },
            next_expiry_ns: 0,
            expirations: 0,
            nonblock: flags.0 & TimerfdFlags::TFD_NONBLOCK != 0,
            cloexec: flags.0 & TimerfdFlags::TFD_CLOEXEC != 0,
        }
    }

    /// Set the timer specification.
    ///
    /// `now_ns` is the current clock value in nanoseconds.
    pub fn settime(&mut self, spec: ITimerSpec, flags: SetTimeFlags, now_ns: u64) -> ITimerSpec {
        let old = self.spec;
        self.spec = spec;
        if spec.is_disarmed() {
            self.next_expiry_ns = 0;
        } else if flags.is_abstime() {
            self.next_expiry_ns = spec.it_value_ns;
        } else {
            self.next_expiry_ns = now_ns.saturating_add(spec.it_value_ns);
        }
        self.expirations = 0;
        old
    }

    /// Query current timer state.
    pub fn gettime(&self, now_ns: u64) -> ITimerSpec {
        if self.next_expiry_ns == 0 {
            return ITimerSpec::default();
        }
        let remaining = self.next_expiry_ns.saturating_sub(now_ns);
        ITimerSpec {
            it_interval_ns: self.spec.it_interval_ns,
            it_value_ns: remaining,
        }
    }

    /// Tick the timer: advance to `now_ns`.
    ///
    /// If the timer has expired, accumulate expirations and reschedule if periodic.
    pub fn tick(&mut self, now_ns: u64) {
        if self.next_expiry_ns == 0 || now_ns < self.next_expiry_ns {
            return;
        }
        let elapsed = now_ns - self.next_expiry_ns;
        if self.spec.it_interval_ns > 0 {
            let count = elapsed / self.spec.it_interval_ns + 1;
            self.expirations = self.expirations.saturating_add(count);
            self.next_expiry_ns += count * self.spec.it_interval_ns;
        } else {
            self.expirations = self.expirations.saturating_add(1);
            self.next_expiry_ns = 0;
        }
    }

    /// Read and reset the expiration counter.
    ///
    /// Returns `Err(WouldBlock)` if no expirations have occurred and
    /// the fd is in non-blocking mode.
    pub fn read(&mut self) -> Result<u64> {
        if self.expirations == 0 {
            if self.nonblock {
                return Err(Error::WouldBlock);
            }
            return Err(Error::WouldBlock);
        }
        let count = self.expirations;
        self.expirations = 0;
        Ok(count)
    }

    /// Check if this fd is readable (has expirations).
    pub fn is_readable(&self) -> bool {
        self.expirations > 0
    }
}

/// Table of timerfd VFS instances.
pub struct TimerfdVfsTable {
    instances: [Option<TimerfdVfs>; 64],
    count: usize,
}

impl TimerfdVfsTable {
    /// Create a new empty table.
    pub const fn new() -> Self {
        TimerfdVfsTable {
            instances: [const { None }; 64],
            count: 0,
        }
    }

    /// Allocate a new timerfd instance.
    pub fn create(&mut self, ino: u64, clock: TimerfdClock, flags: TimerfdFlags) -> Result<usize> {
        if !flags.is_valid() {
            return Err(Error::InvalidArgument);
        }
        for (i, slot) in self.instances.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(TimerfdVfs::new(ino, clock, flags));
                self.count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Get a reference to an instance.
    pub fn get(&self, idx: usize) -> Result<&TimerfdVfs> {
        self.instances
            .get(idx)
            .and_then(|s| s.as_ref())
            .ok_or(Error::NotFound)
    }

    /// Get a mutable reference to an instance.
    pub fn get_mut(&mut self, idx: usize) -> Result<&mut TimerfdVfs> {
        self.instances
            .get_mut(idx)
            .and_then(|s| s.as_mut())
            .ok_or(Error::NotFound)
    }

    /// Close a timerfd instance.
    pub fn close(&mut self, idx: usize) -> Result<()> {
        if idx >= 64 || self.instances[idx].is_none() {
            return Err(Error::NotFound);
        }
        self.instances[idx] = None;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Tick all active timers.
    pub fn tick_all(&mut self, now_ns: u64) {
        for slot in self.instances.iter_mut().flatten() {
            slot.tick(now_ns);
        }
    }

    /// Return count of active instances.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for TimerfdVfsTable {
    fn default() -> Self {
        Self::new()
    }
}
