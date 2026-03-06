// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! timerfd file descriptor.
//!
//! Implements the timerfd_create(2) / timerfd_settime(2) / timerfd_gettime(2)
//! interface. A timerfd delivers timer expiration notifications via a read()
//! call that returns the number of expirations since the last read.

use oncrix_lib::{Error, Result};

/// Clock IDs for timerfd_create.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ClockId {
    /// System-wide realtime clock.
    Realtime = 0,
    /// Monotonic clock (no settable jumps).
    Monotonic = 1,
    /// Boot time (includes suspend).
    Boottime = 7,
    /// POSIX per-process CPU time.
    ProcessCputime = 2,
    /// POSIX per-thread CPU time.
    ThreadCputime = 3,
}

impl TryFrom<i32> for ClockId {
    type Error = Error;

    fn try_from(v: i32) -> Result<Self> {
        match v {
            0 => Ok(Self::Realtime),
            1 => Ok(Self::Monotonic),
            7 => Ok(Self::Boottime),
            2 => Ok(Self::ProcessCputime),
            3 => Ok(Self::ThreadCputime),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// timerfd creation flags.
pub const TFD_NONBLOCK: u32 = 0x0004;
pub const TFD_CLOEXEC: u32 = 0x0002;
pub const TFD_TIMER_ABSTIME: u32 = 1 << 0;
pub const TFD_TIMER_CANCEL_ON_SET: u32 = 1 << 1;

/// A timespec-like structure for nanosecond precision.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timespec {
    /// Seconds component.
    pub tv_sec: i64,
    /// Nanoseconds component (0..999_999_999).
    pub tv_nsec: i64,
}

impl Timespec {
    /// Create a zero timespec.
    pub const fn zero() -> Self {
        Self {
            tv_sec: 0,
            tv_nsec: 0,
        }
    }

    /// Return true if both fields are zero.
    pub fn is_zero(&self) -> bool {
        self.tv_sec == 0 && self.tv_nsec == 0
    }

    /// Convert to nanoseconds (saturating).
    pub fn to_ns(&self) -> u64 {
        (self.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(self.tv_nsec as u64)
    }
}

/// itimerspec: describes an initial expiry and interval.
#[derive(Debug, Clone, Copy, Default)]
pub struct ITimerSpec {
    /// Interval for periodic timer (zero = one-shot).
    pub it_interval: Timespec,
    /// Initial expiration time.
    pub it_value: Timespec,
}

impl ITimerSpec {
    /// Return true if this spec disarms the timer.
    pub fn is_disarm(&self) -> bool {
        self.it_value.is_zero()
    }
}

/// timerfd state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerState {
    /// Timer is disarmed.
    Disarmed,
    /// Timer is armed and waiting.
    Armed,
    /// Timer has expired and expiration count is ready to read.
    Expired,
}

/// A timerfd object.
#[derive(Debug)]
pub struct TimerFd {
    /// Clock source.
    pub clockid: ClockId,
    /// Creation flags.
    pub flags: u32,
    /// Armed timer spec.
    pub spec: ITimerSpec,
    /// Current state.
    pub state: TimerState,
    /// Number of expirations since last read.
    pub expirations: u64,
    /// Simulated current time in nanoseconds (updated by tick()).
    current_ns: u64,
    /// Next expiry time in nanoseconds.
    next_expiry_ns: u64,
}

impl TimerFd {
    /// Create a new timerfd.
    pub fn new(clockid: ClockId, flags: u32) -> Result<Self> {
        Ok(Self {
            clockid,
            flags,
            spec: ITimerSpec::default(),
            state: TimerState::Disarmed,
            expirations: 0,
            current_ns: 0,
            next_expiry_ns: 0,
        })
    }

    /// Return true if non-blocking mode is set.
    pub fn is_nonblock(&self) -> bool {
        self.flags & TFD_NONBLOCK != 0
    }

    /// Set the timer. Passing a zero `it_value` disarms the timer.
    pub fn settime(&mut self, new_value: &ITimerSpec, settime_flags: u32) -> Result<ITimerSpec> {
        let old_spec = self.spec;

        if new_value.is_disarm() {
            self.state = TimerState::Disarmed;
            self.spec = *new_value;
            self.expirations = 0;
            self.next_expiry_ns = 0;
            return Ok(old_spec);
        }

        let expiry_ns = if settime_flags & TFD_TIMER_ABSTIME != 0 {
            new_value.it_value.to_ns()
        } else {
            self.current_ns.saturating_add(new_value.it_value.to_ns())
        };

        self.spec = *new_value;
        self.state = TimerState::Armed;
        self.expirations = 0;
        self.next_expiry_ns = expiry_ns;
        Ok(old_spec)
    }

    /// Get the current timer setting.
    pub fn gettime(&self) -> ITimerSpec {
        if self.state == TimerState::Disarmed {
            return ITimerSpec::default();
        }
        let remaining_ns = self.next_expiry_ns.saturating_sub(self.current_ns);
        ITimerSpec {
            it_interval: self.spec.it_interval,
            it_value: Timespec {
                tv_sec: (remaining_ns / 1_000_000_000) as i64,
                tv_nsec: (remaining_ns % 1_000_000_000) as i64,
            },
        }
    }

    /// Advance the simulated clock by `delta_ns` nanoseconds, firing if due.
    pub fn tick(&mut self, delta_ns: u64) {
        self.current_ns = self.current_ns.saturating_add(delta_ns);
        if self.state != TimerState::Armed {
            return;
        }
        if self.current_ns < self.next_expiry_ns {
            return;
        }

        // Count expirations.
        let interval_ns = self.spec.it_interval.to_ns();
        if interval_ns == 0 {
            self.expirations += 1;
            self.state = TimerState::Expired;
        } else {
            let elapsed = self.current_ns - self.next_expiry_ns;
            let count = elapsed / interval_ns + 1;
            self.expirations += count;
            self.next_expiry_ns += count * interval_ns;
            self.state = TimerState::Expired;
        }
    }

    /// Read the expiration count.
    ///
    /// Returns the count as 8 bytes (u64 LE), then resets to 0.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < 8 {
            return Err(Error::InvalidArgument);
        }
        if self.expirations == 0 {
            return Err(Error::WouldBlock);
        }
        let count = self.expirations;
        self.expirations = 0;
        if self.state == TimerState::Expired {
            self.state = if self.spec.it_interval.is_zero() {
                TimerState::Disarmed
            } else {
                TimerState::Armed
            };
        }
        buf[..8].copy_from_slice(&count.to_ne_bytes());
        Ok(8)
    }

    /// Poll readiness: returns true if there are pending expirations.
    pub fn poll_readable(&self) -> bool {
        self.expirations > 0
    }
}

/// timerfd file wrapping the timer with a file descriptor number.
#[derive(Debug)]
pub struct TimerFdFile {
    /// The underlying timerfd state.
    pub tfd: TimerFd,
    /// File descriptor number.
    pub fd: i32,
}

impl TimerFdFile {
    /// Create a new timerfd file.
    pub fn new(fd: i32, clockid: ClockId, flags: u32) -> Result<Self> {
        Ok(Self {
            tfd: TimerFd::new(clockid, flags)?,
            fd,
        })
    }

    /// Read the expiration count.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.tfd.read(buf)
    }

    /// Set the timer.
    pub fn settime(&mut self, new_value: &ITimerSpec, flags: u32) -> Result<ITimerSpec> {
        self.tfd.settime(new_value, flags)
    }

    /// Get the current timer setting.
    pub fn gettime(&self) -> ITimerSpec {
        self.tfd.gettime()
    }
}
