// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `timerfd_create(2)`, `timerfd_settime(2)`, `timerfd_gettime(2)` —
//! file-descriptor-based timer interface.
//!
//! timerfd provides a file descriptor that delivers timer expiration
//! notifications.  Reading the fd returns a `u64` count of expirations
//! since the last read.  The timer can be one-shot or periodic.
//!
//! # Syscalls
//!
//! | Syscall | Handler | Description |
//! |---------|---------|-------------|
//! | `timerfd_create` | [`sys_timerfd_create`] | Create a new timerfd |
//! | `timerfd_settime` | [`sys_timerfd_settime`] | Arm or disarm the timer |
//! | `timerfd_gettime` | [`sys_timerfd_gettime`] | Query remaining time |
//!
//! # References
//!
//! - Linux: `fs/timerfd.c`
//! - man page: `timerfd_create(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of timerfd instances in the registry.
const MAX_TIMERFDS: usize = 128;

/// Nanoseconds per second.
const NANOS_PER_SEC: i64 = 1_000_000_000;

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Set close-on-exec on the timerfd.
pub const TFD_CLOEXEC: u32 = 0x80000;

/// Enable non-blocking reads on the timerfd.
pub const TFD_NONBLOCK: u32 = 0x800;

/// All valid `timerfd_create` flag bits.
const TFD_CREATE_VALID: u32 = TFD_CLOEXEC | TFD_NONBLOCK;

/// Use absolute time for `timerfd_settime`.
///
/// When set, `it_value` is interpreted as an absolute deadline
/// on the timer's clock. Without this flag, `it_value` is a
/// relative duration from the current time.
pub const TFD_TIMER_ABSTIME: u32 = 1 << 0;

/// Cancel the timer if the realtime clock is set.
///
/// Only meaningful for `CLOCK_REALTIME`-based timers. When the
/// clock is adjusted, the timer fires immediately with
/// `TFD_TIMER_CANCEL_ON_SET` semantics.
pub const TFD_TIMER_CANCEL_ON_SET: u32 = 1 << 1;

/// All valid `timerfd_settime` flag bits.
const TFD_SETTIME_VALID: u32 = TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET;

// ---------------------------------------------------------------------------
// Timespec / Itimerspec (local definitions)
// ---------------------------------------------------------------------------

/// Time specification — seconds and nanoseconds.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TimerfdTimespec {
    /// Whole seconds.
    pub tv_sec: i64,
    /// Nanoseconds (must be in `0..1_000_000_000`).
    pub tv_nsec: i64,
}

impl TimerfdTimespec {
    /// Create a new timespec.
    pub const fn new(tv_sec: i64, tv_nsec: i64) -> Self {
        Self { tv_sec, tv_nsec }
    }

    /// Zero-valued timespec.
    pub const fn zero() -> Self {
        Self {
            tv_sec: 0,
            tv_nsec: 0,
        }
    }

    /// Check if the timespec is zero (both fields are zero).
    pub const fn is_zero(&self) -> bool {
        self.tv_sec == 0 && self.tv_nsec == 0
    }

    /// Validate that the nanosecond field is in `[0, 999_999_999]`.
    pub const fn is_valid(&self) -> bool {
        self.tv_nsec >= 0 && self.tv_nsec < NANOS_PER_SEC
    }

    /// Convert to total nanoseconds, returning `None` on overflow.
    pub fn to_nanos(&self) -> Option<i64> {
        self.tv_sec
            .checked_mul(NANOS_PER_SEC)
            .and_then(|s| s.checked_add(self.tv_nsec))
    }

    /// Construct from total nanoseconds.
    pub fn from_nanos(nanos: i64) -> Self {
        if nanos <= 0 {
            return Self::zero();
        }
        Self {
            tv_sec: nanos / NANOS_PER_SEC,
            tv_nsec: nanos % NANOS_PER_SEC,
        }
    }
}

/// Interval timer specification.
///
/// `it_value` is the initial expiration time. `it_interval` is the
/// repeat period (zero for one-shot timers).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TimerfdItimerspec {
    /// Timer period (zero = one-shot).
    pub it_interval: TimerfdTimespec,
    /// Initial expiration.
    pub it_value: TimerfdTimespec,
}

impl TimerfdItimerspec {
    /// Create a new itimerspec.
    pub const fn new(interval: TimerfdTimespec, value: TimerfdTimespec) -> Self {
        Self {
            it_interval: interval,
            it_value: value,
        }
    }

    /// Zero-valued itimerspec (disarmed timer).
    pub const fn zero() -> Self {
        Self {
            it_interval: TimerfdTimespec::zero(),
            it_value: TimerfdTimespec::zero(),
        }
    }

    /// Validate both timespec fields.
    pub const fn is_valid(&self) -> bool {
        self.it_interval.is_valid() && self.it_value.is_valid()
    }
}

// ---------------------------------------------------------------------------
// ClockId
// ---------------------------------------------------------------------------

/// Clock source for timerfd.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimerfdClockId {
    /// Wall-clock time; settable.
    Realtime = 0,
    /// Monotonic clock; not affected by system time changes.
    #[default]
    Monotonic = 1,
    /// Time since boot, including suspend.
    Boottime = 7,
    /// Realtime alarm — wakes from suspend.
    RealtimeAlarm = 8,
    /// Boottime alarm — wakes from suspend.
    BoottimeAlarm = 9,
}

impl TimerfdClockId {
    /// Convert a raw `i32` to a `TimerfdClockId`, if valid.
    pub fn from_i32(val: i32) -> Option<Self> {
        match val {
            0 => Some(Self::Realtime),
            1 => Some(Self::Monotonic),
            7 => Some(Self::Boottime),
            8 => Some(Self::RealtimeAlarm),
            9 => Some(Self::BoottimeAlarm),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// TimerfdInstance — a single timerfd
// ---------------------------------------------------------------------------

/// A single timerfd instance.
///
/// Tracks the timer's clock source, armed state, expiration count,
/// interval specification, and remaining time until next expiration.
pub struct TimerfdInstance {
    /// Unique identifier.
    id: u64,
    /// Clock source.
    clock_id: TimerfdClockId,
    /// Creation flags.
    create_flags: u32,
    /// Settime flags (TFD_TIMER_ABSTIME, etc.).
    settime_flags: u32,
    /// Current timer specification.
    spec: TimerfdItimerspec,
    /// Number of expirations since last read.
    expiration_count: u64,
    /// Whether the timer is armed.
    armed: bool,
    /// Remaining nanoseconds until next expiration.
    remaining_ns: u64,
    /// PID of the owning process.
    owner_pid: u64,
    /// Whether this slot is active.
    active: bool,
}

impl TimerfdInstance {
    /// Create an inactive timerfd instance.
    const fn new() -> Self {
        Self {
            id: 0,
            clock_id: TimerfdClockId::Monotonic,
            create_flags: 0,
            settime_flags: 0,
            spec: TimerfdItimerspec::zero(),
            expiration_count: 0,
            armed: false,
            remaining_ns: 0,
            owner_pid: 0,
            active: false,
        }
    }

    /// Return the timerfd ID.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Return the clock source.
    pub const fn clock_id(&self) -> TimerfdClockId {
        self.clock_id
    }

    /// Return the creation flags.
    pub const fn create_flags(&self) -> u32 {
        self.create_flags
    }

    /// Return the settime flags.
    pub const fn settime_flags(&self) -> u32 {
        self.settime_flags
    }

    /// Return the current timer specification.
    pub const fn spec(&self) -> &TimerfdItimerspec {
        &self.spec
    }

    /// Return the number of expirations since last read.
    pub const fn expiration_count(&self) -> u64 {
        self.expiration_count
    }

    /// Return whether the timer is armed.
    pub const fn armed(&self) -> bool {
        self.armed
    }

    /// Return the remaining nanoseconds until next expiration.
    pub const fn remaining_ns(&self) -> u64 {
        self.remaining_ns
    }

    /// Return the owner PID.
    pub const fn owner_pid(&self) -> u64 {
        self.owner_pid
    }

    /// Return whether this slot is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Return whether reads will block (no expirations pending).
    pub const fn would_block(&self) -> bool {
        self.expiration_count == 0
    }
}

// ---------------------------------------------------------------------------
// TimerfdRegistry
// ---------------------------------------------------------------------------

/// Registry managing a pool of timerfd instances.
///
/// Each timerfd is identified by a unique `u64` ID assigned at creation.
pub struct TimerfdRegistry {
    /// Timerfd slot array.
    timers: [TimerfdInstance; MAX_TIMERFDS],
    /// Next ID to assign.
    next_id: u64,
    /// Number of active timerfds.
    count: usize,
}

impl TimerfdRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            timers: [const { TimerfdInstance::new() }; MAX_TIMERFDS],
            next_id: 1,
            count: 0,
        }
    }

    /// Return the number of active timerfds.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return `true` if no timerfds are active.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    // ---------------------------------------------------------------
    // Lookup helpers
    // ---------------------------------------------------------------

    /// Find an active timerfd by ID (shared reference).
    fn find(&self, id: u64) -> Result<&TimerfdInstance> {
        self.timers
            .iter()
            .find(|t| t.active && t.id == id)
            .ok_or(Error::NotFound)
    }

    /// Find an active timerfd by ID (mutable reference).
    fn find_mut(&mut self, id: u64) -> Result<&mut TimerfdInstance> {
        self.timers
            .iter_mut()
            .find(|t| t.active && t.id == id)
            .ok_or(Error::NotFound)
    }

    /// Find a free slot.
    fn find_free(&self) -> Option<usize> {
        self.timers.iter().position(|t| !t.active)
    }

    // ---------------------------------------------------------------
    // timerfd_create
    // ---------------------------------------------------------------

    /// Create a new timerfd.
    ///
    /// Returns the assigned ID on success.
    fn create(&mut self, clock_id: TimerfdClockId, flags: u32, pid: u64) -> Result<u64> {
        let idx = self.find_free().ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let slot = &mut self.timers[idx];
        slot.id = id;
        slot.clock_id = clock_id;
        slot.create_flags = flags;
        slot.settime_flags = 0;
        slot.spec = TimerfdItimerspec::zero();
        slot.expiration_count = 0;
        slot.armed = false;
        slot.remaining_ns = 0;
        slot.owner_pid = pid;
        slot.active = true;

        self.count += 1;
        Ok(id)
    }

    // ---------------------------------------------------------------
    // timerfd_settime
    // ---------------------------------------------------------------

    /// Arm or disarm a timerfd.
    ///
    /// Returns the previous timer specification.
    fn settime(
        &mut self,
        id: u64,
        flags: u32,
        new_spec: &TimerfdItimerspec,
    ) -> Result<TimerfdItimerspec> {
        let fd = self.find_mut(id)?;

        // Save old spec for return.
        let old = TimerfdItimerspec {
            it_interval: fd.spec.it_interval,
            it_value: if fd.armed {
                TimerfdTimespec::from_nanos(fd.remaining_ns as i64)
            } else {
                TimerfdTimespec::zero()
            },
        };

        fd.settime_flags = flags;
        fd.spec = *new_spec;

        // Determine whether to arm or disarm.
        if new_spec.it_value.is_zero() {
            // Disarm the timer.
            fd.armed = false;
            fd.remaining_ns = 0;
            fd.expiration_count = 0;
        } else if let Some(ns) = new_spec.it_value.to_nanos() {
            if ns > 0 {
                fd.armed = true;
                fd.remaining_ns = ns as u64;
                fd.expiration_count = 0;
            } else {
                fd.armed = false;
                fd.remaining_ns = 0;
                fd.expiration_count = 0;
            }
        } else {
            fd.armed = false;
            fd.remaining_ns = 0;
            fd.expiration_count = 0;
        }

        Ok(old)
    }

    // ---------------------------------------------------------------
    // timerfd_gettime
    // ---------------------------------------------------------------

    /// Query the current timer specification.
    ///
    /// The returned `it_value` reflects the remaining time until
    /// the next expiration. If disarmed, both fields are zero.
    fn gettime(&self, id: u64) -> Result<TimerfdItimerspec> {
        let fd = self.find(id)?;

        if !fd.armed {
            return Ok(TimerfdItimerspec::zero());
        }

        Ok(TimerfdItimerspec {
            it_interval: fd.spec.it_interval,
            it_value: TimerfdTimespec::from_nanos(fd.remaining_ns as i64),
        })
    }

    // ---------------------------------------------------------------
    // Read / poll
    // ---------------------------------------------------------------

    /// Read the expiration count from a timerfd.
    ///
    /// Returns the number of expirations since the last read and
    /// resets the counter to zero. Returns `WouldBlock` if no
    /// expirations have occurred.
    fn read(&mut self, id: u64) -> Result<u64> {
        let fd = self.find_mut(id)?;

        if fd.expiration_count == 0 {
            if fd.create_flags & TFD_NONBLOCK != 0 {
                return Err(Error::WouldBlock);
            }
            // In a real kernel, we would block.
            return Err(Error::WouldBlock);
        }

        let count = fd.expiration_count;
        fd.expiration_count = 0;
        Ok(count)
    }

    /// Poll a timerfd for readiness.
    ///
    /// Returns a bitmask:
    /// - bit 0 (`POLLIN`): expirations are available for reading
    fn poll(&self, id: u64) -> Result<u32> {
        let fd = self.find(id)?;
        if fd.expiration_count > 0 {
            Ok(0x01) // POLLIN
        } else {
            Ok(0)
        }
    }

    // ---------------------------------------------------------------
    // Close / cleanup
    // ---------------------------------------------------------------

    /// Close a timerfd by ID.
    fn close(&mut self, id: u64) -> Result<()> {
        let fd = self.find_mut(id)?;
        fd.active = false;
        fd.armed = false;
        fd.expiration_count = 0;
        fd.remaining_ns = 0;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Close all timerfds owned by the given PID.
    pub fn cleanup_pid(&mut self, pid: u64) {
        for slot in self.timers.iter_mut() {
            if slot.active && slot.owner_pid == pid {
                slot.active = false;
                slot.armed = false;
                slot.expiration_count = 0;
                slot.remaining_ns = 0;
                self.count = self.count.saturating_sub(1);
            }
        }
    }

    // ---------------------------------------------------------------
    // Timer tick
    // ---------------------------------------------------------------

    /// Advance all armed timers by `elapsed_ns` nanoseconds.
    ///
    /// Expired timers increment their expiration counter. Periodic
    /// timers are re-armed; one-shot timers are disarmed.
    pub fn tick(&mut self, elapsed_ns: u64) {
        for slot in self.timers.iter_mut() {
            if !slot.active || !slot.armed {
                continue;
            }

            if elapsed_ns >= slot.remaining_ns {
                // Timer expired.
                slot.expiration_count = slot.expiration_count.saturating_add(1);

                // Check for periodic re-arm.
                let interval_nanos = slot.spec.it_interval.to_nanos();
                match interval_nanos {
                    Some(ns) if ns > 0 => {
                        let overshoot = elapsed_ns - slot.remaining_ns;
                        let period = ns as u64;
                        if overshoot >= period {
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
}

impl Default for TimerfdRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Syscall handlers
// ---------------------------------------------------------------------------

/// `timerfd_create(2)` — create a new timerfd.
///
/// # Arguments
///
/// * `registry`  — The global timerfd registry.
/// * `clock_id`  — Clock source (0=REALTIME, 1=MONOTONIC, 7=BOOTTIME, etc.).
/// * `flags`     — `TFD_CLOEXEC` and/or `TFD_NONBLOCK`.
/// * `pid`       — Calling process ID.
///
/// # Returns
///
/// The timerfd ID on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Invalid clock ID or unknown flags.
/// * [`Error::OutOfMemory`] — Registry is full.
pub fn sys_timerfd_create(
    registry: &mut TimerfdRegistry,
    clock_id: i32,
    flags: u32,
    pid: u64,
) -> Result<u64> {
    if (flags & !TFD_CREATE_VALID) != 0 {
        return Err(Error::InvalidArgument);
    }

    let clk = TimerfdClockId::from_i32(clock_id).ok_or(Error::InvalidArgument)?;
    registry.create(clk, flags, pid)
}

/// `timerfd_settime(2)` — arm or disarm a timerfd.
///
/// # Arguments
///
/// * `registry`  — The global timerfd registry.
/// * `id`        — Timerfd ID from `timerfd_create`.
/// * `flags`     — `TFD_TIMER_ABSTIME` and/or `TFD_TIMER_CANCEL_ON_SET`.
/// * `new_value` — New timer specification.
///
/// # Returns
///
/// The previous timer specification.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Invalid flags or invalid timespec values.
/// * [`Error::NotFound`] — No timerfd with the given ID.
pub fn sys_timerfd_settime(
    registry: &mut TimerfdRegistry,
    id: u64,
    flags: u32,
    new_value: &TimerfdItimerspec,
) -> Result<TimerfdItimerspec> {
    if (flags & !TFD_SETTIME_VALID) != 0 {
        return Err(Error::InvalidArgument);
    }

    if !new_value.is_valid() {
        return Err(Error::InvalidArgument);
    }

    registry.settime(id, flags, new_value)
}

/// `timerfd_gettime(2)` — query remaining time on a timerfd.
///
/// # Arguments
///
/// * `registry` — The global timerfd registry.
/// * `id`       — Timerfd ID.
///
/// # Returns
///
/// The current timer specification with `it_value` reflecting
/// the remaining time.
///
/// # Errors
///
/// * [`Error::NotFound`] — No timerfd with the given ID.
pub fn sys_timerfd_gettime(registry: &TimerfdRegistry, id: u64) -> Result<TimerfdItimerspec> {
    registry.gettime(id)
}

/// Read the expiration counter from a timerfd.
///
/// Returns the number of expirations since the last read and resets
/// the counter.
///
/// # Errors
///
/// * [`Error::WouldBlock`] — No expirations pending.
/// * [`Error::NotFound`] — No timerfd with the given ID.
pub fn sys_timerfd_read(registry: &mut TimerfdRegistry, id: u64) -> Result<u64> {
    registry.read(id)
}

/// Poll a timerfd for readiness.
///
/// Returns a bitmask where bit 0 indicates data is available for reading.
///
/// # Errors
///
/// * [`Error::NotFound`] — No timerfd with the given ID.
pub fn sys_timerfd_poll(registry: &TimerfdRegistry, id: u64) -> Result<u32> {
    registry.poll(id)
}

/// Close a timerfd.
///
/// # Errors
///
/// * [`Error::NotFound`] — No timerfd with the given ID.
pub fn sys_timerfd_close(registry: &mut TimerfdRegistry, id: u64) -> Result<()> {
    registry.close(id)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_monotonic_timer() {
        let mut r = TimerfdRegistry::new();
        let id = sys_timerfd_create(&mut r, 1, 0, 100);
        assert!(id.is_ok());
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn create_realtime_timer() {
        let mut r = TimerfdRegistry::new();
        let id = sys_timerfd_create(&mut r, 0, TFD_CLOEXEC, 100);
        assert!(id.is_ok());
    }

    #[test]
    fn create_invalid_clock_rejected() {
        let mut r = TimerfdRegistry::new();
        assert_eq!(
            sys_timerfd_create(&mut r, 99, 0, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn create_invalid_flags_rejected() {
        let mut r = TimerfdRegistry::new();
        assert_eq!(
            sys_timerfd_create(&mut r, 1, 0xFFFF, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn settime_arms_timer() {
        let mut r = TimerfdRegistry::new();
        let id = sys_timerfd_create(&mut r, 1, 0, 1).unwrap();
        let spec = TimerfdItimerspec::new(TimerfdTimespec::zero(), TimerfdTimespec::new(1, 0));
        let old = sys_timerfd_settime(&mut r, id, 0, &spec);
        assert!(old.is_ok());
        // Timer should now be armed.
        let fd = r.find(id).unwrap();
        assert!(fd.armed());
    }

    #[test]
    fn settime_disarms_with_zero() {
        let mut r = TimerfdRegistry::new();
        let id = sys_timerfd_create(&mut r, 1, 0, 1).unwrap();
        let spec = TimerfdItimerspec::new(TimerfdTimespec::zero(), TimerfdTimespec::new(5, 0));
        let _ = sys_timerfd_settime(&mut r, id, 0, &spec);
        // Disarm.
        let zero = TimerfdItimerspec::zero();
        let _ = sys_timerfd_settime(&mut r, id, 0, &zero);
        let fd = r.find(id).unwrap();
        assert!(!fd.armed());
    }

    #[test]
    fn settime_invalid_timespec_rejected() {
        let mut r = TimerfdRegistry::new();
        let id = sys_timerfd_create(&mut r, 1, 0, 1).unwrap();
        let bad = TimerfdItimerspec::new(TimerfdTimespec::zero(), TimerfdTimespec::new(0, -1));
        assert_eq!(
            sys_timerfd_settime(&mut r, id, 0, &bad),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn settime_invalid_flags_rejected() {
        let mut r = TimerfdRegistry::new();
        let id = sys_timerfd_create(&mut r, 1, 0, 1).unwrap();
        let spec = TimerfdItimerspec::new(TimerfdTimespec::zero(), TimerfdTimespec::new(1, 0));
        assert_eq!(
            sys_timerfd_settime(&mut r, id, 0xFFFF, &spec),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn gettime_returns_remaining() {
        let mut r = TimerfdRegistry::new();
        let id = sys_timerfd_create(&mut r, 1, 0, 1).unwrap();
        let spec = TimerfdItimerspec::new(TimerfdTimespec::zero(), TimerfdTimespec::new(10, 0));
        let _ = sys_timerfd_settime(&mut r, id, 0, &spec);
        let gt = sys_timerfd_gettime(&r, id).unwrap();
        assert!(!gt.it_value.is_zero());
    }

    #[test]
    fn gettime_disarmed_is_zero() {
        let mut r = TimerfdRegistry::new();
        let id = sys_timerfd_create(&mut r, 1, 0, 1).unwrap();
        let gt = sys_timerfd_gettime(&r, id).unwrap();
        assert!(gt.it_value.is_zero());
        assert!(gt.it_interval.is_zero());
    }

    #[test]
    fn read_returns_expiration_count() {
        let mut r = TimerfdRegistry::new();
        let id = sys_timerfd_create(&mut r, 1, 0, 1).unwrap();
        let spec = TimerfdItimerspec::new(TimerfdTimespec::zero(), TimerfdTimespec::new(0, 100));
        let _ = sys_timerfd_settime(&mut r, id, 0, &spec);
        // Tick past expiration.
        r.tick(200);
        let count = sys_timerfd_read(&mut r, id).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn read_no_expirations_wouldblock() {
        let mut r = TimerfdRegistry::new();
        let id = sys_timerfd_create(&mut r, 1, TFD_NONBLOCK, 1).unwrap();
        let spec = TimerfdItimerspec::new(TimerfdTimespec::zero(), TimerfdTimespec::new(10, 0));
        let _ = sys_timerfd_settime(&mut r, id, 0, &spec);
        assert_eq!(sys_timerfd_read(&mut r, id), Err(Error::WouldBlock));
    }

    #[test]
    fn periodic_timer_rearms() {
        let mut r = TimerfdRegistry::new();
        let id = sys_timerfd_create(&mut r, 1, 0, 1).unwrap();
        let spec = TimerfdItimerspec::new(
            TimerfdTimespec::new(0, 100), // interval
            TimerfdTimespec::new(0, 100), // initial
        );
        let _ = sys_timerfd_settime(&mut r, id, 0, &spec);
        // Tick twice the interval.
        r.tick(250);
        let count = sys_timerfd_read(&mut r, id).unwrap();
        assert!(count >= 2);
        // Timer should still be armed.
        let fd = r.find(id).unwrap();
        assert!(fd.armed());
    }

    #[test]
    fn oneshot_timer_disarms() {
        let mut r = TimerfdRegistry::new();
        let id = sys_timerfd_create(&mut r, 1, 0, 1).unwrap();
        let spec = TimerfdItimerspec::new(
            TimerfdTimespec::zero(),      // no interval
            TimerfdTimespec::new(0, 100), // initial
        );
        let _ = sys_timerfd_settime(&mut r, id, 0, &spec);
        r.tick(200);
        let _ = sys_timerfd_read(&mut r, id);
        let fd = r.find(id).unwrap();
        assert!(!fd.armed());
    }

    #[test]
    fn close_timerfd() {
        let mut r = TimerfdRegistry::new();
        let id = sys_timerfd_create(&mut r, 1, 0, 1).unwrap();
        assert_eq!(r.count(), 1);
        assert_eq!(sys_timerfd_close(&mut r, id), Ok(()));
        assert_eq!(r.count(), 0);
    }

    #[test]
    fn close_unknown_id_fails() {
        let mut r = TimerfdRegistry::new();
        assert_eq!(sys_timerfd_close(&mut r, 999), Err(Error::NotFound));
    }

    #[test]
    fn poll_no_expirations() {
        let mut r = TimerfdRegistry::new();
        let id = sys_timerfd_create(&mut r, 1, 0, 1).unwrap();
        assert_eq!(sys_timerfd_poll(&r, id), Ok(0));
    }

    #[test]
    fn poll_after_expiration() {
        let mut r = TimerfdRegistry::new();
        let id = sys_timerfd_create(&mut r, 1, 0, 1).unwrap();
        let spec = TimerfdItimerspec::new(TimerfdTimespec::zero(), TimerfdTimespec::new(0, 50));
        let _ = sys_timerfd_settime(&mut r, id, 0, &spec);
        r.tick(100);
        assert_eq!(sys_timerfd_poll(&r, id), Ok(0x01));
    }

    #[test]
    fn cleanup_pid_removes_timers() {
        let mut r = TimerfdRegistry::new();
        let _ = sys_timerfd_create(&mut r, 1, 0, 42).unwrap();
        let _ = sys_timerfd_create(&mut r, 0, 0, 42).unwrap();
        let _ = sys_timerfd_create(&mut r, 1, 0, 99).unwrap();
        assert_eq!(r.count(), 3);
        r.cleanup_pid(42);
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn abstime_flag_accepted() {
        let mut r = TimerfdRegistry::new();
        let id = sys_timerfd_create(&mut r, 1, 0, 1).unwrap();
        let spec = TimerfdItimerspec::new(TimerfdTimespec::zero(), TimerfdTimespec::new(100, 0));
        let result = sys_timerfd_settime(&mut r, id, TFD_TIMER_ABSTIME, &spec);
        assert!(result.is_ok());
    }

    #[test]
    fn timespec_from_nanos() {
        let ts = TimerfdTimespec::from_nanos(2_500_000_000);
        assert_eq!(ts.tv_sec, 2);
        assert_eq!(ts.tv_nsec, 500_000_000);
    }

    #[test]
    fn timespec_to_nanos() {
        let ts = TimerfdTimespec::new(1, 500_000_000);
        assert_eq!(ts.to_nanos(), Some(1_500_000_000));
    }
}
