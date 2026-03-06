// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Classic UNIX interval timers — `ITIMER_REAL`, `ITIMER_VIRTUAL`,
//! `ITIMER_PROF`.
//!
//! Implements the BSD/POSIX `getitimer(2)` / `setitimer(2)` /
//! `alarm(2)` semantics. Each process may have up to three
//! interval timers:
//!
//! - **ITIMER_REAL** — counts wall-clock time, delivers `SIGALRM`.
//! - **ITIMER_VIRTUAL** — counts user-mode CPU time, delivers
//!   `SIGVTALRM`.
//! - **ITIMER_PROF** — counts user+kernel CPU time, delivers
//!   `SIGPROF`.
//!
//! # Architecture
//!
//! ```text
//! ItimerManager
//!  ├── processes[MAX_PROCESSES]
//!  │    └── ProcessItimers
//!  │         ├── real:    ItimerState  (ITIMER_REAL)
//!  │         ├── virtual_: ItimerState (ITIMER_VIRTUAL)
//!  │         └── prof:    ItimerState  (ITIMER_PROF)
//!  └── stats: ItimerStats
//! ```
//!
//! # Timer Tick Processing
//!
//! `tick_real(now_ns)` — check ITIMER_REAL timers against
//! wall-clock time. `tick_cpu(pid, user_ns, sys_ns)` — credit
//! CPU time to ITIMER_VIRTUAL and ITIMER_PROF for the given
//! process.
//!
//! Reference: Linux `kernel/time/itimer.c`,
//! `include/linux/sched/signal.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum processes with itimer state.
const MAX_PROCESSES: usize = 256;

/// Nanoseconds per microsecond.
const NANOS_PER_USEC: u64 = 1_000;

/// Microseconds per second.
const USECS_PER_SEC: u64 = 1_000_000;

/// Nanoseconds per second.
const NANOS_PER_SEC: u64 = 1_000_000_000;

// ── itimer which constants ──────────────────────────────────

/// ITIMER_REAL — wall-clock timer, delivers SIGALRM.
pub const ITIMER_REAL: u32 = 0;

/// ITIMER_VIRTUAL — user-CPU-time timer, delivers SIGVTALRM.
pub const ITIMER_VIRTUAL: u32 = 1;

/// ITIMER_PROF — user+kernel CPU-time timer, delivers SIGPROF.
pub const ITIMER_PROF: u32 = 2;

// ── Signal numbers ──────────────────────────────────────────

/// SIGALRM (default for ITIMER_REAL).
const SIGALRM: u32 = 14;

/// SIGVTALRM (for ITIMER_VIRTUAL).
const SIGVTALRM: u32 = 26;

/// SIGPROF (for ITIMER_PROF).
const SIGPROF: u32 = 27;

// ══════════════════════════════════════════════════════════════
// Timeval
// ══════════════════════════════════════════════════════════════

/// BSD `struct timeval` — seconds + microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct Timeval {
    /// Seconds.
    pub tv_sec: i64,
    /// Microseconds (0..999_999).
    pub tv_usec: i64,
}

impl Timeval {
    /// Create a zero timeval.
    pub const fn zero() -> Self {
        Self {
            tv_sec: 0,
            tv_usec: 0,
        }
    }

    /// Create from seconds and microseconds.
    pub const fn new(sec: i64, usec: i64) -> Self {
        Self {
            tv_sec: sec,
            tv_usec: usec,
        }
    }

    /// Return true if this timeval represents zero duration.
    pub const fn is_zero(&self) -> bool {
        self.tv_sec == 0 && self.tv_usec == 0
    }

    /// Convert to total nanoseconds.
    pub fn to_nanos(&self) -> i64 {
        self.tv_sec
            .saturating_mul(NANOS_PER_SEC as i64)
            .saturating_add(self.tv_usec.saturating_mul(NANOS_PER_USEC as i64))
    }

    /// Create from total nanoseconds.
    pub fn from_nanos(ns: i64) -> Self {
        if ns <= 0 {
            return Self::zero();
        }
        let total_usec = ns / NANOS_PER_USEC as i64;
        Self {
            tv_sec: total_usec / USECS_PER_SEC as i64,
            tv_usec: total_usec % USECS_PER_SEC as i64,
        }
    }

    /// Validate that `tv_usec` is in range.
    pub fn validate(&self) -> Result<()> {
        if self.tv_usec < 0 || self.tv_usec >= USECS_PER_SEC as i64 {
            return Err(Error::InvalidArgument);
        }
        if self.tv_sec < 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ══════════════════════════════════════════════════════════════
// Itimerval
// ══════════════════════════════════════════════════════════════

/// BSD `struct itimerval` — interval + current value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct Itimerval {
    /// Reload interval (zero = one-shot).
    pub it_interval: Timeval,
    /// Current value (time remaining).
    pub it_value: Timeval,
}

impl Itimerval {
    /// Create a zeroed itimerval (disarmed).
    pub const fn zero() -> Self {
        Self {
            it_interval: Timeval::zero(),
            it_value: Timeval::zero(),
        }
    }

    /// Validate both fields.
    pub fn validate(&self) -> Result<()> {
        self.it_interval.validate()?;
        self.it_value.validate()
    }
}

// ══════════════════════════════════════════════════════════════
// ItimerState — one timer instance
// ══════════════════════════════════════════════════════════════

/// Internal state for a single interval timer.
#[derive(Debug, Clone, Copy)]
struct ItimerState {
    /// Whether the timer is armed.
    armed: bool,
    /// Absolute expiry time (nanoseconds in the timer's time
    /// base).
    expiry_ns: i64,
    /// Reload interval (nanoseconds). Zero = one-shot.
    interval_ns: i64,
    /// Signal number to deliver on expiration.
    signo: u32,
    /// Whether a signal delivery is pending.
    signal_pending: bool,
}

impl ItimerState {
    /// Create a disarmed timer state.
    const fn new(signo: u32) -> Self {
        Self {
            armed: false,
            expiry_ns: 0,
            interval_ns: 0,
            signo,
            signal_pending: false,
        }
    }

    /// Compute remaining time in nanoseconds.
    fn remaining_ns(&self, now_ns: i64) -> i64 {
        if !self.armed {
            return 0;
        }
        let diff = self.expiry_ns.saturating_sub(now_ns);
        if diff <= 0 { 0 } else { diff }
    }
}

// ══════════════════════════════════════════════════════════════
// ProcessItimers — per-process timer set
// ══════════════════════════════════════════════════════════════

/// Per-process set of the three classic interval timers.
struct ProcessItimers {
    /// Process ID.
    pid: u64,
    /// ITIMER_REAL timer state.
    real: ItimerState,
    /// ITIMER_VIRTUAL timer state.
    virtual_timer: ItimerState,
    /// ITIMER_PROF timer state.
    prof: ItimerState,
    /// Whether this slot is in use.
    active: bool,
    /// Accumulated user-mode CPU nanoseconds.
    user_cpu_ns: i64,
    /// Accumulated system-mode CPU nanoseconds.
    sys_cpu_ns: i64,
}

impl ProcessItimers {
    /// Create an empty slot.
    const fn empty() -> Self {
        Self {
            pid: 0,
            real: ItimerState::new(SIGALRM),
            virtual_timer: ItimerState::new(SIGVTALRM),
            prof: ItimerState::new(SIGPROF),
            active: false,
            user_cpu_ns: 0,
            sys_cpu_ns: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// ItimerExpiry — output from tick
// ══════════════════════════════════════════════════════════════

/// Describes an itimer that expired during a tick.
#[derive(Debug, Clone, Copy, Default)]
pub struct ItimerExpiry {
    /// Process ID.
    pub pid: u64,
    /// Which timer (ITIMER_REAL, etc.).
    pub which: u32,
    /// Signal number to deliver.
    pub signo: u32,
}

// ══════════════════════════════════════════════════════════════
// ItimerStats
// ══════════════════════════════════════════════════════════════

/// Statistics for the itimer subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct ItimerStats {
    /// Total setitimer calls.
    pub set_count: u64,
    /// Total getitimer calls.
    pub get_count: u64,
    /// Total alarm() calls.
    pub alarm_count: u64,
    /// Total ITIMER_REAL expirations.
    pub real_expirations: u64,
    /// Total ITIMER_VIRTUAL expirations.
    pub virtual_expirations: u64,
    /// Total ITIMER_PROF expirations.
    pub prof_expirations: u64,
}

// ══════════════════════════════════════════════════════════════
// ItimerManager
// ══════════════════════════════════════════════════════════════

/// Manages classic UNIX interval timers for all processes.
pub struct ItimerManager {
    /// Per-process itimer state.
    processes: [ProcessItimers; MAX_PROCESSES],
    /// Statistics.
    stats: ItimerStats,
}

impl Default for ItimerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ItimerManager {
    /// Create a new itimer manager.
    pub const fn new() -> Self {
        Self {
            processes: [const { ProcessItimers::empty() }; MAX_PROCESSES],
            stats: ItimerStats {
                set_count: 0,
                get_count: 0,
                alarm_count: 0,
                real_expirations: 0,
                virtual_expirations: 0,
                prof_expirations: 0,
            },
        }
    }

    /// Return statistics.
    pub fn stats(&self) -> &ItimerStats {
        &self.stats
    }

    /// Ensure a process has an itimer slot allocated.
    fn ensure_slot(&mut self, pid: u64) -> Result<usize> {
        // Find existing.
        if let Some(pos) = self.processes.iter().position(|p| p.active && p.pid == pid) {
            return Ok(pos);
        }

        // Allocate new.
        let pos = self
            .processes
            .iter()
            .position(|p| !p.active)
            .ok_or(Error::OutOfMemory)?;

        self.processes[pos].pid = pid;
        self.processes[pos].active = true;
        self.processes[pos].user_cpu_ns = 0;
        self.processes[pos].sys_cpu_ns = 0;
        Ok(pos)
    }

    /// Resolve `which` to a mutable reference to the correct
    /// ItimerState within a ProcessItimers.
    fn get_timer_mut(proc_state: &mut ProcessItimers, which: u32) -> Result<&mut ItimerState> {
        match which {
            ITIMER_REAL => Ok(&mut proc_state.real),
            ITIMER_VIRTUAL => Ok(&mut proc_state.virtual_timer),
            ITIMER_PROF => Ok(&mut proc_state.prof),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Resolve `which` to an immutable reference.
    fn get_timer(proc_state: &ProcessItimers, which: u32) -> Result<&ItimerState> {
        match which {
            ITIMER_REAL => Ok(&proc_state.real),
            ITIMER_VIRTUAL => Ok(&proc_state.virtual_timer),
            ITIMER_PROF => Ok(&proc_state.prof),
            _ => Err(Error::InvalidArgument),
        }
    }

    // ── getitimer ───────────────────────────────────────────

    /// `getitimer(which)` — return the current timer value.
    ///
    /// For `ITIMER_REAL`, `now_ns` is wall-clock nanoseconds.
    /// For `ITIMER_VIRTUAL`, it is the process user CPU nanos.
    /// For `ITIMER_PROF`, it is user + system CPU nanos.
    pub fn getitimer(&mut self, pid: u64, which: u32, now_ns: i64) -> Result<Itimerval> {
        self.stats.get_count += 1;

        let pos = self.processes.iter().position(|p| p.active && p.pid == pid);

        let pos = match pos {
            Some(p) => p,
            None => {
                // No timers set for this process.
                return Ok(Itimerval::zero());
            }
        };

        let proc_state = &self.processes[pos];
        let timer = Self::get_timer(proc_state, which)?;

        let effective_now = match which {
            ITIMER_REAL => now_ns,
            ITIMER_VIRTUAL => proc_state.user_cpu_ns,
            ITIMER_PROF => proc_state.user_cpu_ns.saturating_add(proc_state.sys_cpu_ns),
            _ => return Err(Error::InvalidArgument),
        };

        Ok(Itimerval {
            it_value: Timeval::from_nanos(timer.remaining_ns(effective_now)),
            it_interval: Timeval::from_nanos(timer.interval_ns),
        })
    }

    // ── setitimer ───────────────────────────────────────────

    /// `setitimer(which, new_value)` — set the timer and return
    /// the old value.
    pub fn setitimer(
        &mut self,
        pid: u64,
        which: u32,
        new_value: &Itimerval,
        now_ns: i64,
    ) -> Result<Itimerval> {
        new_value.validate()?;
        self.stats.set_count += 1;

        let pos = self.ensure_slot(pid)?;
        let proc_state = &self.processes[pos];

        let effective_now = match which {
            ITIMER_REAL => now_ns,
            ITIMER_VIRTUAL => proc_state.user_cpu_ns,
            ITIMER_PROF => proc_state.user_cpu_ns.saturating_add(proc_state.sys_cpu_ns),
            _ => return Err(Error::InvalidArgument),
        };

        let timer = Self::get_timer(&self.processes[pos], which)?;
        let old = Itimerval {
            it_value: Timeval::from_nanos(timer.remaining_ns(effective_now)),
            it_interval: Timeval::from_nanos(timer.interval_ns),
        };

        let timer = Self::get_timer_mut(&mut self.processes[pos], which)?;
        if new_value.it_value.is_zero() {
            timer.armed = false;
            timer.expiry_ns = 0;
            timer.interval_ns = 0;
            timer.signal_pending = false;
        } else {
            let value_ns = new_value.it_value.to_nanos();
            timer.expiry_ns = effective_now.saturating_add(value_ns);
            timer.interval_ns = new_value.it_interval.to_nanos();
            timer.armed = true;
            timer.signal_pending = false;
        }

        Ok(old)
    }

    // ── alarm ───────────────────────────────────────────────

    /// `alarm(seconds)` — set ITIMER_REAL to fire after
    /// `seconds` seconds. Returns the seconds remaining on
    /// the previous alarm (0 if none).
    pub fn alarm(&mut self, pid: u64, seconds: u32, now_ns: i64) -> Result<u32> {
        self.stats.alarm_count += 1;

        let pos = self.ensure_slot(pid)?;
        let timer = &self.processes[pos].real;
        let old_remaining = timer.remaining_ns(now_ns);
        let old_secs = if old_remaining > 0 {
            (old_remaining as u64).div_ceil(NANOS_PER_SEC) as u32
        } else {
            0
        };

        let timer = &mut self.processes[pos].real;
        if seconds == 0 {
            timer.armed = false;
            timer.expiry_ns = 0;
            timer.interval_ns = 0;
            timer.signal_pending = false;
        } else {
            let ns = (seconds as i64).saturating_mul(NANOS_PER_SEC as i64);
            timer.expiry_ns = now_ns.saturating_add(ns);
            timer.interval_ns = 0; // alarm() is one-shot
            timer.armed = true;
            timer.signal_pending = false;
        }

        Ok(old_secs)
    }

    // ── tick_real ───────────────────────────────────────────

    /// Check all ITIMER_REAL timers against wall-clock time.
    ///
    /// Returns the number of expired timers. Expired timer
    /// information is written to `expired_out`.
    pub fn tick_real(
        &mut self,
        now_ns: i64,
        expired_out: &mut [ItimerExpiry],
        max_expired: usize,
    ) -> usize {
        let mut count = 0;
        let limit = max_expired.min(expired_out.len());

        for proc_state in &mut self.processes {
            if !proc_state.active || !proc_state.real.armed {
                continue;
            }
            if now_ns < proc_state.real.expiry_ns {
                continue;
            }

            // Expired.
            proc_state.real.signal_pending = true;
            self.stats.real_expirations += 1;

            if count < limit {
                expired_out[count] = ItimerExpiry {
                    pid: proc_state.pid,
                    which: ITIMER_REAL,
                    signo: proc_state.real.signo,
                };
                count += 1;
            }

            // Re-arm or disarm.
            if proc_state.real.interval_ns > 0 {
                let elapsed = now_ns - proc_state.real.expiry_ns;
                let periods = (elapsed / proc_state.real.interval_ns) + 1;
                proc_state.real.expiry_ns += periods * proc_state.real.interval_ns;
            } else {
                proc_state.real.armed = false;
            }
        }

        count
    }

    // ── tick_cpu ────────────────────────────────────────────

    /// Credit CPU time to a process and check ITIMER_VIRTUAL
    /// and ITIMER_PROF timers.
    pub fn tick_cpu(
        &mut self,
        pid: u64,
        user_ns: i64,
        sys_ns: i64,
        expired_out: &mut [ItimerExpiry],
        max_expired: usize,
    ) -> usize {
        let pos = match self.processes.iter().position(|p| p.active && p.pid == pid) {
            Some(p) => p,
            None => return 0,
        };

        let proc_state = &mut self.processes[pos];
        proc_state.user_cpu_ns = proc_state.user_cpu_ns.saturating_add(user_ns);
        proc_state.sys_cpu_ns = proc_state.sys_cpu_ns.saturating_add(sys_ns);

        let mut count = 0;
        let limit = max_expired.min(expired_out.len());

        // Check ITIMER_VIRTUAL (user CPU time only).
        if proc_state.virtual_timer.armed {
            let now = proc_state.user_cpu_ns;
            if now >= proc_state.virtual_timer.expiry_ns {
                proc_state.virtual_timer.signal_pending = true;
                self.stats.virtual_expirations += 1;

                if count < limit {
                    expired_out[count] = ItimerExpiry {
                        pid: proc_state.pid,
                        which: ITIMER_VIRTUAL,
                        signo: proc_state.virtual_timer.signo,
                    };
                    count += 1;
                }

                if proc_state.virtual_timer.interval_ns > 0 {
                    let elapsed = now - proc_state.virtual_timer.expiry_ns;
                    let periods = (elapsed / proc_state.virtual_timer.interval_ns) + 1;
                    proc_state.virtual_timer.expiry_ns +=
                        periods * proc_state.virtual_timer.interval_ns;
                } else {
                    proc_state.virtual_timer.armed = false;
                }
            }
        }

        // Check ITIMER_PROF (user + kernel CPU time).
        if proc_state.prof.armed {
            let now = proc_state.user_cpu_ns.saturating_add(proc_state.sys_cpu_ns);
            if now >= proc_state.prof.expiry_ns {
                proc_state.prof.signal_pending = true;
                self.stats.prof_expirations += 1;

                if count < limit {
                    expired_out[count] = ItimerExpiry {
                        pid: proc_state.pid,
                        which: ITIMER_PROF,
                        signo: proc_state.prof.signo,
                    };
                    count += 1;
                }

                if proc_state.prof.interval_ns > 0 {
                    let elapsed = now - proc_state.prof.expiry_ns;
                    let periods = (elapsed / proc_state.prof.interval_ns) + 1;
                    proc_state.prof.expiry_ns += periods * proc_state.prof.interval_ns;
                } else {
                    proc_state.prof.armed = false;
                }
            }
        }

        count
    }

    // ── cleanup ─────────────────────────────────────────────

    /// Remove all itimer state for a process (on exit).
    pub fn remove_process(&mut self, pid: u64) -> Result<()> {
        let pos = self
            .processes
            .iter()
            .position(|p| p.active && p.pid == pid)
            .ok_or(Error::NotFound)?;

        self.processes[pos] = ProcessItimers::empty();
        Ok(())
    }
}
