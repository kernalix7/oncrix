// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Process resource usage accounting (POSIX `getrusage` / `times`).
//!
//! Provides [`Rusage`] (POSIX `struct rusage`), [`ProcessAccounting`]
//! for per-process resource tracking, and [`ProcessTimes`] for the
//! `times()` syscall. All public recording methods use saturating
//! arithmetic to avoid overflow in long-running processes.
//!
//! # POSIX Reference
//!
//! - `getrusage()`: IEEE Std 1003.1-2024, XSH §getrusage
//! - `times()`: IEEE Std 1003.1-2024, XSH §times

/// POSIX `struct timeval` — time with microsecond precision.
///
/// Used within [`Rusage`] for CPU time accounting (`ru_utime`,
/// `ru_stime`). Both fields are signed to match the POSIX ABI.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Timeval {
    /// Seconds component.
    pub tv_sec: i64,
    /// Microseconds component (0..999_999).
    pub tv_usec: i64,
}

impl Timeval {
    /// Create a new `Timeval` from seconds and microseconds.
    pub const fn new(tv_sec: i64, tv_usec: i64) -> Self {
        Self { tv_sec, tv_usec }
    }

    /// Create a zero-valued `Timeval`.
    pub const fn zero() -> Self {
        Self {
            tv_sec: 0,
            tv_usec: 0,
        }
    }

    /// Add another `Timeval` to this one using saturating arithmetic.
    ///
    /// Normalizes the result so that `tv_usec` is in `0..999_999`.
    pub fn saturating_add(&mut self, other: &Timeval) {
        let usec = self.tv_usec.saturating_add(other.tv_usec);
        let carry = usec / 1_000_000;
        self.tv_usec = usec % 1_000_000;
        self.tv_sec = self
            .tv_sec
            .saturating_add(other.tv_sec)
            .saturating_add(carry);
    }
}

/// POSIX `struct rusage` — resource usage statistics.
///
/// Returned by `getrusage()` to report how much CPU time and other
/// resources a process (or its children) has consumed. All counters
/// are cumulative since process creation.
///
/// # Layout
///
/// The `#[repr(C)]` layout matches the Linux x86_64 ABI so that
/// `copy_to_user` can write this struct directly to user space.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Rusage {
    /// User CPU time consumed.
    pub ru_utime: Timeval,
    /// System CPU time consumed.
    pub ru_stime: Timeval,
    /// Maximum resident set size (in kilobytes).
    pub ru_maxrss: i64,
    /// Page reclaims (minor page faults — no I/O).
    pub ru_minflt: i64,
    /// Page faults (major page faults — required I/O).
    pub ru_majflt: i64,
    /// Block input operations.
    pub ru_inblock: i64,
    /// Block output operations.
    pub ru_oublock: i64,
    /// Voluntary context switches.
    pub ru_nvcsw: i64,
    /// Involuntary context switches.
    pub ru_nivcsw: i64,
    /// Signals received.
    pub ru_nsignals: i64,
    /// Swaps.
    pub ru_nswap: i64,
    /// IPC messages sent.
    pub ru_msgsnd: i64,
    /// IPC messages received.
    pub ru_msgrcv: i64,
}

impl Rusage {
    /// Create a zeroed `Rusage`.
    pub const fn zero() -> Self {
        Self {
            ru_utime: Timeval::zero(),
            ru_stime: Timeval::zero(),
            ru_maxrss: 0,
            ru_minflt: 0,
            ru_majflt: 0,
            ru_inblock: 0,
            ru_oublock: 0,
            ru_nvcsw: 0,
            ru_nivcsw: 0,
            ru_nsignals: 0,
            ru_nswap: 0,
            ru_msgsnd: 0,
            ru_msgrcv: 0,
        }
    }

    /// Accumulate another `Rusage` into this one (saturating).
    ///
    /// Used to merge a child's usage into `children_usage` after
    /// `wait4()` reaps the child.
    pub fn accumulate(&mut self, other: &Rusage) {
        self.ru_utime.saturating_add(&other.ru_utime);
        self.ru_stime.saturating_add(&other.ru_stime);
        if other.ru_maxrss > self.ru_maxrss {
            self.ru_maxrss = other.ru_maxrss;
        }
        self.ru_minflt = self.ru_minflt.saturating_add(other.ru_minflt);
        self.ru_majflt = self.ru_majflt.saturating_add(other.ru_majflt);
        self.ru_inblock = self.ru_inblock.saturating_add(other.ru_inblock);
        self.ru_oublock = self.ru_oublock.saturating_add(other.ru_oublock);
        self.ru_nvcsw = self.ru_nvcsw.saturating_add(other.ru_nvcsw);
        self.ru_nivcsw = self.ru_nivcsw.saturating_add(other.ru_nivcsw);
        self.ru_nsignals = self.ru_nsignals.saturating_add(other.ru_nsignals);
        self.ru_nswap = self.ru_nswap.saturating_add(other.ru_nswap);
        self.ru_msgsnd = self.ru_msgsnd.saturating_add(other.ru_msgsnd);
        self.ru_msgrcv = self.ru_msgrcv.saturating_add(other.ru_msgrcv);
    }
}

// ── Syscall constants ────────────────────────────────────────────

/// `RUSAGE_SELF` — Return resource usage for the calling process.
pub const RUSAGE_SELF: i32 = 0;

/// `RUSAGE_CHILDREN` — Return resource usage for all waited children.
pub const RUSAGE_CHILDREN: i32 = -1;

/// `RUSAGE_THREAD` — Return resource usage for the calling thread.
pub const RUSAGE_THREAD: i32 = 1;

/// Selector for `getrusage()` indicating whose usage to return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RusageWho {
    /// Return usage for the calling process itself.
    Self_ = 0,
    /// Return accumulated usage of waited children.
    Children = 1,
    /// Return usage for the calling thread only.
    Thread = 2,
}

impl RusageWho {
    /// Convert a raw `i32` (from the syscall argument) to a
    /// `RusageWho` variant.
    ///
    /// Returns `None` for unrecognised values.
    pub fn from_raw(raw: i32) -> Option<Self> {
        match raw {
            RUSAGE_SELF => Some(Self::Self_),
            RUSAGE_CHILDREN => Some(Self::Children),
            RUSAGE_THREAD => Some(Self::Thread),
            _ => None,
        }
    }
}

// ── Per-process accounting ──────────────────────────────────────

/// Per-process resource accounting state.
///
/// Embedded in each `Process` struct. The scheduler and fault
/// handlers call the `record_*` methods to update counters; the
/// `getrusage` syscall reads them via [`get_rusage`](Self::get_rusage).
#[derive(Debug, Clone)]
pub struct ProcessAccounting {
    /// Cumulative resource usage for this process.
    self_usage: Rusage,
    /// Accumulated usage from waited (reaped) children.
    children_usage: Rusage,
    /// Tick count when the process was created.
    start_tick: u64,
    /// Tick count when the process was last scheduled in.
    last_schedule_tick: u64,
}

impl ProcessAccounting {
    /// Create a new accounting state, recording the creation tick.
    pub const fn new(start_tick: u64) -> Self {
        Self {
            self_usage: Rusage::zero(),
            children_usage: Rusage::zero(),
            start_tick,
            last_schedule_tick: start_tick,
        }
    }

    /// Return the tick at which the process was created.
    pub fn start_tick(&self) -> u64 {
        self.start_tick
    }

    /// Return the tick of the last schedule-in event.
    pub fn last_schedule_tick(&self) -> u64 {
        self.last_schedule_tick
    }

    /// Update the last-scheduled tick (called on context switch in).
    pub fn set_last_schedule_tick(&mut self, tick: u64) {
        self.last_schedule_tick = tick;
    }

    /// Record a context switch (voluntary or involuntary).
    pub fn record_context_switch(&mut self, voluntary: bool) {
        if voluntary {
            self.self_usage.ru_nvcsw = self.self_usage.ru_nvcsw.saturating_add(1);
        } else {
            self.self_usage.ru_nivcsw = self.self_usage.ru_nivcsw.saturating_add(1);
        }
    }

    /// Record a page fault (minor or major).
    pub fn record_page_fault(&mut self, major: bool) {
        if major {
            self.self_usage.ru_majflt = self.self_usage.ru_majflt.saturating_add(1);
        } else {
            self.self_usage.ru_minflt = self.self_usage.ru_minflt.saturating_add(1);
        }
    }

    /// Record a block I/O operation (input or output).
    pub fn record_block_io(&mut self, input: bool) {
        if input {
            self.self_usage.ru_inblock = self.self_usage.ru_inblock.saturating_add(1);
        } else {
            self.self_usage.ru_oublock = self.self_usage.ru_oublock.saturating_add(1);
        }
    }

    /// Record a signal delivery.
    pub fn record_signal(&mut self) {
        self.self_usage.ru_nsignals = self.self_usage.ru_nsignals.saturating_add(1);
    }

    /// Record an IPC message (sent or received).
    pub fn record_ipc(&mut self, sent: bool) {
        if sent {
            self.self_usage.ru_msgsnd = self.self_usage.ru_msgsnd.saturating_add(1);
        } else {
            self.self_usage.ru_msgrcv = self.self_usage.ru_msgrcv.saturating_add(1);
        }
    }

    /// Update CPU time from tick counts.
    ///
    /// Converts `user_ticks` and `sys_ticks` to [`Timeval`] using
    /// the given `ticks_per_sec` frequency and adds them to the
    /// cumulative `ru_utime` / `ru_stime`.
    ///
    /// # Panics
    ///
    /// Does **not** panic. If `ticks_per_sec` is zero, the method
    /// returns without updating (avoids division by zero).
    pub fn update_cpu_time(&mut self, user_ticks: u64, sys_ticks: u64, ticks_per_sec: u64) {
        if ticks_per_sec == 0 {
            return;
        }
        let user_tv = ticks_to_timeval(user_ticks, ticks_per_sec);
        let sys_tv = ticks_to_timeval(sys_ticks, ticks_per_sec);
        self.self_usage.ru_utime.saturating_add(&user_tv);
        self.self_usage.ru_stime.saturating_add(&sys_tv);
    }

    /// Update the maximum resident set size if `current_rss_kb` is
    /// larger than the recorded maximum.
    pub fn update_maxrss(&mut self, current_rss_kb: i64) {
        if current_rss_kb > self.self_usage.ru_maxrss {
            self.self_usage.ru_maxrss = current_rss_kb;
        }
    }

    /// Retrieve resource usage for the given `who` selector.
    ///
    /// - `Self_` / `Thread` — returns `self_usage` (thread-level
    ///   granularity is not yet implemented; falls back to process).
    /// - `Children` — returns `children_usage`.
    pub fn get_rusage(&self, who: RusageWho) -> Rusage {
        match who {
            RusageWho::Self_ | RusageWho::Thread => self.self_usage,
            RusageWho::Children => self.children_usage,
        }
    }

    /// Accumulate a waited child's resource usage.
    ///
    /// Called by `wait4()` after reaping a child process. The
    /// child's own `self_usage` (and its `children_usage`) are
    /// merged into this process's `children_usage`.
    pub fn accumulate_child(&mut self, child_usage: &Rusage) {
        self.children_usage.accumulate(child_usage);
    }
}

// ── ProcessTimes (for `times()` syscall) ────────────────────────

/// Result of the `times()` syscall (POSIX `struct tms`).
///
/// All values are in clock ticks. The tick frequency is
/// system-dependent (`sysconf(_SC_CLK_TCK)`).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct ProcessTimes {
    /// User CPU time of the process (ticks).
    pub tms_utime: u64,
    /// System CPU time of the process (ticks).
    pub tms_stime: u64,
    /// User CPU time of waited children (ticks).
    pub tms_cutime: u64,
    /// System CPU time of waited children (ticks).
    pub tms_cstime: u64,
}

/// Convert a [`ProcessAccounting`] to [`ProcessTimes`] (tick-based).
///
/// Reverses the `Timeval → ticks` conversion so that `times()`
/// can return values in the expected clock-tick unit.
///
/// If `ticks_per_sec` is zero, all fields are returned as zero.
pub fn get_process_times(acct: &ProcessAccounting, ticks_per_sec: u64) -> ProcessTimes {
    if ticks_per_sec == 0 {
        return ProcessTimes::default();
    }
    let self_usage = acct.get_rusage(RusageWho::Self_);
    let child_usage = acct.get_rusage(RusageWho::Children);
    ProcessTimes {
        tms_utime: timeval_to_ticks(&self_usage.ru_utime, ticks_per_sec),
        tms_stime: timeval_to_ticks(&self_usage.ru_stime, ticks_per_sec),
        tms_cutime: timeval_to_ticks(&child_usage.ru_utime, ticks_per_sec),
        tms_cstime: timeval_to_ticks(&child_usage.ru_stime, ticks_per_sec),
    }
}

// ── Internal helpers ────────────────────────────────────────────

/// Convert a tick count to a [`Timeval`].
fn ticks_to_timeval(ticks: u64, ticks_per_sec: u64) -> Timeval {
    let secs = ticks / ticks_per_sec;
    let remainder = ticks % ticks_per_sec;
    // remainder * 1_000_000 / ticks_per_sec — use u128 to avoid
    // overflow on large remainder values.
    let usec = (remainder as u128).saturating_mul(1_000_000) / (ticks_per_sec as u128);
    Timeval {
        tv_sec: secs as i64,
        tv_usec: usec as i64,
    }
}

/// Convert a [`Timeval`] back to ticks.
fn timeval_to_ticks(tv: &Timeval, ticks_per_sec: u64) -> u64 {
    let sec_ticks = (tv.tv_sec as u64).saturating_mul(ticks_per_sec);
    // tv_usec * ticks_per_sec / 1_000_000 — use u128 to avoid
    // overflow.
    let usec_ticks =
        ((tv.tv_usec as u64 as u128).saturating_mul(ticks_per_sec as u128) / 1_000_000) as u64;
    sec_ticks.saturating_add(usec_ticks)
}
