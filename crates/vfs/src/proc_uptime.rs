// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! /proc/uptime implementation.
//!
//! Provides the system uptime (seconds since boot) and total CPU idle time,
//! formatted as two space-separated floating-point values followed by a
//! newline, matching the Linux /proc/uptime format.
//!
//! # Format
//!
//! ```text
//! uptime_seconds.centiseconds idle_seconds.centiseconds\n
//! ```
//!
//! Example: `"123.45 987.65\n"`
//!
//! # References
//!
//! - Linux `fs/proc/uptime.c`
//! - `man 5 proc` (uptime entry)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Resolution of the uptime counter: ticks per second.
pub const TICKS_PER_SEC: u64 = 100;

/// Maximum output buffer length.
const MAX_OUTPUT: usize = 64;

// ---------------------------------------------------------------------------
// BootTime
// ---------------------------------------------------------------------------

/// Tracks boot time and per-CPU idle time for /proc/uptime.
#[derive(Clone, Copy, Debug)]
pub struct BootTime {
    /// Monotonic tick counter at boot (usually 0).
    pub boot_tick: u64,
    /// Total idle ticks across all CPUs since boot.
    pub total_idle_ticks: u64,
    /// Number of CPUs contributing to `total_idle_ticks`.
    pub num_cpus: u32,
}

impl BootTime {
    /// Create a new `BootTime` for a system with `num_cpus` CPUs booted at tick 0.
    pub const fn new(num_cpus: u32) -> Self {
        Self {
            boot_tick: 0,
            total_idle_ticks: 0,
            num_cpus,
        }
    }

    /// Add `idle_ticks` idle ticks (from one CPU's scheduler accounting).
    pub fn add_idle_ticks(&mut self, idle_ticks: u64) {
        self.total_idle_ticks = self.total_idle_ticks.saturating_add(idle_ticks);
    }

    /// Return the uptime in ticks (current_tick − boot_tick).
    pub fn uptime_ticks(&self, current_tick: u64) -> u64 {
        current_tick.saturating_sub(self.boot_tick)
    }

    /// Return the total idle time in ticks.
    pub fn idle_ticks(&self) -> u64 {
        self.total_idle_ticks
    }
}

// ---------------------------------------------------------------------------
// /proc/uptime formatter
// ---------------------------------------------------------------------------

/// Generate the /proc/uptime content into `buf`.
///
/// `current_tick` is the current monotonic tick count.
/// `boot` supplies the boot time reference and accumulated idle ticks.
///
/// Returns the number of bytes written, or `Err(InvalidArgument)` if `buf`
/// is too small.
///
/// # Format
///
/// `"uptime.cc idle.cc\n"` where `.cc` is centiseconds (two digits).
pub fn generate_uptime(boot: &BootTime, current_tick: u64, buf: &mut [u8]) -> Result<usize> {
    let uptime_ticks = boot.uptime_ticks(current_tick);
    let idle_ticks = boot.idle_ticks();

    let uptime_secs = uptime_ticks / TICKS_PER_SEC;
    let uptime_centis = (uptime_ticks % TICKS_PER_SEC) * 100 / TICKS_PER_SEC;

    let idle_secs = idle_ticks / TICKS_PER_SEC;
    let idle_centis = (idle_ticks % TICKS_PER_SEC) * 100 / TICKS_PER_SEC;

    let mut tmp = [0u8; MAX_OUTPUT];
    let n = fmt_uptime(&mut tmp, uptime_secs, uptime_centis, idle_secs, idle_centis)?;

    if buf.len() < n {
        return Err(Error::InvalidArgument);
    }
    buf[..n].copy_from_slice(&tmp[..n]);
    Ok(n)
}

/// Format "uptime.cc idle.cc\n" into `out`.
fn fmt_uptime(
    out: &mut [u8; MAX_OUTPUT],
    uptime_secs: u64,
    uptime_centis: u64,
    idle_secs: u64,
    idle_centis: u64,
) -> Result<usize> {
    let mut pos = 0;
    pos += write_seconds(out, pos, uptime_secs, uptime_centis)?;
    out[pos] = b' ';
    pos += 1;
    pos += write_seconds(out, pos, idle_secs, idle_centis)?;
    out[pos] = b'\n';
    pos += 1;
    Ok(pos)
}

/// Write "secs.centis" (two decimal places) at `offset` in `out`.
fn write_seconds(
    out: &mut [u8; MAX_OUTPUT],
    offset: usize,
    secs: u64,
    centis: u64,
) -> Result<usize> {
    let mut n = write_dec(out, offset, secs)?;
    out[offset + n] = b'.';
    n += 1;
    // Always emit two digits.
    if centis < 10 {
        out[offset + n] = b'0';
        n += 1;
    }
    n += write_dec(out, offset + n, centis)?;
    Ok(n)
}

/// Write `v` as decimal digits at `out[offset..]`, return byte count.
fn write_dec(out: &mut [u8; MAX_OUTPUT], offset: usize, mut v: u64) -> Result<usize> {
    if offset >= MAX_OUTPUT {
        return Err(Error::InvalidArgument);
    }
    if v == 0 {
        out[offset] = b'0';
        return Ok(1);
    }
    let mut tmp = [0u8; 20];
    let mut len = 0usize;
    while v > 0 {
        tmp[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    if offset + len > MAX_OUTPUT {
        return Err(Error::InvalidArgument);
    }
    for i in 0..len {
        out[offset + i] = tmp[len - 1 - i];
    }
    Ok(len)
}

// ---------------------------------------------------------------------------
// CPU tick accounting
// ---------------------------------------------------------------------------

/// Per-CPU tick accounting for uptime and idle tracking.
#[derive(Clone, Copy, Debug, Default)]
pub struct CpuTicks {
    /// Total ticks this CPU has spent in the idle task.
    pub idle: u64,
    /// Total ticks this CPU has spent running user code.
    pub user: u64,
    /// Total ticks this CPU has spent running kernel code.
    pub system: u64,
}

impl CpuTicks {
    /// Return total ticks (idle + user + system) — i.e., uptime of this CPU.
    pub fn total(&self) -> u64 {
        self.idle
            .saturating_add(self.user)
            .saturating_add(self.system)
    }
}

/// Accumulate idle ticks from a slice of `CpuTicks` into `boot`.
pub fn accumulate_idle(boot: &mut BootTime, cpus: &[CpuTicks]) {
    let total_idle: u64 = cpus.iter().fold(0u64, |acc, c| acc.saturating_add(c.idle));
    boot.total_idle_ticks = total_idle;
}
