// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! /proc/loadavg implementation.
//!
//! Computes and formats the system load averages for the 1-, 5-, and 15-minute
//! windows using an exponential moving average (EMA) identical to the Linux
//! kernel's `calc_global_load` algorithm.
//!
//! The EMA is computed using fixed-point arithmetic with a shift of
//! `FSHIFT = 11` bits. The decay factors `EXP_1`, `EXP_5`, `EXP_15`
//! correspond to e^(-5/60), e^(-5/300), e^(-5/900) scaled by 2^11.
//!
//! # References
//!
//! - Linux `kernel/sched/loadavg.c`
//! - `include/linux/sched/loadavg.h`
//! - `/proc/loadavg` procfs documentation

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Fixed-point constants
// ---------------------------------------------------------------------------

/// Fixed-point shift used for EMA (2^FSHIFT = 2048).
const FSHIFT: u32 = 11;

/// Fixed-point scale factor.
const FIXED_1: u64 = 1 << FSHIFT;

/// EMA decay factor for 1-minute load average (e^(-5/60) × 2^11 ≈ 1884).
const EXP_1: u64 = 1884;

/// EMA decay factor for 5-minute load average (e^(-5/300) × 2^11 ≈ 2014).
const EXP_5: u64 = 2014;

/// EMA decay factor for 15-minute load average (e^(-5/900) × 2^11 ≈ 2037).
const EXP_15: u64 = 2037;

/// Maximum formatted string length for one load average value ("xxx.xx").
const FMT_BUF_SIZE: usize = 128;

// ---------------------------------------------------------------------------
// LoadAvg
// ---------------------------------------------------------------------------

/// System load average state.
///
/// Values are stored in fixed-point (× 2^FSHIFT).
#[derive(Clone, Copy, Debug)]
pub struct LoadAvg {
    /// 1-minute exponential moving average (fixed-point).
    pub load_1: u64,
    /// 5-minute exponential moving average (fixed-point).
    pub load_5: u64,
    /// 15-minute exponential moving average (fixed-point).
    pub load_15: u64,
    /// Number of currently runnable tasks.
    pub running: u32,
    /// Total number of existing tasks.
    pub total: u32,
    /// PID of the most recently created task (for the last field in /proc/loadavg).
    pub last_pid: u32,
}

impl LoadAvg {
    /// Create a zeroed `LoadAvg`.
    pub const fn new() -> Self {
        Self {
            load_1: 0,
            load_5: 0,
            load_15: 0,
            running: 0,
            total: 0,
            last_pid: 0,
        }
    }

    /// Return the 1-min load as an integer part and two decimal digits.
    pub fn load1_parts(&self) -> (u64, u64) {
        fixed_to_decimal(self.load_1)
    }

    /// Return the 5-min load as an integer part and two decimal digits.
    pub fn load5_parts(&self) -> (u64, u64) {
        fixed_to_decimal(self.load_5)
    }

    /// Return the 15-min load as an integer part and two decimal digits.
    pub fn load15_parts(&self) -> (u64, u64) {
        fixed_to_decimal(self.load_15)
    }
}

/// Convert a fixed-point load value to (integer, centesimal) parts.
///
/// E.g., `fixed_to_decimal(2048 + 1024)` → `(1, 50)` for "1.50".
fn fixed_to_decimal(fp: u64) -> (u64, u64) {
    let integer = fp >> FSHIFT;
    // fractional × 100 / FIXED_1
    let frac = ((fp & (FIXED_1 - 1)) * 100) >> FSHIFT;
    (integer, frac)
}

// ---------------------------------------------------------------------------
// EMA update
// ---------------------------------------------------------------------------

/// Update all three EMA load values with the current active task count.
///
/// `active` is the number of runnable + uninterruptible tasks at this sample.
/// The function must be called every 5 scheduler ticks (≈ 5 s at HZ=100).
pub fn calc_load(avg: &mut LoadAvg, active: u64) {
    avg.load_1 = calc_ema(avg.load_1, active, EXP_1);
    avg.load_5 = calc_ema(avg.load_5, active, EXP_5);
    avg.load_15 = calc_ema(avg.load_15, active, EXP_15);
}

/// Compute one EMA step: `new = old × exp + active × (1 − exp)`.
///
/// All values are fixed-point (× 2^FSHIFT).
fn calc_ema(old: u64, active: u64, exp: u64) -> u64 {
    let active_fp = active << FSHIFT;
    // new = old * exp / FIXED_1 + active_fp * (FIXED_1 - exp) / FIXED_1
    (old * exp + active_fp * (FIXED_1 - exp)) / FIXED_1
}

// ---------------------------------------------------------------------------
// /proc/loadavg formatter
// ---------------------------------------------------------------------------

/// Write the /proc/loadavg content into `buf`.
///
/// Format: `"1.23 4.56 7.89 running/total last_pid\n"`
///
/// Returns the number of bytes written, or `Err(InvalidArgument)` if `buf`
/// is too small.
pub fn generate_loadavg(avg: &LoadAvg, buf: &mut [u8]) -> Result<usize> {
    let (i1, f1) = avg.load1_parts();
    let (i5, f5) = avg.load5_parts();
    let (i15, f15) = avg.load15_parts();

    let mut tmp = [0u8; FMT_BUF_SIZE];
    let written = fmt_loadavg(
        &mut tmp,
        i1,
        f1,
        i5,
        f5,
        i15,
        f15,
        avg.running,
        avg.total,
        avg.last_pid,
    )?;

    if buf.len() < written {
        return Err(Error::InvalidArgument);
    }
    buf[..written].copy_from_slice(&tmp[..written]);
    Ok(written)
}

/// Write load average string into `out`, return byte count.
fn fmt_loadavg(
    out: &mut [u8; FMT_BUF_SIZE],
    i1: u64,
    f1: u64,
    i5: u64,
    f5: u64,
    i15: u64,
    f15: u64,
    running: u32,
    total: u32,
    last_pid: u32,
) -> Result<usize> {
    let mut pos = 0;

    pos += write_load(out, pos, i1, f1)?;
    out[pos] = b' ';
    pos += 1;
    pos += write_load(out, pos, i5, f5)?;
    out[pos] = b' ';
    pos += 1;
    pos += write_load(out, pos, i15, f15)?;
    out[pos] = b' ';
    pos += 1;
    pos += write_u32(out, pos, running)?;
    out[pos] = b'/';
    pos += 1;
    pos += write_u32(out, pos, total)?;
    out[pos] = b' ';
    pos += 1;
    pos += write_u32(out, pos, last_pid)?;
    out[pos] = b'\n';
    pos += 1;

    Ok(pos)
}

/// Write "XX.YY" into `out` starting at `offset`.
fn write_load(out: &mut [u8; FMT_BUF_SIZE], offset: usize, int: u64, frac: u64) -> Result<usize> {
    let mut n = write_u64(out, offset, int)?;
    out[offset + n] = b'.';
    n += 1;
    // Always two decimal digits.
    if frac < 10 {
        out[offset + n] = b'0';
        n += 1;
    }
    n += write_u64(out, offset + n, frac)?;
    Ok(n)
}

/// Write a u64 decimal number, return byte count written.
fn write_u64(out: &mut [u8; FMT_BUF_SIZE], offset: usize, mut v: u64) -> Result<usize> {
    if offset >= FMT_BUF_SIZE {
        return Err(Error::InvalidArgument);
    }
    if v == 0 {
        out[offset] = b'0';
        return Ok(1);
    }
    let mut tmp = [0u8; 20];
    let mut len = 0;
    while v > 0 {
        tmp[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    if offset + len > FMT_BUF_SIZE {
        return Err(Error::InvalidArgument);
    }
    for i in 0..len {
        out[offset + i] = tmp[len - 1 - i];
    }
    Ok(len)
}

/// Write a u32 decimal number, return byte count written.
fn write_u32(out: &mut [u8; FMT_BUF_SIZE], offset: usize, v: u32) -> Result<usize> {
    write_u64(out, offset, v as u64)
}

// ---------------------------------------------------------------------------
// Boot-time tracking for idle reporting
// ---------------------------------------------------------------------------

/// Idle time accumulator per CPU.
#[derive(Clone, Copy, Debug, Default)]
pub struct CpuIdle {
    /// Total idle time in ticks.
    pub idle_ticks: u64,
}

/// Compute total system idle time across all CPUs.
///
/// `cpus` is a slice of per-CPU idle accumulators.
/// Returns the sum of all `idle_ticks` values.
pub fn total_idle_ticks(cpus: &[CpuIdle]) -> u64 {
    cpus.iter()
        .fold(0u64, |acc, c| acc.saturating_add(c.idle_ticks))
}
