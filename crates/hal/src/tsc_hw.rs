// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! TSC (Time Stamp Counter) hardware calibration and access layer.
//!
//! The x86_64 TSC is a 64-bit counter incremented by the processor at
//! a hardware-defined rate. Modern CPUs provide an "invariant TSC" that
//! ticks at a constant rate regardless of frequency scaling (CPUID
//! 0x80000007 EDX bit 8).
//!
//! This module provides:
//! - CPUID-based capability detection (`TscHwInfo`)
//! - Frequency detection via CPUID 0x15 / 0x16 (`TscHwCalibration`)
//! - `rdtsc` / `rdtscp` access primitives
//! - MSR helpers for TSC Deadline (`IA32_TSC_DEADLINE`)
//!
//! The higher-level `tsc.rs` clocksource builds on top of these primitives.
//!
//! Reference: Intel SDM Vol 3B §17.17; AMD Architecture Programmer's Manual.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// MSR: `IA32_TSC_DEADLINE` — programs the one-shot APIC TSC-deadline timer.
pub const MSR_TSC_DEADLINE: u32 = 0x0000_06E0;

/// CPUID leaf 0x01 ECX bit 24: TSC Deadline support.
pub const CPUID01_ECX_TSC_DEADLINE: u32 = 1 << 24;

/// CPUID leaf 0x80000007 EDX bit 8: invariant TSC.
pub const CPUID_APM_EDX_INVARIANT: u32 = 1 << 8;

/// CPUID leaf 0x80000007 EDX bit 24: nonstop TSC.
pub const CPUID_APM_EDX_NONSTOP: u32 = 1 << 24;

/// CPUID leaf for TSC / crystal clock information.
pub const CPUID_LEAF_TSC_CRYSTAL: u32 = 0x15;

/// CPUID leaf for processor base frequency information.
pub const CPUID_LEAF_PROC_FREQ: u32 = 0x16;

/// Minimum plausible TSC frequency (1 MHz).
pub const TSC_FREQ_MIN_HZ: u64 = 1_000_000;

/// Maximum plausible TSC frequency (10 GHz).
pub const TSC_FREQ_MAX_HZ: u64 = 10_000_000_000;

/// Nominal crystal frequency for Intel Skylake (24 MHz).
pub const CRYSTAL_SKYLAKE_HZ: u64 = 24_000_000;

/// Nominal crystal frequency for Intel Ice Lake (25 MHz).
pub const CRYSTAL_ICE_LAKE_HZ: u64 = 25_000_000;

/// Default crystal frequency when not reported by CPUID (19.2 MHz).
pub const CRYSTAL_DEFAULT_HZ: u64 = 19_200_000;

// ---------------------------------------------------------------------------
// CalibrationSource
// ---------------------------------------------------------------------------

/// Which method was used to determine the TSC frequency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CalibrationSource {
    /// CPUID leaf 0x15 (crystal clock ratio). Most accurate.
    Cpuid15,
    /// CPUID leaf 0x16 (base frequency in MHz).
    Cpuid16,
    /// PIT-based software measurement. Least accurate.
    PitGate,
    /// Frequency not yet determined.
    #[default]
    Unknown,
}

// ---------------------------------------------------------------------------
// TscHwInfo
// ---------------------------------------------------------------------------

/// TSC hardware capability flags derived from CPUID.
#[derive(Debug, Clone, Copy, Default)]
pub struct TscHwInfo {
    /// TSC ticks at constant rate independent of CPU frequency scaling.
    pub invariant: bool,
    /// TSC continues to tick in deep C-states.
    pub nonstop: bool,
    /// `IA32_TSC_DEADLINE` MSR is available for APIC timer programming.
    pub tsc_deadline: bool,
}

impl TscHwInfo {
    /// Query TSC capabilities from CPUID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] on non-x86_64 targets.
    pub fn query() -> Result<Self> {
        #[cfg(target_arch = "x86_64")]
        {
            let ecx1 = cpuid_ecx(1, 0);
            let edx_apm = cpuid_edx(0x8000_0007, 0);
            Ok(Self {
                invariant: edx_apm & CPUID_APM_EDX_INVARIANT != 0,
                nonstop: edx_apm & CPUID_APM_EDX_NONSTOP != 0,
                tsc_deadline: ecx1 & CPUID01_ECX_TSC_DEADLINE != 0,
            })
        }
        #[cfg(not(target_arch = "x86_64"))]
        Err(Error::NotImplemented)
    }
}

// ---------------------------------------------------------------------------
// TscHwCalibration
// ---------------------------------------------------------------------------

/// TSC frequency calibration result.
#[derive(Debug, Clone, Copy)]
pub struct TscHwCalibration {
    /// TSC frequency in Hz.
    pub freq_hz: u64,
    /// Source used to derive the frequency.
    pub source: CalibrationSource,
    /// Pre-computed ticks per microsecond.
    pub ticks_per_us: u64,
    /// Pre-computed ticks per millisecond.
    pub ticks_per_ms: u64,
}

impl TscHwCalibration {
    /// Calibrate the TSC frequency.
    ///
    /// Tries CPUID 0x15 → 0x16 → PIT gate calibration in order.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if no method succeeds within the plausible
    /// frequency range `[TSC_FREQ_MIN_HZ, TSC_FREQ_MAX_HZ]`.
    /// Returns [`Error::NotImplemented`] on non-x86_64 targets.
    pub fn calibrate() -> Result<Self> {
        #[cfg(target_arch = "x86_64")]
        {
            if let Some(hz) = cpuid15_freq() {
                if (TSC_FREQ_MIN_HZ..=TSC_FREQ_MAX_HZ).contains(&hz) {
                    return Ok(Self::build(hz, CalibrationSource::Cpuid15));
                }
            }
            if let Some(hz) = cpuid16_freq() {
                if (TSC_FREQ_MIN_HZ..=TSC_FREQ_MAX_HZ).contains(&hz) {
                    return Ok(Self::build(hz, CalibrationSource::Cpuid16));
                }
            }
            let hz = pit_gate_freq();
            if (TSC_FREQ_MIN_HZ..=TSC_FREQ_MAX_HZ).contains(&hz) {
                return Ok(Self::build(hz, CalibrationSource::PitGate));
            }
            Err(Error::IoError)
        }
        #[cfg(not(target_arch = "x86_64"))]
        Err(Error::NotImplemented)
    }

    fn build(freq_hz: u64, source: CalibrationSource) -> Self {
        Self {
            freq_hz,
            source,
            ticks_per_us: freq_hz / 1_000_000,
            ticks_per_ms: freq_hz / 1_000,
        }
    }

    /// Convert TSC ticks to nanoseconds.
    #[inline]
    pub fn ticks_to_ns(&self, ticks: u64) -> u64 {
        if self.freq_hz == 0 {
            return 0;
        }
        ((ticks as u128).saturating_mul(1_000_000_000) / self.freq_hz as u128) as u64
    }

    /// Convert nanoseconds to TSC ticks.
    #[inline]
    pub fn ns_to_ticks(&self, ns: u64) -> u64 {
        if self.freq_hz == 0 {
            return 0;
        }
        ((ns as u128).saturating_mul(self.freq_hz as u128) / 1_000_000_000) as u64
    }
}

// ---------------------------------------------------------------------------
// rdtsc / rdtscp primitives
// ---------------------------------------------------------------------------

/// Read the TSC with `rdtsc` (non-serialising).
///
/// Returns 0 on non-x86_64 targets.
#[inline]
pub fn tsc_read() -> u64 {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: `rdtsc` is unprivileged, read-only, and has no side effects.
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nostack, nomem, preserves_flags),
        );
        (hi as u64) << 32 | lo as u64
    }
    #[cfg(not(target_arch = "x86_64"))]
    0
}

/// Read the TSC with `rdtscp` (serialising, also returns `IA32_TSC_AUX`).
///
/// Returns `(tsc, aux)`. Both are 0 on non-x86_64 targets.
#[inline]
pub fn tsc_read_serialised() -> (u64, u32) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: `rdtscp` is unprivileged, serialises prior loads/stores.
    unsafe {
        let lo: u32;
        let hi: u32;
        let aux: u32;
        core::arch::asm!(
            "rdtscp",
            out("eax") lo,
            out("edx") hi,
            out("ecx") aux,
            options(nostack, nomem, preserves_flags),
        );
        ((hi as u64) << 32 | lo as u64, aux)
    }
    #[cfg(not(target_arch = "x86_64"))]
    (0, 0)
}

// ---------------------------------------------------------------------------
// TSC Deadline MSR helpers
// ---------------------------------------------------------------------------

/// Program the `IA32_TSC_DEADLINE` MSR to `value`.
///
/// Setting `value` to 0 disarms any pending deadline interrupt.
///
/// # Safety
///
/// Must be called from ring 0. The CPU must support TSC Deadline
/// (`TscHwInfo::tsc_deadline == true`).
#[cfg(target_arch = "x86_64")]
pub unsafe fn tsc_deadline_write(value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    // SAFETY: Caller guarantees ring-0 and TSC-deadline capability.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") MSR_TSC_DEADLINE,
            in("eax") lo,
            in("edx") hi,
            options(nostack, nomem, preserves_flags),
        );
    }
}

/// Read the `IA32_TSC_DEADLINE` MSR.
///
/// # Safety
///
/// Must be called from ring 0 on a CPU that supports TSC Deadline.
#[cfg(target_arch = "x86_64")]
pub unsafe fn tsc_deadline_read() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: rdmsr on a valid MSR; caller ensures ring-0 context.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") MSR_TSC_DEADLINE,
            out("eax") lo,
            out("edx") hi,
            options(nostack, nomem, preserves_flags),
        );
    }
    (hi as u64) << 32 | lo as u64
}

// ---------------------------------------------------------------------------
// x86_64-internal CPUID / calibration helpers
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
fn cpuid_ecx(leaf: u32, sub: u32) -> u32 {
    let ecx: u32;
    // SAFETY: CPUID at any privilege level; rbx preserved via push/pop.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") leaf => _,
            inout("ecx") sub => ecx,
            out("edx") _,
            options(nostack, nomem, preserves_flags),
        );
    }
    ecx
}

#[cfg(target_arch = "x86_64")]
fn cpuid_edx(leaf: u32, sub: u32) -> u32 {
    let edx: u32;
    // SAFETY: CPUID at any privilege level; rbx preserved via push/pop.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") leaf => _,
            inout("ecx") sub => _,
            out("edx") edx,
            options(nostack, nomem, preserves_flags),
        );
    }
    edx
}

#[cfg(target_arch = "x86_64")]
fn cpuid_all(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;
    // SAFETY: CPUID; rbx saved to a scratch register then restored.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {tmp:e}, ebx",
            "pop rbx",
            inout("eax") leaf => eax,
            inout("ecx") sub => ecx,
            tmp = out(reg) ebx,
            out("edx") edx,
            options(nostack, nomem, preserves_flags),
        );
    }
    (eax, ebx, ecx, edx)
}

#[cfg(target_arch = "x86_64")]
fn cpuid15_freq() -> Option<u64> {
    let (denom, numer, crystal_hz_raw, _) = cpuid_all(CPUID_LEAF_TSC_CRYSTAL, 0);
    if denom == 0 || numer == 0 {
        return None;
    }
    let crystal_hz: u64 = if crystal_hz_raw != 0 {
        crystal_hz_raw as u64
    } else {
        // Heuristic: query base frequency leaf to pick crystal model.
        let (base_mhz, _, _, _) = cpuid_all(CPUID_LEAF_PROC_FREQ, 0);
        match base_mhz & 0xFFFF {
            1800..=4800 => CRYSTAL_SKYLAKE_HZ,
            _ => CRYSTAL_ICE_LAKE_HZ,
        }
    };
    Some(crystal_hz.saturating_mul(numer as u64) / denom as u64)
}

#[cfg(target_arch = "x86_64")]
fn cpuid16_freq() -> Option<u64> {
    let (eax, _, _, _) = cpuid_all(CPUID_LEAF_PROC_FREQ, 0);
    let base_mhz = eax & 0xFFFF;
    if base_mhz == 0 {
        return None;
    }
    Some(base_mhz as u64 * 1_000_000)
}

/// PIT gate-based TSC calibration (~10 ms window on channel 2).
#[cfg(target_arch = "x86_64")]
fn pit_gate_freq() -> u64 {
    const PIT_CLOCK_HZ: u64 = 1_193_182;
    const GATE_TICKS: u16 = 11_932; // ~10 ms
    const GATE_NS: u64 = GATE_TICKS as u64 * 1_000_000_000 / PIT_CLOCK_HZ;

    // SAFETY: Port I/O ring-0 only; standard PIT/system-control registers.
    unsafe {
        let ctrl: u8;
        core::arch::asm!("in al, 0x61", out("al") ctrl, options(nostack, nomem));
        // Disable gate
        core::arch::asm!("out 0x61, al", in("al") ctrl & 0xFE_u8, options(nostack, nomem));
        // Channel 2: lo/hi byte, mode 0, binary
        core::arch::asm!("out 0x43, al", in("al") 0xB0_u8, options(nostack, nomem));
        core::arch::asm!("out 0x42, al",
            in("al") (GATE_TICKS & 0xFF) as u8, options(nostack, nomem));
        core::arch::asm!("out 0x42, al",
            in("al") (GATE_TICKS >> 8) as u8, options(nostack, nomem));
        // Enable gate
        core::arch::asm!("out 0x61, al", in("al") ctrl | 0x01_u8, options(nostack, nomem));
    }

    let start = tsc_read();
    loop {
        let status: u8;
        // SAFETY: Polling port 0x61 OUT2 (bit 5) — read only, ring-0 context.
        unsafe {
            core::arch::asm!("in al, 0x61", out("al") status, options(nostack, nomem));
        }
        if status & 0x20 != 0 {
            break;
        }
        core::hint::spin_loop();
    }
    let end = tsc_read();
    let elapsed = end.wrapping_sub(start);
    if GATE_NS == 0 {
        return 0;
    }
    ((elapsed as u128).saturating_mul(1_000_000_000) / GATE_NS as u128) as u64
}
