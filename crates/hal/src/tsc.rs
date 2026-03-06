// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! TSC (Time Stamp Counter) calibration and clocksource.
//!
//! The x86_64 TSC is a 64-bit monotonically increasing counter incremented
//! at a hardware frequency. Modern Intel/AMD CPUs expose an "invariant TSC"
//! that runs at a constant rate regardless of CPU frequency scaling (CPUID
//! leaf 0x80000007, EDX bit 8).
//!
//! # Calibration
//!
//! The TSC frequency is determined by one of three methods (in priority order):
//!
//! 1. **CPUID leaf 0x15** — crystal clock ratio (`tsc_freq = crystal_hz * num / denom`).
//!    Available on Skylake and later Intel CPUs.
//! 2. **CPUID leaf 0x16** — CPU base frequency in MHz (direct).
//!    Available on Skylake and later as a fallback.
//! 3. **PIT calibration** — measure TSC ticks in a known PIT interval
//!    (software fallback, less precise).
//!
//! # Architecture
//!
//! - [`TscInfo`] — capabilities from CPUID (invariant, nonstop, deadline).
//! - [`TscCalibration`] — calibrated frequency and method used.
//! - [`Tsc`] — the main clocksource, implementing the [`Timer`] trait.
//! - [`TscDeadline`] — per-CPU deadline timer using `IA32_TSC_DEADLINE` MSR.
//!
//! All assembly is gated behind `#[cfg(target_arch = "x86_64")]`.
//!
//! Reference: Intel 64 and IA-32 Architectures Software Developer's Manual,
//! Volume 3B §17.17 (Time Stamp Counter), §18.7.3 (TSC Deadline).

use oncrix_lib::{Error, Result};

use crate::timer::Timer;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// CPUID leaf for TSC / core crystal clock information.
const CPUID_LEAF_TSC_CRYSTAL: u32 = 0x15;

/// CPUID leaf for processor frequency information.
const CPUID_LEAF_PROC_FREQ: u32 = 0x16;

/// CPUID extended leaf for advanced power management (invariant TSC).
const CPUID_LEAF_APM: u32 = 0x8000_0007;

/// CPUID leaf 1 ECX bit 24: TSC Deadline support (`CPUID.01H:ECX[24]`).
const CPUID_ECX_TSC_DEADLINE: u32 = 1 << 24;

/// CPUID AMD Power Management EDX bit 8: invariant TSC.
const CPUID_APM_EDX_INVARIANT_TSC: u32 = 1 << 8;

/// CPUID AMD Power Management EDX bit 24: nonstop TSC.
const CPUID_APM_EDX_NONSTOP_TSC: u32 = 1 << 24;

/// MSR address for `IA32_TSC_DEADLINE`.
pub const MSR_TSC_DEADLINE: u32 = 0x6E0;

/// Nominal crystal frequency for Skylake desktop / server (24 MHz).
const CRYSTAL_FREQ_SKYLAKE_HZ: u64 = 24_000_000;

/// Nominal crystal frequency for Ice Lake (25 MHz).
const CRYSTAL_FREQ_ICE_LAKE_HZ: u64 = 25_000_000;

/// Crystal frequency used when CPUID does not report it (19.2 MHz default).
const CRYSTAL_FREQ_DEFAULT_HZ: u64 = 19_200_000;

/// Maximum number of TSC deadline slots (one per CPU).
const MAX_TSC_DEADLINE_CPUS: usize = 64;

/// Minimum acceptable TSC frequency (1 MHz — sanity check).
const TSC_FREQ_MIN_HZ: u64 = 1_000_000;

/// Maximum acceptable TSC frequency (10 GHz — sanity check).
const TSC_FREQ_MAX_HZ: u64 = 10_000_000_000;

// ---------------------------------------------------------------------------
// CalibrationMethod
// ---------------------------------------------------------------------------

/// The method used to determine the TSC frequency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalibrationMethod {
    /// Frequency derived from CPUID leaf 0x15 crystal ratio.
    Cpuid15,
    /// Frequency derived from CPUID leaf 0x16 base frequency.
    Cpuid16,
    /// Frequency estimated by timing the PIT (fallback).
    PitCalibration,
    /// Not yet calibrated.
    Unknown,
}

// ---------------------------------------------------------------------------
// TscInfo
// ---------------------------------------------------------------------------

/// TSC capability flags obtained from CPUID.
#[derive(Debug, Clone, Copy, Default)]
pub struct TscInfo {
    /// TSC runs at a constant rate regardless of CPU frequency scaling.
    pub invariant: bool,
    /// TSC does not stop in deep C-states (C3+).
    pub nonstop: bool,
    /// `IA32_TSC_DEADLINE` MSR is available for APIC timer programming.
    pub deadline_capable: bool,
}

impl TscInfo {
    /// Query TSC capabilities via CPUID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] on non-x86_64 targets.
    pub fn query() -> Result<Self> {
        #[cfg(target_arch = "x86_64")]
        {
            let mut info = TscInfo::default();

            // CPUID leaf 1 — check ECX bit 24 for TSC Deadline.
            let ecx1 = cpuid_ecx(1, 0);
            info.deadline_capable = ecx1 & CPUID_ECX_TSC_DEADLINE != 0;

            // CPUID leaf 0x80000007 — AMD/Intel advanced power management.
            let edx_apm = cpuid_edx(CPUID_LEAF_APM, 0);
            info.invariant = edx_apm & CPUID_APM_EDX_INVARIANT_TSC != 0;
            info.nonstop = edx_apm & CPUID_APM_EDX_NONSTOP_TSC != 0;

            Ok(info)
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Err(Error::NotImplemented)
        }
    }
}

// ---------------------------------------------------------------------------
// TscCalibration
// ---------------------------------------------------------------------------

/// Result of TSC frequency calibration.
#[derive(Debug, Clone, Copy)]
pub struct TscCalibration {
    /// Calibrated TSC frequency in Hz.
    pub frequency_hz: u64,
    /// Method used to determine the frequency.
    pub method: CalibrationMethod,
    /// TSC ticks per microsecond (rounded).
    pub ticks_per_us: u64,
    /// TSC ticks per millisecond.
    pub ticks_per_ms: u64,
}

impl TscCalibration {
    /// Attempt to calibrate the TSC frequency.
    ///
    /// Tries CPUID leaf 0x15, then 0x16, and finally falls back to a
    /// PIT-based software measurement.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if all calibration methods fail
    /// to produce a frequency in the plausible range.
    pub fn calibrate() -> Result<Self> {
        #[cfg(target_arch = "x86_64")]
        {
            // Try CPUID leaf 0x15 first.
            if let Some(freq) = calibrate_via_cpuid15() {
                if freq >= TSC_FREQ_MIN_HZ && freq <= TSC_FREQ_MAX_HZ {
                    return Ok(Self::build(freq, CalibrationMethod::Cpuid15));
                }
            }

            // Try CPUID leaf 0x16.
            if let Some(freq) = calibrate_via_cpuid16() {
                if freq >= TSC_FREQ_MIN_HZ && freq <= TSC_FREQ_MAX_HZ {
                    return Ok(Self::build(freq, CalibrationMethod::Cpuid16));
                }
            }

            // Fall back to PIT calibration.
            let freq = calibrate_via_pit();
            if freq >= TSC_FREQ_MIN_HZ && freq <= TSC_FREQ_MAX_HZ {
                return Ok(Self::build(freq, CalibrationMethod::PitCalibration));
            }

            Err(Error::IoError)
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Err(Error::NotImplemented)
        }
    }

    fn build(frequency_hz: u64, method: CalibrationMethod) -> Self {
        let ticks_per_us = frequency_hz / 1_000_000;
        let ticks_per_ms = frequency_hz / 1_000;
        Self {
            frequency_hz,
            method,
            ticks_per_us,
            ticks_per_ms,
        }
    }

    /// Convert TSC ticks to nanoseconds.
    #[inline]
    pub fn ticks_to_ns(&self, ticks: u64) -> u64 {
        if self.frequency_hz == 0 {
            return 0;
        }
        // ns = ticks * 10^9 / freq
        (ticks as u128)
            .saturating_mul(1_000_000_000)
            .wrapping_div(self.frequency_hz as u128) as u64
    }

    /// Convert nanoseconds to TSC ticks.
    #[inline]
    pub fn ns_to_ticks(&self, ns: u64) -> u64 {
        if self.frequency_hz == 0 {
            return 0;
        }
        // ticks = ns * freq / 10^9
        (ns as u128)
            .saturating_mul(self.frequency_hz as u128)
            .wrapping_div(1_000_000_000) as u64
    }
}

// ---------------------------------------------------------------------------
// Tsc (clocksource)
// ---------------------------------------------------------------------------

/// TSC clocksource.
///
/// After calibration, provides monotonic nanosecond timestamps via
/// the `rdtsc` instruction and implements the [`Timer`] trait.
pub struct Tsc {
    /// Calibration result.
    calibration: TscCalibration,
    /// TSC capability flags.
    info: TscInfo,
    /// Whether the TSC has been successfully calibrated.
    ready: bool,
}

impl Tsc {
    /// Create an uninitialised TSC clocksource.
    pub const fn new() -> Self {
        Self {
            calibration: TscCalibration {
                frequency_hz: 0,
                method: CalibrationMethod::Unknown,
                ticks_per_us: 0,
                ticks_per_ms: 0,
            },
            info: TscInfo {
                invariant: false,
                nonstop: false,
                deadline_capable: false,
            },
            ready: false,
        }
    }

    /// Initialise the TSC by querying capabilities and calibrating.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if calibration fails.
    /// Returns [`Error::NotImplemented`] on non-x86_64 targets.
    pub fn init(&mut self) -> Result<()> {
        self.info = TscInfo::query()?;
        self.calibration = TscCalibration::calibrate()?;
        self.ready = true;
        Ok(())
    }

    /// Return `true` if the TSC is invariant (constant rate).
    pub fn is_invariant(&self) -> bool {
        self.info.invariant
    }

    /// Return `true` if `IA32_TSC_DEADLINE` is available.
    pub fn is_deadline_capable(&self) -> bool {
        self.info.deadline_capable
    }

    /// Return the calibration result.
    pub fn calibration(&self) -> &TscCalibration {
        &self.calibration
    }

    /// Return the TSC information flags.
    pub fn info(&self) -> &TscInfo {
        &self.info
    }

    /// Read the current TSC value using `rdtsc`.
    ///
    /// Returns 0 on non-x86_64 targets.
    #[inline]
    pub fn read_tsc() -> u64 {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: `rdtsc` is a read-only instruction available at any
        // privilege level. It does not fault and has no side effects.
        unsafe {
            let lo: u32;
            let hi: u32;
            core::arch::asm!(
                "rdtsc",
                out("eax") lo,
                out("edx") hi,
                options(nostack, nomem, preserves_flags),
            );
            ((hi as u64) << 32) | lo as u64
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            0
        }
    }

    /// Read the TSC with a serialising fence (`rdtscp`).
    ///
    /// `rdtscp` waits for all prior instructions to retire before
    /// reading the counter and also returns the `IA32_TSC_AUX` MSR
    /// value (CPU ID on Linux-style setups).
    ///
    /// Returns `(tsc, aux)`. Returns `(0, 0)` on non-x86_64.
    #[inline]
    pub fn read_tscp() -> (u64, u32) {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: `rdtscp` is available at any privilege level on CPUs
        // that support it. Serialises prior loads/stores before reading.
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
            (((hi as u64) << 32) | lo as u64, aux)
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            (0, 0)
        }
    }

    /// Convert a TSC counter value to nanoseconds.
    pub fn tsc_to_ns(&self, tsc: u64) -> u64 {
        self.calibration.ticks_to_ns(tsc)
    }

    /// Return the current time in nanoseconds since calibration.
    pub fn now_ns(&self) -> u64 {
        let tsc = Self::read_tsc();
        self.calibration.ticks_to_ns(tsc)
    }
}

impl Default for Tsc {
    fn default() -> Self {
        Self::new()
    }
}

impl Timer for Tsc {
    fn frequency_hz(&self) -> u64 {
        self.calibration.frequency_hz
    }

    fn current_ticks(&self) -> u64 {
        Self::read_tsc()
    }

    fn set_oneshot(&mut self, _ticks: u64) -> Result<()> {
        // TSC itself is a free-running counter; one-shot is via TSC Deadline
        // MSR or APIC. Not directly programmable here.
        Err(Error::NotImplemented)
    }

    fn set_periodic(&mut self, _ticks: u64) -> Result<()> {
        Err(Error::NotImplemented)
    }

    fn stop(&mut self) -> Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TscDeadline
// ---------------------------------------------------------------------------

/// Per-CPU TSC deadline timer slot.
#[derive(Debug, Clone, Copy, Default)]
pub struct TscDeadlineSlot {
    /// The absolute TSC value at which the deadline fires.
    pub deadline: u64,
    /// Whether the slot is armed.
    pub armed: bool,
}

/// TSC deadline timer manager (one slot per CPU).
///
/// Programs the `IA32_TSC_DEADLINE` MSR to request a one-shot APIC
/// interrupt when the TSC reaches the programmed value.
pub struct TscDeadline {
    slots: [TscDeadlineSlot; MAX_TSC_DEADLINE_CPUS],
    count: usize,
}

impl TscDeadline {
    /// Create an empty deadline manager.
    pub const fn new() -> Self {
        Self {
            slots: [TscDeadlineSlot {
                deadline: 0,
                armed: false,
            }; MAX_TSC_DEADLINE_CPUS],
            count: 0,
        }
    }

    /// Arm a TSC deadline for the given logical CPU.
    ///
    /// Writes the absolute TSC deadline value to `IA32_TSC_DEADLINE`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of range.
    /// Returns [`Error::NotImplemented`] on non-x86_64 targets.
    pub fn arm(&mut self, cpu_id: usize, deadline_tsc: u64) -> Result<()> {
        if cpu_id >= MAX_TSC_DEADLINE_CPUS {
            return Err(Error::InvalidArgument);
        }

        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: Writing to IA32_TSC_DEADLINE MSR is a privileged
            // operation valid only in ring 0. The MSR exists on all CPUs
            // that report CPUID.01H:ECX[24] = 1.
            unsafe {
                wrmsr(MSR_TSC_DEADLINE, deadline_tsc);
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = deadline_tsc;
            return Err(Error::NotImplemented);
        }

        self.slots[cpu_id] = TscDeadlineSlot {
            deadline: deadline_tsc,
            armed: true,
        };
        if cpu_id >= self.count {
            self.count = cpu_id + 1;
        }
        Ok(())
    }

    /// Disarm a TSC deadline by writing 0 to the MSR.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of range.
    pub fn disarm(&mut self, cpu_id: usize) -> Result<()> {
        if cpu_id >= MAX_TSC_DEADLINE_CPUS {
            return Err(Error::InvalidArgument);
        }

        #[cfg(target_arch = "x86_64")]
        // SAFETY: Writing 0 to IA32_TSC_DEADLINE disarms any pending
        // deadline interrupt. Ring 0 only.
        unsafe {
            wrmsr(MSR_TSC_DEADLINE, 0);
        }

        self.slots[cpu_id].armed = false;
        Ok(())
    }

    /// Return the deadline slot for a CPU.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of range.
    pub fn slot(&self, cpu_id: usize) -> Result<&TscDeadlineSlot> {
        self.slots.get(cpu_id).ok_or(Error::InvalidArgument)
    }

    /// Return the number of deadline slots in use.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for TscDeadline {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// x86_64 CPUID / MSR helpers
// ---------------------------------------------------------------------------

/// Read the ECX output of CPUID for a given leaf/sub-leaf.
#[cfg(target_arch = "x86_64")]
fn cpuid_ecx(leaf: u32, subleaf: u32) -> u32 {
    let ecx: u32;
    // SAFETY: CPUID is a read-only instruction available at all privilege
    // levels. It never faults on supported leaves. rbx is preserved via
    // push/pop because LLVM reserves it for internal use.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") leaf => _,
            inout("ecx") subleaf => ecx,
            out("edx") _,
            options(nostack, nomem, preserves_flags),
        );
    }
    ecx
}

/// Read the EDX output of CPUID for a given leaf/sub-leaf.
#[cfg(target_arch = "x86_64")]
fn cpuid_edx(leaf: u32, subleaf: u32) -> u32 {
    let edx: u32;
    // SAFETY: CPUID is a read-only instruction available at all privilege
    // levels. It never faults on supported leaves. rbx is preserved via
    // push/pop because LLVM reserves it for internal use.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") leaf => _,
            inout("ecx") subleaf => _,
            out("edx") edx,
            options(nostack, nomem, preserves_flags),
        );
    }
    edx
}

/// Read EAX, EBX, ECX, EDX from CPUID for a given leaf/sub-leaf.
#[cfg(target_arch = "x86_64")]
fn cpuid_all(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;
    // SAFETY: CPUID is a read-only instruction available at all privilege
    // levels. It never faults on supported leaves. rbx is saved to a
    // temporary register (rsi) then restored because LLVM reserves rbx.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            inout("eax") leaf => eax,
            inout("ecx") subleaf => ecx,
            ebx_out = out(reg) ebx,
            out("edx") edx,
            options(nostack, nomem, preserves_flags),
        );
    }
    (eax, ebx, ecx, edx)
}

/// Write a 64-bit value to an MSR.
///
/// # Safety
///
/// Must be called from ring 0. The MSR address must be valid for
/// the current CPU model.
#[cfg(target_arch = "x86_64")]
unsafe fn wrmsr(msr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    // SAFETY: Caller guarantees ring-0 context and valid MSR address.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nostack, nomem, preserves_flags),
        );
    }
}

// ---------------------------------------------------------------------------
// Calibration helpers (x86_64-only)
// ---------------------------------------------------------------------------

/// Attempt TSC frequency calibration from CPUID leaf 0x15.
///
/// Returns `Some(freq_hz)` when the ratio is non-zero and a crystal
/// frequency is known. Returns `None` if this leaf is not available.
#[cfg(target_arch = "x86_64")]
fn calibrate_via_cpuid15() -> Option<u64> {
    let (eax, ebx, ecx, _) = cpuid_all(CPUID_LEAF_TSC_CRYSTAL, 0);

    // EAX = denominator, EBX = numerator, ECX = crystal clock Hz
    let denom = eax;
    let numer = ebx;
    if denom == 0 || numer == 0 {
        return None;
    }

    // ECX contains the crystal frequency. If zero, use a model-specific default.
    let crystal_hz: u64 = if ecx != 0 {
        ecx as u64
    } else {
        // Heuristic: check the CPU base frequency leaf to infer the model.
        let (base_mhz, _, _, _) = cpuid_all(CPUID_LEAF_PROC_FREQ, 0);
        match base_mhz {
            // Skylake-D / Cascade Lake: 24 MHz
            1800..=4800 => CRYSTAL_FREQ_SKYLAKE_HZ,
            // Ice Lake: 25 MHz
            _ => CRYSTAL_FREQ_ICE_LAKE_HZ,
        }
    };

    // TSC freq = crystal_hz * numerator / denominator
    let freq = crystal_hz.saturating_mul(numer as u64) / denom as u64;
    Some(freq)
}

/// Attempt TSC frequency calibration from CPUID leaf 0x16.
///
/// Returns `Some(freq_hz)` when the base frequency in EAX is non-zero.
#[cfg(target_arch = "x86_64")]
fn calibrate_via_cpuid16() -> Option<u64> {
    let (eax, _, _, _) = cpuid_all(CPUID_LEAF_PROC_FREQ, 0);
    let base_mhz = eax & 0xFFFF;
    if base_mhz == 0 {
        return None;
    }
    // Base frequency in MHz → Hz
    Some(base_mhz as u64 * 1_000_000)
}

/// Calibrate the TSC against the PIT channel 2 with a ~10 ms gate.
///
/// Uses PIT mode 0 (interrupt on terminal count) on I/O port 0x61.
/// The gate is ~10 ms (PIT at 1.193182 MHz, 11932 ticks ≈ 10 ms).
///
/// Returns the estimated TSC frequency in Hz.
#[cfg(target_arch = "x86_64")]
fn calibrate_via_pit() -> u64 {
    // PIT constants
    const PIT_CLOCK_HZ: u64 = 1_193_182;
    const GATE_TICKS: u16 = 11_932; // ~10 ms
    const GATE_NS: u64 = (GATE_TICKS as u64 * 1_000_000_000) / PIT_CLOCK_HZ;

    // Configure PIT channel 2, mode 0, LSB then MSB.
    // SAFETY: Port I/O to PIT control (0x43) and channel 2 (0x42) is
    // a standard x86 BIOS-era interface available in ring 0.
    unsafe {
        // Disable gate (bit 0 of port 0x61).
        let val: u8;
        core::arch::asm!("in al, 0x61", out("al") val, options(nostack, nomem));
        core::arch::asm!("out 0x61, al", in("al") val & 0xFE_u8, options(nostack, nomem));

        // PIT command: channel 2, lo/hi byte, mode 0, binary.
        core::arch::asm!("out 0x43, al", in("al") 0xB0_u8, options(nostack, nomem));
        // Load count (LSB then MSB).
        core::arch::asm!("out 0x42, al", in("al") (GATE_TICKS & 0xFF) as u8,
                         options(nostack, nomem));
        core::arch::asm!("out 0x42, al", in("al") (GATE_TICKS >> 8) as u8,
                         options(nostack, nomem));

        // Enable gate.
        core::arch::asm!("out 0x61, al", in("al") val | 0x01_u8, options(nostack, nomem));
    }

    let tsc_start = Tsc::read_tsc();

    // Poll PIT OUT2 (bit 5 of port 0x61) until high.
    loop {
        let status: u8;
        // SAFETY: Read-only port I/O to system control port B (0x61).
        unsafe {
            core::arch::asm!("in al, 0x61", out("al") status, options(nostack, nomem));
        }
        if status & 0x20 != 0 {
            break;
        }
    }

    let tsc_end = Tsc::read_tsc();

    let elapsed = tsc_end.wrapping_sub(tsc_start);
    if GATE_NS == 0 {
        return 0;
    }
    // freq = ticks * 10^9 / gate_ns
    ((elapsed as u128).saturating_mul(1_000_000_000) / GATE_NS as u128) as u64
}

/// Fallback crystal frequency constant used when CPUID 0x15 ECX is zero.
#[allow(dead_code)]
const _CRYSTAL_DEFAULT: u64 = CRYSTAL_FREQ_DEFAULT_HZ;
