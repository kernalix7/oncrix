// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU frequency scaling hardware interface.
//!
//! Exposes the hardware mechanisms used for CPU frequency scaling on x86:
//!
//! - **ACPI P-states** via MSR IA32_PERF_CTL / IA32_PERF_STATUS
//! - **Intel SpeedStep** (Enhanced Intel SpeedStep Technology, EIST)
//! - **AMD Cool'n'Quiet** via MSR FIDVID_CTL
//! - **CPPC** (Collaborative Processor Performance Control, ACPI 6.x)
//!
//! This module deals only with the register-level hardware interface.
//! The higher-level governor and policy logic resides in `cpufreq.rs`.
//!
//! # MSR Reference
//!
//! | MSR | Address | Description |
//! |-----|---------|-------------|
//! | IA32_MPERF | 0xE7 | Max freq cycles (denominator) |
//! | IA32_APERF | 0xE8 | Actual freq cycles (numerator) |
//! | IA32_PERF_STATUS | 0x198 | Current P-state |
//! | IA32_PERF_CTL | 0x199 | Target P-state |
//! | MSR_PLATFORM_INFO | 0xCE | Min/max non-turbo ratio |
//! | MSR_TURBO_RATIO_LIMIT | 0x1AD | Max turbo ratio |
//!
//! Reference: Intel 64 and IA-32 Architectures Software Developer's Manual,
//! Volume 3B, Chapter 14 (Power and Thermal Management).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// MSR Addresses
// ---------------------------------------------------------------------------

/// IA32_MPERF — Maximum Performance Frequency Clock Count.
pub const MSR_IA32_MPERF: u32 = 0x0000_00E7;
/// IA32_APERF — Actual Performance Frequency Clock Count.
pub const MSR_IA32_APERF: u32 = 0x0000_00E8;
/// IA32_PERF_STATUS — Current P-state hardware coordinate.
pub const MSR_IA32_PERF_STATUS: u32 = 0x0000_0198;
/// IA32_PERF_CTL — Target P-state request.
pub const MSR_IA32_PERF_CTL: u32 = 0x0000_0199;
/// MSR_PLATFORM_INFO — Platform information (min/max non-turbo ratio).
pub const MSR_PLATFORM_INFO: u32 = 0x0000_00CE;
/// MSR_TURBO_RATIO_LIMIT — Maximum turbo core ratio for 1C/2C/3C/4C.
pub const MSR_TURBO_RATIO_LIMIT: u32 = 0x0000_01AD;
/// IA32_ENERGY_PERF_BIAS — Energy/performance preference hint.
pub const MSR_ENERGY_PERF_BIAS: u32 = 0x0000_01B0;
/// IA32_HWP_CAPABILITIES — HWP capabilities (Intel HWP).
pub const MSR_HWP_CAPABILITIES: u32 = 0x0000_0771;
/// IA32_HWP_REQUEST — HWP performance request.
pub const MSR_HWP_REQUEST: u32 = 0x0000_0774;
/// AMD MSR_FIDVID_CTL — FID/VID control (legacy Cool'n'Quiet).
pub const MSR_AMD_FIDVID_CTL: u32 = 0xC001_0041;
/// AMD MSR_FIDVID_STATUS — FID/VID status.
pub const MSR_AMD_FIDVID_STATUS: u32 = 0xC001_0042;

// ---------------------------------------------------------------------------
// PLATFORM_INFO bit fields
// ---------------------------------------------------------------------------

/// Bits 15:8 of MSR_PLATFORM_INFO: maximum non-turbo ratio.
pub const PLATFORM_INFO_MAX_RATIO_SHIFT: u32 = 8;
pub const PLATFORM_INFO_MAX_RATIO_MASK: u64 = 0xFF << 8;
/// Bits 47:40 of MSR_PLATFORM_INFO: minimum operating ratio.
pub const PLATFORM_INFO_MIN_RATIO_SHIFT: u32 = 40;
pub const PLATFORM_INFO_MIN_RATIO_MASK: u64 = 0xFFu64 << 40;

// ---------------------------------------------------------------------------
// PERF_CTL / PERF_STATUS bit fields
// ---------------------------------------------------------------------------

/// Bits 15:0 of IA32_PERF_CTL: P-state target (FID/VID encoded).
pub const PERF_CTL_TARGET_MASK: u64 = 0xFFFF;

// ---------------------------------------------------------------------------
// HWP_REQUEST fields
// ---------------------------------------------------------------------------

/// HWP_REQUEST bits 7:0: minimum performance.
pub const HWP_REQ_MIN_PERF_MASK: u64 = 0xFF;
/// HWP_REQUEST bits 15:8: maximum performance.
pub const HWP_REQ_MAX_PERF_MASK: u64 = 0xFF00;
/// HWP_REQUEST bits 23:16: desired performance.
pub const HWP_REQ_DESIRED_PERF_MASK: u64 = 0xFF_0000;
/// HWP_REQUEST bits 31:24: energy/performance preference.
pub const HWP_REQ_ENERGY_PREF_MASK: u64 = 0xFF00_0000;

// ---------------------------------------------------------------------------
// Bus ratio to frequency
// ---------------------------------------------------------------------------

/// Typical x86 bus clock frequency in MHz (100 MHz reference).
pub const BUS_FREQ_MHZ: u32 = 100;

// ---------------------------------------------------------------------------
// MSR helpers
// ---------------------------------------------------------------------------

/// Read a 64-bit MSR value on x86_64.
///
/// # Safety
///
/// `msr` must be a valid, accessible MSR on the current CPU.
#[cfg(target_arch = "x86_64")]
unsafe fn rdmsr(msr: u32) -> u64 {
    // SAFETY: RDMSR is always accessible in kernel mode; caller ensures msr is valid.
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
        (hi as u64) << 32 | lo as u64
    }
}

/// Write a 64-bit value to an MSR on x86_64.
///
/// # Safety
///
/// `msr` must be a writable MSR; `val` must be a valid value for that MSR.
#[cfg(target_arch = "x86_64")]
unsafe fn wrmsr(msr: u32, val: u64) {
    // SAFETY: WRMSR in kernel mode; caller validates MSR and value.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") (val as u32),
            in("edx") ((val >> 32) as u32),
            options(nomem, nostack, preserves_flags),
        );
    }
}

// ---------------------------------------------------------------------------
// PstateCoord
// ---------------------------------------------------------------------------

/// P-state hardware coordinate (bits 15:0 of IA32_PERF_CTL/STATUS).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct PstateCoord(pub u16);

impl PstateCoord {
    /// Extract the bus ratio (FID) encoded in bits 13:8.
    pub fn ratio(self) -> u8 {
        ((self.0 >> 8) & 0x3F) as u8
    }

    /// Compute the approximate frequency in MHz given a 100 MHz bus.
    pub fn freq_mhz(self) -> u32 {
        self.ratio() as u32 * BUS_FREQ_MHZ
    }
}

// ---------------------------------------------------------------------------
// CpufreqHw
// ---------------------------------------------------------------------------

/// CPU frequency scaling hardware interface.
pub struct CpufreqHw {
    /// Maximum non-turbo ratio (from MSR_PLATFORM_INFO).
    max_ratio: u8,
    /// Minimum operating ratio.
    min_ratio: u8,
    /// True if Intel HWP (Hardware P-states) is available.
    hwp_enabled: bool,
}

impl CpufreqHw {
    /// Create an uninitialized [`CpufreqHw`].
    pub const fn new() -> Self {
        Self {
            max_ratio: 0,
            min_ratio: 0,
            hwp_enabled: false,
        }
    }

    /// Probe hardware and cache capability information.
    #[cfg(target_arch = "x86_64")]
    pub fn init(&mut self) -> Result<()> {
        // SAFETY: MSR_PLATFORM_INFO is universally readable on Intel Core CPUs.
        let platform = unsafe { rdmsr(MSR_PLATFORM_INFO) };
        self.max_ratio =
            ((platform & PLATFORM_INFO_MAX_RATIO_MASK) >> PLATFORM_INFO_MAX_RATIO_SHIFT) as u8;
        self.min_ratio =
            ((platform & PLATFORM_INFO_MIN_RATIO_MASK) >> PLATFORM_INFO_MIN_RATIO_SHIFT) as u8;

        // Check HWP capability via CPUID leaf 6.EAX bit 7
        let cpuid6_eax: u32;
        // SAFETY: CPUID is always available on x86_64.
        unsafe {
            core::arch::asm!(
                "cpuid",
                inout("eax") 6u32 => cpuid6_eax,
                out("ecx") _,
                options(nomem, nostack, preserves_flags),
            );
        }
        self.hwp_enabled = (cpuid6_eax & (1 << 7)) != 0;

        Ok(())
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn init(&mut self) -> Result<()> {
        Err(Error::NotImplemented)
    }

    /// Read the current P-state hardware coordinate from IA32_PERF_STATUS.
    #[cfg(target_arch = "x86_64")]
    pub fn current_pstate(&self) -> PstateCoord {
        // SAFETY: IA32_PERF_STATUS is readable in kernel mode on Intel CPUs.
        let val = unsafe { rdmsr(MSR_IA32_PERF_STATUS) };
        PstateCoord((val & PERF_CTL_TARGET_MASK) as u16)
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn current_pstate(&self) -> PstateCoord {
        PstateCoord(0)
    }

    /// Request a P-state transition via IA32_PERF_CTL.
    #[cfg(target_arch = "x86_64")]
    pub fn request_pstate(&self, coord: PstateCoord) -> Result<()> {
        // SAFETY: Writing IA32_PERF_CTL to request a frequency change.
        unsafe { wrmsr(MSR_IA32_PERF_CTL, coord.0 as u64) };
        Ok(())
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn request_pstate(&self, _coord: PstateCoord) -> Result<()> {
        Err(Error::NotImplemented)
    }

    /// Read the MPERF/APERF counters and compute effective frequency ratio.
    ///
    /// Returns `(mperf, aperf)` — the caller can compute the effective
    /// frequency as `base_freq * aperf / mperf`.
    #[cfg(target_arch = "x86_64")]
    pub fn read_aperf_mperf(&self) -> (u64, u64) {
        // SAFETY: IA32_MPERF and IA32_APERF are readable in kernel mode.
        let mperf = unsafe { rdmsr(MSR_IA32_MPERF) };
        let aperf = unsafe { rdmsr(MSR_IA32_APERF) };
        (mperf, aperf)
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn read_aperf_mperf(&self) -> (u64, u64) {
        (0, 0)
    }

    /// Read the maximum turbo core ratios from MSR_TURBO_RATIO_LIMIT.
    ///
    /// Returns a 4-element array: `[1C, 2C, 3C, 4C]` max turbo ratios.
    #[cfg(target_arch = "x86_64")]
    pub fn turbo_ratios(&self) -> [u8; 4] {
        // SAFETY: MSR_TURBO_RATIO_LIMIT is readable on Intel processors with turbo.
        let val = unsafe { rdmsr(MSR_TURBO_RATIO_LIMIT) };
        [
            (val & 0xFF) as u8,
            ((val >> 8) & 0xFF) as u8,
            ((val >> 16) & 0xFF) as u8,
            ((val >> 24) & 0xFF) as u8,
        ]
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn turbo_ratios(&self) -> [u8; 4] {
        [0; 4]
    }

    /// Program an Intel HWP performance request.
    ///
    /// `min_perf`, `max_perf`, `desired` are in the 0–255 HWP scale.
    #[cfg(target_arch = "x86_64")]
    pub fn hwp_set_request(&self, min_perf: u8, max_perf: u8, desired: u8, epp: u8) -> Result<()> {
        if !self.hwp_enabled {
            return Err(Error::NotImplemented);
        }
        let req = min_perf as u64
            | ((max_perf as u64) << 8)
            | ((desired as u64) << 16)
            | ((epp as u64) << 24);
        // SAFETY: Writing IA32_HWP_REQUEST to set performance hints.
        unsafe { wrmsr(MSR_HWP_REQUEST, req) };
        Ok(())
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn hwp_set_request(&self, _min: u8, _max: u8, _desired: u8, _epp: u8) -> Result<()> {
        Err(Error::NotImplemented)
    }

    /// Return cached maximum non-turbo ratio.
    pub const fn max_ratio(&self) -> u8 {
        self.max_ratio
    }

    /// Return cached minimum ratio.
    pub const fn min_ratio(&self) -> u8 {
        self.min_ratio
    }

    /// Return true if Intel HWP is available and initialized.
    pub const fn hwp_available(&self) -> bool {
        self.hwp_enabled
    }

    /// Compute base frequency in MHz from a ratio.
    pub fn ratio_to_freq_mhz(&self, ratio: u8) -> u32 {
        ratio as u32 * BUS_FREQ_MHZ
    }
}
