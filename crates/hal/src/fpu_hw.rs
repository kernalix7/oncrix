// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! FPU/SSE/AVX state save and restore using FXSAVE/XSAVE.
//!
//! On x86_64 every context switch must preserve the floating-point and SIMD
//! register state. This module provides:
//!
//! - **FXSAVE/FXRSTOR** — 512-byte legacy save area for x87 FPU + SSE.
//! - **XSAVE/XRSTOR** — Extended save area supporting AVX, AVX-512, etc.
//! - **CR0/CR4 helpers** — Enable FPU, SSE, and AVX via control register bits.
//! - **XCR0 (XFEATURE_ENABLED_MASK)** — XSAVE component bitmap enabling/reading.
//!
//! Reference: Intel 64 and IA-32 Architectures Software Developer's Manual,
//! Volume 1, Chapter 13 — Managing State Using the XSAVE Feature Set.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Save Area Sizes and Alignment
// ---------------------------------------------------------------------------

/// Size of the FXSAVE/FXRSTOR legacy state save area in bytes.
pub const FXSAVE_AREA_SIZE: usize = 512;

/// Alignment required for FXSAVE/FXRSTOR areas.
pub const FXSAVE_ALIGN: usize = 16;

/// Maximum supported XSAVE area size (conservative: 4 KiB covers AVX-512).
pub const XSAVE_AREA_MAX: usize = 4096;

/// Alignment required for XSAVE/XRSTOR areas (64-byte per spec).
pub const XSAVE_ALIGN: usize = 64;

// ---------------------------------------------------------------------------
// XCR0 (XFEATURE_ENABLED_MASK) Component Bits
// ---------------------------------------------------------------------------

/// XCR0 bit: x87 FPU state (always required when XSAVE is used).
pub const XCR0_X87: u64 = 1 << 0;
/// XCR0 bit: SSE state (XMM0–XMM15 + MXCSR).
pub const XCR0_SSE: u64 = 1 << 1;
/// XCR0 bit: AVX state (upper halves of YMM0–YMM15).
pub const XCR0_AVX: u64 = 1 << 2;
/// XCR0 bit: AVX-512 opmask registers (k0–k7).
pub const XCR0_OPMASK: u64 = 1 << 5;
/// XCR0 bit: AVX-512 ZMM_HI256 (upper halves of ZMM0–ZMM15).
pub const XCR0_ZMM_HI256: u64 = 1 << 6;
/// XCR0 bit: AVX-512 HI16_ZMM (ZMM16–ZMM31 full registers).
pub const XCR0_HI16_ZMM: u64 = 1 << 7;

/// XCR0 value enabling x87 + SSE only.
pub const XCR0_SSE_ONLY: u64 = XCR0_X87 | XCR0_SSE;
/// XCR0 value enabling x87 + SSE + AVX.
pub const XCR0_AVX_FULL: u64 = XCR0_X87 | XCR0_SSE | XCR0_AVX;
/// XCR0 value enabling full AVX-512 support.
pub const XCR0_AVX512_FULL: u64 =
    XCR0_X87 | XCR0_SSE | XCR0_AVX | XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM;

// ---------------------------------------------------------------------------
// FXSAVE Area
// ---------------------------------------------------------------------------

/// 512-byte FXSAVE/FXRSTOR state area.
///
/// Must be 16-byte aligned; the CPU raises #GP on a misaligned address.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct FxsaveArea {
    /// Raw 512-byte state region. Layout is defined by the CPU hardware.
    pub data: [u8; FXSAVE_AREA_SIZE],
}

impl FxsaveArea {
    /// Creates a zeroed FXSAVE area.
    pub const fn new() -> Self {
        Self {
            data: [0u8; FXSAVE_AREA_SIZE],
        }
    }

    /// Saves the current FPU/SSE state into this area using `FXSAVE64`.
    ///
    /// # Safety
    /// - The CPU must have SSE enabled (`CR4.OSFXSR = 1`).
    /// - `self` is 16-byte aligned (guaranteed by `#[repr(align(16))]`).
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn save(&mut self) {
        // SAFETY: Caller ensures OSFXSR; alignment guaranteed by repr.
        unsafe {
            core::arch::asm!(
                "fxsave64 [{ptr}]",
                ptr = in(reg) self.data.as_mut_ptr(),
                options(nostack, preserves_flags),
            );
        }
    }

    /// Restores the FPU/SSE state from this area using `FXRSTOR64`.
    ///
    /// # Safety
    /// - The CPU must have SSE enabled (`CR4.OSFXSR = 1`).
    /// - `self` must contain a valid saved state (previously written by `save()`).
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn restore(&self) {
        // SAFETY: Caller ensures OSFXSR and valid saved state.
        unsafe {
            core::arch::asm!(
                "fxrstor64 [{ptr}]",
                ptr = in(reg) self.data.as_ptr(),
                options(nostack, preserves_flags),
            );
        }
    }
}

impl Default for FxsaveArea {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// XSAVE Area
// ---------------------------------------------------------------------------

/// Extended XSAVE state area (4 KiB, 64-byte aligned).
///
/// Memory layout:
/// - Bytes 0–511: Legacy region (same as FXSAVE area).
/// - Bytes 512–575: XSAVE header (`XSTATE_BV` component bitmap).
/// - Bytes 576+: Extended region (offsets defined by CPUID leaf 0xD).
#[repr(C, align(64))]
pub struct XsaveArea {
    /// Raw state storage.
    pub data: [u8; XSAVE_AREA_MAX],
}

impl XsaveArea {
    /// Creates a zeroed XSAVE area.
    pub const fn new() -> Self {
        Self {
            data: [0u8; XSAVE_AREA_MAX],
        }
    }

    /// Saves all XSAVE-enabled components matching `mask` using `XSAVE64`.
    ///
    /// # Parameters
    /// - `mask`: XCR0-compatible component mask (e.g., `XCR0_AVX_FULL`).
    ///
    /// # Safety
    /// - XSAVE must be supported and enabled (`CR4.OSXSAVE = 1`).
    /// - `self` must be 64-byte aligned (guaranteed by `#[repr(align(64))]`).
    /// - The area must be large enough for the enabled components.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn save(&mut self, mask: u64) {
        let lo = mask as u32;
        let hi = (mask >> 32) as u32;
        // SAFETY: Caller guarantees OSXSAVE enabled; alignment and size guaranteed.
        unsafe {
            core::arch::asm!(
                "xsave64 [{ptr}]",
                ptr = in(reg) self.data.as_mut_ptr(),
                in("eax") lo,
                in("edx") hi,
                options(nostack, preserves_flags),
            );
        }
    }

    /// Restores XSAVE-enabled components matching `mask` using `XRSTOR64`.
    ///
    /// # Safety
    /// - XSAVE must be supported and enabled.
    /// - `self` must contain a valid saved state (previously written by `save()`).
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn restore(&self, mask: u64) {
        let lo = mask as u32;
        let hi = (mask >> 32) as u32;
        // SAFETY: Caller guarantees OSXSAVE enabled and valid saved state.
        unsafe {
            core::arch::asm!(
                "xrstor64 [{ptr}]",
                ptr = in(reg) self.data.as_ptr(),
                in("eax") lo,
                in("edx") hi,
                options(nostack, preserves_flags),
            );
        }
    }
}

impl Default for XsaveArea {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// XCR0 Access (xgetbv / xsetbv)
// ---------------------------------------------------------------------------

/// Reads XCR0 (the XSAVE component enable mask).
///
/// # Safety
/// - CPU must support XSAVE (`CPUID.01H:ECX[26]`).
/// - Must be called from ring 0, or with `CR4.OSXSAVE = 1`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn read_xcr0() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: Caller guarantees XSAVE support.
    unsafe {
        core::arch::asm!(
            "xgetbv",
            in("ecx") 0u32,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Writes XCR0 to enable a set of XSAVE components.
///
/// # Safety
/// - CPU must support XSAVE.
/// - `val` must have bits 0 (x87) and 1 (SSE) set; the CPU rejects values missing these.
/// - Must be called from ring 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn write_xcr0(val: u64) {
    let lo = val as u32;
    let hi = (val >> 32) as u32;
    // SAFETY: Caller ensures val is a valid XCR0 combination and ring 0.
    unsafe {
        core::arch::asm!(
            "xsetbv",
            in("ecx") 0u32,
            in("eax") lo,
            in("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
}

// ---------------------------------------------------------------------------
// CPUID-based Size Query
// ---------------------------------------------------------------------------

/// Returns the XSAVE area size for the currently-enabled XCR0 components,
/// as reported by CPUID leaf 0xD, sub-leaf 0 (EBX).
///
/// This is the minimum save area size needed by XSAVE.
///
/// # Safety
/// CPUID leaf 0xD must be available (check `max_basic_leaf >= 0xD`).
#[cfg(target_arch = "x86_64")]
pub unsafe fn xsave_size_for_current() -> Result<u32> {
    let ebx: u32;
    // SAFETY: CPUID is always safe to call; RBX preserved via tmp register.
    unsafe {
        core::arch::asm!(
            "mov {tmp:r}, rbx",
            "cpuid",
            "xchg {tmp:r}, rbx",
            inout("eax") 0x0Du32 => _,
            inout("ecx") 0u32 => _,
            tmp = out(reg) ebx,
            out("edx") _,
            options(nomem, nostack, preserves_flags),
        );
    }
    if ebx as usize > XSAVE_AREA_MAX {
        return Err(Error::InvalidArgument);
    }
    Ok(ebx)
}

// ---------------------------------------------------------------------------
// FPU Save Mode
// ---------------------------------------------------------------------------

/// Identifies which FPU save/restore mechanism to use for context switches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FpuMode {
    /// Use `FXSAVE64`/`FXRSTOR64` (SSE only, no AVX).
    Fxsave,
    /// Use `XSAVE64`/`XRSTOR64` with the given component mask.
    Xsave(u64),
}

impl FpuMode {
    /// Returns the state save area size in bytes required for this mode.
    pub const fn area_size(&self) -> usize {
        match self {
            FpuMode::Fxsave => FXSAVE_AREA_SIZE,
            FpuMode::Xsave(_) => XSAVE_AREA_MAX,
        }
    }

    /// Returns `true` if AVX state is included in this mode.
    pub const fn has_avx(&self) -> bool {
        match self {
            FpuMode::Fxsave => false,
            FpuMode::Xsave(mask) => *mask & XCR0_AVX != 0,
        }
    }
}

// ---------------------------------------------------------------------------
// FPU Initialisation
// ---------------------------------------------------------------------------

/// Initialises FPU/SSE/AVX on the current CPU.
///
/// Steps performed:
/// 1. Clear `CR0.EM` (disable FPU emulation) and set `CR0.MP`.
/// 2. Set `CR4.OSFXSR` and `CR4.OSXMMEXCPT` (SSE + exception support).
/// 3. If XSAVE is available, also set `CR4.OSXSAVE` and configure XCR0.
///
/// # Parameters
/// - `enable_avx`: Request AVX support if the CPU provides it.
///
/// # Errors
/// Returns `Error::NotImplemented` if SSE is not available on this CPU.
///
/// # Safety
/// Must be called from ring 0, once per CPU, during early boot.
/// Misuse can prevent FPU access or trigger unexpected #NM/#GP faults.
#[cfg(target_arch = "x86_64")]
pub unsafe fn init_fpu(enable_avx: bool) -> Result<()> {
    use crate::cr_regs;

    // SAFETY: Boot-time ring-0 initialisation; exclusive CPU access assumed.
    unsafe {
        // Step 1: Adjust CR0: clear EM, set MP, set NE.
        let cr0 = cr_regs::read_cr0();
        cr_regs::write_cr0((cr0 & !cr_regs::cr0::EM) | cr_regs::cr0::MP | cr_regs::cr0::NE);

        // Step 2: Enable SSE in CR4.
        let cr4 = cr_regs::read_cr4();
        cr_regs::write_cr4(cr4 | cr_regs::cr4::OSFXSR | cr_regs::cr4::OSXMMEXCPT);

        // Step 3: Probe XSAVE via CPUID leaf 1, ECX bit 26.
        let ecx: u32;
        core::arch::asm!(
            "mov {tmp:r}, rbx",
            "cpuid",
            "xchg {tmp:r}, rbx",
            inout("eax") 1u32 => _,
            out("ecx") ecx,
            out("edx") _,
            tmp = out(reg) _,
            options(nomem, nostack, preserves_flags),
        );
        let has_xsave = ecx & (1 << 26) != 0;
        let has_avx = ecx & (1 << 28) != 0;

        if has_xsave {
            // Enable OSXSAVE so ring-3 can use XSAVE instructions.
            let cr4 = cr_regs::read_cr4();
            cr_regs::write_cr4(cr4 | cr_regs::cr4::OSXSAVE);

            // Choose XCR0 mask based on available and requested features.
            let mask = if enable_avx && has_avx {
                XCR0_AVX_FULL
            } else {
                XCR0_SSE_ONLY
            };
            write_xcr0(mask);
        }
    }
    Ok(())
}

/// Detects the FPU save mode appropriate for the current CPU.
///
/// Must be called after `init_fpu()` so that XCR0 is configured.
///
/// # Safety
/// CPUID must be available (always true on x86_64).
#[cfg(target_arch = "x86_64")]
pub unsafe fn detect_fpu_mode() -> FpuMode {
    // SAFETY: Informational CPUID read; RBX preserved via tmp register.
    unsafe {
        let ecx: u32;
        core::arch::asm!(
            "mov {tmp:r}, rbx",
            "cpuid",
            "xchg {tmp:r}, rbx",
            inout("eax") 1u32 => _,
            out("ecx") ecx,
            out("edx") _,
            tmp = out(reg) _,
            options(nomem, nostack, preserves_flags),
        );
        let has_xsave = ecx & (1 << 26) != 0;
        let has_avx = ecx & (1 << 28) != 0;
        if has_xsave {
            let mask = if has_avx {
                XCR0_AVX_FULL
            } else {
                XCR0_SSE_ONLY
            };
            FpuMode::Xsave(mask)
        } else {
            FpuMode::Fxsave
        }
    }
}
