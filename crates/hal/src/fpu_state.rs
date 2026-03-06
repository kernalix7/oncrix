// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! FPU/SSE/AVX processor state save and restore.
//!
//! Modern x86_64 processors may use `XSAVE`/`XRSTOR` (if OSXSAVE is set in CR4)
//! or the legacy `FXSAVE`/`FXRSTOR` for saving floating-point, SSE, and AVX state.
//!
//! # State components tracked by XCR0
//! | Bit | Component | Min size |
//! |-----|-----------|----------|
//! |  0  | x87 FPU   | 160 bytes|
//! |  1  | SSE (XMM) | 256 bytes|
//! |  2  | AVX (YMM high) | 256 bytes|
//! | 5–7 | AVX-512 (opmask, ZMM_hi256, Hi16_ZMM) | variable |
//!
//! # Lazy FPU tracking
//! The kernel uses lazy FPU context switching: on every task switch the TS bit
//! in CR0 is set. When the task uses an FPU instruction, a #NM (Device Not
//! Available) fault fires, at which point we save the previous owner's state,
//! restore the current task's state, and clear TS.
//!
//! Reference: Intel 64 and IA-32 Architectures Software Developer's Manual,
//! Volume 1, Chapter 13 — Managing State Using x87 FPU.

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of the FXSAVE area in bytes (always 512 bytes).
pub const FXSAVE_SIZE: usize = 512;

/// Size of the XSAVE area in bytes. Must be at least 4096 bytes to hold
/// x87 + SSE + AVX + AVX-512 state. The exact size is returned by CPUID
/// leaf 0xD, but we use a fixed upper bound for static allocation.
pub const XSAVE_AREA_SIZE: usize = 4096;

/// Required alignment for FXSAVE/FXRSTOR areas.
pub const FXSAVE_ALIGN: usize = 16;

/// Required alignment for XSAVE/XRSTOR areas.
pub const XSAVE_ALIGN: usize = 64;

// ---------------------------------------------------------------------------
// XCR0 Feature Bits
// ---------------------------------------------------------------------------

/// XCR0 bit 0: x87 FPU state.
pub const XCR0_X87: u64 = 1 << 0;
/// XCR0 bit 1: SSE (XMM0–XMM15) state.
pub const XCR0_SSE: u64 = 1 << 1;
/// XCR0 bit 2: AVX (YMM high halves) state.
pub const XCR0_AVX: u64 = 1 << 2;
/// XCR0 bit 5: AVX-512 opmask registers (k0–k7).
pub const XCR0_OPMASK: u64 = 1 << 5;
/// XCR0 bit 6: AVX-512 ZMM_Hi256 (upper 256 bits of ZMM0–ZMM15).
pub const XCR0_ZMM_HI256: u64 = 1 << 6;
/// XCR0 bit 7: AVX-512 Hi16_ZMM (ZMM16–ZMM31).
pub const XCR0_HI16_ZMM: u64 = 1 << 7;

/// XCR0 value enabling all standard components (x87 + SSE + AVX).
pub const XCR0_BASE: u64 = XCR0_X87 | XCR0_SSE | XCR0_AVX;

/// XCR0 value enabling all AVX-512 components.
pub const XCR0_AVX512: u64 = XCR0_BASE | XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM;

// ---------------------------------------------------------------------------
// FPU State Buffer
// ---------------------------------------------------------------------------

/// Storage for one task's FPU/SSE/AVX processor state.
///
/// The buffer must be 64-byte aligned for `xsave`/`xrstor`. Since static
/// guarantees can't enforce heap alignment here, callers using `FpuState`
/// as a stack or embedded field must ensure it falls on a 64-byte boundary.
///
/// The actual save format depends on whether OSXSAVE is enabled:
/// - OSXSAVE set: XSAVE format (extended state).
/// - OSXSAVE clear: FXSAVE format (512 bytes, legacy).
#[repr(C, align(64))]
pub struct FpuState {
    /// Raw save area. Zeroed on construction.
    buf: [u8; XSAVE_AREA_SIZE],
    /// `true` if this buffer contains valid saved state.
    pub valid: bool,
}

impl FpuState {
    /// Creates a new, empty (invalid) FPU state buffer.
    pub const fn new() -> Self {
        Self {
            buf: [0u8; XSAVE_AREA_SIZE],
            valid: false,
        }
    }

    /// Returns a pointer to the save area buffer.
    pub fn as_ptr(&self) -> *const u8 {
        self.buf.as_ptr()
    }

    /// Returns a mutable pointer to the save area buffer.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.buf.as_mut_ptr()
    }

    /// Marks the state as invalid (e.g., after a new task starts).
    pub fn invalidate(&mut self) {
        self.valid = false;
    }
}

impl Default for FpuState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

/// Initializes the FPU: sets OSFXSR and OSXMMEXCPT in CR4, clears EM and TS,
/// sets MP in CR0, and issues `finit`.
///
/// Should be called once per CPU during early boot.
///
/// # Safety
/// Must be called from ring 0 before any FPU/SSE instructions execute.
#[cfg(target_arch = "x86_64")]
pub unsafe fn init_fpu() {
    use crate::cr_regs::{clear_cr0_bits, cr0, cr4, read_cr4, set_cr0_bits, set_cr4_bits};
    // SAFETY: Modifying CR0/CR4 to enable FPU/SSE; safe during boot.
    unsafe {
        // Clear EM (emulation) and set MP (monitor coprocessor), NE
        clear_cr0_bits(cr0::EM);
        set_cr0_bits(cr0::MP | cr0::NE);

        // Enable FXSAVE/FXRSTOR and unmasked SIMD exceptions in CR4
        set_cr4_bits(cr4::OSFXSR | cr4::OSXMMEXCPT);

        // If OSXSAVE is supported, enable it too
        let cpuid_ecx = cpuid_ecx_leaf1();
        if cpuid_ecx & (1 << 27) != 0 {
            set_cr4_bits(cr4::OSXSAVE);
            // Set XCR0 to enable x87 + SSE + AVX if supported
            let avx_supported = cpuid_ecx & (1 << 28) != 0;
            let xcr0 = if avx_supported {
                XCR0_BASE
            } else {
                XCR0_X87 | XCR0_SSE
            };
            write_xcr0(xcr0);
        }

        // Check that OSXSAVE is now set before we use xsave path
        let _cr4_val = read_cr4();

        // Initialize FPU to a clean state
        core::arch::asm!("fninit", options(nomem, nostack));
    }
}

/// Returns ECX from CPUID leaf 1 to detect SSE/AVX/OSXSAVE support.
///
/// # Safety
/// CPUID is available on all x86_64 CPUs. Using a temporary register via
/// the `{tmp:r}` modifier to avoid clobbering rbx (which is reserved in
/// certain calling conventions).
#[cfg(target_arch = "x86_64")]
unsafe fn cpuid_ecx_leaf1() -> u32 {
    let ecx: u32;
    // SAFETY: CPUID is a safe read-only instruction on x86_64.
    unsafe {
        core::arch::asm!(
            "mov {tmp:r}, rbx",
            "cpuid",
            "mov rbx, {tmp:r}",
            tmp = out(reg) _,
            inout("eax") 1u32 => _,
            out("ecx") ecx,
            out("edx") _,
            options(nomem, nostack),
        );
    }
    ecx
}

// ---------------------------------------------------------------------------
// XCR0 Access
// ---------------------------------------------------------------------------

/// Reads the current value of XCR0 (Extended Control Register 0).
///
/// # Safety
/// Requires OSXSAVE to be set in CR4 (i.e., `init_fpu()` was called with AVX
/// support). Calling `xgetbv` without OSXSAVE causes `#UD`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn read_xcr0() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: xgetbv with ECX=0 reads XCR0; requires OSXSAVE.
    unsafe {
        core::arch::asm!(
            "xgetbv",
            in("ecx") 0u32,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Writes `val` to XCR0.
///
/// # Safety
/// - Requires OSXSAVE in CR4.
/// - Bits must form a valid and supported feature set (check CPUID 0xD first).
/// - x87 (bit 0) and SSE (bit 1) must always remain enabled.
#[cfg(target_arch = "x86_64")]
pub unsafe fn write_xcr0(val: u64) {
    let lo = val as u32;
    let hi = (val >> 32) as u32;
    // SAFETY: xsetbv with ECX=0 writes XCR0; caller verified supported bits.
    unsafe {
        core::arch::asm!(
            "xsetbv",
            in("ecx") 0u32,
            in("eax") lo,
            in("edx") hi,
            options(nomem, nostack),
        );
    }
}

// ---------------------------------------------------------------------------
// Save / Restore
// ---------------------------------------------------------------------------

/// Saves the current FPU/SSE state into `state` using `FXSAVE`.
///
/// # Safety
/// - `state.buf` must be 16-byte aligned.
/// - The FPU must be initialized and in a consistent state.
/// - Must be called from ring 0 with interrupts disabled (or TS clear).
#[cfg(target_arch = "x86_64")]
pub unsafe fn fxsave(state: &mut FpuState) {
    // SAFETY: FXSAVE into a 16-byte aligned 512-byte buffer.
    unsafe {
        core::arch::asm!(
            "fxsave64 [{0}]",
            in(reg) state.buf.as_mut_ptr(),
            options(nostack),
        );
        state.valid = true;
    }
}

/// Restores FPU/SSE state from `state` using `FXRSTOR`.
///
/// # Safety
/// Same alignment and initialization requirements as `fxsave`.
/// `state.valid` should be `true`; restoring invalid data causes
/// undefined FPU behaviour.
#[cfg(target_arch = "x86_64")]
pub unsafe fn fxrstor(state: &FpuState) {
    // SAFETY: FXRSTOR from a 16-byte aligned buffer with valid content.
    unsafe {
        core::arch::asm!(
            "fxrstor64 [{0}]",
            in(reg) state.buf.as_ptr(),
            options(nostack),
        );
    }
}

/// Saves the full extended processor state into `state` using `XSAVE`.
///
/// Saves all components enabled in XCR0.
///
/// # Safety
/// - `state.buf` must be 64-byte aligned.
/// - OSXSAVE must be set in CR4.
/// - Must be called from ring 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn xsave(state: &mut FpuState) {
    // SAFETY: XSAVE into a 64-byte aligned buffer; OSXSAVE is set.
    unsafe {
        core::arch::asm!(
            "xsave64 [{0}]",
            in(reg) state.buf.as_mut_ptr(),
            in("eax") u32::MAX,
            in("edx") u32::MAX,
            options(nostack),
        );
        state.valid = true;
    }
}

/// Restores extended processor state from `state` using `XRSTOR`.
///
/// # Safety
/// Same as `xsave`. `state.valid` must be `true`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn xrstor(state: &FpuState) {
    // SAFETY: XRSTOR from a 64-byte aligned buffer with valid content.
    unsafe {
        core::arch::asm!(
            "xrstor64 [{0}]",
            in(reg) state.buf.as_ptr(),
            in("eax") u32::MAX,
            in("edx") u32::MAX,
            options(nostack),
        );
    }
}

/// Saves FPU state using XSAVE if OSXSAVE is enabled, or FXSAVE otherwise.
///
/// # Safety
/// See `xsave` and `fxsave`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn save_fpu_state(state: &mut FpuState, use_xsave: bool) {
    // SAFETY: Dispatches to either xsave or fxsave based on feature flag.
    unsafe {
        if use_xsave {
            xsave(state);
        } else {
            fxsave(state);
        }
    }
}

/// Restores FPU state using XRSTOR if OSXSAVE is enabled, or FXRSTOR otherwise.
///
/// # Safety
/// See `xrstor` and `fxrstor`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn restore_fpu_state(state: &FpuState, use_xsave: bool) {
    // SAFETY: Dispatches to either xrstor or fxrstor based on feature flag.
    unsafe {
        if use_xsave {
            xrstor(state);
        } else {
            fxrstor(state);
        }
    }
}

// ---------------------------------------------------------------------------
// Lazy FPU CR0.TS helpers
// ---------------------------------------------------------------------------

/// Sets CR0.TS (Task Switched) to trigger #NM on next FPU/SSE instruction.
///
/// Called on every task switch to implement lazy FPU context saving.
///
/// # Safety
/// Must be called from ring 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn lazy_fpu_disable() {
    use crate::cr_regs::{cr0, set_cr0_bits};
    // SAFETY: Setting TS defers FPU context save until it is actually needed.
    unsafe { set_cr0_bits(cr0::TS) }
}

/// Clears CR0.TS (after saving previous owner and restoring current task's state).
///
/// Called from the #NM exception handler.
///
/// # Safety
/// Must be called from ring 0, after the FPU state has been properly managed.
#[cfg(target_arch = "x86_64")]
pub unsafe fn lazy_fpu_enable() {
    // SAFETY: CLTS clears the Task Switched flag; called after FPU state management.
    unsafe {
        core::arch::asm!("clts", options(nomem, nostack, preserves_flags));
    }
}
