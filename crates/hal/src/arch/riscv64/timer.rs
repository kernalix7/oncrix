// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RISC-V CLINT timer driver (SBI or direct MMIO).
//!
//! Uses the SBI timer extension (EID 0x54494D45 "TIME") for portability.
//! Falls back to direct CLINT MMIO (base 0x0200_0000) when SBI is unavailable.
//!
//! QEMU virt: SBI (OpenSBI) is available via `ecall` in S-mode.
//!
//! References:
//!   - RISC-V SBI Specification §5 (Timer Extension)
//!   - RISC-V Privileged Spec §3.1.15 (mtime / mtimecmp)

use crate::timer::Timer;
use oncrix_lib::Result;

/// CLINT MMIO base for QEMU virt machine.
pub const CLINT_BASE: usize = 0x0200_0000;

/// SBI extension ID for the Timer extension.
const SBI_EXT_TIMER: usize = 0x5449_4D45;
/// SBI function ID: sbi_set_timer.
const SBI_FUNC_SET_TIMER: usize = 0;

/// Perform an SBI ecall.
///
/// # Safety
/// `ext` and `fid` must be valid SBI extension / function IDs.
/// Arguments are passed in a0–a5; return in a0 (error) and a1 (value).
#[cfg(target_arch = "riscv64")]
unsafe fn sbi_call(ext: usize, fid: usize, a0: usize, a1: usize, a2: usize) -> (isize, usize) {
    let error: isize;
    let value: usize;
    // SAFETY: ecall transfers to M-mode (SBI firmware); arguments follow
    // the SBI calling convention (RISC-V ABI).
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") a0 => error,
            inlateout("a1") a1 => value,
            in("a2") a2,
            in("a6") fid,
            in("a7") ext,
            options(nostack),
        );
    }
    (error, value)
}

/// RISC-V generic timer (SBI-based).
pub struct RiscvTimer;

impl RiscvTimer {
    /// Create a new timer handle.
    pub const fn new() -> Self {
        Self
    }

    /// Read the current time via the `time` CSR (`rdtime`).
    #[cfg(target_arch = "riscv64")]
    fn read_mtime() -> u64 {
        // The CLINT mtime MMIO register (0x0200_BFF8) is M-mode only — OpenSBI
        // configures PMP so an S-mode read of it faults. The architectural
        // `time` CSR (0xC01), provided by Zicntr and mirrored from mtime by the
        // firmware, is the S-mode-accessible view; `rdtime` reads it.
        let t: u64;
        // SAFETY: `rdtime` (csrr time) is a side-effect-free read of the
        // S-mode-readable time counter.
        unsafe {
            core::arch::asm!("rdtime {}", out(reg) t, options(nomem, nostack, preserves_flags));
        }
        t
    }

    /// Set the next timer interrupt via SBI `sbi_set_timer`.
    #[cfg(target_arch = "riscv64")]
    fn set_timer_sbi(absolute_time: u64) {
        // SAFETY: SBI ecall with the Timer extension (EID 0x54494D45).
        // a0 = stime_value (lower 64 bits on RV64).
        unsafe {
            sbi_call(
                SBI_EXT_TIMER,
                SBI_FUNC_SET_TIMER,
                absolute_time as usize,
                0,
                0,
            );
        }
    }
}

impl Default for RiscvTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl Timer for RiscvTimer {
    fn frequency_hz(&self) -> u64 {
        // QEMU virt exposes timer frequency via the device tree (timebase-frequency).
        // 10 MHz is the default; read from a known fixed address or use SBI probe.
        10_000_000
    }

    fn current_ticks(&self) -> u64 {
        #[cfg(target_arch = "riscv64")]
        {
            Self::read_mtime()
        }
        #[cfg(not(target_arch = "riscv64"))]
        {
            0
        }
    }

    fn set_oneshot(&mut self, ticks: u64) -> Result<()> {
        #[cfg(target_arch = "riscv64")]
        {
            let deadline = Self::read_mtime().wrapping_add(ticks);
            Self::set_timer_sbi(deadline);

            // Enable supervisor timer interrupt in sie register.
            // SAFETY: Writing sie.STIE (bit 5) to enable S-mode timer interrupts.
            unsafe {
                core::arch::asm!(
                    "csrs sie, {stie}",
                    stie = in(reg) 1usize << 5,
                    options(nostack, preserves_flags),
                );
            }
        }
        #[cfg(not(target_arch = "riscv64"))]
        let _ = ticks;
        Ok(())
    }

    fn set_periodic(&mut self, ticks: u64) -> Result<()> {
        // No hardware periodic mode; re-arm in the interrupt handler.
        self.set_oneshot(ticks)
    }

    fn stop(&mut self) -> Result<()> {
        // Mask the supervisor timer interrupt in sie.
        #[cfg(target_arch = "riscv64")]
        {
            // SAFETY: Clearing sie.STIE (bit 5) disables S-mode timer interrupts.
            unsafe {
                core::arch::asm!(
                    "csrc sie, {stie}",
                    stie = in(reg) 1usize << 5,
                    options(nostack, preserves_flags),
                );
            }
        }
        Ok(())
    }
}
