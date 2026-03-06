// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Local APIC timer — one-shot, periodic, and TSC-deadline modes.
//!
//! The Local APIC contains a built-in 32-bit down-counter timer that can
//! deliver a vector to the current CPU in three modes:
//!
//! | Mode          | Bits 18:17 | Description                                   |
//! |---------------|:----------:|-----------------------------------------------|
//! | One-shot      |  `00`      | Fires once when counter reaches zero.         |
//! | Periodic      |  `01`      | Reloads from initial-count and fires again.   |
//! | TSC-deadline  |  `10`      | Fires when TSC ≥ `IA32_TSC_DEADLINE` MSR.     |
//!
//! This module wraps the low-level APIC MMIO accesses from `lapic.rs` and
//! provides a higher-level [`LapicTimer`] driver suitable for per-CPU tick
//! and one-shot event programming.
//!
//! Reference: Intel SDM Vol 3A §10.5.4 (APIC Timer), §10.6.3 (LVT Timer).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// APIC register offsets (from `lapic.rs` — copied for standalone use)
// ---------------------------------------------------------------------------

/// LVT Timer Register.
const REG_LVT_TIMER: u32 = 0x320;

/// Initial Count Register.
const REG_TIMER_INITIAL: u32 = 0x380;

/// Current Count Register (read-only).
const REG_TIMER_CURRENT: u32 = 0x390;

/// Divide Configuration Register.
const REG_TIMER_DIVIDE: u32 = 0x3E0;

/// LVT bit 16: mask bit (interrupt disabled when set).
const LVT_MASKED: u32 = 1 << 16;

/// LVT timer mode field: bits 18:17.
const LVT_TIMER_MODE_MASK: u32 = 0x3 << 17;

/// LVT timer mode: one-shot (bits 18:17 = 00).
const LVT_TIMER_ONESHOT: u32 = 0x0 << 17;

/// LVT timer mode: periodic (bits 18:17 = 01).
const LVT_TIMER_PERIODIC: u32 = 0x1 << 17;

/// LVT timer mode: TSC-deadline (bits 18:17 = 10).
const LVT_TIMER_TSCDEADLINE: u32 = 0x2 << 17;

/// MSR: `IA32_TSC_DEADLINE`.
const MSR_TSC_DEADLINE: u32 = 0x6E0;

// ---------------------------------------------------------------------------
// TimerMode
// ---------------------------------------------------------------------------

/// APIC timer operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimerMode {
    /// One-shot: fires once when the counter reaches zero.
    #[default]
    OneShot,
    /// Periodic: reloads from initial count and fires repeatedly.
    Periodic,
    /// TSC-deadline: fires when TSC ≥ `IA32_TSC_DEADLINE` MSR.
    TscDeadline,
}

// ---------------------------------------------------------------------------
// DivideConfig
// ---------------------------------------------------------------------------

/// APIC timer divide configuration.
///
/// The timer input clock = (APIC bus clock or core crystal clock) / divisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum DivideConfig {
    /// Divide by 2.
    By2 = 0x0,
    /// Divide by 4.
    By4 = 0x1,
    /// Divide by 8.
    By8 = 0x2,
    /// Divide by 16.
    #[default]
    By16 = 0x3,
    /// Divide by 32.
    By32 = 0x8,
    /// Divide by 64.
    By64 = 0x9,
    /// Divide by 128.
    By128 = 0xA,
    /// Divide by 1 (use raw input clock).
    By1 = 0xB,
}

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

#[inline]
unsafe fn read_apic(base: u64, offset: u32) -> u32 {
    // SAFETY: Caller guarantees base+offset is a valid APIC MMIO address.
    unsafe { core::ptr::read_volatile((base + offset as u64) as *const u32) }
}

#[inline]
unsafe fn write_apic(base: u64, offset: u32, val: u32) {
    // SAFETY: Caller guarantees base+offset is a valid APIC MMIO address.
    unsafe { core::ptr::write_volatile((base + offset as u64) as *mut u32, val) }
}

// ---------------------------------------------------------------------------
// LapicTimer
// ---------------------------------------------------------------------------

/// Local APIC timer driver.
///
/// Wraps the APIC MMIO region and provides one-shot, periodic, and
/// TSC-deadline timer programming for a single CPU core.
pub struct LapicTimer {
    /// Virtual base address of the Local APIC MMIO region.
    apic_base: u64,
    /// Currently configured mode.
    mode: TimerMode,
    /// Interrupt vector for timer expiry.
    vector: u8,
    /// Divide configuration in use.
    divide: DivideConfig,
    /// Whether TSC-deadline mode is available.
    tsc_deadline_capable: bool,
    /// Whether the timer is currently running.
    running: bool,
}

impl LapicTimer {
    /// Create a new `LapicTimer` for the APIC at `apic_base`.
    ///
    /// `vector` is the interrupt vector to deliver on expiry.
    /// `tsc_deadline_capable` should be set from `TscHwInfo::tsc_deadline`.
    pub const fn new(apic_base: u64, vector: u8, tsc_deadline_capable: bool) -> Self {
        Self {
            apic_base,
            mode: TimerMode::OneShot,
            vector,
            divide: DivideConfig::By16,
            tsc_deadline_capable,
            running: false,
        }
    }

    /// Set the divide configuration.
    ///
    /// Must be called before `arm_oneshot` / `arm_periodic` to take effect.
    pub fn set_divide(&mut self, divide: DivideConfig) {
        self.divide = divide;
    }

    /// Arm the timer in one-shot mode with `initial_count`.
    ///
    /// The timer fires when the counter decrements to zero.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `initial_count` is zero.
    pub fn arm_oneshot(&mut self, initial_count: u32) -> Result<()> {
        if initial_count == 0 {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: apic_base is a mapped Local APIC MMIO region.
        unsafe {
            write_apic(self.apic_base, REG_TIMER_DIVIDE, self.divide as u32);
            let lvt = LVT_TIMER_ONESHOT | (self.vector as u32);
            write_apic(self.apic_base, REG_LVT_TIMER, lvt);
            write_apic(self.apic_base, REG_TIMER_INITIAL, initial_count);
        }
        self.mode = TimerMode::OneShot;
        self.running = true;
        Ok(())
    }

    /// Arm the timer in periodic mode with `initial_count`.
    ///
    /// The timer fires every time the counter decrements from `initial_count`
    /// to zero.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `initial_count` is zero.
    pub fn arm_periodic(&mut self, initial_count: u32) -> Result<()> {
        if initial_count == 0 {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: apic_base is a mapped Local APIC MMIO region.
        unsafe {
            write_apic(self.apic_base, REG_TIMER_DIVIDE, self.divide as u32);
            let lvt = LVT_TIMER_PERIODIC | (self.vector as u32);
            write_apic(self.apic_base, REG_LVT_TIMER, lvt);
            write_apic(self.apic_base, REG_TIMER_INITIAL, initial_count);
        }
        self.mode = TimerMode::Periodic;
        self.running = true;
        Ok(())
    }

    /// Arm the timer in TSC-deadline mode with an absolute `tsc_deadline`.
    ///
    /// Fires when the processor TSC reaches or exceeds `tsc_deadline`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if TSC-deadline is not supported
    /// or the build target is not x86_64.
    pub fn arm_tsc_deadline(&mut self, tsc_deadline: u64) -> Result<()> {
        if !self.tsc_deadline_capable {
            return Err(Error::NotImplemented);
        }
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: Writing the LVT timer register to TSC-deadline mode.
            unsafe {
                let lvt = LVT_TIMER_TSCDEADLINE | (self.vector as u32);
                write_apic(self.apic_base, REG_LVT_TIMER, lvt);
                // Serialise before writing the MSR.
                core::arch::asm!("mfence", options(nostack, nomem, preserves_flags));
                // Write IA32_TSC_DEADLINE MSR
                let lo = tsc_deadline as u32;
                let hi = (tsc_deadline >> 32) as u32;
                core::arch::asm!(
                    "wrmsr",
                    in("ecx") MSR_TSC_DEADLINE,
                    in("eax") lo,
                    in("edx") hi,
                    options(nostack, nomem, preserves_flags),
                );
            }
            self.mode = TimerMode::TscDeadline;
            self.running = true;
            Ok(())
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = tsc_deadline;
            Err(Error::NotImplemented)
        }
    }

    /// Stop the timer by masking the LVT entry and writing zero to initial count.
    pub fn stop(&mut self) {
        // SAFETY: Masking the LVT timer prevents further interrupts.
        unsafe {
            let lvt = read_apic(self.apic_base, REG_LVT_TIMER);
            write_apic(self.apic_base, REG_LVT_TIMER, lvt | LVT_MASKED);
            write_apic(self.apic_base, REG_TIMER_INITIAL, 0);
        }
        self.running = false;
    }

    /// Read the current timer counter value.
    pub fn current_count(&self) -> u32 {
        // SAFETY: Reading a read-only APIC register.
        unsafe { read_apic(self.apic_base, REG_TIMER_CURRENT) }
    }

    /// Return the timer mode in use.
    pub const fn mode(&self) -> TimerMode {
        self.mode
    }

    /// Return `true` if the timer is currently running.
    pub const fn is_running(&self) -> bool {
        self.running
    }

    /// Return the configured interrupt vector.
    pub const fn vector(&self) -> u8 {
        self.vector
    }

    /// Change the interrupt vector for future arm operations.
    ///
    /// Takes effect on the next `arm_*` call.
    pub fn set_vector(&mut self, vector: u8) {
        self.vector = vector;
    }

    /// Mask/unmask the LVT timer entry without stopping the counter.
    ///
    /// Useful for temporarily suppressing delivery.
    pub fn set_masked(&self, masked: bool) {
        // SAFETY: Read-modify-write on the LVT timer register.
        unsafe {
            let lvt = read_apic(self.apic_base, REG_LVT_TIMER);
            let new_lvt = if masked {
                (lvt & !LVT_TIMER_MODE_MASK) | LVT_MASKED
            } else {
                lvt & !LVT_MASKED
            };
            write_apic(self.apic_base, REG_LVT_TIMER, new_lvt);
        }
    }
}

// ---------------------------------------------------------------------------
// Frequency calibration via PIT
// ---------------------------------------------------------------------------

/// Calibrate the APIC timer frequency using the PIT as a reference.
///
/// Programs channel 0 of the APIC timer in one-shot mode and measures
/// how many APIC ticks correspond to a PIT window.
///
/// Returns the APIC timer frequency in Hz, or `Err(Error::IoError)` if the
/// measured frequency is implausible.
///
/// # Safety
///
/// `apic_base` must be the virtual address of a mapped Local APIC MMIO region.
/// Must be called from ring 0.
pub unsafe fn calibrate_with_pit(apic_base: u64, divide: DivideConfig) -> Result<u64> {
    #[cfg(target_arch = "x86_64")]
    {
        const PIT_CLOCK_HZ: u64 = 1_193_182;
        const GATE_TICKS: u16 = 11_932; // ~10 ms
        const GATE_NS: u64 = GATE_TICKS as u64 * 1_000_000_000 / PIT_CLOCK_HZ;

        // SAFETY: Port I/O to PIT/system-control, ring-0 context.
        unsafe {
            let ctrl: u8;
            core::arch::asm!("in al, 0x61", out("al") ctrl, options(nostack, nomem));
            core::arch::asm!("out 0x61, al", in("al") ctrl & 0xFE_u8, options(nostack, nomem));
            core::arch::asm!("out 0x43, al", in("al") 0xB0_u8, options(nostack, nomem));
            core::arch::asm!("out 0x42, al",
                in("al") (GATE_TICKS & 0xFF) as u8, options(nostack, nomem));
            core::arch::asm!("out 0x42, al",
                in("al") (GATE_TICKS >> 8) as u8, options(nostack, nomem));

            // Arm APIC timer with maximum initial count.
            write_apic(apic_base, REG_TIMER_DIVIDE, divide as u32);
            let lvt = LVT_TIMER_ONESHOT | LVT_MASKED | 0xFF;
            write_apic(apic_base, REG_LVT_TIMER, lvt);
            write_apic(apic_base, REG_TIMER_INITIAL, u32::MAX);

            // Enable PIT gate.
            core::arch::asm!("out 0x61, al", in("al") ctrl | 0x01_u8, options(nostack, nomem));
        }

        // Poll OUT2 until terminal count.
        loop {
            let s: u8;
            // SAFETY: Polling port 0x61 bit 5 — read-only.
            unsafe {
                core::arch::asm!("in al, 0x61", out("al") s, options(nostack, nomem));
            }
            if s & 0x20 != 0 {
                break;
            }
            core::hint::spin_loop();
        }

        // SAFETY: Reading the APIC timer current count.
        let remaining = unsafe { read_apic(apic_base, REG_TIMER_CURRENT) };
        let elapsed = u32::MAX.wrapping_sub(remaining) as u64;

        // freq = elapsed_ticks * 10^9 / gate_ns
        let freq = ((elapsed as u128).saturating_mul(1_000_000_000) / GATE_NS as u128) as u64;
        if freq < 1_000_000 || freq > 10_000_000_000 {
            return Err(Error::IoError);
        }
        Ok(freq)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (apic_base, divide);
        Err(Error::NotImplemented)
    }
}
