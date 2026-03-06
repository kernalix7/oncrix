// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! x86_64 Local APIC (LAPIC) low-level access layer.
//!
//! This module provides direct register-level access to the x86_64
//! Local APIC, complementing the higher-level `apic` and `lapic`
//! modules with:
//!
//! - xAPIC (MMIO) and x2APIC (MSR) mode support
//! - LAPIC timer setup and one-shot/periodic modes
//! - Inter-Processor Interrupt (IPI) delivery
//! - Spurious interrupt vector configuration
//! - End-of-interrupt (EOI) signaling
//!
//! Reference: Intel SDM Vol. 3A, Chapter 10 — Advanced Programmable
//! Interrupt Controller (APIC).

use oncrix_lib::{Error, Result};

// ── LAPIC Register Offsets (xAPIC MMIO mode) ──────────────────────────────

/// LAPIC ID register offset.
pub const LAPIC_ID: u32 = 0x020;
/// LAPIC version register offset.
pub const LAPIC_VER: u32 = 0x030;
/// Task Priority Register.
pub const LAPIC_TPR: u32 = 0x080;
/// End-of-Interrupt register.
pub const LAPIC_EOI: u32 = 0x0B0;
/// Spurious Interrupt Vector Register.
pub const LAPIC_SVR: u32 = 0x0F0;
/// Interrupt Command Register low 32 bits.
pub const LAPIC_ICR_LO: u32 = 0x300;
/// Interrupt Command Register high 32 bits.
pub const LAPIC_ICR_HI: u32 = 0x310;
/// LVT Timer register.
pub const LAPIC_LVT_TIMER: u32 = 0x320;
/// LVT LINT0 register.
pub const LAPIC_LVT_LINT0: u32 = 0x350;
/// LVT LINT1 register.
pub const LAPIC_LVT_LINT1: u32 = 0x360;
/// LVT Error register.
pub const LAPIC_LVT_ERROR: u32 = 0x370;
/// Initial Count register (timer).
pub const LAPIC_TIMER_INIT: u32 = 0x380;
/// Current Count register (timer).
pub const LAPIC_TIMER_CUR: u32 = 0x390;
/// Divide Configuration register (timer).
pub const LAPIC_TIMER_DCR: u32 = 0x3E0;

// ── Register Bit Definitions ───────────────────────────────────────────────

/// SVR: APIC Software Enable bit.
pub const SVR_ENABLE: u32 = 1 << 8;
/// SVR: Focus Processor Checking disable bit.
pub const SVR_FOCUS_DISABLE: u32 = 1 << 9;
/// LVT MASK bit — mask the interrupt vector.
pub const LVT_MASKED: u32 = 1 << 16;
/// LVT Timer mode: periodic.
pub const LVT_TIMER_PERIODIC: u32 = 1 << 17;
/// LVT Timer mode: TSC-deadline (bit 18).
pub const LVT_TIMER_TSCDEADLINE: u32 = 1 << 18;
/// ICR delivery status: Send Pending.
pub const ICR_SEND_PENDING: u32 = 1 << 12;
/// ICR delivery mode: INIT.
pub const ICR_DELIV_INIT: u32 = 5 << 8;
/// ICR delivery mode: Start-Up (SIPI).
pub const ICR_DELIV_SIPI: u32 = 6 << 8;
/// ICR level: Assert.
pub const ICR_LEVEL_ASSERT: u32 = 1 << 14;

/// x2APIC MSR base for register access (APIC_BASE_MSR + offset/16).
const X2APIC_MSR_BASE: u32 = 0x800;

/// x86 APIC_BASE MSR index.
const MSR_APIC_BASE: u32 = 0x1B;
/// x2APIC enable bit in APIC_BASE MSR.
const APIC_BASE_X2APIC_EN: u64 = 1 << 10;
/// xAPIC global enable bit.
const APIC_BASE_ENABLE: u64 = 1 << 11;

// ── MSR helpers ────────────────────────────────────────────────────────────

/// Read an MSR.
///
/// # Safety
/// The MSR index must be valid for the current CPU model and privilege level.
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: caller guarantees valid MSR index.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nostack, nomem, preserves_flags),
        );
    }
    ((hi as u64) << 32) | lo as u64
}

/// Write an MSR.
///
/// # Safety
/// The MSR index must be valid; writing incorrect values can crash the system.
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn wrmsr(msr: u32, val: u64) {
    // SAFETY: caller guarantees valid MSR index and safe value.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") val as u32,
            in("edx") (val >> 32) as u32,
            options(nostack, nomem, preserves_flags),
        );
    }
}

// ── LAPIC Access Mode ──────────────────────────────────────────────────────

/// LAPIC operating mode.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LapicMode {
    /// xAPIC mode: registers accessed via MMIO.
    XApic(usize),
    /// x2APIC mode: registers accessed via MSRs.
    X2Apic,
}

// ── Local APIC ─────────────────────────────────────────────────────────────

/// x86_64 Local APIC controller.
pub struct X86Lapic {
    mode: LapicMode,
}

impl Default for X86Lapic {
    fn default() -> Self {
        Self {
            mode: LapicMode::XApic(0xFEE0_0000),
        }
    }
}

impl X86Lapic {
    /// Create an xAPIC instance with the given MMIO base.
    ///
    /// # Safety
    /// `base` must be the MMIO base of the Local APIC, mapped with
    /// strong uncacheable (UC) memory type, read/write permissions.
    pub unsafe fn new_xapic(base: usize) -> Self {
        Self {
            mode: LapicMode::XApic(base),
        }
    }

    /// Create an x2APIC instance (uses MSR access).
    pub fn new_x2apic() -> Self {
        Self {
            mode: LapicMode::X2Apic,
        }
    }

    /// Read a LAPIC register (32-bit).
    pub fn read(&self, offset: u32) -> u32 {
        match self.mode {
            LapicMode::XApic(base) => {
                // SAFETY: base is valid MMIO, offset is a known LAPIC register.
                unsafe { core::ptr::read_volatile((base + offset as usize) as *const u32) }
            }
            #[cfg(target_arch = "x86_64")]
            LapicMode::X2Apic => {
                let msr = X2APIC_MSR_BASE + (offset >> 4);
                // SAFETY: x2APIC MSR derived from valid register offset.
                unsafe { rdmsr(msr) as u32 }
            }
            #[cfg(not(target_arch = "x86_64"))]
            LapicMode::X2Apic => 0,
        }
    }

    /// Write a LAPIC register (32-bit).
    pub fn write(&self, offset: u32, val: u32) {
        match self.mode {
            LapicMode::XApic(base) => {
                // SAFETY: base is valid MMIO, offset is a known LAPIC register.
                unsafe { core::ptr::write_volatile((base + offset as usize) as *mut u32, val) }
            }
            #[cfg(target_arch = "x86_64")]
            LapicMode::X2Apic => {
                let msr = X2APIC_MSR_BASE + (offset >> 4);
                // SAFETY: x2APIC MSR derived from valid register offset.
                unsafe { wrmsr(msr, val as u64) }
            }
            #[cfg(not(target_arch = "x86_64"))]
            LapicMode::X2Apic => {}
        }
    }

    /// Initialize the LAPIC: enable via SVR, set spurious vector.
    pub fn init(&self, spurious_vector: u8) -> Result<()> {
        let svr = SVR_ENABLE | SVR_FOCUS_DISABLE | spurious_vector as u32;
        self.write(LAPIC_SVR, svr);
        // Mask LVT entries by default.
        self.write(LAPIC_LVT_TIMER, LVT_MASKED);
        self.write(LAPIC_LVT_LINT0, LVT_MASKED);
        self.write(LAPIC_LVT_LINT1, LVT_MASKED);
        self.write(LAPIC_LVT_ERROR, LVT_MASKED);
        // Accept all interrupt priorities.
        self.write(LAPIC_TPR, 0);
        Ok(())
    }

    /// Enable the LAPIC software enable bit in APIC_BASE MSR.
    ///
    /// # Safety
    /// Must be called from a CPU with APIC support; modifies APIC_BASE MSR.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn enable_global(&self) -> Result<()> {
        // SAFETY: MSR_APIC_BASE is valid on all x86_64 CPUs with APIC.
        let val = unsafe { rdmsr(MSR_APIC_BASE) };
        unsafe { wrmsr(MSR_APIC_BASE, val | APIC_BASE_ENABLE) }
        Ok(())
    }

    /// Switch the LAPIC to x2APIC mode.
    ///
    /// # Safety
    /// Must only be called when already in xAPIC enabled mode (bit 11 set).
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn enable_x2apic(&self) -> Result<()> {
        // SAFETY: MSR_APIC_BASE modification to enable x2APIC; must be in
        // xAPIC mode (EN=1) before setting x2APIC bit.
        let val = unsafe { rdmsr(MSR_APIC_BASE) };
        unsafe { wrmsr(MSR_APIC_BASE, val | APIC_BASE_ENABLE | APIC_BASE_X2APIC_EN) }
        Ok(())
    }

    /// Signal End-of-Interrupt.
    pub fn eoi(&self) {
        self.write(LAPIC_EOI, 0);
    }

    /// Read the current LAPIC ID.
    pub fn id(&self) -> u32 {
        match self.mode {
            LapicMode::XApic(_) => self.read(LAPIC_ID) >> 24,
            LapicMode::X2Apic => self.read(LAPIC_ID),
        }
    }

    /// Configure one-shot LAPIC timer with the given initial count and vector.
    pub fn timer_oneshot(&self, vector: u8, count: u32, divide: u8) -> Result<()> {
        // Divide configuration: 0b1011 = divide by 1.
        self.write(LAPIC_TIMER_DCR, divide as u32 & 0xF);
        self.write(LAPIC_LVT_TIMER, vector as u32); // one-shot mode
        self.write(LAPIC_TIMER_INIT, count);
        Ok(())
    }

    /// Configure periodic LAPIC timer.
    pub fn timer_periodic(&self, vector: u8, count: u32, divide: u8) -> Result<()> {
        self.write(LAPIC_TIMER_DCR, divide as u32 & 0xF);
        self.write(LAPIC_LVT_TIMER, vector as u32 | LVT_TIMER_PERIODIC);
        self.write(LAPIC_TIMER_INIT, count);
        Ok(())
    }

    /// Stop the LAPIC timer.
    pub fn timer_stop(&self) {
        self.write(LAPIC_TIMER_INIT, 0);
        self.write(LAPIC_LVT_TIMER, LVT_MASKED);
    }

    /// Send an INIT IPI to a specific APIC ID (xAPIC only).
    pub fn send_init_ipi(&self, dest_apic_id: u32) -> Result<()> {
        self.write(LAPIC_ICR_HI, dest_apic_id << 24);
        self.write(LAPIC_ICR_LO, ICR_DELIV_INIT | ICR_LEVEL_ASSERT);
        self.wait_icr_idle()
    }

    /// Send a Start-Up (SIPI) IPI with the given startup page (shifted right 12 bits).
    pub fn send_sipi(&self, dest_apic_id: u32, startup_page: u8) -> Result<()> {
        self.write(LAPIC_ICR_HI, dest_apic_id << 24);
        self.write(
            LAPIC_ICR_LO,
            ICR_DELIV_SIPI | ICR_LEVEL_ASSERT | startup_page as u32,
        );
        self.wait_icr_idle()
    }

    /// Poll ICR delivery status until idle or timeout.
    fn wait_icr_idle(&self) -> Result<()> {
        for _ in 0..100_000 {
            if self.read(LAPIC_ICR_LO) & ICR_SEND_PENDING == 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }
}
