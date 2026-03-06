// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ACPI power management — S-states, C-states, and PM register access.
//!
//! Provides hardware-level access to ACPI fixed hardware registers (FADT)
//! for system sleep states (S1–S5) and processor idle states (C-states).
//!
//! # ACPI Sleep States
//!
//! | State | Name     | Description                           |
//! |-------|----------|---------------------------------------|
//! | S0    | Working  | System is fully on                    |
//! | S1    | Sleeping | Low-latency sleep, CPU/cache powered  |
//! | S3    | Suspend  | RAM retained, CPU/devices off         |
//! | S4    | Hibernate| RAM saved to disk, full power off     |
//! | S5    | Soft Off | Power off (no context retained)       |
//!
//! # C-states (CPU Idle)
//!
//! | State | Name | Description               |
//! |-------|------|---------------------------|
//! | C0    | —    | Active execution          |
//! | C1    | Halt | `hlt` instruction         |
//! | C2    | —    | Stop grant, clock gated   |
//! | C3    | Sleep| Stop clock, cache flushed |
//!
//! Reference: ACPI Specification 6.5, Sections 4 and 8.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// ACPI PM1 Register Bit Fields
// ---------------------------------------------------------------------------

/// PM1 Status: Power button pressed.
pub const PM1_STS_PWRBTN: u16 = 1 << 8;
/// PM1 Status: Sleep/wake button pressed.
pub const PM1_STS_SLPBTN: u16 = 1 << 9;
/// PM1 Status: RTC alarm.
pub const PM1_STS_RTC: u16 = 1 << 10;
/// PM1 Status: Wake status (RO).
pub const PM1_STS_WAK_STS: u16 = 1 << 15;

/// PM1 Enable: Power button enable.
pub const PM1_EN_PWRBTN: u16 = 1 << 8;
/// PM1 Enable: Sleep button enable.
pub const PM1_EN_SLPBTN: u16 = 1 << 9;
/// PM1 Enable: RTC alarm enable.
pub const PM1_EN_RTC: u16 = 1 << 10;

/// PM1 Control: SCI enable.
pub const PM1_CNT_SCI_EN: u16 = 1 << 0;
/// PM1 Control: Bus master reload.
pub const PM1_CNT_BM_RLD: u16 = 1 << 1;
/// PM1 Control: Global release.
pub const PM1_CNT_GBL_RLS: u16 = 1 << 2;
/// PM1 Control: Sleep type (bits 12:10).
pub const PM1_CNT_SLP_TYP_SHIFT: u16 = 10;
pub const PM1_CNT_SLP_TYP_MASK: u16 = 0x1C00;
/// PM1 Control: Sleep enable.
pub const PM1_CNT_SLP_EN: u16 = 1 << 13;

// ---------------------------------------------------------------------------
// ACPI Sleep Type Values (from \_S<N> DSDT objects)
// ---------------------------------------------------------------------------

/// ACPI SLP_TYP value for S3 (suspend to RAM) — typical value, hardware varies.
pub const SLP_TYP_S3: u8 = 5;
/// ACPI SLP_TYP value for S5 (soft power off) — typical value, hardware varies.
pub const SLP_TYP_S5: u8 = 7;

// ---------------------------------------------------------------------------
// C-state residency MSRs (Intel)
// ---------------------------------------------------------------------------

/// IA32_MWAIT_POWER_STATE — power state hint for MWAIT.
pub const MSR_IA32_MWAIT_POWER_STATE: u32 = 0x0000_01B3;
/// C1 MWAIT hint: enter C1 halt state.
pub const MWAIT_C1_HINT: u32 = 0x0000_0000;
/// C2 MWAIT hint.
pub const MWAIT_C2_HINT: u32 = 0x0000_0010;
/// C3 MWAIT hint.
pub const MWAIT_C3_HINT: u32 = 0x0000_0020;

// ---------------------------------------------------------------------------
// Port I/O helpers
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
unsafe fn inw(port: u16) -> u16 {
    // SAFETY: Caller ensures port is a valid ACPI PM register port.
    unsafe {
        let v: u16;
        core::arch::asm!(
            "in ax, dx",
            out("ax") v,
            in("dx") port,
            options(nomem, nostack, preserves_flags),
        );
        v
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn outw(port: u16, val: u16) {
    // SAFETY: Caller ensures port is a valid ACPI PM register port.
    unsafe {
        core::arch::asm!(
            "out dx, ax",
            in("dx") port,
            in("ax") val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

// ---------------------------------------------------------------------------
// PowerMgmt
// ---------------------------------------------------------------------------

/// ACPI power management hardware interface.
///
/// Stores the I/O port addresses of the ACPI PM1 registers, as parsed
/// from the FADT (Fixed ACPI Description Table).
pub struct PowerMgmt {
    /// PM1a Status register port.
    pm1a_sts: u16,
    /// PM1a Enable register port.
    pm1a_en: u16,
    /// PM1a Control register port.
    pm1a_cnt: u16,
    /// PM1b Control register port (optional; 0 = not present).
    pm1b_cnt: u16,
    /// SCI interrupt number.
    sci_int: u8,
}

impl PowerMgmt {
    /// Create a new [`PowerMgmt`] from FADT-derived port addresses.
    pub const fn new(
        pm1a_sts: u16,
        pm1a_en: u16,
        pm1a_cnt: u16,
        pm1b_cnt: u16,
        sci_int: u8,
    ) -> Self {
        Self {
            pm1a_sts,
            pm1a_en,
            pm1a_cnt,
            pm1b_cnt,
            sci_int,
        }
    }

    /// Read the PM1a Status register.
    #[cfg(target_arch = "x86_64")]
    pub fn pm1a_status(&self) -> u16 {
        // SAFETY: Reading ACPI PM1a status port.
        unsafe { inw(self.pm1a_sts) }
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn pm1a_status(&self) -> u16 {
        0
    }

    /// Clear PM1a status bits (write-1-to-clear).
    #[cfg(target_arch = "x86_64")]
    pub fn clear_pm1a_status(&self, bits: u16) {
        // SAFETY: Writing ACPI PM1a status port (W1C).
        unsafe { outw(self.pm1a_sts, bits) };
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn clear_pm1a_status(&self, _bits: u16) {}

    /// Read the PM1a Enable register.
    #[cfg(target_arch = "x86_64")]
    pub fn pm1a_enable(&self) -> u16 {
        // SAFETY: Reading ACPI PM1a enable port.
        unsafe { inw(self.pm1a_en) }
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn pm1a_enable(&self) -> u16 {
        0
    }

    /// Write the PM1a Enable register.
    #[cfg(target_arch = "x86_64")]
    pub fn set_pm1a_enable(&self, val: u16) {
        // SAFETY: Writing ACPI PM1a enable port.
        unsafe { outw(self.pm1a_en, val) };
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn set_pm1a_enable(&self, _val: u16) {}

    /// Read the PM1a Control register.
    #[cfg(target_arch = "x86_64")]
    pub fn pm1a_control(&self) -> u16 {
        // SAFETY: Reading ACPI PM1a control port.
        unsafe { inw(self.pm1a_cnt) }
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn pm1a_control(&self) -> u16 {
        0
    }

    /// Write the PM1a Control register.
    #[cfg(target_arch = "x86_64")]
    pub fn write_pm1a_control(&self, val: u16) {
        // SAFETY: Writing ACPI PM1a control register.
        unsafe { outw(self.pm1a_cnt, val) };
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn write_pm1a_control(&self, _val: u16) {}

    /// Enable ACPI (set SCI_EN bit in PM1a CNT).
    pub fn acpi_enable(&self) -> Result<()> {
        let cnt = self.pm1a_control();
        self.write_pm1a_control(cnt | PM1_CNT_SCI_EN);
        // Verify
        if (self.pm1a_control() & PM1_CNT_SCI_EN) != 0 {
            Ok(())
        } else {
            Err(Error::IoError)
        }
    }

    /// Enter a sleep state by writing SLP_TYP + SLP_EN to PM1 CNT.
    ///
    /// `slp_typ` is the hardware sleep type value (from DSDT \_S<N> objects).
    pub fn enter_sleep_state(&self, slp_typ: u8) -> Result<()> {
        let slp_typ_bits = (slp_typ as u16 & 0x7) << PM1_CNT_SLP_TYP_SHIFT;
        let cnt = (self.pm1a_control() & !(PM1_CNT_SLP_TYP_MASK)) | slp_typ_bits | PM1_CNT_SLP_EN;

        // Write to PM1a
        self.write_pm1a_control(cnt);

        // Write to PM1b if present
        if self.pm1b_cnt != 0 {
            #[cfg(target_arch = "x86_64")]
            // SAFETY: Writing PM1b control register to initiate sleep.
            unsafe {
                outw(self.pm1b_cnt, cnt)
            };
        }

        // Hardware should cut power; if we return, something went wrong
        Err(Error::IoError)
    }

    /// Perform a full system power-off (S5).
    pub fn power_off(&self) -> Result<()> {
        self.enter_sleep_state(SLP_TYP_S5)
    }

    /// Perform a suspend-to-RAM (S3).
    pub fn suspend_to_ram(&self) -> Result<()> {
        self.enter_sleep_state(SLP_TYP_S3)
    }

    /// Enter CPU idle C1 via `hlt` instruction.
    #[cfg(target_arch = "x86_64")]
    pub fn cpu_idle_c1(&self) {
        // SAFETY: `hlt` is safe in kernel mode with interrupts enabled.
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn cpu_idle_c1(&self) {}

    /// Enter CPU idle state using `mwait` with a specified sub-state hint.
    ///
    /// `hint` encodes the C-state target (e.g., `MWAIT_C1_HINT`).
    #[cfg(target_arch = "x86_64")]
    pub fn cpu_idle_mwait(&self, hint: u32) {
        // SAFETY: MONITOR/MWAIT sequence for CPU idle.  The monitor address is
        // a dummy stack value; the CPU will wake on any interrupt.
        unsafe {
            let dummy: u32 = 0;
            core::arch::asm!(
                "monitor",
                in("eax") core::ptr::addr_of!(dummy),
                in("ecx") 0u32,
                in("edx") 0u32,
                options(nomem, nostack, preserves_flags),
            );
            core::arch::asm!(
                "mwait",
                in("eax") hint,
                in("ecx") 0u32,
                options(nomem, nostack, preserves_flags),
            );
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn cpu_idle_mwait(&self, _hint: u32) {}

    /// Return the SCI interrupt number.
    pub const fn sci_int(&self) -> u8 {
        self.sci_int
    }

    /// Return the PM1a status port.
    pub const fn pm1a_sts_port(&self) -> u16 {
        self.pm1a_sts
    }

    /// Return the PM1a control port.
    pub const fn pm1a_cnt_port(&self) -> u16 {
        self.pm1a_cnt
    }
}
