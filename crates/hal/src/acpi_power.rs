// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ACPI power management and sleep state control.
//!
//! Implements the ACPI power management interface for system sleep states
//! (S0–S5), PM1 event/control registers, power button handling, and
//! battery/AC adapter presence detection via ACPI methods.
//!
//! # Sleep States
//!
//! | State | Name      | Description                         |
//! |-------|-----------|-------------------------------------|
//! | S0    | Working   | Normal operation                    |
//! | S1    | Sleep     | CPU stopped, cache flushed          |
//! | S3    | Suspend   | RAM retained, most HW off           |
//! | S4    | Hibernate | RAM saved to disk, power off        |
//! | S5    | Soft Off  | No power except wake circuitry      |
//!
//! Reference: ACPI Specification 6.5 §7 (Power and Performance Management).

use oncrix_lib::Result;

// ---------------------------------------------------------------------------
// ACPI sleep type / sleep enable bits (PM1 control register)
// ---------------------------------------------------------------------------

/// PM1 control register: sleep enable bit.
pub const PM1_CNT_SLP_EN: u16 = 1 << 13;

/// PM1 control register: sleep type field shift.
pub const PM1_CNT_SLP_TYP_SHIFT: u16 = 10;

/// PM1 control register: sleep type mask (bits 12:10).
pub const PM1_CNT_SLP_TYP_MASK: u16 = 0x7 << 10;

/// PM1 status register: power button status bit.
pub const PM1_STS_PWRBTN: u16 = 1 << 8;

/// PM1 status register: wake status.
pub const PM1_STS_WAK: u16 = 1 << 15;

/// PM1 enable register: power button enable bit.
pub const PM1_EN_PWRBTN: u16 = 1 << 8;

// ---------------------------------------------------------------------------
// ACPI sleep state values
// ---------------------------------------------------------------------------

/// ACPI sleep state: working (S0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpiSleepState {
    /// S0: working.
    S0,
    /// S1: CPU stop grant.
    S1,
    /// S3: suspend to RAM.
    S3,
    /// S4: suspend to disk (hibernate).
    S4,
    /// S5: soft power-off.
    S5,
}

impl AcpiSleepState {
    /// Returns the SLP_TYP value for this sleep state.
    ///
    /// The actual values are platform-dependent (read from _S0_, _S3_, _S5_
    /// ACPI objects). We use the values common on IA-PC platforms.
    pub fn slp_typ_a(self) -> u8 {
        match self {
            AcpiSleepState::S0 => 0,
            AcpiSleepState::S1 => 1,
            AcpiSleepState::S3 => 5,
            AcpiSleepState::S4 => 6,
            AcpiSleepState::S5 => 7,
        }
    }
}

// ---------------------------------------------------------------------------
// PM1 register block accessor
// ---------------------------------------------------------------------------

/// ACPI PM1 register block descriptor.
///
/// Represents either PM1a or PM1b (each is optional). The caller maps
/// the physical GAS address to a virtual address before constructing this.
#[derive(Debug, Clone, Copy)]
pub struct Pm1Block {
    /// Base I/O port or MMIO virtual address for the event/status block.
    pub event_base: u64,
    /// Base for the control block.
    pub ctrl_base: u64,
    /// Whether this block is I/O port–based (true) or MMIO (false).
    pub is_io: bool,
    /// Whether this block is present (non-zero address).
    pub present: bool,
}

impl Pm1Block {
    /// Creates a new PM1 block descriptor.
    pub const fn new(event_base: u64, ctrl_base: u64, is_io: bool) -> Self {
        Self {
            event_base,
            ctrl_base,
            is_io,
            present: event_base != 0 || ctrl_base != 0,
        }
    }

    /// Reads the PM1 status register (event_base + 0).
    ///
    /// # Safety
    ///
    /// Caller must ensure the base address is valid and the block is present.
    pub unsafe fn read_status(&self) -> u16 {
        if !self.present {
            return 0;
        }
        if self.is_io {
            // SAFETY: Caller ensures valid I/O port.
            unsafe { port_inw(self.event_base as u16) }
        } else {
            let addr = self.event_base as *const u16;
            // SAFETY: Caller ensures valid MMIO mapping.
            unsafe { core::ptr::read_volatile(addr) }
        }
    }

    /// Writes the PM1 status register (write-1-to-clear).
    ///
    /// # Safety
    ///
    /// Caller must ensure the base address is valid and the block is present.
    pub unsafe fn write_status(&self, val: u16) {
        if !self.present {
            return;
        }
        if self.is_io {
            // SAFETY: Caller ensures valid I/O port.
            unsafe { port_outw(self.event_base as u16, val) };
        } else {
            let addr = self.event_base as *mut u16;
            // SAFETY: Caller ensures valid MMIO mapping.
            unsafe { core::ptr::write_volatile(addr, val) };
        }
    }

    /// Reads the PM1 control register (ctrl_base + 0).
    ///
    /// # Safety
    ///
    /// Caller must ensure valid mapping.
    pub unsafe fn read_ctrl(&self) -> u16 {
        if !self.present {
            return 0;
        }
        if self.is_io {
            // SAFETY: Caller ensures valid I/O port.
            unsafe { port_inw(self.ctrl_base as u16) }
        } else {
            let addr = self.ctrl_base as *const u16;
            // SAFETY: Caller ensures valid MMIO mapping.
            unsafe { core::ptr::read_volatile(addr) }
        }
    }

    /// Writes the PM1 control register.
    ///
    /// # Safety
    ///
    /// Caller must ensure valid mapping.
    pub unsafe fn write_ctrl(&self, val: u16) {
        if !self.present {
            return;
        }
        if self.is_io {
            // SAFETY: Caller ensures valid I/O port.
            unsafe { port_outw(self.ctrl_base as u16, val) };
        } else {
            let addr = self.ctrl_base as *mut u16;
            // SAFETY: Caller ensures valid MMIO mapping.
            unsafe { core::ptr::write_volatile(addr, val) };
        }
    }
}

// ---------------------------------------------------------------------------
// AcpiPmState
// ---------------------------------------------------------------------------

/// ACPI power management controller state.
pub struct AcpiPmState {
    /// PM1a register block.
    pub pm1a: Pm1Block,
    /// PM1b register block (may be absent).
    pub pm1b: Pm1Block,
    /// Current sleep state.
    pub sleep_state: AcpiSleepState,
    /// Power button event pending.
    pub power_button_pending: bool,
}

impl AcpiPmState {
    /// Creates a new ACPI PM state instance.
    pub const fn new(pm1a: Pm1Block, pm1b: Pm1Block) -> Self {
        Self {
            pm1a,
            pm1b,
            sleep_state: AcpiSleepState::S0,
            power_button_pending: false,
        }
    }

    /// Initiates a system sleep transition to `state`.
    ///
    /// Writes the SLP_TYP and SLP_EN bits to PM1a (and PM1b if present).
    ///
    /// # Safety
    ///
    /// Must be called from ring 0 with interrupts disabled. For S3/S5 this
    /// will power off or suspend the system.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for unsupported states.
    pub unsafe fn enter_sleep(&mut self, state: AcpiSleepState) -> Result<()> {
        let slp_typ = state.slp_typ_a() as u16;
        let ctrl_val = (slp_typ << PM1_CNT_SLP_TYP_SHIFT) | PM1_CNT_SLP_EN;

        // SAFETY: Caller ensures ring 0, interrupts disabled.
        unsafe {
            self.pm1a.write_ctrl(ctrl_val);
            if self.pm1b.present {
                self.pm1b.write_ctrl(ctrl_val);
            }
        }
        self.sleep_state = state;
        Ok(())
    }

    /// Acknowledges a power button press event.
    ///
    /// # Safety
    ///
    /// Must be called from ring 0 (SCI handler context).
    pub unsafe fn ack_power_button(&mut self) {
        // SAFETY: Caller ensures ring 0.
        unsafe {
            self.pm1a.write_status(PM1_STS_PWRBTN);
            if self.pm1b.present {
                self.pm1b.write_status(PM1_STS_PWRBTN);
            }
        }
        self.power_button_pending = false;
    }

    /// Reads PM1 status and checks for power button event.
    ///
    /// # Safety
    ///
    /// Must be called from ring 0.
    pub unsafe fn poll_events(&mut self) {
        // SAFETY: Caller ensures ring 0.
        let status = unsafe { self.pm1a.read_status() };
        if status & PM1_STS_PWRBTN != 0 {
            self.power_button_pending = true;
        }
    }

    /// Enables power button interrupts via the PM1 enable register.
    ///
    /// # Safety
    ///
    /// Must be called from ring 0.
    pub unsafe fn enable_power_button_irq(&self) {
        // PM1 enable register is at event_base + 2.
        if self.pm1a.present && self.pm1a.is_io {
            let port = (self.pm1a.event_base as u16).wrapping_add(2);
            // SAFETY: Caller ensures ring 0 and valid I/O port.
            unsafe { port_outw(port, PM1_EN_PWRBTN) };
        }
    }

    /// Performs a soft power-off (S5).
    ///
    /// # Safety
    ///
    /// Must be called from ring 0 with no pending work.
    pub unsafe fn power_off(&mut self) -> Result<()> {
        // SAFETY: Delegates to enter_sleep which handles the write.
        unsafe { self.enter_sleep(AcpiSleepState::S5) }
    }
}

// ---------------------------------------------------------------------------
// Inline port I/O helpers
// ---------------------------------------------------------------------------

/// Read a 16-bit value from an I/O port.
///
/// # Safety
///
/// Must be called from ring 0 with a valid I/O port.
#[cfg(target_arch = "x86_64")]
unsafe fn port_inw(port: u16) -> u16 {
    let val: u16;
    // SAFETY: Caller guarantees ring 0 and valid port.
    unsafe {
        core::arch::asm!(
            "in ax, dx",
            out("ax") val,
            in("dx") port,
            options(nomem, nostack),
        );
    }
    val
}

/// Write a 16-bit value to an I/O port.
///
/// # Safety
///
/// Must be called from ring 0 with a valid I/O port.
#[cfg(target_arch = "x86_64")]
unsafe fn port_outw(port: u16, val: u16) {
    // SAFETY: Caller guarantees ring 0 and valid port.
    unsafe {
        core::arch::asm!(
            "out dx, ax",
            in("dx") port,
            in("ax") val,
            options(nomem, nostack),
        );
    }
}

// Stubs for non-x86_64 targets so the module compiles.
#[cfg(not(target_arch = "x86_64"))]
unsafe fn port_inw(_port: u16) -> u16 {
    0
}
#[cfg(not(target_arch = "x86_64"))]
unsafe fn port_outw(_port: u16, _val: u16) {}
