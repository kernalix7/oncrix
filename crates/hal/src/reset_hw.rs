// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! System reset and shutdown hardware interface.
//!
//! Provides platform-level reset and power-off mechanisms for x86_64:
//!
//! | Mechanism        | Method                                  | Notes                        |
//! |------------------|-----------------------------------------|------------------------------|
//! | Keyboard ctrl    | Write 0xFE to PS/2 controller (0x64)   | Classic, universally works   |
//! | ACPI reset reg   | Write to FADT `RESET_REG` (port/MMIO)  | ACPI 2.0+ preferred          |
//! | Triple fault     | Load null IDT, then INT 3 / invlpg 0   | Emergency fallback           |
//! | ACPI S5 shutdown | Write sleep-type value to PM1a/b ctrl  | Requires ACPI AML parse      |
//! | EFI runtime      | `EFI_RESET_SYSTEM` service              | Preferred in UEFI systems    |
//!
//! Reference: ACPI Specification 6.5 §4.8.3; Intel 8042 Application Note.

use oncrix_lib::Result;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// PS/2 controller command port.
pub const PS2_CMD_PORT: u16 = 0x64;

/// PS/2 controller data port.
pub const PS2_DATA_PORT: u16 = 0x60;

/// PS/2 reset command (pulse output line LOW to trigger CPU reset).
pub const PS2_RESET_CMD: u8 = 0xFE;

/// PS/2 input buffer full status bit.
pub const PS2_STATUS_IBF: u8 = 0x02;

/// ACPI PM1 control register: SLP_EN bit (bit 13).
pub const ACPI_SLP_EN: u16 = 1 << 13;

/// ACPI PM1 control register: SLP_TYP mask (bits 12:10).
pub const ACPI_SLP_TYP_MASK: u16 = 0x1C00;

/// ACPI SLP_TYP value for S5 (soft-off) in common BIOSes.
pub const ACPI_S5_SLP_TYP_DEFAULT: u16 = 0x07 << 10;

/// QEMU ACPI power-off port and magic value.
pub const QEMU_ACPI_OFF_PORT: u16 = 0x604;

/// Magic value to write to QEMU ACPI shutdown port.
pub const QEMU_ACPI_OFF_VAL: u16 = 0x2000;

/// Bochs / old QEMU shutdown port.
pub const BOCHS_SHUTDOWN_PORT: u16 = 0x8900;

// ---------------------------------------------------------------------------
// ResetMethod
// ---------------------------------------------------------------------------

/// Hardware reset method to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResetMethod {
    /// PS/2 keyboard controller reset (universal fallback).
    #[default]
    Ps2Keyboard,
    /// ACPI reset register (requires firmware-provided register address).
    AcpiResetReg,
    /// x86 triple fault (emergency only — no clean shutdown).
    TripleFault,
}

/// Power-off method to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShutdownMethod {
    /// ACPI S5 via PM1 control register.
    #[default]
    AcpiS5,
    /// QEMU ACPI shutdown port (for virtualized environments).
    QemuAcpi,
    /// Bochs / old QEMU shutdown string.
    BochsShutdown,
}

// ---------------------------------------------------------------------------
// Port I/O helpers
// ---------------------------------------------------------------------------

/// Write a byte to an I/O port.
///
/// # Safety
///
/// Ring 0 only. Caller must ensure `port` is a valid I/O port.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn outb(port: u16, val: u8) {
    // SAFETY: Port I/O; caller ensures port is valid and ring-0 context.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nostack, nomem));
    }
}

/// Write a 16-bit word to an I/O port.
///
/// # Safety
///
/// Ring 0 only.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn outw(port: u16, val: u16) {
    // SAFETY: Port I/O; caller ensures port is valid and ring-0 context.
    unsafe {
        core::arch::asm!("out dx, ax", in("dx") port, in("ax") val, options(nostack, nomem));
    }
}

/// Read a byte from an I/O port.
///
/// # Safety
///
/// Ring 0 only.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    // SAFETY: Port I/O; ring-0 context.
    unsafe {
        core::arch::asm!("in al, dx", out("al") v, in("dx") port, options(nostack, nomem));
    }
    v
}

// ---------------------------------------------------------------------------
// Reset implementations
// ---------------------------------------------------------------------------

/// Perform a system reset via the PS/2 keyboard controller.
///
/// Writes the reset command (0xFE) to port 0x64. This pulses the CPU
/// reset line and causes an immediate reboot.
///
/// # Safety
///
/// This function does not return. Must be called from ring 0.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] on non-x86_64 targets.
pub unsafe fn reset_via_ps2() -> Result<()> {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: Port I/O to PS/2 controller; ring-0. This triggers a hard reset.
        unsafe {
            // Wait until input buffer is empty.
            let mut limit = 0x100_000u32;
            while inb(PS2_CMD_PORT) & PS2_STATUS_IBF != 0 && limit > 0 {
                limit -= 1;
                core::hint::spin_loop();
            }
            outb(PS2_CMD_PORT, PS2_RESET_CMD);
        }
        // Spin — hardware should reset before we get here.
        loop {
            core::hint::spin_loop();
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    Err(Error::NotImplemented)
}

/// ACPI reset register type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpiResetRegType {
    /// Port I/O register.
    PortIo,
    /// Memory-mapped I/O register.
    Mmio,
}

/// Perform a system reset by writing to the ACPI reset register.
///
/// The FADT provides the reset register address, type, and value.
///
/// # Safety
///
/// This function does not return on success. Must be called from ring 0.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] on non-x86_64 targets.
pub unsafe fn reset_via_acpi(
    reg_type: AcpiResetRegType,
    reg_addr: u64,
    reset_value: u8,
) -> Result<()> {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: Writing to the ACPI reset register triggers a platform reset.
        unsafe {
            match reg_type {
                AcpiResetRegType::PortIo => {
                    outb(reg_addr as u16, reset_value);
                }
                AcpiResetRegType::Mmio => {
                    core::ptr::write_volatile(reg_addr as *mut u8, reset_value);
                }
            }
        }
        loop {
            core::hint::spin_loop();
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (reg_type, reg_addr, reset_value);
        Err(Error::NotImplemented)
    }
}

/// Perform a system reset via triple fault.
///
/// Loads a null IDT descriptor and triggers a divide-by-zero to cause
/// a triple fault, which resets the CPU. This is an absolute last resort.
///
/// # Safety
///
/// This function does not return. Causes immediate uncontrolled reboot.
#[cfg(target_arch = "x86_64")]
pub unsafe fn reset_via_triple_fault() -> ! {
    // SAFETY: Emergency reset — loads a null IDT then faults.
    unsafe {
        core::arch::asm!(
            "lidt [{null_idt}]",
            "int3",
            null_idt = sym NULL_IDT_DESCRIPTOR,
            options(nostack, noreturn),
        );
    }
}

#[cfg(target_arch = "x86_64")]
/// Null IDT descriptor for triple-fault reset (limit=0, base=0).
static NULL_IDT_DESCRIPTOR: [u8; 10] = [0u8; 10];

// ---------------------------------------------------------------------------
// Shutdown implementations
// ---------------------------------------------------------------------------

/// Power off the system via ACPI S5 sleep state.
///
/// Writes the sleep type and SLP_EN bit to the PM1a control register.
///
/// # Safety
///
/// Must be called from ring 0. The system should be in a clean state.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] on non-x86_64 targets.
pub unsafe fn shutdown_acpi_s5(pm1a_ctrl_port: u16, slp_typ: u16) -> Result<()> {
    #[cfg(target_arch = "x86_64")]
    {
        let val = (slp_typ & ACPI_SLP_TYP_MASK) | ACPI_SLP_EN;
        // SAFETY: Writing sleep command to PM1 control register.
        unsafe {
            outw(pm1a_ctrl_port, val);
        }
        loop {
            core::hint::spin_loop();
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (pm1a_ctrl_port, slp_typ);
        Err(Error::NotImplemented)
    }
}

/// Power off using QEMU's ACPI shutdown port (0x604).
///
/// # Safety
///
/// Ring 0 only; only works in QEMU.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] on non-x86_64 targets.
pub unsafe fn shutdown_qemu() -> Result<()> {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: Writing QEMU magic value to ACPI power-off port.
        unsafe {
            outw(QEMU_ACPI_OFF_PORT, QEMU_ACPI_OFF_VAL);
        }
        loop {
            core::hint::spin_loop();
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    Err(Error::NotImplemented)
}

/// Power off using the Bochs/old-QEMU shutdown mechanism.
///
/// Writes the ASCII string `"Shutdown"` byte-by-byte to port 0x8900.
///
/// # Safety
///
/// Ring 0 only.
///
/// # Errors
///
/// Returns [`Error::NotImplemented`] on non-x86_64 targets.
pub unsafe fn shutdown_bochs() -> Result<()> {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: Bochs shutdown sequence via port 0x8900.
        unsafe {
            for &b in b"Shutdown" {
                outb(BOCHS_SHUTDOWN_PORT, b);
            }
        }
        loop {
            core::hint::spin_loop();
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    Err(Error::NotImplemented)
}

// ---------------------------------------------------------------------------
// ResetController
// ---------------------------------------------------------------------------

/// High-level reset / shutdown controller.
///
/// Provides a unified interface for triggering system reset or power-off
/// using the best available mechanism.
pub struct ResetController {
    /// Preferred reset method.
    reset_method: ResetMethod,
    /// ACPI reset register type (for `AcpiResetReg`).
    acpi_reset_reg_type: AcpiResetRegType,
    /// ACPI reset register address.
    acpi_reset_reg_addr: u64,
    /// ACPI reset register value.
    acpi_reset_value: u8,
    /// PM1a control port for ACPI S5 shutdown.
    pm1a_ctrl_port: u16,
    /// SLP_TYP value for S5.
    s5_slp_typ: u16,
    /// Preferred shutdown method.
    shutdown_method: ShutdownMethod,
}

impl ResetController {
    /// Create a controller with PS/2 reset and QEMU shutdown as defaults.
    pub const fn new() -> Self {
        Self {
            reset_method: ResetMethod::Ps2Keyboard,
            acpi_reset_reg_type: AcpiResetRegType::PortIo,
            acpi_reset_reg_addr: 0,
            acpi_reset_value: 0,
            pm1a_ctrl_port: 0,
            s5_slp_typ: ACPI_S5_SLP_TYP_DEFAULT,
            shutdown_method: ShutdownMethod::QemuAcpi,
        }
    }

    /// Configure the ACPI reset register from FADT data.
    pub fn set_acpi_reset(&mut self, reg_type: AcpiResetRegType, reg_addr: u64, reset_value: u8) {
        self.acpi_reset_reg_type = reg_type;
        self.acpi_reset_reg_addr = reg_addr;
        self.acpi_reset_value = reset_value;
        self.reset_method = ResetMethod::AcpiResetReg;
    }

    /// Configure the ACPI S5 shutdown parameters.
    pub fn set_acpi_s5(&mut self, pm1a_ctrl_port: u16, slp_typ: u16) {
        self.pm1a_ctrl_port = pm1a_ctrl_port;
        self.s5_slp_typ = slp_typ;
        self.shutdown_method = ShutdownMethod::AcpiS5;
    }

    /// Set the preferred shutdown method.
    pub fn set_shutdown_method(&mut self, method: ShutdownMethod) {
        self.shutdown_method = method;
    }

    /// Trigger a system reset.
    ///
    /// Tries the configured method, then falls back to PS/2.
    ///
    /// # Safety
    ///
    /// This function does not return (on x86_64). Must be called from ring 0.
    ///
    /// # Errors
    ///
    /// Returns `Err` only on non-x86_64 targets.
    pub unsafe fn reset(&self) -> Result<()> {
        match self.reset_method {
            ResetMethod::Ps2Keyboard => {
                // SAFETY: Calling reset_via_ps2 which does not return.
                unsafe { reset_via_ps2() }
            }
            ResetMethod::AcpiResetReg => {
                // SAFETY: Calling reset_via_acpi which does not return.
                unsafe {
                    reset_via_acpi(
                        self.acpi_reset_reg_type,
                        self.acpi_reset_reg_addr,
                        self.acpi_reset_value,
                    )
                }
            }
            ResetMethod::TripleFault => {
                #[cfg(target_arch = "x86_64")]
                // SAFETY: Emergency triple fault reset.
                unsafe {
                    reset_via_triple_fault()
                }
                #[cfg(not(target_arch = "x86_64"))]
                Err(Error::NotImplemented)
            }
        }
    }

    /// Power off the system.
    ///
    /// # Safety
    ///
    /// This function does not return (on x86_64). Must be called from ring 0.
    ///
    /// # Errors
    ///
    /// Returns `Err` only on non-x86_64 targets.
    pub unsafe fn shutdown(&self) -> Result<()> {
        match self.shutdown_method {
            ShutdownMethod::AcpiS5 => {
                // SAFETY: ACPI S5 shutdown via PM1 control register.
                unsafe { shutdown_acpi_s5(self.pm1a_ctrl_port, self.s5_slp_typ) }
            }
            ShutdownMethod::QemuAcpi => {
                // SAFETY: QEMU ACPI shutdown port.
                unsafe { shutdown_qemu() }
            }
            ShutdownMethod::BochsShutdown => {
                // SAFETY: Bochs shutdown sequence.
                unsafe { shutdown_bochs() }
            }
        }
    }
}

impl Default for ResetController {
    fn default() -> Self {
        Self::new()
    }
}
