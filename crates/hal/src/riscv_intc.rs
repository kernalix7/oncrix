// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RISC-V Core Local Interrupt Controller (CLINT/INTC) abstraction.
//!
//! Manages machine-mode and supervisor-mode interrupts on RISC-V cores via the
//! `mie`/`sie` CSRs and the RISC-V interrupt pending infrastructure.
//!
//! # Interrupt Sources
//!
//! RISC-V defines standard interrupt causes:
//! - Software interrupts (MSI/SSI): IPI delivery
//! - Timer interrupts (MTI/STI): from CLINT `mtimecmp`
//! - External interrupts (MEI/SEI): from PLIC
//!
//! # References
//!
//! - RISC-V Privileged Architecture Specification, Chapter 3 (Machine-Level ISA)
//! - SiFive CLINT specification

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

/// RISC-V interrupt cause codes (mcause/scause with interrupt bit set).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum InterruptCause {
    /// Machine-mode software interrupt.
    MachineSoftware = 3,
    /// Machine-mode timer interrupt.
    MachineTimer = 7,
    /// Machine-mode external interrupt.
    MachineExternal = 11,
    /// Supervisor-mode software interrupt.
    SupervisorSoftware = 1,
    /// Supervisor-mode timer interrupt.
    SupervisorTimer = 5,
    /// Supervisor-mode external interrupt.
    SupervisorExternal = 9,
    /// Unknown interrupt cause.
    Unknown = 0xFF,
}

impl InterruptCause {
    /// Converts a raw cause value (interrupt bit cleared) to an `InterruptCause`.
    pub fn from_raw(cause: u64) -> Self {
        match cause {
            3 => Self::MachineSoftware,
            7 => Self::MachineTimer,
            11 => Self::MachineExternal,
            1 => Self::SupervisorSoftware,
            5 => Self::SupervisorTimer,
            9 => Self::SupervisorExternal,
            _ => Self::Unknown,
        }
    }
}

/// Privilege mode for interrupt enable/disable operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivMode {
    /// Machine mode (M-mode).
    Machine,
    /// Supervisor mode (S-mode).
    Supervisor,
}

/// RISC-V interrupt controller abstraction.
///
/// Wraps CSR-level interrupt enable/disable and provides a high-level API
/// for managing RISC-V core-local interrupts.
pub struct RiscvIntc {
    /// Privilege mode this controller manages.
    mode: PrivMode,
    /// Whether interrupts are globally enabled.
    global_enabled: bool,
}

impl RiscvIntc {
    /// Creates a new RISC-V interrupt controller for the given privilege mode.
    pub const fn new(mode: PrivMode) -> Self {
        Self {
            mode,
            global_enabled: false,
        }
    }

    /// Initializes the interrupt controller by disabling all interrupts.
    ///
    /// Should be called during early boot before enabling specific interrupt sources.
    pub fn init(&mut self) -> Result<()> {
        #[cfg(target_arch = "riscv64")]
        {
            match self.mode {
                PrivMode::Machine => {
                    // SAFETY: Writing to mie CSR is safe in M-mode context.
                    // Clears all machine interrupt enables.
                    unsafe {
                        core::arch::asm!("csrw mie, zero", options(nomem, nostack));
                    }
                }
                PrivMode::Supervisor => {
                    // SAFETY: Writing to sie CSR clears all supervisor interrupt enables.
                    unsafe {
                        core::arch::asm!("csrw sie, zero", options(nomem, nostack));
                    }
                }
            }
        }
        self.global_enabled = false;
        Ok(())
    }

    /// Enables a specific interrupt source.
    pub fn enable(&mut self, cause: InterruptCause) -> Result<()> {
        let bit = self.ie_bit(cause)?;
        self.set_ie_bit(bit, true);
        Ok(())
    }

    /// Disables a specific interrupt source.
    pub fn disable(&mut self, cause: InterruptCause) -> Result<()> {
        let bit = self.ie_bit(cause)?;
        self.set_ie_bit(bit, false);
        Ok(())
    }

    /// Globally enables interrupts for this privilege mode (sets mstatus.MIE or sstatus.SIE).
    pub fn global_enable(&mut self) {
        #[cfg(target_arch = "riscv64")]
        {
            match self.mode {
                PrivMode::Machine => {
                    // SAFETY: Setting mstatus.MIE enables machine-mode interrupt delivery.
                    // Must only be called when the interrupt handler is properly configured.
                    unsafe {
                        core::arch::asm!("csrsi mstatus, 0x8", options(nomem, nostack));
                    }
                }
                PrivMode::Supervisor => {
                    // SAFETY: Setting sstatus.SIE enables supervisor-mode interrupt delivery.
                    unsafe {
                        core::arch::asm!("csrsi sstatus, 0x2", options(nomem, nostack));
                    }
                }
            }
        }
        self.global_enabled = true;
    }

    /// Globally disables interrupts for this privilege mode.
    pub fn global_disable(&mut self) {
        #[cfg(target_arch = "riscv64")]
        {
            match self.mode {
                PrivMode::Machine => {
                    // SAFETY: Clearing mstatus.MIE disables machine-mode interrupt delivery.
                    unsafe {
                        core::arch::asm!("csrci mstatus, 0x8", options(nomem, nostack));
                    }
                }
                PrivMode::Supervisor => {
                    // SAFETY: Clearing sstatus.SIE disables supervisor-mode interrupt delivery.
                    unsafe {
                        core::arch::asm!("csrci sstatus, 0x2", options(nomem, nostack));
                    }
                }
            }
        }
        self.global_enabled = false;
    }

    /// Returns whether global interrupts are enabled.
    pub fn is_global_enabled(&self) -> bool {
        self.global_enabled
    }

    /// Reads the pending interrupt register (mip or sip).
    #[cfg(target_arch = "riscv64")]
    pub fn read_pending(&self) -> u64 {
        let val: u64;
        match self.mode {
            PrivMode::Machine => {
                // SAFETY: Reading mip CSR is always safe in M-mode.
                unsafe {
                    core::arch::asm!("csrr {}, mip", out(reg) val, options(nomem, nostack));
                }
            }
            PrivMode::Supervisor => {
                // SAFETY: Reading sip CSR is safe in S-mode.
                unsafe {
                    core::arch::asm!("csrr {}, sip", out(reg) val, options(nomem, nostack));
                }
            }
        }
        val
    }

    /// Triggers a machine-mode software interrupt on the current hart via CLINT.
    ///
    /// # Arguments
    ///
    /// * `clint_base` - Base address of the CLINT MMIO region
    /// * `hart_id` - Target hart identifier
    pub fn trigger_software_interrupt(clint_base: usize, hart_id: usize) {
        let msip_addr = (clint_base + hart_id * 4) as *mut u32;
        // SAFETY: clint_base + hart_id * 4 is the msip register for hart_id in the CLINT.
        // Volatile write is required to deliver the IPI to the target hart.
        unsafe { msip_addr.write_volatile(1) }
    }

    /// Clears a pending machine-mode software interrupt on the current hart.
    pub fn clear_software_interrupt(clint_base: usize, hart_id: usize) {
        let msip_addr = (clint_base + hart_id * 4) as *mut u32;
        // SAFETY: Writing 0 to msip clears the pending software interrupt for the hart.
        unsafe { msip_addr.write_volatile(0) }
    }

    fn ie_bit(&self, cause: InterruptCause) -> Result<u64> {
        let bit = match (self.mode, cause) {
            (PrivMode::Machine, InterruptCause::MachineSoftware) => 3,
            (PrivMode::Machine, InterruptCause::MachineTimer) => 7,
            (PrivMode::Machine, InterruptCause::MachineExternal) => 11,
            (PrivMode::Supervisor, InterruptCause::SupervisorSoftware) => 1,
            (PrivMode::Supervisor, InterruptCause::SupervisorTimer) => 5,
            (PrivMode::Supervisor, InterruptCause::SupervisorExternal) => 9,
            _ => return Err(Error::InvalidArgument),
        };
        Ok(bit)
    }

    fn set_ie_bit(&self, bit: u64, enable: bool) {
        #[cfg(target_arch = "riscv64")]
        {
            let mask = 1u64 << bit;
            match (self.mode, enable) {
                (PrivMode::Machine, true) => {
                    // SAFETY: csrrs sets bits in mie; bit is a valid IE bit position.
                    unsafe {
                        core::arch::asm!(
                            "csrrs zero, mie, {mask}",
                            mask = in(reg) mask,
                            options(nomem, nostack)
                        );
                    }
                }
                (PrivMode::Machine, false) => {
                    // SAFETY: csrrc clears bits in mie; bit is a valid IE bit position.
                    unsafe {
                        core::arch::asm!(
                            "csrrc zero, mie, {mask}",
                            mask = in(reg) mask,
                            options(nomem, nostack)
                        );
                    }
                }
                (PrivMode::Supervisor, true) => {
                    // SAFETY: csrrs sets bits in sie; bit is a valid IE bit position.
                    unsafe {
                        core::arch::asm!(
                            "csrrs zero, sie, {mask}",
                            mask = in(reg) mask,
                            options(nomem, nostack)
                        );
                    }
                }
                (PrivMode::Supervisor, false) => {
                    // SAFETY: csrrc clears bits in sie; bit is a valid IE bit position.
                    unsafe {
                        core::arch::asm!(
                            "csrrc zero, sie, {mask}",
                            mask = in(reg) mask,
                            options(nomem, nostack)
                        );
                    }
                }
            }
        }
        let _ = (bit, enable);
    }
}

impl Default for RiscvIntc {
    fn default() -> Self {
        Self::new(PrivMode::Supervisor)
    }
}
