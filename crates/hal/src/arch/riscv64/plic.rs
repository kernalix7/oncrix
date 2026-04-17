// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RISC-V Platform-Level Interrupt Controller (PLIC) stub.
//!
//! Initializes the PLIC so that the NS16550 UART interrupt (IRQ 10 on QEMU
//! virt) and the timer interrupt can reach supervisor mode.
//!
//! QEMU `virt` machine PLIC MMIO base: 0x0C00_0000.
//! Hart 0 S-mode claim/complete: base + 0x20_1004 (context 1).
//!
//! Reference: RISC-V PLIC specification (riscv/riscv-plic-spec).

use oncrix_lib::Result;

/// PLIC MMIO base for QEMU virt machine.
pub const PLIC_BASE: usize = 0x0C00_0000;

// ── PLIC register offsets ─────────────────────────────────────────────────────

/// Priority register for interrupt source N (4 bytes each, base + 4*N).
const PLIC_PRIORITY: usize = 0x0000_0000;

/// Interrupt enable bits for context C, source N.
/// Offset: 0x2000 + 0x80*C + 4*(N/32)
const PLIC_ENABLE_BASE: usize = 0x0000_2000;

/// Priority threshold for context C.
/// Offset: 0x20_0000 + 0x1000*C
const PLIC_THRESHOLD_BASE: usize = 0x0020_0000;

/// Claim/complete register for context C.
/// Offset: 0x20_0004 + 0x1000*C
const PLIC_CLAIM_BASE: usize = 0x0020_0004;

/// Hart 0 S-mode is context 1 on QEMU virt.
const HART0_SMODE_CONTEXT: usize = 1;

/// UART0 interrupt source number on QEMU virt.
pub const UART_IRQ: u32 = 10;

/// Read a 32-bit MMIO register.
///
/// # Safety
/// `addr` must be a valid, mapped MMIO address.
#[inline]
unsafe fn read32(addr: usize) -> u32 {
    // SAFETY: caller guarantees the address is a valid MMIO register.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Write a 32-bit MMIO register.
///
/// # Safety
/// `addr` must be a valid, mapped MMIO address.
#[inline]
unsafe fn write32(addr: usize, val: u32) {
    // SAFETY: caller guarantees the address is a valid MMIO register.
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
}

/// RISC-V PLIC controller.
pub struct Plic {
    base: usize,
}

impl Plic {
    /// Create a PLIC instance at the given MMIO base.
    pub const fn new(base: usize) -> Self {
        Self { base }
    }

    /// Initialize the PLIC: set priority for UART IRQ, enable it for
    /// hart 0 S-mode, and set the priority threshold to 0 (accept all).
    pub fn init(&self) -> Result<()> {
        // SAFETY: Writing to well-known PLIC MMIO registers for QEMU virt.
        unsafe {
            // Set UART IRQ priority to 1 (any non-zero value enables it).
            write32(self.base + PLIC_PRIORITY + 4 * UART_IRQ as usize, 1);

            // Enable UART IRQ for hart 0 S-mode context.
            let enable_addr = self.base
                + PLIC_ENABLE_BASE
                + 0x80 * HART0_SMODE_CONTEXT
                + 4 * (UART_IRQ as usize / 32);
            let bit = 1u32 << (UART_IRQ % 32);
            let current = read32(enable_addr);
            write32(enable_addr, current | bit);

            // Set priority threshold to 0 for hart 0 S-mode (accept all).
            write32(
                self.base + PLIC_THRESHOLD_BASE + 0x1000 * HART0_SMODE_CONTEXT,
                0,
            );
        }
        Ok(())
    }

    /// Claim the highest-priority pending interrupt for hart 0 S-mode.
    ///
    /// Returns the interrupt source number (0 if no interrupt pending).
    pub fn claim(&self) -> u32 {
        // SAFETY: Reading the PLIC claim register.
        unsafe { read32(self.base + PLIC_CLAIM_BASE + 0x1000 * HART0_SMODE_CONTEXT) }
    }

    /// Complete (acknowledge) an interrupt.
    pub fn complete(&self, irq: u32) {
        // SAFETY: Writing to the PLIC complete register.
        unsafe {
            write32(
                self.base + PLIC_CLAIM_BASE + 0x1000 * HART0_SMODE_CONTEXT,
                irq,
            )
        }
    }
}
