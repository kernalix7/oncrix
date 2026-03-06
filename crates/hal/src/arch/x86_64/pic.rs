// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! 8259 PIC (Programmable Interrupt Controller) driver.
//!
//! The legacy 8259 PIC pair (master + slave) maps hardware IRQs 0-15
//! to CPU interrupt vectors. This driver remaps them to vectors 32-47
//! to avoid collision with CPU exceptions (vectors 0-31).

use crate::interrupt::{InterruptController, InterruptVector};
use oncrix_lib::Result;

/// Master PIC I/O ports.
mod master {
    pub const COMMAND: u16 = 0x20;
    pub const DATA: u16 = 0x21;
}

/// Slave PIC I/O ports.
mod slave {
    pub const COMMAND: u16 = 0xA0;
    pub const DATA: u16 = 0xA1;
}

/// ICW1: initialization + ICW4 needed.
const ICW1_INIT: u8 = 0x11;
/// ICW4: 8086 mode.
const ICW4_8086: u8 = 0x01;
/// End-of-interrupt command.
const EOI: u8 = 0x20;

/// Base vector offset for master PIC (IRQ 0-7 → vectors 32-39).
pub const PIC_MASTER_OFFSET: u8 = 32;
/// Base vector offset for slave PIC (IRQ 8-15 → vectors 40-47).
pub const PIC_SLAVE_OFFSET: u8 = 40;

/// Total number of IRQ lines (master + slave).
const IRQ_COUNT: u8 = 16;

/// Cascaded 8259 PIC pair.
pub struct Pic8259 {
    /// IRQ mask: bit N set = IRQ N masked (disabled).
    mask: u16,
}

impl Default for Pic8259 {
    fn default() -> Self {
        Self::new()
    }
}

impl Pic8259 {
    /// Create a new PIC instance (all IRQs masked).
    pub const fn new() -> Self {
        Self { mask: 0xFFFF }
    }

    /// Initialize (remap) the PIC pair.
    ///
    /// After this call, IRQ 0-7 map to vectors 32-39 and
    /// IRQ 8-15 map to vectors 40-47. All IRQs start masked.
    pub fn init(&mut self) {
        // SAFETY: Writing to well-known PIC I/O ports in Ring 0.
        unsafe {
            use super::io::{inb, outb};

            // Save current masks.
            let mask_master = inb(master::DATA);
            let mask_slave = inb(slave::DATA);

            // ICW1: begin initialization sequence.
            outb(master::COMMAND, ICW1_INIT);
            io_wait();
            outb(slave::COMMAND, ICW1_INIT);
            io_wait();

            // ICW2: vector offset.
            outb(master::DATA, PIC_MASTER_OFFSET);
            io_wait();
            outb(slave::DATA, PIC_SLAVE_OFFSET);
            io_wait();

            // ICW3: master has slave on IRQ2, slave cascade identity = 2.
            outb(master::DATA, 4); // IRQ2 has slave
            io_wait();
            outb(slave::DATA, 2); // slave cascade identity
            io_wait();

            // ICW4: 8086 mode.
            outb(master::DATA, ICW4_8086);
            io_wait();
            outb(slave::DATA, ICW4_8086);
            io_wait();

            // Restore saved masks.
            outb(master::DATA, mask_master);
            outb(slave::DATA, mask_slave);
        }

        self.mask = 0xFFFF;
        self.apply_mask();
    }

    /// Apply the current mask to hardware.
    fn apply_mask(&self) {
        // SAFETY: Writing to PIC data ports in Ring 0.
        unsafe {
            super::io::outb(master::DATA, (self.mask & 0xFF) as u8);
            super::io::outb(slave::DATA, (self.mask >> 8) as u8);
        }
    }

    /// Convert an interrupt vector back to an IRQ number, if applicable.
    fn vector_to_irq(vector: InterruptVector) -> Option<u8> {
        let v = vector.0;
        if (PIC_MASTER_OFFSET..PIC_MASTER_OFFSET + IRQ_COUNT).contains(&v) {
            Some(v - PIC_MASTER_OFFSET)
        } else {
            None
        }
    }
}

impl InterruptController for Pic8259 {
    fn enable(&mut self, vector: InterruptVector) -> Result<()> {
        let irq = Self::vector_to_irq(vector).ok_or(oncrix_lib::Error::InvalidArgument)?;
        self.mask &= !(1 << irq);
        // If enabling a slave IRQ (8-15), also unmask cascade line (IRQ2).
        if irq >= 8 {
            self.mask &= !(1 << 2);
        }
        self.apply_mask();
        Ok(())
    }

    fn disable(&mut self, vector: InterruptVector) -> Result<()> {
        let irq = Self::vector_to_irq(vector).ok_or(oncrix_lib::Error::InvalidArgument)?;
        self.mask |= 1 << irq;
        self.apply_mask();
        Ok(())
    }

    fn acknowledge(&mut self, vector: InterruptVector) -> Result<()> {
        let irq = Self::vector_to_irq(vector).ok_or(oncrix_lib::Error::InvalidArgument)?;
        // SAFETY: Writing EOI to PIC command ports in Ring 0.
        unsafe {
            if irq >= 8 {
                super::io::outb(slave::COMMAND, EOI);
            }
            super::io::outb(master::COMMAND, EOI);
        }
        Ok(())
    }

    fn is_enabled(&self, vector: InterruptVector) -> bool {
        match Self::vector_to_irq(vector) {
            Some(irq) => self.mask & (1 << irq) == 0,
            None => false,
        }
    }

    unsafe fn enable_all(&mut self) {
        // SAFETY: Caller guarantees handlers are installed.
        unsafe {
            core::arch::asm!("sti", options(nomem, nostack));
        }
    }

    fn disable_all(&mut self) -> bool {
        let flags: u64;
        // SAFETY: Reading RFLAGS and disabling interrupts in Ring 0.
        // `cli` clears the IF bit in RFLAGS, so `preserves_flags` is
        // intentionally omitted.
        unsafe {
            core::arch::asm!(
                "pushfq; pop {}; cli",
                out(reg) flags,
                options(nomem),
            );
        }
        // IF (Interrupt Flag) is bit 9.
        flags & (1 << 9) != 0
    }
}

/// Short I/O delay (write to unused port 0x80).
fn io_wait() {
    // SAFETY: Port 0x80 is the POST diagnostic port, writing to it
    // is a standard technique for introducing a small I/O delay.
    unsafe {
        super::io::outb(0x80, 0);
    }
}
