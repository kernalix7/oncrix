// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Intel 8259A Programmable Interrupt Controller (PIC) driver.
//!
//! Implements the classic dual-PIC (master + slave) cascade configuration
//! present in all PC-compatible systems.  In modern systems with an APIC,
//! the 8259 is masked or disabled after remapping, but it must be properly
//! initialised first so its spurious interrupt vectors do not collide with
//! CPU exception vectors (0–31).
//!
//! # Cascade topology
//!
//! ```text
//! CPU ← INTR ← Master PIC (IRQ 0–7)  ← IRQ 0: PIT
//!                                      ← IRQ 1: keyboard
//!                                      ← IRQ 2: (cascade to Slave)
//!                                      ← IRQ 3–7: COM2, LPT, …
//!              Slave PIC (IRQ 8–15)   ← IRQ 8: RTC
//!                                      ← IRQ 9–15: FPU, ATA, …
//! ```
//!
//! # I/O port layout
//!
//! | Register | Master | Slave |
//! |----------|--------|-------|
//! | Command  | 0x20   | 0xA0  |
//! | Data/IMR | 0x21   | 0xA1  |
//!
//! Reference: Intel 8259A Datasheet; OSDev Wiki — 8259 PIC.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// I/O Ports
// ---------------------------------------------------------------------------

/// Master PIC command port.
pub const PIC_MASTER_CMD: u16 = 0x20;
/// Master PIC data / IMR port.
pub const PIC_MASTER_DATA: u16 = 0x21;
/// Slave PIC command port.
pub const PIC_SLAVE_CMD: u16 = 0xA0;
/// Slave PIC data / IMR port.
pub const PIC_SLAVE_DATA: u16 = 0xA1;

// ---------------------------------------------------------------------------
// Initialization Command Words (ICWs)
// ---------------------------------------------------------------------------

/// ICW1 base: begin initialization sequence.
const ICW1_INIT: u8 = 0x10;
/// ICW1 modifier: ICW4 required.
const ICW1_ICW4: u8 = 0x01;

/// ICW3 for master: slave is attached to IRQ line 2.
const ICW3_MASTER_CASCADE_IRQ2: u8 = 0x04;
/// ICW3 for slave: slave ID is 2 (matches master IRQ 2).
const ICW3_SLAVE_ID2: u8 = 0x02;

/// ICW4: 8086/8088 mode (not MCS-80/85).
const ICW4_8086: u8 = 0x01;

// ---------------------------------------------------------------------------
// Operational Control Words (OCWs)
// ---------------------------------------------------------------------------

/// OCW2 non-specific EOI (End-Of-Interrupt) command.
const OCW2_EOI: u8 = 0x20;

/// OCW3: read IRR (Interrupt Request Register).
const OCW3_READ_IRR: u8 = 0x0A;
/// OCW3: read ISR (In-Service Register).
const OCW3_READ_ISR: u8 = 0x0B;

// ---------------------------------------------------------------------------
// Default interrupt vector bases
// ---------------------------------------------------------------------------

/// Default master PIC interrupt base (remapped above exception range).
pub const MASTER_VECTOR_BASE: u8 = 0x20;
/// Default slave PIC interrupt base.
pub const SLAVE_VECTOR_BASE: u8 = 0x28;

// ---------------------------------------------------------------------------
// Port I/O helpers
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
unsafe fn outb(port: u16, val: u8) {
    // SAFETY: Caller ensures `port` is a valid I/O address.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn inb(port: u16) -> u8 {
    // SAFETY: Caller ensures `port` is a valid I/O address.
    unsafe {
        let val: u8;
        core::arch::asm!(
            "in al, dx",
            out("al") val,
            in("dx") port,
            options(nomem, nostack, preserves_flags),
        );
        val
    }
}

/// Issue approximately 1–2 µs I/O delay by writing to a dummy port.
#[cfg(target_arch = "x86_64")]
fn io_wait() {
    // SAFETY: Port 0x80 is a POST diagnostic port used for I/O delays.
    unsafe { outb(0x80, 0) };
}

// ---------------------------------------------------------------------------
// Pic8259
// ---------------------------------------------------------------------------

/// Dual 8259A PIC controller (master + slave in cascade).
pub struct Pic8259 {
    /// Vector base for master PIC (IRQ 0–7).
    master_base: u8,
    /// Vector base for slave PIC (IRQ 8–15).
    slave_base: u8,
    /// Current IMR for master (bit = IRQ masked).
    master_mask: u8,
    /// Current IMR for slave.
    slave_mask: u8,
}

impl Pic8259 {
    /// Create a new [`Pic8259`] driver.
    ///
    /// `master_base` must be 8-aligned; `slave_base = master_base + 8`.
    pub const fn new(master_base: u8, slave_base: u8) -> Self {
        Self {
            master_base,
            slave_base,
            master_mask: 0xFF,
            slave_mask: 0xFF,
        }
    }

    /// Create a PIC with the default PC-AT vector bases (0x20 / 0x28).
    pub const fn default_bases() -> Self {
        Self::new(MASTER_VECTOR_BASE, SLAVE_VECTOR_BASE)
    }

    /// Initialize and remap both PICs.
    ///
    /// Sends ICW1–ICW4 to both master and slave, then restores the saved
    /// interrupt masks.  Interrupts should be disabled by the caller while
    /// this runs.
    #[cfg(target_arch = "x86_64")]
    pub fn init(&mut self) -> Result<()> {
        // SAFETY: We are in x86_64 mode and these are valid PIC ports.
        unsafe {
            // Save existing masks
            self.master_mask = inb(PIC_MASTER_DATA);
            self.slave_mask = inb(PIC_SLAVE_DATA);

            // ICW1 — start initialization
            outb(PIC_MASTER_CMD, ICW1_INIT | ICW1_ICW4);
            io_wait();
            outb(PIC_SLAVE_CMD, ICW1_INIT | ICW1_ICW4);
            io_wait();

            // ICW2 — vector bases
            outb(PIC_MASTER_DATA, self.master_base);
            io_wait();
            outb(PIC_SLAVE_DATA, self.slave_base);
            io_wait();

            // ICW3 — cascade wiring
            outb(PIC_MASTER_DATA, ICW3_MASTER_CASCADE_IRQ2);
            io_wait();
            outb(PIC_SLAVE_DATA, ICW3_SLAVE_ID2);
            io_wait();

            // ICW4 — 8086 mode
            outb(PIC_MASTER_DATA, ICW4_8086);
            io_wait();
            outb(PIC_SLAVE_DATA, ICW4_8086);
            io_wait();

            // Restore masks
            outb(PIC_MASTER_DATA, self.master_mask);
            outb(PIC_SLAVE_DATA, self.slave_mask);
        }
        Ok(())
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn init(&mut self) -> Result<()> {
        Err(Error::NotImplemented)
    }

    /// Mask all IRQs (disable all PIC-routed interrupts).
    #[cfg(target_arch = "x86_64")]
    pub fn mask_all(&mut self) {
        self.master_mask = 0xFF;
        self.slave_mask = 0xFF;
        // SAFETY: Writing 0xFF to PIC data ports masks all IRQs.
        unsafe {
            outb(PIC_MASTER_DATA, 0xFF);
            outb(PIC_SLAVE_DATA, 0xFF);
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn mask_all(&mut self) {}

    /// Unmask a single IRQ line (0–15).
    #[cfg(target_arch = "x86_64")]
    pub fn enable_irq(&mut self, irq: u8) -> Result<()> {
        if irq > 15 {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: Writes to PIC IMR ports are safe on x86.
        unsafe {
            if irq < 8 {
                self.master_mask &= !(1u8 << irq);
                outb(PIC_MASTER_DATA, self.master_mask);
            } else {
                // Unmask slave line on master (IRQ 2) if not already unmasked
                self.master_mask &= !(1u8 << 2);
                outb(PIC_MASTER_DATA, self.master_mask);

                self.slave_mask &= !(1u8 << (irq - 8));
                outb(PIC_SLAVE_DATA, self.slave_mask);
            }
        }
        Ok(())
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn enable_irq(&mut self, _irq: u8) -> Result<()> {
        Err(Error::NotImplemented)
    }

    /// Mask a single IRQ line (0–15).
    #[cfg(target_arch = "x86_64")]
    pub fn disable_irq(&mut self, irq: u8) -> Result<()> {
        if irq > 15 {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: Writes to PIC IMR ports are safe on x86.
        unsafe {
            if irq < 8 {
                self.master_mask |= 1u8 << irq;
                outb(PIC_MASTER_DATA, self.master_mask);
            } else {
                self.slave_mask |= 1u8 << (irq - 8);
                outb(PIC_SLAVE_DATA, self.slave_mask);
            }
        }
        Ok(())
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn disable_irq(&mut self, _irq: u8) -> Result<()> {
        Err(Error::NotImplemented)
    }

    /// Send an End-Of-Interrupt (EOI) for the given IRQ line.
    ///
    /// For IRQs 8–15 (slave), EOI is sent to the slave first, then to
    /// master IRQ 2 (cascade line).
    #[cfg(target_arch = "x86_64")]
    pub fn send_eoi(&self, irq: u8) {
        // SAFETY: OCW2 EOI command to PIC command ports.
        unsafe {
            if irq >= 8 {
                outb(PIC_SLAVE_CMD, OCW2_EOI);
            }
            outb(PIC_MASTER_CMD, OCW2_EOI);
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn send_eoi(&self, _irq: u8) {}

    /// Read the Interrupt Request Register (IRR) for both PICs.
    ///
    /// Returns `(master_irr, slave_irr)`.
    #[cfg(target_arch = "x86_64")]
    pub fn read_irr(&self) -> (u8, u8) {
        // SAFETY: OCW3 read-IRR command.
        unsafe {
            outb(PIC_MASTER_CMD, OCW3_READ_IRR);
            outb(PIC_SLAVE_CMD, OCW3_READ_IRR);
            (inb(PIC_MASTER_CMD), inb(PIC_SLAVE_CMD))
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn read_irr(&self) -> (u8, u8) {
        (0, 0)
    }

    /// Read the In-Service Register (ISR) for both PICs.
    ///
    /// Returns `(master_isr, slave_isr)`.
    #[cfg(target_arch = "x86_64")]
    pub fn read_isr(&self) -> (u8, u8) {
        // SAFETY: OCW3 read-ISR command.
        unsafe {
            outb(PIC_MASTER_CMD, OCW3_READ_ISR);
            outb(PIC_SLAVE_CMD, OCW3_READ_ISR);
            (inb(PIC_MASTER_CMD), inb(PIC_SLAVE_CMD))
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn read_isr(&self) -> (u8, u8) {
        (0, 0)
    }

    /// Check whether an IRQ appears to be spurious.
    ///
    /// A spurious IRQ 7 (master) or IRQ 15 (slave) has no corresponding
    /// ISR bit set.  Spurious interrupts should NOT receive an EOI.
    pub fn is_spurious(&self, irq: u8) -> bool {
        let (misr, sisr) = self.read_isr();
        match irq {
            7 => (misr & (1 << 7)) == 0,
            15 => (sisr & (1 << 7)) == 0,
            _ => false,
        }
    }

    /// Return the master vector base.
    pub const fn master_base(&self) -> u8 {
        self.master_base
    }

    /// Return the slave vector base.
    pub const fn slave_base(&self) -> u8 {
        self.slave_base
    }

    /// Return the current master IMR value.
    pub const fn master_mask(&self) -> u8 {
        self.master_mask
    }

    /// Return the current slave IMR value.
    pub const fn slave_mask(&self) -> u8 {
        self.slave_mask
    }
}
