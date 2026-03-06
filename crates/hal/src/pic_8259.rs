// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Legacy 8259A Programmable Interrupt Controller (PIC) driver.
//!
//! The 8259A is the original PC interrupt controller, now typically virtualized
//! by the chipset. In modern systems with APIC, the PIC is disabled early in boot,
//! but must first be properly remapped so its spurious interrupts don't land on
//! CPU exception vectors (0–31).
//!
//! # Cascade configuration
//! The PC-AT uses two 8259As in cascade: master (IRQ 0–7) and slave (IRQ 8–15).
//! The slave is connected to master's IRQ 2.
//!
//! # I/O port layout
//! | Port | Master | Slave |
//! |------|--------|-------|
//! | Command/Status | 0x20 | 0xA0 |
//! | Data/IMR       | 0x21 | 0xA1 |
//!
//! Reference: Intel 8259A Programmable Interrupt Controller Datasheet.

// ---------------------------------------------------------------------------
// Port Addresses
// ---------------------------------------------------------------------------

/// Master PIC command port.
const PIC_MASTER_CMD: u16 = 0x20;
/// Master PIC data/IMR port.
const PIC_MASTER_DATA: u16 = 0x21;
/// Slave PIC command port.
const PIC_SLAVE_CMD: u16 = 0xA0;
/// Slave PIC data/IMR port.
const PIC_SLAVE_DATA: u16 = 0xA1;

// ---------------------------------------------------------------------------
// Initialization Command Words (ICWs)
// ---------------------------------------------------------------------------

/// ICW1: Initialize PIC; IC4 bit set (ICW4 needed).
const ICW1_INIT: u8 = 0x10;
/// ICW1: Cascade mode (slave PIC connected, not SNGL).
const ICW1_CASCADE: u8 = 0x00;
/// ICW1: Edge-triggered mode (not LTIM).
const ICW1_EDGE: u8 = 0x00;
/// ICW1: ICW4 required.
const ICW1_ICW4: u8 = 0x01;

/// ICW4: 8086/8088 mode.
const ICW4_8086: u8 = 0x01;
/// ICW4: Auto EOI mode (PIC clears ISR automatically after INTA).
const ICW4_AUTO_EOI: u8 = 0x02;
/// ICW4: Normal (non-buffered) mode.
const ICW4_NORMAL: u8 = 0x00;

// ---------------------------------------------------------------------------
// OCW (Operational Control Words)
// ---------------------------------------------------------------------------

/// OCW2: Non-specific EOI command.
const EOI_NONSPECIFIC: u8 = 0x20;

/// OCW3: Read ISR command (In-Service Register).
const OCW3_READ_ISR: u8 = 0x0B;
/// OCW3: Read IRR command (Interrupt Request Register).
const OCW3_READ_IRR: u8 = 0x0A;
/// OCW3 fixed bits.
const OCW3_FIXED: u8 = 0x08;

// ---------------------------------------------------------------------------
// Port I/O primitives
// ---------------------------------------------------------------------------

/// Writes `val` to I/O port `port`.
///
/// # Safety
/// Writing to arbitrary I/O ports can have unexpected hardware side effects.
/// Caller must ensure `port` is the correct PIC port.
#[cfg(target_arch = "x86_64")]
unsafe fn outb(port: u16, val: u8) {
    // SAFETY: Port I/O instruction; caller guarantees port is valid.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
    }
}

/// Reads a byte from I/O port `port`.
///
/// # Safety
/// See `outb`.
#[cfg(target_arch = "x86_64")]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: Port I/O read; caller guarantees port is valid.
    unsafe {
        core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack));
    }
    val
}

/// Issues a short I/O delay by writing to port 0x80 (POST diagnostic port).
///
/// # Safety
/// Writing to port 0x80 is generally harmless on x86 PCs (POST code port).
#[cfg(target_arch = "x86_64")]
unsafe fn io_wait() {
    // SAFETY: Port 0x80 is the POST diagnostic port; writes are ignored.
    unsafe { outb(0x80, 0) }
}

// ---------------------------------------------------------------------------
// 8259 PIC Driver
// ---------------------------------------------------------------------------

/// Represents one 8259A PIC (master or slave).
#[derive(Clone, Copy, Debug)]
pub struct Pic8259 {
    /// Command/status port.
    cmd_port: u16,
    /// Data/IMR port.
    data_port: u16,
    /// Current IRQ mask (bit N = 1 means IRQ N is masked).
    mask: u8,
}

impl Pic8259 {
    /// Creates a new PIC instance.
    const fn new(cmd_port: u16, data_port: u16) -> Self {
        Self {
            cmd_port,
            data_port,
            mask: 0xFF, // All masked initially
        }
    }

    /// Sends `val` to the command port.
    ///
    /// # Safety
    /// Only valid during PIC initialization or OCW write sequences.
    #[cfg(target_arch = "x86_64")]
    unsafe fn cmd(&self, val: u8) {
        // SAFETY: cmd_port is a valid PIC command port.
        unsafe { outb(self.cmd_port, val) }
    }

    /// Sends `val` to the data/IMR port.
    ///
    /// # Safety
    /// Only valid during PIC initialization or mask update sequences.
    #[cfg(target_arch = "x86_64")]
    unsafe fn data(&self, val: u8) {
        // SAFETY: data_port is a valid PIC data port.
        unsafe { outb(self.data_port, val) }
    }

    /// Reads the current Interrupt Mask Register.
    ///
    /// # Safety
    /// Must only be called when PIC is initialized.
    #[cfg(target_arch = "x86_64")]
    unsafe fn read_imr(&self) -> u8 {
        // SAFETY: Reading the data port returns the IMR.
        unsafe { inb(self.data_port) }
    }

    /// Reads the ISR or IRR depending on which OCW3 command was last sent.
    ///
    /// # Safety
    /// Caller must send the appropriate OCW3 command first.
    #[cfg(target_arch = "x86_64")]
    unsafe fn read_status(&self) -> u8 {
        // SAFETY: Reading command port after OCW3 returns requested register.
        unsafe { inb(self.cmd_port) }
    }
}

/// Combined master+slave 8259A PIC cascade controller.
pub struct CascadedPic {
    master: Pic8259,
    slave: Pic8259,
}

impl CascadedPic {
    /// Creates a new cascaded PIC controller using standard PC ports.
    pub const fn new() -> Self {
        Self {
            master: Pic8259::new(PIC_MASTER_CMD, PIC_MASTER_DATA),
            slave: Pic8259::new(PIC_SLAVE_CMD, PIC_SLAVE_DATA),
        }
    }

    /// Remaps both PICs and initialises them in cascade mode.
    ///
    /// # Parameters
    /// - `master_base`: First IRQ vector for master PIC (IRQ 0 → this vector).
    /// - `slave_base`: First IRQ vector for slave PIC (IRQ 8 → this vector).
    ///
    /// # Safety
    /// Must be called exactly once during early boot, before enabling interrupts.
    /// Incorrect base vectors that overlap CPU exceptions (0–31) cause undefined
    /// interrupt dispatch.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn init_cascade(&mut self, master_base: u8, slave_base: u8) {
        // SAFETY: PIC initialisation sequence per the 8259A datasheet.
        unsafe {
            // Save existing masks
            let master_mask = inb(PIC_MASTER_DATA);
            let slave_mask = inb(PIC_SLAVE_DATA);

            // ICW1: Start initialisation
            let icw1 = ICW1_INIT | ICW1_CASCADE | ICW1_EDGE | ICW1_ICW4;
            self.master.cmd(icw1);
            io_wait();
            self.slave.cmd(icw1);
            io_wait();

            // ICW2: Set vector offsets
            self.master.data(master_base);
            io_wait();
            self.slave.data(slave_base);
            io_wait();

            // ICW3: Master — slave on IRQ2; Slave — cascade identity 2
            self.master.data(0x04); // IRQ2 has slave
            io_wait();
            self.slave.data(0x02); // Slave identity = 2
            io_wait();

            // ICW4: 8086 mode, non-buffered, normal EOI
            let icw4 = ICW4_8086 | ICW4_NORMAL;
            self.master.data(icw4);
            io_wait();
            self.slave.data(icw4);
            io_wait();

            // Restore original masks
            outb(PIC_MASTER_DATA, master_mask);
            outb(PIC_SLAVE_DATA, slave_mask);

            self.master.mask = master_mask;
            self.slave.mask = slave_mask;
        }
    }

    /// Remaps the PICs to `master_base` and `slave_base` vectors.
    ///
    /// Convenience alias for `init_cascade` that masks all IRQs after remapping.
    ///
    /// # Safety
    /// See `init_cascade`.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn remap(&mut self, master_base: u8, slave_base: u8) {
        // SAFETY: Delegating to init_cascade.
        unsafe {
            self.init_cascade(master_base, slave_base);
            self.disable();
        }
    }

    /// Disables both PICs by masking all IRQs.
    ///
    /// Called before activating the APIC to prevent spurious 8259 interrupts.
    ///
    /// # Safety
    /// After this call, no legacy IRQs will be delivered. Ensure APIC is
    /// configured before calling if IRQs are needed.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn disable(&mut self) {
        // SAFETY: Masking all IRQs is safe; disables legacy interrupt delivery.
        unsafe {
            outb(PIC_MASTER_DATA, 0xFF);
            outb(PIC_SLAVE_DATA, 0xFF);
            self.master.mask = 0xFF;
            self.slave.mask = 0xFF;
        }
    }

    /// Masks (disables) a single IRQ line.
    ///
    /// # Parameters
    /// - `irq`: IRQ number 0–15 (0–7 = master, 8–15 = slave).
    ///
    /// # Safety
    /// Masking an IRQ while it is active may delay interrupt acknowledgement.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn mask_irq(&mut self, irq: u8) {
        // SAFETY: IRQ masking is safe; updates IMR.
        unsafe {
            if irq < 8 {
                self.master.mask |= 1 << irq;
                outb(PIC_MASTER_DATA, self.master.mask);
            } else if irq < 16 {
                self.slave.mask |= 1 << (irq - 8);
                outb(PIC_SLAVE_DATA, self.slave.mask);
            }
        }
    }

    /// Unmasks (enables) a single IRQ line.
    ///
    /// # Parameters
    /// - `irq`: IRQ number 0–15.
    ///
    /// # Safety
    /// Ensure the IRQ handler is registered before unmasking.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn unmask_irq(&mut self, irq: u8) {
        // SAFETY: Unmasking IRQ enables interrupt delivery for that line.
        unsafe {
            if irq < 8 {
                self.master.mask &= !(1 << irq);
                outb(PIC_MASTER_DATA, self.master.mask);
            } else if irq < 16 {
                self.slave.mask &= !(1 << (irq - 8));
                outb(PIC_SLAVE_DATA, self.slave.mask);
                // Ensure IRQ2 (cascade) is unmasked on master
                self.master.mask &= !(1 << 2);
                outb(PIC_MASTER_DATA, self.master.mask);
            }
        }
    }

    /// Sends End-of-Interrupt for `irq`.
    ///
    /// For slave IRQs (8–15), sends EOI to both slave and master.
    ///
    /// # Safety
    /// Must only be called at the end of the corresponding IRQ handler.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn send_eoi(&self, irq: u8) {
        // SAFETY: EOI is sent at the end of an IRQ handler.
        unsafe {
            if irq >= 8 {
                outb(PIC_SLAVE_CMD, EOI_NONSPECIFIC);
            }
            outb(PIC_MASTER_CMD, EOI_NONSPECIFIC);
        }
    }

    /// Reads the In-Service Register (ISR) of both PICs.
    ///
    /// Returns a 16-bit value: bits 15:8 = slave ISR, bits 7:0 = master ISR.
    ///
    /// # Safety
    /// Must be called from ring 0.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn read_isr(&self) -> u16 {
        // SAFETY: OCW3 command followed by status read per 8259A datasheet.
        unsafe {
            outb(PIC_MASTER_CMD, OCW3_FIXED | OCW3_READ_ISR);
            outb(PIC_SLAVE_CMD, OCW3_FIXED | OCW3_READ_ISR);
            let master_isr = self.master.read_status();
            let slave_isr = self.slave.read_status();
            ((slave_isr as u16) << 8) | (master_isr as u16)
        }
    }

    /// Reads the Interrupt Request Register (IRR) of both PICs.
    ///
    /// Returns a 16-bit value: bits 15:8 = slave IRR, bits 7:0 = master IRR.
    ///
    /// # Safety
    /// Must be called from ring 0.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn read_irr(&self) -> u16 {
        // SAFETY: OCW3 command followed by status read per 8259A datasheet.
        unsafe {
            outb(PIC_MASTER_CMD, OCW3_FIXED | OCW3_READ_IRR);
            outb(PIC_SLAVE_CMD, OCW3_FIXED | OCW3_READ_IRR);
            let master_irr = self.master.read_status();
            let slave_irr = self.slave.read_status();
            ((slave_irr as u16) << 8) | (master_irr as u16)
        }
    }

    /// Returns the current IRQ mask as a 16-bit value.
    ///
    /// Bit N = 1 means IRQ N is masked.
    pub fn irq_mask(&self) -> u16 {
        ((self.slave.mask as u16) << 8) | (self.master.mask as u16)
    }

    /// Sets the complete IRQ mask from a 16-bit value.
    ///
    /// # Safety
    /// Unmasks in this call will immediately enable IRQ delivery. Handlers
    /// must be configured before unmasking.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn set_irq_mask(&mut self, mask: u16) {
        // SAFETY: Caller ensures handlers are registered for unmasked IRQs.
        unsafe {
            self.master.mask = mask as u8;
            self.slave.mask = (mask >> 8) as u8;
            outb(PIC_MASTER_DATA, self.master.mask);
            outb(PIC_SLAVE_DATA, self.slave.mask);
        }
    }

    /// Returns a reference to the master PIC.
    pub fn master(&self) -> &Pic8259 {
        &self.master
    }

    /// Returns a reference to the slave PIC.
    pub fn slave(&self) -> &Pic8259 {
        &self.slave
    }
}

impl Default for CascadedPic {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns `true` if an IRQ is a spurious interrupt from the master PIC.
///
/// A spurious IRQ 7 occurs when the master PIC raises IRQ 7 without a real
/// interrupt. Check the ISR bit for IRQ 7; if it is 0, the interrupt is spurious.
///
/// # Parameters
/// - `isr`: The 16-bit ISR value from `read_isr()`.
pub fn is_spurious_master(isr: u16) -> bool {
    (isr & 0x0080) == 0
}

/// Returns `true` if an IRQ is a spurious interrupt from the slave PIC (IRQ 15).
///
/// # Parameters
/// - `isr`: The 16-bit ISR value from `read_isr()`.
pub fn is_spurious_slave(isr: u16) -> bool {
    (isr & 0x8000) == 0
}
