// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Local APIC (Advanced Programmable Interrupt Controller) driver.
//!
//! The Local APIC is an on-chip interrupt controller present on every x86_64
//! processor core. It handles:
//! - **External IRQs** routed from the I/O APIC.
//! - **Inter-Processor Interrupts (IPI)** for SMP coordination.
//! - **Local interrupt sources**: APIC timer, thermal, performance, LINT0/1.
//! - **Spurious interrupts**: handled via the Spurious Vector Register.
//!
//! Access is via MMIO at the APIC base address (default 0xFEE00000, readable
//! from `IA32_APIC_BASE` MSR). All registers are 32 bits wide at 16-byte aligned
//! offsets.
//!
//! Reference: Intel 64 and IA-32 Architectures Software Developer's Manual,
//! Volume 3A, Chapter 10 — Advanced Programmable Interrupt Controller.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// APIC Register Offsets (byte offsets from APIC base)
// ---------------------------------------------------------------------------

/// Local APIC ID Register (read-only).
pub const REG_ID: u32 = 0x020;
/// Local APIC Version Register (read-only).
pub const REG_VER: u32 = 0x030;
/// Task Priority Register (TPR).
pub const REG_TPR: u32 = 0x080;
/// Arbitration Priority Register (APR, read-only).
pub const REG_APR: u32 = 0x090;
/// Processor Priority Register (PPR, read-only).
pub const REG_PPR: u32 = 0x0A0;
/// End-Of-Interrupt Register (write-only, write any value to send EOI).
pub const REG_EOI: u32 = 0x0B0;
/// Remote Read Register (RRD).
pub const REG_RRD: u32 = 0x0C0;
/// Logical Destination Register (LDR).
pub const REG_LDR: u32 = 0x0D0;
/// Destination Format Register (DFR).
pub const REG_DFR: u32 = 0x0E0;
/// Spurious Interrupt Vector Register (SVR).
pub const REG_SVR: u32 = 0x0F0;

// In-Service Registers (ISR) — 256 bits across 8 dwords at 0x100..0x170.
/// ISR register 0 (vectors 31:0).
pub const REG_ISR0: u32 = 0x100;
/// Trigger Mode Registers (TMR) — 256 bits across 8 dwords at 0x180..0x1F0.
pub const REG_TMR0: u32 = 0x180;
/// Interrupt Request Registers (IRR) — 256 bits across 8 dwords at 0x200..0x270.
pub const REG_IRR0: u32 = 0x200;
/// Error Status Register (ESR).
pub const REG_ESR: u32 = 0x280;
/// LVT CMCI (Corrected Machine Check Interrupt).
pub const REG_LVT_CMCI: u32 = 0x2F0;
/// Interrupt Command Register low dword (bits 31:0).
pub const REG_ICR_LOW: u32 = 0x300;
/// Interrupt Command Register high dword (bits 63:32).
pub const REG_ICR_HIGH: u32 = 0x310;
/// LVT Timer Register.
pub const REG_LVT_TIMER: u32 = 0x320;
/// LVT Thermal Sensor Register.
pub const REG_LVT_THERMAL: u32 = 0x330;
/// LVT Performance Monitoring Counter Register.
pub const REG_LVT_PERF: u32 = 0x340;
/// LVT LINT0 Register.
pub const REG_LVT_LINT0: u32 = 0x350;
/// LVT LINT1 Register.
pub const REG_LVT_LINT1: u32 = 0x360;
/// LVT Error Register.
pub const REG_LVT_ERROR: u32 = 0x370;
/// Initial Count Register (for APIC timer).
pub const REG_TIMER_INITIAL: u32 = 0x380;
/// Current Count Register (for APIC timer, read-only).
pub const REG_TIMER_CURRENT: u32 = 0x390;
/// Divide Configuration Register (for APIC timer).
pub const REG_TIMER_DIVIDE: u32 = 0x3E0;

// ---------------------------------------------------------------------------
// SVR / LVT / ICR Bit Definitions
// ---------------------------------------------------------------------------

/// SVR bit 8: APIC software enable.
pub const SVR_ENABLE: u32 = 1 << 8;
/// SVR bits 7:0: Spurious vector number (typically 0xFF).
pub const SVR_VECTOR_MASK: u32 = 0xFF;

/// LVT bit 16: Interrupt masked.
pub const LVT_MASKED: u32 = 1 << 16;
/// LVT bits 10:8: Delivery mode field.
pub const LVT_DELIVERY_SHIFT: u32 = 8;
/// LVT Timer Mode: one-shot (bits 18:17 = 00).
pub const LVT_TIMER_ONESHOT: u32 = 0 << 17;
/// LVT Timer Mode: periodic (bits 18:17 = 01).
pub const LVT_TIMER_PERIODIC: u32 = 1 << 17;
/// LVT Timer Mode: TSC-deadline (bits 18:17 = 10).
pub const LVT_TIMER_TSCDEADLINE: u32 = 2 << 17;

/// ICR delivery mode: Fixed.
pub const ICR_DELIVERY_FIXED: u32 = 0 << 8;
/// ICR delivery mode: Lowest Priority.
pub const ICR_DELIVERY_LOWPRI: u32 = 1 << 8;
/// ICR delivery mode: SMI.
pub const ICR_DELIVERY_SMI: u32 = 2 << 8;
/// ICR delivery mode: NMI.
pub const ICR_DELIVERY_NMI: u32 = 4 << 8;
/// ICR delivery mode: INIT.
pub const ICR_DELIVERY_INIT: u32 = 5 << 8;
/// ICR delivery mode: SIPI (Startup IPI).
pub const ICR_DELIVERY_SIPI: u32 = 6 << 8;

/// ICR bit 11: destination mode (0=physical, 1=logical).
pub const ICR_DEST_LOGICAL: u32 = 1 << 11;
/// ICR bit 12: Delivery status (read-only, 1=pending).
pub const ICR_SEND_PENDING: u32 = 1 << 12;
/// ICR bit 14: Level (1=assert, 0=de-assert; only for INIT de-assert).
pub const ICR_LEVEL_ASSERT: u32 = 1 << 14;
/// ICR bit 15: Trigger mode (0=edge, 1=level).
pub const ICR_TRIGGER_LEVEL: u32 = 1 << 15;

/// ICR destination shorthand: No shorthand (use destination field).
pub const ICR_DEST_NO_SHORTHAND: u32 = 0 << 18;
/// ICR destination shorthand: Self.
pub const ICR_DEST_SELF: u32 = 1 << 18;
/// ICR destination shorthand: All including self.
pub const ICR_DEST_ALL_INCL_SELF: u32 = 2 << 18;
/// ICR destination shorthand: All excluding self.
pub const ICR_DEST_ALL_EXCL_SELF: u32 = 3 << 18;

/// Timer divide configuration: divide by 1.
pub const TIMER_DIV_1: u32 = 0x0B;
/// Timer divide configuration: divide by 2.
pub const TIMER_DIV_2: u32 = 0x00;
/// Timer divide configuration: divide by 4.
pub const TIMER_DIV_4: u32 = 0x01;
/// Timer divide configuration: divide by 8.
pub const TIMER_DIV_8: u32 = 0x02;
/// Timer divide configuration: divide by 16.
pub const TIMER_DIV_16: u32 = 0x03;
/// Timer divide configuration: divide by 128.
pub const TIMER_DIV_128: u32 = 0x0A;

// ---------------------------------------------------------------------------
// Local APIC Driver
// ---------------------------------------------------------------------------

/// Reads a 32-bit value from an APIC MMIO register.
///
/// # Safety
/// `base` must be the virtual address of a mapped Local APIC MMIO region,
/// and `offset` must be a valid register offset (aligned to 16 bytes, ≤ 0x3F0).
#[inline]
unsafe fn read_reg(base: u64, offset: u32) -> u32 {
    let ptr = (base + offset as u64) as *const u32;
    // SAFETY: Caller guarantees base+offset is a valid MMIO address.
    unsafe { core::ptr::read_volatile(ptr) }
}

/// Writes a 32-bit value to an APIC MMIO register.
///
/// # Safety
/// Same as `read_reg`.
#[inline]
unsafe fn write_reg(base: u64, offset: u32, val: u32) {
    let ptr = (base + offset as u64) as *mut u32;
    // SAFETY: Caller guarantees base+offset is a valid MMIO address.
    unsafe { core::ptr::write_volatile(ptr, val) }
}

/// Local APIC controller for a single CPU core.
pub struct Lapic {
    /// Virtual base address of the Local APIC MMIO region.
    base: u64,
}

impl Lapic {
    /// Creates a new `Lapic` instance at `base`.
    ///
    /// # Parameters
    /// - `base`: Virtual address of the mapped APIC MMIO region (typically 0xFEE00000).
    pub const fn new(base: u64) -> Self {
        Self { base }
    }

    /// Reads a register at `offset`.
    ///
    /// # Safety
    /// `offset` must be a valid APIC register offset.
    pub unsafe fn read(&self, offset: u32) -> u32 {
        // SAFETY: base is a mapped APIC MMIO region; caller validates offset.
        unsafe { read_reg(self.base, offset) }
    }

    /// Writes `val` to the register at `offset`.
    ///
    /// # Safety
    /// `offset` must be a valid writable APIC register offset.
    pub unsafe fn write(&self, offset: u32, val: u32) {
        // SAFETY: base is a mapped APIC MMIO region; caller validates offset.
        unsafe { write_reg(self.base, offset, val) }
    }

    /// Returns the Local APIC ID (APIC ID field, bits 31:24 of REG_ID).
    ///
    /// # Safety
    /// Caller must ensure APIC is accessible at the base address.
    pub unsafe fn id(&self) -> u8 {
        // SAFETY: REG_ID is a valid read-only register.
        unsafe { (self.read(REG_ID) >> 24) as u8 }
    }

    /// Returns the APIC version number (bits 7:0 of REG_VER).
    ///
    /// # Safety
    /// See `id`.
    pub unsafe fn version(&self) -> u8 {
        // SAFETY: REG_VER is a valid read-only register.
        unsafe { (self.read(REG_VER) & 0xFF) as u8 }
    }

    /// Enables the APIC by setting the software-enable bit in SVR.
    ///
    /// Also sets the spurious vector to `spurious_vec`.
    ///
    /// # Safety
    /// Caller must have mapped the APIC region before calling.
    pub unsafe fn enable(&self, spurious_vec: u8) {
        // SAFETY: Writing SVR to enable APIC and set spurious vector.
        unsafe {
            let svr = SVR_ENABLE | (spurious_vec as u32 & SVR_VECTOR_MASK);
            self.write(REG_SVR, svr);
        }
    }

    /// Sends an End-of-Interrupt signal.
    ///
    /// Must be called at the end of every interrupt handler (except NMI/SMI).
    ///
    /// # Safety
    /// Caller must be inside an interrupt handler and not send EOI for NMI/SMI.
    pub unsafe fn send_eoi(&self) {
        // SAFETY: Writing 0 to EOI register acknowledges the current interrupt.
        unsafe { self.write(REG_EOI, 0) }
    }

    /// Sets the Task Priority Register to `priority` (0–15 in bits 7:4).
    ///
    /// Interrupts with vector < (priority << 4) are inhibited.
    ///
    /// # Safety
    /// Caller should not lower priority while serving a higher-priority interrupt.
    pub unsafe fn set_task_priority(&self, priority: u8) {
        // SAFETY: TPR write is safe; affects interrupt delivery threshold.
        unsafe { self.write(REG_TPR, (priority as u32) << 4) }
    }

    /// Sends an IPI to APIC `dest_id` with `delivery_mode` and `vector`.
    ///
    /// Waits for delivery by polling the ICR send-pending bit.
    ///
    /// # Safety
    /// Destination APIC must be online. An INIT IPI to a live CPU is destructive.
    pub unsafe fn send_ipi(&self, dest_id: u8, delivery_mode: u32, vector: u8) -> Result<()> {
        // SAFETY: ICR writes dispatch IPIs; caller ensures target is valid.
        unsafe {
            // Write destination (high dword) first
            self.write(REG_ICR_HIGH, (dest_id as u32) << 24);
            // Write command (low dword) to trigger the IPI
            let cmd = delivery_mode | (vector as u32);
            self.write(REG_ICR_LOW, cmd);
            // Poll until delivery is complete (ICR_SEND_PENDING clears)
            let mut timeout = 100_000u32;
            while self.read(REG_ICR_LOW) & ICR_SEND_PENDING != 0 {
                if timeout == 0 {
                    return Err(Error::Busy);
                }
                timeout -= 1;
                core::hint::spin_loop();
            }
        }
        Ok(())
    }

    /// Sends an IPI to all CPUs except self.
    ///
    /// # Safety
    /// See `send_ipi`.
    pub unsafe fn send_ipi_all_excl_self(&self, vector: u8) -> Result<()> {
        // SAFETY: Shorthand IPI; targets all APs.
        unsafe {
            self.write(REG_ICR_HIGH, 0);
            let cmd = ICR_DEST_ALL_EXCL_SELF | ICR_DELIVERY_FIXED | (vector as u32);
            self.write(REG_ICR_LOW, cmd);
            let mut timeout = 100_000u32;
            while self.read(REG_ICR_LOW) & ICR_SEND_PENDING != 0 {
                if timeout == 0 {
                    return Err(Error::Busy);
                }
                timeout -= 1;
                core::hint::spin_loop();
            }
        }
        Ok(())
    }

    /// Configures the APIC timer.
    ///
    /// # Parameters
    /// - `vector`: Interrupt vector for timer expiry.
    /// - `initial_count`: Counter reload value.
    /// - `divide`: Divide configuration (e.g., `TIMER_DIV_16`).
    /// - `periodic`: If `true`, reload after expiry; otherwise one-shot.
    ///
    /// # Safety
    /// Caller must have enabled the APIC before configuring the timer.
    pub unsafe fn configure_timer(
        &self,
        vector: u8,
        initial_count: u32,
        divide: u32,
        periodic: bool,
    ) {
        // SAFETY: Timer registers are valid APIC MMIO; APIC is enabled.
        unsafe {
            self.write(REG_TIMER_DIVIDE, divide);
            let mode = if periodic {
                LVT_TIMER_PERIODIC
            } else {
                LVT_TIMER_ONESHOT
            };
            self.write(REG_LVT_TIMER, mode | (vector as u32));
            self.write(REG_TIMER_INITIAL, initial_count);
        }
    }

    /// Returns the current APIC timer count.
    ///
    /// # Safety
    /// See `read`.
    pub unsafe fn timer_count(&self) -> u32 {
        // SAFETY: REG_TIMER_CURRENT is a valid read-only register.
        unsafe { self.read(REG_TIMER_CURRENT) }
    }

    /// Masks an LVT entry (prevents the interrupt from being delivered).
    ///
    /// # Safety
    /// `lvt_offset` must be a valid LVT register offset.
    pub unsafe fn mask_lvt(&self, lvt_offset: u32) {
        // SAFETY: Read-modify-write on a valid LVT register.
        unsafe {
            let v = self.read(lvt_offset);
            self.write(lvt_offset, v | LVT_MASKED);
        }
    }

    /// Unmasks an LVT entry.
    ///
    /// # Safety
    /// `lvt_offset` must be a valid LVT register offset.
    pub unsafe fn unmask_lvt(&self, lvt_offset: u32) {
        // SAFETY: Read-modify-write on a valid LVT register.
        unsafe {
            let v = self.read(lvt_offset);
            self.write(lvt_offset, v & !LVT_MASKED);
        }
    }

    /// Reads the Error Status Register.
    ///
    /// The ESR must be written (any value) before reading to latch the current
    /// error bits.
    ///
    /// # Safety
    /// Should only be called when handling an APIC error interrupt.
    pub unsafe fn read_esr(&self) -> u32 {
        // SAFETY: ESR write-then-read is the correct sequence per the Intel spec.
        unsafe {
            self.write(REG_ESR, 0);
            self.read(REG_ESR)
        }
    }
}
