// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! GICv3 Generic Interrupt Controller stub for aarch64.
//!
//! Initializes the GIC distributor and the primary CPU redistributor
//! so that the system can receive interrupts from the physical timer
//! and other peripherals.
//!
//! QEMU `virt` machine defaults:
//!   GICD base: 0x0800_0000
//!   GICR base: 0x080A_0000  (first redistributor frame)
//!
//! Reference: ARM IHI0069 GICv3 Architecture Specification.

use oncrix_lib::Result;

/// GIC distributor MMIO base (QEMU virt).
pub const GICD_BASE: usize = 0x0800_0000;
/// GIC redistributor MMIO base — first CPU frame (QEMU virt).
pub const GICR_BASE: usize = 0x080A_0000;

/// Spurious interrupt ID.
///
/// The GIC CPU interface returns this INTID from `ICC_IAR1_EL1` when no
/// interrupt is pending (or the pending IRQ has insufficient priority),
/// signalling that no acknowledgement or EOI is required.
pub const SPURIOUS_INTID: u32 = 1023;

/// Mask covering the valid INTID field of `ICC_IAR1_EL1` (bits [23:0]).
const INTID_MASK: u32 = 0x00FF_FFFF;

// ── Distributor register offsets ──────────────────────────────────────────────

const GICD_CTLR: usize = 0x000;
const GICD_TYPER: usize = 0x004;
const GICD_ISENABLER: usize = 0x100;

// ── Redistributor register offsets (LP frame) ─────────────────────────────────

const GICR_WAKER: usize = 0x014;
/// SGI frame offset within a redistributor stride (64 KiB).
const GICR_SGI_BASE: usize = 0x0001_0000;
const GICR_ISENABLER0: usize = GICR_SGI_BASE + 0x100;

// ── GICD_CTLR bits ────────────────────────────────────────────────────────────

/// Affinity routing enable (ARE_NS).
const GICD_CTLR_ARE_NS: u32 = 1 << 4;
/// Non-secure Group 1 enable.
const GICD_CTLR_ENABLE_G1NS: u32 = 1 << 1;

// ── GICR_WAKER bits ───────────────────────────────────────────────────────────

/// ProcessorSleep — clear to wake the redistributor.
const GICR_WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
/// ChildrenAsleep — poll until clear.
const GICR_WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;

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

/// GICv3 controller handle.
pub struct Gicv3 {
    gicd_base: usize,
    gicr_base: usize,
}

impl Gicv3 {
    /// Create a GICv3 instance at the given MMIO bases.
    pub const fn new(gicd_base: usize, gicr_base: usize) -> Self {
        Self {
            gicd_base,
            gicr_base,
        }
    }

    /// Initialize the GIC distributor and primary CPU redistributor.
    pub fn init(&self) -> Result<()> {
        // SAFETY: We access well-known QEMU virt MMIO addresses for
        // the GICv3 distributor and redistributor registers.
        unsafe {
            self.init_distributor();
            self.init_redistributor();
            self.init_cpu_interface();
        }
        Ok(())
    }

    /// Initialize the distributor: enable affinity routing, enable Group 1.
    ///
    /// # Safety
    /// Caller must ensure GICD MMIO is accessible.
    unsafe fn init_distributor(&self) {
        let base = self.gicd_base;

        // Read ITLinesNumber to discover how many SPI registers to configure.
        // SAFETY: reading GICD_TYPER to determine interrupt count.
        let typer = unsafe { read32(base + GICD_TYPER) };
        let it_lines = (typer & 0x1F) as usize;

        // Disable all SPIs.
        for i in 1..=it_lines {
            // SAFETY: GICD_ISENABLER + 4*i is within the SPI clear range.
            unsafe { write32(base + GICD_ISENABLER + 4 * i, 0) };
        }

        // Enable affinity routing and NS Group 1.
        // SAFETY: GICD_CTLR is the distributor control register.
        unsafe { write32(base + GICD_CTLR, GICD_CTLR_ARE_NS | GICD_CTLR_ENABLE_G1NS) };
    }

    /// Wake the primary CPU redistributor.
    ///
    /// # Safety
    /// Caller must ensure GICR MMIO is accessible.
    unsafe fn init_redistributor(&self) {
        let base = self.gicr_base;

        // Clear ProcessorSleep to wake the redistributor.
        // SAFETY: GICR_WAKER is the redistributor wake register.
        let waker = unsafe { read32(base + GICR_WAKER) };
        // SAFETY: writing back with PROCESSOR_SLEEP cleared.
        unsafe { write32(base + GICR_WAKER, waker & !GICR_WAKER_PROCESSOR_SLEEP) };

        // Spin until ChildrenAsleep is clear (redistributor is awake).
        let mut spins = 0u32;
        loop {
            // SAFETY: polling GICR_WAKER ChildrenAsleep bit.
            if unsafe { read32(base + GICR_WAKER) } & GICR_WAKER_CHILDREN_ASLEEP == 0 {
                break;
            }
            spins = spins.wrapping_add(1);
            // Avoid infinite spin in pathological cases (non-QEMU hardware).
            if spins >= 1_000_000 {
                break;
            }
        }

        // Enable SGI 0 (used for IPI) and PPI 30 (physical non-secure timer).
        // Bit 0 = SGI0, bit 30 = PPI30 (CNTP interrupt).
        // SAFETY: GICR_ISENABLER0 is the SGI/PPI enable register.
        unsafe { write32(base + GICR_ISENABLER0, (1 << 0) | (1 << 30)) };
    }

    /// Configure ICC system registers to enable Group 1 interrupts.
    ///
    /// # Safety
    /// Must be called after redistributor wake; requires EL1 system register access.
    #[cfg(target_arch = "aarch64")]
    unsafe fn init_cpu_interface(&self) {
        // SAFETY: Writing ICC_SRE_EL1 to enable system register interface.
        // ICC_SRE_EL1.SRE (bit 0) must be 1 before any other ICC registers
        // can be accessed. ICC_SRE_EL1.DFB (bit 1) and DIB (bit 2) disable
        // FIQ/IRQ bypass; set both to keep all interrupts in IRQ mode.
        unsafe {
            core::arch::asm!(
                "msr icc_sre_el1, {val}",
                "isb",
                val = in(reg) 0b111u64,
            );

            // Set ICC_PMR_EL1 to lowest priority mask (0xFF = accept all).
            core::arch::asm!(
                "msr icc_pmr_el1, {val}",
                "isb",
                val = in(reg) 0xFFu64,
            );

            // Enable Group 1 interrupts via ICC_IGRPEN1_EL1.
            core::arch::asm!(
                "msr icc_igrpen1_el1, {val}",
                "isb",
                val = in(reg) 1u64,
            );
        }
    }

    #[cfg(not(target_arch = "aarch64"))]
    unsafe fn init_cpu_interface(&self) {}

    /// Acknowledge the highest-priority pending Group 1 interrupt.
    ///
    /// Reads `ICC_IAR1_EL1`, which the CPU interface treats as the
    /// interrupt-acknowledge operation: it moves the highest-priority
    /// pending Group 1 IRQ to the active state and returns its INTID.
    /// A return value of [`SPURIOUS_INTID`] means no IRQ was pending and
    /// the caller must not issue a matching [`Self::eoi_irq`].
    ///
    /// Only the low 24 bits carry the INTID; the upper bits are masked off.
    #[cfg(target_arch = "aarch64")]
    pub fn ack_irq(&self) -> u32 {
        let iar: u64;
        // SAFETY: Reading ICC_IAR1_EL1 acknowledges the highest-priority
        // pending Group 1 IRQ and returns its INTID. This is a privileged
        // EL1 system-register read whose side effect (moving the IRQ to the
        // active state) is exactly the intended acknowledge operation.
        unsafe {
            core::arch::asm!(
                "mrs {iar}, ICC_IAR1_EL1",
                iar = out(reg) iar,
                options(nostack, preserves_flags),
            );
        }
        (iar as u32) & INTID_MASK
    }

    /// Signal end-of-interrupt for a previously acknowledged INTID.
    ///
    /// Writes `ICC_EOIR1_EL1` to drop the active priority and de-activate
    /// the IRQ named by `intid`. `intid` must be the value returned by a
    /// prior [`Self::ack_irq`] call and must not be [`SPURIOUS_INTID`].
    #[cfg(target_arch = "aarch64")]
    pub fn eoi_irq(&self, intid: u32) {
        // SAFETY: Writing ICC_EOIR1_EL1 signals end-of-interrupt for an
        // INTID previously returned by ack_irq(), de-activating it in the
        // CPU interface. A prior `dsb`/`isb` is not required here: the CPU
        // interface serialises the ack/EOI pair, and the timer re-arm that
        // precedes this write already issued its own `isb` via CNTP_CTL.
        unsafe {
            core::arch::asm!(
                "msr ICC_EOIR1_EL1, {intid}",
                "isb",
                intid = in(reg) intid as u64,
                options(nostack, preserves_flags),
            );
        }
    }

    /// Non-aarch64 build stub for [`Self::ack_irq`].
    #[cfg(not(target_arch = "aarch64"))]
    pub fn ack_irq(&self) -> u32 {
        SPURIOUS_INTID
    }

    /// Non-aarch64 build stub for [`Self::eoi_irq`].
    #[cfg(not(target_arch = "aarch64"))]
    pub fn eoi_irq(&self, _intid: u32) {}
}
