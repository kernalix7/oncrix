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

// ── Redistributor register offsets ────────────────────────────────────────────
//
// The redistributor is split into two 64 KiB frames:
//   • RD_base   (GICR_BASE + 0x0)      — control/wake registers (GICR_WAKER …)
//   • SGI_base  (GICR_BASE + 0x10000)  — the SGI/PPI banked registers that
//     configure INTIDs 0..31 for this PE (IGROUPR0, IPRIORITYR, ICFGR1,
//     ISENABLER0, IGRPMODR0, …).
// All PPI-30 (CNTP) configuration therefore lives at SGI_base, i.e. every
// offset below is added to `GICR_BASE + GICR_SGI_BASE`.

/// GICR_WAKER lives in the RD_base frame (offset 0 from GICR_BASE).
const GICR_WAKER: usize = 0x014;
/// SGI_base frame offset within a redistributor stride (64 KiB).
const GICR_SGI_BASE: usize = 0x0001_0000;
/// Interrupt Group register for SGIs/PPIs (INTID 0..31): 1 bit each.
const GICR_IGROUPR0: usize = GICR_SGI_BASE + 0x080;
/// Set-enable register for SGIs/PPIs (INTID 0..31): 1 bit each.
const GICR_ISENABLER0: usize = GICR_SGI_BASE + 0x100;
/// Priority registers for SGIs/PPIs: 1 byte per INTID, 4 INTIDs per word.
const GICR_IPRIORITYR: usize = GICR_SGI_BASE + 0x400;
/// Config register for PPIs (INTID 16..31): 2 bits each (edge/level).
const GICR_ICFGR1: usize = GICR_SGI_BASE + 0xC04;
/// Interrupt Group-modifier register for SGIs/PPIs: 1 bit each.
const GICR_IGRPMODR0: usize = GICR_SGI_BASE + 0xD00;

/// The CNTP EL1 physical timer interrupt is PPI INTID 30.
const PPI_TIMER_INTID: u32 = 30;

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

        // ── Configure the SGI/PPI bank BEFORE enabling any INTID ──────────────
        //
        // The CPU interface (ICC_IGRPEN1_EL1) only delivers Group 1 interrupts,
        // and only when their priority is numerically LOWER than ICC_PMR_EL1.
        // On reset QEMU leaves these banked registers at values that block a
        // freshly-armed PPI: IGROUPR0 may default to Group 0 (never delivered
        // via IGRPEN1), and IPRIORITYR defaults to 0xFF which is NOT lower than
        // PMR=0xFF, so the interrupt is filtered out. We must program them.

        // 1. Assign every SGI/PPI (INTID 0..31) to Group 1, and clear the
        //    group-modifier so they are Non-secure Group 1 (not Secure G1).
        //    IGRPMODR is RES0 when the GIC runs in a single security state, so
        //    writing 0 is always safe and keeps a two-security-state GIC in NS.
        // SAFETY: GICR_IGROUPR0 / GICR_IGRPMODR0 are the SGI_base group
        // registers for this PE's banked INTIDs 0..31.
        unsafe {
            write32(base + GICR_IGROUPR0, 0xFFFF_FFFF);
            write32(base + GICR_IGRPMODR0, 0x0000_0000);
        }

        // 2. Give PPI 30 a deliverable priority. IPRIORITYR is byte-addressable
        //    (4 INTIDs per 32-bit word); INTID 30 lives in word 30/4 = 7 at
        //    byte 30 % 4 = 2. We read-modify-write only that byte to 0x00 —
        //    the highest priority, guaranteed lower than PMR=0xFF, and immune
        //    to the single-security-state priority top-bit aliasing (a 0x00
        //    field reads back as 0x00 regardless of the writable-bit view).
        let pri_word = base + GICR_IPRIORITYR + (PPI_TIMER_INTID as usize / 4) * 4;
        let pri_shift = (PPI_TIMER_INTID % 4) * 8;
        // SAFETY: pri_word addresses IPRIORITYR7 within the SGI_base frame.
        unsafe {
            let cur = read32(pri_word);
            write32(pri_word, cur & !(0xFFu32 << pri_shift));
        }

        // 3. Configure PPI 30 as level-sensitive. ICFGR1 covers PPIs 16..31
        //    with 2 bits each; INTID 30 occupies bits [2*(30-16)+1 : 2*(30-16)]
        //    = bits [29:28]. Level-sensitive is 0b00, so clear that field. This
        //    matches the CNTP timer, whose interrupt line stays asserted while
        //    CNTP_CTL_EL0.ISTATUS==1; edge config could miss a re-armed line.
        let cfg_shift = 2 * (PPI_TIMER_INTID - 16);
        // SAFETY: GICR_ICFGR1 is the PPI config register in the SGI_base frame.
        unsafe {
            let cur = read32(base + GICR_ICFGR1);
            write32(base + GICR_ICFGR1, cur & !(0b11u32 << cfg_shift));
        }

        // 4. Enable SGI 0 (used for IPI) and PPI 30 (physical non-secure timer).
        //    Bit 0 = SGI0, bit 30 = PPI30 (CNTP interrupt).
        // SAFETY: GICR_ISENABLER0 is the SGI/PPI enable register.
        unsafe { write32(base + GICR_ISENABLER0, (1 << 0) | (1 << PPI_TIMER_INTID)) };
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
