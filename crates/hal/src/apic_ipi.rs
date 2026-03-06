// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! APIC Inter-Processor Interrupt (IPI) sending.
//!
//! IPIs are used for:
//! - **TLB shootdown** — force remote CPUs to flush stale TLB entries.
//! - **Reschedule** — kick a CPU out of its idle loop.
//! - **NMI broadcast** — crash diagnostics.
//! - **INIT/STARTUP** — bring Application Processors (APs) online.
//!
//! Supports both xAPIC (MMIO) and x2APIC (MSR) modes.
//!
//! Reference: Intel 64 and IA-32 Architectures Software Developer's Manual,
//! Volume 3A, §10.6 — Issuing Interprocessor Interrupts.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// ICR Field Definitions
// ---------------------------------------------------------------------------

/// ICR Delivery Mode: Fixed — deliver to the specified vector.
pub const ICR_DELIVERY_FIXED: u32 = 0b000 << 8;
/// ICR Delivery Mode: Lowest Priority.
pub const ICR_DELIVERY_LOWEST: u32 = 0b001 << 8;
/// ICR Delivery Mode: SMI.
pub const ICR_DELIVERY_SMI: u32 = 0b010 << 8;
/// ICR Delivery Mode: NMI (vector ignored).
pub const ICR_DELIVERY_NMI: u32 = 0b100 << 8;
/// ICR Delivery Mode: INIT.
pub const ICR_DELIVERY_INIT: u32 = 0b101 << 8;
/// ICR Delivery Mode: STARTUP (SIPI).
pub const ICR_DELIVERY_STARTUP: u32 = 0b110 << 8;

/// ICR Destination Mode: Physical (destination field is APIC ID).
pub const ICR_DEST_PHYSICAL: u32 = 0 << 11;
/// ICR Destination Mode: Logical (destination field is MDA).
pub const ICR_DEST_LOGICAL: u32 = 1 << 11;

/// ICR Delivery Status: Idle (read-only; safe to send next IPI).
pub const ICR_STATUS_IDLE: u32 = 0 << 12;
/// ICR Delivery Status: Send Pending (must wait before sending another).
pub const ICR_STATUS_PENDING: u32 = 1 << 12;

/// ICR Level: De-assert (for INIT de-assert only).
pub const ICR_LEVEL_DEASSERT: u32 = 0 << 14;
/// ICR Level: Assert (normal for all IPIs except INIT de-assert).
pub const ICR_LEVEL_ASSERT: u32 = 1 << 14;

/// ICR Trigger Mode: Edge-triggered.
pub const ICR_TRIGGER_EDGE: u32 = 0 << 15;
/// ICR Trigger Mode: Level-triggered (only for INIT).
pub const ICR_TRIGGER_LEVEL: u32 = 1 << 15;

/// ICR Shorthand: No shorthand (use destination field).
pub const ICR_DEST_NO_SHORTHAND: u32 = 0b00 << 18;
/// ICR Shorthand: Self (send to current CPU only).
pub const ICR_DEST_SELF: u32 = 0b01 << 18;
/// ICR Shorthand: All including self.
pub const ICR_DEST_ALL_INCL_SELF: u32 = 0b10 << 18;
/// ICR Shorthand: All excluding self.
pub const ICR_DEST_ALL_EXCL_SELF: u32 = 0b11 << 18;

// ---------------------------------------------------------------------------
// APIC Mode
// ---------------------------------------------------------------------------

/// Identifies whether the system is using xAPIC (MMIO) or x2APIC (MSR) mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApicMode {
    /// xAPIC: ICR accessed via MMIO at `base + 0x300` / `base + 0x310`.
    XApic { base: u64 },
    /// x2APIC: ICR accessed via MSR 0x830.
    X2Apic,
}

// ---------------------------------------------------------------------------
// xAPIC MMIO helpers
// ---------------------------------------------------------------------------

/// Reads a 32-bit xAPIC register at `base + offset`.
///
/// # Safety
/// `base` must be the correctly mapped xAPIC MMIO base address.
#[inline]
unsafe fn xapic_read(base: u64, offset: u32) -> u32 {
    let ptr = (base + offset as u64) as *const u32;
    // SAFETY: Caller guarantees base is a valid xAPIC MMIO mapping.
    unsafe { core::ptr::read_volatile(ptr) }
}

/// Writes a 32-bit value to an xAPIC register at `base + offset`.
///
/// # Safety
/// `base` must be the correctly mapped xAPIC MMIO base address.
#[inline]
unsafe fn xapic_write(base: u64, offset: u32, val: u32) {
    let ptr = (base + offset as u64) as *mut u32;
    // SAFETY: Caller guarantees base is a valid xAPIC MMIO mapping.
    unsafe { core::ptr::write_volatile(ptr, val) }
}

// xAPIC ICR register offsets.
const ICR_LOW: u32 = 0x300;
const ICR_HIGH: u32 = 0x310;

// x2APIC ICR MSR.
const X2APIC_ICR_MSR: u32 = 0x0830;

// ---------------------------------------------------------------------------
// IPI Send
// ---------------------------------------------------------------------------

/// Waits for the delivery-status bit to clear (xAPIC only).
///
/// Returns `Error::Busy` after `timeout` spin iterations if the APIC is still busy.
///
/// # Safety
/// `base` must be a valid xAPIC MMIO mapping.
#[cfg(target_arch = "x86_64")]
unsafe fn wait_for_idle_xapic(base: u64, mut timeout: u32) -> Result<()> {
    // SAFETY: xapic_read is safe; caller owns the MMIO base.
    unsafe {
        loop {
            let icr_lo = xapic_read(base, ICR_LOW);
            if icr_lo & ICR_STATUS_PENDING == 0 {
                return Ok(());
            }
            if timeout == 0 {
                return Err(Error::Busy);
            }
            timeout -= 1;
            core::hint::spin_loop();
        }
    }
}

/// Sends a single IPI using xAPIC MMIO.
///
/// # Parameters
/// - `base`: xAPIC MMIO base virtual address.
/// - `dest_apic_id`: Target APIC ID (8-bit legacy).
/// - `icr_low`: Lower 32 bits of the ICR (delivery mode, vector, flags).
///
/// # Errors
/// Returns `Error::Busy` if the ICR is still pending after many spins.
///
/// # Safety
/// - `base` must be a valid mapped xAPIC region.
/// - Caller must ensure the vector and delivery mode are correct.
/// - Must be called with interrupts disabled (or from an SMP-safe context).
#[cfg(target_arch = "x86_64")]
pub unsafe fn send_ipi_xapic(base: u64, dest_apic_id: u8, icr_low: u32) -> Result<()> {
    // SAFETY: xapic_read/write are safe with a valid MMIO base.
    unsafe {
        wait_for_idle_xapic(base, 100_000)?;
        // Write ICR high first (destination), then ICR low triggers the send.
        xapic_write(base, ICR_HIGH, (dest_apic_id as u32) << 24);
        xapic_write(base, ICR_LOW, icr_low);
    }
    Ok(())
}

/// Sends a single IPI using x2APIC MSR.
///
/// The x2APIC ICR is a 64-bit MSR (0x830); a single write atomically sends the IPI.
///
/// # Parameters
/// - `dest_x2apic_id`: 32-bit x2APIC destination ID.
/// - `icr_low`: ICR[31:0] (vector, delivery mode, flags).
///
/// # Safety
/// - CPU must be in x2APIC mode.
/// - Must be called with interrupts disabled.
#[cfg(target_arch = "x86_64")]
pub unsafe fn send_ipi_x2apic(dest_x2apic_id: u32, icr_low: u32) {
    let icr = ((dest_x2apic_id as u64) << 32) | (icr_low as u64);
    // SAFETY: x2APIC MSR write; caller ensures x2APIC mode.
    unsafe {
        crate::msr::wrmsr(X2APIC_ICR_MSR, icr);
    }
}

// ---------------------------------------------------------------------------
// High-level IPI helpers
// ---------------------------------------------------------------------------

/// Sends an IPI using the active APIC mode.
///
/// # Parameters
/// - `mode`: Current APIC mode.
/// - `dest_apic_id`: 32-bit destination APIC ID.
/// - `vector`: Interrupt vector (0–255).
/// - `delivery`: Delivery mode constant (`ICR_DELIVERY_*`).
///
/// # Errors
/// Returns `Error::Busy` if xAPIC ICR is still pending.
///
/// # Safety
/// See `send_ipi_xapic` / `send_ipi_x2apic`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn send_ipi(mode: ApicMode, dest_apic_id: u32, vector: u8, delivery: u32) -> Result<()> {
    let icr_low = delivery
        | ICR_DEST_PHYSICAL
        | ICR_LEVEL_ASSERT
        | ICR_TRIGGER_EDGE
        | ICR_DEST_NO_SHORTHAND
        | (vector as u32);
    // SAFETY: Caller ensures mode, dest, and vector are valid.
    unsafe {
        match mode {
            ApicMode::XApic { base } => {
                send_ipi_xapic(base, dest_apic_id as u8, icr_low)?;
            }
            ApicMode::X2Apic => {
                send_ipi_x2apic(dest_apic_id, icr_low);
            }
        }
    }
    Ok(())
}

/// Broadcasts a fixed-vector IPI to all CPUs excluding self.
///
/// # Safety
/// See `send_ipi`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn broadcast_ipi_all_excl_self(mode: ApicMode, vector: u8) -> Result<()> {
    let icr_low = ICR_DELIVERY_FIXED
        | ICR_DEST_PHYSICAL
        | ICR_LEVEL_ASSERT
        | ICR_TRIGGER_EDGE
        | ICR_DEST_ALL_EXCL_SELF
        | (vector as u32);
    // SAFETY: Broadcast with shorthand; no destination field needed.
    unsafe {
        match mode {
            ApicMode::XApic { base } => {
                wait_for_idle_xapic(base, 100_000)?;
                xapic_write(base, ICR_LOW, icr_low);
            }
            ApicMode::X2Apic => {
                // x2APIC: destination field = 0xFFFF_FFFF for broadcast shorthand.
                send_ipi_x2apic(0xFFFF_FFFF, icr_low);
            }
        }
    }
    Ok(())
}

/// Sends an NMI IPI to `dest_apic_id`.
///
/// # Safety
/// See `send_ipi`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn send_nmi(mode: ApicMode, dest_apic_id: u32) -> Result<()> {
    // SAFETY: NMI delivery; vector field is ignored.
    unsafe { send_ipi(mode, dest_apic_id, 0, ICR_DELIVERY_NMI) }
}

/// Sends an INIT IPI to an AP to reset it.
///
/// # Safety
/// See `send_ipi`. INIT resets the target CPU; must only be used during AP bringup.
#[cfg(target_arch = "x86_64")]
pub unsafe fn send_init(mode: ApicMode, dest_apic_id: u32) -> Result<()> {
    let icr_low = ICR_DELIVERY_INIT
        | ICR_DEST_PHYSICAL
        | ICR_LEVEL_ASSERT
        | ICR_TRIGGER_LEVEL
        | ICR_DEST_NO_SHORTHAND;
    // SAFETY: INIT send; AP is expected to be halted.
    unsafe {
        match mode {
            ApicMode::XApic { base } => {
                wait_for_idle_xapic(base, 100_000)?;
                xapic_write(base, ICR_HIGH, (dest_apic_id as u32) << 24);
                xapic_write(base, ICR_LOW, icr_low);
            }
            ApicMode::X2Apic => {
                send_ipi_x2apic(dest_apic_id, icr_low);
            }
        }
    }
    Ok(())
}

/// Sends a STARTUP IPI (SIPI) to an AP.
///
/// `startup_page` is the 4 KiB physical page number where the AP trampoline resides.
///
/// # Safety
/// See `send_ipi`. Must be sent after an INIT IPI and a 10 ms delay.
#[cfg(target_arch = "x86_64")]
pub unsafe fn send_sipi(mode: ApicMode, dest_apic_id: u32, startup_page: u8) -> Result<()> {
    let icr_low = ICR_DELIVERY_STARTUP
        | ICR_DEST_PHYSICAL
        | ICR_LEVEL_ASSERT
        | ICR_TRIGGER_EDGE
        | ICR_DEST_NO_SHORTHAND
        | (startup_page as u32);
    // SAFETY: SIPI; startup_page is the 4K page where AP trampoline is located.
    unsafe {
        match mode {
            ApicMode::XApic { base } => {
                wait_for_idle_xapic(base, 100_000)?;
                xapic_write(base, ICR_HIGH, (dest_apic_id as u32) << 24);
                xapic_write(base, ICR_LOW, icr_low);
            }
            ApicMode::X2Apic => {
                send_ipi_x2apic(dest_apic_id, icr_low);
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// IPI Descriptor
// ---------------------------------------------------------------------------

/// Describes a pending IPI to be sent.
#[derive(Clone, Copy, Debug)]
pub struct IpiRequest {
    /// Destination APIC ID.
    pub dest: u32,
    /// Interrupt vector.
    pub vector: u8,
    /// Delivery mode (one of `ICR_DELIVERY_*`).
    pub delivery: u32,
}

impl IpiRequest {
    /// Creates a fixed-vector IPI request.
    pub const fn fixed(dest: u32, vector: u8) -> Self {
        Self {
            dest,
            vector,
            delivery: ICR_DELIVERY_FIXED,
        }
    }

    /// Creates an NMI IPI request.
    pub const fn nmi(dest: u32) -> Self {
        Self {
            dest,
            vector: 0,
            delivery: ICR_DELIVERY_NMI,
        }
    }

    /// Sends this IPI.
    ///
    /// # Safety
    /// See `send_ipi`.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn send(self, mode: ApicMode) -> Result<()> {
        // SAFETY: Delegating to send_ipi; caller ensures mode and vector are valid.
        unsafe { send_ipi(mode, self.dest, self.vector, self.delivery) }
    }
}
