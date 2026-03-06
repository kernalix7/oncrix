// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Interrupt remapping (Intel VT-d interrupt remapping).
//!
//! Provides the Interrupt Remapping Table Entry (IRTE) type and a
//! fixed-size `IrTable` that allocates and manages IRTE slots.
//! When interrupt remapping is enabled through the IOMMU, device
//! MSI/MSI-X messages contain an index into this table rather than
//! targeting a CPU APIC directly.
//!
//! # References
//!
//! Intel VT-d Specification, Chapter 5 — Interrupt Remapping.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of IRTE slots in the table.
pub const IR_TABLE_SIZE: usize = 256;

/// IRTE bit: Present — entry is valid and active.
const IRTE_PRESENT: u64 = 1 << 0;

/// IRTE bit: Destination Mode — 0 = physical, 1 = logical.
const IRTE_DEST_LOGICAL: u64 = 1 << 2;

/// IRTE bit: Redirection Hint — set to allow redirection.
const IRTE_RH: u64 = 1 << 3;

/// IRTE bit: Trigger Mode — 0 = edge, 1 = level.
const IRTE_TRIGGER_LEVEL: u64 = 1 << 4;

/// IRTE bit: Delivery Status (read-only in hardware; writable here).
const IRTE_DELIVERY_STATUS: u64 = 1 << 8;

/// IRTE delivery mode shift (bits 7:5).
const IRTE_DELIV_MODE_SHIFT: u32 = 5;

/// IRTE delivery mode mask (3 bits).
const IRTE_DELIV_MODE_MASK: u64 = 0x7 << 5;

/// IRTE vector field shift (bits 23:16 in the high 32 bits, overall bit 48).
const IRTE_VECTOR_SHIFT: u32 = 16;

/// IRTE destination APIC ID shift (bits 31:24 in high 32 bits, bit 56).
const IRTE_DEST_SHIFT: u32 = 40;

/// Posted interrupt descriptor address shift (bit 9 and above in low qword).
const IRTE_PDA_LOW_SHIFT: u32 = 6;

// ── Delivery modes ───────────────────────────────────────────────────────────

/// Interrupt delivery mode field values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeliveryMode {
    /// Fixed delivery to specified APIC(s).
    Fixed = 0b000,
    /// Lowest-priority delivery.
    LowestPriority = 0b001,
    /// SMI delivery.
    Smi = 0b010,
    /// NMI delivery.
    Nmi = 0b100,
    /// INIT delivery.
    Init = 0b101,
    /// External interrupt delivery.
    ExtInt = 0b111,
}

// ── IrteEntry ────────────────────────────────────────────────────────────────

/// Interrupt Remapping Table Entry.
///
/// Each IRTE is 128 bits (two 64-bit words). For simplicity we
/// encode all fields into a single 128-bit pair: `low` and `high`.
///
/// Layout (simplified — see VT-d spec for full layout):
/// ```text
/// low[0]     = Present
/// low[2]     = DestMode (0=phys, 1=logical)
/// low[3]     = RH
/// low[4]     = Trigger Mode (0=edge, 1=level)
/// low[7:5]   = Delivery Mode
/// low[23:16] = Vector
/// low[63:32] = Destination APIC ID (for physical mode bits 39:32)
/// high[63:32]= Upper destination / reserved
/// ```
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct IrteEntry {
    /// Low 64-bit word.
    pub low: u64,
    /// High 64-bit word.
    pub high: u64,
}

impl IrteEntry {
    /// Create a zeroed (not-present) IRTE.
    pub const fn new() -> Self {
        Self { low: 0, high: 0 }
    }

    /// Build an IRTE for a fixed-delivery interrupt.
    ///
    /// - `dest_apic_id`: destination local APIC ID.
    /// - `vector`: interrupt vector (0x10–0xFE).
    /// - `level`: `true` for level-triggered, `false` for edge.
    /// - `mode`: delivery mode.
    pub fn build(dest_apic_id: u32, vector: u8, level: bool, mode: DeliveryMode) -> Self {
        let mut low: u64 = IRTE_PRESENT;
        if level {
            low |= IRTE_TRIGGER_LEVEL;
        }
        low &= !IRTE_DELIV_MODE_MASK;
        low |= (mode as u64) << IRTE_DELIV_MODE_SHIFT;
        low |= (vector as u64) << IRTE_VECTOR_SHIFT;
        low |= (dest_apic_id as u64) << IRTE_DEST_SHIFT;

        Self { low, high: 0 }
    }

    /// Return whether this IRTE is present (valid).
    pub fn is_present(&self) -> bool {
        self.low & IRTE_PRESENT != 0
    }

    /// Return the interrupt vector.
    pub fn vector(&self) -> u8 {
        ((self.low >> IRTE_VECTOR_SHIFT) & 0xFF) as u8
    }

    /// Return the destination APIC ID.
    pub fn dest_apic_id(&self) -> u32 {
        ((self.low >> IRTE_DEST_SHIFT) & 0xFF_FFFF) as u32
    }

    /// Return the delivery mode.
    pub fn delivery_mode(&self) -> u8 {
        ((self.low >> IRTE_DELIV_MODE_SHIFT) & 0x7) as u8
    }

    /// Return whether the trigger is level.
    pub fn is_level_triggered(&self) -> bool {
        self.low & IRTE_TRIGGER_LEVEL != 0
    }

    /// Mark this IRTE as not present (invalidate).
    pub fn invalidate(&mut self) {
        self.low &= !IRTE_PRESENT;
        self.high = 0;
    }

    /// Set up a Posted Interrupt descriptor address.
    ///
    /// `pda_phys` must be 64-byte aligned. Sets the PDA low field
    /// and marks the entry as using posted-interrupt delivery.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `pda_phys` is not
    /// 64-byte aligned.
    pub fn set_posted_interrupt(&mut self, pda_phys: u64) -> Result<()> {
        if pda_phys & 0x3F != 0 {
            return Err(Error::InvalidArgument);
        }
        // Encode PDA in high word (bits 63:6 of PDA → IRTE high[63:6]).
        self.high = pda_phys >> IRTE_PDA_LOW_SHIFT;
        Ok(())
    }
}

// ── IrTable ──────────────────────────────────────────────────────────────────

/// Fixed-size Interrupt Remapping Table.
///
/// Manages `IR_TABLE_SIZE` IRTE slots and tracks which are in use.
pub struct IrTable {
    /// The actual IRTE array.
    entries: [IrteEntry; IR_TABLE_SIZE],
    /// Bitmap of allocated slots (bit N = slot N in use).
    allocated: [u64; IR_TABLE_SIZE / 64],
    /// Number of allocated entries.
    count: usize,
    /// Whether interrupt remapping is globally enabled.
    enabled: bool,
}

impl IrTable {
    /// Create an empty interrupt remapping table.
    pub const fn new() -> Self {
        Self {
            entries: [const { IrteEntry::new() }; IR_TABLE_SIZE],
            allocated: [0u64; IR_TABLE_SIZE / 64],
            count: 0,
            enabled: false,
        }
    }

    /// Allocate and initialise an IRTE slot.
    ///
    /// Returns the slot index on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if no free slots remain.
    pub fn alloc_irte(
        &mut self,
        dest_apic_id: u32,
        vector: u8,
        level: bool,
        mode: DeliveryMode,
    ) -> Result<usize> {
        let slot = self.find_free_slot().ok_or(Error::OutOfMemory)?;
        self.entries[slot] = IrteEntry::build(dest_apic_id, vector, level, mode);
        self.set_allocated(slot);
        self.count += 1;
        Ok(slot)
    }

    /// Free an IRTE slot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range
    /// or not currently allocated.
    pub fn free_irte(&mut self, index: usize) -> Result<()> {
        if index >= IR_TABLE_SIZE {
            return Err(Error::InvalidArgument);
        }
        if !self.is_allocated(index) {
            return Err(Error::InvalidArgument);
        }
        self.entries[index].invalidate();
        self.clear_allocated(index);
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Update an existing IRTE in-place.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range
    /// or not allocated.
    pub fn update_irte(
        &mut self,
        index: usize,
        dest_apic_id: u32,
        vector: u8,
        level: bool,
        mode: DeliveryMode,
    ) -> Result<()> {
        if index >= IR_TABLE_SIZE || !self.is_allocated(index) {
            return Err(Error::InvalidArgument);
        }
        self.entries[index] = IrteEntry::build(dest_apic_id, vector, level, mode);
        Ok(())
    }

    /// Return an immutable reference to an IRTE entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range.
    pub fn get(&self, index: usize) -> Result<&IrteEntry> {
        if index >= IR_TABLE_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.entries[index])
    }

    /// Return the base address and size of the entry array.
    ///
    /// Suitable for programming into an IOMMU register.
    pub fn table_base(&self) -> (*const IrteEntry, usize) {
        (self.entries.as_ptr(), IR_TABLE_SIZE)
    }

    /// Return the number of allocated entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Mark interrupt remapping as enabled.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Return whether interrupt remapping is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    // ── Bitmap helpers ───────────────────────────────────────────────────────

    fn find_free_slot(&self) -> Option<usize> {
        for word_idx in 0..(IR_TABLE_SIZE / 64) {
            let word = self.allocated[word_idx];
            if word != u64::MAX {
                let bit = word.trailing_ones() as usize;
                return Some(word_idx * 64 + bit);
            }
        }
        None
    }

    fn is_allocated(&self, index: usize) -> bool {
        let word = index / 64;
        let bit = index % 64;
        self.allocated[word] & (1u64 << bit) != 0
    }

    fn set_allocated(&mut self, index: usize) {
        let word = index / 64;
        let bit = index % 64;
        self.allocated[word] |= 1u64 << bit;
    }

    fn clear_allocated(&mut self, index: usize) {
        let word = index / 64;
        let bit = index % 64;
        self.allocated[word] &= !(1u64 << bit);
    }
}

impl Default for IrTable {
    fn default() -> Self {
        Self::new()
    }
}

// ── IR capability detection ───────────────────────────────────────────────────

/// Check whether interrupt remapping is supported by reading the IOMMU
/// Extended Capability register bit 3 (IR support).
///
/// `ecap_val` should be the 64-bit value of the IOMMU ECAP register.
pub fn ir_capability_supported(ecap_val: u64) -> bool {
    // VT-d ECAP register: bit 3 = IR (Interrupt Remapping support).
    ecap_val & (1 << 3) != 0
}

/// Check whether posted-interrupt delivery is supported.
///
/// `ecap_val` is the IOMMU Extended Capability register value.
/// Bit 59 = Posted Interrupt Support.
pub fn posted_interrupt_supported(ecap_val: u64) -> bool {
    ecap_val & (1 << 59) != 0
}
