// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! I/O APIC driver — redirection table management, IRQ routing, and
//! level/edge trigger configuration.
//!
//! # Hardware Overview
//!
//! The I/O APIC (Intel 82093AA and compatible) bridges external interrupt
//! pins from devices to Local APICs inside processors. It is accessed
//! through two MMIO registers:
//!
//! - **IOREGSEL** at `base + 0x00` — selects which indirect register to
//!   read or write.
//! - **IOWIN** at `base + 0x10` — data window for the selected register.
//!
//! ## Redirection Table
//!
//! Each of the 24 IRQ pins has a 64-bit Redirection Table Entry (RTE) split
//! across two 32-bit indirect registers (low = `0x10 + pin*2`, high =
//! `0x11 + pin*2`). The RTE encodes:
//!
//! | Bits  | Field            |
//! |-------|------------------|
//! | 63:56 | Destination      |
//! | 16    | Mask (1=masked)  |
//! | 15    | Trigger mode     |
//! | 13    | Pin polarity     |
//! | 11    | Destination mode |
//! | 10:8  | Delivery mode    |
//! | 7:0   | Vector           |
//!
//! ## Multi-APIC Systems
//!
//! Servers may have multiple I/O APICs. [`IoapicManager`] tracks up to
//! [`MAX_IOAPICS`] instances and provides a unified GSI (Global System
//! Interrupt) routing interface.
//!
//! Reference: Intel 82093AA I/O APIC Datasheet; Intel SDM Vol 3A §10.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// IOREGSEL register offset.
const IOREGSEL: u64 = 0x00;
/// IOWIN register offset.
const IOWIN: u64 = 0x10;

/// Indirect register index: I/O APIC ID register.
const REG_IOAPICID: u32 = 0x00;
/// Indirect register index: I/O APIC version register.
const REG_IOAPICVER: u32 = 0x01;
/// Indirect register index: I/O APIC arbitration register.
const REG_IOAPICARB: u32 = 0x02;

/// Redirection entry low-half base index.
const RTE_BASE: u32 = 0x10;

/// Maximum IRQ pins per I/O APIC.
pub const MAX_PINS: usize = 24;

/// Maximum number of I/O APICs in the system.
pub const MAX_IOAPICS: usize = 8;

/// Default I/O APIC MMIO base address (single-APIC systems).
pub const IOAPIC_DEFAULT_BASE: u64 = 0xFEC0_0000;

// ---------------------------------------------------------------------------
// RTE bit masks / shifts
// ---------------------------------------------------------------------------

const RTE_VECTOR_MASK: u64 = 0xFF;
const RTE_DELIVERY_SHIFT: u32 = 8;
const RTE_DELIVERY_MASK: u64 = 0x7 << RTE_DELIVERY_SHIFT;
const RTE_DEST_MODE_BIT: u64 = 1 << 11;
const RTE_POLARITY_BIT: u64 = 1 << 13;
const RTE_TRIGGER_BIT: u64 = 1 << 15;
const RTE_MASK_BIT: u64 = 1 << 16;
const RTE_DEST_SHIFT: u32 = 56;

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

/// Read a 32-bit MMIO register.
#[inline]
fn mmio_read32(addr: u64) -> u32 {
    // SAFETY: `addr` is a valid volatile MMIO address within the I/O APIC
    // register window, guaranteed by the IoApicDriver constructor callers.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Write a 32-bit MMIO register.
#[inline]
fn mmio_write32(addr: u64, val: u32) {
    // SAFETY: `addr` is a valid volatile MMIO address within the I/O APIC
    // register window, guaranteed by the IoApicDriver constructor callers.
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
}

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

/// Interrupt delivery mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoapicDelivery {
    /// Deliver to the specified vector on the destination APIC.
    Fixed,
    /// Deliver to the lowest-priority APIC among the destination set.
    LowestPriority,
    /// System Management Interrupt (edge-triggered only).
    Smi,
    /// Non-Maskable Interrupt.
    Nmi,
    /// INIT signal.
    Init,
    /// External interrupt (routes through legacy 8259).
    ExtInt,
}

impl IoapicDelivery {
    fn to_bits(self) -> u64 {
        let v = match self {
            Self::Fixed => 0b000u64,
            Self::LowestPriority => 0b001,
            Self::Smi => 0b010,
            Self::Nmi => 0b100,
            Self::Init => 0b101,
            Self::ExtInt => 0b111,
        };
        v << RTE_DELIVERY_SHIFT
    }

    fn from_bits(raw: u64) -> Self {
        match (raw & RTE_DELIVERY_MASK) >> RTE_DELIVERY_SHIFT {
            0b001 => Self::LowestPriority,
            0b010 => Self::Smi,
            0b100 => Self::Nmi,
            0b101 => Self::Init,
            0b111 => Self::ExtInt,
            _ => Self::Fixed,
        }
    }
}

/// Interrupt pin polarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IoapicPolarity {
    /// Active high (ISA default).
    #[default]
    High,
    /// Active low (PCI default).
    Low,
}

/// Interrupt trigger mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IoapicTrigger {
    /// Edge-triggered (ISA default).
    #[default]
    Edge,
    /// Level-triggered (PCI default).
    Level,
}

/// Destination mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IoapicDestMode {
    /// Physical — destination field is a Local APIC ID.
    #[default]
    Physical,
    /// Logical — destination field is a logical APIC cluster/bitmask.
    Logical,
}

// ---------------------------------------------------------------------------
// Redirection Table Entry
// ---------------------------------------------------------------------------

/// A decoded I/O APIC Redirection Table Entry.
#[derive(Debug, Clone, Copy)]
pub struct IoapicRte {
    /// Interrupt vector (16–255; 0–15 are reserved by architecture).
    pub vector: u8,
    /// Delivery mode.
    pub delivery: IoapicDelivery,
    /// Destination mode.
    pub dest_mode: IoapicDestMode,
    /// Pin polarity.
    pub polarity: IoapicPolarity,
    /// Trigger mode.
    pub trigger: IoapicTrigger,
    /// Whether the interrupt is masked (suppressed).
    pub masked: bool,
    /// Destination APIC ID or logical cluster.
    pub destination: u8,
}

impl IoapicRte {
    /// Create a masked RTE pointing at `vector`.
    pub const fn masked(vector: u8) -> Self {
        Self {
            vector,
            delivery: IoapicDelivery::Fixed,
            dest_mode: IoapicDestMode::Physical,
            polarity: IoapicPolarity::High,
            trigger: IoapicTrigger::Edge,
            masked: true,
            destination: 0,
        }
    }

    /// Encode the RTE as a raw 64-bit value.
    pub fn to_raw(&self) -> u64 {
        let mut raw = self.vector as u64 & RTE_VECTOR_MASK;
        raw |= self.delivery.to_bits();
        if self.dest_mode == IoapicDestMode::Logical {
            raw |= RTE_DEST_MODE_BIT;
        }
        if self.polarity == IoapicPolarity::Low {
            raw |= RTE_POLARITY_BIT;
        }
        if self.trigger == IoapicTrigger::Level {
            raw |= RTE_TRIGGER_BIT;
        }
        if self.masked {
            raw |= RTE_MASK_BIT;
        }
        raw |= (self.destination as u64) << RTE_DEST_SHIFT;
        raw
    }

    /// Decode an RTE from its raw 64-bit register value.
    pub fn from_raw(raw: u64) -> Self {
        Self {
            vector: (raw & RTE_VECTOR_MASK) as u8,
            delivery: IoapicDelivery::from_bits(raw),
            dest_mode: if raw & RTE_DEST_MODE_BIT != 0 {
                IoapicDestMode::Logical
            } else {
                IoapicDestMode::Physical
            },
            polarity: if raw & RTE_POLARITY_BIT != 0 {
                IoapicPolarity::Low
            } else {
                IoapicPolarity::High
            },
            trigger: if raw & RTE_TRIGGER_BIT != 0 {
                IoapicTrigger::Level
            } else {
                IoapicTrigger::Edge
            },
            masked: raw & RTE_MASK_BIT != 0,
            destination: (raw >> RTE_DEST_SHIFT) as u8,
        }
    }
}

// ---------------------------------------------------------------------------
// IoApicDriver — single I/O APIC
// ---------------------------------------------------------------------------

/// Hardware capabilities read from the version register.
#[derive(Debug, Clone, Copy, Default)]
pub struct IoapicVersion {
    /// I/O APIC hardware version number.
    pub version: u8,
    /// Maximum redirection entry index (entry count = max + 1).
    pub max_rte: u8,
}

/// Driver for a single I/O APIC chip.
///
/// Call `init()` after construction to read hardware capabilities and
/// mask all pins as a safety measure.
pub struct IoApicDriver {
    /// MMIO base address.
    base: u64,
    /// Global System Interrupt base (lowest GSI served by this APIC).
    gsi_base: u32,
    /// Hardware version information.
    version: IoapicVersion,
    /// Number of IRQ pins on this chip.
    pin_count: u8,
    /// Whether `init()` has been called successfully.
    initialized: bool,
}

impl IoApicDriver {
    /// Create a new driver instance.
    ///
    /// The device is not accessible until [`init`](Self::init) is called.
    pub const fn new(base: u64, gsi_base: u32) -> Self {
        Self {
            base,
            gsi_base,
            version: IoapicVersion {
                version: 0,
                max_rte: 0,
            },
            pin_count: 0,
            initialized: false,
        }
    }

    /// Initialize the I/O APIC.
    ///
    /// Reads hardware version registers and masks all redirection entries.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if `base == 0`.
    pub fn init(&mut self) -> Result<()> {
        if self.base == 0 {
            return Err(Error::InvalidArgument);
        }

        let ver_raw = self.read_reg(REG_IOAPICVER);
        self.version.version = (ver_raw & 0xFF) as u8;
        self.version.max_rte = ((ver_raw >> 16) & 0xFF) as u8;
        self.pin_count = self.version.max_rte.saturating_add(1).min(MAX_PINS as u8);

        // Mask all pins.
        for pin in 0..self.pin_count {
            let rte = IoapicRte::masked(0);
            self.write_rte_raw(pin, rte.to_raw())?;
        }

        self.initialized = true;
        Ok(())
    }

    // -- Indirect register access ------------------------------------------

    /// Read an indirect register.
    fn read_reg(&self, reg: u32) -> u32 {
        mmio_write32(self.base + IOREGSEL, reg);
        mmio_read32(self.base + IOWIN)
    }

    /// Write an indirect register.
    fn write_reg(&self, reg: u32, val: u32) {
        mmio_write32(self.base + IOREGSEL, reg);
        mmio_write32(self.base + IOWIN, val);
    }

    // -- Redirection table -------------------------------------------------

    /// Low RTE register index for a given pin.
    const fn rte_low(pin: u8) -> u32 {
        RTE_BASE + (pin as u32) * 2
    }

    /// High RTE register index for a given pin.
    const fn rte_high(pin: u8) -> u32 {
        RTE_BASE + (pin as u32) * 2 + 1
    }

    fn write_rte_raw(&self, pin: u8, raw: u64) -> Result<()> {
        if pin as usize >= MAX_PINS {
            return Err(Error::InvalidArgument);
        }
        // Write high word first (destination), then low (may unmask).
        self.write_reg(Self::rte_high(pin), (raw >> 32) as u32);
        self.write_reg(Self::rte_low(pin), raw as u32);
        Ok(())
    }

    fn read_rte_raw(&self, pin: u8) -> Result<u64> {
        if pin as usize >= MAX_PINS {
            return Err(Error::InvalidArgument);
        }
        let lo = self.read_reg(Self::rte_low(pin)) as u64;
        let hi = self.read_reg(Self::rte_high(pin)) as u64;
        Ok(lo | (hi << 32))
    }

    // -- Public API --------------------------------------------------------

    /// Read the RTE for `pin`.
    ///
    /// # Errors
    ///
    /// Returns `IoError` if not initialized or `InvalidArgument` if `pin`
    /// is out of range.
    pub fn read_rte(&self, pin: u8) -> Result<IoapicRte> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        if pin >= self.pin_count {
            return Err(Error::InvalidArgument);
        }
        let raw = self.read_rte_raw(pin)?;
        Ok(IoapicRte::from_raw(raw))
    }

    /// Write an RTE for `pin`.
    ///
    /// # Errors
    ///
    /// Returns `IoError` if not initialized or `InvalidArgument` if `pin`
    /// is out of range.
    pub fn write_rte(&self, pin: u8, rte: &IoapicRte) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        if pin >= self.pin_count {
            return Err(Error::InvalidArgument);
        }
        self.write_rte_raw(pin, rte.to_raw())
    }

    /// Mask (suppress) interrupts on `pin`.
    pub fn mask_pin(&self, pin: u8) -> Result<()> {
        let mut rte = self.read_rte(pin)?;
        rte.masked = true;
        self.write_rte(pin, &rte)
    }

    /// Unmask (enable) interrupts on `pin`.
    pub fn unmask_pin(&self, pin: u8) -> Result<()> {
        let mut rte = self.read_rte(pin)?;
        rte.masked = false;
        self.write_rte(pin, &rte)
    }

    /// Configure and enable a pin with the given routing parameters.
    ///
    /// `vector` must be in the range 16–255 (architectural restriction).
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if `vector < 16` or `pin` is out of range.
    pub fn route_pin(
        &self,
        pin: u8,
        vector: u8,
        dest: u8,
        delivery: IoapicDelivery,
        trigger: IoapicTrigger,
        polarity: IoapicPolarity,
    ) -> Result<()> {
        if vector < 16 {
            return Err(Error::InvalidArgument);
        }
        let rte = IoapicRte {
            vector,
            delivery,
            dest_mode: IoapicDestMode::Physical,
            polarity,
            trigger,
            masked: false,
            destination: dest,
        };
        self.write_rte(pin, &rte)
    }

    /// Return the GSI base served by this I/O APIC.
    pub fn gsi_base(&self) -> u32 {
        self.gsi_base
    }

    /// Return the highest GSI served (exclusive).
    pub fn gsi_end(&self) -> u32 {
        self.gsi_base + self.pin_count as u32
    }

    /// Return the number of IRQ pins.
    pub fn pin_count(&self) -> u8 {
        self.pin_count
    }

    /// Return hardware version information.
    pub fn version(&self) -> IoapicVersion {
        self.version
    }

    /// Return `true` if the driver has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Return the MMIO base address.
    pub fn base_addr(&self) -> u64 {
        self.base
    }

    /// Set the I/O APIC hardware ID register.
    pub fn set_id(&self, id: u8) {
        self.write_reg(REG_IOAPICID, (id as u32 & 0xF) << 24);
    }

    /// Read the I/O APIC hardware ID.
    pub fn read_id(&self) -> u8 {
        ((self.read_reg(REG_IOAPICID) >> 24) & 0xF) as u8
    }

    /// Read the arbitration ID.
    pub fn read_arb_id(&self) -> u8 {
        ((self.read_reg(REG_IOAPICARB) >> 24) & 0xF) as u8
    }
}

// ---------------------------------------------------------------------------
// IoapicManager — multi-I/O-APIC system
// ---------------------------------------------------------------------------

/// Registration record for one I/O APIC within the system manager.
#[derive(Debug, Clone, Copy)]
struct IoapicSlot {
    base: u64,
    gsi_base: u32,
    pin_count: u8,
    active: bool,
}

impl IoapicSlot {
    const EMPTY: Self = Self {
        base: 0,
        gsi_base: 0,
        pin_count: 0,
        active: false,
    };
}

/// System-level manager for multiple I/O APICs.
///
/// Converts Global System Interrupts (GSIs) to `(slot, pin)` pairs and
/// tracks which I/O APIC covers each GSI range.
pub struct IoapicManager {
    slots: [IoapicSlot; MAX_IOAPICS],
    count: usize,
}

impl IoapicManager {
    /// Create an empty manager.
    pub const fn new() -> Self {
        Self {
            slots: [IoapicSlot::EMPTY; MAX_IOAPICS],
            count: 0,
        }
    }

    /// Register an I/O APIC.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `base == 0`.
    /// - `AlreadyExists` if an I/O APIC with the same `base` is already registered.
    /// - `OutOfMemory` if the table is full.
    pub fn register(&mut self, base: u64, gsi_base: u32, pin_count: u8) -> Result<usize> {
        if base == 0 {
            return Err(Error::InvalidArgument);
        }
        for slot in &self.slots[..self.count] {
            if slot.active && slot.base == base {
                return Err(Error::AlreadyExists);
            }
        }
        if self.count >= MAX_IOAPICS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.slots[idx] = IoapicSlot {
            base,
            gsi_base,
            pin_count,
            active: true,
        };
        self.count += 1;
        Ok(idx)
    }

    /// Translate a GSI to `(slot_index, pin)`.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if no registered I/O APIC covers `gsi`.
    pub fn gsi_to_pin(&self, gsi: u32) -> Result<(usize, u8)> {
        for (i, slot) in self.slots[..self.count].iter().enumerate() {
            if !slot.active {
                continue;
            }
            let end = slot.gsi_base + slot.pin_count as u32;
            if gsi >= slot.gsi_base && gsi < end {
                return Ok((i, (gsi - slot.gsi_base) as u8));
            }
        }
        Err(Error::NotFound)
    }

    /// Return the base address of the I/O APIC at `index`.
    pub fn base_of(&self, index: usize) -> Option<u64> {
        if index < self.count && self.slots[index].active {
            Some(self.slots[index].base)
        } else {
            None
        }
    }

    /// Return the number of registered I/O APICs.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Return `true` if no I/O APICs are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for IoapicManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rte_encode_decode_roundtrip() {
        let rte = IoapicRte {
            vector: 0x30,
            delivery: IoapicDelivery::Fixed,
            dest_mode: IoapicDestMode::Physical,
            polarity: IoapicPolarity::Low,
            trigger: IoapicTrigger::Level,
            masked: false,
            destination: 0x02,
        };
        let raw = rte.to_raw();
        let decoded = IoapicRte::from_raw(raw);
        assert_eq!(decoded.vector, rte.vector);
        assert_eq!(decoded.polarity, rte.polarity);
        assert_eq!(decoded.trigger, rte.trigger);
        assert!(!decoded.masked);
        assert_eq!(decoded.destination, rte.destination);
    }

    #[test]
    fn rte_masked_default() {
        let rte = IoapicRte::masked(0x40);
        assert!(rte.masked);
        assert_eq!(rte.vector, 0x40);
        let raw = rte.to_raw();
        assert!(raw & RTE_MASK_BIT != 0);
    }

    #[test]
    fn manager_register_and_lookup() {
        let mut mgr = IoapicManager::new();
        mgr.register(0xFEC0_0000, 0, 24).unwrap();
        mgr.register(0xFEC0_1000, 24, 8).unwrap();
        assert_eq!(mgr.count(), 2);

        let (slot, pin) = mgr.gsi_to_pin(5).unwrap();
        assert_eq!(slot, 0);
        assert_eq!(pin, 5);

        let (slot2, pin2) = mgr.gsi_to_pin(25).unwrap();
        assert_eq!(slot2, 1);
        assert_eq!(pin2, 1);
    }

    #[test]
    fn manager_gsi_not_found() {
        let mut mgr = IoapicManager::new();
        mgr.register(0xFEC0_0000, 0, 24).unwrap();
        assert!(mgr.gsi_to_pin(100).is_err());
    }

    #[test]
    fn manager_duplicate_rejected() {
        let mut mgr = IoapicManager::new();
        mgr.register(0xFEC0_0000, 0, 24).unwrap();
        assert_eq!(
            mgr.register(0xFEC0_0000, 24, 8).unwrap_err(),
            Error::AlreadyExists
        );
    }

    #[test]
    fn delivery_mode_roundtrip() {
        let modes = [
            IoapicDelivery::Fixed,
            IoapicDelivery::LowestPriority,
            IoapicDelivery::Smi,
            IoapicDelivery::Nmi,
            IoapicDelivery::Init,
            IoapicDelivery::ExtInt,
        ];
        for mode in modes {
            let bits = mode.to_bits();
            let decoded = IoapicDelivery::from_bits(bits);
            assert_eq!(
                core::mem::discriminant(&decoded),
                core::mem::discriminant(&mode)
            );
        }
    }
}
