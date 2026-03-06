// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! I/O APIC (Advanced Programmable Interrupt Controller) driver.
//!
//! The I/O APIC routes external device interrupts (e.g., keyboard, disk,
//! network) to Local APICs on individual CPUs. Each I/O APIC provides a
//! set of redirection table entries (RTEs) that map device IRQ pins to
//! interrupt vectors, delivery modes, and destination processors.
//!
//! # Architecture
//!
//! The I/O APIC is accessed through two memory-mapped registers:
//! - **IOREGSEL** (offset 0x00) — selects the indirect register to access.
//! - **IOWIN** (offset 0x10) — data window for the selected register.
//!
//! Redirection entries are 64 bits wide and split across two 32-bit
//! indirect registers (low and high halves). Each I/O APIC can support
//! up to 24 redirection entries (IRQ pins).
//!
//! ```text
//! ┌──────────┐   IRQ pin   ┌──────────┐   interrupt bus   ┌────────────┐
//! │  Device   │────────────>│ I/O APIC │─────────────────>│ Local APIC │
//! └──────────┘             └──────────┘                   └────────────┘
//! ```
//!
//! # Multiple I/O APICs
//!
//! Systems may have multiple I/O APICs (up to 8 tracked here), each with
//! a different base address and global system interrupt (GSI) base. The
//! [`IoApicSystem`] aggregates all I/O APICs and provides a unified
//! GSI-based routing interface.
//!
//! Reference: Intel 82093AA I/O APIC Datasheet; Intel SDM Volume 3A,
//! Chapter 10.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// IOREGSEL — register select offset from I/O APIC base.
const IOREGSEL_OFFSET: u64 = 0x00;

/// IOWIN — data window offset from I/O APIC base.
const IOWIN_OFFSET: u64 = 0x10;

/// Indirect register index: I/O APIC ID.
const REG_ID: u32 = 0x00;

/// Indirect register index: I/O APIC Version.
const REG_VERSION: u32 = 0x01;

/// Indirect register index: I/O APIC Arbitration ID.
const REG_ARB_ID: u32 = 0x02;

/// Maximum number of redirection entries per I/O APIC.
const MAX_REDIR_ENTRIES: usize = 24;

/// Maximum number of I/O APICs in the system.
const MAX_IOAPICS: usize = 8;

/// Default I/O APIC MMIO base address.
pub const DEFAULT_IOAPIC_BASE: u64 = 0xFEC0_0000;

// ---------------------------------------------------------------------------
// Redirection entry bit fields
// ---------------------------------------------------------------------------

/// Bit 16: Interrupt Mask (1 = masked, 0 = unmasked).
const REDIR_MASK: u64 = 1 << 16;

/// Bit 15: Trigger Mode (0 = edge, 1 = level).
const REDIR_TRIGGER_LEVEL: u64 = 1 << 15;

/// Bit 14: Remote IRR (read-only, level-triggered only).
const _REDIR_REMOTE_IRR: u64 = 1 << 14;

/// Bit 13: Interrupt Input Pin Polarity (0 = active high, 1 = active low).
const REDIR_POLARITY_LOW: u64 = 1 << 13;

/// Bit 11: Destination Mode (0 = physical, 1 = logical).
const REDIR_DEST_LOGICAL: u64 = 1 << 11;

/// Bits 10:8: Delivery Mode field shift.
const REDIR_DELIVERY_SHIFT: u32 = 8;

/// Bits 7:0: Interrupt Vector mask.
const REDIR_VECTOR_MASK: u64 = 0xFF;

/// Bits 63:56: Destination field (APIC ID for physical mode).
const REDIR_DEST_SHIFT: u32 = 56;

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

/// Read a 32-bit value from an MMIO address.
fn read_mmio32(addr: u64) -> u32 {
    // SAFETY: The caller guarantees that `addr` is a valid, mapped MMIO
    // address aligned to 4 bytes within the I/O APIC register space.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Write a 32-bit value to an MMIO address.
fn write_mmio32(addr: u64, val: u32) {
    // SAFETY: The caller guarantees that `addr` is a valid, mapped MMIO
    // address aligned to 4 bytes within the I/O APIC register space.
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
}

// ---------------------------------------------------------------------------
// DeliveryMode
// ---------------------------------------------------------------------------

/// I/O APIC interrupt delivery mode.
///
/// Determines how the interrupt is delivered to the destination
/// Local APIC(s).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryMode {
    /// Deliver to the vector specified in the redirection entry.
    Fixed,
    /// Deliver to the lowest-priority processor accepting interrupts.
    LowestPriority,
    /// System Management Interrupt (edge-triggered only).
    Smi,
    /// Non-Maskable Interrupt (vector field ignored).
    Nmi,
    /// INIT signal (vector field ignored).
    Init,
    /// External interrupt (ExtINT), routed through the 8259 PIC.
    ExtInt,
}

impl DeliveryMode {
    /// Encode the delivery mode as the 3-bit field value.
    const fn to_bits(self) -> u64 {
        let val = match self {
            Self::Fixed => 0b000,
            Self::LowestPriority => 0b001,
            Self::Smi => 0b010,
            Self::Nmi => 0b100,
            Self::Init => 0b101,
            Self::ExtInt => 0b111,
        };
        val << REDIR_DELIVERY_SHIFT
    }

    /// Decode the delivery mode from a raw redirection entry value.
    fn from_bits(raw: u64) -> Self {
        match (raw >> REDIR_DELIVERY_SHIFT) & 0x7 {
            0b000 => Self::Fixed,
            0b001 => Self::LowestPriority,
            0b010 => Self::Smi,
            0b100 => Self::Nmi,
            0b101 => Self::Init,
            0b111 => Self::ExtInt,
            _ => Self::Fixed,
        }
    }
}

// ---------------------------------------------------------------------------
// PinPolarity
// ---------------------------------------------------------------------------

/// Interrupt input pin polarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PinPolarity {
    /// Active high (default for ISA interrupts).
    #[default]
    ActiveHigh,
    /// Active low (common for PCI interrupts).
    ActiveLow,
}

// ---------------------------------------------------------------------------
// TriggerMode
// ---------------------------------------------------------------------------

/// Interrupt trigger mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TriggerMode {
    /// Edge-triggered (default for ISA interrupts).
    #[default]
    Edge,
    /// Level-triggered (common for PCI interrupts).
    Level,
}

// ---------------------------------------------------------------------------
// DestinationMode
// ---------------------------------------------------------------------------

/// Interrupt destination mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DestinationMode {
    /// Physical — destination field is an APIC ID.
    #[default]
    Physical,
    /// Logical — destination field is a logical APIC bitmask.
    Logical,
}

// ---------------------------------------------------------------------------
// RedirectionEntry
// ---------------------------------------------------------------------------

/// A parsed I/O APIC redirection table entry.
///
/// Each entry maps a single IRQ pin to a specific interrupt vector,
/// delivery mode, destination CPU, trigger mode, and polarity.
#[derive(Debug, Clone, Copy)]
pub struct RedirectionEntry {
    /// Interrupt vector number (0-255).
    pub vector: u8,
    /// How the interrupt is delivered.
    pub delivery_mode: DeliveryMode,
    /// Physical or logical destination.
    pub destination_mode: DestinationMode,
    /// Pin polarity.
    pub polarity: PinPolarity,
    /// Edge or level triggered.
    pub trigger_mode: TriggerMode,
    /// Whether the interrupt is masked (suppressed).
    pub masked: bool,
    /// Destination APIC ID (physical) or logical destination.
    pub destination: u8,
}

impl RedirectionEntry {
    /// Create a new masked redirection entry for the given vector.
    pub const fn new_masked(vector: u8) -> Self {
        Self {
            vector,
            delivery_mode: DeliveryMode::Fixed,
            destination_mode: DestinationMode::Physical,
            polarity: PinPolarity::ActiveHigh,
            trigger_mode: TriggerMode::Edge,
            masked: true,
            destination: 0,
        }
    }

    /// Encode this entry into the raw 64-bit register value.
    pub fn to_raw(&self) -> u64 {
        let mut raw: u64 = self.vector as u64 & REDIR_VECTOR_MASK;

        raw |= self.delivery_mode.to_bits();

        if self.destination_mode == DestinationMode::Logical {
            raw |= REDIR_DEST_LOGICAL;
        }

        if self.polarity == PinPolarity::ActiveLow {
            raw |= REDIR_POLARITY_LOW;
        }

        if self.trigger_mode == TriggerMode::Level {
            raw |= REDIR_TRIGGER_LEVEL;
        }

        if self.masked {
            raw |= REDIR_MASK;
        }

        raw |= (self.destination as u64) << REDIR_DEST_SHIFT;

        raw
    }

    /// Decode a redirection entry from its raw 64-bit register value.
    pub fn from_raw(raw: u64) -> Self {
        Self {
            vector: (raw & REDIR_VECTOR_MASK) as u8,
            delivery_mode: DeliveryMode::from_bits(raw),
            destination_mode: if raw & REDIR_DEST_LOGICAL != 0 {
                DestinationMode::Logical
            } else {
                DestinationMode::Physical
            },
            polarity: if raw & REDIR_POLARITY_LOW != 0 {
                PinPolarity::ActiveLow
            } else {
                PinPolarity::ActiveHigh
            },
            trigger_mode: if raw & REDIR_TRIGGER_LEVEL != 0 {
                TriggerMode::Level
            } else {
                TriggerMode::Edge
            },
            masked: raw & REDIR_MASK != 0,
            destination: (raw >> REDIR_DEST_SHIFT) as u8,
        }
    }
}

// ---------------------------------------------------------------------------
// IoApicInfo
// ---------------------------------------------------------------------------

/// Capabilities parsed from the I/O APIC version register.
#[derive(Debug, Clone, Copy)]
pub struct IoApicInfo {
    /// I/O APIC hardware ID.
    pub id: u8,
    /// I/O APIC version.
    pub version: u8,
    /// Maximum redirection entry index (number of entries = max + 1).
    pub max_redir_entry: u8,
    /// Arbitration ID.
    pub arb_id: u8,
}

// ---------------------------------------------------------------------------
// IoApicDevice — single I/O APIC
// ---------------------------------------------------------------------------

/// Driver for a single I/O APIC.
///
/// Provides indirect register access and redirection table management
/// for one I/O APIC instance. Use [`IoApicSystem`] to manage multiple
/// I/O APICs.
pub struct IoApicDevice {
    /// MMIO base address.
    base: u64,
    /// Global system interrupt base for this I/O APIC.
    gsi_base: u32,
    /// Hardware info (read during init).
    info: IoApicInfo,
    /// Number of redirection entries.
    entry_count: u8,
    /// Whether the device has been initialized.
    initialized: bool,
}

impl IoApicDevice {
    /// Create a new I/O APIC driver for the device at `base`.
    ///
    /// The device is not usable until [`init`](Self::init) is called.
    pub const fn new(base: u64, gsi_base: u32) -> Self {
        Self {
            base,
            gsi_base,
            info: IoApicInfo {
                id: 0,
                version: 0,
                max_redir_entry: 0,
                arb_id: 0,
            },
            entry_count: 0,
            initialized: false,
        }
    }

    /// Initialize the I/O APIC by reading its hardware capabilities.
    ///
    /// Reads the ID, version, and arbitration registers. Masks all
    /// redirection entries as a safety measure.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the base address is zero.
    pub fn init(&mut self) -> Result<()> {
        if self.base == 0 {
            return Err(Error::InvalidArgument);
        }

        // Read identification registers.
        let id_raw = self.read_indirect(REG_ID);
        self.info.id = ((id_raw >> 24) & 0x0F) as u8;

        let ver_raw = self.read_indirect(REG_VERSION);
        self.info.version = (ver_raw & 0xFF) as u8;
        self.info.max_redir_entry = ((ver_raw >> 16) & 0xFF) as u8;

        let arb_raw = self.read_indirect(REG_ARB_ID);
        self.info.arb_id = ((arb_raw >> 24) & 0x0F) as u8;

        self.entry_count = self.info.max_redir_entry.saturating_add(1);
        if self.entry_count as usize > MAX_REDIR_ENTRIES {
            self.entry_count = MAX_REDIR_ENTRIES as u8;
        }

        // Mask all interrupts during initialization.
        for pin in 0..self.entry_count {
            let entry = RedirectionEntry::new_masked(0);
            self.write_redirection(pin, &entry)?;
        }

        self.initialized = true;
        Ok(())
    }

    // -- Indirect register access ------------------------------------------

    /// Read a 32-bit indirect register.
    fn read_indirect(&self, reg: u32) -> u32 {
        write_mmio32(self.base + IOREGSEL_OFFSET, reg);
        read_mmio32(self.base + IOWIN_OFFSET)
    }

    /// Write a 32-bit indirect register.
    fn write_indirect(&self, reg: u32, val: u32) {
        write_mmio32(self.base + IOREGSEL_OFFSET, reg);
        write_mmio32(self.base + IOWIN_OFFSET, val);
    }

    // -- Redirection table -------------------------------------------------

    /// Compute the low indirect register index for a redirection entry.
    const fn redir_low(pin: u8) -> u32 {
        0x10 + (pin as u32) * 2
    }

    /// Compute the high indirect register index for a redirection entry.
    const fn redir_high(pin: u8) -> u32 {
        0x10 + (pin as u32) * 2 + 1
    }

    /// Read a 64-bit redirection table entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `pin` is out of range.
    pub fn read_redirection(&self, pin: u8) -> Result<RedirectionEntry> {
        if pin >= self.entry_count {
            return Err(Error::InvalidArgument);
        }
        let low = self.read_indirect(Self::redir_low(pin)) as u64;
        let high = self.read_indirect(Self::redir_high(pin)) as u64;
        Ok(RedirectionEntry::from_raw(low | (high << 32)))
    }

    /// Write a 64-bit redirection table entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `pin` is out of range.
    pub fn write_redirection(&self, pin: u8, entry: &RedirectionEntry) -> Result<()> {
        if pin >= self.entry_count {
            return Err(Error::InvalidArgument);
        }
        let raw = entry.to_raw();
        // Write high word first (contains destination), then low word
        // (which may unmask the interrupt and trigger delivery).
        self.write_indirect(Self::redir_high(pin), (raw >> 32) as u32);
        self.write_indirect(Self::redir_low(pin), raw as u32);
        Ok(())
    }

    /// Mask (disable) a specific IRQ pin.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `pin` is out of range.
    pub fn mask_irq(&self, pin: u8) -> Result<()> {
        let mut entry = self.read_redirection(pin)?;
        entry.masked = true;
        self.write_redirection(pin, &entry)
    }

    /// Unmask (enable) a specific IRQ pin.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `pin` is out of range.
    pub fn unmask_irq(&self, pin: u8) -> Result<()> {
        let mut entry = self.read_redirection(pin)?;
        entry.masked = false;
        self.write_redirection(pin, &entry)
    }

    /// Route an IRQ pin to a specific vector and destination APIC.
    ///
    /// Configures the delivery mode, trigger mode, polarity, and
    /// destination for the specified pin, then unmasks it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `pin` is out of range
    /// or `vector` is below 16 (reserved by x86 architecture).
    pub fn route_irq(
        &self,
        pin: u8,
        vector: u8,
        dest_apic_id: u8,
        delivery: DeliveryMode,
        trigger: TriggerMode,
        polarity: PinPolarity,
    ) -> Result<()> {
        if vector < 16 {
            return Err(Error::InvalidArgument);
        }

        let entry = RedirectionEntry {
            vector,
            delivery_mode: delivery,
            destination_mode: DestinationMode::Physical,
            polarity,
            trigger_mode: trigger,
            masked: false,
            destination: dest_apic_id,
        };
        self.write_redirection(pin, &entry)
    }

    // -- Accessors ---------------------------------------------------------

    /// Return the hardware info read during initialization.
    pub fn info(&self) -> &IoApicInfo {
        &self.info
    }

    /// Return the MMIO base address.
    pub fn base_address(&self) -> u64 {
        self.base
    }

    /// Return the GSI base for this I/O APIC.
    pub fn gsi_base(&self) -> u32 {
        self.gsi_base
    }

    /// Return the number of redirection entries.
    pub fn entry_count(&self) -> u8 {
        self.entry_count
    }

    /// Return whether the device has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Set the I/O APIC ID.
    ///
    /// Writes the ID register. The ID is used for arbitration.
    pub fn set_id(&self, id: u8) {
        let val = (id as u32 & 0x0F) << 24;
        self.write_indirect(REG_ID, val);
    }
}

impl core::fmt::Debug for IoApicDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IoApicDevice")
            .field("base", &self.base)
            .field("gsi_base", &self.gsi_base)
            .field("info", &self.info)
            .field("entry_count", &self.entry_count)
            .field("initialized", &self.initialized)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// IoApicSystem — multi-I/O-APIC manager
// ---------------------------------------------------------------------------

/// Descriptor for a registered I/O APIC.
#[derive(Debug, Clone, Copy)]
struct IoApicSlot {
    /// MMIO base address.
    base: u64,
    /// Global system interrupt base.
    gsi_base: u32,
    /// Number of redirection entries.
    entry_count: u8,
    /// Whether this slot is occupied.
    active: bool,
}

impl IoApicSlot {
    const fn empty() -> Self {
        Self {
            base: 0,
            gsi_base: 0,
            entry_count: 0,
            active: false,
        }
    }
}

/// System-level I/O APIC manager.
///
/// Tracks up to [`MAX_IOAPICS`] I/O APICs and provides a unified
/// interface for routing GSIs (Global System Interrupts) to vectors.
pub struct IoApicSystem {
    /// Registered I/O APIC slots.
    slots: [IoApicSlot; MAX_IOAPICS],
    /// Number of registered I/O APICs.
    count: usize,
}

impl IoApicSystem {
    /// Create an empty I/O APIC system manager.
    pub const fn new() -> Self {
        Self {
            slots: [IoApicSlot::empty(); MAX_IOAPICS],
            count: 0,
        }
    }

    /// Register a new I/O APIC.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the maximum number of I/O APICs
    /// has been reached. Returns [`Error::AlreadyExists`] if an I/O APIC
    /// with the same base address is already registered.
    pub fn register(&mut self, base: u64, gsi_base: u32, entry_count: u8) -> Result<usize> {
        if base == 0 {
            return Err(Error::InvalidArgument);
        }
        // Check for duplicates.
        for slot in &self.slots[..self.count] {
            if slot.active && slot.base == base {
                return Err(Error::AlreadyExists);
            }
        }
        if self.count >= MAX_IOAPICS {
            return Err(Error::OutOfMemory);
        }

        let idx = self.count;
        self.slots[idx] = IoApicSlot {
            base,
            gsi_base,
            entry_count,
            active: true,
        };
        self.count += 1;
        Ok(idx)
    }

    /// Find which I/O APIC handles a given GSI.
    ///
    /// Returns `(slot_index, local_pin)` where `local_pin` is the
    /// pin offset within that I/O APIC.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no I/O APIC covers the GSI.
    pub fn gsi_to_pin(&self, gsi: u32) -> Result<(usize, u8)> {
        for (i, slot) in self.slots[..self.count].iter().enumerate() {
            if !slot.active {
                continue;
            }
            let end_gsi = slot.gsi_base + slot.entry_count as u32;
            if gsi >= slot.gsi_base && gsi < end_gsi {
                let pin = (gsi - slot.gsi_base) as u8;
                return Ok((i, pin));
            }
        }
        Err(Error::NotFound)
    }

    /// Return the number of registered I/O APICs.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Return the slot descriptor at the given index.
    ///
    /// Returns `None` if the index is out of range.
    pub fn get(&self, index: usize) -> Option<(u64, u32, u8)> {
        if index < self.count && self.slots[index].active {
            let s = &self.slots[index];
            Some((s.base, s.gsi_base, s.entry_count))
        } else {
            None
        }
    }

    /// Check if the system has any registered I/O APICs.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for IoApicSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for IoApicSystem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IoApicSystem")
            .field("count", &self.count)
            .finish()
    }
}
