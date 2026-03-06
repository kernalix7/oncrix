// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! x86 I/O APIC (Advanced Programmable Interrupt Controller) driver.
//!
//! Manages the I/O APIC found in x86 systems, routing hardware interrupts
//! from peripheral devices to LAPIC on specific CPUs.
//!
//! # Register Access
//!
//! The I/O APIC uses an indirect register access mechanism:
//! - Write register index to IOREGSEL (offset 0x00)
//! - Read/write register value from/to IOWIN (offset 0x10)
//!
//! # Redirection Table
//!
//! Each I/O APIC has up to 24 redirection table entries (RTEs), each 64-bit
//! wide, stored in two 32-bit registers (IOREDTBL_LO + IOREDTBL_HI).

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

/// Maximum number of I/O APIC redirection table entries.
pub const IOAPIC_MAX_ENTRIES: usize = 24;

/// Default I/O APIC MMIO base address.
pub const IOAPIC_DEFAULT_BASE: usize = 0xFEC0_0000;

// I/O APIC register indices
const IOAPIC_ID: u8 = 0x00;
const IOAPIC_VER: u8 = 0x01;
const IOAPIC_ARB: u8 = 0x02;
const IOAPIC_REDTBL_BASE: u8 = 0x10;

// Register access offsets within the MMIO region
const IOREGSEL: usize = 0x00;
const IOWIN: usize = 0x10;

/// Delivery mode for I/O APIC redirections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeliveryMode {
    /// Fixed: delivered to the CPU specified in the destination field.
    Fixed = 0b000,
    /// Lowest priority: delivered to the lowest-priority CPU among destinations.
    LowestPriority = 0b001,
    /// System Management Interrupt.
    Smi = 0b010,
    /// Non-Maskable Interrupt.
    Nmi = 0b100,
    /// INIT signal.
    Init = 0b101,
    /// ExtINT: treats interrupt like an 8259A interrupt.
    ExtInt = 0b111,
}

/// Destination mode for I/O APIC redirections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DestinationMode {
    /// Physical: destination field specifies APIC ID.
    Physical = 0,
    /// Logical: destination field specifies a set of processors.
    Logical = 1,
}

/// Trigger mode for I/O APIC redirections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TriggerMode {
    /// Edge-triggered.
    Edge = 0,
    /// Level-triggered.
    Level = 1,
}

/// Polarity of the interrupt signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Polarity {
    /// Active high.
    ActiveHigh = 0,
    /// Active low.
    ActiveLow = 1,
}

/// A single I/O APIC Redirection Table Entry.
#[derive(Debug, Clone, Copy)]
pub struct RedirectionEntry {
    /// Interrupt vector (0x10–0xFE).
    pub vector: u8,
    /// Delivery mode.
    pub delivery: DeliveryMode,
    /// Destination mode.
    pub dest_mode: DestinationMode,
    /// Polarity of the interrupt.
    pub polarity: Polarity,
    /// Trigger mode.
    pub trigger: TriggerMode,
    /// Whether the interrupt is masked (disabled).
    pub masked: bool,
    /// Destination APIC ID or logical CPU set.
    pub destination: u8,
}

impl RedirectionEntry {
    /// Encodes this entry into two 32-bit register values (low, high).
    pub fn encode(&self) -> (u32, u32) {
        let lo = (self.vector as u32)
            | ((self.delivery as u32) << 8)
            | ((self.dest_mode as u32) << 11)
            | ((self.polarity as u32) << 13)
            | ((self.trigger as u32) << 15)
            | (if self.masked { 1 << 16 } else { 0 });
        let hi = (self.destination as u32) << 24;
        (lo, hi)
    }

    /// Decodes two 32-bit register values into a `RedirectionEntry`.
    pub fn decode(lo: u32, hi: u32) -> Self {
        Self {
            vector: (lo & 0xFF) as u8,
            delivery: match (lo >> 8) & 0x7 {
                0 => DeliveryMode::Fixed,
                1 => DeliveryMode::LowestPriority,
                2 => DeliveryMode::Smi,
                4 => DeliveryMode::Nmi,
                5 => DeliveryMode::Init,
                _ => DeliveryMode::ExtInt,
            },
            dest_mode: if (lo >> 11) & 1 == 0 {
                DestinationMode::Physical
            } else {
                DestinationMode::Logical
            },
            polarity: if (lo >> 13) & 1 == 0 {
                Polarity::ActiveHigh
            } else {
                Polarity::ActiveLow
            },
            trigger: if (lo >> 15) & 1 == 0 {
                TriggerMode::Edge
            } else {
                TriggerMode::Level
            },
            masked: (lo >> 16) & 1 != 0,
            destination: ((hi >> 24) & 0xFF) as u8,
        }
    }
}

/// x86 I/O APIC controller.
pub struct X86Ioapic {
    /// MMIO base address.
    base: usize,
    /// I/O APIC ID read from hardware.
    id: u8,
    /// Number of redirection table entries.
    num_entries: u8,
    /// GSI base (global system interrupt) for this I/O APIC.
    gsi_base: u32,
}

impl X86Ioapic {
    /// Creates a new I/O APIC instance.
    ///
    /// # Arguments
    ///
    /// * `base` - MMIO base address of the I/O APIC
    /// * `gsi_base` - First Global System Interrupt number handled by this APIC
    pub const fn new(base: usize, gsi_base: u32) -> Self {
        Self {
            base,
            id: 0,
            num_entries: 0,
            gsi_base,
        }
    }

    /// Initializes the I/O APIC and masks all interrupts.
    pub fn init(&mut self) -> Result<()> {
        let id_reg = self.read_reg(IOAPIC_ID);
        self.id = ((id_reg >> 24) & 0xF) as u8;

        let ver_reg = self.read_reg(IOAPIC_VER);
        let max_redir = ((ver_reg >> 16) & 0xFF) as u8;
        self.num_entries = max_redir + 1;

        if (self.num_entries as usize) > IOAPIC_MAX_ENTRIES {
            return Err(Error::InvalidArgument);
        }

        // Mask all entries
        for i in 0..self.num_entries {
            let entry = self.read_entry(i)?;
            let (lo, hi) = entry.encode();
            let masked_lo = lo | (1 << 16);
            self.write_entry_raw(i, masked_lo, hi);
        }

        Ok(())
    }

    /// Reads a redirection table entry.
    pub fn read_entry(&self, index: u8) -> Result<RedirectionEntry> {
        if index >= self.num_entries {
            return Err(Error::InvalidArgument);
        }
        let reg_base = IOAPIC_REDTBL_BASE + index * 2;
        let lo = self.read_reg(reg_base);
        let hi = self.read_reg(reg_base + 1);
        Ok(RedirectionEntry::decode(lo, hi))
    }

    /// Writes a redirection table entry.
    pub fn write_entry(&self, index: u8, entry: &RedirectionEntry) -> Result<()> {
        if index >= self.num_entries {
            return Err(Error::InvalidArgument);
        }
        let (lo, hi) = entry.encode();
        self.write_entry_raw(index, lo, hi);
        Ok(())
    }

    /// Masks (disables) a specific IRQ line.
    pub fn mask_irq(&self, index: u8) -> Result<()> {
        let mut entry = self.read_entry(index)?;
        entry.masked = true;
        self.write_entry(index, &entry)
    }

    /// Unmasks (enables) a specific IRQ line.
    pub fn unmask_irq(&self, index: u8) -> Result<()> {
        let mut entry = self.read_entry(index)?;
        entry.masked = false;
        self.write_entry(index, &entry)
    }

    /// Returns the I/O APIC hardware ID.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Returns the number of redirection table entries.
    pub fn num_entries(&self) -> u8 {
        self.num_entries
    }

    /// Returns the GSI base for this I/O APIC.
    pub fn gsi_base(&self) -> u32 {
        self.gsi_base
    }

    fn write_entry_raw(&self, index: u8, lo: u32, hi: u32) {
        let reg_base = IOAPIC_REDTBL_BASE + index * 2;
        // Mask first (write LO with mask bit set) before updating HI
        self.write_reg(reg_base, lo | (1 << 16));
        self.write_reg(reg_base + 1, hi);
        self.write_reg(reg_base, lo);
    }

    fn read_reg(&self, index: u8) -> u32 {
        let sel = self.base as *mut u32;
        let win = (self.base + IOWIN) as *const u32;
        // SAFETY: base is a valid I/O APIC MMIO region. Writing to IOREGSEL then
        // reading IOWIN is the documented indirect register access protocol for the I/O APIC.
        // Both accesses must be volatile to prevent reordering.
        unsafe {
            sel.write_volatile(index as u32);
            win.read_volatile()
        }
    }

    fn write_reg(&self, index: u8, value: u32) {
        let sel = self.base as *mut u32;
        let win = (self.base + IOWIN) as *mut u32;
        // SAFETY: base is a valid I/O APIC MMIO region. The indirect write protocol
        // requires writing the register index to IOREGSEL before writing the value to IOWIN.
        unsafe {
            sel.write_volatile(index as u32);
            win.write_volatile(value);
        }
    }
}

impl Default for X86Ioapic {
    fn default() -> Self {
        Self::new(IOAPIC_DEFAULT_BASE, 0)
    }
}
