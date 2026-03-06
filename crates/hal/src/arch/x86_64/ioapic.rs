// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! I/O APIC (Input/Output Advanced Programmable Interrupt Controller).
//!
//! The I/O APIC handles external interrupt routing from devices to
//! Local APICs (CPUs). It replaces the legacy 8259 PIC for interrupt
//! delivery in modern x86_64 systems.
//!
//! Each I/O APIC has a set of redirection entries that map device
//! IRQs to interrupt vectors on specific CPUs. The I/O APIC is
//! memory-mapped, typically at `0xFEC0_0000`.
//!
//! Reference: Intel 82093AA I/O APIC Datasheet, Linux kernel
//! `arch/x86/kernel/apic/io_apic.c`.

/// Default I/O APIC base address.
pub const IOAPIC_DEFAULT_BASE: u64 = 0xFEC0_0000;

/// I/O APIC register select (index) — offset 0x00.
const IOREGSEL: u32 = 0x00;
/// I/O APIC data register — offset 0x10.
const IOWIN: u32 = 0x10;

/// I/O APIC register indices (written to IOREGSEL).
mod reg {
    /// I/O APIC ID register.
    pub const IOAPICID: u32 = 0x00;
    /// I/O APIC version register.
    pub const IOAPICVER: u32 = 0x01;
    /// I/O APIC arbitration ID register.
    #[allow(dead_code)]
    pub const IOAPICARB: u32 = 0x02;
    /// Base index for redirection table entries.
    /// Each entry uses two 32-bit registers: low (2*n + 0x10)
    /// and high (2*n + 0x11).
    pub const IOREDTBL_BASE: u32 = 0x10;
}

/// Redirection entry delivery modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeliveryMode {
    /// Normal interrupt delivery.
    Fixed = 0b000,
    /// Deliver to the lowest-priority CPU.
    LowestPriority = 0b001,
    /// System Management Interrupt.
    Smi = 0b010,
    /// Non-Maskable Interrupt.
    Nmi = 0b100,
    /// INIT signal.
    Init = 0b101,
    /// External interrupt (ExtINT).
    ExtInt = 0b111,
}

/// Interrupt pin polarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Polarity {
    /// Active high.
    ActiveHigh,
    /// Active low.
    ActiveLow,
}

/// Interrupt trigger mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerMode {
    /// Edge-triggered.
    Edge,
    /// Level-triggered.
    Level,
}

/// An I/O APIC redirection table entry.
///
/// Each entry configures how a specific IRQ is routed to a CPU.
/// The entry is 64 bits split across two 32-bit MMIO registers.
#[derive(Debug, Clone, Copy)]
pub struct RedirectionEntry {
    /// Interrupt vector (0-255). The IDT index on the target CPU.
    pub vector: u8,
    /// Delivery mode.
    pub delivery_mode: DeliveryMode,
    /// Destination mode: false = physical, true = logical.
    pub logical_dest: bool,
    /// Pin polarity.
    pub polarity: Polarity,
    /// Trigger mode.
    pub trigger: TriggerMode,
    /// Masked: if true, the interrupt is suppressed.
    pub masked: bool,
    /// Destination APIC ID (physical mode) or logical destination.
    pub destination: u8,
}

impl RedirectionEntry {
    /// Create a masked entry (interrupt disabled).
    pub const fn masked() -> Self {
        Self {
            vector: 0,
            delivery_mode: DeliveryMode::Fixed,
            logical_dest: false,
            polarity: Polarity::ActiveHigh,
            trigger: TriggerMode::Edge,
            masked: true,
            destination: 0,
        }
    }

    /// Encode this entry as a 64-bit register value.
    fn encode(&self) -> u64 {
        let mut val: u64 = self.vector as u64;

        // Delivery mode (bits 10:8).
        val |= (self.delivery_mode as u64) << 8;

        // Destination mode (bit 11): 0 = physical, 1 = logical.
        if self.logical_dest {
            val |= 1 << 11;
        }

        // Polarity (bit 13): 0 = active high, 1 = active low.
        if matches!(self.polarity, Polarity::ActiveLow) {
            val |= 1 << 13;
        }

        // Trigger mode (bit 15): 0 = edge, 1 = level.
        if matches!(self.trigger, TriggerMode::Level) {
            val |= 1 << 15;
        }

        // Mask (bit 16): 1 = masked.
        if self.masked {
            val |= 1 << 16;
        }

        // Destination (bits 63:56 in the high 32-bit word).
        val |= (self.destination as u64) << 56;

        val
    }

    /// Decode a 64-bit register value into a redirection entry.
    fn decode(val: u64) -> Self {
        let vector = val as u8;

        let delivery_mode = match ((val >> 8) & 0x7) as u8 {
            0b001 => DeliveryMode::LowestPriority,
            0b010 => DeliveryMode::Smi,
            0b100 => DeliveryMode::Nmi,
            0b101 => DeliveryMode::Init,
            0b111 => DeliveryMode::ExtInt,
            _ => DeliveryMode::Fixed,
        };

        let logical_dest = val & (1 << 11) != 0;

        let polarity = if val & (1 << 13) != 0 {
            Polarity::ActiveLow
        } else {
            Polarity::ActiveHigh
        };

        let trigger = if val & (1 << 15) != 0 {
            TriggerMode::Level
        } else {
            TriggerMode::Edge
        };

        let masked = val & (1 << 16) != 0;
        let destination = (val >> 56) as u8;

        Self {
            vector,
            delivery_mode,
            logical_dest,
            polarity,
            trigger,
            masked,
            destination,
        }
    }
}

/// I/O APIC driver.
///
/// Provides access to a single I/O APIC. Most systems have one
/// I/O APIC, but multi-socket systems may have more.
pub struct IoApic {
    /// MMIO base address.
    base: u64,
    /// Global System Interrupt base for this I/O APIC.
    gsi_base: u32,
    /// Number of redirection entries (max IRQ inputs).
    max_entries: u8,
}

impl IoApic {
    /// Create a new I/O APIC driver.
    ///
    /// `base` is the MMIO base address (from ACPI MADT).
    /// `gsi_base` is the first Global System Interrupt this
    /// I/O APIC handles.
    pub fn new(base: u64, gsi_base: u32) -> Self {
        let mut apic = Self {
            base,
            gsi_base,
            max_entries: 0,
        };
        // Read the version register to get max redirection entries.
        let ver = apic.read_reg(reg::IOAPICVER);
        apic.max_entries = ((ver >> 16) & 0xFF) as u8 + 1;
        apic
    }

    /// Read an I/O APIC register by index.
    fn read_reg(&self, index: u32) -> u32 {
        // SAFETY: I/O APIC MMIO region is identity-mapped in kernel
        // space. We write the index to IOREGSEL, then read from IOWIN.
        unsafe {
            let sel = (self.base + IOREGSEL as u64) as *mut u32;
            let win = (self.base + IOWIN as u64) as *const u32;
            core::ptr::write_volatile(sel, index);
            core::ptr::read_volatile(win)
        }
    }

    /// Write an I/O APIC register by index.
    fn write_reg(&self, index: u32, value: u32) {
        // SAFETY: I/O APIC MMIO region is identity-mapped in kernel
        // space. We write the index to IOREGSEL, then write to IOWIN.
        unsafe {
            let sel = (self.base + IOREGSEL as u64) as *mut u32;
            let win = (self.base + IOWIN as u64) as *mut u32;
            core::ptr::write_volatile(sel, index);
            core::ptr::write_volatile(win, value);
        }
    }

    /// Return the I/O APIC ID.
    pub fn id(&self) -> u8 {
        ((self.read_reg(reg::IOAPICID) >> 24) & 0xF) as u8
    }

    /// Return the I/O APIC version.
    pub fn version(&self) -> u8 {
        (self.read_reg(reg::IOAPICVER) & 0xFF) as u8
    }

    /// Return the number of redirection entries (interrupt inputs).
    pub fn max_entries(&self) -> u8 {
        self.max_entries
    }

    /// Return the GSI base for this I/O APIC.
    pub fn gsi_base(&self) -> u32 {
        self.gsi_base
    }

    /// Read a redirection table entry.
    ///
    /// `irq` is the pin number (0-based, relative to this I/O APIC).
    pub fn read_entry(&self, irq: u8) -> Option<RedirectionEntry> {
        if irq >= self.max_entries {
            return None;
        }
        let reg_lo = reg::IOREDTBL_BASE + (irq as u32) * 2;
        let reg_hi = reg_lo + 1;
        let lo = self.read_reg(reg_lo) as u64;
        let hi = self.read_reg(reg_hi) as u64;
        Some(RedirectionEntry::decode(lo | (hi << 32)))
    }

    /// Write a redirection table entry.
    ///
    /// `irq` is the pin number (0-based, relative to this I/O APIC).
    pub fn write_entry(&self, irq: u8, entry: &RedirectionEntry) -> bool {
        if irq >= self.max_entries {
            return false;
        }
        let val = entry.encode();
        let reg_lo = reg::IOREDTBL_BASE + (irq as u32) * 2;
        let reg_hi = reg_lo + 1;
        // Write high word first to avoid briefly unmasking with
        // wrong destination.
        self.write_reg(reg_hi, (val >> 32) as u32);
        self.write_reg(reg_lo, val as u32);
        true
    }

    /// Route an IRQ to a specific CPU and vector.
    ///
    /// This is a convenience function that sets up a typical
    /// fixed-delivery, edge-triggered, active-high interrupt.
    ///
    /// - `irq`: I/O APIC pin number
    /// - `vector`: IDT vector on the target CPU
    /// - `dest_apic_id`: target CPU's Local APIC ID
    pub fn route_irq(&self, irq: u8, vector: u8, dest_apic_id: u8) -> bool {
        let entry = RedirectionEntry {
            vector,
            delivery_mode: DeliveryMode::Fixed,
            logical_dest: false,
            polarity: Polarity::ActiveHigh,
            trigger: TriggerMode::Edge,
            masked: false,
            destination: dest_apic_id,
        };
        self.write_entry(irq, &entry)
    }

    /// Route an IRQ with specific polarity and trigger settings.
    ///
    /// Used when ACPI interrupt source overrides specify non-default
    /// polarity or trigger mode.
    pub fn route_irq_override(
        &self,
        irq: u8,
        vector: u8,
        dest_apic_id: u8,
        polarity: Polarity,
        trigger: TriggerMode,
    ) -> bool {
        let entry = RedirectionEntry {
            vector,
            delivery_mode: DeliveryMode::Fixed,
            logical_dest: false,
            polarity,
            trigger,
            masked: false,
            destination: dest_apic_id,
        };
        self.write_entry(irq, &entry)
    }

    /// Mask (disable) an IRQ.
    pub fn mask_irq(&self, irq: u8) -> bool {
        if let Some(mut entry) = self.read_entry(irq) {
            entry.masked = true;
            self.write_entry(irq, &entry)
        } else {
            false
        }
    }

    /// Unmask (enable) an IRQ.
    pub fn unmask_irq(&self, irq: u8) -> bool {
        if let Some(mut entry) = self.read_entry(irq) {
            entry.masked = false;
            self.write_entry(irq, &entry)
        } else {
            false
        }
    }

    /// Mask all interrupts (initialize all entries as masked).
    pub fn mask_all(&self) {
        let masked = RedirectionEntry::masked();
        for i in 0..self.max_entries {
            self.write_entry(i, &masked);
        }
    }

    /// Convert a Global System Interrupt to a local pin number.
    ///
    /// Returns `None` if the GSI is not handled by this I/O APIC.
    pub fn gsi_to_pin(&self, gsi: u32) -> Option<u8> {
        let end = self.gsi_base.saturating_add(self.max_entries as u32);
        if gsi >= self.gsi_base && gsi < end {
            Some((gsi - self.gsi_base) as u8)
        } else {
            None
        }
    }
}

impl core::fmt::Debug for IoApic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IoApic")
            .field("base", &format_args!("{:#x}", self.base))
            .field("gsi_base", &self.gsi_base)
            .field("max_entries", &self.max_entries)
            .finish()
    }
}

/// Apply ACPI interrupt source overrides to set up ISA IRQ routing.
///
/// The standard ISA IRQs (0-15) are identity-mapped to GSIs by
/// default. ACPI overrides change this for specific IRQs (e.g.,
/// IRQ 0 → GSI 2 is common for the timer).
///
/// - `ioapic`: the I/O APIC to configure
/// - `overrides`: interrupt source overrides from the MADT
/// - `override_count`: number of overrides
/// - `base_vector`: IDT vector offset (e.g., 32 for ISA IRQ 0 → vector 32)
/// - `dest_apic_id`: target CPU's Local APIC ID
pub fn apply_isa_overrides(
    ioapic: &IoApic,
    overrides: &[crate::acpi::MadtOverride],
    base_vector: u8,
    dest_apic_id: u8,
) {
    // First, set up default identity mapping for ISA IRQs 0-15.
    for irq in 0..16u8 {
        if let Some(pin) = ioapic.gsi_to_pin(irq as u32) {
            ioapic.route_irq(pin, base_vector.saturating_add(irq), dest_apic_id);
        }
    }

    // Then apply overrides.
    for ovr in overrides {
        let vector = base_vector.saturating_add(ovr.irq_source);

        let polarity = match ovr.flags & 0x3 {
            0b01 => Polarity::ActiveHigh,
            0b11 => Polarity::ActiveLow,
            _ => Polarity::ActiveHigh, // conforming to bus spec
        };

        let trigger = match (ovr.flags >> 2) & 0x3 {
            0b01 => TriggerMode::Edge,
            0b11 => TriggerMode::Level,
            _ => TriggerMode::Edge, // conforming to bus spec
        };

        if let Some(pin) = ioapic.gsi_to_pin(ovr.gsi) {
            ioapic.route_irq_override(pin, vector, dest_apic_id, polarity, trigger);
        }
    }
}
