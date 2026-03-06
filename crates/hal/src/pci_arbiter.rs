// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCI bus arbitration and resource allocation.
//!
//! Manages PCI resource allocation including memory-mapped I/O windows,
//! I/O port ranges, interrupt routing, and bus number assignment.
//! Acts as the central authority for PCI resource conflicts resolution.
//!
//! # Resource Types
//!
//! - **Memory BARs**: 32-bit or 64-bit MMIO windows
//! - **I/O BARs**: Legacy x86 I/O port windows
//! - **Bus numbers**: Primary/secondary/subordinate bus numbering
//! - **Interrupts**: INTx routing, MSI/MSI-X vector assignment

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

/// PCI resource type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciResourceType {
    /// 32-bit prefetchable or non-prefetchable MMIO.
    Memory32,
    /// 64-bit prefetchable MMIO.
    Memory64,
    /// Legacy I/O port space.
    IoPort,
    /// PCI bus number range.
    BusRange,
}

/// A PCI resource allocation entry.
#[derive(Debug, Clone, Copy)]
pub struct PciResource {
    /// Resource type.
    pub res_type: PciResourceType,
    /// Start address or bus number.
    pub start: u64,
    /// End address (inclusive) or end bus number.
    pub end: u64,
    /// Whether the region is prefetchable (for memory resources).
    pub prefetchable: bool,
    /// Owner: PCI BDF encoded as (bus << 8 | dev << 3 | func).
    pub owner_bdf: u16,
}

impl PciResource {
    /// Returns the size of this resource in bytes (or count for bus ranges).
    pub fn size(&self) -> u64 {
        self.end - self.start + 1
    }

    /// Returns whether this resource overlaps with another.
    pub fn overlaps(&self, other: &PciResource) -> bool {
        self.res_type == other.res_type && self.start <= other.end && other.start <= self.end
    }

    /// Returns whether this resource is properly aligned for its size.
    pub fn is_aligned(&self) -> bool {
        let size = self.size();
        if !size.is_power_of_two() {
            return false;
        }
        self.start & (size - 1) == 0
    }
}

/// Maximum number of tracked PCI resource allocations.
pub const MAX_PCI_RESOURCES: usize = 128;

/// PCI resource arbiter — allocates and tracks all PCI resources.
pub struct PciArbiter {
    resources: [Option<PciResource>; MAX_PCI_RESOURCES],
    count: usize,
    /// Next available 32-bit MMIO address.
    next_mmio32: u64,
    /// Next available 64-bit MMIO address.
    next_mmio64: u64,
    /// Next available I/O port.
    next_ioport: u64,
    /// Next available bus number.
    next_bus: u8,
}

impl PciArbiter {
    /// Creates a new PCI arbiter.
    ///
    /// # Arguments
    ///
    /// * `mmio32_start` - Start of the 32-bit MMIO allocation window
    /// * `mmio64_start` - Start of the 64-bit MMIO allocation window
    /// * `ioport_start` - Start of the I/O port allocation window
    /// * `bus_start` - First bus number to allocate
    pub const fn new(
        mmio32_start: u64,
        mmio64_start: u64,
        ioport_start: u64,
        bus_start: u8,
    ) -> Self {
        const NONE: Option<PciResource> = None;
        Self {
            resources: [NONE; MAX_PCI_RESOURCES],
            count: 0,
            next_mmio32: mmio32_start,
            next_mmio64: mmio64_start,
            next_ioport: ioport_start,
            next_bus: bus_start,
        }
    }

    /// Allocates a 32-bit MMIO resource for a device.
    pub fn alloc_mmio32(
        &mut self,
        owner_bdf: u16,
        size: u32,
        prefetchable: bool,
    ) -> Result<PciResource> {
        if size == 0 || !size.is_power_of_two() {
            return Err(Error::InvalidArgument);
        }
        // Align to size
        let aligned = (self.next_mmio32 + size as u64 - 1) & !(size as u64 - 1);
        let end = aligned + size as u64 - 1;
        if end > 0xFFFF_FFFF {
            return Err(Error::OutOfMemory);
        }
        let res = PciResource {
            res_type: PciResourceType::Memory32,
            start: aligned,
            end,
            prefetchable,
            owner_bdf,
        };
        self.store(res)?;
        self.next_mmio32 = end + 1;
        Ok(res)
    }

    /// Allocates a 64-bit MMIO resource for a device.
    pub fn alloc_mmio64(&mut self, owner_bdf: u16, size: u64) -> Result<PciResource> {
        if size == 0 || !size.is_power_of_two() {
            return Err(Error::InvalidArgument);
        }
        let aligned = (self.next_mmio64 + size - 1) & !(size - 1);
        let end = aligned + size - 1;
        let res = PciResource {
            res_type: PciResourceType::Memory64,
            start: aligned,
            end,
            prefetchable: true,
            owner_bdf,
        };
        self.store(res)?;
        self.next_mmio64 = end + 1;
        Ok(res)
    }

    /// Allocates an I/O port resource.
    pub fn alloc_ioport(&mut self, owner_bdf: u16, size: u32) -> Result<PciResource> {
        if size == 0 || !size.is_power_of_two() {
            return Err(Error::InvalidArgument);
        }
        let aligned = (self.next_ioport + size as u64 - 1) & !(size as u64 - 1);
        let end = aligned + size as u64 - 1;
        if end > 0xFFFF {
            return Err(Error::OutOfMemory);
        }
        let res = PciResource {
            res_type: PciResourceType::IoPort,
            start: aligned,
            end,
            prefetchable: false,
            owner_bdf,
        };
        self.store(res)?;
        self.next_ioport = end + 1;
        Ok(res)
    }

    /// Allocates a PCI bus number.
    pub fn alloc_bus(&mut self, owner_bdf: u16) -> Result<u8> {
        if self.next_bus == 0 {
            return Err(Error::OutOfMemory);
        }
        let bus = self.next_bus;
        let res = PciResource {
            res_type: PciResourceType::BusRange,
            start: bus as u64,
            end: bus as u64,
            prefetchable: false,
            owner_bdf,
        };
        self.store(res)?;
        self.next_bus = self.next_bus.wrapping_add(1);
        Ok(bus)
    }

    /// Releases a resource allocation.
    pub fn free(&mut self, owner_bdf: u16, start: u64) -> Result<()> {
        for i in 0..self.count {
            if let Some(res) = self.resources[i] {
                if res.owner_bdf == owner_bdf && res.start == start {
                    self.resources[i] = self.resources[self.count - 1];
                    self.resources[self.count - 1] = None;
                    self.count -= 1;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of allocated resources.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns whether there are no allocations.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    fn store(&mut self, res: PciResource) -> Result<()> {
        if self.count >= MAX_PCI_RESOURCES {
            return Err(Error::OutOfMemory);
        }
        self.resources[self.count] = Some(res);
        self.count += 1;
        Ok(())
    }
}

impl Default for PciArbiter {
    fn default() -> Self {
        Self::new(0x8000_0000, 0x1_0000_0000, 0xC000, 1)
    }
}
