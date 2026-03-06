// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Physical memory map provided by the bootloader.

/// Maximum number of memory regions supported.
pub const MAX_MEMORY_REGIONS: usize = 128;

/// Type of a physical memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MemoryRegionKind {
    /// Usable RAM, available for kernel allocation.
    Usable = 1,
    /// Reserved by firmware or hardware.
    Reserved = 2,
    /// ACPI reclaimable memory.
    AcpiReclaimable = 3,
    /// ACPI NVS (non-volatile storage).
    AcpiNvs = 4,
    /// Bad / defective memory.
    Defective = 5,
    /// Memory used by the bootloader (reclaimable after boot).
    BootloaderReclaimable = 0x1000,
    /// Memory containing the kernel image.
    KernelImage = 0x1001,
}

/// A contiguous region of physical memory.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryRegion {
    /// Physical start address (page-aligned).
    pub start: u64,
    /// Length in bytes.
    pub length: u64,
    /// Region type.
    pub kind: MemoryRegionKind,
}

/// Physical memory map passed from bootloader to kernel.
///
/// Contains a fixed-size array of memory regions. The bootloader fills
/// in `count` entries; remaining slots are unused.
#[derive(Debug)]
pub struct MemoryMap {
    regions: [MemoryRegion; MAX_MEMORY_REGIONS],
    count: usize,
}

impl Default for MemoryMap {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryMap {
    /// Create an empty memory map.
    pub const fn new() -> Self {
        Self {
            regions: [MemoryRegion {
                start: 0,
                length: 0,
                kind: MemoryRegionKind::Reserved,
            }; MAX_MEMORY_REGIONS],
            count: 0,
        }
    }

    /// Add a memory region to the map.
    ///
    /// Returns `Err(InvalidArgument)` if the map is full.
    pub fn push(&mut self, region: MemoryRegion) -> oncrix_lib::Result<()> {
        if self.count >= MAX_MEMORY_REGIONS {
            return Err(oncrix_lib::Error::InvalidArgument);
        }
        self.regions[self.count] = region;
        self.count += 1;
        Ok(())
    }

    /// Returns the number of valid regions.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if the memory map has no regions.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns a slice of valid memory regions.
    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions[..self.count]
    }

    /// Returns an iterator over usable memory regions.
    pub fn usable_regions(&self) -> impl Iterator<Item = &MemoryRegion> {
        self.regions()
            .iter()
            .filter(|r| r.kind == MemoryRegionKind::Usable)
    }

    /// Returns the total amount of usable physical memory in bytes.
    pub fn total_usable_memory(&self) -> u64 {
        self.usable_regions().map(|r| r.length).sum()
    }
}
