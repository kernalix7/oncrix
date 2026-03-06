// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-process virtual address space management.
//!
//! Each process has its own address space with a root page table
//! (PML4). The kernel is mapped in the higher half of every address
//! space; user code occupies the lower half.

use crate::addr::{PhysAddr, VirtAddr};
use crate::frame::FrameAllocator;
use crate::page_table::flags;
use oncrix_lib::{Error, Result};

/// Start of user-space virtual memory.
pub const USER_SPACE_START: u64 = 0x0000_0000_0040_0000;
/// End of user-space virtual memory (canonical hole boundary).
pub const USER_SPACE_END: u64 = 0x0000_7FFF_FFFF_FFFF;
/// Start of kernel-space virtual memory (higher half).
pub const KERNEL_SPACE_START: u64 = 0xFFFF_8000_0000_0000;

/// Maximum number of memory regions per address space.
const MAX_REGIONS: usize = 64;

/// Protection flags for a virtual memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Protection(pub u8);

impl Protection {
    /// Readable.
    pub const READ: Self = Self(1 << 0);
    /// Writable.
    pub const WRITE: Self = Self(1 << 1);
    /// Executable.
    pub const EXEC: Self = Self(1 << 2);

    /// Read + Write.
    pub const RW: Self = Self(Self::READ.0 | Self::WRITE.0);
    /// Read + Execute.
    pub const RX: Self = Self(Self::READ.0 | Self::EXEC.0);
    /// Read + Write + Execute.
    pub const RWX: Self = Self(Self::READ.0 | Self::WRITE.0 | Self::EXEC.0);

    /// Check if a flag is set.
    pub fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 == flag.0
    }

    /// Convert to page table entry flags.
    pub fn to_pte_flags(self) -> u64 {
        let mut f = flags::PRESENT | flags::USER;
        if self.contains(Self::WRITE) {
            f |= flags::WRITABLE;
        }
        if !self.contains(Self::EXEC) {
            f |= flags::NO_EXECUTE;
        }
        f
    }
}

/// A contiguous virtual memory region.
#[derive(Debug, Clone, Copy)]
pub struct VmRegion {
    /// Start virtual address (page-aligned).
    pub start: VirtAddr,
    /// Size in bytes (page-aligned).
    pub size: u64,
    /// Protection flags.
    pub prot: Protection,
    /// Region type.
    pub kind: RegionKind,
}

/// What kind of memory region this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    /// Program code (.text).
    Code,
    /// Program data (.data, .bss).
    Data,
    /// Heap (grows upward via brk/mmap).
    Heap,
    /// Stack (grows downward).
    Stack,
    /// Memory-mapped region (mmap).
    Mmap,
}

/// Per-process virtual address space.
///
/// Contains the root page table physical address and a list of
/// mapped virtual memory regions.
pub struct AddressSpace {
    /// Physical address of the PML4 (root page table).
    pml4_phys: PhysAddr,
    /// Virtual memory regions.
    regions: [Option<VmRegion>; MAX_REGIONS],
    /// Number of active regions.
    region_count: usize,
    /// Current program break (heap end).
    brk: VirtAddr,
}

impl AddressSpace {
    /// Create a new address space with the given PML4 physical address.
    ///
    /// The caller is responsible for allocating and initializing the
    /// PML4 frame (typically copying kernel mappings from the current
    /// address space).
    pub fn new(pml4_phys: PhysAddr) -> Self {
        const NONE: Option<VmRegion> = None;
        Self {
            pml4_phys,
            regions: [NONE; MAX_REGIONS],
            region_count: 0,
            brk: VirtAddr::new(USER_SPACE_START),
        }
    }

    /// Return the physical address of the PML4.
    pub fn pml4_phys(&self) -> PhysAddr {
        self.pml4_phys
    }

    /// Return the current program break.
    pub fn brk(&self) -> VirtAddr {
        self.brk
    }

    /// Set the program break (for brk syscall).
    pub fn set_brk(&mut self, new_brk: VirtAddr) {
        self.brk = new_brk;
    }

    /// Add a virtual memory region.
    pub fn add_region(&mut self, region: VmRegion) -> Result<()> {
        if self.region_count >= MAX_REGIONS {
            return Err(Error::OutOfMemory);
        }
        // Overlap check — use saturating arithmetic to prevent overflow.
        let end = region.start.as_u64().saturating_add(region.size);
        for existing in self.regions.iter().flatten() {
            let ex_end = existing.start.as_u64().saturating_add(existing.size);
            if region.start.as_u64() < ex_end && end > existing.start.as_u64() {
                return Err(Error::AlreadyExists);
            }
        }

        for slot in self.regions.iter_mut() {
            if slot.is_none() {
                *slot = Some(region);
                self.region_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a region by start address.
    pub fn remove_region(&mut self, start: VirtAddr) -> Result<VmRegion> {
        for slot in self.regions.iter_mut() {
            if let Some(region) = slot {
                if region.start == start {
                    let removed = *region;
                    *slot = None;
                    self.region_count -= 1;
                    return Ok(removed);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Find the region containing a virtual address.
    pub fn find_region(&self, addr: VirtAddr) -> Option<&VmRegion> {
        self.regions.iter().filter_map(|s| s.as_ref()).find(|r| {
            let a = addr.as_u64();
            a >= r.start.as_u64() && a < r.start.as_u64() + r.size
        })
    }

    /// Return the number of active regions.
    pub fn region_count(&self) -> usize {
        self.region_count
    }

    /// Iterate over all active regions.
    pub fn regions(&self) -> impl Iterator<Item = &VmRegion> {
        self.regions.iter().filter_map(|s| s.as_ref())
    }

    /// Allocate a PML4 frame and create a new address space.
    ///
    /// Copies the kernel half (entries 256-511) from the current PML4
    /// so the kernel is mapped in every process.
    pub fn create_user_space<A: FrameAllocator>(alloc: &mut A) -> Result<Self> {
        let frame = alloc.allocate_frame().ok_or(Error::OutOfMemory)?;
        // Zero the frame and copy kernel mappings would happen here.
        // For now, just return the address space with the allocated frame.
        Ok(Self::new(frame.start_addr()))
    }
}
