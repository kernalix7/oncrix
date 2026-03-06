// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Resource management.
//!
//! Tracks I/O port, memory-mapped I/O, IRQ, and DMA address
//! ranges. Resources form a tree (parent/child/sibling) to
//! represent the hardware topology. The kernel uses this to
//! prevent conflicting device access.
//!
//! # Design
//!
//! ```text
//!   Resource
//!   +-------------------+
//!   | name              |
//!   | start / end       |  address range
//!   | flags             |  IORESOURCE_IO / MEM / IRQ / DMA
//!   | parent / child    |  tree indices
//!   | sibling           |
//!   +-------------------+
//!
//!   ResourceTree:
//!   ioport_resource  (root for I/O ports: 0x0000–0xFFFF)
//!   iomem_resource   (root for MMIO: 0x00000000–0xFFFFFFFF...)
//! ```
//!
//! # Operations
//!
//! - `request_region()` — claim an I/O port range.
//! - `release_region()` — release an I/O port range.
//! - `request_mem_region()` — claim a memory-mapped range.
//!
//! # Reference
//!
//! Linux `kernel/resource.c`,
//! `include/linux/ioport.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum resource entries.
const MAX_RESOURCES: usize = 512;

/// No index sentinel.
const NO_IDX: u32 = u32::MAX;

/// Maximum name length.
const MAX_NAME_LEN: usize = 48;

// ======================================================================
// Resource flags
// ======================================================================

/// I/O port resource.
pub const IORESOURCE_IO: u32 = 1 << 0;

/// Memory-mapped I/O resource.
pub const IORESOURCE_MEM: u32 = 1 << 1;

/// IRQ resource.
pub const IORESOURCE_IRQ: u32 = 1 << 2;

/// DMA channel resource.
pub const IORESOURCE_DMA: u32 = 1 << 3;

/// Resource is busy (in use by a driver).
pub const IORESOURCE_BUSY: u32 = 1 << 8;

/// Prefetchable memory.
pub const IORESOURCE_PREFETCH: u32 = 1 << 9;

/// Read-only resource.
pub const IORESOURCE_READONLY: u32 = 1 << 10;

// ======================================================================
// Resource
// ======================================================================

/// A system resource (I/O port, MMIO, IRQ, or DMA range).
#[derive(Debug, Clone, Copy)]
pub struct Resource {
    /// Resource name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Start address.
    start: u64,
    /// End address (inclusive).
    end: u64,
    /// Flags (IORESOURCE_*).
    flags: u32,
    /// Parent resource index.
    parent: u32,
    /// First child resource index.
    child: u32,
    /// Next sibling resource index.
    sibling: u32,
    /// Whether this slot is allocated.
    allocated: bool,
    /// Owner identifier (driver/subsystem).
    owner_id: u32,
}

impl Resource {
    /// Creates a new empty resource.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            start: 0,
            end: 0,
            flags: 0,
            parent: NO_IDX,
            child: NO_IDX,
            sibling: NO_IDX,
            allocated: false,
            owner_id: 0,
        }
    }

    /// Returns the resource name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns the start address.
    pub fn start(&self) -> u64 {
        self.start
    }

    /// Returns the end address.
    pub fn end(&self) -> u64 {
        self.end
    }

    /// Returns the size of the resource.
    pub fn size(&self) -> u64 {
        if self.end >= self.start {
            self.end - self.start + 1
        } else {
            0
        }
    }

    /// Returns the flags.
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// Returns the parent index.
    pub fn parent(&self) -> u32 {
        self.parent
    }

    /// Returns the child index.
    pub fn child(&self) -> u32 {
        self.child
    }

    /// Returns the sibling index.
    pub fn sibling(&self) -> u32 {
        self.sibling
    }

    /// Returns whether this resource is busy.
    pub fn is_busy(&self) -> bool {
        self.flags & IORESOURCE_BUSY != 0
    }

    /// Returns the owner ID.
    pub fn owner_id(&self) -> u32 {
        self.owner_id
    }
}

// ======================================================================
// ResourceTree
// ======================================================================

/// Manages the system resource tree.
pub struct ResourceTree {
    /// Resource pool.
    resources: [Resource; MAX_RESOURCES],
    /// Number of allocated resources.
    count: usize,
    /// Root index for I/O port space.
    ioport_root: u32,
    /// Root index for memory space.
    iomem_root: u32,
}

impl ResourceTree {
    /// Creates a new resource tree with root resources.
    pub const fn new() -> Self {
        Self {
            resources: [const { Resource::new() }; MAX_RESOURCES],
            count: 0,
            ioport_root: NO_IDX,
            iomem_root: NO_IDX,
        }
    }

    /// Initializes the root resources (ioport + iomem).
    pub fn init_roots(&mut self) -> Result<()> {
        // I/O port root: 0x0000 - 0xFFFF.
        let io_idx = self.alloc_resource(b"ioport", 0x0000, 0xFFFF, IORESOURCE_IO)?;
        self.ioport_root = io_idx as u32;

        // Memory root: 0 - u64::MAX.
        let mem_idx = self.alloc_resource(b"iomem", 0, u64::MAX, IORESOURCE_MEM)?;
        self.iomem_root = mem_idx as u32;

        Ok(())
    }

    /// Requests an I/O port region.
    pub fn request_region(
        &mut self,
        name: &[u8],
        start: u64,
        size: u64,
        owner_id: u32,
    ) -> Result<usize> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        let end = start.checked_add(size - 1).ok_or(Error::InvalidArgument)?;

        // Check for conflicts with existing I/O resources.
        self.check_conflict(start, end, IORESOURCE_IO)?;

        let idx = self.alloc_resource(name, start, end, IORESOURCE_IO | IORESOURCE_BUSY)?;
        self.resources[idx].owner_id = owner_id;
        self.resources[idx].parent = self.ioport_root;

        // Link as child of ioport root.
        self.link_child(self.ioport_root, idx as u32);

        Ok(idx)
    }

    /// Releases an I/O port region.
    pub fn release_region(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_RESOURCES || !self.resources[idx].allocated {
            return Err(Error::NotFound);
        }
        if self.resources[idx].flags & IORESOURCE_IO == 0 {
            return Err(Error::InvalidArgument);
        }
        self.unlink_child(self.resources[idx].parent, idx as u32);
        self.resources[idx] = Resource::new();
        self.count -= 1;
        Ok(())
    }

    /// Requests a memory-mapped region.
    pub fn request_mem_region(
        &mut self,
        name: &[u8],
        start: u64,
        size: u64,
        owner_id: u32,
    ) -> Result<usize> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        let end = start.checked_add(size - 1).ok_or(Error::InvalidArgument)?;

        self.check_conflict(start, end, IORESOURCE_MEM)?;

        let idx = self.alloc_resource(name, start, end, IORESOURCE_MEM | IORESOURCE_BUSY)?;
        self.resources[idx].owner_id = owner_id;
        self.resources[idx].parent = self.iomem_root;

        self.link_child(self.iomem_root, idx as u32);

        Ok(idx)
    }

    /// Releases a memory region.
    pub fn release_mem_region(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_RESOURCES || !self.resources[idx].allocated {
            return Err(Error::NotFound);
        }
        if self.resources[idx].flags & IORESOURCE_MEM == 0 {
            return Err(Error::InvalidArgument);
        }
        self.unlink_child(self.resources[idx].parent, idx as u32);
        self.resources[idx] = Resource::new();
        self.count -= 1;
        Ok(())
    }

    /// Returns a reference to a resource.
    pub fn get(&self, idx: usize) -> Result<&Resource> {
        if idx >= MAX_RESOURCES || !self.resources[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(&self.resources[idx])
    }

    /// Returns the number of allocated resources.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns the I/O port root index.
    pub fn ioport_root(&self) -> u32 {
        self.ioport_root
    }

    /// Returns the memory root index.
    pub fn iomem_root(&self) -> u32 {
        self.iomem_root
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Allocates a resource entry.
    fn alloc_resource(&mut self, name: &[u8], start: u64, end: u64, flags: u32) -> Result<usize> {
        if self.count >= MAX_RESOURCES {
            return Err(Error::OutOfMemory);
        }
        let idx = self
            .resources
            .iter()
            .position(|r| !r.allocated)
            .ok_or(Error::OutOfMemory)?;
        let copy_len = name.len().min(MAX_NAME_LEN);
        self.resources[idx].name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.resources[idx].name_len = copy_len;
        self.resources[idx].start = start;
        self.resources[idx].end = end;
        self.resources[idx].flags = flags;
        self.resources[idx].allocated = true;
        self.count += 1;
        Ok(idx)
    }

    /// Checks for conflicts with existing resources.
    fn check_conflict(&self, start: u64, end: u64, flag_type: u32) -> Result<()> {
        for r in &self.resources {
            if r.allocated
                && r.flags & flag_type != 0
                && r.flags & IORESOURCE_BUSY != 0
                && start <= r.end
                && end >= r.start
            {
                return Err(Error::Busy);
            }
        }
        Ok(())
    }

    /// Links a child resource under a parent.
    fn link_child(&mut self, parent: u32, child: u32) {
        if parent == NO_IDX {
            return;
        }
        let pi = parent as usize;
        if pi >= MAX_RESOURCES {
            return;
        }
        let old_first = self.resources[pi].child;
        self.resources[child as usize].sibling = old_first;
        self.resources[pi].child = child;
    }

    /// Unlinks a child resource from a parent.
    fn unlink_child(&mut self, parent: u32, child: u32) {
        if parent == NO_IDX {
            return;
        }
        let pi = parent as usize;
        if pi >= MAX_RESOURCES {
            return;
        }
        if self.resources[pi].child == child {
            self.resources[pi].child = self.resources[child as usize].sibling;
            return;
        }
        let mut cur = self.resources[pi].child;
        while cur != NO_IDX {
            let ci = cur as usize;
            if self.resources[ci].sibling == child {
                self.resources[ci].sibling = self.resources[child as usize].sibling;
                return;
            }
            cur = self.resources[ci].sibling;
        }
    }
}
