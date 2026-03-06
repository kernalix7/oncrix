// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Physical frame and virtual page types.

use crate::addr::{PAGE_SIZE, PhysAddr, VirtAddr};

/// A physical page frame (4 KiB aligned region of physical memory).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Frame {
    /// Frame number (physical address >> 12).
    number: u64,
}

impl Frame {
    /// Create a frame from a page-aligned physical address.
    ///
    /// Returns `None` if the address is not page-aligned.
    pub const fn from_addr(addr: PhysAddr) -> Option<Self> {
        if !addr.is_aligned() {
            return None;
        }
        Some(Self {
            number: addr.as_u64() / PAGE_SIZE as u64,
        })
    }

    /// Create a frame from a frame number.
    pub const fn from_number(number: u64) -> Self {
        Self { number }
    }

    /// Create a frame containing the given physical address.
    pub const fn containing(addr: PhysAddr) -> Self {
        Self {
            number: addr.as_u64() / PAGE_SIZE as u64,
        }
    }

    /// Return the frame number.
    pub const fn number(self) -> u64 {
        self.number
    }

    /// Return the start physical address of this frame.
    pub const fn start_addr(self) -> PhysAddr {
        PhysAddr::new(self.number * PAGE_SIZE as u64)
    }
}

/// A virtual memory page (4 KiB aligned region of virtual memory).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Page {
    /// Page number (virtual address >> 12).
    number: u64,
}

impl Page {
    /// Create a page from a page-aligned virtual address.
    ///
    /// Returns `None` if the address is not page-aligned.
    pub const fn from_addr(addr: VirtAddr) -> Option<Self> {
        if !addr.is_aligned() {
            return None;
        }
        Some(Self {
            number: addr.as_u64() / PAGE_SIZE as u64,
        })
    }

    /// Create a page containing the given virtual address.
    pub const fn containing(addr: VirtAddr) -> Self {
        Self {
            number: addr.as_u64() / PAGE_SIZE as u64,
        }
    }

    /// Return the page number.
    pub const fn number(self) -> u64 {
        self.number
    }

    /// Return the start virtual address of this page.
    pub const fn start_addr(self) -> VirtAddr {
        VirtAddr::new(self.number * PAGE_SIZE as u64)
    }
}

/// Trait for physical frame allocators.
///
/// The kernel's memory manager implements this to hand out
/// free physical frames for page table construction and
/// general allocation.
pub trait FrameAllocator {
    /// Allocate a single physical frame.
    ///
    /// Returns `None` if no frames are available.
    fn allocate_frame(&mut self) -> Option<Frame>;

    /// Deallocate a previously allocated frame.
    fn deallocate_frame(&mut self, frame: Frame);

    /// Return the number of free frames available.
    fn free_frames(&self) -> usize;
}
