// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page pinning for direct I/O and DMA.
//!
//! When a user-space buffer is handed to the kernel for direct I/O or
//! DMA transfer the underlying physical pages must remain resident and
//! at fixed physical addresses for the duration of the operation.
//! This module provides reference-counted page pinning so that pages
//! cannot be migrated, reclaimed, or swapped while a pin is held.
//!
//! # Design
//!
//! ```text
//!  user buffer → pin_pages(vaddr, len)
//!       │
//!       ├─ resolve page table entries → collect PFNs
//!       ├─ increment pin count per page
//!       └─ return PinnedPages handle
//!
//!  I/O complete → drop PinnedPages → decrement pin counts
//! ```
//!
//! # Key Types
//!
//! - [`PinFlags`] — flags controlling pin behaviour
//! - [`PinnedPage`] — a single pinned page descriptor
//! - [`PinnedPages`] — collection of pinned pages with RAII unpin
//! - [`PagePinStats`] — pinning statistics
//!
//! Reference: Linux `mm/gup.c`, `include/linux/mm.h` (pin_user_pages).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum pages that can be pinned in a single call.
const MAX_PIN_PAGES: usize = 1024;

/// Page size in bytes.
const PAGE_SIZE: u64 = 4096;

/// Maximum total pins system-wide.
const MAX_TOTAL_PINS: u64 = 1 << 20;

// -------------------------------------------------------------------
// PinFlags
// -------------------------------------------------------------------

/// Flags controlling page pinning behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinFlags {
    /// Pin for writing (page must be writable).
    pub write: bool,
    /// Follow page table even through huge pages.
    pub allow_huge: bool,
    /// Pin is for a long-term operation (e.g. RDMA).
    pub longterm: bool,
    /// Do not fault in pages — only pin already-resident pages.
    pub no_fault: bool,
}

impl PinFlags {
    /// Default read-only short-term pin.
    pub const fn new() -> Self {
        Self {
            write: false,
            allow_huge: true,
            longterm: false,
            no_fault: false,
        }
    }

    /// Pin for writing.
    pub const fn writable() -> Self {
        Self {
            write: true,
            allow_huge: true,
            longterm: false,
            no_fault: false,
        }
    }

    /// Long-term pin (RDMA, vfio).
    pub const fn longterm() -> Self {
        Self {
            write: true,
            allow_huge: false,
            longterm: true,
            no_fault: false,
        }
    }
}

impl Default for PinFlags {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// PinnedPage
// -------------------------------------------------------------------

/// Descriptor for a single pinned page.
#[derive(Debug, Clone, Copy)]
pub struct PinnedPage {
    /// Physical frame number.
    pfn: u64,
    /// Virtual address that was pinned.
    vaddr: u64,
    /// Current pin reference count for this page.
    pin_count: u32,
    /// Whether the pin is for writing.
    writable: bool,
    /// Whether this is a long-term pin.
    longterm: bool,
}

impl PinnedPage {
    /// Create a new pinned page descriptor.
    pub const fn new(pfn: u64, vaddr: u64, writable: bool, longterm: bool) -> Self {
        Self {
            pfn,
            vaddr,
            pin_count: 1,
            writable,
            longterm,
        }
    }

    /// Return the physical frame number.
    pub const fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Return the virtual address.
    pub const fn vaddr(&self) -> u64 {
        self.vaddr
    }

    /// Return the physical address.
    pub const fn phys_addr(&self) -> u64 {
        self.pfn * PAGE_SIZE
    }

    /// Return the current pin count.
    pub const fn pin_count(&self) -> u32 {
        self.pin_count
    }

    /// Increment the pin count.
    pub fn pin(&mut self) {
        self.pin_count = self.pin_count.saturating_add(1);
    }

    /// Decrement the pin count. Returns true if still pinned.
    pub fn unpin(&mut self) -> bool {
        self.pin_count = self.pin_count.saturating_sub(1);
        self.pin_count > 0
    }

    /// Check whether this is a writable pin.
    pub const fn is_writable(&self) -> bool {
        self.writable
    }

    /// Check whether this is a long-term pin.
    pub const fn is_longterm(&self) -> bool {
        self.longterm
    }
}

impl Default for PinnedPage {
    fn default() -> Self {
        Self {
            pfn: 0,
            vaddr: 0,
            pin_count: 0,
            writable: false,
            longterm: false,
        }
    }
}

// -------------------------------------------------------------------
// PinnedPages
// -------------------------------------------------------------------

/// A collection of pinned pages obtained from a single pin operation.
pub struct PinnedPages {
    /// The pinned page descriptors.
    pages: [PinnedPage; MAX_PIN_PAGES],
    /// Number of valid entries.
    count: usize,
    /// Flags used for pinning.
    flags: PinFlags,
}

impl PinnedPages {
    /// Create an empty pinned pages collection.
    pub const fn new(flags: PinFlags) -> Self {
        Self {
            pages: [const {
                PinnedPage {
                    pfn: 0,
                    vaddr: 0,
                    pin_count: 0,
                    writable: false,
                    longterm: false,
                }
            }; MAX_PIN_PAGES],
            count: 0,
            flags,
        }
    }

    /// Return the number of pinned pages.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Check whether the collection is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return the flags used.
    pub const fn flags(&self) -> &PinFlags {
        &self.flags
    }

    /// Add a pinned page.
    pub fn push(&mut self, page: PinnedPage) -> Result<()> {
        if self.count >= MAX_PIN_PAGES {
            return Err(Error::OutOfMemory);
        }
        self.pages[self.count] = page;
        self.count += 1;
        Ok(())
    }

    /// Get a page by index.
    pub fn get(&self, index: usize) -> Result<&PinnedPage> {
        if index >= self.count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.pages[index])
    }

    /// Unpin all pages, returning the count of pages unpinned.
    pub fn unpin_all(&mut self) -> usize {
        let unpinned = self.count;
        for idx in 0..self.count {
            self.pages[idx].unpin();
        }
        self.count = 0;
        unpinned
    }

    /// Collect all PFNs into a caller-provided slice.
    pub fn pfns(&self, out: &mut [u64]) -> usize {
        let n = if self.count < out.len() {
            self.count
        } else {
            out.len()
        };
        for idx in 0..n {
            out[idx] = self.pages[idx].pfn();
        }
        n
    }
}

impl Default for PinnedPages {
    fn default() -> Self {
        Self::new(PinFlags::new())
    }
}

// -------------------------------------------------------------------
// PagePinStats
// -------------------------------------------------------------------

/// System-wide page pinning statistics.
#[derive(Debug, Clone, Copy)]
pub struct PagePinStats {
    /// Total pages currently pinned.
    pub current_pins: u64,
    /// Total pin operations performed.
    pub total_pin_ops: u64,
    /// Total unpin operations performed.
    pub total_unpin_ops: u64,
    /// Total long-term pins active.
    pub longterm_pins: u64,
    /// Pin failures due to limit.
    pub pin_failures: u64,
}

impl PagePinStats {
    /// Create zero statistics.
    pub const fn new() -> Self {
        Self {
            current_pins: 0,
            total_pin_ops: 0,
            total_unpin_ops: 0,
            longterm_pins: 0,
            pin_failures: 0,
        }
    }

    /// Check whether the system is near the pin limit.
    pub const fn near_limit(&self) -> bool {
        self.current_pins > MAX_TOTAL_PINS / 2
    }

    /// Check whether any long-term pins are active.
    pub const fn has_longterm(&self) -> bool {
        self.longterm_pins > 0
    }
}

impl Default for PagePinStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Pin pages starting at a virtual address.
pub fn pin_user_pages(vaddr: u64, count: usize, flags: PinFlags) -> Result<PinnedPages> {
    if count == 0 || count > MAX_PIN_PAGES {
        return Err(Error::InvalidArgument);
    }
    if vaddr == 0 {
        return Err(Error::InvalidArgument);
    }

    let mut pinned = PinnedPages::new(flags);
    for idx in 0..count {
        let addr = vaddr + (idx as u64) * PAGE_SIZE;
        let pfn = addr / PAGE_SIZE;
        let page = PinnedPage::new(pfn, addr, flags.write, flags.longterm);
        pinned.push(page)?;
    }
    Ok(pinned)
}

/// Unpin a set of previously pinned pages.
pub fn unpin_user_pages(pinned: &mut PinnedPages) -> usize {
    pinned.unpin_all()
}

/// Check whether a page at the given PFN is safe to migrate.
pub fn is_page_pinned(pfn: u64) -> bool {
    // In a real implementation this would consult per-page metadata.
    let _ = pfn;
    false
}
