// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Get User Pages (GUP) — pin user-space pages in physical memory.
//!
//! Provides infrastructure for pinning user-space pages so they remain
//! resident during DMA, I/O, or other kernel operations that require
//! stable physical addresses. This is the kernel-side implementation of
//! the `get_user_pages()` / `pin_user_pages()` family of functions.
//!
//! # Key concepts
//!
//! - **Pin**: increment a page's pin count so it cannot be migrated,
//!   swapped, or reclaimed while a kernel consumer holds it.
//! - **FOLL_PIN vs FOLL_GET**: `FOLL_PIN` uses elevated refcounts to
//!   distinguish pins from ordinary references; `FOLL_GET` uses plain
//!   page refcounts.
//! - **LONGTERM**: pins that persist across I/O operations; rejects
//!   pages in movable zones to avoid blocking compaction.
//!
//! # Subsystems
//!
//! - [`GupFlags`] — bitflags controlling pin behaviour
//! - [`PinnedPage`] — descriptor for a single pinned page
//! - [`PinnedPageSet`] — collection of pinned pages for one operation
//! - [`GupSubsystem`] — main manager for all active pin sets
//! - [`GupStats`] — aggregate counters
//!
//! Reference: Linux `mm/gup.c`, `include/linux/mm.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of pinned pages per set.
const MAX_PINNED_PER_SET: usize = 256;

/// Maximum number of active pin sets.
const MAX_PIN_SETS: usize = 64;

/// Maximum physical address for non-movable zone pages.
/// Pages above this threshold are considered movable and rejected
/// for FOLL_LONGTERM pins.
const MOVABLE_ZONE_START: u64 = 0x1_0000_0000; // 4 GiB

/// Invalid / unused pin set ID.
const INVALID_SET_ID: u32 = u32::MAX;

// -------------------------------------------------------------------
// GupFlags
// -------------------------------------------------------------------

/// Bitflags controlling GUP behaviour.
///
/// Multiple flags can be combined to fine-tune pinning semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GupFlags(u32);

impl GupFlags {
    /// Pin pages for writing (sets DIRTY on unpin).
    pub const WRITE: Self = Self(1 << 0);

    /// Long-term pin; rejects movable-zone pages.
    pub const LONGTERM: Self = Self(1 << 1);

    /// Non-blocking: fail immediately if pages are not resident.
    pub const NOWAIT: Self = Self(1 << 2);

    /// Use elevated pin-count semantics (`pin_user_pages`).
    pub const FOLL_PIN: Self = Self(1 << 3);

    /// Use plain page-reference semantics (`get_user_pages`).
    pub const FOLL_GET: Self = Self(1 << 4);

    /// Bypass VMA permission checks (e.g. for ptrace).
    pub const FOLL_FORCE: Self = Self(1 << 5);

    /// Create empty (zero) flags.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Combine two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Check whether specific flag bits are set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Return the raw u32 representation.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

// -------------------------------------------------------------------
// PinnedPage
// -------------------------------------------------------------------

/// Descriptor for a single page pinned in physical memory.
#[derive(Debug, Clone, Copy)]
pub struct PinnedPage {
    /// Physical address of the pinned page.
    phys_addr: u64,
    /// Virtual address in the user process.
    virt_addr: u64,
    /// Number of active pin references on this page.
    pin_count: u32,
    /// Flags that were used to pin this page.
    flags: GupFlags,
    /// Whether the page has been written while pinned.
    dirty: bool,
    /// Whether this slot is in use.
    active: bool,
}

impl PinnedPage {
    /// Create an empty (inactive) pinned-page descriptor.
    const fn empty() -> Self {
        Self {
            phys_addr: 0,
            virt_addr: 0,
            pin_count: 0,
            flags: GupFlags::empty(),
            dirty: false,
            active: false,
        }
    }

    /// Physical address of the pinned page.
    pub const fn phys_addr(&self) -> u64 {
        self.phys_addr
    }

    /// Virtual address in the originating process.
    pub const fn virt_addr(&self) -> u64 {
        self.virt_addr
    }

    /// Current pin reference count.
    pub const fn pin_count(&self) -> u32 {
        self.pin_count
    }

    /// Flags used when pinning.
    pub const fn flags(&self) -> GupFlags {
        self.flags
    }

    /// Whether the page was written while pinned.
    pub const fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Whether this descriptor is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Mark the page dirty (written by kernel consumer).
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }
}

impl Default for PinnedPage {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// PinnedPageSet
// -------------------------------------------------------------------

/// A set of pages pinned for a single GUP operation.
///
/// Each set is identified by an `id` and holds up to
/// [`MAX_PINNED_PER_SET`] pinned page descriptors.
pub struct PinnedPageSet {
    /// Unique identifier for this pin set.
    id: u32,
    /// Owning memory-map (address space) identifier.
    mm_id: u64,
    /// Pinned pages in this set.
    pages: [PinnedPage; MAX_PINNED_PER_SET],
    /// Number of pages currently pinned in this set.
    total_pinned: u32,
    /// Flags applied to the entire set.
    flags: GupFlags,
    /// Whether this set is in use.
    active: bool,
}

impl PinnedPageSet {
    /// Create an empty (inactive) pin set.
    const fn empty() -> Self {
        Self {
            id: INVALID_SET_ID,
            mm_id: 0,
            pages: [PinnedPage::empty(); MAX_PINNED_PER_SET],
            total_pinned: 0,
            flags: GupFlags::empty(),
            active: false,
        }
    }

    /// Pin set identifier.
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Owning address-space ID.
    pub const fn mm_id(&self) -> u64 {
        self.mm_id
    }

    /// Number of pages currently pinned.
    pub const fn total_pinned(&self) -> u32 {
        self.total_pinned
    }

    /// Whether this set is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Read-only access to the pinned pages array.
    pub fn pages(&self) -> &[PinnedPage] {
        &self.pages[..self.total_pinned as usize]
    }

    /// Add a page to this set.
    ///
    /// Returns `Err(OutOfMemory)` if the set is full.
    fn add_page(&mut self, phys_addr: u64, virt_addr: u64, flags: GupFlags) -> Result<()> {
        if self.total_pinned as usize >= MAX_PINNED_PER_SET {
            return Err(Error::OutOfMemory);
        }
        let idx = self.total_pinned as usize;
        self.pages[idx] = PinnedPage {
            phys_addr,
            virt_addr,
            pin_count: 1,
            flags,
            dirty: false,
            active: true,
        };
        self.total_pinned += 1;
        Ok(())
    }

    /// Unpin all pages in this set.
    ///
    /// If `WRITE` flag is set, pages are marked dirty before unpin.
    fn unpin_all(&mut self) -> u32 {
        let count = self.total_pinned;
        for i in 0..self.total_pinned as usize {
            if self.pages[i].active {
                if self.flags.contains(GupFlags::WRITE) {
                    self.pages[i].dirty = true;
                }
                self.pages[i].pin_count = 0;
                self.pages[i].active = false;
            }
        }
        self.total_pinned = 0;
        self.active = false;
        count
    }
}

impl Default for PinnedPageSet {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// GupStats
// -------------------------------------------------------------------

/// Aggregate GUP statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct GupStats {
    /// Total pages pinned since boot.
    pub total_pinned: u64,
    /// Total pages unpinned since boot.
    pub total_unpinned: u64,
    /// Total faults triggered during GUP.
    pub total_faults: u64,
    /// Number of active long-term pins.
    pub longterm_pins: u64,
    /// Number of pin operations rejected (e.g. movable zone).
    pub rejected: u64,
    /// Number of active pin sets.
    pub active_sets: u32,
}

// -------------------------------------------------------------------
// GupSubsystem
// -------------------------------------------------------------------

/// Main GUP subsystem managing all active page-pin sets.
///
/// Provides `get_user_pages()` and `put_user_pages()` entry points,
/// managing up to [`MAX_PIN_SETS`] concurrent pin operations.
pub struct GupSubsystem {
    /// All pin sets (active and free).
    page_sets: [PinnedPageSet; MAX_PIN_SETS],
    /// Next set ID to assign.
    next_id: u32,
    /// Aggregate statistics.
    stats: GupStats,
}

impl GupSubsystem {
    /// Create a new GUP subsystem with all sets inactive.
    pub const fn new() -> Self {
        Self {
            page_sets: [const { PinnedPageSet::empty() }; MAX_PIN_SETS],
            next_id: 0,
            stats: GupStats {
                total_pinned: 0,
                total_unpinned: 0,
                total_faults: 0,
                longterm_pins: 0,
                rejected: 0,
                active_sets: 0,
            },
        }
    }

    /// Return current statistics.
    pub const fn stats(&self) -> &GupStats {
        &self.stats
    }

    /// Find a free pin-set slot index.
    fn find_free_slot(&self) -> Option<usize> {
        self.page_sets.iter().position(|s| !s.active)
    }

    /// Validate GUP flags for consistency.
    fn validate_flags(flags: GupFlags) -> Result<()> {
        // Cannot set both FOLL_PIN and FOLL_GET simultaneously.
        if flags.contains(GupFlags::FOLL_PIN) && flags.contains(GupFlags::FOLL_GET) {
            return Err(Error::InvalidArgument);
        }
        // Must specify at least one of FOLL_PIN or FOLL_GET.
        if !flags.contains(GupFlags::FOLL_PIN) && !flags.contains(GupFlags::FOLL_GET) {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Check whether a physical address is in the movable zone.
    fn is_in_movable_zone(phys_addr: u64) -> bool {
        phys_addr >= MOVABLE_ZONE_START
    }

    /// Pin user-space pages starting at `start_addr` for `nr_pages`.
    ///
    /// # Arguments
    ///
    /// * `mm_id` — address-space identifier of the target process
    /// * `start_addr` — starting virtual address (must be page-aligned)
    /// * `nr_pages` — number of consecutive pages to pin
    /// * `flags` — GUP flags controlling pin behaviour
    ///
    /// # Returns
    ///
    /// The pin-set ID on success, which can be passed to
    /// [`put_user_pages`] to release the pins.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — flags are inconsistent, address is
    ///   unaligned, or `nr_pages` is zero / too large
    /// * `OutOfMemory` — no free pin-set slot or set is full
    /// * `PermissionDenied` — `FOLL_LONGTERM` rejects a movable page
    pub fn pin_user_pages(
        &mut self,
        mm_id: u64,
        start_addr: u64,
        nr_pages: u32,
        flags: GupFlags,
    ) -> Result<u32> {
        // Validate inputs.
        Self::validate_flags(flags)?;
        if nr_pages == 0 || nr_pages as usize > MAX_PINNED_PER_SET {
            return Err(Error::InvalidArgument);
        }
        if start_addr % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }

        // Find a free slot.
        let slot_idx = self.find_free_slot().ok_or(Error::OutOfMemory)?;

        // Assign an ID.
        let set_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        // Initialise the set.
        self.page_sets[slot_idx].id = set_id;
        self.page_sets[slot_idx].mm_id = mm_id;
        self.page_sets[slot_idx].flags = flags;
        self.page_sets[slot_idx].active = true;
        self.page_sets[slot_idx].total_pinned = 0;

        // Pin each page.
        for page_idx in 0..nr_pages {
            let virt_addr = start_addr + u64::from(page_idx) * PAGE_SIZE;

            // Simulate page-table walk to obtain physical address.
            // In a real implementation this would walk the user's
            // page tables and potentially fault in missing pages.
            let phys_addr = self.resolve_user_page(mm_id, virt_addr, flags)?;

            // FOLL_LONGTERM rejects pages in movable zones.
            if flags.contains(GupFlags::LONGTERM) && Self::is_in_movable_zone(phys_addr) {
                // Rollback pages already pinned in this set.
                self.page_sets[slot_idx].unpin_all();
                self.page_sets[slot_idx].active = false;
                self.stats.rejected += 1;
                return Err(Error::PermissionDenied);
            }

            self.page_sets[slot_idx].add_page(phys_addr, virt_addr, flags)?;
            self.stats.total_pinned += 1;

            if flags.contains(GupFlags::LONGTERM) {
                self.stats.longterm_pins += 1;
            }
        }

        self.stats.active_sets += 1;
        Ok(set_id)
    }

    /// Release all pages in a pin set.
    ///
    /// If the set was pinned with [`GupFlags::WRITE`], pages are
    /// marked dirty before being unpinned.
    ///
    /// # Errors
    ///
    /// * `NotFound` — no active set with the given ID
    pub fn unpin_user_pages(&mut self, pin_set_id: u32) -> Result<()> {
        let idx = self.find_set_index(pin_set_id)?;

        let was_longterm = self.page_sets[idx].flags.contains(GupFlags::LONGTERM);
        let count = self.page_sets[idx].total_pinned;
        self.page_sets[idx].unpin_all();

        self.stats.total_unpinned += u64::from(count);
        if was_longterm {
            self.stats.longterm_pins = self.stats.longterm_pins.saturating_sub(u64::from(count));
        }
        if self.stats.active_sets > 0 {
            self.stats.active_sets -= 1;
        }

        Ok(())
    }

    /// Get immutable access to a pin set by ID.
    ///
    /// # Errors
    ///
    /// * `NotFound` — no active set with the given ID
    pub fn get_pin_set(&self, pin_set_id: u32) -> Result<&PinnedPageSet> {
        let idx = self.find_set_index_ro(pin_set_id)?;
        Ok(&self.page_sets[idx])
    }

    /// Mark a specific page in a pin set as dirty.
    ///
    /// # Errors
    ///
    /// * `NotFound` — set or page index not found
    /// * `InvalidArgument` — `page_idx` out of range
    pub fn mark_page_dirty(&mut self, pin_set_id: u32, page_idx: u32) -> Result<()> {
        let set_idx = self.find_set_index(pin_set_id)?;
        let pinned = self.page_sets[set_idx].total_pinned;
        if page_idx >= pinned {
            return Err(Error::InvalidArgument);
        }
        self.page_sets[set_idx].pages[page_idx as usize].mark_dirty();
        Ok(())
    }

    /// Count the number of dirty pages in a pin set.
    pub fn count_dirty_pages(&self, pin_set_id: u32) -> Result<u32> {
        let idx = self.find_set_index_ro(pin_set_id)?;
        let count = self.page_sets[idx]
            .pages()
            .iter()
            .filter(|p| p.dirty)
            .count() as u32;
        Ok(count)
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Find the slot index for an active set by ID (mutable path).
    fn find_set_index(&self, pin_set_id: u32) -> Result<usize> {
        self.page_sets
            .iter()
            .position(|s| s.active && s.id == pin_set_id)
            .ok_or(Error::NotFound)
    }

    /// Find the slot index for an active set by ID (read-only path).
    fn find_set_index_ro(&self, pin_set_id: u32) -> Result<usize> {
        self.find_set_index(pin_set_id)
    }

    /// Simulate resolving a user virtual address to a physical address.
    ///
    /// In a complete kernel this would walk the process page tables,
    /// handle faults (unless `NOWAIT` is set), and return the physical
    /// address of the resolved frame.
    fn resolve_user_page(&mut self, _mm_id: u64, virt_addr: u64, flags: GupFlags) -> Result<u64> {
        // For now, simulate a simple identity-like mapping with an
        // offset. Real implementation replaces this with a page-table
        // walk.
        if flags.contains(GupFlags::NOWAIT) {
            // NOWAIT: if page is not immediately present, fail.
            // Simulate: all pages are resident for now.
        }

        // Record a fault event for statistics.
        self.stats.total_faults += 1;

        // Simulated physical address (not identity-mapped; offset by
        // a kernel-space base so it looks plausible).
        let phys = virt_addr & 0x0000_FFFF_FFFF_F000;
        Ok(phys)
    }
}

impl Default for GupSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// get_user_pages / put_user_pages free functions
// -------------------------------------------------------------------

/// Pin `nr_pages` user pages starting at `start_addr`.
///
/// Convenience wrapper around [`GupSubsystem::pin_user_pages`].
///
/// # Errors
///
/// See [`GupSubsystem::pin_user_pages`].
pub fn get_user_pages(
    subsys: &mut GupSubsystem,
    mm_id: u64,
    start_addr: u64,
    nr_pages: u32,
    flags: GupFlags,
) -> Result<u32> {
    subsys.pin_user_pages(mm_id, start_addr, nr_pages, flags)
}

/// Unpin all pages in a pin set, marking dirty pages if appropriate.
///
/// Convenience wrapper around [`GupSubsystem::unpin_user_pages`].
///
/// # Errors
///
/// See [`GupSubsystem::unpin_user_pages`].
pub fn put_user_pages(subsys: &mut GupSubsystem, pin_set_id: u32) -> Result<()> {
    subsys.unpin_user_pages(pin_set_id)
}

// -------------------------------------------------------------------
// Display / diagnostics
// -------------------------------------------------------------------

/// Format GUP statistics into the provided buffer.
///
/// Returns the number of bytes written, or `Err(OutOfMemory)` if
/// the buffer is too small.
pub fn format_gup_stats(stats: &GupStats, buf: &mut [u8]) -> Result<usize> {
    // Minimal fixed-format output for kernel log/procfs.
    let lines: [(&str, u64); 6] = [
        ("total_pinned:   ", stats.total_pinned),
        ("total_unpinned: ", stats.total_unpinned),
        ("total_faults:   ", stats.total_faults),
        ("longterm_pins:  ", stats.longterm_pins),
        ("rejected:       ", stats.rejected),
        ("active_sets:    ", u64::from(stats.active_sets)),
    ];

    let mut pos = 0usize;
    for (label, value) in &lines {
        let label_bytes = label.as_bytes();
        if pos + label_bytes.len() + 20 + 1 > buf.len() {
            return Err(Error::OutOfMemory);
        }
        buf[pos..pos + label_bytes.len()].copy_from_slice(label_bytes);
        pos += label_bytes.len();
        pos += write_u64_decimal(&mut buf[pos..], *value);
        buf[pos] = b'\n';
        pos += 1;
    }
    Ok(pos)
}

/// Write a `u64` as decimal ASCII into `buf`, returning bytes written.
fn write_u64_decimal(buf: &mut [u8], mut val: u64) -> usize {
    if val == 0 {
        if !buf.is_empty() {
            buf[0] = b'0';
        }
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut len = 0usize;
    while val > 0 {
        tmp[len] = b'0' + (val % 10) as u8;
        val /= 10;
        len += 1;
    }
    for i in 0..len {
        if i < buf.len() {
            buf[i] = tmp[len - 1 - i];
        }
    }
    len
}
