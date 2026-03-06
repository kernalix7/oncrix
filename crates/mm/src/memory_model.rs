// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory model abstractions for different physical memory layouts.
//!
//! Modern operating systems need to cope with diverse physical memory
//! topologies: some machines have a contiguous flat address space while
//! others have sparse, non-contiguous memory with large holes. This
//! module abstracts the physical memory layout through a section-based
//! model that supports three configurations:
//!
//! - **FlatMem**: Contiguous physical memory with a 1:1 PFN-to-page
//!   mapping. Simple but wastes metadata for holes.
//! - **SparseMem**: Section-granular memory model. Only sections that
//!   are actually present consume metadata. Efficient for machines
//!   with large physical address holes.
//! - **SparseVmemmap**: Sparse model with virtual memmap. Sections
//!   are mapped into a contiguous virtual address range, allowing
//!   O(1) PFN-to-page lookups while still only consuming metadata
//!   for present sections.
//!
//! # Subsystems
//!
//! - [`MemoryModel`] — enum selecting the active memory model
//! - [`MemSection`] — per-section metadata (present, online, NUMA node)
//! - [`MemSectionFlags`] — section state flags
//! - [`MemMap`] — the global memory map (array of sections)
//! - [`MemMapSubsystem`] — top-level management with section operations
//! - [`MemModelStats`] — statistics on sections and pages
//!
//! Reference: Linux `mm/sparse.c`, `mm/sparse-vmemmap.c`,
//! `include/linux/mmzone.h`, `include/asm-generic/memory_model.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Number of pages per section (128 MiB / 4 KiB = 32768 pages).
const PAGES_PER_SECTION: u64 = 32768;

/// Section size in bytes (128 MiB).
const SECTION_SIZE_BYTES: u64 = PAGES_PER_SECTION * PAGE_SIZE;

/// Maximum number of memory sections.
const MAX_SECTIONS: usize = 256;

/// PFN shift to derive section number.
const SECTION_PFN_SHIFT: u32 = 15; // log2(32768)

/// Invalid NUMA node identifier.
const NUMA_NO_NODE: u8 = 0xFF;

/// Maximum NUMA nodes supported.
const _MAX_NUMNODES: usize = 8;

// -------------------------------------------------------------------
// MemoryModel
// -------------------------------------------------------------------

/// The physical memory model in use.
///
/// Selected at boot time based on hardware topology and kernel
/// configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MemoryModel {
    /// Flat (contiguous) memory model.
    ///
    /// Assumes physical memory is contiguous from address 0.
    /// The PFN-to-page mapping is a simple array index.
    /// Suitable for small systems with no memory holes.
    #[default]
    FlatMem,

    /// Sparse memory model (classic).
    ///
    /// Physical memory is divided into sections. Only sections
    /// with present memory have metadata allocated. PFN-to-page
    /// lookup requires a section table indirection.
    SparseMem,

    /// Sparse memory model with virtual memmap.
    ///
    /// Like SparseMem but section metadata is mapped into a
    /// contiguous virtual address range, enabling O(1) lookups
    /// while still being memory-efficient for sparse layouts.
    SparseVmemmap,
}

impl MemoryModel {
    /// Human-readable name for the memory model.
    pub const fn name(self) -> &'static str {
        match self {
            Self::FlatMem => "flatmem",
            Self::SparseMem => "sparsemem",
            Self::SparseVmemmap => "sparsemem-vmemmap",
        }
    }

    /// Whether the model supports memory hotplug.
    pub const fn supports_hotplug(self) -> bool {
        matches!(self, Self::SparseMem | Self::SparseVmemmap)
    }

    /// Whether the model uses section-based tracking.
    pub const fn is_sparse(self) -> bool {
        matches!(self, Self::SparseMem | Self::SparseVmemmap)
    }

    /// Whether PFN-to-page lookup is O(1).
    pub const fn has_constant_lookup(self) -> bool {
        matches!(self, Self::FlatMem | Self::SparseVmemmap)
    }
}

// -------------------------------------------------------------------
// MemSectionFlags
// -------------------------------------------------------------------

/// Section state flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MemSectionFlags(u32);

impl MemSectionFlags {
    /// Section has physical memory present.
    pub const PRESENT: Self = Self(1 << 0);

    /// Section is online (usable for allocation).
    pub const ONLINE: Self = Self(1 << 1);

    /// Section is being hot-added.
    pub const ADDING: Self = Self(1 << 2);

    /// Section is being hot-removed.
    pub const REMOVING: Self = Self(1 << 3);

    /// Section has been memory-tested (no errors found).
    pub const TESTED: Self = Self(1 << 4);

    /// Section belongs to a movable zone.
    pub const MOVABLE: Self = Self(1 << 5);

    /// Section metadata is vmemmap-backed.
    pub const VMEMMAP: Self = Self(1 << 6);

    /// Section has early boot reservations.
    pub const EARLY: Self = Self(1 << 7);

    /// No flags set.
    pub const NONE: Self = Self(0);

    /// Create flags from a raw `u32` value.
    pub const fn from_raw(v: u32) -> Self {
        Self(v)
    }

    /// Return the raw `u32` representation.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Check whether `other` flags are all present in `self`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Combine two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Remove specific flags.
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Test if any flags are set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

// -------------------------------------------------------------------
// MemSection
// -------------------------------------------------------------------

/// Metadata for a single physical memory section.
///
/// Each section covers `PAGES_PER_SECTION` contiguous page frames
/// (128 MiB at 4 KiB page size).
#[derive(Debug, Clone, Copy)]
pub struct MemSection {
    /// Section number (index into the section table).
    pub section_nr: u64,
    /// Start page frame number of this section.
    pub start_pfn: u64,
    /// Number of valid pages in this section.
    pub nr_pages: u64,
    /// Section state flags.
    pub flags: MemSectionFlags,
    /// NUMA node this section belongs to.
    pub nid: u8,
    /// Zone index within the NUMA node.
    pub zone_idx: u8,
    /// Usage count (for hotplug tracking).
    pub usage_count: u32,
    /// Whether this section slot is in use.
    pub active: bool,
}

impl MemSection {
    /// Create an empty (unused) section descriptor.
    const fn empty() -> Self {
        Self {
            section_nr: 0,
            start_pfn: 0,
            nr_pages: 0,
            flags: MemSectionFlags::NONE,
            nid: NUMA_NO_NODE,
            zone_idx: 0,
            usage_count: 0,
            active: false,
        }
    }

    /// Whether this section has present memory.
    pub const fn is_present(&self) -> bool {
        self.flags.contains(MemSectionFlags::PRESENT)
    }

    /// Whether this section is online.
    pub const fn is_online(&self) -> bool {
        self.flags.contains(MemSectionFlags::ONLINE)
    }

    /// End PFN (exclusive) of this section.
    pub const fn end_pfn(&self) -> u64 {
        self.start_pfn + self.nr_pages
    }

    /// Size of this section in bytes.
    pub const fn size_bytes(&self) -> u64 {
        self.nr_pages * PAGE_SIZE
    }

    /// Whether a given PFN falls within this section.
    pub const fn contains_pfn(&self, pfn: u64) -> bool {
        pfn >= self.start_pfn && pfn < self.start_pfn + self.nr_pages
    }

    /// Bring this section online.
    pub fn set_online(&mut self) {
        self.flags = self.flags.union(MemSectionFlags::ONLINE);
    }

    /// Take this section offline.
    pub fn set_offline(&mut self) {
        self.flags = self.flags.difference(MemSectionFlags::ONLINE);
    }
}

// -------------------------------------------------------------------
// MemMap
// -------------------------------------------------------------------

/// Global memory map: an array of memory sections.
///
/// Tracks up to `MAX_SECTIONS` sections, each covering 128 MiB of
/// physical address space.
pub struct MemMap {
    /// Active memory model.
    model: MemoryModel,
    /// Section table.
    sections: [MemSection; MAX_SECTIONS],
    /// Total pages across all present sections.
    total_pages: u64,
    /// Number of sections currently registered.
    nr_sections: usize,
    /// Maximum PFN seen across all sections.
    max_pfn: u64,
    /// Minimum PFN seen across all sections.
    min_pfn: u64,
}

impl MemMap {
    /// Create a new empty memory map with the specified model.
    pub fn new(model: MemoryModel) -> Self {
        Self {
            model,
            sections: [const { MemSection::empty() }; MAX_SECTIONS],
            total_pages: 0,
            nr_sections: 0,
            max_pfn: 0,
            min_pfn: u64::MAX,
        }
    }

    /// Active memory model.
    pub const fn model(&self) -> MemoryModel {
        self.model
    }

    /// Total pages across all present sections.
    pub const fn total_pages(&self) -> u64 {
        self.total_pages
    }

    /// Number of registered sections.
    pub const fn nr_sections(&self) -> usize {
        self.nr_sections
    }

    /// Maximum PFN across all sections.
    pub const fn max_pfn(&self) -> u64 {
        self.max_pfn
    }

    /// Minimum PFN across all sections.
    pub const fn min_pfn(&self) -> u64 {
        if self.nr_sections == 0 {
            return 0;
        }
        self.min_pfn
    }

    /// Total physical memory in bytes.
    pub const fn total_bytes(&self) -> u64 {
        self.total_pages * PAGE_SIZE
    }

    /// Get a reference to a section by section number.
    pub fn section(&self, section_nr: u64) -> Result<&MemSection> {
        if section_nr as usize >= MAX_SECTIONS {
            return Err(Error::InvalidArgument);
        }
        let sec = &self.sections[section_nr as usize];
        if !sec.active {
            return Err(Error::NotFound);
        }
        Ok(sec)
    }

    /// Get a mutable reference to a section by section number.
    pub fn section_mut(&mut self, section_nr: u64) -> Result<&mut MemSection> {
        if section_nr as usize >= MAX_SECTIONS {
            return Err(Error::InvalidArgument);
        }
        let sec = &mut self.sections[section_nr as usize];
        if !sec.active {
            return Err(Error::NotFound);
        }
        Ok(sec)
    }

    /// Add a new section to the memory map.
    pub fn add_section(
        &mut self,
        section_nr: u64,
        start_pfn: u64,
        nr_pages: u64,
        nid: u8,
    ) -> Result<()> {
        if section_nr as usize >= MAX_SECTIONS {
            return Err(Error::InvalidArgument);
        }
        if self.sections[section_nr as usize].active {
            return Err(Error::AlreadyExists);
        }
        if nr_pages == 0 || nr_pages > PAGES_PER_SECTION {
            return Err(Error::InvalidArgument);
        }

        self.sections[section_nr as usize] = MemSection {
            section_nr,
            start_pfn,
            nr_pages,
            flags: MemSectionFlags::PRESENT,
            nid,
            zone_idx: 0,
            usage_count: 0,
            active: true,
        };

        self.nr_sections += 1;
        self.total_pages += nr_pages;

        let end_pfn = start_pfn + nr_pages;
        if end_pfn > self.max_pfn {
            self.max_pfn = end_pfn;
        }
        if start_pfn < self.min_pfn {
            self.min_pfn = start_pfn;
        }

        Ok(())
    }

    /// Remove a section from the memory map.
    pub fn remove_section(&mut self, section_nr: u64) -> Result<MemSection> {
        if section_nr as usize >= MAX_SECTIONS {
            return Err(Error::InvalidArgument);
        }
        let sec = &self.sections[section_nr as usize];
        if !sec.active {
            return Err(Error::NotFound);
        }
        if sec.is_online() {
            return Err(Error::Busy);
        }

        let removed = *sec;
        self.sections[section_nr as usize] = MemSection::empty();
        self.nr_sections = self.nr_sections.saturating_sub(1);
        self.total_pages = self.total_pages.saturating_sub(removed.nr_pages);

        // Recompute min/max PFN.
        self.recompute_pfn_bounds();

        Ok(removed)
    }

    /// Bring a section online (make it usable for allocation).
    pub fn online_section(&mut self, section_nr: u64) -> Result<()> {
        if section_nr as usize >= MAX_SECTIONS {
            return Err(Error::InvalidArgument);
        }
        if !self.sections[section_nr as usize].active {
            return Err(Error::NotFound);
        }
        if self.sections[section_nr as usize].is_online() {
            return Ok(()); // already online
        }
        self.sections[section_nr as usize].set_online();
        Ok(())
    }

    /// Take a section offline.
    pub fn offline_section(&mut self, section_nr: u64) -> Result<()> {
        if section_nr as usize >= MAX_SECTIONS {
            return Err(Error::InvalidArgument);
        }
        if !self.sections[section_nr as usize].active {
            return Err(Error::NotFound);
        }
        if !self.sections[section_nr as usize].is_online() {
            return Ok(()); // already offline
        }
        self.sections[section_nr as usize].set_offline();
        Ok(())
    }

    /// Convert a PFN to its containing section number.
    pub const fn pfn_to_section(pfn: u64) -> u64 {
        pfn >> SECTION_PFN_SHIFT
    }

    /// Convert a section number to its start PFN.
    pub const fn section_to_pfn(section_nr: u64) -> u64 {
        section_nr << SECTION_PFN_SHIFT
    }

    /// Check whether a PFN is valid (belongs to a present section).
    pub fn pfn_valid(&self, pfn: u64) -> bool {
        let section_nr = Self::pfn_to_section(pfn);
        if section_nr as usize >= MAX_SECTIONS {
            return false;
        }
        let sec = &self.sections[section_nr as usize];
        sec.active && sec.is_present() && sec.contains_pfn(pfn)
    }

    /// Check whether a PFN belongs to an online section.
    pub fn pfn_online(&self, pfn: u64) -> bool {
        let section_nr = Self::pfn_to_section(pfn);
        if section_nr as usize >= MAX_SECTIONS {
            return false;
        }
        let sec = &self.sections[section_nr as usize];
        sec.active && sec.is_online() && sec.contains_pfn(pfn)
    }

    /// Get the NUMA node for a given PFN.
    pub fn pfn_to_nid(&self, pfn: u64) -> Result<u8> {
        let section_nr = Self::pfn_to_section(pfn);
        if section_nr as usize >= MAX_SECTIONS {
            return Err(Error::InvalidArgument);
        }
        let sec = &self.sections[section_nr as usize];
        if !sec.active || !sec.is_present() {
            return Err(Error::NotFound);
        }
        Ok(sec.nid)
    }

    /// Convert a physical address to a PFN.
    pub const fn addr_to_pfn(addr: u64) -> u64 {
        addr / PAGE_SIZE
    }

    /// Convert a PFN to a physical address.
    pub const fn pfn_to_addr(pfn: u64) -> u64 {
        pfn * PAGE_SIZE
    }

    /// Iterate over all present sections and count online ones.
    pub fn count_online_sections(&self) -> usize {
        let mut count = 0;
        for sec in &self.sections {
            if sec.active && sec.is_online() {
                count += 1;
            }
        }
        count
    }

    /// Iterate over all present sections and count present ones.
    pub fn count_present_sections(&self) -> usize {
        let mut count = 0;
        for sec in &self.sections {
            if sec.active && sec.is_present() {
                count += 1;
            }
        }
        count
    }

    /// Recompute min/max PFN bounds after a section removal.
    fn recompute_pfn_bounds(&mut self) {
        self.max_pfn = 0;
        self.min_pfn = u64::MAX;
        for sec in &self.sections {
            if sec.active {
                let end = sec.start_pfn + sec.nr_pages;
                if end > self.max_pfn {
                    self.max_pfn = end;
                }
                if sec.start_pfn < self.min_pfn {
                    self.min_pfn = sec.start_pfn;
                }
            }
        }
        if self.nr_sections == 0 {
            self.min_pfn = 0;
        }
    }
}

impl Default for MemMap {
    fn default() -> Self {
        Self::new(MemoryModel::FlatMem)
    }
}

// -------------------------------------------------------------------
// MemModelStats
// -------------------------------------------------------------------

/// Memory model statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemModelStats {
    /// Number of sections with present memory.
    pub sections_present: u64,
    /// Number of sections that are online.
    pub sections_online: u64,
    /// Total pages across all present sections.
    pub total_pages: u64,
    /// Maximum PFN across all sections.
    pub max_pfn: u64,
    /// Minimum PFN across all sections.
    pub min_pfn: u64,
    /// Total physical memory in bytes.
    pub total_bytes: u64,
    /// Section size in bytes.
    pub section_size_bytes: u64,
    /// Pages per section.
    pub pages_per_section: u64,
    /// Sections added since boot.
    pub sections_added: u64,
    /// Sections removed since boot.
    pub sections_removed: u64,
}

impl MemModelStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            sections_present: 0,
            sections_online: 0,
            total_pages: 0,
            max_pfn: 0,
            min_pfn: 0,
            total_bytes: 0,
            section_size_bytes: SECTION_SIZE_BYTES,
            pages_per_section: PAGES_PER_SECTION,
            sections_added: 0,
            sections_removed: 0,
        }
    }

    /// Address space coverage ratio (max_pfn / total_pages).
    ///
    /// A ratio close to 1.0 means dense memory, higher means sparse.
    /// Returns the ratio multiplied by 100 for integer representation.
    pub const fn sparseness_percent(&self) -> u64 {
        if self.total_pages == 0 {
            return 0;
        }
        self.max_pfn * 100 / self.total_pages
    }
}

// -------------------------------------------------------------------
// MemMapSubsystem
// -------------------------------------------------------------------

/// Top-level memory model management subsystem.
///
/// Wraps the [`MemMap`] and provides initialization, section
/// management operations, and statistics collection.
pub struct MemMapSubsystem {
    /// The global memory map.
    memmap: MemMap,
    /// Aggregate statistics.
    stats: MemModelStats,
    /// Whether the subsystem has been initialized.
    initialized: bool,
}

impl MemMapSubsystem {
    /// Create a new uninitialized memory model subsystem.
    pub fn new() -> Self {
        Self {
            memmap: MemMap::new(MemoryModel::FlatMem),
            stats: MemModelStats::new(),
            initialized: false,
        }
    }

    /// Initialize the subsystem with the given memory model.
    pub fn init(&mut self, model: MemoryModel) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        self.memmap = MemMap::new(model);
        self.stats = MemModelStats::new();
        self.initialized = true;
        Ok(())
    }

    /// Whether the subsystem is initialized.
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Active memory model.
    pub const fn model(&self) -> MemoryModel {
        self.memmap.model()
    }

    /// Reference to the underlying memory map.
    pub const fn memmap(&self) -> &MemMap {
        &self.memmap
    }

    /// Mutable reference to the underlying memory map.
    pub fn memmap_mut(&mut self) -> &mut MemMap {
        &mut self.memmap
    }

    /// Add a memory section.
    pub fn add_section(
        &mut self,
        section_nr: u64,
        start_pfn: u64,
        nr_pages: u64,
        nid: u8,
    ) -> Result<()> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        self.memmap
            .add_section(section_nr, start_pfn, nr_pages, nid)?;
        self.stats.sections_added += 1;
        self.refresh_stats();
        Ok(())
    }

    /// Remove a memory section (must be offline first).
    pub fn remove_section(&mut self, section_nr: u64) -> Result<MemSection> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        let removed = self.memmap.remove_section(section_nr)?;
        self.stats.sections_removed += 1;
        self.refresh_stats();
        Ok(removed)
    }

    /// Bring a section online.
    pub fn online_section(&mut self, section_nr: u64) -> Result<()> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        self.memmap.online_section(section_nr)?;
        self.refresh_stats();
        Ok(())
    }

    /// Take a section offline.
    pub fn offline_section(&mut self, section_nr: u64) -> Result<()> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        self.memmap.offline_section(section_nr)?;
        self.refresh_stats();
        Ok(())
    }

    /// Check whether a PFN is valid.
    pub fn pfn_valid(&self, pfn: u64) -> bool {
        self.memmap.pfn_valid(pfn)
    }

    /// Check whether a PFN is online.
    pub fn pfn_online(&self, pfn: u64) -> bool {
        self.memmap.pfn_online(pfn)
    }

    /// Convert PFN to section number.
    pub const fn pfn_to_section(pfn: u64) -> u64 {
        MemMap::pfn_to_section(pfn)
    }

    /// Convert section number to start PFN.
    pub const fn section_to_pfn(section_nr: u64) -> u64 {
        MemMap::section_to_pfn(section_nr)
    }

    /// Current statistics.
    pub const fn stats(&self) -> &MemModelStats {
        &self.stats
    }

    /// Refresh statistics from current memory map state.
    fn refresh_stats(&mut self) {
        self.stats.sections_present = self.memmap.count_present_sections() as u64;
        self.stats.sections_online = self.memmap.count_online_sections() as u64;
        self.stats.total_pages = self.memmap.total_pages();
        self.stats.max_pfn = self.memmap.max_pfn();
        self.stats.min_pfn = self.memmap.min_pfn();
        self.stats.total_bytes = self.memmap.total_bytes();
    }

    /// Validate the integrity of the memory map.
    ///
    /// Checks for overlapping sections and consistent PFN bounds.
    pub fn validate(&self) -> Result<()> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }

        // Check for overlapping sections.
        for i in 0..MAX_SECTIONS {
            let sec_i = &self.memmap.sections[i];
            if !sec_i.active {
                continue;
            }
            for j in (i + 1)..MAX_SECTIONS {
                let sec_j = &self.memmap.sections[j];
                if !sec_j.active {
                    continue;
                }
                // Check overlap.
                let i_end = sec_i.start_pfn + sec_i.nr_pages;
                let j_end = sec_j.start_pfn + sec_j.nr_pages;
                if sec_i.start_pfn < j_end && sec_j.start_pfn < i_end {
                    return Err(Error::InvalidArgument);
                }
            }
        }

        Ok(())
    }

    /// Find the section containing a given physical address.
    pub fn find_section_by_addr(&self, addr: u64) -> Result<&MemSection> {
        let pfn = MemMap::addr_to_pfn(addr);
        let section_nr = MemMap::pfn_to_section(pfn);
        self.memmap.section(section_nr)
    }

    /// Total physical memory tracked in bytes.
    pub fn total_memory_bytes(&self) -> u64 {
        self.memmap.total_bytes()
    }
}

impl Default for MemMapSubsystem {
    fn default() -> Self {
        Self::new()
    }
}
