// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory section management (sparse memory model).
//!
//! Implements the sparse memory model where physical memory is divided
//! into fixed-size sections. Each section represents a contiguous range
//! of page frames and tracks its usage state. This allows efficient
//! management of non-contiguous physical memory layouts common on modern
//! systems with memory hotplug.
//!
//! - [`SectionUsage`] — section usage state
//! - [`MemSection`] — a single memory section
//! - [`SectionMap`] — global section map
//! - [`SectionStats`] — section statistics
//!
//! Reference: `.kernelORG/` — `mm/sparse.c`, `include/linux/mmzone.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Size of a memory section in pages (128 MiB / 4 KiB = 32768 pages).
const PAGES_PER_SECTION: u64 = 32768;

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Section size in bytes (128 MiB).
const SECTION_SIZE: u64 = PAGES_PER_SECTION * PAGE_SIZE;

/// Maximum number of sections.
const MAX_SECTIONS: usize = 512;

/// PFN bits used for section number.
const SECTION_SHIFT: u32 = 15; // log2(32768)

/// Invalid section number sentinel.
const INVALID_SECTION: u32 = u32::MAX;

// -------------------------------------------------------------------
// SectionUsage
// -------------------------------------------------------------------

/// Usage state of a memory section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SectionUsage {
    /// Section is empty / not populated.
    #[default]
    Empty,
    /// Section is in early boot (memblock-managed).
    Early,
    /// Section is fully online and used.
    Used,
    /// Section is being onlined (transition state).
    Onlining,
    /// Section is being offlined (transition state).
    Offlining,
    /// Section has been offlined.
    Offlined,
}

impl SectionUsage {
    /// Returns true if the section contains usable pages.
    pub fn is_usable(self) -> bool {
        matches!(self, SectionUsage::Early | SectionUsage::Used)
    }

    /// Returns true if the section is in a transition state.
    pub fn is_transitioning(self) -> bool {
        matches!(self, SectionUsage::Onlining | SectionUsage::Offlining)
    }
}

// -------------------------------------------------------------------
// MemSection
// -------------------------------------------------------------------

/// A single memory section in the sparse memory model.
///
/// Each section represents [`PAGES_PER_SECTION`] contiguous page frames,
/// identified by a section number derived from the base PFN.
#[derive(Debug, Clone, Copy)]
pub struct MemSection {
    /// Section number.
    section_nr: u32,
    /// Base page frame number of this section.
    page_offset: u64,
    /// Usage state.
    usage: SectionUsage,
    /// NUMA node this section belongs to.
    nid: u16,
    /// Number of present (populated) pages.
    present_pages: u64,
    /// Section flags.
    flags: u32,
}

/// Section flag: has a mem_map (page struct array).
const SECTION_HAS_MEM_MAP: u32 = 1 << 0;

/// Section flag: is early (boot-time).
const SECTION_IS_EARLY: u32 = 1 << 1;

/// Section flag: marked for online.
const SECTION_MARKED_ONLINE: u32 = 1 << 2;

impl MemSection {
    /// Creates a new memory section.
    pub fn new(section_nr: u32, nid: u16) -> Self {
        let page_offset = section_nr_to_pfn(section_nr);
        Self {
            section_nr,
            page_offset,
            usage: SectionUsage::Empty,
            nid,
            present_pages: 0,
            flags: 0,
        }
    }

    /// Returns the section number.
    pub fn section_nr(&self) -> u32 {
        self.section_nr
    }

    /// Returns the base PFN.
    pub fn page_offset(&self) -> u64 {
        self.page_offset
    }

    /// Returns the usage state.
    pub fn usage(&self) -> SectionUsage {
        self.usage
    }

    /// Sets the usage state.
    pub fn set_usage(&mut self, usage: SectionUsage) {
        self.usage = usage;
    }

    /// Returns the NUMA node.
    pub fn nid(&self) -> u16 {
        self.nid
    }

    /// Returns the number of present pages.
    pub fn present_pages(&self) -> u64 {
        self.present_pages
    }

    /// Sets the number of present pages.
    pub fn set_present_pages(&mut self, count: u64) {
        self.present_pages = count.min(PAGES_PER_SECTION);
    }

    /// Returns the end PFN (exclusive).
    pub fn end_pfn(&self) -> u64 {
        self.page_offset + PAGES_PER_SECTION
    }

    /// Checks whether a PFN belongs to this section.
    pub fn contains_pfn(&self, pfn: u64) -> bool {
        pfn >= self.page_offset && pfn < self.end_pfn()
    }

    /// Returns section flags.
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// Sets a flag.
    pub fn set_flag(&mut self, flag: u32) {
        self.flags |= flag;
    }

    /// Clears a flag.
    pub fn clear_flag(&mut self, flag: u32) {
        self.flags &= !flag;
    }

    /// Checks if the section has a mem_map.
    pub fn has_mem_map(&self) -> bool {
        self.flags & SECTION_HAS_MEM_MAP != 0
    }

    /// Marks the section as having a mem_map.
    pub fn mark_has_mem_map(&mut self) {
        self.set_flag(SECTION_HAS_MEM_MAP);
    }
}

impl Default for MemSection {
    fn default() -> Self {
        Self {
            section_nr: INVALID_SECTION,
            page_offset: 0,
            usage: SectionUsage::Empty,
            nid: 0,
            present_pages: 0,
            flags: 0,
        }
    }
}

// -------------------------------------------------------------------
// Conversion functions
// -------------------------------------------------------------------

/// Converts a section number to the base PFN.
pub fn section_nr_to_pfn(section_nr: u32) -> u64 {
    (section_nr as u64) << SECTION_SHIFT
}

/// Converts a PFN to its section number.
pub fn pfn_to_section_nr(pfn: u64) -> u32 {
    (pfn >> SECTION_SHIFT) as u32
}

/// Returns the start address of a section.
pub fn section_start_addr(section_nr: u32) -> u64 {
    section_nr_to_pfn(section_nr) * PAGE_SIZE
}

/// Returns the end address of a section (exclusive).
pub fn section_end_addr(section_nr: u32) -> u64 {
    section_start_addr(section_nr) + SECTION_SIZE
}

// -------------------------------------------------------------------
// SectionStats
// -------------------------------------------------------------------

/// Statistics about memory sections.
#[derive(Debug, Clone, Copy, Default)]
pub struct SectionStats {
    /// Total registered sections.
    pub total: u32,
    /// Sections in Used state.
    pub used: u32,
    /// Sections in Empty state.
    pub empty: u32,
    /// Sections in Early state.
    pub early: u32,
    /// Sections in transition.
    pub transitioning: u32,
    /// Sections offlined.
    pub offlined: u32,
    /// Total present pages across all sections.
    pub total_present_pages: u64,
}

// -------------------------------------------------------------------
// SectionMap
// -------------------------------------------------------------------

/// Global section map for sparse memory.
///
/// Tracks all memory sections in the system and provides lookup,
/// registration, and validation operations.
pub struct SectionMap {
    /// All sections.
    sections: [MemSection; MAX_SECTIONS],
    /// Number of registered sections.
    nr_sections: usize,
    /// Maximum section number seen.
    max_section_nr: u32,
}

impl SectionMap {
    /// Creates a new empty section map.
    pub fn new() -> Self {
        Self {
            sections: [MemSection::default(); MAX_SECTIONS],
            nr_sections: 0,
            max_section_nr: 0,
        }
    }

    /// Registers a new memory section.
    pub fn register(
        &mut self,
        section_nr: u32,
        nid: u16,
        present_pages: u64,
        usage: SectionUsage,
    ) -> Result<()> {
        let idx = section_nr as usize;
        if idx >= MAX_SECTIONS {
            return Err(Error::InvalidArgument);
        }
        if self.sections[idx].usage != SectionUsage::Empty
            && self.sections[idx].section_nr != INVALID_SECTION
        {
            return Err(Error::AlreadyExists);
        }
        let mut section = MemSection::new(section_nr, nid);
        section.set_present_pages(present_pages);
        section.set_usage(usage);
        if usage == SectionUsage::Early {
            section.set_flag(SECTION_IS_EARLY);
        }
        self.sections[idx] = section;
        self.nr_sections += 1;
        if section_nr > self.max_section_nr {
            self.max_section_nr = section_nr;
        }
        Ok(())
    }

    /// Unregisters a memory section.
    pub fn unregister(&mut self, section_nr: u32) -> Result<()> {
        let idx = section_nr as usize;
        if idx >= MAX_SECTIONS {
            return Err(Error::InvalidArgument);
        }
        if self.sections[idx].section_nr == INVALID_SECTION {
            return Err(Error::NotFound);
        }
        self.sections[idx] = MemSection::default();
        self.nr_sections = self.nr_sections.saturating_sub(1);
        Ok(())
    }

    /// Returns a reference to a section by number.
    pub fn get(&self, section_nr: u32) -> Option<&MemSection> {
        let idx = section_nr as usize;
        if idx >= MAX_SECTIONS {
            return None;
        }
        let sec = &self.sections[idx];
        if sec.section_nr == INVALID_SECTION {
            return None;
        }
        Some(sec)
    }

    /// Returns a mutable reference to a section by number.
    pub fn get_mut(&mut self, section_nr: u32) -> Option<&mut MemSection> {
        let idx = section_nr as usize;
        if idx >= MAX_SECTIONS {
            return None;
        }
        if self.sections[idx].section_nr == INVALID_SECTION {
            return None;
        }
        Some(&mut self.sections[idx])
    }

    /// Checks if a section number is valid (registered and usable).
    pub fn valid_section(&self, section_nr: u32) -> bool {
        self.get(section_nr)
            .map(|s| s.usage().is_usable())
            .unwrap_or(false)
    }

    /// Finds the section containing a given PFN.
    pub fn pfn_to_section(&self, pfn: u64) -> Option<&MemSection> {
        let section_nr = pfn_to_section_nr(pfn);
        self.get(section_nr)
    }

    /// Returns the number of registered sections.
    pub fn nr_sections(&self) -> usize {
        self.nr_sections
    }

    /// Returns the maximum section number.
    pub fn max_section_nr(&self) -> u32 {
        self.max_section_nr
    }

    /// Collects statistics about all sections.
    pub fn stats(&self) -> SectionStats {
        let mut stats = SectionStats::default();
        for sec in &self.sections {
            if sec.section_nr == INVALID_SECTION {
                continue;
            }
            stats.total += 1;
            stats.total_present_pages += sec.present_pages;
            match sec.usage {
                SectionUsage::Used => stats.used += 1,
                SectionUsage::Empty => stats.empty += 1,
                SectionUsage::Early => stats.early += 1,
                SectionUsage::Offlined => stats.offlined += 1,
                SectionUsage::Onlining | SectionUsage::Offlining => {
                    stats.transitioning += 1;
                }
            }
        }
        stats
    }

    /// Transitions a section from Early to Used.
    pub fn activate_section(&mut self, section_nr: u32) -> Result<()> {
        let section = self.get_mut(section_nr).ok_or(Error::NotFound)?;
        if section.usage != SectionUsage::Early {
            return Err(Error::InvalidArgument);
        }
        section.set_usage(SectionUsage::Used);
        section.clear_flag(SECTION_IS_EARLY);
        section.mark_has_mem_map();
        Ok(())
    }

    /// Starts offlining a section.
    pub fn begin_offline(&mut self, section_nr: u32) -> Result<()> {
        let section = self.get_mut(section_nr).ok_or(Error::NotFound)?;
        if section.usage != SectionUsage::Used {
            return Err(Error::InvalidArgument);
        }
        section.set_usage(SectionUsage::Offlining);
        Ok(())
    }

    /// Completes offlining a section.
    pub fn complete_offline(&mut self, section_nr: u32) -> Result<()> {
        let section = self.get_mut(section_nr).ok_or(Error::NotFound)?;
        if section.usage != SectionUsage::Offlining {
            return Err(Error::InvalidArgument);
        }
        section.set_usage(SectionUsage::Offlined);
        Ok(())
    }

    /// Starts onlining a section.
    pub fn begin_online(&mut self, section_nr: u32) -> Result<()> {
        let section = self.get_mut(section_nr).ok_or(Error::NotFound)?;
        if section.usage != SectionUsage::Offlined {
            return Err(Error::InvalidArgument);
        }
        section.set_usage(SectionUsage::Onlining);
        Ok(())
    }

    /// Completes onlining a section.
    pub fn complete_online(&mut self, section_nr: u32) -> Result<()> {
        let section = self.get_mut(section_nr).ok_or(Error::NotFound)?;
        if section.usage != SectionUsage::Onlining {
            return Err(Error::InvalidArgument);
        }
        section.set_usage(SectionUsage::Used);
        section.mark_has_mem_map();
        Ok(())
    }
}

impl Default for SectionMap {
    fn default() -> Self {
        Self::new()
    }
}
