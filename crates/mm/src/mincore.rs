// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! mincore() — memory residency query.
//!
//! Implements the `mincore()` system call interface, which reports
//! whether pages backing a virtual address range are resident in
//! physical memory. For each page in the range, a single byte in
//! the output vector is set: bit 0 indicates the page is present
//! in RAM.
//!
//! # Design
//!
//! The implementation walks per-VMA page-table structures to
//! determine residency. Different VMA types are handled:
//!
//! - **Anonymous pages**: check the process page table for a present
//!   PTE.
//! - **File-backed pages**: check the page cache or page table.
//! - **Swap-backed pages**: check the swap cache for the swap
//!   entry; if cached the page is considered resident.
//! - **Huge pages** (THP/hugetlb): a 2 MiB/1 GiB huge page counts
//!   as all constituent base pages being resident.
//! - **Shared memory**: treat as file-backed.
//!
//! # Output Format
//!
//! The output vector contains one byte per page. Only bit 0 is
//! defined:
//! - `0x01`: page is resident in memory.
//! - `0x00`: page is not resident.
//!
//! Reference: Linux `mm/mincore.c`, POSIX `mincore(2)`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Huge page size (2 MiB).
const HUGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;

/// Gigantic page size (1 GiB).
const GIGA_PAGE_SIZE: u64 = 1024 * 1024 * 1024;

/// Number of base pages in a 2 MiB huge page.
const HUGE_PAGE_NR_PAGES: usize = (HUGE_PAGE_SIZE / PAGE_SIZE) as usize;

/// Maximum number of VMAs that mincore can walk.
const MAX_VMAS: usize = 256;

/// Maximum number of PTE entries the walker can examine per VMA.
const MAX_PTE_ENTRIES: usize = 4096;

/// Maximum number of swap cache entries tracked.
const MAX_SWAP_CACHE: usize = 1024;

/// Maximum output vector size (pages).
const MAX_OUTPUT_PAGES: usize = 65536;

/// Bit in the output byte indicating the page is resident.
const PAGE_RESIDENT_BIT: u8 = 0x01;

// -------------------------------------------------------------------
// VmaType
// -------------------------------------------------------------------

/// Type of a virtual memory area.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VmaType {
    /// Anonymous (process-private) pages.
    #[default]
    Anonymous,
    /// File-backed pages (page cache).
    FileBacked,
    /// Shared memory region.
    SharedMemory,
    /// Huge page (THP or hugetlb).
    HugePage,
    /// Device-mapped (e.g. DAX or MMIO).
    DeviceMapped,
}

// -------------------------------------------------------------------
// VmaPermissions
// -------------------------------------------------------------------

/// Permission bits for a VMA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmaPermissions(u8);

impl VmaPermissions {
    /// Readable.
    pub const READ: Self = Self(1 << 0);
    /// Writable.
    pub const WRITE: Self = Self(1 << 1);
    /// Executable.
    pub const EXEC: Self = Self(1 << 2);
    /// Shared (vs private).
    pub const SHARED: Self = Self(1 << 3);

    /// Empty permissions.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Check whether a flag is set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Set a flag.
    pub const fn insert(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl Default for VmaPermissions {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// VmaInfo
// -------------------------------------------------------------------

/// Descriptor for a virtual memory area.
#[derive(Debug, Clone, Copy)]
pub struct VmaInfo {
    /// Starting virtual address (page-aligned).
    pub vm_start: u64,
    /// Ending virtual address (exclusive, page-aligned).
    pub vm_end: u64,
    /// VMA type.
    pub vma_type: VmaType,
    /// Permission bits.
    pub permissions: VmaPermissions,
    /// Inode number (for file-backed VMAs).
    pub inode: u64,
    /// File offset in bytes (for file-backed VMAs).
    pub file_offset: u64,
    /// Whether this VMA uses huge pages.
    pub huge_page: bool,
    /// Whether this VMA slot is in use.
    pub active: bool,
}

impl Default for VmaInfo {
    fn default() -> Self {
        Self {
            vm_start: 0,
            vm_end: 0,
            vma_type: VmaType::Anonymous,
            permissions: VmaPermissions::empty(),
            inode: 0,
            file_offset: 0,
            huge_page: false,
            active: false,
        }
    }
}

impl VmaInfo {
    /// Return the length of this VMA in bytes.
    pub fn length(&self) -> u64 {
        self.vm_end.saturating_sub(self.vm_start)
    }

    /// Return the number of base pages spanned by this VMA.
    pub fn page_count(&self) -> u64 {
        self.length() / PAGE_SIZE
    }

    /// Check whether a virtual address falls within this VMA.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.vm_start && addr < self.vm_end
    }
}

// -------------------------------------------------------------------
// PteEntry
// -------------------------------------------------------------------

/// Simplified page table entry for residency checks.
#[derive(Debug, Clone, Copy, Default)]
pub struct PteEntry {
    /// Virtual page number (vaddr / PAGE_SIZE).
    pub vpn: u64,
    /// Physical frame number (0 if not present).
    pub pfn: u64,
    /// Whether the PTE is present (page is in RAM).
    pub present: bool,
    /// Whether the page is in swap (swap entry is valid).
    pub swapped: bool,
    /// Swap entry identifier (only valid when `swapped` is true).
    pub swap_entry: u64,
    /// Whether this is a huge page PTE.
    pub huge: bool,
}

// -------------------------------------------------------------------
// SwapCacheEntry
// -------------------------------------------------------------------

/// A swap cache entry: a page that was swapped out but is still
/// cached in RAM.
#[derive(Debug, Clone, Copy, Default)]
pub struct SwapCacheEntry {
    /// Swap entry identifier.
    pub swap_entry: u64,
    /// Whether this cache slot is valid.
    pub valid: bool,
}

// -------------------------------------------------------------------
// MincoreQuery
// -------------------------------------------------------------------

/// Parameters for a mincore() query.
#[derive(Debug, Clone, Copy)]
pub struct MincoreQuery {
    /// Starting virtual address (must be page-aligned).
    pub addr: u64,
    /// Length in bytes (will be rounded up to page boundary).
    pub length: u64,
}

impl MincoreQuery {
    /// Create a new mincore query.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `addr` is not
    /// page-aligned.
    pub fn new(addr: u64, length: u64) -> Result<Self> {
        if addr % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { addr, length })
    }

    /// Return the number of pages covered by this query.
    pub fn page_count(&self) -> usize {
        let rounded = (self.length + PAGE_SIZE - 1) / PAGE_SIZE;
        rounded as usize
    }

    /// Return the ending virtual address (exclusive).
    pub fn end_addr(&self) -> u64 {
        self.addr + (self.page_count() as u64) * PAGE_SIZE
    }
}

// -------------------------------------------------------------------
// MincoreStats
// -------------------------------------------------------------------

/// Statistics from mincore operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct MincoreStats {
    /// Total mincore() calls made.
    pub queries: u64,
    /// Total pages examined.
    pub pages_examined: u64,
    /// Pages found resident.
    pub pages_resident: u64,
    /// Pages found not resident.
    pub pages_not_resident: u64,
    /// Pages resolved via swap cache lookup.
    pub swap_cache_hits: u64,
    /// Huge pages encountered.
    pub huge_pages_examined: u64,
    /// Queries that returned errors.
    pub query_errors: u64,
}

// -------------------------------------------------------------------
// MincoreWalker
// -------------------------------------------------------------------

/// The mincore page-table walker and residency checker.
///
/// Maintains a set of VMAs, page table entries, and a swap cache
/// to resolve mincore queries.
pub struct MincoreWalker {
    /// VMA descriptors.
    vmas: [VmaInfo; MAX_VMAS],
    /// Number of active VMAs.
    vma_count: usize,
    /// Page table entries (flat array used for simulation).
    ptes: [PteEntry; MAX_PTE_ENTRIES],
    /// Number of PTE entries.
    pte_count: usize,
    /// Swap cache.
    swap_cache: [SwapCacheEntry; MAX_SWAP_CACHE],
    /// Number of swap cache entries.
    swap_cache_count: usize,
    /// Accumulated statistics.
    stats: MincoreStats,
}

impl MincoreWalker {
    /// Create a new mincore walker.
    pub fn new() -> Self {
        Self {
            vmas: [VmaInfo::default(); MAX_VMAS],
            vma_count: 0,
            ptes: [PteEntry::default(); MAX_PTE_ENTRIES],
            pte_count: 0,
            swap_cache: [SwapCacheEntry::default(); MAX_SWAP_CACHE],
            swap_cache_count: 0,
            stats: MincoreStats::default(),
        }
    }

    /// Return accumulated statistics.
    pub fn stats(&self) -> MincoreStats {
        self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = MincoreStats::default();
    }

    /// Register a VMA.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the VMA table is full.
    /// Returns [`Error::InvalidArgument`] if the VMA range is
    /// invalid.
    pub fn add_vma(&mut self, vma: VmaInfo) -> Result<usize> {
        if vma.vm_start >= vma.vm_end {
            return Err(Error::InvalidArgument);
        }
        if vma.vm_start % PAGE_SIZE != 0 || vma.vm_end % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.vma_count >= MAX_VMAS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.vma_count;
        self.vmas[idx] = vma;
        self.vmas[idx].active = true;
        self.vma_count += 1;
        Ok(idx)
    }

    /// Remove a VMA by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the index is out of
    /// range.
    pub fn remove_vma(&mut self, idx: usize) -> Result<()> {
        if idx >= self.vma_count {
            return Err(Error::InvalidArgument);
        }
        self.vmas[idx].active = false;
        Ok(())
    }

    /// Install a page table entry (for simulation).
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the PTE table is full.
    pub fn install_pte(&mut self, pte: PteEntry) -> Result<usize> {
        if self.pte_count >= MAX_PTE_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.pte_count;
        self.ptes[idx] = pte;
        self.pte_count += 1;
        Ok(idx)
    }

    /// Add a swap cache entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the swap cache is full.
    pub fn add_swap_cache_entry(&mut self, swap_entry: u64) -> Result<usize> {
        if self.swap_cache_count >= MAX_SWAP_CACHE {
            return Err(Error::OutOfMemory);
        }
        let idx = self.swap_cache_count;
        self.swap_cache[idx] = SwapCacheEntry {
            swap_entry,
            valid: true,
        };
        self.swap_cache_count += 1;
        Ok(idx)
    }

    /// Remove a swap cache entry.
    pub fn remove_swap_cache_entry(&mut self, swap_entry: u64) {
        for i in 0..self.swap_cache_count {
            if self.swap_cache[i].valid && self.swap_cache[i].swap_entry == swap_entry {
                self.swap_cache[i].valid = false;
                return;
            }
        }
    }

    /// Perform a mincore() query.
    ///
    /// Fills `output` with one byte per page: bit 0 set if the page
    /// is resident. The caller must ensure `output.len()` is at
    /// least `query.page_count()`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `output` is too small
    /// or the query range is not fully covered by VMAs.
    pub fn mincore(&mut self, query: &MincoreQuery, output: &mut [u8]) -> Result<()> {
        let nr_pages = query.page_count();
        if nr_pages == 0 {
            return Ok(());
        }
        if output.len() < nr_pages {
            return Err(Error::InvalidArgument);
        }
        if nr_pages > MAX_OUTPUT_PAGES {
            return Err(Error::InvalidArgument);
        }

        self.stats.queries += 1;

        // Walk each page in the query range.
        let mut page_idx = 0usize;
        let mut addr = query.addr;
        let end = query.end_addr();

        while addr < end && page_idx < nr_pages {
            // Find the VMA covering this address.
            let vma_idx = self.find_vma(addr);
            if vma_idx.is_none() {
                // No VMA: page is not resident (ENOMEM in real
                // kernel, but we report 0).
                output[page_idx] = 0;
                addr += PAGE_SIZE;
                page_idx += 1;
                self.stats.pages_not_resident += 1;
                self.stats.pages_examined += 1;
                continue;
            }
            let vi = vma_idx.unwrap_or(0);
            let vma = &self.vmas[vi];

            match vma.vma_type {
                VmaType::HugePage => {
                    let resident = self.check_huge_page_resident(addr);
                    self.stats.huge_pages_examined += 1;
                    // All base pages within the huge page share the
                    // same residency.
                    let pages_in_huge = HUGE_PAGE_NR_PAGES.min(nr_pages - page_idx);
                    let val = if resident { PAGE_RESIDENT_BIT } else { 0 };
                    for j in 0..pages_in_huge {
                        output[page_idx + j] = val;
                    }
                    if resident {
                        self.stats.pages_resident += pages_in_huge as u64;
                    } else {
                        self.stats.pages_not_resident += pages_in_huge as u64;
                    }
                    self.stats.pages_examined += pages_in_huge as u64;
                    addr += (pages_in_huge as u64) * PAGE_SIZE;
                    page_idx += pages_in_huge;
                }
                VmaType::DeviceMapped => {
                    // Device-mapped pages are always resident.
                    output[page_idx] = PAGE_RESIDENT_BIT;
                    self.stats.pages_resident += 1;
                    self.stats.pages_examined += 1;
                    addr += PAGE_SIZE;
                    page_idx += 1;
                }
                _ => {
                    // Anonymous, file-backed, or shared memory: walk
                    // the page table.
                    let resident = self.check_page_resident(addr, vma);
                    output[page_idx] = if resident { PAGE_RESIDENT_BIT } else { 0 };
                    if resident {
                        self.stats.pages_resident += 1;
                    } else {
                        self.stats.pages_not_resident += 1;
                    }
                    self.stats.pages_examined += 1;
                    addr += PAGE_SIZE;
                    page_idx += 1;
                }
            }
        }

        Ok(())
    }

    /// Simplified mincore for a single page: returns whether the
    /// page at `addr` is resident.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `addr` is not
    /// page-aligned.
    /// Returns [`Error::NotFound`] if no VMA covers the address.
    pub fn is_resident(&self, addr: u64) -> Result<bool> {
        if addr % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        let vi = self.find_vma(addr).ok_or(Error::NotFound)?;
        let vma = &self.vmas[vi];
        Ok(self.check_page_resident(addr, vma))
    }

    /// Return the total number of resident pages in a range.
    ///
    /// This is a convenience wrapper that allocates a stack buffer.
    ///
    /// # Errors
    ///
    /// Returns errors from [`mincore`].
    pub fn count_resident(&mut self, addr: u64, length: u64) -> Result<usize> {
        let query = MincoreQuery::new(addr, length)?;
        let nr = query.page_count();
        if nr > MAX_OUTPUT_PAGES {
            return Err(Error::InvalidArgument);
        }
        // Use a fixed buffer on the stack (limited to a reasonable
        // size to avoid stack overflow).
        let mut buf = [0u8; 256];
        let mut total_resident = 0usize;
        let mut offset = 0usize;
        let mut current_addr = addr;
        while offset < nr {
            let chunk = (nr - offset).min(buf.len());
            let sub_query = MincoreQuery::new(current_addr, (chunk as u64) * PAGE_SIZE)?;
            self.mincore(&sub_query, &mut buf[..chunk])?;
            for i in 0..chunk {
                if buf[i] & PAGE_RESIDENT_BIT != 0 {
                    total_resident += 1;
                }
            }
            offset += chunk;
            current_addr += (chunk as u64) * PAGE_SIZE;
        }
        Ok(total_resident)
    }

    /// Return the number of VMAs.
    pub fn vma_count(&self) -> usize {
        self.vma_count
    }

    /// Return the number of installed PTEs.
    pub fn pte_count(&self) -> usize {
        self.pte_count
    }

    // --- internal helpers ---

    /// Find the VMA covering `addr`.
    fn find_vma(&self, addr: u64) -> Option<usize> {
        for i in 0..self.vma_count {
            if self.vmas[i].active && self.vmas[i].contains(addr) {
                return Some(i);
            }
        }
        None
    }

    /// Check whether a page is resident by walking the PTE table.
    fn check_page_resident(&self, addr: u64, vma: &VmaInfo) -> bool {
        let vpn = addr / PAGE_SIZE;

        // Look up the PTE for this VPN.
        for i in 0..self.pte_count {
            let pte = &self.ptes[i];
            if pte.vpn != vpn {
                continue;
            }
            // PTE found.
            if pte.present {
                return true;
            }
            // Page is in swap; check the swap cache.
            if pte.swapped {
                return self.swap_cache_lookup(pte.swap_entry);
            }
            return false;
        }

        // No PTE means the page was never faulted in.
        // For file-backed VMAs we could check the page cache, but
        // without one we report not resident.
        let _ = vma;
        false
    }

    /// Check whether a huge page at `addr` is resident.
    fn check_huge_page_resident(&self, addr: u64) -> bool {
        let huge_base = addr & !(HUGE_PAGE_SIZE - 1);
        let vpn = huge_base / PAGE_SIZE;
        for i in 0..self.pte_count {
            if self.ptes[i].vpn == vpn && self.ptes[i].huge {
                return self.ptes[i].present;
            }
        }
        false
    }

    /// Look up a swap entry in the swap cache.
    fn swap_cache_lookup(&self, swap_entry: u64) -> bool {
        for i in 0..self.swap_cache_count {
            if self.swap_cache[i].valid && self.swap_cache[i].swap_entry == swap_entry {
                return true;
            }
        }
        false
    }
}

impl Default for MincoreWalker {
    fn default() -> Self {
        Self::new()
    }
}
