// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DAX (Direct Access) for persistent memory.
//!
//! Provides direct CPU-load/store access to persistent memory
//! (PMEM) without going through the page cache. Filesystems on
//! PMEM devices use DAX to map persistent storage directly into
//! process address spaces, eliminating double-copy overhead.
//!
//! # Design
//!
//! - [`DaxDevice`] — represents a persistent memory device with
//!   physical range and block size
//! - [`DaxMapping`] — a single direct mapping from virtual address
//!   to physical PMEM range
//! - [`DaxFaultType`] — classification of DAX page faults
//! - [`DaxFaultResult`] — outcome of handling a DAX fault
//! - [`DaxFlags`] — per-mapping flags (writable, CoW, huge page)
//! - [`DaxEntry`] — exceptional page-cache entry representing a
//!   DAX mapping
//! - [`DaxWritebackRange`] — range descriptor for cache-line
//!   writeback operations
//! - [`DaxStats`] — aggregate DAX statistics
//! - [`DaxManager`] — top-level manager for DAX devices, mappings,
//!   and fault handling
//!
//! # Fault Handling
//!
//! When a process accesses a DAX-mapped region:
//!
//! 1. The MMU triggers a page fault.
//! 2. The fault handler determines whether this is a PTE-level
//!    (4 KiB) or PMD-level (2 MiB) fault.
//! 3. For read faults, the PFN is looked up and mapped directly.
//! 4. For write faults on CoW mappings, a new page is allocated,
//!    data is copied, and the mapping is updated.
//! 5. For write faults on writable mappings, dirty tracking is
//!    enabled for writeback.
//!
//! Reference: Linux `fs/dax.c`, `include/linux/dax.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// PMD (Page Middle Directory) huge page size (2 MiB).
const PMD_SIZE: u64 = 2 * 1024 * 1024;

/// PUD (Page Upper Directory) huge page size (1 GiB).
const PUD_SIZE: u64 = 1024 * 1024 * 1024;

/// Maximum number of DAX devices.
const MAX_DAX_DEVICES: usize = 8;

/// Maximum number of active DAX mappings.
const MAX_DAX_MAPPINGS: usize = 1024;

/// Maximum number of exceptional entries tracked.
const MAX_DAX_ENTRIES: usize = 2048;

/// Maximum writeback ranges queued.
const MAX_WRITEBACK_RANGES: usize = 64;

/// DAX entry type tag for PTE-level entries.
const DAX_ENTRY_PTE: u8 = 1;

/// DAX entry type tag for PMD-level entries.
const DAX_ENTRY_PMD: u8 = 2;

/// DAX entry type tag for zero page entries.
const DAX_ENTRY_ZERO: u8 = 3;

// -------------------------------------------------------------------
// DaxFlags
// -------------------------------------------------------------------

/// Per-mapping flags for DAX regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DaxFlags(u32);

impl DaxFlags {
    /// Mapping is readable.
    pub const READ: Self = Self(1 << 0);
    /// Mapping is writable.
    pub const WRITE: Self = Self(1 << 1);
    /// Mapping uses copy-on-write semantics.
    pub const COW: Self = Self(1 << 2);
    /// Mapping uses PMD (2 MiB) huge pages.
    pub const HUGE_PMD: Self = Self(1 << 3);
    /// Mapping uses PUD (1 GiB) huge pages.
    pub const HUGE_PUD: Self = Self(1 << 4);
    /// Mapping has dirty pages pending writeback.
    pub const DIRTY: Self = Self(1 << 5);
    /// Mapping is shared between processes.
    pub const SHARED: Self = Self(1 << 6);

    /// Empty flag set.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Check whether the given flag is set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Set the given flag.
    pub const fn insert(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Clear the given flag.
    pub const fn remove(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

impl Default for DaxFlags {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// DaxFaultType
// -------------------------------------------------------------------

/// Classification of a DAX page fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DaxFaultType {
    /// PTE-level fault (4 KiB page).
    #[default]
    Pte,
    /// PMD-level fault (2 MiB huge page).
    Pmd,
    /// PUD-level fault (1 GiB huge page).
    Pud,
}

// -------------------------------------------------------------------
// DaxFaultResult
// -------------------------------------------------------------------

/// Outcome of handling a DAX page fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DaxFaultResult {
    /// Fault handled successfully; PFN was mapped.
    #[default]
    Mapped,
    /// Fault handled by allocating a new page (CoW break).
    CowBreak,
    /// A zero page was installed.
    ZeroPage,
    /// Fault required a fallback to smaller page size.
    Fallback,
    /// Fault could not be handled (error).
    Error,
    /// Mapping needs retry (e.g. race condition).
    Retry,
}

// -------------------------------------------------------------------
// DaxDevice
// -------------------------------------------------------------------

/// A persistent memory device accessible via DAX.
#[derive(Debug, Clone, Copy)]
pub struct DaxDevice {
    /// Device identifier.
    pub id: u32,
    /// Starting physical address of the PMEM region.
    pub phys_start: u64,
    /// Length of the PMEM region in bytes.
    pub phys_len: u64,
    /// Block/sector size for I/O alignment.
    pub block_size: u32,
    /// Whether the device is currently alive.
    pub alive: bool,
    /// Number of active mappings to this device.
    pub mapping_count: usize,
    /// Whether the device supports PMD (2 MiB) mappings.
    pub supports_pmd: bool,
    /// Whether the device supports PUD (1 GiB) mappings.
    pub supports_pud: bool,
}

impl Default for DaxDevice {
    fn default() -> Self {
        Self {
            id: 0,
            phys_start: 0,
            phys_len: 0,
            block_size: 512,
            alive: false,
            mapping_count: 0,
            supports_pmd: false,
            supports_pud: false,
        }
    }
}

impl DaxDevice {
    /// Return the ending physical address (exclusive).
    pub fn phys_end(&self) -> u64 {
        self.phys_start + self.phys_len
    }

    /// Check whether a physical address falls within this device.
    pub fn contains_phys(&self, addr: u64) -> bool {
        addr >= self.phys_start && addr < self.phys_end()
    }

    /// Convert a device-relative offset to a physical address.
    pub fn offset_to_phys(&self, offset: u64) -> Result<u64> {
        if offset >= self.phys_len {
            return Err(Error::InvalidArgument);
        }
        Ok(self.phys_start + offset)
    }

    /// Convert a physical address to a PFN.
    pub fn phys_to_pfn(addr: u64) -> u64 {
        addr / PAGE_SIZE
    }

    /// Return the number of pages in this device.
    pub fn page_count(&self) -> u64 {
        self.phys_len / PAGE_SIZE
    }
}

// -------------------------------------------------------------------
// DaxMapping
// -------------------------------------------------------------------

/// A single DAX mapping from virtual to physical PMEM.
#[derive(Debug, Clone, Copy)]
pub struct DaxMapping {
    /// Virtual address start (page-aligned).
    pub virt_start: u64,
    /// Length of the mapping in bytes.
    pub length: u64,
    /// Device-relative physical offset.
    pub phys_offset: u64,
    /// Index of the device in the device table.
    pub device_idx: usize,
    /// Mapping flags.
    pub flags: DaxFlags,
    /// Inode number (for filesystem DAX).
    pub inode: u64,
    /// File offset corresponding to the mapping start.
    pub file_offset: u64,
    /// Whether this mapping slot is in use.
    pub active: bool,
    /// Reference count (number of processes sharing).
    pub ref_count: u32,
}

impl Default for DaxMapping {
    fn default() -> Self {
        Self {
            virt_start: 0,
            length: 0,
            phys_offset: 0,
            device_idx: 0,
            flags: DaxFlags::empty(),
            inode: 0,
            file_offset: 0,
            active: false,
            ref_count: 0,
        }
    }
}

// -------------------------------------------------------------------
// DaxEntry
// -------------------------------------------------------------------

/// Exceptional page-cache entry representing a DAX mapping.
///
/// In a traditional page cache, each slot holds a `struct page *`.
/// For DAX, the slot instead holds an exceptional entry encoding the
/// PFN and entry type.
#[derive(Debug, Clone, Copy)]
pub struct DaxEntry {
    /// Page frame number of the persistent memory page.
    pub pfn: u64,
    /// Entry type (PTE, PMD, or zero).
    pub entry_type: u8,
    /// Whether the entry is dirty (needs writeback).
    pub dirty: bool,
    /// Whether this entry slot is in use.
    pub valid: bool,
    /// Mapping index that created this entry.
    pub mapping_idx: usize,
    /// Inode number owning this entry.
    pub inode: u64,
    /// Page index within the inode.
    pub page_index: u64,
}

impl Default for DaxEntry {
    fn default() -> Self {
        Self {
            pfn: 0,
            entry_type: 0,
            dirty: false,
            valid: false,
            mapping_idx: 0,
            inode: 0,
            page_index: 0,
        }
    }
}

// -------------------------------------------------------------------
// DaxWritebackRange
// -------------------------------------------------------------------

/// Descriptor for a DAX writeback (cache-line flush) operation.
#[derive(Debug, Clone, Copy)]
pub struct DaxWritebackRange {
    /// Device index.
    pub device_idx: usize,
    /// Starting physical address.
    pub phys_start: u64,
    /// Length in bytes.
    pub length: u64,
    /// Whether the writeback has been completed.
    pub completed: bool,
}

impl Default for DaxWritebackRange {
    fn default() -> Self {
        Self {
            device_idx: 0,
            phys_start: 0,
            length: 0,
            completed: false,
        }
    }
}

// -------------------------------------------------------------------
// DaxStats
// -------------------------------------------------------------------

/// Aggregate DAX statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct DaxStats {
    /// Number of PTE-level faults handled.
    pub pte_faults: u64,
    /// Number of PMD-level faults handled.
    pub pmd_faults: u64,
    /// Number of PUD-level faults handled.
    pub pud_faults: u64,
    /// Number of read faults.
    pub read_faults: u64,
    /// Number of write faults.
    pub write_faults: u64,
    /// Number of CoW breaks performed.
    pub cow_breaks: u64,
    /// Number of zero pages installed.
    pub zero_pages: u64,
    /// Number of PMD-to-PTE fallbacks.
    pub pmd_fallbacks: u64,
    /// Number of writeback flushes.
    pub writebacks: u64,
    /// Total bytes written back.
    pub writeback_bytes: u64,
    /// Number of mappings created.
    pub mappings_created: u64,
    /// Number of mappings destroyed.
    pub mappings_destroyed: u64,
}

// -------------------------------------------------------------------
// DaxManager
// -------------------------------------------------------------------

/// Top-level DAX manager for persistent memory devices.
///
/// Manages device registration, direct mappings, exceptional
/// entries, fault handling, and writeback operations.
pub struct DaxManager {
    /// Registered DAX devices.
    devices: [DaxDevice; MAX_DAX_DEVICES],
    /// Number of registered devices.
    device_count: usize,
    /// Active DAX mappings.
    mappings: [DaxMapping; MAX_DAX_MAPPINGS],
    /// Number of active mappings.
    mapping_count: usize,
    /// Exceptional entry table.
    entries: [DaxEntry; MAX_DAX_ENTRIES],
    /// Number of entries in use.
    entry_count: usize,
    /// Writeback queue.
    writeback_queue: [DaxWritebackRange; MAX_WRITEBACK_RANGES],
    /// Number of pending writeback ranges.
    writeback_count: usize,
    /// Aggregate statistics.
    stats: DaxStats,
    /// Whether the DAX subsystem is enabled.
    enabled: bool,
    /// Next PFN to allocate for CoW copies (simulated allocator).
    next_cow_pfn: u64,
}

impl DaxManager {
    /// Create a new DAX manager.
    pub fn new() -> Self {
        Self {
            devices: [DaxDevice::default(); MAX_DAX_DEVICES],
            device_count: 0,
            mappings: [DaxMapping::default(); MAX_DAX_MAPPINGS],
            mapping_count: 0,
            entries: [DaxEntry::default(); MAX_DAX_ENTRIES],
            entry_count: 0,
            writeback_queue: [DaxWritebackRange::default(); MAX_WRITEBACK_RANGES],
            writeback_count: 0,
            stats: DaxStats::default(),
            enabled: false,
            next_cow_pfn: 0x10_0000, // 1 MiB base for CoW copies
        }
    }

    /// Enable the DAX subsystem.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the DAX subsystem.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Return whether DAX is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Return aggregate statistics.
    pub fn stats(&self) -> DaxStats {
        self.stats
    }

    /// Return the number of registered devices.
    pub fn device_count(&self) -> usize {
        self.device_count
    }

    /// Return a reference to a device by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `idx` is out of range.
    pub fn device(&self, idx: usize) -> Result<&DaxDevice> {
        if idx >= self.device_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.devices[idx])
    }

    /// Register a new DAX device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the device table is full.
    /// Returns [`Error::InvalidArgument`] if `phys_len` is zero or
    /// the range overlaps an existing device.
    pub fn register_device(
        &mut self,
        phys_start: u64,
        phys_len: u64,
        block_size: u32,
    ) -> Result<usize> {
        if phys_len == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.device_count >= MAX_DAX_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let end = phys_start + phys_len;
        // Check for overlap with existing devices.
        for i in 0..self.device_count {
            let d = &self.devices[i];
            if d.alive && phys_start < d.phys_end() && end > d.phys_start {
                return Err(Error::InvalidArgument);
            }
        }
        let idx = self.device_count;
        self.devices[idx] = DaxDevice {
            id: idx as u32,
            phys_start,
            phys_len,
            block_size,
            alive: true,
            mapping_count: 0,
            supports_pmd: phys_len >= PMD_SIZE,
            supports_pud: phys_len >= PUD_SIZE,
        };
        self.device_count += 1;
        Ok(idx)
    }

    /// Unregister a DAX device.
    ///
    /// All mappings to this device are invalidated.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the index is invalid.
    /// Returns [`Error::Busy`] if the device still has active
    /// mappings.
    pub fn unregister_device(&mut self, idx: usize) -> Result<()> {
        if idx >= self.device_count || !self.devices[idx].alive {
            return Err(Error::InvalidArgument);
        }
        if self.devices[idx].mapping_count > 0 {
            return Err(Error::Busy);
        }
        self.devices[idx].alive = false;
        // Invalidate entries referencing this device.
        for i in 0..self.entry_count {
            if self.entries[i].valid {
                let pfn = self.entries[i].pfn;
                let phys = pfn * PAGE_SIZE;
                if self.devices[idx].contains_phys(phys) {
                    self.entries[i].valid = false;
                }
            }
        }
        Ok(())
    }

    /// Create a new DAX mapping.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the mapping table is full.
    /// Returns [`Error::InvalidArgument`] if the device index is
    /// invalid or the offset is out of range.
    pub fn create_mapping(
        &mut self,
        device_idx: usize,
        virt_start: u64,
        length: u64,
        phys_offset: u64,
        flags: DaxFlags,
        inode: u64,
        file_offset: u64,
    ) -> Result<usize> {
        if device_idx >= self.device_count || !self.devices[device_idx].alive {
            return Err(Error::InvalidArgument);
        }
        if phys_offset + length > self.devices[device_idx].phys_len {
            return Err(Error::InvalidArgument);
        }
        if self.mapping_count >= MAX_DAX_MAPPINGS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.mapping_count;
        self.mappings[idx] = DaxMapping {
            virt_start,
            length,
            phys_offset,
            device_idx,
            flags,
            inode,
            file_offset,
            active: true,
            ref_count: 1,
        };
        self.mapping_count += 1;
        self.devices[device_idx].mapping_count += 1;
        self.stats.mappings_created += 1;
        Ok(idx)
    }

    /// Destroy a DAX mapping.
    ///
    /// Decrements the reference count; when it reaches zero the
    /// mapping is freed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the mapping index is
    /// invalid.
    pub fn destroy_mapping(&mut self, idx: usize) -> Result<()> {
        if idx >= self.mapping_count || !self.mappings[idx].active {
            return Err(Error::InvalidArgument);
        }
        self.mappings[idx].ref_count = self.mappings[idx].ref_count.saturating_sub(1);
        if self.mappings[idx].ref_count == 0 {
            self.mappings[idx].active = false;
            let dev = self.mappings[idx].device_idx;
            if dev < self.device_count {
                self.devices[dev].mapping_count = self.devices[dev].mapping_count.saturating_sub(1);
            }
            self.stats.mappings_destroyed += 1;
        }
        Ok(())
    }

    /// Handle a DAX page fault.
    ///
    /// Resolves the faulting virtual address to a physical PFN and
    /// installs the mapping. For CoW faults, allocates a new page
    /// and copies data.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no mapping covers the address.
    /// Returns [`Error::OutOfMemory`] if entry table is full.
    pub fn handle_fault(
        &mut self,
        virt_addr: u64,
        write: bool,
        fault_type: DaxFaultType,
    ) -> Result<DaxFaultResult> {
        if !self.enabled {
            return Err(Error::NotFound);
        }

        // Find the mapping covering this address.
        let mapping_idx = self.find_mapping(virt_addr).ok_or(Error::NotFound)?;
        let mapping = self.mappings[mapping_idx];
        let dev_idx = mapping.device_idx;

        // Compute the physical address.
        let offset_in_mapping = virt_addr - mapping.virt_start;
        let phys_addr = self.devices[dev_idx].phys_start + mapping.phys_offset + offset_in_mapping;
        let pfn = DaxDevice::phys_to_pfn(phys_addr);

        // Classify the fault.
        match fault_type {
            DaxFaultType::Pte => self.stats.pte_faults += 1,
            DaxFaultType::Pmd => self.stats.pmd_faults += 1,
            DaxFaultType::Pud => self.stats.pud_faults += 1,
        }

        if write {
            self.stats.write_faults += 1;
        } else {
            self.stats.read_faults += 1;
        }

        // Check for PMD/PUD alignment and device support.
        let result = match fault_type {
            DaxFaultType::Pmd => {
                if !self.devices[dev_idx].supports_pmd || (phys_addr % PMD_SIZE) != 0 {
                    self.stats.pmd_fallbacks += 1;
                    self.install_pte_entry(
                        pfn,
                        mapping_idx,
                        mapping.inode,
                        offset_in_mapping / PAGE_SIZE,
                        write,
                    )?
                } else {
                    self.install_pmd_entry(
                        pfn,
                        mapping_idx,
                        mapping.inode,
                        offset_in_mapping / PAGE_SIZE,
                        write,
                    )?
                }
            }
            DaxFaultType::Pud => {
                if !self.devices[dev_idx].supports_pud || (phys_addr % PUD_SIZE) != 0 {
                    self.stats.pmd_fallbacks += 1;
                    self.install_pte_entry(
                        pfn,
                        mapping_idx,
                        mapping.inode,
                        offset_in_mapping / PAGE_SIZE,
                        write,
                    )?
                } else {
                    self.install_pte_entry(
                        pfn,
                        mapping_idx,
                        mapping.inode,
                        offset_in_mapping / PAGE_SIZE,
                        write,
                    )?
                }
            }
            DaxFaultType::Pte => self.install_pte_entry(
                pfn,
                mapping_idx,
                mapping.inode,
                offset_in_mapping / PAGE_SIZE,
                write,
            )?,
        };

        // Handle CoW break if needed.
        if write && mapping.flags.contains(DaxFlags::COW) {
            return self.handle_cow_fault(mapping_idx, pfn);
        }

        // Mark dirty for writeback.
        if write {
            self.mappings[mapping_idx].flags =
                self.mappings[mapping_idx].flags.insert(DaxFlags::DIRTY);
        }

        Ok(result)
    }

    /// Handle a zero-page fault (first access to an unallocated
    /// region).
    ///
    /// Installs a zero-filled page entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the entry table is full.
    pub fn handle_zero_fault(
        &mut self,
        mapping_idx: usize,
        page_index: u64,
    ) -> Result<DaxFaultResult> {
        if mapping_idx >= self.mapping_count || !self.mappings[mapping_idx].active {
            return Err(Error::InvalidArgument);
        }
        if self.entry_count >= MAX_DAX_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let inode = self.mappings[mapping_idx].inode;
        let slot = self.entry_count;
        self.entries[slot] = DaxEntry {
            pfn: 0, // Zero page — no real PFN.
            entry_type: DAX_ENTRY_ZERO,
            dirty: false,
            valid: true,
            mapping_idx,
            inode,
            page_index,
        };
        self.entry_count += 1;
        self.stats.zero_pages += 1;
        Ok(DaxFaultResult::ZeroPage)
    }

    /// Queue a writeback for a range of physical addresses.
    ///
    /// In real hardware this would issue CLWB/CLFLUSH instructions
    /// followed by SFENCE.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the writeback queue is
    /// full.
    /// Returns [`Error::InvalidArgument`] if the device index is
    /// invalid.
    pub fn queue_writeback(
        &mut self,
        device_idx: usize,
        phys_start: u64,
        length: u64,
    ) -> Result<()> {
        if device_idx >= self.device_count {
            return Err(Error::InvalidArgument);
        }
        if self.writeback_count >= MAX_WRITEBACK_RANGES {
            return Err(Error::OutOfMemory);
        }
        let slot = self.writeback_count;
        self.writeback_queue[slot] = DaxWritebackRange {
            device_idx,
            phys_start,
            length,
            completed: false,
        };
        self.writeback_count += 1;
        Ok(())
    }

    /// Process all pending writebacks.
    ///
    /// Returns the number of writeback operations completed.
    pub fn flush_writebacks(&mut self) -> usize {
        let mut flushed = 0;
        for i in 0..self.writeback_count {
            if !self.writeback_queue[i].completed {
                self.writeback_queue[i].completed = true;
                self.stats.writebacks += 1;
                self.stats.writeback_bytes += self.writeback_queue[i].length;
                flushed += 1;
            }
        }
        // Compact the queue: remove completed entries.
        self.writeback_count = 0;
        flushed
    }

    /// Invalidate all DAX entries for a given inode.
    pub fn invalidate_inode(&mut self, inode: u64) {
        for i in 0..self.entry_count {
            if self.entries[i].valid && self.entries[i].inode == inode {
                self.entries[i].valid = false;
            }
        }
    }

    /// Invalidate a specific DAX entry by inode and page index.
    pub fn invalidate_entry(&mut self, inode: u64, page_index: u64) {
        for i in 0..self.entry_count {
            if self.entries[i].valid
                && self.entries[i].inode == inode
                && self.entries[i].page_index == page_index
            {
                self.entries[i].valid = false;
            }
        }
    }

    /// Return the number of active mappings.
    pub fn active_mapping_count(&self) -> usize {
        let mut count = 0;
        for i in 0..self.mapping_count {
            if self.mappings[i].active {
                count += 1;
            }
        }
        count
    }

    /// Return the number of valid entries.
    pub fn valid_entry_count(&self) -> usize {
        let mut count = 0;
        for i in 0..self.entry_count {
            if self.entries[i].valid {
                count += 1;
            }
        }
        count
    }

    /// Return the number of dirty entries pending writeback.
    pub fn dirty_entry_count(&self) -> usize {
        let mut count = 0;
        for i in 0..self.entry_count {
            if self.entries[i].valid && self.entries[i].dirty {
                count += 1;
            }
        }
        count
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = DaxStats::default();
    }

    // --- internal helpers ---

    /// Find the mapping that covers a virtual address.
    fn find_mapping(&self, virt_addr: u64) -> Option<usize> {
        for i in 0..self.mapping_count {
            let m = &self.mappings[i];
            if m.active && virt_addr >= m.virt_start && virt_addr < m.virt_start + m.length {
                return Some(i);
            }
        }
        None
    }

    /// Install a PTE-level exceptional entry.
    fn install_pte_entry(
        &mut self,
        pfn: u64,
        mapping_idx: usize,
        inode: u64,
        page_index: u64,
        dirty: bool,
    ) -> Result<DaxFaultResult> {
        if self.entry_count >= MAX_DAX_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        // Check if an entry already exists.
        for i in 0..self.entry_count {
            if self.entries[i].valid
                && self.entries[i].inode == inode
                && self.entries[i].page_index == page_index
            {
                self.entries[i].dirty = self.entries[i].dirty || dirty;
                return Ok(DaxFaultResult::Mapped);
            }
        }
        let slot = self.entry_count;
        self.entries[slot] = DaxEntry {
            pfn,
            entry_type: DAX_ENTRY_PTE,
            dirty,
            valid: true,
            mapping_idx,
            inode,
            page_index,
        };
        self.entry_count += 1;
        Ok(DaxFaultResult::Mapped)
    }

    /// Install a PMD-level exceptional entry.
    fn install_pmd_entry(
        &mut self,
        pfn: u64,
        mapping_idx: usize,
        inode: u64,
        page_index: u64,
        dirty: bool,
    ) -> Result<DaxFaultResult> {
        if self.entry_count >= MAX_DAX_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let slot = self.entry_count;
        self.entries[slot] = DaxEntry {
            pfn,
            entry_type: DAX_ENTRY_PMD,
            dirty,
            valid: true,
            mapping_idx,
            inode,
            page_index,
        };
        self.entry_count += 1;
        Ok(DaxFaultResult::Mapped)
    }

    /// Handle a CoW fault: allocate a new PFN, copy data, and update
    /// the entry.
    fn handle_cow_fault(
        &mut self,
        mapping_idx: usize,
        original_pfn: u64,
    ) -> Result<DaxFaultResult> {
        let new_pfn = self.next_cow_pfn;
        self.next_cow_pfn += 1;

        // Find and update the entry for this mapping.
        for i in 0..self.entry_count {
            if self.entries[i].valid
                && self.entries[i].mapping_idx == mapping_idx
                && self.entries[i].pfn == original_pfn
            {
                self.entries[i].pfn = new_pfn;
                self.entries[i].dirty = true;
                self.stats.cow_breaks += 1;
                return Ok(DaxFaultResult::CowBreak);
            }
        }
        // No existing entry — install a fresh one with the new PFN.
        if self.entry_count >= MAX_DAX_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let inode = self.mappings[mapping_idx].inode;
        let slot = self.entry_count;
        self.entries[slot] = DaxEntry {
            pfn: new_pfn,
            entry_type: DAX_ENTRY_PTE,
            dirty: true,
            valid: true,
            mapping_idx,
            inode,
            page_index: 0,
        };
        self.entry_count += 1;
        self.stats.cow_breaks += 1;
        Ok(DaxFaultResult::CowBreak)
    }
}

impl Default for DaxManager {
    fn default() -> Self {
        Self::new()
    }
}
