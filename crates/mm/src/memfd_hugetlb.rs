// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memfd huge-page support.
//!
//! Extends `memfd_create(2)` with huge-page backing via the
//! `MFD_HUGETLB` flag. When a memfd is created with this flag,
//! allocations come from the hugetlb pool instead of the normal page
//! allocator, providing 2 MiB or 1 GiB pages for shared memory
//! regions.
//!
//! # Design
//!
//! ```text
//!  memfd_create("name", MFD_HUGETLB | MFD_HUGE_2MB)
//!     │
//!     ├─ allocate anonymous inode
//!     ├─ set hugetlb backing (order 9 = 2 MiB)
//!     ├─ ftruncate(fd, size) → reserve huge pages
//!     └─ mmap(fd) → map huge pages into address space
//! ```
//!
//! # Key Types
//!
//! - [`HugePageSize`] — huge-page size selector
//! - [`MemfdHugetlb`] — a single hugetlb-backed memfd
//! - [`MemfdHugetlbTable`] — tracks all hugetlb memfds
//! - [`MemfdHugetlbStats`] — allocation statistics
//!
//! Reference: Linux `mm/memfd.c`, `include/uapi/linux/memfd.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum hugetlb memfds.
const MAX_MEMFDS: usize = 512;

/// 2 MiB huge page size.
const HUGE_2M: u64 = 2 * 1024 * 1024;

/// 1 GiB huge page size.
const HUGE_1G: u64 = 1024 * 1024 * 1024;

/// Page size (regular).
const PAGE_SIZE: u64 = 4096;

/// Maximum name length.
const MAX_NAME_LEN: usize = 249;

// -------------------------------------------------------------------
// HugePageSize
// -------------------------------------------------------------------

/// Huge-page size selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HugePageSize {
    /// 2 MiB huge pages.
    Huge2M,
    /// 1 GiB huge pages.
    Huge1G,
}

impl HugePageSize {
    /// Return a label string.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Huge2M => "2MiB",
            Self::Huge1G => "1GiB",
        }
    }

    /// Return the size in bytes.
    pub const fn size_bytes(&self) -> u64 {
        match self {
            Self::Huge2M => HUGE_2M,
            Self::Huge1G => HUGE_1G,
        }
    }

    /// Return the order (log2 of pages).
    pub const fn order(&self) -> u32 {
        match self {
            Self::Huge2M => 9,
            Self::Huge1G => 18,
        }
    }

    /// Return the number of base pages.
    pub const fn base_pages(&self) -> u64 {
        match self {
            Self::Huge2M => HUGE_2M / PAGE_SIZE,
            Self::Huge1G => HUGE_1G / PAGE_SIZE,
        }
    }
}

// -------------------------------------------------------------------
// MemfdHugetlb
// -------------------------------------------------------------------

/// A single hugetlb-backed memfd.
#[derive(Debug, Clone, Copy)]
pub struct MemfdHugetlb {
    /// File descriptor number.
    fd: u64,
    /// Huge-page size.
    page_size: HugePageSize,
    /// Total size in bytes.
    total_size: u64,
    /// Number of huge pages reserved.
    reserved_pages: u64,
    /// Number of huge pages faulted in.
    faulted_pages: u64,
    /// Owner PID.
    owner_pid: u64,
    /// Whether the memfd is sealed.
    sealed: bool,
    /// Name length in bytes.
    name_len: u8,
    /// Name bytes (truncated for storage).
    name: [u8; 32],
}

impl MemfdHugetlb {
    /// Create a new hugetlb memfd.
    pub const fn new(fd: u64, page_size: HugePageSize, owner_pid: u64) -> Self {
        Self {
            fd,
            page_size,
            total_size: 0,
            reserved_pages: 0,
            faulted_pages: 0,
            owner_pid,
            sealed: false,
            name_len: 0,
            name: [0u8; 32],
        }
    }

    /// Return the file descriptor.
    pub const fn fd(&self) -> u64 {
        self.fd
    }

    /// Return the huge-page size.
    pub const fn page_size(&self) -> HugePageSize {
        self.page_size
    }

    /// Return the total size.
    pub const fn total_size(&self) -> u64 {
        self.total_size
    }

    /// Return the number of reserved huge pages.
    pub const fn reserved_pages(&self) -> u64 {
        self.reserved_pages
    }

    /// Return the number of faulted huge pages.
    pub const fn faulted_pages(&self) -> u64 {
        self.faulted_pages
    }

    /// Return the owner PID.
    pub const fn owner_pid(&self) -> u64 {
        self.owner_pid
    }

    /// Check whether the memfd is sealed.
    pub const fn sealed(&self) -> bool {
        self.sealed
    }

    /// Set the total size and compute reserved pages.
    pub fn set_size(&mut self, size: u64) -> Result<()> {
        let ps = self.page_size.size_bytes();
        if (size % ps) != 0 {
            return Err(Error::InvalidArgument);
        }
        self.total_size = size;
        self.reserved_pages = size / ps;
        Ok(())
    }

    /// Record a page fault.
    pub fn record_fault(&mut self) -> Result<()> {
        if self.faulted_pages >= self.reserved_pages {
            return Err(Error::OutOfMemory);
        }
        self.faulted_pages += 1;
        Ok(())
    }

    /// Seal the memfd.
    pub fn seal(&mut self) {
        self.sealed = true;
    }

    /// Faulted ratio as percent.
    pub const fn faulted_pct(&self) -> u64 {
        if self.reserved_pages == 0 {
            return 0;
        }
        self.faulted_pages * 100 / self.reserved_pages
    }
}

impl Default for MemfdHugetlb {
    fn default() -> Self {
        Self {
            fd: 0,
            page_size: HugePageSize::Huge2M,
            total_size: 0,
            reserved_pages: 0,
            faulted_pages: 0,
            owner_pid: 0,
            sealed: false,
            name_len: 0,
            name: [0u8; 32],
        }
    }
}

// -------------------------------------------------------------------
// MemfdHugetlbStats
// -------------------------------------------------------------------

/// Allocation statistics.
#[derive(Debug, Clone, Copy)]
pub struct MemfdHugetlbStats {
    /// Total memfds created.
    pub total_created: u64,
    /// Total 2M memfds.
    pub created_2m: u64,
    /// Total 1G memfds.
    pub created_1g: u64,
    /// Total huge pages reserved.
    pub pages_reserved: u64,
    /// Total huge pages faulted.
    pub pages_faulted: u64,
    /// Reservation failures.
    pub reserve_failures: u64,
}

impl MemfdHugetlbStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            total_created: 0,
            created_2m: 0,
            created_1g: 0,
            pages_reserved: 0,
            pages_faulted: 0,
            reserve_failures: 0,
        }
    }
}

impl Default for MemfdHugetlbStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MemfdHugetlbTable
// -------------------------------------------------------------------

/// Tracks all hugetlb-backed memfds.
pub struct MemfdHugetlbTable {
    /// Memfds.
    entries: [MemfdHugetlb; MAX_MEMFDS],
    /// Number of entries.
    count: usize,
    /// Next FD number.
    next_fd: u64,
    /// Statistics.
    stats: MemfdHugetlbStats,
}

impl MemfdHugetlbTable {
    /// Create a new table.
    pub const fn new() -> Self {
        Self {
            entries: [const {
                MemfdHugetlb {
                    fd: 0,
                    page_size: HugePageSize::Huge2M,
                    total_size: 0,
                    reserved_pages: 0,
                    faulted_pages: 0,
                    owner_pid: 0,
                    sealed: false,
                    name_len: 0,
                    name: [0u8; 32],
                }
            }; MAX_MEMFDS],
            count: 0,
            next_fd: 3,
            stats: MemfdHugetlbStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &MemfdHugetlbStats {
        &self.stats
    }

    /// Return the number of entries.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Create a hugetlb memfd.
    pub fn create(&mut self, page_size: HugePageSize, owner_pid: u64) -> Result<u64> {
        if self.count >= MAX_MEMFDS {
            return Err(Error::OutOfMemory);
        }
        let fd = self.next_fd;
        self.entries[self.count] = MemfdHugetlb::new(fd, page_size, owner_pid);
        self.count += 1;
        self.next_fd += 1;
        self.stats.total_created += 1;
        match page_size {
            HugePageSize::Huge2M => self.stats.created_2m += 1,
            HugePageSize::Huge1G => self.stats.created_1g += 1,
        }
        Ok(fd)
    }

    /// Set size on a memfd.
    pub fn set_size(&mut self, fd: u64, size: u64) -> Result<()> {
        for idx in 0..self.count {
            if self.entries[idx].fd() == fd {
                self.entries[idx].set_size(size)?;
                let rp = self.entries[idx].reserved_pages();
                self.stats.pages_reserved += rp;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Find a memfd by FD.
    pub fn find(&self, fd: u64) -> Option<&MemfdHugetlb> {
        for idx in 0..self.count {
            if self.entries[idx].fd() == fd {
                return Some(&self.entries[idx]);
            }
        }
        None
    }
}

impl Default for MemfdHugetlbTable {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the maximum memfds.
pub const fn max_memfds() -> usize {
    MAX_MEMFDS
}

/// Return the maximum name length.
pub const fn max_name_len() -> usize {
    MAX_NAME_LEN
}
