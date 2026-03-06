// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! hugetlbfs inode operations.
//!
//! hugetlbfs is a special-purpose filesystem providing huge-page-backed
//! anonymous memory mappings. It supports 2 MiB and 1 GiB huge pages on
//! x86_64.
//!
//! # Design
//!
//! - [`HugePageSize`] — supported huge page sizes
//! - [`HugetlbfsInode`] — per-inode state (size, huge_page_order, page pool)
//! - `alloc_huge_page` / `free_huge_page` — page pool management
//! - `hugetlb_fault` — handle page faults in huge-page VMAs
//! - `hugetlb_truncate` — return pages on file truncation
//! - `hugetlb_mmap_validate` — validate mmap parameters
//!
//! # References
//!
//! - Linux `mm/hugetlb.c`, `fs/hugetlbfs/inode.c`
//! - `include/linux/hugetlb.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum hugetlbfs inodes.
pub const MAX_HUGETLB_INODES: usize = 64;

/// Maximum huge pages per inode.
pub const MAX_PAGES_PER_INODE: usize = 128;

/// 2 MiB page size in bytes.
pub const HUGE_PAGE_2M: u64 = 2 * 1024 * 1024;

/// 1 GiB page size in bytes.
pub const HUGE_PAGE_1G: u64 = 1024 * 1024 * 1024;

/// Global huge page pool size (2 MiB pages).
pub const POOL_SIZE_2M: usize = 4096;

/// Global huge page pool size (1 GiB pages).
pub const POOL_SIZE_1G: usize = 32;

/// Order for 2 MiB pages (2^9 base pages).
pub const ORDER_2M: u32 = 9;

/// Order for 1 GiB pages (2^18 base pages).
pub const ORDER_1G: u32 = 18;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Supported huge page sizes on x86_64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HugePageSize {
    /// 2 MiB huge pages.
    Size2M,
    /// 1 GiB huge pages.
    Size1G,
}

impl HugePageSize {
    /// Return the page size in bytes.
    pub fn bytes(self) -> u64 {
        match self {
            HugePageSize::Size2M => HUGE_PAGE_2M,
            HugePageSize::Size1G => HUGE_PAGE_1G,
        }
    }

    /// Return the page order (log2 of base-page count).
    pub fn order(self) -> u32 {
        match self {
            HugePageSize::Size2M => ORDER_2M,
            HugePageSize::Size1G => ORDER_1G,
        }
    }

    /// Parse from pool index.
    pub fn from_order(order: u32) -> Option<Self> {
        match order {
            ORDER_2M => Some(HugePageSize::Size2M),
            ORDER_1G => Some(HugePageSize::Size1G),
            _ => None,
        }
    }
}

/// A single huge page in the global pool.
#[derive(Debug, Clone, Copy, Default)]
struct HugePage {
    /// Physical address of this page.
    phys_addr: u64,
    /// Inode that owns this page (0 = free).
    owner_inode: u64,
    /// Page index within the owning inode.
    page_index: u64,
}

/// hugetlbfs inode.
#[derive(Clone)]
pub struct HugetlbfsInode {
    /// Inode number.
    pub ino: u64,
    /// File size in bytes (must be a multiple of huge_page_size).
    pub size: u64,
    /// Huge page size for this inode.
    pub hpage_size: HugePageSize,
    /// Indices of allocated huge pages (into the global pool).
    pub page_indices: [usize; MAX_PAGES_PER_INODE],
    /// Number of allocated pages.
    pub page_count: usize,
    /// Maximum number of pages allowed.
    pub max_pages: usize,
    /// In use.
    pub in_use: bool,
}

impl HugetlbfsInode {
    fn empty() -> Self {
        Self {
            ino: 0,
            size: 0,
            hpage_size: HugePageSize::Size2M,
            page_indices: [0usize; MAX_PAGES_PER_INODE],
            page_count: 0,
            max_pages: MAX_PAGES_PER_INODE,
            in_use: false,
        }
    }
}

/// Global hugetlbfs state: inode table + page pools.
pub struct HugetlbfsState {
    inodes: [HugetlbfsInode; MAX_HUGETLB_INODES],
    inode_count: usize,
    /// 2 MiB page pool.
    pool_2m: [HugePage; POOL_SIZE_2M],
    /// 1 GiB page pool.
    pool_1g: [HugePage; POOL_SIZE_1G],
    /// Free 2M page count.
    pub free_2m: usize,
    /// Free 1G page count.
    pub free_1g: usize,
    /// Next inode number.
    next_ino: u64,
}

impl HugetlbfsState {
    /// Create a new state with `free_2m` and `free_1g` pages pre-allocated.
    pub fn new(free_2m: usize, free_1g: usize) -> Self {
        let fm = free_2m.min(POOL_SIZE_2M);
        let fg = free_1g.min(POOL_SIZE_1G);

        let mut pool_2m = [HugePage::default(); POOL_SIZE_2M];
        let mut pool_1g = [HugePage::default(); POOL_SIZE_1G];

        // Assign synthetic physical addresses.
        for i in 0..fm {
            pool_2m[i].phys_addr = (i as u64 + 1) * HUGE_PAGE_2M;
        }
        for i in 0..fg {
            pool_1g[i].phys_addr = (i as u64 + 1) * HUGE_PAGE_1G;
        }

        Self {
            inodes: core::array::from_fn(|_| HugetlbfsInode::empty()),
            inode_count: 0,
            pool_2m,
            pool_1g,
            free_2m: fm,
            free_1g: fg,
            next_ino: 1,
        }
    }

    fn find_inode(&self, ino: u64) -> Option<usize> {
        for i in 0..MAX_HUGETLB_INODES {
            if self.inodes[i].in_use && self.inodes[i].ino == ino {
                return Some(i);
            }
        }
        None
    }

    fn find_free_inode(&self) -> Option<usize> {
        for i in 0..MAX_HUGETLB_INODES {
            if !self.inodes[i].in_use {
                return Some(i);
            }
        }
        None
    }

    fn find_free_2m_page(&self) -> Option<usize> {
        for i in 0..POOL_SIZE_2M {
            if self.pool_2m[i].phys_addr != 0 && self.pool_2m[i].owner_inode == 0 {
                return Some(i);
            }
        }
        None
    }

    fn find_free_1g_page(&self) -> Option<usize> {
        for i in 0..POOL_SIZE_1G {
            if self.pool_1g[i].phys_addr != 0 && self.pool_1g[i].owner_inode == 0 {
                return Some(i);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Create a new hugetlbfs inode with the given huge page size.
///
/// Returns the inode number.
pub fn hugetlbfs_create_inode(
    state: &mut HugetlbfsState,
    hpage_size: HugePageSize,
    max_pages: usize,
) -> Result<u64> {
    let slot = state.find_free_inode().ok_or(Error::OutOfMemory)?;
    let ino = state.next_ino;
    state.next_ino += 1;

    let mut inode = HugetlbfsInode::empty();
    inode.ino = ino;
    inode.hpage_size = hpage_size;
    inode.max_pages = max_pages.min(MAX_PAGES_PER_INODE);
    inode.in_use = true;

    state.inodes[slot] = inode;
    state.inode_count += 1;
    Ok(ino)
}

/// Allocate a huge page for inode `ino` at `page_index`.
///
/// Returns the physical address of the allocated page.
pub fn alloc_huge_page(state: &mut HugetlbfsState, ino: u64, page_index: u64) -> Result<u64> {
    let inode_slot = state.find_inode(ino).ok_or(Error::NotFound)?;
    let hpage_size = state.inodes[inode_slot].hpage_size;

    if state.inodes[inode_slot].page_count >= state.inodes[inode_slot].max_pages {
        return Err(Error::OutOfMemory);
    }

    let (pool_slot, phys_addr) = match hpage_size {
        HugePageSize::Size2M => {
            let slot = state.find_free_2m_page().ok_or(Error::OutOfMemory)?;
            let addr = state.pool_2m[slot].phys_addr;
            state.pool_2m[slot].owner_inode = ino;
            state.pool_2m[slot].page_index = page_index;
            state.free_2m -= 1;
            (slot, addr)
        }
        HugePageSize::Size1G => {
            let slot = state.find_free_1g_page().ok_or(Error::OutOfMemory)?;
            let addr = state.pool_1g[slot].phys_addr;
            state.pool_1g[slot].owner_inode = ino;
            state.pool_1g[slot].page_index = page_index;
            state.free_1g -= 1;
            (slot, addr)
        }
    };

    let pc = state.inodes[inode_slot].page_count;
    state.inodes[inode_slot].page_indices[pc] = pool_slot;
    state.inodes[inode_slot].page_count += 1;
    state.inodes[inode_slot].size = (page_index + 1) * hpage_size.bytes();

    Ok(phys_addr)
}

/// Free a huge page for inode `ino` at `page_index`.
pub fn free_huge_page(state: &mut HugetlbfsState, ino: u64, page_index: u64) -> Result<()> {
    let inode_slot = state.find_inode(ino).ok_or(Error::NotFound)?;
    let hpage_size = state.inodes[inode_slot].hpage_size;

    // Find and clear the page in the appropriate pool.
    match hpage_size {
        HugePageSize::Size2M => {
            for i in 0..POOL_SIZE_2M {
                if state.pool_2m[i].owner_inode == ino && state.pool_2m[i].page_index == page_index
                {
                    // Remove from inode's page list.
                    let pc = state.inodes[inode_slot].page_count;
                    let mut new_pc = 0;
                    let mut new_indices = [0usize; MAX_PAGES_PER_INODE];
                    for j in 0..pc {
                        if state.inodes[inode_slot].page_indices[j] != i {
                            new_indices[new_pc] = state.inodes[inode_slot].page_indices[j];
                            new_pc += 1;
                        }
                    }
                    state.inodes[inode_slot].page_indices = new_indices;
                    state.inodes[inode_slot].page_count = new_pc;
                    state.pool_2m[i].owner_inode = 0;
                    state.free_2m += 1;
                    return Ok(());
                }
            }
        }
        HugePageSize::Size1G => {
            for i in 0..POOL_SIZE_1G {
                if state.pool_1g[i].owner_inode == ino && state.pool_1g[i].page_index == page_index
                {
                    let pc = state.inodes[inode_slot].page_count;
                    let mut new_pc = 0;
                    let mut new_indices = [0usize; MAX_PAGES_PER_INODE];
                    for j in 0..pc {
                        if state.inodes[inode_slot].page_indices[j] != i {
                            new_indices[new_pc] = state.inodes[inode_slot].page_indices[j];
                            new_pc += 1;
                        }
                    }
                    state.inodes[inode_slot].page_indices = new_indices;
                    state.inodes[inode_slot].page_count = new_pc;
                    state.pool_1g[i].owner_inode = 0;
                    state.free_1g += 1;
                    return Ok(());
                }
            }
        }
    }
    Err(Error::NotFound)
}

/// Handle a page fault for a huge-page VMA.
///
/// Returns the physical address of the huge page backing the fault address.
/// Allocates a new page if none exists.
pub fn hugetlb_fault(state: &mut HugetlbfsState, ino: u64, fault_addr: u64) -> Result<u64> {
    let inode_slot = state.find_inode(ino).ok_or(Error::NotFound)?;
    let hpage_size = state.inodes[inode_slot].hpage_size;
    let page_index = fault_addr / hpage_size.bytes();

    // Check if page is already allocated.
    let pool = match hpage_size {
        HugePageSize::Size2M => {
            for i in 0..POOL_SIZE_2M {
                if state.pool_2m[i].owner_inode == ino && state.pool_2m[i].page_index == page_index
                {
                    return Ok(state.pool_2m[i].phys_addr);
                }
            }
            None::<u64>
        }
        HugePageSize::Size1G => {
            for i in 0..POOL_SIZE_1G {
                if state.pool_1g[i].owner_inode == ino && state.pool_1g[i].page_index == page_index
                {
                    return Ok(state.pool_1g[i].phys_addr);
                }
            }
            None::<u64>
        }
    };
    let _ = pool;

    // Allocate a new page.
    alloc_huge_page(state, ino, page_index)
}

/// Truncate an inode to `new_size` bytes, freeing pages beyond the new end.
///
/// `new_size` must be a multiple of the huge page size.
pub fn hugetlb_truncate(state: &mut HugetlbfsState, ino: u64, new_size: u64) -> Result<()> {
    let inode_slot = state.find_inode(ino).ok_or(Error::NotFound)?;
    let hpage_size = state.inodes[inode_slot].hpage_size;
    if new_size % hpage_size.bytes() != 0 {
        return Err(Error::InvalidArgument);
    }
    let new_page_count = new_size / hpage_size.bytes();

    // Free pages beyond new_page_count.
    let current_pc = state.inodes[inode_slot].page_count;
    for pi in 0..current_pc {
        let pool_slot = state.inodes[inode_slot].page_indices[pi];
        let page_idx = match hpage_size {
            HugePageSize::Size2M => state.pool_2m[pool_slot].page_index,
            HugePageSize::Size1G => state.pool_1g[pool_slot].page_index,
        };
        if page_idx >= new_page_count {
            match hpage_size {
                HugePageSize::Size2M => {
                    state.pool_2m[pool_slot].owner_inode = 0;
                    state.free_2m += 1;
                }
                HugePageSize::Size1G => {
                    state.pool_1g[pool_slot].owner_inode = 0;
                    state.free_1g += 1;
                }
            }
        }
    }

    // Rebuild page_indices for surviving pages.
    let mut new_indices = [0usize; MAX_PAGES_PER_INODE];
    let mut new_pc = 0;
    for pi in 0..current_pc {
        let pool_slot = state.inodes[inode_slot].page_indices[pi];
        let in_use = match hpage_size {
            HugePageSize::Size2M => state.pool_2m[pool_slot].owner_inode == ino,
            HugePageSize::Size1G => state.pool_1g[pool_slot].owner_inode == ino,
        };
        if in_use {
            new_indices[new_pc] = pool_slot;
            new_pc += 1;
        }
    }
    state.inodes[inode_slot].page_indices = new_indices;
    state.inodes[inode_slot].page_count = new_pc;
    state.inodes[inode_slot].size = new_size;
    Ok(())
}

/// Validate mmap parameters for a hugetlbfs file.
///
/// Checks alignment and size constraints.
pub fn hugetlb_mmap_validate(
    state: &HugetlbfsState,
    ino: u64,
    addr: u64,
    length: u64,
) -> Result<()> {
    let inode_slot = state.find_inode(ino).ok_or(Error::NotFound)?;
    let hpage_size = state.inodes[inode_slot].hpage_size.bytes();
    if addr % hpage_size != 0 {
        return Err(Error::InvalidArgument);
    }
    if length == 0 || length % hpage_size != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Remove a hugetlbfs inode and free all its pages.
pub fn hugetlbfs_remove_inode(state: &mut HugetlbfsState, ino: u64) -> Result<()> {
    let inode_slot = state.find_inode(ino).ok_or(Error::NotFound)?;
    let hpage_size = state.inodes[inode_slot].hpage_size;
    let pc = state.inodes[inode_slot].page_count;

    for pi in 0..pc {
        let pool_slot = state.inodes[inode_slot].page_indices[pi];
        match hpage_size {
            HugePageSize::Size2M => {
                state.pool_2m[pool_slot].owner_inode = 0;
                state.free_2m += 1;
            }
            HugePageSize::Size1G => {
                state.pool_1g[pool_slot].owner_inode = 0;
                state.free_1g += 1;
            }
        }
    }

    state.inodes[inode_slot] = HugetlbfsInode::empty();
    state.inode_count = state.inode_count.saturating_sub(1);
    Ok(())
}
