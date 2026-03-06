// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Anonymous `mmap(2)` handler.
//!
//! Implements anonymous memory mapping — creating virtual memory areas
//! (VMAs) backed by zero-filled pages rather than a file.
//!
//! # Flags
//!
//! | Flag | Value | Description |
//! |------|-------|-------------|
//! | `MAP_ANONYMOUS` | 0x20   | Anonymous mapping (no file backing) |
//! | `MAP_PRIVATE`   | 0x02   | Copy-on-write (changes not shared) |
//! | `MAP_SHARED`    | 0x01   | Share changes with other mappers |
//! | `MAP_FIXED`     | 0x10   | Map exactly at `addr` |
//! | `MAP_POPULATE`  | 0x8000 | Pre-fault pages (populate page tables) |
//!
//! # Protection flags (`PROT_*`)
//!
//! | Flag | Value | Meaning |
//! |------|-------|---------|
//! | `PROT_NONE`  | 0 | No access |
//! | `PROT_READ`  | 1 | Pages are readable |
//! | `PROT_WRITE` | 2 | Pages are writable |
//! | `PROT_EXEC`  | 4 | Pages are executable |
//!
//! # Key behaviours
//!
//! - `len` is rounded up to the next page boundary (4096 bytes).
//! - If `addr == 0` the kernel chooses an address.
//! - `MAP_FIXED` maps exactly at `addr`; existing mappings are replaced.
//! - Anonymous pages are zero-filled on demand.
//!
//! # POSIX Conformance
//!
//! `MAP_ANONYMOUS` is a Linux/BSD extension; the rest follows
//! POSIX.1-2024 `mmap()`.
//!
//! # References
//!
//! - POSIX.1-2024: `mmap()`
//! - Linux: `mm/mmap.c`, `do_mmap()`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Protection flags
// ---------------------------------------------------------------------------

/// No access.
pub const PROT_NONE: u32 = 0;
/// Readable.
pub const PROT_READ: u32 = 1;
/// Writable.
pub const PROT_WRITE: u32 = 2;
/// Executable.
pub const PROT_EXEC: u32 = 4;

/// All valid PROT bits.
const PROT_VALID: u32 = PROT_READ | PROT_WRITE | PROT_EXEC;

// ---------------------------------------------------------------------------
// Mapping flags
// ---------------------------------------------------------------------------

/// Shared mapping.
pub const MAP_SHARED: u32 = 0x01;
/// Private copy-on-write mapping.
pub const MAP_PRIVATE: u32 = 0x02;
/// Map at fixed address.
pub const MAP_FIXED: u32 = 0x10;
/// Anonymous mapping (no file).
pub const MAP_ANONYMOUS: u32 = 0x20;
/// Pre-fault pages.
pub const MAP_POPULATE: u32 = 0x8000;

/// Mask for type bits (MAP_SHARED vs MAP_PRIVATE).
const MAP_TYPE: u32 = 0x0F;
/// All known flags.
const MAP_KNOWN: u32 = MAP_SHARED | MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_POPULATE;

/// Page size.
pub const PAGE_SIZE: u64 = 4096;

/// Maximum number of VMAs in the stub.
pub const MAX_VMA_COUNT: usize = 256;

/// Starting address for the kernel's address hint (mmap base).
const MMAP_BASE: u64 = 0x0000_7FFF_0000_0000;

// ---------------------------------------------------------------------------
// MmapFlags — validated mapping flags
// ---------------------------------------------------------------------------

/// Validated flags for an anonymous `mmap` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmapFlags(pub u32);

impl MmapFlags {
    /// Construct from raw flags.
    ///
    /// # Errors
    ///
    /// * [`Error::InvalidArgument`] — unknown flags, or neither `MAP_SHARED`
    ///   nor `MAP_PRIVATE` is set, or both are set.
    pub fn from_raw(raw: u32) -> Result<Self> {
        if raw & !MAP_KNOWN != 0 {
            return Err(Error::InvalidArgument);
        }
        let map_type = raw & MAP_TYPE;
        if map_type == 0 || (raw & MAP_SHARED != 0 && raw & MAP_PRIVATE != 0) {
            return Err(Error::InvalidArgument);
        }
        if raw & MAP_ANONYMOUS == 0 {
            return Err(Error::InvalidArgument); // This handler is anonymous-only.
        }
        Ok(Self(raw))
    }

    /// Return `true` if `MAP_FIXED` is set.
    pub const fn is_fixed(self) -> bool {
        self.0 & MAP_FIXED != 0
    }

    /// Return `true` if `MAP_SHARED` is set.
    pub const fn is_shared(self) -> bool {
        self.0 & MAP_SHARED != 0
    }

    /// Return `true` if `MAP_PRIVATE` is set.
    pub const fn is_private(self) -> bool {
        self.0 & MAP_PRIVATE != 0
    }

    /// Return `true` if `MAP_POPULATE` is set.
    pub const fn is_populate(self) -> bool {
        self.0 & MAP_POPULATE != 0
    }
}

// ---------------------------------------------------------------------------
// VmaEntry — one virtual memory area
// ---------------------------------------------------------------------------

/// A stub virtual memory area (VMA) entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmaEntry {
    /// Start address (page-aligned).
    pub start: u64,
    /// End address (exclusive, page-aligned).
    pub end: u64,
    /// Protection flags.
    pub prot: u32,
    /// Mapping flags.
    pub flags: MmapFlags,
    /// Whether pages are pre-populated (PROT_NONE implies no pages).
    pub populated: bool,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl VmaEntry {
    const fn empty() -> Self {
        Self {
            start: 0,
            end: 0,
            prot: 0,
            flags: MmapFlags(0),
            populated: false,
            in_use: false,
        }
    }

    /// Return the length of this VMA in bytes.
    pub const fn len(&self) -> u64 {
        self.end - self.start
    }

    /// Return `true` if this VMA contains `addr`.
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
}

// ---------------------------------------------------------------------------
// VmaTable — the process's virtual memory map
// ---------------------------------------------------------------------------

/// A stub virtual memory area table.
pub struct VmaTable {
    vmas: [VmaEntry; MAX_VMA_COUNT],
    count: usize,
    /// Current hint for the next allocation (bumped on each new allocation).
    next_addr: u64,
}

impl VmaTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            vmas: [const { VmaEntry::empty() }; MAX_VMA_COUNT],
            count: 0,
            next_addr: MMAP_BASE,
        }
    }

    /// Insert a VMA.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    fn insert(&mut self, vma: VmaEntry) -> Result<()> {
        for slot in self.vmas.iter_mut() {
            if !slot.in_use {
                *slot = vma;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find a VMA that contains `addr`.
    pub fn find_containing(&self, addr: u64) -> Option<&VmaEntry> {
        self.vmas.iter().find(|v| v.in_use && v.contains(addr))
    }

    /// Remove a VMA whose start address matches `addr`.
    pub fn remove_at(&mut self, addr: u64) -> bool {
        for slot in self.vmas.iter_mut() {
            if slot.in_use && slot.start == addr {
                *slot = VmaEntry::empty();
                self.count = self.count.saturating_sub(1);
                return true;
            }
        }
        false
    }

    /// Check if any existing VMA overlaps [`start`, `end`).
    fn overlaps(&self, start: u64, end: u64) -> bool {
        self.vmas
            .iter()
            .any(|v| v.in_use && v.start < end && v.end > start)
    }

    /// Allocate a non-overlapping address region of `len` bytes.
    fn alloc_addr(&mut self, len: u64) -> Option<u64> {
        let mut candidate = self.next_addr;
        // Simple linear scan to find a free slot.
        for _ in 0..MAX_VMA_COUNT {
            let end = candidate.checked_add(len)?;
            if !self.overlaps(candidate, end) {
                self.next_addr = end;
                return Some(candidate);
            }
            candidate = candidate.checked_add(PAGE_SIZE)?;
        }
        None
    }

    /// Return the number of VMAs.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for VmaTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Round up to page size
// ---------------------------------------------------------------------------

/// Round `len` up to the nearest page boundary.
pub const fn round_up_page(len: u64) -> u64 {
    (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

// ---------------------------------------------------------------------------
// do_mmap_anonymous — main handler
// ---------------------------------------------------------------------------

/// Handler for anonymous `mmap(2)`.
///
/// Creates a new anonymous VMA of size `len` bytes with the given
/// protection and flags.
///
/// # Arguments
///
/// * `table` — virtual memory area table
/// * `addr`  — requested start address (0 = kernel chooses; `MAP_FIXED` requires exact)
/// * `len`   — mapping length in bytes (rounded up to page size)
/// * `prot`  — protection flags (`PROT_*`)
/// * `flags` — mapping flags (must include `MAP_ANONYMOUS`)
///
/// # Returns
///
/// The start address of the new mapping.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — zero `len`, bad flags, bad prot bits,
///   or `MAP_FIXED` with an unaligned address
/// * [`Error::OutOfMemory`]     — VMA table full, or no free address region
pub fn do_mmap_anonymous(
    table: &mut VmaTable,
    addr: u64,
    len: u64,
    prot: u32,
    raw_flags: u32,
) -> Result<u64> {
    if len == 0 {
        return Err(Error::InvalidArgument);
    }
    if prot & !PROT_VALID != 0 {
        return Err(Error::InvalidArgument);
    }

    let flags = MmapFlags::from_raw(raw_flags)?;
    let map_len = round_up_page(len);

    let start = if flags.is_fixed() {
        if addr % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        // MAP_FIXED: remove any existing VMAs that overlap.
        let end = addr.checked_add(map_len).ok_or(Error::InvalidArgument)?;
        // Collect starts to remove.
        let mut to_remove = [0u64; MAX_VMA_COUNT];
        let mut n_remove = 0usize;
        for vma in table.vmas.iter() {
            if vma.in_use && vma.start < end && vma.end > addr {
                if n_remove < MAX_VMA_COUNT {
                    to_remove[n_remove] = vma.start;
                    n_remove += 1;
                }
            }
        }
        for i in 0..n_remove {
            table.remove_at(to_remove[i]);
        }
        addr
    } else if addr != 0 {
        // Hint: try `addr` first, fall back to allocation.
        let end = addr.checked_add(map_len).ok_or(Error::InvalidArgument)?;
        if addr % PAGE_SIZE == 0 && !table.overlaps(addr, end) {
            addr
        } else {
            table.alloc_addr(map_len).ok_or(Error::OutOfMemory)?
        }
    } else {
        table.alloc_addr(map_len).ok_or(Error::OutOfMemory)?
    };

    let populated = flags.is_populate() && prot != PROT_NONE;

    let vma = VmaEntry {
        start,
        end: start + map_len,
        prot,
        flags,
        populated,
        in_use: true,
    };

    table.insert(vma)?;
    Ok(start)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mmap_anon_basic() {
        let mut t = VmaTable::new();
        let addr = do_mmap_anonymous(
            &mut t,
            0,
            4096,
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE,
        )
        .unwrap();
        assert!(addr > 0);
        assert_eq!(t.count(), 1);
    }

    #[test]
    fn mmap_anon_len_rounded_up() {
        let mut t = VmaTable::new();
        let addr = do_mmap_anonymous(&mut t, 0, 1, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE).unwrap();
        let vma = t.find_containing(addr).unwrap();
        assert_eq!(vma.len(), PAGE_SIZE); // rounded up
    }

    #[test]
    fn mmap_anon_fixed() {
        let mut t = VmaTable::new();
        let target = 0x0000_4000_0000_0000u64;
        let addr = do_mmap_anonymous(
            &mut t,
            target,
            PAGE_SIZE,
            PROT_READ,
            MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
        )
        .unwrap();
        assert_eq!(addr, target);
    }

    #[test]
    fn mmap_anon_fixed_unaligned_rejected() {
        let mut t = VmaTable::new();
        assert_eq!(
            do_mmap_anonymous(
                &mut t,
                1,
                PAGE_SIZE,
                PROT_READ,
                MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn mmap_anon_zero_len_rejected() {
        let mut t = VmaTable::new();
        assert_eq!(
            do_mmap_anonymous(&mut t, 0, 0, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn mmap_anon_bad_prot_rejected() {
        let mut t = VmaTable::new();
        assert_eq!(
            do_mmap_anonymous(&mut t, 0, PAGE_SIZE, 0xFF, MAP_ANONYMOUS | MAP_PRIVATE),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn mmap_anon_missing_anonymous_flag() {
        let mut t = VmaTable::new();
        assert_eq!(
            do_mmap_anonymous(&mut t, 0, PAGE_SIZE, PROT_READ, MAP_PRIVATE),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn mmap_anon_shared_and_private_rejected() {
        let mut t = VmaTable::new();
        assert_eq!(
            do_mmap_anonymous(
                &mut t,
                0,
                PAGE_SIZE,
                PROT_READ,
                MAP_ANONYMOUS | MAP_SHARED | MAP_PRIVATE
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn mmap_anon_multiple_allocations() {
        let mut t = VmaTable::new();
        let a1 = do_mmap_anonymous(&mut t, 0, PAGE_SIZE, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE)
            .unwrap();
        let a2 = do_mmap_anonymous(
            &mut t,
            0,
            PAGE_SIZE,
            PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE,
        )
        .unwrap();
        assert_ne!(a1, a2);
        assert_eq!(t.count(), 2);
    }

    #[test]
    fn mmap_anon_populate() {
        let mut t = VmaTable::new();
        let addr = do_mmap_anonymous(
            &mut t,
            0,
            PAGE_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE,
        )
        .unwrap();
        let vma = t.find_containing(addr).unwrap();
        assert!(vma.populated);
    }

    #[test]
    fn mmap_anon_prot_none_not_populated() {
        let mut t = VmaTable::new();
        let addr = do_mmap_anonymous(
            &mut t,
            0,
            PAGE_SIZE,
            PROT_NONE,
            MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE,
        )
        .unwrap();
        let vma = t.find_containing(addr).unwrap();
        assert!(!vma.populated);
    }

    #[test]
    fn round_up_page_size() {
        assert_eq!(round_up_page(1), 4096);
        assert_eq!(round_up_page(4096), 4096);
        assert_eq!(round_up_page(4097), 8192);
    }

    #[test]
    fn vma_contains() {
        let v = VmaEntry {
            start: 0x1000,
            end: 0x2000,
            prot: PROT_READ,
            flags: MmapFlags(MAP_ANONYMOUS | MAP_PRIVATE),
            populated: false,
            in_use: true,
        };
        assert!(v.contains(0x1000));
        assert!(v.contains(0x1FFF));
        assert!(!v.contains(0x2000));
        assert!(!v.contains(0x0FFF));
    }
}
