// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Architecture-neutral page table entry wrapper.
//!
//! Provides a [`PageTableEntry`] type that wraps the raw 64-bit PTE
//! value and exposes typed getters/setters for PTE flags (present,
//! writable, user, accessed, dirty, huge, global, no-execute). Also
//! provides a [`ProtectionMap`] for mapping VM flags (VM_READ,
//! VM_WRITE, VM_EXEC, VM_SHARED) to PTE protection bits.
//!
//! - [`PteFlags`] — individual PTE flag constants
//! - [`PageTableEntry`] — the PTE wrapper
//! - [`VmFlags`] — virtual memory area flags
//! - [`ProtectionMap`] — VM flags to PTE translation
//!
//! Reference: `.kernelORG/` — `arch/x86/include/asm/pgtable_types.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants — PTE flags (x86_64 compatible)
// -------------------------------------------------------------------

/// PTE flag: page is present in memory.
pub const PTE_PRESENT: u64 = 1 << 0;

/// PTE flag: page is writable.
pub const PTE_WRITABLE: u64 = 1 << 1;

/// PTE flag: page is accessible from user mode.
pub const PTE_USER: u64 = 1 << 2;

/// PTE flag: write-through caching.
pub const PTE_WRITE_THROUGH: u64 = 1 << 3;

/// PTE flag: cache disabled.
pub const PTE_CACHE_DISABLE: u64 = 1 << 4;

/// PTE flag: page has been accessed.
pub const PTE_ACCESSED: u64 = 1 << 5;

/// PTE flag: page has been written (dirty).
pub const PTE_DIRTY: u64 = 1 << 6;

/// PTE flag: huge page (PSE for 4 MiB, or 2 MiB in PAE/long mode).
pub const PTE_HUGE: u64 = 1 << 7;

/// PTE flag: global page (not flushed on CR3 switch).
pub const PTE_GLOBAL: u64 = 1 << 8;

/// Software-defined flag: copy-on-write.
pub const PTE_COW: u64 = 1 << 9;

/// Software-defined flag: special mapping.
pub const PTE_SPECIAL: u64 = 1 << 10;

/// Software-defined flag: page is in swap.
pub const PTE_SWAP: u64 = 1 << 11;

/// PTE flag: no-execute (bit 63 on x86_64).
pub const PTE_NX: u64 = 1 << 63;

/// Mask for the physical frame number in the PTE.
const PTE_PFN_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Page shift (log2 of page size).
const PAGE_SHIFT: u32 = 12;

// -------------------------------------------------------------------
// PageTableEntry
// -------------------------------------------------------------------

/// Architecture-neutral page table entry.
///
/// Wraps a raw 64-bit value and provides typed access to individual
/// flag bits and the page frame number.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PageTableEntry {
    /// Raw PTE value.
    raw: u64,
}

impl PageTableEntry {
    /// Creates a PTE from a raw value.
    pub const fn from_raw(raw: u64) -> Self {
        Self { raw }
    }

    /// Creates an empty (not present) PTE.
    pub const fn empty() -> Self {
        Self { raw: 0 }
    }

    /// Creates a PTE from a PFN and flags.
    pub const fn from_pfn_flags(pfn: u64, flags: u64) -> Self {
        Self {
            raw: (pfn << PAGE_SHIFT) | flags,
        }
    }

    /// Returns the raw PTE value.
    pub const fn raw(self) -> u64 {
        self.raw
    }

    /// Extracts the page frame number from the PTE.
    pub const fn to_pfn(self) -> u64 {
        (self.raw & PTE_PFN_MASK) >> PAGE_SHIFT
    }

    /// Extracts the physical address from the PTE.
    pub const fn to_phys_addr(self) -> u64 {
        self.raw & PTE_PFN_MASK
    }

    /// Returns the flags portion of the PTE (without the PFN).
    pub const fn flags(self) -> u64 {
        self.raw & !PTE_PFN_MASK
    }

    // --- Flag getters ---

    /// Returns true if the page is present.
    pub const fn is_present(self) -> bool {
        self.raw & PTE_PRESENT != 0
    }

    /// Returns true if the page is writable.
    pub const fn is_writable(self) -> bool {
        self.raw & PTE_WRITABLE != 0
    }

    /// Returns true if the page is user-accessible.
    pub const fn is_user(self) -> bool {
        self.raw & PTE_USER != 0
    }

    /// Returns true if the page has been accessed.
    pub const fn is_accessed(self) -> bool {
        self.raw & PTE_ACCESSED != 0
    }

    /// Returns true if the page is dirty.
    pub const fn is_dirty(self) -> bool {
        self.raw & PTE_DIRTY != 0
    }

    /// Returns true if this is a huge page entry.
    pub const fn is_huge(self) -> bool {
        self.raw & PTE_HUGE != 0
    }

    /// Returns true if this is a global page.
    pub const fn is_global(self) -> bool {
        self.raw & PTE_GLOBAL != 0
    }

    /// Returns true if the page is no-execute.
    pub const fn is_nx(self) -> bool {
        self.raw & PTE_NX != 0
    }

    /// Returns true if this is a CoW page.
    pub const fn is_cow(self) -> bool {
        self.raw & PTE_COW != 0
    }

    /// Returns true if this is a special mapping.
    pub const fn is_special(self) -> bool {
        self.raw & PTE_SPECIAL != 0
    }

    /// Returns true if this entry represents a swap entry.
    pub const fn is_swap(self) -> bool {
        self.raw & PTE_SWAP != 0
    }

    /// Returns true if write-through caching is enabled.
    pub const fn is_write_through(self) -> bool {
        self.raw & PTE_WRITE_THROUGH != 0
    }

    /// Returns true if cache is disabled.
    pub const fn is_cache_disabled(self) -> bool {
        self.raw & PTE_CACHE_DISABLE != 0
    }

    // --- Flag setters ---

    /// Sets the present flag.
    pub fn set_present(&mut self, val: bool) {
        if val {
            self.raw |= PTE_PRESENT;
        } else {
            self.raw &= !PTE_PRESENT;
        }
    }

    /// Sets the writable flag.
    pub fn set_writable(&mut self, val: bool) {
        if val {
            self.raw |= PTE_WRITABLE;
        } else {
            self.raw &= !PTE_WRITABLE;
        }
    }

    /// Sets the user flag.
    pub fn set_user(&mut self, val: bool) {
        if val {
            self.raw |= PTE_USER;
        } else {
            self.raw &= !PTE_USER;
        }
    }

    /// Sets the accessed flag.
    pub fn set_accessed(&mut self, val: bool) {
        if val {
            self.raw |= PTE_ACCESSED;
        } else {
            self.raw &= !PTE_ACCESSED;
        }
    }

    /// Sets the dirty flag.
    pub fn set_dirty(&mut self, val: bool) {
        if val {
            self.raw |= PTE_DIRTY;
        } else {
            self.raw &= !PTE_DIRTY;
        }
    }

    /// Sets the huge page flag.
    pub fn set_huge(&mut self, val: bool) {
        if val {
            self.raw |= PTE_HUGE;
        } else {
            self.raw &= !PTE_HUGE;
        }
    }

    /// Sets the global flag.
    pub fn set_global(&mut self, val: bool) {
        if val {
            self.raw |= PTE_GLOBAL;
        } else {
            self.raw &= !PTE_GLOBAL;
        }
    }

    /// Sets the no-execute flag.
    pub fn set_nx(&mut self, val: bool) {
        if val {
            self.raw |= PTE_NX;
        } else {
            self.raw &= !PTE_NX;
        }
    }

    /// Sets the copy-on-write flag.
    pub fn set_cow(&mut self, val: bool) {
        if val {
            self.raw |= PTE_COW;
        } else {
            self.raw &= !PTE_COW;
        }
    }

    /// Clears the accessed and dirty bits.
    pub fn clear_ad(&mut self) {
        self.raw &= !(PTE_ACCESSED | PTE_DIRTY);
    }

    /// Makes the PTE read-only (clears writable, sets CoW).
    pub fn make_cow(&mut self) {
        self.raw &= !PTE_WRITABLE;
        self.raw |= PTE_COW;
    }

    /// Returns a new PTE with updated flags, preserving the PFN.
    pub fn with_flags(self, new_flags: u64) -> Self {
        Self {
            raw: (self.raw & PTE_PFN_MASK) | new_flags,
        }
    }

    /// Returns a new PTE with the same flags but a different PFN.
    pub fn with_pfn(self, pfn: u64) -> Self {
        Self {
            raw: (pfn << PAGE_SHIFT) | self.flags(),
        }
    }
}

impl Default for PageTableEntry {
    fn default() -> Self {
        Self::empty()
    }
}

impl core::fmt::Debug for PageTableEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "PTE(pfn={:#x}, flags={:#x}{}{}{}{}{}{})",
            self.to_pfn(),
            self.flags(),
            if self.is_present() { " P" } else { "" },
            if self.is_writable() { " W" } else { "" },
            if self.is_user() { " U" } else { "" },
            if self.is_dirty() { " D" } else { "" },
            if self.is_huge() { " H" } else { "" },
            if self.is_nx() { " NX" } else { "" },
        )
    }
}

// -------------------------------------------------------------------
// VmFlags — Virtual memory area permission flags
// -------------------------------------------------------------------

/// Virtual memory area flags for protection mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VmFlags(u32);

/// VM flag: readable.
pub const VM_READ: u32 = 1 << 0;

/// VM flag: writable.
pub const VM_WRITE: u32 = 1 << 1;

/// VM flag: executable.
pub const VM_EXEC: u32 = 1 << 2;

/// VM flag: shared mapping.
pub const VM_SHARED: u32 = 1 << 3;

/// VM flag: may read.
pub const VM_MAYREAD: u32 = 1 << 4;

/// VM flag: may write.
pub const VM_MAYWRITE: u32 = 1 << 5;

/// VM flag: may execute.
pub const VM_MAYEXEC: u32 = 1 << 6;

/// VM flag: grows downward (stack).
pub const VM_GROWSDOWN: u32 = 1 << 7;

/// VM flag: locked in memory.
pub const VM_LOCKED: u32 = 1 << 8;

impl VmFlags {
    /// Creates new VM flags from raw value.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw flags value.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Tests if the given flag is set.
    pub const fn contains(self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    /// Returns true if readable.
    pub const fn is_read(self) -> bool {
        self.0 & VM_READ != 0
    }

    /// Returns true if writable.
    pub const fn is_write(self) -> bool {
        self.0 & VM_WRITE != 0
    }

    /// Returns true if executable.
    pub const fn is_exec(self) -> bool {
        self.0 & VM_EXEC != 0
    }

    /// Returns true if shared.
    pub const fn is_shared(self) -> bool {
        self.0 & VM_SHARED != 0
    }

    /// Computes a 4-bit protection index for `protection_map` lookup.
    ///
    /// Bits: `[shared][exec][write][read]`.
    pub fn protection_index(self) -> usize {
        let mut idx = 0;
        if self.is_read() {
            idx |= 1;
        }
        if self.is_write() {
            idx |= 2;
        }
        if self.is_exec() {
            idx |= 4;
        }
        if self.is_shared() {
            idx |= 8;
        }
        idx
    }
}

// -------------------------------------------------------------------
// ProtectionMap
// -------------------------------------------------------------------

/// Number of protection map entries (4 bits = 16 combinations).
const PROT_MAP_SIZE: usize = 16;

/// Maps VM flags to PTE protection bits.
///
/// The 16-entry table is indexed by `[shared][exec][write][read]`.
/// Each entry contains the PTE flags to apply for that combination.
pub struct ProtectionMap {
    /// The mapping table.
    entries: [u64; PROT_MAP_SIZE],
}

impl ProtectionMap {
    /// Creates the default x86_64 protection map.
    pub fn new_x86_64() -> Self {
        let mut entries = [0u64; PROT_MAP_SIZE];

        // Private mappings (shared=0).
        // 0b0000: none        -> not present
        entries[0b0000] = 0;
        // 0b0001: read        -> present, NX
        entries[0b0001] = PTE_PRESENT | PTE_NX;
        // 0b0010: write       -> present, writable, NX
        entries[0b0010] = PTE_PRESENT | PTE_WRITABLE | PTE_NX;
        // 0b0011: read+write  -> present, writable, NX
        entries[0b0011] = PTE_PRESENT | PTE_WRITABLE | PTE_NX;
        // 0b0100: exec        -> present
        entries[0b0100] = PTE_PRESENT;
        // 0b0101: read+exec   -> present
        entries[0b0101] = PTE_PRESENT;
        // 0b0110: write+exec  -> present, writable
        entries[0b0110] = PTE_PRESENT | PTE_WRITABLE;
        // 0b0111: rwx         -> present, writable
        entries[0b0111] = PTE_PRESENT | PTE_WRITABLE;

        // Shared mappings (shared=1).
        // 0b1000: none        -> not present
        entries[0b1000] = 0;
        // 0b1001: read        -> present, NX
        entries[0b1001] = PTE_PRESENT | PTE_NX;
        // 0b1010: write       -> present, writable, NX
        entries[0b1010] = PTE_PRESENT | PTE_WRITABLE | PTE_NX;
        // 0b1011: read+write  -> present, writable, NX
        entries[0b1011] = PTE_PRESENT | PTE_WRITABLE | PTE_NX;
        // 0b1100: exec        -> present
        entries[0b1100] = PTE_PRESENT;
        // 0b1101: read+exec   -> present
        entries[0b1101] = PTE_PRESENT;
        // 0b1110: write+exec  -> present, writable
        entries[0b1110] = PTE_PRESENT | PTE_WRITABLE;
        // 0b1111: rwx         -> present, writable
        entries[0b1111] = PTE_PRESENT | PTE_WRITABLE;

        Self { entries }
    }

    /// Looks up PTE flags for the given VM flags.
    pub fn lookup(&self, vm_flags: VmFlags) -> u64 {
        let idx = vm_flags.protection_index();
        self.entries[idx]
    }

    /// Sets a custom entry in the protection map.
    pub fn set_entry(&mut self, index: usize, pte_flags: u64) -> Result<()> {
        if index >= PROT_MAP_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.entries[index] = pte_flags;
        Ok(())
    }

    /// Returns the raw entries.
    pub fn entries(&self) -> &[u64; PROT_MAP_SIZE] {
        &self.entries
    }

    /// Creates a PTE for a user-space mapping.
    pub fn make_user_pte(&self, pfn: u64, vm_flags: VmFlags) -> PageTableEntry {
        let flags = self.lookup(vm_flags) | PTE_USER | PTE_ACCESSED;
        PageTableEntry::from_pfn_flags(pfn, flags)
    }

    /// Creates a PTE for a kernel mapping.
    pub fn make_kernel_pte(&self, pfn: u64, writable: bool) -> PageTableEntry {
        let mut flags = PTE_PRESENT | PTE_ACCESSED | PTE_GLOBAL | PTE_NX;
        if writable {
            flags |= PTE_WRITABLE;
        }
        PageTableEntry::from_pfn_flags(pfn, flags)
    }
}

impl Default for ProtectionMap {
    fn default() -> Self {
        Self::new_x86_64()
    }
}
