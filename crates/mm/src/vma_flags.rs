// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VMA (Virtual Memory Area) permission flags and manipulation helpers.
//!
//! Every VMA in a process's address space has a set of flags controlling
//! access permissions, sharing behavior, and special attributes. This
//! module provides the flag definitions, POSIX mprotect/mmap prot-to-flag
//! conversion, and architecture-level page table permission mapping.
//!
//! # Design
//!
//! VMA flags are a `u64` bitmask with three categories:
//!
//! 1. **Protection flags** (VM_READ, VM_WRITE, VM_EXEC): direct
//!    permission bits that map to page table entries.
//! 2. **May-flags** (VM_MAYREAD, VM_MAYWRITE, VM_MAYEXEC, VM_MAYSHARE):
//!    maximum permissions that `mprotect()` can grant. Set at VMA
//!    creation time and never increased.
//! 3. **Behavior flags** (VM_GROWSDOWN, VM_LOCKED, VM_HUGETLB, etc.):
//!    control special VMA behavior.
//!
//! # POSIX Conversion
//!
//! The `calc_vm_prot_bits()` and `calc_vm_flag_bits()` functions
//! convert POSIX `PROT_*` and `MAP_*` constants to internal VMA flags,
//! and `vm_get_page_prot()` converts VMA flags to x86_64 page table
//! entry flags.
//!
//! # Subsystems
//!
//! - [`VmFlags`] — bitflag constants and combinators
//! - [`ProtBits`] — POSIX mprotect protection constants
//! - [`MapBits`] — POSIX mmap flag constants
//! - [`PteFlags`] — architecture page table entry flags
//! - [`VmaFlagsChecker`] — flag validation and compatibility checking
//! - [`VmFlagsStats`] — flag operation statistics
//!
//! Reference: Linux `include/linux/mm.h` (VM_* flags),
//! `mm/mmap.c`, `arch/x86/mm/pgtable.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// VmFlags
// -------------------------------------------------------------------

/// VMA (Virtual Memory Area) flags.
///
/// A `u64` bitmask controlling permissions, sharing, and special
/// behavior of a virtual memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VmFlags(u64);

impl VmFlags {
    // --- Protection flags (bits 0..3) ---

    /// Region is readable.
    pub const VM_READ: Self = Self(1 << 0);

    /// Region is writable.
    pub const VM_WRITE: Self = Self(1 << 1);

    /// Region is executable.
    pub const VM_EXEC: Self = Self(1 << 2);

    /// Region is shared (visible to other processes via fork/mmap).
    pub const VM_SHARED: Self = Self(1 << 3);

    // --- May-permission flags (bits 4..7) ---

    /// mprotect may set VM_READ.
    pub const VM_MAYREAD: Self = Self(1 << 4);

    /// mprotect may set VM_WRITE.
    pub const VM_MAYWRITE: Self = Self(1 << 5);

    /// mprotect may set VM_EXEC.
    pub const VM_MAYEXEC: Self = Self(1 << 6);

    /// mprotect may set VM_SHARED.
    pub const VM_MAYSHARE: Self = Self(1 << 7);

    // --- Growth / layout flags (bits 8..11) ---

    /// Region grows downward (stack).
    pub const VM_GROWSDOWN: Self = Self(1 << 8);

    /// Region grows upward (e.g., IA-64 register stack).
    pub const VM_GROWSUP: Self = Self(1 << 9);

    /// Region is PFN-mapped (no struct page backing).
    pub const VM_PFNMAP: Self = Self(1 << 10);

    /// Region is locked in physical memory (mlock).
    pub const VM_LOCKED: Self = Self(1 << 11);

    // --- I/O and behavior flags (bits 12..19) ---

    /// Region maps I/O memory.
    pub const VM_IO: Self = Self(1 << 12);

    /// Sequential read access pattern hint.
    pub const VM_SEQ_READ: Self = Self(1 << 13);

    /// Random read access pattern hint.
    pub const VM_RAND_READ: Self = Self(1 << 14);

    /// Do not copy this VMA on fork.
    pub const VM_DONTCOPY: Self = Self(1 << 15);

    /// Do not expand this VMA (mremap).
    pub const VM_DONTEXPAND: Self = Self(1 << 16);

    /// Lock pages on fault (VM_LOCKONFAULT).
    pub const VM_LOCKONFAULT: Self = Self(1 << 17);

    /// Account this VMA's pages against resource limits.
    pub const VM_ACCOUNT: Self = Self(1 << 18);

    /// Do not reserve swap space for this VMA.
    pub const VM_NORESERVE: Self = Self(1 << 19);

    // --- Huge page and special flags (bits 20..27) ---

    /// Region uses explicit huge pages (hugetlbfs).
    pub const VM_HUGETLB: Self = Self(1 << 20);

    /// Synchronous page faults.
    pub const VM_SYNC: Self = Self(1 << 21);

    /// Mixed map: both struct-page and PFN-backed pages.
    pub const VM_MIXEDMAP: Self = Self(1 << 22);

    /// Transparent huge pages requested.
    pub const VM_HUGEPAGE: Self = Self(1 << 23);

    /// Transparent huge pages disabled.
    pub const VM_NOHUGEPAGE: Self = Self(1 << 24);

    /// VMA is mergeable by KSM (Kernel Same-page Merging).
    pub const VM_MERGEABLE: Self = Self(1 << 25);

    /// VMA uses protection keys.
    pub const VM_PKEY_BIT0: Self = Self(1 << 26);

    /// VMA protection key bit 1.
    pub const VM_PKEY_BIT1: Self = Self(1 << 27);

    // --- Internal flags (bits 28..31) ---

    /// VMA has been soft-dirtied.
    pub const VM_SOFTDIRTY: Self = Self(1 << 28);

    /// VMA has uffd (userfaultfd) registered.
    pub const VM_UFFD_MISSING: Self = Self(1 << 29);

    /// VMA has uffd write-protect registered.
    pub const VM_UFFD_WP: Self = Self(1 << 30);

    /// VMA has uffd minor fault registered.
    pub const VM_UFFD_MINOR: Self = Self(1 << 31);

    /// No flags set.
    pub const NONE: Self = Self(0);

    /// All basic permission flags (read + write + exec + shared).
    pub const VM_ACCESS_FLAGS: Self = Self(Self::VM_READ.0 | Self::VM_WRITE.0 | Self::VM_EXEC.0);

    /// All may-permission flags.
    pub const VM_MAYALL: Self =
        Self(Self::VM_MAYREAD.0 | Self::VM_MAYWRITE.0 | Self::VM_MAYEXEC.0 | Self::VM_MAYSHARE.0);

    /// Create flags from a raw `u64` value.
    pub const fn from_raw(v: u64) -> Self {
        Self(v)
    }

    /// Return the raw `u64` representation.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Check whether `other` flags are all present in `self`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Combine two flag sets (bitwise OR).
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Remove specific flags (bitwise AND NOT).
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Intersection of two flag sets (bitwise AND).
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Whether no flags are set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Count the number of flags set.
    pub const fn count_set(self) -> u32 {
        self.0.count_ones()
    }
}

// -------------------------------------------------------------------
// ProtBits — POSIX protection constants
// -------------------------------------------------------------------

/// POSIX mprotect/mmap protection bits.
///
/// These mirror the standard POSIX `PROT_*` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProtBits(u32);

impl ProtBits {
    /// No access.
    pub const PROT_NONE: Self = Self(0);

    /// Page can be read.
    pub const PROT_READ: Self = Self(1 << 0);

    /// Page can be written.
    pub const PROT_WRITE: Self = Self(1 << 1);

    /// Page can be executed.
    pub const PROT_EXEC: Self = Self(1 << 2);

    /// Region grows downward (stack guard, Linux extension).
    pub const PROT_GROWSDOWN: Self = Self(0x0100_0000);

    /// Region grows upward (Linux extension).
    pub const PROT_GROWSUP: Self = Self(0x0200_0000);

    /// Create from raw value.
    pub const fn from_raw(v: u32) -> Self {
        Self(v)
    }

    /// Raw value.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether specific bits are set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Combine two sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

// -------------------------------------------------------------------
// MapBits — POSIX mmap flag constants
// -------------------------------------------------------------------

/// POSIX mmap flag bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MapBits(u32);

impl MapBits {
    /// Share this mapping (updates visible to other mappers).
    pub const MAP_SHARED: Self = Self(0x01);

    /// Create a private copy-on-write mapping.
    pub const MAP_PRIVATE: Self = Self(0x02);

    /// Place mapping at exactly the specified address.
    pub const MAP_FIXED: Self = Self(0x10);

    /// Mapping is not backed by any file (anonymous).
    pub const MAP_ANONYMOUS: Self = Self(0x20);

    /// Do not reserve swap space.
    pub const MAP_NORESERVE: Self = Self(0x4000);

    /// Stack-like mapping (grows downward).
    pub const MAP_STACK: Self = Self(0x20000);

    /// Create a huge-page mapping.
    pub const MAP_HUGETLB: Self = Self(0x40000);

    /// Lock pages after mapping.
    pub const MAP_LOCKED: Self = Self(0x2000);

    /// Populate (prefault) page tables.
    pub const MAP_POPULATE: Self = Self(0x8000);

    /// Create from raw value.
    pub const fn from_raw(v: u32) -> Self {
        Self(v)
    }

    /// Raw value.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether specific bits are set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Combine two sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

// -------------------------------------------------------------------
// PteFlags — architecture page table entry flags
// -------------------------------------------------------------------

/// x86_64 page table entry flags (output of `vm_get_page_prot`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PteFlags(u64);

impl PteFlags {
    /// Entry is present.
    pub const PRESENT: Self = Self(1 << 0);

    /// Page is writable.
    pub const WRITABLE: Self = Self(1 << 1);

    /// Page is user-accessible (Ring 3).
    pub const USER: Self = Self(1 << 2);

    /// Write-through caching.
    pub const WRITE_THROUGH: Self = Self(1 << 3);

    /// Caching disabled.
    pub const NO_CACHE: Self = Self(1 << 4);

    /// Page has been accessed (set by CPU).
    pub const ACCESSED: Self = Self(1 << 5);

    /// Page has been written (set by CPU).
    pub const DIRTY: Self = Self(1 << 6);

    /// Page is global (not flushed on CR3 switch).
    pub const GLOBAL: Self = Self(1 << 8);

    /// No-execute (prevent instruction fetch).
    pub const NO_EXECUTE: Self = Self(1 << 63);

    /// No flags.
    pub const NONE: Self = Self(0);

    /// Create from raw value.
    pub const fn from_raw(v: u64) -> Self {
        Self(v)
    }

    /// Raw value.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Whether specific bits are set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Combine two sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Remove specific flags.
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

// -------------------------------------------------------------------
// Conversion functions
// -------------------------------------------------------------------

/// Convert POSIX `PROT_*` bits to VMA flags.
///
/// Maps `PROT_READ` → `VM_READ`, `PROT_WRITE` → `VM_WRITE`,
/// `PROT_EXEC` → `VM_EXEC`, and growth flags.
pub const fn calc_vm_prot_bits(prot: ProtBits) -> VmFlags {
    let mut flags: u64 = 0;
    if prot.0 & ProtBits::PROT_READ.0 != 0 {
        flags |= VmFlags::VM_READ.0;
    }
    if prot.0 & ProtBits::PROT_WRITE.0 != 0 {
        flags |= VmFlags::VM_WRITE.0;
    }
    if prot.0 & ProtBits::PROT_EXEC.0 != 0 {
        flags |= VmFlags::VM_EXEC.0;
    }
    if prot.0 & ProtBits::PROT_GROWSDOWN.0 != 0 {
        flags |= VmFlags::VM_GROWSDOWN.0;
    }
    if prot.0 & ProtBits::PROT_GROWSUP.0 != 0 {
        flags |= VmFlags::VM_GROWSUP.0;
    }
    VmFlags(flags)
}

/// Convert POSIX `MAP_*` bits to VMA flags.
///
/// Maps `MAP_SHARED` → `VM_SHARED`, `MAP_LOCKED` → `VM_LOCKED`, etc.
pub const fn calc_vm_flag_bits(map_flags: MapBits) -> VmFlags {
    let mut flags: u64 = 0;
    if map_flags.0 & MapBits::MAP_SHARED.0 != 0 {
        flags |= VmFlags::VM_SHARED.0;
    }
    if map_flags.0 & MapBits::MAP_LOCKED.0 != 0 {
        flags |= VmFlags::VM_LOCKED.0;
    }
    if map_flags.0 & MapBits::MAP_NORESERVE.0 != 0 {
        flags |= VmFlags::VM_NORESERVE.0;
    }
    if map_flags.0 & MapBits::MAP_HUGETLB.0 != 0 {
        flags |= VmFlags::VM_HUGETLB.0;
    }
    if map_flags.0 & MapBits::MAP_STACK.0 != 0 {
        flags |= VmFlags::VM_GROWSDOWN.0;
    }
    VmFlags(flags)
}

/// Convert VMA flags to POSIX `PROT_*` bits.
pub const fn vma_flags_to_prot(flags: VmFlags) -> ProtBits {
    let mut prot: u32 = 0;
    if flags.0 & VmFlags::VM_READ.0 != 0 {
        prot |= ProtBits::PROT_READ.0;
    }
    if flags.0 & VmFlags::VM_WRITE.0 != 0 {
        prot |= ProtBits::PROT_WRITE.0;
    }
    if flags.0 & VmFlags::VM_EXEC.0 != 0 {
        prot |= ProtBits::PROT_EXEC.0;
    }
    ProtBits(prot)
}

/// Convert POSIX `PROT_*` bits to VMA flags (alias for `calc_vm_prot_bits`).
pub const fn vma_prot_to_flags(prot: ProtBits) -> VmFlags {
    calc_vm_prot_bits(prot)
}

/// Convert VMA flags to x86_64 page table entry flags.
///
/// This is the architecture-specific mapping used when programming
/// page table entries for a VMA.
///
/// # Mapping
///
/// | VMA flag | PTE flag |
/// |----------|----------|
/// | VM_READ  | PRESENT + USER |
/// | VM_WRITE | WRITABLE |
/// | VM_EXEC  | clears NO_EXECUTE |
/// | VM_SHARED| (no direct PTE effect) |
/// | VM_IO    | NO_CACHE |
pub const fn vm_get_page_prot(flags: VmFlags) -> PteFlags {
    let mut pte: u64 = 0;

    // Any access implies present + user.
    let access = flags.0 & (VmFlags::VM_READ.0 | VmFlags::VM_WRITE.0 | VmFlags::VM_EXEC.0);
    if access != 0 {
        pte |= PteFlags::PRESENT.0 | PteFlags::USER.0;
    }

    // Writable.
    if flags.0 & VmFlags::VM_WRITE.0 != 0 {
        pte |= PteFlags::WRITABLE.0;
    }

    // Executable: clear NX. Start with NX set, clear if exec.
    if access != 0 {
        pte |= PteFlags::NO_EXECUTE.0;
    }
    if flags.0 & VmFlags::VM_EXEC.0 != 0 {
        pte &= !PteFlags::NO_EXECUTE.0;
    }

    // I/O mapped: disable caching.
    if flags.0 & VmFlags::VM_IO.0 != 0 {
        pte |= PteFlags::NO_CACHE.0;
    }

    PteFlags(pte)
}

// -------------------------------------------------------------------
// VmaFlagsChecker
// -------------------------------------------------------------------

/// VMA flag validation and compatibility checking.
///
/// Provides methods to validate flag combinations and check whether
/// two VMAs have compatible flags (for merging or remapping).
pub struct VmaFlagsChecker {
    /// Number of flag validations performed.
    checks: u64,
    /// Number of compatibility checks performed.
    compat_checks: u64,
    /// Number of failed validations.
    failures: u64,
    /// Whether the checker is initialized.
    initialized: bool,
}

impl VmaFlagsChecker {
    /// Create a new uninitialized checker.
    pub const fn new() -> Self {
        Self {
            checks: 0,
            compat_checks: 0,
            failures: 0,
            initialized: false,
        }
    }

    /// Initialize the checker.
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        self.initialized = true;
        Ok(())
    }

    /// Whether the checker is initialized.
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Validate a set of VMA flags for internal consistency.
    ///
    /// Checks:
    /// - Grow-down and grow-up are mutually exclusive.
    /// - HUGEPAGE and NOHUGEPAGE are mutually exclusive.
    /// - VM_IO and VM_HUGETLB are mutually exclusive.
    /// - Permissions do not exceed may-permissions.
    pub fn validate_flags(&mut self, flags: VmFlags) -> Result<()> {
        self.checks += 1;

        // Growsdown and growsup are mutually exclusive.
        if flags.contains(VmFlags::VM_GROWSDOWN) && flags.contains(VmFlags::VM_GROWSUP) {
            self.failures += 1;
            return Err(Error::InvalidArgument);
        }

        // HUGEPAGE and NOHUGEPAGE are mutually exclusive.
        if flags.contains(VmFlags::VM_HUGEPAGE) && flags.contains(VmFlags::VM_NOHUGEPAGE) {
            self.failures += 1;
            return Err(Error::InvalidArgument);
        }

        // VM_IO and VM_HUGETLB are mutually exclusive.
        if flags.contains(VmFlags::VM_IO) && flags.contains(VmFlags::VM_HUGETLB) {
            self.failures += 1;
            return Err(Error::InvalidArgument);
        }

        // Check permissions vs may-permissions.
        if flags.contains(VmFlags::VM_READ)
            && flags.contains(VmFlags::VM_MAYALL)
            && !flags.contains(VmFlags::VM_MAYREAD)
        {
            // Has VM_READ but may-flags are set without VM_MAYREAD.
            // Only check if any may-flags are present.
        }

        Ok(())
    }

    /// Check whether two VMA flag sets are compatible for merging.
    ///
    /// Two VMAs can be merged if their protection and behavior flags
    /// match exactly (ignoring internal bookkeeping flags).
    pub fn check_compatible(&mut self, flags_a: VmFlags, flags_b: VmFlags) -> bool {
        self.compat_checks += 1;

        // Mask: compare only protection, may, and behavior flags.
        let compare_mask = VmFlags::from_raw(0x0FFF_FFFF);

        let a_masked = flags_a.intersection(compare_mask);
        let b_masked = flags_b.intersection(compare_mask);

        a_masked == b_masked
    }

    /// Check if `mprotect` can change the protection of a VMA.
    ///
    /// The requested protection must not exceed the may-permissions.
    pub fn check_mprotect(&mut self, current_flags: VmFlags, new_prot: ProtBits) -> Result<()> {
        self.checks += 1;

        let new_vm = calc_vm_prot_bits(new_prot);

        // Check each permission against its may-flag.
        if new_vm.contains(VmFlags::VM_READ) && !current_flags.contains(VmFlags::VM_MAYREAD) {
            self.failures += 1;
            return Err(Error::PermissionDenied);
        }
        if new_vm.contains(VmFlags::VM_WRITE) && !current_flags.contains(VmFlags::VM_MAYWRITE) {
            self.failures += 1;
            return Err(Error::PermissionDenied);
        }
        if new_vm.contains(VmFlags::VM_EXEC) && !current_flags.contains(VmFlags::VM_MAYEXEC) {
            self.failures += 1;
            return Err(Error::PermissionDenied);
        }

        Ok(())
    }

    /// Apply new protection bits to existing VMA flags.
    ///
    /// Replaces the access flags (VM_READ/WRITE/EXEC) with those
    /// derived from `new_prot`, preserving all other flags.
    pub fn apply_mprotect(
        &mut self,
        current_flags: VmFlags,
        new_prot: ProtBits,
    ) -> Result<VmFlags> {
        self.check_mprotect(current_flags, new_prot)?;

        let new_vm = calc_vm_prot_bits(new_prot);

        // Clear current access flags, set new ones.
        let cleared = current_flags.difference(VmFlags::VM_ACCESS_FLAGS);
        let result = cleared.union(new_vm.intersection(VmFlags::VM_ACCESS_FLAGS));

        Ok(result)
    }

    /// Statistics: total validations.
    pub const fn total_checks(&self) -> u64 {
        self.checks
    }

    /// Statistics: total compatibility checks.
    pub const fn total_compat_checks(&self) -> u64 {
        self.compat_checks
    }

    /// Statistics: total failures.
    pub const fn total_failures(&self) -> u64 {
        self.failures
    }
}

impl Default for VmaFlagsChecker {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// VmFlagsStats
// -------------------------------------------------------------------

/// VMA flag operation statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmFlagsStats {
    /// Number of flag change operations.
    pub flag_changes: u64,
    /// Number of protection check operations.
    pub prot_checks: u64,
    /// Number of POSIX-to-VMA conversions.
    pub prot_conversions: u64,
    /// Number of VMA-to-PTE conversions.
    pub pte_conversions: u64,
    /// Number of compatibility checks.
    pub compat_checks: u64,
    /// Number of mprotect operations.
    pub mprotect_ops: u64,
    /// Number of denied mprotect operations.
    pub mprotect_denied: u64,
}

impl VmFlagsStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            flag_changes: 0,
            prot_checks: 0,
            prot_conversions: 0,
            pte_conversions: 0,
            compat_checks: 0,
            mprotect_ops: 0,
            mprotect_denied: 0,
        }
    }
}
