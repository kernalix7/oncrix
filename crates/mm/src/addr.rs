// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Physical and virtual address newtypes with alignment guarantees.

use core::fmt;

/// Standard page size (4 KiB).
pub const PAGE_SIZE: usize = 4096;

/// Bits to shift for page-frame alignment.
pub const PAGE_SHIFT: usize = 12;

/// A physical memory address.
///
/// On x86_64, only the lower 52 bits are valid.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PhysAddr(u64);

impl PhysAddr {
    /// Create a new `PhysAddr`, truncating to valid physical bits.
    pub const fn new(addr: u64) -> Self {
        // x86_64: bits 52..63 must be zero
        Self(addr & 0x000F_FFFF_FFFF_FFFF)
    }

    /// Return the raw `u64` value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Check whether this address is page-aligned.
    pub const fn is_aligned(self) -> bool {
        self.0 % PAGE_SIZE as u64 == 0
    }

    /// Align this address down to the nearest page boundary.
    pub const fn align_down(self) -> Self {
        Self(self.0 & !(PAGE_SIZE as u64 - 1))
    }

    /// Align this address up to the nearest page boundary.
    ///
    /// Returns `None` on overflow.
    pub const fn align_up(self) -> Option<Self> {
        let mask = PAGE_SIZE as u64 - 1;
        match self.0.checked_add(mask) {
            Some(aligned) => Some(Self::new(aligned & !mask)),
            None => None,
        }
    }
}

impl fmt::Debug for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PhysAddr({:#x})", self.0)
    }
}

impl fmt::Display for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

/// A virtual memory address.
///
/// On x86_64, valid canonical addresses have bits 47..63 either all
/// set or all clear (sign-extension of bit 47).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct VirtAddr(u64);

impl VirtAddr {
    /// Create a new `VirtAddr`, enforcing canonical form on x86_64.
    ///
    /// Bit 47 is sign-extended into bits 48..63.
    pub const fn new(addr: u64) -> Self {
        // Sign-extend from bit 47
        let shifted = ((addr << 16) as i64 >> 16) as u64;
        Self(shifted)
    }

    /// Return the raw `u64` value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Check whether this address is page-aligned.
    pub const fn is_aligned(self) -> bool {
        self.0 % PAGE_SIZE as u64 == 0
    }

    /// Align this address down to the nearest page boundary.
    pub const fn align_down(self) -> Self {
        Self(self.0 & !(PAGE_SIZE as u64 - 1))
    }

    /// Align this address up to the nearest page boundary.
    ///
    /// Returns `None` on overflow.
    pub const fn align_up(self) -> Option<Self> {
        let mask = PAGE_SIZE as u64 - 1;
        match self.0.checked_add(mask) {
            Some(aligned) => Some(Self::new(aligned & !mask)),
            None => None,
        }
    }

    /// Page table indices for this virtual address (P4, P3, P2, P1).
    pub const fn page_table_indices(self) -> [usize; 4] {
        [
            ((self.0 >> 39) & 0x1FF) as usize, // P4 (PML4)
            ((self.0 >> 30) & 0x1FF) as usize, // P3 (PDPT)
            ((self.0 >> 21) & 0x1FF) as usize, // P2 (PD)
            ((self.0 >> 12) & 0x1FF) as usize, // P1 (PT)
        ]
    }

    /// Page offset (lower 12 bits).
    pub const fn page_offset(self) -> u16 {
        (self.0 & 0xFFF) as u16
    }
}

impl fmt::Debug for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VirtAddr({:#x})", self.0)
    }
}

impl fmt::Display for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}
