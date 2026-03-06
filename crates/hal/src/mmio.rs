// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory-Mapped I/O (MMIO) abstraction.
//!
//! Provides typed volatile read/write helpers for MMIO register
//! regions, plus an `MmioRegion` descriptor and an `MmioMapping`
//! that tracks mapped regions with a simple reference-count stub.
//!
//! # Access patterns
//!
//! All reads and writes use `core::ptr::read_volatile` /
//! `core::ptr::write_volatile` so the compiler cannot elide or
//! reorder them.  "Relaxed" variants are semantically identical on
//! x86_64 (which has a strong memory model) but are provided for
//! clarity when barriers are not needed.

use oncrix_lib::{Error, Result};

// ── Typed volatile helpers ───────────────────────────────────────────────────

/// Read a `u8` from an MMIO address.
///
/// # Safety
///
/// `addr` must be a valid, mapped, readable MMIO address.
pub unsafe fn read8(addr: u64) -> u8 {
    // SAFETY: Caller guarantees addr is valid MMIO.
    unsafe { core::ptr::read_volatile(addr as *const u8) }
}

/// Read a `u16` from an MMIO address.
///
/// # Safety
///
/// `addr` must be 2-byte aligned and point to a valid MMIO region.
pub unsafe fn read16(addr: u64) -> u16 {
    // SAFETY: Caller guarantees alignment and valid MMIO.
    unsafe { core::ptr::read_volatile(addr as *const u16) }
}

/// Read a `u32` from an MMIO address.
///
/// # Safety
///
/// `addr` must be 4-byte aligned and point to a valid MMIO region.
pub unsafe fn read32(addr: u64) -> u32 {
    // SAFETY: Caller guarantees alignment and valid MMIO.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Read a `u64` from an MMIO address.
///
/// # Safety
///
/// `addr` must be 8-byte aligned and point to a valid MMIO region.
pub unsafe fn read64(addr: u64) -> u64 {
    // SAFETY: Caller guarantees alignment and valid MMIO.
    unsafe { core::ptr::read_volatile(addr as *const u64) }
}

/// Write a `u8` to an MMIO address.
///
/// # Safety
///
/// `addr` must be a valid, mapped, writable MMIO address.
pub unsafe fn write8(addr: u64, val: u8) {
    // SAFETY: Caller guarantees addr is valid MMIO.
    unsafe { core::ptr::write_volatile(addr as *mut u8, val) }
}

/// Write a `u16` to an MMIO address.
///
/// # Safety
///
/// `addr` must be 2-byte aligned.
pub unsafe fn write16(addr: u64, val: u16) {
    // SAFETY: Caller guarantees alignment and valid MMIO.
    unsafe { core::ptr::write_volatile(addr as *mut u16, val) }
}

/// Write a `u32` to an MMIO address.
///
/// # Safety
///
/// `addr` must be 4-byte aligned.
pub unsafe fn write32(addr: u64, val: u32) {
    // SAFETY: Caller guarantees alignment and valid MMIO.
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
}

/// Write a `u64` to an MMIO address.
///
/// # Safety
///
/// `addr` must be 8-byte aligned.
pub unsafe fn write64(addr: u64, val: u64) {
    // SAFETY: Caller guarantees alignment and valid MMIO.
    unsafe { core::ptr::write_volatile(addr as *mut u64, val) }
}

// Relaxed variants — on x86_64 identical to the non-relaxed forms.

/// Read a `u32` without ordering guarantees (no-op fence on x86_64).
///
/// # Safety
///
/// Same as [`read32`].
pub unsafe fn readl_relaxed(addr: u64) -> u32 {
    // SAFETY: Same as read32.
    unsafe { read32(addr) }
}

/// Write a `u32` without ordering guarantees (no-op fence on x86_64).
///
/// # Safety
///
/// Same as [`write32`].
pub unsafe fn writel_relaxed(addr: u64, val: u32) {
    // SAFETY: Same as write32.
    unsafe { write32(addr, val) }
}

// ── Offset-based helpers ─────────────────────────────────────────────────────

/// Read a `u32` at `base + offset`.
///
/// # Safety
///
/// `base + offset` must be a valid, 4-byte-aligned MMIO address.
pub unsafe fn read_mmio32(base: u64, offset: u64) -> u32 {
    // SAFETY: Caller provides valid MMIO base and offset.
    unsafe { read32(base + offset) }
}

/// Write a `u32` at `base + offset`.
///
/// # Safety
///
/// `base + offset` must be a valid, 4-byte-aligned, writable MMIO address.
pub unsafe fn write_mmio32(base: u64, offset: u64, val: u32) {
    // SAFETY: Caller provides valid MMIO base, offset, and write access.
    unsafe { write32(base + offset, val) }
}

/// Read a `u64` at `base + offset`.
///
/// # Safety
///
/// `base + offset` must be valid and 8-byte aligned.
pub unsafe fn read_mmio64(base: u64, offset: u64) -> u64 {
    // SAFETY: Caller provides valid MMIO base and offset.
    unsafe { read64(base + offset) }
}

/// Write a `u64` at `base + offset`.
///
/// # Safety
///
/// `base + offset` must be valid, 8-byte aligned, and writable.
pub unsafe fn write_mmio64(base: u64, offset: u64, val: u64) {
    // SAFETY: Caller provides valid MMIO base, offset, and write access.
    unsafe { write64(base + offset, val) }
}

// ── MmioRegion ───────────────────────────────────────────────────────────────

/// Descriptor for a physical MMIO region.
#[derive(Debug, Clone, Copy)]
pub struct MmioRegion {
    /// Physical base address.
    pub phys_base: u64,
    /// Region size in bytes.
    pub size: usize,
}

impl MmioRegion {
    /// Create a new region descriptor.
    pub const fn new(phys_base: u64, size: usize) -> Self {
        Self { phys_base, size }
    }

    /// Return whether the region contains the given physical offset.
    pub fn contains_offset(&self, offset: usize) -> bool {
        offset < self.size
    }

    /// Return the physical address for a given offset.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `offset >= size`.
    pub fn addr_at(&self, offset: usize) -> Result<u64> {
        if offset >= self.size {
            return Err(Error::InvalidArgument);
        }
        Ok(self.phys_base + offset as u64)
    }
}

// ── MmioMapping ──────────────────────────────────────────────────────────────

/// An active kernel-virtual mapping of an MMIO region.
///
/// In a real kernel, `ioremap` would walk the page tables and map
/// the physical region into kernel virtual address space. Here we
/// model the relationship but do not perform actual page table
/// manipulation (that is handled by the `mm` crate).
#[derive(Debug)]
pub struct MmioMapping {
    /// Underlying region descriptor.
    region: MmioRegion,
    /// Kernel virtual base address of the mapping.
    virt_base: u64,
    /// Reference count (simple bump counter, not atomic here).
    ref_count: u32,
}

impl MmioMapping {
    /// Create a new MMIO mapping.
    ///
    /// `virt_base` is the kernel virtual address that maps to
    /// `region.phys_base`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `virt_base` is zero.
    pub fn new(region: MmioRegion, virt_base: u64) -> Result<Self> {
        if virt_base == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            region,
            virt_base,
            ref_count: 1,
        })
    }

    /// Return the kernel virtual base address.
    pub fn virt_base(&self) -> u64 {
        self.virt_base
    }

    /// Return the underlying region descriptor.
    pub fn region(&self) -> &MmioRegion {
        &self.region
    }

    /// Read a `u32` at `offset` within the mapping.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if offset is out of bounds.
    pub fn read32_at(&self, offset: usize) -> Result<u32> {
        if offset + 4 > self.region.size {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: virt_base + offset is within the mapped region validated
        // by the bounds check above.
        Ok(unsafe { read32(self.virt_base + offset as u64) })
    }

    /// Write a `u32` at `offset` within the mapping.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if offset is out of bounds.
    pub fn write32_at(&self, offset: usize, val: u32) -> Result<()> {
        if offset + 4 > self.region.size {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: same as read32_at.
        unsafe { write32(self.virt_base + offset as u64, val) };
        Ok(())
    }

    /// Read a `u64` at `offset` within the mapping.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if offset is out of bounds.
    pub fn read64_at(&self, offset: usize) -> Result<u64> {
        if offset + 8 > self.region.size {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: bounds checked above.
        Ok(unsafe { read64(self.virt_base + offset as u64) })
    }

    /// Write a `u64` at `offset` within the mapping.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if offset is out of bounds.
    pub fn write64_at(&self, offset: usize, val: u64) -> Result<()> {
        if offset + 8 > self.region.size {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: bounds checked above.
        unsafe { write64(self.virt_base + offset as u64, val) };
        Ok(())
    }

    /// Increment the reference count (stub — real impl would use atomics).
    pub fn acquire(&mut self) {
        self.ref_count = self.ref_count.saturating_add(1);
    }

    /// Decrement the reference count.
    ///
    /// Returns `true` if the count reaches zero (mapping should be released).
    pub fn release(&mut self) -> bool {
        self.ref_count = self.ref_count.saturating_sub(1);
        self.ref_count == 0
    }

    /// Return the current reference count.
    pub fn ref_count(&self) -> u32 {
        self.ref_count
    }
}

// ── ioremap / iounmap stubs ───────────────────────────────────────────────────

/// Map a physical MMIO region into kernel virtual address space.
///
/// In ONCRIX, actual page table manipulation is handled by the `mm`
/// crate.  This function validates the request and returns a mapping
/// descriptor; the caller must supply the pre-mapped `virt_base`.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `phys_base` or `size` is zero,
/// or if `virt_base` is zero.
pub fn ioremap(phys_base: u64, size: usize, virt_base: u64) -> Result<MmioMapping> {
    if phys_base == 0 || size == 0 || virt_base == 0 {
        return Err(Error::InvalidArgument);
    }
    let region = MmioRegion::new(phys_base, size);
    MmioMapping::new(region, virt_base)
}

/// Release an MMIO mapping.
///
/// Decrements the reference count. Returns `true` when the mapping
/// reaches zero references and the virtual mapping should be torn down
/// (actual teardown is performed by the `mm` crate).
pub fn iounmap(mapping: &mut MmioMapping) -> bool {
    mapping.release()
}
