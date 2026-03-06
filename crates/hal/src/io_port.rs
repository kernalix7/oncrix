// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! I/O port abstraction layer.
//!
//! Provides safe wrappers around x86 IN/OUT instructions and a
//! simple allocator that tracks which 16-bit I/O port ranges have
//! been claimed by drivers.
//!
//! # Usage
//!
//! ```no_run
//! let mut alloc = IoPortAllocator::new();
//! alloc.request(0x3F8, 8, "uart0").unwrap();
//! let _v = inb(0x3F8);
//! ```

use oncrix_lib::{Error, Result};

// ── Port I/O primitives ───────────────────────────────────────────────────────

/// Read a byte (8-bit) from an I/O port.
///
/// # Safety (x86_64)
///
/// Must be called at CPL 0. The port must be accessible to kernel
/// space (IOPL=0 or the TSS I/O permission bitmap must allow it).
#[cfg(target_arch = "x86_64")]
pub fn inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: Caller ensures CPL 0 ring and valid port.
    unsafe {
        core::arch::asm!(
            "in al, dx",
            in("dx") port,
            out("al") val,
            options(nostack, nomem, preserves_flags),
        );
    }
    val
}

/// Write a byte (8-bit) to an I/O port.
///
/// # Safety (x86_64)
///
/// Must be called at CPL 0.
#[cfg(target_arch = "x86_64")]
pub fn outb(port: u16, val: u8) {
    // SAFETY: Caller ensures CPL 0 ring and valid port.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nostack, nomem, preserves_flags),
        );
    }
}

/// Read a 16-bit word from an I/O port.
#[cfg(target_arch = "x86_64")]
pub fn inw(port: u16) -> u16 {
    let val: u16;
    // SAFETY: Caller ensures CPL 0 ring and valid port.
    unsafe {
        core::arch::asm!(
            "in ax, dx",
            in("dx") port,
            out("ax") val,
            options(nostack, nomem, preserves_flags),
        );
    }
    val
}

/// Write a 16-bit word to an I/O port.
#[cfg(target_arch = "x86_64")]
pub fn outw(port: u16, val: u16) {
    // SAFETY: Caller ensures CPL 0 ring and valid port.
    unsafe {
        core::arch::asm!(
            "out dx, ax",
            in("dx") port,
            in("ax") val,
            options(nostack, nomem, preserves_flags),
        );
    }
}

/// Read a 32-bit doubleword from an I/O port.
#[cfg(target_arch = "x86_64")]
pub fn inl(port: u16) -> u32 {
    let val: u32;
    // SAFETY: Caller ensures CPL 0 ring and valid port.
    unsafe {
        core::arch::asm!(
            "in eax, dx",
            in("dx") port,
            out("eax") val,
            options(nostack, nomem, preserves_flags),
        );
    }
    val
}

/// Write a 32-bit doubleword to an I/O port.
#[cfg(target_arch = "x86_64")]
pub fn outl(port: u16, val: u32) {
    // SAFETY: Caller ensures CPL 0 ring and valid port.
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") port,
            in("eax") val,
            options(nostack, nomem, preserves_flags),
        );
    }
}

// Non-x86_64 stubs.
#[cfg(not(target_arch = "x86_64"))]
pub fn inb(_port: u16) -> u8 {
    0
}
#[cfg(not(target_arch = "x86_64"))]
pub fn outb(_port: u16, _val: u8) {}
#[cfg(not(target_arch = "x86_64"))]
pub fn inw(_port: u16) -> u16 {
    0
}
#[cfg(not(target_arch = "x86_64"))]
pub fn outw(_port: u16, _val: u16) {}
#[cfg(not(target_arch = "x86_64"))]
pub fn inl(_port: u16) -> u32 {
    0
}
#[cfg(not(target_arch = "x86_64"))]
pub fn outl(_port: u16, _val: u32) {}

// ── PortRange ────────────────────────────────────────────────────────────────

/// A named I/O port range.
#[derive(Debug, Clone, Copy)]
pub struct PortRange {
    /// First port in the range.
    pub base: u16,
    /// Number of ports in the range.
    pub size: u16,
    /// Name tag (up to 16 bytes, NUL-terminated or filled).
    pub name: [u8; 16],
    /// Whether this slot is occupied.
    pub occupied: bool,
}

impl PortRange {
    /// Create an empty slot.
    pub const fn empty() -> Self {
        Self {
            base: 0,
            size: 0,
            name: [0u8; 16],
            occupied: false,
        }
    }

    /// Create a named port range.
    pub fn new(base: u16, size: u16, name: &str) -> Self {
        let mut n = [0u8; 16];
        let bytes = name.as_bytes();
        let len = bytes.len().min(15);
        n[..len].copy_from_slice(&bytes[..len]);
        Self {
            base,
            size,
            name: n,
            occupied: true,
        }
    }

    /// Return whether `port` falls within this range.
    pub fn contains(&self, port: u16) -> bool {
        port >= self.base && port < self.base.saturating_add(self.size)
    }

    /// Return whether this range overlaps `[other_base, other_base+other_size)`.
    pub fn overlaps(&self, other_base: u16, other_size: u16) -> bool {
        let self_end = self.base.saturating_add(self.size);
        let other_end = other_base.saturating_add(other_size);
        self.base < other_end && other_base < self_end
    }
}

// ── IoPortAllocator ───────────────────────────────────────────────────────────

/// Maximum number of simultaneously tracked port ranges.
const MAX_PORT_RANGES: usize = 64;

/// I/O port range allocator.
///
/// Tracks which 16-bit I/O port ranges have been claimed by drivers
/// and prevents double-registration.
pub struct IoPortAllocator {
    ranges: [PortRange; MAX_PORT_RANGES],
    count: usize,
}

impl IoPortAllocator {
    /// Create an empty allocator.
    pub const fn new() -> Self {
        Self {
            ranges: [const { PortRange::empty() }; MAX_PORT_RANGES],
            count: 0,
        }
    }

    /// Claim a port range on behalf of a named driver.
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyExists`] if any port in the range is already claimed.
    /// - [`Error::OutOfMemory`] if no allocator slots remain.
    /// - [`Error::InvalidArgument`] if `size` is zero.
    pub fn request(&mut self, base: u16, size: u16, name: &str) -> Result<()> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        // Check for overlap with any existing range.
        for i in 0..self.count {
            if self.ranges[i].occupied && self.ranges[i].overlaps(base, size) {
                return Err(Error::AlreadyExists);
            }
        }
        if self.count >= MAX_PORT_RANGES {
            return Err(Error::OutOfMemory);
        }
        self.ranges[self.count] = PortRange::new(base, size, name);
        self.count += 1;
        Ok(())
    }

    /// Release a previously claimed port range.
    ///
    /// Removes the range that starts at `base` with `size` ports.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching range exists.
    pub fn release(&mut self, base: u16, size: u16) -> Result<()> {
        for i in 0..self.count {
            if self.ranges[i].occupied && self.ranges[i].base == base && self.ranges[i].size == size
            {
                // Swap-remove to keep the array compact.
                self.count -= 1;
                self.ranges.swap(i, self.count);
                self.ranges[self.count] = PortRange::empty();
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Return the number of registered ranges.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return whether no ranges are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Look up which range owns `port`, if any.
    pub fn find(&self, port: u16) -> Option<&PortRange> {
        for i in 0..self.count {
            if self.ranges[i].occupied && self.ranges[i].contains(port) {
                return Some(&self.ranges[i]);
            }
        }
        None
    }

    /// Return whether `port` has been claimed.
    pub fn is_claimed(&self, port: u16) -> bool {
        self.find(port).is_some()
    }
}

impl Default for IoPortAllocator {
    fn default() -> Self {
        Self::new()
    }
}

// ── I/O delay ────────────────────────────────────────────────────────────────

/// Perform an I/O delay by writing to port 0x80 (POST diagnostic).
///
/// Used after slow ISA device accesses that require a settling period.
pub fn io_delay() {
    outb(0x80, 0);
}
