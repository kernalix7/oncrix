// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel Address Sanitizer (KASAN).
//!
//! Runtime memory error detector for the kernel. KASAN uses shadow
//! memory to track the accessibility of every byte in kernel space.
//! Each 8 bytes of kernel memory map to 1 byte of shadow memory.
//!
//! # Detected Errors
//!
//! - Out-of-bounds heap/stack access
//! - Use-after-free
//! - Double-free
//! - Invalid-free (freeing non-allocated memory)
//!
//! # Shadow Memory Layout
//!
//! ```text
//! Kernel address space    Shadow memory
//! ┌─────────────┐        ┌───────┐
//! │ 8 bytes     │ ──────>│ 1 byte│
//! │ 8 bytes     │ ──────>│ 1 byte│
//! └─────────────┘        └───────┘
//!
//! Shadow values:
//!   0x00         = all 8 bytes accessible
//!   0x01..0x07   = first N bytes accessible
//!   0xFE         = freed memory (use-after-free)
//!   0xFF         = inaccessible (out-of-bounds)
//!   0xFD         = stack red-zone
//! ```

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Shadow memory scale: 1 shadow byte per 8 kernel bytes.
const SHADOW_SCALE: usize = 3; // 1 << 3 = 8

/// Shadow value: all 8 bytes accessible.
const SHADOW_ACCESSIBLE: u8 = 0x00;

/// Shadow value: freed memory.
const SHADOW_FREED: u8 = 0xFE;

/// Shadow value: completely inaccessible.
const SHADOW_INACCESSIBLE: u8 = 0xFF;

/// Shadow value: stack red-zone.
const SHADOW_STACK_REDZONE: u8 = 0xFD;

/// Shadow value: slab red-zone.
const _SHADOW_SLAB_REDZONE: u8 = 0xFC;

/// Maximum number of KASAN reports to buffer.
const MAX_REPORTS: usize = 64;

/// Maximum quarantine entries (deferred free list).
const MAX_QUARANTINE: usize = 256;

/// Maximum stack backtrace depth.
const MAX_BACKTRACE: usize = 16;

// ======================================================================
// Types
// ======================================================================

/// Type of memory error detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KasanErrorType {
    /// Access beyond allocated region.
    OutOfBounds,
    /// Access to freed memory.
    UseAfterFree,
    /// Second free of the same allocation.
    DoubleFree,
    /// Free of non-heap memory.
    InvalidFree,
    /// Stack buffer overflow.
    StackOverflow,
    /// Access to a global variable red-zone.
    GlobalOverflow,
}

impl Default for KasanErrorType {
    fn default() -> Self {
        Self::OutOfBounds
    }
}

/// A KASAN error report.
#[derive(Debug, Clone, Copy)]
pub struct KasanReport {
    /// Type of error detected.
    pub error_type: KasanErrorType,
    /// Faulting address.
    pub address: u64,
    /// Size of the access that triggered the error.
    pub access_size: usize,
    /// Whether the access was a write.
    pub is_write: bool,
    /// Instruction pointer where the violation occurred.
    pub ip: u64,
    /// Backtrace of return addresses.
    pub backtrace: [u64; MAX_BACKTRACE],
    /// Number of valid entries in backtrace.
    pub bt_depth: usize,
    /// Shadow byte value at the faulting address.
    pub shadow_val: u8,
    /// Timestamp (tick) of the report.
    pub timestamp: u64,
}

impl KasanReport {
    /// Creates an empty report.
    pub const fn new() -> Self {
        Self {
            error_type: KasanErrorType::OutOfBounds,
            address: 0,
            access_size: 0,
            is_write: false,
            ip: 0,
            backtrace: [0u64; MAX_BACKTRACE],
            bt_depth: 0,
            shadow_val: 0,
            timestamp: 0,
        }
    }
}

impl Default for KasanReport {
    fn default() -> Self {
        Self::new()
    }
}

/// Quarantine entry for deferred-free tracking.
#[derive(Debug, Clone, Copy)]
pub struct QuarantineEntry {
    /// Base address of the freed region.
    pub addr: u64,
    /// Size of the freed region.
    pub size: usize,
    /// Tick when the region was freed.
    pub free_tick: u64,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl QuarantineEntry {
    /// Creates an empty quarantine entry.
    pub const fn new() -> Self {
        Self {
            addr: 0,
            size: 0,
            free_tick: 0,
            active: false,
        }
    }
}

impl Default for QuarantineEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// KASAN subsystem state.
pub struct Kasan {
    /// Whether KASAN checking is enabled.
    enabled: bool,
    /// Shadow memory base address.
    shadow_base: u64,
    /// Shadow memory size in bytes.
    shadow_size: usize,
    /// Buffered error reports.
    reports: [KasanReport; MAX_REPORTS],
    /// Number of reports collected.
    nr_reports: usize,
    /// Quarantine for freed allocations.
    quarantine: [QuarantineEntry; MAX_QUARANTINE],
    /// Number of active quarantine entries.
    nr_quarantine: usize,
    /// Total errors detected since boot.
    total_errors: u64,
}

impl Kasan {
    /// Creates a new uninitialised KASAN instance.
    pub const fn new() -> Self {
        Self {
            enabled: false,
            shadow_base: 0,
            shadow_size: 0,
            reports: [KasanReport::new(); MAX_REPORTS],
            nr_reports: 0,
            quarantine: [QuarantineEntry::new(); MAX_QUARANTINE],
            nr_quarantine: 0,
            total_errors: 0,
        }
    }

    /// Initialises KASAN with the given shadow memory region.
    pub fn init(&mut self, shadow_base: u64, shadow_size: usize) -> Result<()> {
        if shadow_size == 0 {
            return Err(Error::InvalidArgument);
        }
        self.shadow_base = shadow_base;
        self.shadow_size = shadow_size;
        self.enabled = true;
        Ok(())
    }

    /// Checks a memory access against the shadow map.
    ///
    /// Returns `Ok(())` if the access is valid, or an error report
    /// describing the violation.
    pub fn check_access(
        &mut self,
        addr: u64,
        size: usize,
        is_write: bool,
        ip: u64,
        tick: u64,
    ) -> Result<()> {
        if !self.enabled || size == 0 {
            return Ok(());
        }

        let shadow_offset = (addr >> SHADOW_SCALE) as usize;
        if shadow_offset >= self.shadow_size {
            return Err(Error::InvalidArgument);
        }

        // In a real implementation, we would read the shadow byte
        // from shadow_base + shadow_offset. Here we simulate
        // the check interface.
        let shadow_val = self.read_shadow(addr)?;

        let error_type = match shadow_val {
            SHADOW_ACCESSIBLE => return Ok(()),
            v if v >= 1 && v <= 7 => {
                // Partially accessible — check if access fits.
                let offset_in_qword = (addr & 7) as u8;
                let end = offset_in_qword + size as u8;
                if end <= v {
                    return Ok(());
                }
                KasanErrorType::OutOfBounds
            }
            SHADOW_FREED => KasanErrorType::UseAfterFree,
            SHADOW_INACCESSIBLE => KasanErrorType::OutOfBounds,
            SHADOW_STACK_REDZONE => KasanErrorType::StackOverflow,
            _ => KasanErrorType::GlobalOverflow,
        };

        self.record_report(error_type, addr, size, is_write, ip, shadow_val, tick);
        Err(Error::InvalidArgument)
    }

    /// Poisons a memory region (marks as inaccessible).
    pub fn poison(&mut self, addr: u64, size: usize, value: u8) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        let start_shadow = (addr >> SHADOW_SCALE) as usize;
        let end_shadow = ((addr + size as u64) >> SHADOW_SCALE) as usize;
        if end_shadow > self.shadow_size {
            return Err(Error::InvalidArgument);
        }
        // In a real kernel we would memset shadow[start..end] = value.
        let _ = (start_shadow, end_shadow, value);
        Ok(())
    }

    /// Un-poisons a memory region (marks as fully accessible).
    pub fn unpoison(&mut self, addr: u64, size: usize) -> Result<()> {
        self.poison(addr, size, SHADOW_ACCESSIBLE)
    }

    /// Adds a freed allocation to the quarantine.
    pub fn quarantine_add(&mut self, addr: u64, size: usize, tick: u64) -> Result<()> {
        if self.nr_quarantine >= MAX_QUARANTINE {
            // Evict the oldest entry.
            self.quarantine_drain(1)?;
        }
        for entry in &mut self.quarantine {
            if !entry.active {
                *entry = QuarantineEntry {
                    addr,
                    size,
                    free_tick: tick,
                    active: true,
                };
                self.nr_quarantine += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Drains `count` oldest quarantine entries.
    pub fn quarantine_drain(&mut self, count: usize) -> Result<usize> {
        let mut drained = 0usize;
        for _ in 0..count {
            let mut oldest_idx = None;
            let mut oldest_tick = u64::MAX;
            for (i, entry) in self.quarantine.iter().enumerate() {
                if entry.active && entry.free_tick < oldest_tick {
                    oldest_tick = entry.free_tick;
                    oldest_idx = Some(i);
                }
            }
            match oldest_idx {
                Some(idx) => {
                    self.quarantine[idx].active = false;
                    self.nr_quarantine = self.nr_quarantine.saturating_sub(1);
                    drained += 1;
                }
                None => break,
            }
        }
        Ok(drained)
    }

    /// Returns the number of error reports collected.
    pub fn nr_reports(&self) -> usize {
        self.nr_reports
    }

    /// Returns total errors detected.
    pub fn total_errors(&self) -> u64 {
        self.total_errors
    }

    /// Whether KASAN is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Reads a shadow byte for the given kernel address.
    fn read_shadow(&self, addr: u64) -> Result<u8> {
        let offset = (addr >> SHADOW_SCALE) as usize;
        if offset >= self.shadow_size {
            return Err(Error::InvalidArgument);
        }
        // Placeholder: a real implementation reads
        // *(self.shadow_base + offset) via uaccess.
        Ok(SHADOW_ACCESSIBLE)
    }

    /// Records an error report.
    fn record_report(
        &mut self,
        error_type: KasanErrorType,
        address: u64,
        access_size: usize,
        is_write: bool,
        ip: u64,
        shadow_val: u8,
        timestamp: u64,
    ) {
        self.total_errors += 1;
        if self.nr_reports >= MAX_REPORTS {
            return;
        }
        let report = &mut self.reports[self.nr_reports];
        report.error_type = error_type;
        report.address = address;
        report.access_size = access_size;
        report.is_write = is_write;
        report.ip = ip;
        report.shadow_val = shadow_val;
        report.timestamp = timestamp;
        self.nr_reports += 1;
    }
}

impl Default for Kasan {
    fn default() -> Self {
        Self::new()
    }
}
