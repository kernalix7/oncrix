// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel Address Sanitizer (KASAN) core engine.
//!
//! KASAN detects out-of-bounds and use-after-free bugs by maintaining
//! a shadow memory map. Each 8 bytes of kernel memory is described by
//! 1 byte of shadow memory: 0 means all 8 bytes are accessible,
//! 1..7 means only that many bytes are accessible, and negative values
//! encode specific error classes (freed, red-zone, etc.).
//!
//! # Design
//!
//! ```text
//! Kernel address space         Shadow memory (1:8 ratio)
//! ┌───────────────────┐       ┌──────────────────┐
//! │ 8 bytes (data)    │  ──▶  │ 1 byte (shadow)  │
//! │ 8 bytes           │  ──▶  │ 1 byte           │
//! │   ...             │       │   ...             │
//! └───────────────────┘       └──────────────────┘
//! ```
//!
//! # Key Types
//!
//! - [`ShadowTag`] — shadow byte meanings (accessible, freed, red-zone, etc.)
//! - [`KasanState`] — global KASAN engine state
//! - [`KasanReport`] — error report for a detected violation
//!
//! Reference: Linux `mm/kasan/kasan.h`, `mm/kasan/common.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Number of kernel bytes per shadow byte.
const SHADOW_SCALE: usize = 8;

/// Maximum shadow memory size (covers 256 MiB of kernel memory).
const MAX_SHADOW_SIZE: usize = 32 * 1024;

/// Maximum stored reports before the buffer wraps.
const MAX_REPORTS: usize = 64;

// -------------------------------------------------------------------
// ShadowTag
// -------------------------------------------------------------------

/// Shadow memory tag values indicating access validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i8)]
pub enum ShadowTag {
    /// All 8 bytes accessible.
    Accessible = 0,
    /// Partial access: 1 byte accessible.
    Partial1 = 1,
    /// Partial access: 2 bytes accessible.
    Partial2 = 2,
    /// Partial access: 3 bytes accessible.
    Partial3 = 3,
    /// Partial access: 4 bytes accessible.
    Partial4 = 4,
    /// Freed memory (use-after-free).
    Freed = -1,
    /// Left red-zone (out-of-bounds before object).
    LeftRedZone = -2,
    /// Right red-zone (out-of-bounds after object).
    RightRedZone = -3,
    /// Stack left red-zone.
    StackLeft = -4,
    /// Stack use-after-return.
    StackAfterReturn = -5,
    /// Global red-zone.
    GlobalRedZone = -6,
}

impl ShadowTag {
    /// Returns `true` if this tag indicates fully accessible memory.
    pub const fn is_accessible(self) -> bool {
        (self as i8) == 0
    }

    /// Returns `true` if this tag indicates an error state.
    pub const fn is_error(self) -> bool {
        (self as i8) < 0
    }

    /// Returns the number of accessible bytes (0 for error states).
    pub const fn accessible_bytes(self) -> usize {
        let v = self as i8;
        if v < 0 {
            0
        } else if v == 0 {
            SHADOW_SCALE
        } else {
            v as usize
        }
    }
}

impl Default for ShadowTag {
    fn default() -> Self {
        Self::Accessible
    }
}

// -------------------------------------------------------------------
// KasanReport
// -------------------------------------------------------------------

/// An error report generated when KASAN detects a violation.
#[derive(Debug, Clone, Copy)]
pub struct KasanReport {
    /// Faulting address.
    pub address: u64,
    /// Size of the attempted access.
    pub access_size: usize,
    /// Whether the access was a write (false = read).
    pub is_write: bool,
    /// The shadow tag at the faulting address.
    pub shadow_tag: i8,
    /// Instruction pointer of the faulting code.
    pub ip: u64,
}

impl KasanReport {
    /// Creates a new report.
    pub const fn new(
        address: u64,
        access_size: usize,
        is_write: bool,
        shadow_tag: i8,
        ip: u64,
    ) -> Self {
        Self {
            address,
            access_size,
            is_write,
            shadow_tag,
            ip,
        }
    }

    /// Returns a human-readable tag description.
    pub const fn tag_description(&self) -> &'static str {
        match self.shadow_tag {
            0 => "accessible",
            1..=7 => "partial",
            -1 => "use-after-free",
            -2 => "left-oob",
            -3 => "right-oob",
            -4 => "stack-left-rz",
            -5 => "stack-use-after-return",
            -6 => "global-rz",
            _ => "unknown",
        }
    }
}

impl Default for KasanReport {
    fn default() -> Self {
        Self::new(0, 0, false, 0, 0)
    }
}

// -------------------------------------------------------------------
// KasanState
// -------------------------------------------------------------------

/// Global KASAN engine state.
///
/// Manages the shadow memory and collected error reports.
pub struct KasanState {
    /// Shadow memory array.
    shadow: [i8; MAX_SHADOW_SIZE],
    /// Base address of the kernel region being tracked.
    base_addr: u64,
    /// Size of the tracked kernel region in bytes.
    tracked_size: usize,
    /// Whether KASAN is enabled.
    enabled: bool,
    /// Error reports ring buffer.
    reports: [KasanReport; MAX_REPORTS],
    /// Number of reports stored.
    report_count: usize,
    /// Total violations detected.
    total_violations: u64,
}

impl KasanState {
    /// Creates a new KASAN state (disabled by default).
    pub const fn new() -> Self {
        Self {
            shadow: [0i8; MAX_SHADOW_SIZE],
            base_addr: 0,
            tracked_size: 0,
            enabled: false,
            reports: [const { KasanReport::new(0, 0, false, 0, 0) }; MAX_REPORTS],
            report_count: 0,
            total_violations: 0,
        }
    }

    /// Initializes the KASAN engine for a kernel memory region.
    pub fn init(&mut self, base: u64, size: usize) -> Result<()> {
        let shadow_needed = size / SHADOW_SCALE;
        if shadow_needed > MAX_SHADOW_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.base_addr = base;
        self.tracked_size = size;
        // Mark everything accessible initially.
        for b in self.shadow[..shadow_needed].iter_mut() {
            *b = 0;
        }
        self.enabled = true;
        Ok(())
    }

    /// Returns whether KASAN is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the total number of violations detected.
    pub const fn total_violations(&self) -> u64 {
        self.total_violations
    }

    /// Returns the number of stored reports.
    pub const fn report_count(&self) -> usize {
        self.report_count
    }

    /// Returns stored reports.
    pub fn reports(&self) -> &[KasanReport] {
        &self.reports[..self.report_count]
    }

    /// Converts a kernel address to a shadow index.
    fn addr_to_shadow(&self, addr: u64) -> Option<usize> {
        if addr < self.base_addr {
            return None;
        }
        let offset = (addr - self.base_addr) as usize;
        if offset >= self.tracked_size {
            return None;
        }
        Some(offset / SHADOW_SCALE)
    }

    /// Poisons a memory range (marks as inaccessible).
    pub fn poison(&mut self, addr: u64, size: usize, tag: i8) -> Result<()> {
        if !self.enabled {
            return Err(Error::InvalidArgument);
        }
        let start_idx = self.addr_to_shadow(addr).ok_or(Error::InvalidArgument)?;
        let end_idx = self
            .addr_to_shadow(addr + size as u64 - 1)
            .ok_or(Error::InvalidArgument)?;
        for i in start_idx..=end_idx {
            if i < MAX_SHADOW_SIZE {
                self.shadow[i] = tag;
            }
        }
        Ok(())
    }

    /// Unpoisons a memory range (marks as fully accessible).
    pub fn unpoison(&mut self, addr: u64, size: usize) -> Result<()> {
        self.poison(addr, size, 0)
    }

    /// Checks whether an access at `addr` of `size` bytes is valid.
    ///
    /// Returns `Ok(())` if accessible, or `Err` with a report appended.
    pub fn check_access(&mut self, addr: u64, size: usize, is_write: bool, ip: u64) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let shadow_idx = match self.addr_to_shadow(addr) {
            Some(idx) => idx,
            None => return Ok(()), // Outside tracked range.
        };
        if shadow_idx >= MAX_SHADOW_SIZE {
            return Ok(());
        }

        let tag = self.shadow[shadow_idx];
        if tag == 0 {
            return Ok(()); // Fully accessible.
        }
        if tag > 0 {
            // Partial: check if the access fits.
            let offset_in_grain = (addr - self.base_addr) as usize % SHADOW_SCALE;
            if offset_in_grain + size <= tag as usize {
                return Ok(());
            }
        }

        // Violation detected.
        self.total_violations = self.total_violations.saturating_add(1);
        if self.report_count < MAX_REPORTS {
            self.reports[self.report_count] = KasanReport::new(addr, size, is_write, tag, ip);
            self.report_count += 1;
        }
        Err(Error::InvalidArgument)
    }
}

impl Default for KasanState {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Creates and initializes a KASAN state for the given region.
pub fn kasan_init(base: u64, size: usize) -> Result<KasanState> {
    let mut state = KasanState::new();
    state.init(base, size)?;
    Ok(state)
}

/// Poisons freed memory so that use-after-free is detected.
pub fn kasan_poison_free(state: &mut KasanState, addr: u64, size: usize) -> Result<()> {
    state.poison(addr, size, ShadowTag::Freed as i8)
}

/// Checks a memory access for KASAN violations.
pub fn kasan_check(
    state: &mut KasanState,
    addr: u64,
    size: usize,
    is_write: bool,
    ip: u64,
) -> Result<()> {
    state.check_access(addr, size, is_write, ip)
}
