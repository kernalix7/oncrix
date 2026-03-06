// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! HMM device memory mirroring.
//!
//! Heterogeneous Memory Management (HMM) allows device drivers (GPU,
//! accelerators) to mirror process address spaces into device page
//! tables. This module manages device-side mirrors: tracking which
//! pages are mirrored, handling invalidation callbacks when the CPU
//! address space changes, and coordinating migration between CPU and
//! device memory.
//!
//! # Design
//!
//! ```text
//!  hmm_mirror_register(mm, device)
//!     │
//!     ├─ register MMU notifier for address space
//!     ├─ on CPU page table change → invalidate device mirror
//!     └─ on device fault → migrate page to device memory
//!
//!  hmm_range_fault(range)
//!     │
//!     ├─ walk CPU page tables
//!     ├─ collect PFNs for device mapping
//!     └─ map into device page table
//! ```
//!
//! # Key Types
//!
//! - [`DeviceType`] — type of device being mirrored
//! - [`DeviceMirror`] — a single device mirror registration
//! - [`HmmDeviceManager`] — manages all device mirrors
//! - [`HmmDeviceStats`] — mirroring statistics
//!
//! Reference: Linux `mm/hmm.c`, `include/linux/hmm.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum device mirrors.
const MAX_MIRRORS: usize = 256;

/// Maximum pages per range fault.
const MAX_RANGE_PAGES: usize = 4096;

/// Page size.
const PAGE_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// DeviceType
// -------------------------------------------------------------------

/// Type of device being mirrored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    /// GPU device.
    Gpu,
    /// FPGA accelerator.
    Fpga,
    /// Network accelerator.
    Nic,
    /// Generic device.
    Generic,
}

impl DeviceType {
    /// Return a label string.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Gpu => "GPU",
            Self::Fpga => "FPGA",
            Self::Nic => "NIC",
            Self::Generic => "generic",
        }
    }
}

// -------------------------------------------------------------------
// DeviceMirror
// -------------------------------------------------------------------

/// A single device mirror registration.
#[derive(Debug, Clone, Copy)]
pub struct DeviceMirror {
    /// Mirror ID.
    mirror_id: u64,
    /// Process ID being mirrored.
    pid: u64,
    /// Device type.
    device_type: DeviceType,
    /// Device ID.
    device_id: u64,
    /// Number of pages currently mirrored.
    mirrored_pages: u64,
    /// Number of invalidation callbacks received.
    invalidations: u64,
    /// Number of range faults served.
    range_faults: u64,
    /// Whether the mirror is active.
    active: bool,
    /// Timestamp of registration.
    registered_at: u64,
}

impl DeviceMirror {
    /// Create a new device mirror.
    pub const fn new(
        mirror_id: u64,
        pid: u64,
        device_type: DeviceType,
        device_id: u64,
        timestamp: u64,
    ) -> Self {
        Self {
            mirror_id,
            pid,
            device_type,
            device_id,
            mirrored_pages: 0,
            invalidations: 0,
            range_faults: 0,
            active: true,
            registered_at: timestamp,
        }
    }

    /// Return the mirror ID.
    pub const fn mirror_id(&self) -> u64 {
        self.mirror_id
    }

    /// Return the PID.
    pub const fn pid(&self) -> u64 {
        self.pid
    }

    /// Return the device type.
    pub const fn device_type(&self) -> DeviceType {
        self.device_type
    }

    /// Return the device ID.
    pub const fn device_id(&self) -> u64 {
        self.device_id
    }

    /// Return the mirrored page count.
    pub const fn mirrored_pages(&self) -> u64 {
        self.mirrored_pages
    }

    /// Return the invalidation count.
    pub const fn invalidations(&self) -> u64 {
        self.invalidations
    }

    /// Return the range fault count.
    pub const fn range_faults(&self) -> u64 {
        self.range_faults
    }

    /// Check whether the mirror is active.
    pub const fn active(&self) -> bool {
        self.active
    }

    /// Deactivate the mirror.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Record an invalidation.
    pub fn record_invalidation(&mut self, pages: u64) {
        self.invalidations = self.invalidations.saturating_add(1);
        self.mirrored_pages = self.mirrored_pages.saturating_sub(pages);
    }

    /// Record a range fault.
    pub fn record_range_fault(&mut self, pages: u64) {
        self.range_faults = self.range_faults.saturating_add(1);
        self.mirrored_pages = self.mirrored_pages.saturating_add(pages);
    }

    /// Mirrored memory in bytes.
    pub const fn mirrored_bytes(&self) -> u64 {
        self.mirrored_pages * PAGE_SIZE
    }
}

impl Default for DeviceMirror {
    fn default() -> Self {
        Self {
            mirror_id: 0,
            pid: 0,
            device_type: DeviceType::Generic,
            device_id: 0,
            mirrored_pages: 0,
            invalidations: 0,
            range_faults: 0,
            active: false,
            registered_at: 0,
        }
    }
}

// -------------------------------------------------------------------
// HmmDeviceStats
// -------------------------------------------------------------------

/// Mirroring statistics.
#[derive(Debug, Clone, Copy)]
pub struct HmmDeviceStats {
    /// Total mirrors registered.
    pub mirrors_registered: u64,
    /// Total mirrors deactivated.
    pub mirrors_deactivated: u64,
    /// Total invalidation callbacks.
    pub total_invalidations: u64,
    /// Total range faults served.
    pub total_range_faults: u64,
    /// Total pages mirrored.
    pub total_pages_mirrored: u64,
    /// Total pages invalidated.
    pub total_pages_invalidated: u64,
}

impl HmmDeviceStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            mirrors_registered: 0,
            mirrors_deactivated: 0,
            total_invalidations: 0,
            total_range_faults: 0,
            total_pages_mirrored: 0,
            total_pages_invalidated: 0,
        }
    }
}

impl Default for HmmDeviceStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// HmmDeviceManager
// -------------------------------------------------------------------

/// Manages all device mirrors.
pub struct HmmDeviceManager {
    /// Mirrors.
    mirrors: [DeviceMirror; MAX_MIRRORS],
    /// Number of mirrors.
    count: usize,
    /// Next mirror ID.
    next_id: u64,
    /// Statistics.
    stats: HmmDeviceStats,
}

impl HmmDeviceManager {
    /// Create a new manager.
    pub const fn new() -> Self {
        Self {
            mirrors: [const {
                DeviceMirror {
                    mirror_id: 0,
                    pid: 0,
                    device_type: DeviceType::Generic,
                    device_id: 0,
                    mirrored_pages: 0,
                    invalidations: 0,
                    range_faults: 0,
                    active: false,
                    registered_at: 0,
                }
            }; MAX_MIRRORS],
            count: 0,
            next_id: 1,
            stats: HmmDeviceStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &HmmDeviceStats {
        &self.stats
    }

    /// Return the number of mirrors.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Register a device mirror.
    pub fn register(
        &mut self,
        pid: u64,
        device_type: DeviceType,
        device_id: u64,
        timestamp: u64,
    ) -> Result<u64> {
        if self.count >= MAX_MIRRORS {
            return Err(Error::OutOfMemory);
        }
        let mid = self.next_id;
        self.mirrors[self.count] = DeviceMirror::new(mid, pid, device_type, device_id, timestamp);
        self.count += 1;
        self.next_id += 1;
        self.stats.mirrors_registered += 1;
        Ok(mid)
    }

    /// Handle an invalidation for a mirror.
    pub fn invalidate(&mut self, mirror_id: u64, pages: u64) -> Result<()> {
        for idx in 0..self.count {
            if self.mirrors[idx].mirror_id() == mirror_id && self.mirrors[idx].active() {
                self.mirrors[idx].record_invalidation(pages);
                self.stats.total_invalidations += 1;
                self.stats.total_pages_invalidated += pages;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Handle a range fault for a mirror.
    pub fn range_fault(&mut self, mirror_id: u64, pages: u64) -> Result<()> {
        if (pages as usize) > MAX_RANGE_PAGES {
            return Err(Error::InvalidArgument);
        }
        for idx in 0..self.count {
            if self.mirrors[idx].mirror_id() == mirror_id && self.mirrors[idx].active() {
                self.mirrors[idx].record_range_fault(pages);
                self.stats.total_range_faults += 1;
                self.stats.total_pages_mirrored += pages;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Deactivate a mirror.
    pub fn deactivate(&mut self, mirror_id: u64) -> Result<()> {
        for idx in 0..self.count {
            if self.mirrors[idx].mirror_id() == mirror_id {
                self.mirrors[idx].deactivate();
                self.stats.mirrors_deactivated += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Find a mirror by ID.
    pub fn find(&self, mirror_id: u64) -> Option<&DeviceMirror> {
        for idx in 0..self.count {
            if self.mirrors[idx].mirror_id() == mirror_id {
                return Some(&self.mirrors[idx]);
            }
        }
        None
    }
}

impl Default for HmmDeviceManager {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the maximum mirrors.
pub const fn max_mirrors() -> usize {
    MAX_MIRRORS
}

/// Return the maximum range fault pages.
pub const fn max_range_pages() -> usize {
    MAX_RANGE_PAGES
}
