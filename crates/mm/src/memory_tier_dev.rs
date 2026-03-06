// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory tier device management.
//!
//! Modern systems have multiple memory types (DRAM, CXL, HBM,
//! persistent memory) organized into tiers by performance. This
//! module manages the device-side registration: associating physical
//! memory ranges with tier levels, handling demotion targets, and
//! providing the sysfs interface for tier configuration.
//!
//! # Design
//!
//! ```text
//!  memory_tier_register(device, adist)
//!     │
//!     ├─ compute tier from abstract distance (adist)
//!     ├─ associate NUMA nodes with tier
//!     └─ set demotion target for each node
//!
//!  page reclaim → demote hot tier → cold tier
//! ```
//!
//! # Key Types
//!
//! - [`TierLevel`] — memory tier classification
//! - [`TierDevice`] — a device associated with a memory tier
//! - [`MemoryTierDevManager`] — manages tier devices
//! - [`TierDevStats`] — device statistics
//!
//! Reference: Linux `mm/memory-tiers.c`, `include/linux/memory-tiers.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum tier levels.
const MAX_TIERS: usize = 8;

/// Maximum devices.
const MAX_DEVICES: usize = 128;

/// Maximum NUMA nodes per device.
const MAX_NODES_PER_DEVICE: usize = 16;

/// Default abstract distance for DRAM.
const DEFAULT_DRAM_ADIST: u32 = 512;

// -------------------------------------------------------------------
// TierLevel
// -------------------------------------------------------------------

/// Memory tier classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TierLevel {
    /// Highest performance (e.g., HBM).
    Tier0,
    /// High performance (e.g., local DRAM).
    Tier1,
    /// Medium performance (e.g., CXL-attached DRAM).
    Tier2,
    /// Lower performance (e.g., persistent memory).
    Tier3,
    /// Lowest tier (e.g., CXL-attached persistent memory).
    Tier4,
}

impl TierLevel {
    /// Return a label string.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Tier0 => "tier-0 (HBM)",
            Self::Tier1 => "tier-1 (DRAM)",
            Self::Tier2 => "tier-2 (CXL)",
            Self::Tier3 => "tier-3 (PMEM)",
            Self::Tier4 => "tier-4 (slow)",
        }
    }

    /// Return the numeric tier.
    pub const fn as_u32(&self) -> u32 {
        match self {
            Self::Tier0 => 0,
            Self::Tier1 => 1,
            Self::Tier2 => 2,
            Self::Tier3 => 3,
            Self::Tier4 => 4,
        }
    }

    /// Classify from abstract distance.
    pub const fn from_adist(adist: u32) -> Self {
        if adist < 256 {
            Self::Tier0
        } else if adist < 512 {
            Self::Tier1
        } else if adist < 1024 {
            Self::Tier2
        } else if adist < 2048 {
            Self::Tier3
        } else {
            Self::Tier4
        }
    }

    /// Return the demotion target tier.
    pub const fn demotion_target(&self) -> Option<TierLevel> {
        match self {
            Self::Tier0 => Some(Self::Tier1),
            Self::Tier1 => Some(Self::Tier2),
            Self::Tier2 => Some(Self::Tier3),
            Self::Tier3 => Some(Self::Tier4),
            Self::Tier4 => None,
        }
    }
}

// -------------------------------------------------------------------
// TierDevice
// -------------------------------------------------------------------

/// A device associated with a memory tier.
#[derive(Debug, Clone, Copy)]
pub struct TierDevice {
    /// Device ID.
    device_id: u64,
    /// Tier level.
    tier: TierLevel,
    /// Abstract distance.
    adist: u32,
    /// NUMA nodes associated.
    nodes: [u32; MAX_NODES_PER_DEVICE],
    /// Number of nodes.
    node_count: u8,
    /// Total memory in pages.
    total_pages: u64,
    /// Whether the device is online.
    online: bool,
}

impl TierDevice {
    /// Create a new tier device.
    pub const fn new(device_id: u64, adist: u32) -> Self {
        Self {
            device_id,
            tier: TierLevel::from_adist(adist),
            adist,
            nodes: [0; MAX_NODES_PER_DEVICE],
            node_count: 0,
            total_pages: 0,
            online: true,
        }
    }

    /// Return the device ID.
    pub const fn device_id(&self) -> u64 {
        self.device_id
    }

    /// Return the tier.
    pub const fn tier(&self) -> TierLevel {
        self.tier
    }

    /// Return the abstract distance.
    pub const fn adist(&self) -> u32 {
        self.adist
    }

    /// Return the node count.
    pub const fn node_count(&self) -> u8 {
        self.node_count
    }

    /// Return the total pages.
    pub const fn total_pages(&self) -> u64 {
        self.total_pages
    }

    /// Check whether online.
    pub const fn online(&self) -> bool {
        self.online
    }

    /// Set total pages.
    pub fn set_total_pages(&mut self, pages: u64) {
        self.total_pages = pages;
    }

    /// Add a NUMA node.
    pub fn add_node(&mut self, node: u32) -> Result<()> {
        if (self.node_count as usize) >= MAX_NODES_PER_DEVICE {
            return Err(Error::OutOfMemory);
        }
        self.nodes[self.node_count as usize] = node;
        self.node_count += 1;
        Ok(())
    }

    /// Take offline.
    pub fn set_offline(&mut self) {
        self.online = false;
    }

    /// Get a node by index.
    pub fn get_node(&self, index: usize) -> Option<u32> {
        if index < self.node_count as usize {
            Some(self.nodes[index])
        } else {
            None
        }
    }
}

impl Default for TierDevice {
    fn default() -> Self {
        Self {
            device_id: 0,
            tier: TierLevel::Tier1,
            adist: DEFAULT_DRAM_ADIST,
            nodes: [0; MAX_NODES_PER_DEVICE],
            node_count: 0,
            total_pages: 0,
            online: false,
        }
    }
}

// -------------------------------------------------------------------
// TierDevStats
// -------------------------------------------------------------------

/// Device statistics.
#[derive(Debug, Clone, Copy)]
pub struct TierDevStats {
    /// Total devices registered.
    pub devices_registered: u64,
    /// Total devices offlined.
    pub devices_offlined: u64,
    /// Total NUMA nodes associated.
    pub nodes_associated: u64,
    /// Total pages across all devices.
    pub total_pages: u64,
}

impl TierDevStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            devices_registered: 0,
            devices_offlined: 0,
            nodes_associated: 0,
            total_pages: 0,
        }
    }
}

impl Default for TierDevStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MemoryTierDevManager
// -------------------------------------------------------------------

/// Manages memory tier devices.
pub struct MemoryTierDevManager {
    /// Devices.
    devices: [TierDevice; MAX_DEVICES],
    /// Number of devices.
    count: usize,
    /// Statistics.
    stats: TierDevStats,
}

impl MemoryTierDevManager {
    /// Create a new manager.
    pub const fn new() -> Self {
        Self {
            devices: [const {
                TierDevice {
                    device_id: 0,
                    tier: TierLevel::Tier1,
                    adist: DEFAULT_DRAM_ADIST,
                    nodes: [0; MAX_NODES_PER_DEVICE],
                    node_count: 0,
                    total_pages: 0,
                    online: false,
                }
            }; MAX_DEVICES],
            count: 0,
            stats: TierDevStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &TierDevStats {
        &self.stats
    }

    /// Return the device count.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Register a device.
    pub fn register(&mut self, device_id: u64, adist: u32) -> Result<()> {
        if self.count >= MAX_DEVICES {
            return Err(Error::OutOfMemory);
        }
        self.devices[self.count] = TierDevice::new(device_id, adist);
        self.count += 1;
        self.stats.devices_registered += 1;
        Ok(())
    }

    /// Add a NUMA node to a device.
    pub fn add_node(&mut self, device_id: u64, node: u32) -> Result<()> {
        for idx in 0..self.count {
            if self.devices[idx].device_id() == device_id {
                self.devices[idx].add_node(node)?;
                self.stats.nodes_associated += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Find a device by ID.
    pub fn find(&self, device_id: u64) -> Option<&TierDevice> {
        for idx in 0..self.count {
            if self.devices[idx].device_id() == device_id {
                return Some(&self.devices[idx]);
            }
        }
        None
    }

    /// Count devices at a given tier.
    pub fn count_at_tier(&self, tier: TierLevel) -> usize {
        let mut n = 0;
        for idx in 0..self.count {
            if self.devices[idx].tier() == tier && self.devices[idx].online() {
                n += 1;
            }
        }
        n
    }
}

impl Default for MemoryTierDevManager {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the maximum devices.
pub const fn max_devices() -> usize {
    MAX_DEVICES
}

/// Return the maximum tiers.
pub const fn max_tiers() -> usize {
    MAX_TIERS
}

/// Return the default DRAM abstract distance.
pub const fn default_dram_adist() -> u32 {
    DEFAULT_DRAM_ADIST
}
