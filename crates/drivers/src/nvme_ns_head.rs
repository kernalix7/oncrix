// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NVMe namespace head management and multipath support.
//!
//! Implements the "namespace head" abstraction that groups multiple
//! NVMe paths to the same underlying namespace. When a namespace is
//! accessible through more than one controller (ANA multipath), a
//! single [`NvmeNsHead`] is created and each path is represented by
//! an [`NvmePath`].
//!
//! # Architecture
//!
//! ```text
//! NvmeNsHead { NGUID/EUI-64/NSID }
//!   ├── NvmePath { ctrl_id: 0, state: Optimized }
//!   └── NvmePath { ctrl_id: 1, state: NonOptimized }
//! ```
//!
//! Path selection strategies:
//! - **RoundRobin** — cycle through live paths regardless of ANA state.
//! - **NumaAware** — prefer the path whose controller matches the CPU
//!   NUMA node (approximated by `numa_hint` in [`NvmePath`]).
//!
//! Reference: Linux `drivers/nvme/host/multipath.c`,
//! `drivers/nvme/host/core.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum paths per namespace head.
const MAX_PATHS: usize = 8;

/// Maximum namespace heads tracked.
const MAX_NS_HEADS: usize = 32;

/// Invalid NSID sentinel.
const NSID_INVALID: u32 = 0;

// ---------------------------------------------------------------------------
// Namespace Identification
// ---------------------------------------------------------------------------

/// 128-bit Namespace Globally Unique Identifier (NGUID).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Nguid(pub [u8; 16]);

impl Nguid {
    /// Create a zeroed NGUID (used when the controller reports no NGUID).
    pub const fn zero() -> Self {
        Self([0u8; 16])
    }

    /// Return whether all bytes are zero (not assigned).
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

/// 64-bit IEEE Extended Unique Identifier for a namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Eui64(pub u64);

impl Eui64 {
    /// Create a zeroed EUI-64.
    pub const fn zero() -> Self {
        Self(0)
    }

    /// Return whether the EUI-64 is unassigned.
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

// ---------------------------------------------------------------------------
// ANA (Asymmetric Namespace Access) State
// ---------------------------------------------------------------------------

/// ANA group state for an NVMe path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnaState {
    /// Optimized path — lowest latency.
    Optimized,
    /// Non-optimized but accessible.
    NonOptimized,
    /// Path is inaccessible (link down, controller fault).
    Inaccessible,
    /// Controller reports persistent loss.
    PersistentLoss,
    /// Change state — in transition.
    Change,
}

impl AnaState {
    /// Whether this state can serve I/O.
    pub fn is_accessible(&self) -> bool {
        matches!(self, Self::Optimized | Self::NonOptimized)
    }

    /// Numeric priority for path selection (lower = preferred).
    pub fn priority(&self) -> u8 {
        match self {
            Self::Optimized => 0,
            Self::NonOptimized => 1,
            Self::Change => 2,
            Self::PersistentLoss => 3,
            Self::Inaccessible => 4,
        }
    }
}

// ---------------------------------------------------------------------------
// Path Selection Policy
// ---------------------------------------------------------------------------

/// I/O path selection strategy for a multipath namespace head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathPolicy {
    /// Cycle through live paths in round-robin order.
    RoundRobin,
    /// Prefer the path whose `numa_hint` matches a given NUMA node.
    NumaAware,
}

// ---------------------------------------------------------------------------
// NVMe Path
// ---------------------------------------------------------------------------

/// Represents a single I/O path to an NVMe namespace through one controller.
#[derive(Debug, Clone, Copy)]
pub struct NvmePath {
    /// Controller index (index into the system NVMe controller table).
    pub ctrl_id: u32,
    /// Namespace ID on this controller.
    pub nsid: u32,
    /// Current ANA state of this path.
    pub ana_state: AnaState,
    /// NUMA node hint for this path (controller's PCIe proximity).
    pub numa_hint: u32,
    /// Whether this path is enabled for I/O.
    pub enabled: bool,
    /// Total I/O operations dispatched through this path.
    pub io_count: u64,
}

impl NvmePath {
    /// Create a new path for the given controller and NSID.
    pub const fn new(ctrl_id: u32, nsid: u32, numa_hint: u32) -> Self {
        Self {
            ctrl_id,
            nsid,
            ana_state: AnaState::Optimized,
            numa_hint,
            enabled: true,
            io_count: 0,
        }
    }

    /// Whether this path can currently serve I/O.
    pub fn is_live(&self) -> bool {
        self.enabled && self.ana_state.is_accessible()
    }
}

// ---------------------------------------------------------------------------
// Namespace Head
// ---------------------------------------------------------------------------

/// Multipath head for a single NVMe namespace.
///
/// Groups all available paths (controllers) to the same namespace and
/// selects among them based on [`PathPolicy`].
pub struct NvmeNsHead {
    /// Namespace Globally Unique Identifier.
    pub nguid: Nguid,
    /// IEEE Extended Unique Identifier.
    pub eui64: Eui64,
    /// Namespace ID (on any controller; used as fallback key).
    pub nsid: u32,
    /// Logical block size in bytes (power of two).
    pub lba_size: u32,
    /// Namespace capacity in logical blocks.
    pub capacity_lba: u64,
    /// Active paths to this namespace.
    paths: [Option<NvmePath>; MAX_PATHS],
    /// Number of paths registered.
    path_count: usize,
    /// Round-robin cursor (index into `paths`).
    rr_cursor: usize,
    /// I/O path selection policy.
    pub policy: PathPolicy,
    /// Whether the head is fully initialised and ready for I/O.
    pub ready: bool,
}

impl NvmeNsHead {
    /// Create a new namespace head identified by `nguid`, `eui64`, and `nsid`.
    pub fn new(nguid: Nguid, eui64: Eui64, nsid: u32, lba_size: u32, capacity_lba: u64) -> Self {
        Self {
            nguid,
            eui64,
            nsid,
            lba_size,
            capacity_lba,
            paths: [const { None }; MAX_PATHS],
            path_count: 0,
            rr_cursor: 0,
            policy: PathPolicy::RoundRobin,
            ready: false,
        }
    }

    /// Attach a new path to this namespace head.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the path table is full.
    /// - [`Error::AlreadyExists`] if a path for this `ctrl_id` already exists.
    pub fn attach_path(&mut self, path: NvmePath) -> Result<()> {
        if self.path_count >= MAX_PATHS {
            return Err(Error::OutOfMemory);
        }
        let dup = self.paths[..self.path_count]
            .iter()
            .filter_map(|p| p.as_ref())
            .any(|p| p.ctrl_id == path.ctrl_id);
        if dup {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .paths
            .iter()
            .position(|p| p.is_none())
            .ok_or(Error::OutOfMemory)?;
        self.paths[slot] = Some(path);
        if slot >= self.path_count {
            self.path_count = slot + 1;
        }
        self.ready = true;
        Ok(())
    }

    /// Detach (remove) a path by controller ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no path for `ctrl_id` exists.
    pub fn detach_path(&mut self, ctrl_id: u32) -> Result<()> {
        let slot = self.paths[..self.path_count]
            .iter()
            .position(|p| p.map_or(false, |p| p.ctrl_id == ctrl_id))
            .ok_or(Error::NotFound)?;
        self.paths[slot] = None;
        while self.path_count > 0 && self.paths[self.path_count - 1].is_none() {
            self.path_count -= 1;
        }
        self.ready = self.path_count > 0;
        Ok(())
    }

    /// Update the ANA state for a specific path.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no path for `ctrl_id` exists.
    pub fn update_ana_state(&mut self, ctrl_id: u32, state: AnaState) -> Result<()> {
        let slot = self.paths[..self.path_count]
            .iter()
            .position(|p| p.map_or(false, |p| p.ctrl_id == ctrl_id))
            .ok_or(Error::NotFound)?;
        if let Some(p) = self.paths[slot].as_mut() {
            p.ana_state = state;
        }
        Ok(())
    }

    /// Select a path for the next I/O operation.
    ///
    /// Returns the selected path's index and a mutable reference.
    ///
    /// - `RoundRobin`: cycles through live paths.
    /// - `NumaAware`: picks the best ANA state among paths with matching
    ///   `numa_hint`; falls back to any live path.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if no live paths are available.
    pub fn select_path(&mut self, numa_node: u32) -> Result<&mut NvmePath> {
        match self.policy {
            PathPolicy::RoundRobin => self.rr_select(),
            PathPolicy::NumaAware => self.numa_select(numa_node),
        }
    }

    fn rr_select(&mut self) -> Result<&mut NvmePath> {
        let start = self.rr_cursor;
        let count = self.path_count;
        for i in 0..count {
            let idx = (start + i) % count;
            if self.paths[idx].as_ref().map_or(false, |p| p.is_live()) {
                self.rr_cursor = (idx + 1) % count;
                if let Some(p) = self.paths[idx].as_mut() {
                    p.io_count += 1;
                    // SAFETY: We checked is_live() above so paths[idx] is Some.
                    // Returning a mutable reference within the same field is safe
                    // as we do not alias any other part of `self.paths`.
                    return Ok(unsafe { &mut *(p as *mut NvmePath) });
                }
            }
        }
        Err(Error::Busy)
    }

    fn numa_select(&mut self, numa_node: u32) -> Result<&mut NvmePath> {
        // First: find the best-ANA live path on the preferred NUMA node.
        let best_idx = {
            let mut best: Option<usize> = None;
            let mut best_prio = u8::MAX;
            for (i, slot) in self.paths[..self.path_count].iter().enumerate() {
                if let Some(p) = slot {
                    if p.is_live() && p.numa_hint == numa_node {
                        let prio = p.ana_state.priority();
                        if prio < best_prio {
                            best_prio = prio;
                            best = Some(i);
                        }
                    }
                }
            }
            best
        };

        if let Some(idx) = best_idx {
            if let Some(p) = self.paths[idx].as_mut() {
                p.io_count += 1;
                // SAFETY: unique mutable reference to paths[idx].
                return Ok(unsafe { &mut *(p as *mut NvmePath) });
            }
        }

        // Fallback to round-robin across any live path.
        self.rr_select()
    }

    /// Trigger a namespace rescan.
    ///
    /// In a real driver this would re-read the Identify Namespace data
    /// structure from each attached controller and update capacity/lba_size.
    /// Here we mark `ready = false` to signal that a rescan is needed.
    pub fn rescan(&mut self) {
        self.ready = false;
    }

    /// Mark the rescan complete and restore the ready flag if paths exist.
    pub fn rescan_complete(&mut self, lba_size: u32, capacity_lba: u64) {
        self.lba_size = lba_size;
        self.capacity_lba = capacity_lba;
        self.ready = self.path_count > 0;
    }

    /// Return the number of attached paths.
    pub fn path_count(&self) -> usize {
        self.path_count
    }

    /// Return the number of live (accessible) paths.
    pub fn live_path_count(&self) -> usize {
        self.paths[..self.path_count]
            .iter()
            .filter(|p| p.as_ref().map_or(false, |p| p.is_live()))
            .count()
    }
}

// ---------------------------------------------------------------------------
// Namespace Head Registry
// ---------------------------------------------------------------------------

/// System-wide registry of NVMe namespace heads.
pub struct NvmeNsHeadRegistry {
    /// Registered heads.
    heads: [Option<NvmeNsHead>; MAX_NS_HEADS],
    /// Number of registered heads.
    count: usize,
}

impl Default for NvmeNsHeadRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl NvmeNsHeadRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            heads: core::array::from_fn(|_| None),
            count: 0,
        }
    }

    /// Register a new namespace head.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, head: NvmeNsHead) -> Result<usize> {
        if self.count >= MAX_NS_HEADS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.heads[idx] = Some(head);
        self.count += 1;
        Ok(idx)
    }

    /// Find a namespace head by NGUID.
    pub fn find_by_nguid(&self, nguid: &Nguid) -> Option<&NvmeNsHead> {
        self.heads[..self.count]
            .iter()
            .find_map(|h| h.as_ref().filter(|h| &h.nguid == nguid))
    }

    /// Find a mutable namespace head by NGUID.
    pub fn find_by_nguid_mut(&mut self, nguid: &Nguid) -> Option<&mut NvmeNsHead> {
        self.heads[..self.count]
            .iter_mut()
            .find_map(|h| h.as_mut().filter(|h| &h.nguid == nguid))
    }

    /// Find a namespace head by NSID (used as fallback when NGUID is zero).
    pub fn find_by_nsid(&self, nsid: u32) -> Option<&NvmeNsHead> {
        if nsid == NSID_INVALID {
            return None;
        }
        self.heads[..self.count]
            .iter()
            .find_map(|h| h.as_ref().filter(|h| h.nsid == nsid))
    }

    /// Get a mutable reference to a head by index.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut NvmeNsHead> {
        if idx < self.count {
            self.heads[idx].as_mut()
        } else {
            None
        }
    }

    /// Return the total number of registered heads.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Return whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
