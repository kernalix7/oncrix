// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NVMe multipath I/O (NVMe-MI and ANA group support).
//!
//! Implements NVMe multipath I/O as defined by the NVMe Base
//! Specification 2.0, Asymmetric Namespace Access (ANA) feature.
//! Multiple controllers can be attached to the same namespace;
//! this module selects the optimal path for each I/O based on
//! ANA group state (Optimized, Non-Optimized, Inaccessible,
//! Persistent Loss).
//!
//! # Architecture
//!
//! ```text
//! File system / block layer
//!       │  submit_io()
//!       ▼
//! NvmeMultipathDevice
//!       │  select_path() → NvmePath (controller + ANA group)
//!       ▼
//! NvmeController (crates/drivers/src/nvme.rs)
//! ```
//!
//! # Path Selection Policy
//!
//! - **RoundRobin**: cycles through all Optimized paths.
//! - **LeastQueue**: selects the path with the fewest pending I/Os.
//! - **Static**: always prefers the first Optimized path (fail-over).
//!
//! # Usage
//!
//! ```ignore
//! let mut mpdev = NvmeMultipathDevice::new(ns_id);
//! mpdev.add_path(ctrl_id_0, AnaState::Optimized, 0)?;
//! mpdev.add_path(ctrl_id_1, AnaState::NonOptimized, 1)?;
//! let path = mpdev.select_path()?;
//! ```

extern crate alloc;

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────

/// Maximum paths per multipath device.
const MAX_PATHS: usize = 8;
/// Maximum multipath devices in the system.
const MAX_MP_DEVICES: usize = 16;
/// I/O queue depth limit per path for LeastQueue selection.
const MAX_QUEUE_DEPTH: u32 = 1024;

// ── ANA State ─────────────────────────────────────────────────

/// Asymmetric Namespace Access (ANA) group state.
///
/// Defined in NVMe Base Spec 2.0, section 8.18.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnaState {
    /// Optimized path: lowest latency, maximum throughput.
    Optimized = 0,
    /// Non-Optimized path: accessible but sub-optimal (e.g., remote controller).
    NonOptimized = 1,
    /// Inaccessible path: namespace is temporarily unavailable on this path.
    Inaccessible = 2,
    /// Persistent loss: path has been permanently lost.
    PersistentLoss = 3,
    /// Change pending: ANA group state is being updated.
    ChangePending = 4,
}

impl AnaState {
    /// Return whether this state allows I/O to be submitted.
    pub const fn is_io_capable(&self) -> bool {
        matches!(self, Self::Optimized | Self::NonOptimized)
    }

    /// Return whether this is the preferred state for I/O.
    pub const fn is_optimized(&self) -> bool {
        matches!(self, Self::Optimized)
    }
}

// ── Path Selection Policy ─────────────────────────────────────

/// Policy for selecting among available multipath paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathPolicy {
    /// Distribute I/O in round-robin order across Optimized paths.
    RoundRobin,
    /// Submit to the path with the fewest pending I/Os.
    LeastQueue,
    /// Always prefer the first Optimized path; fall over on failure.
    Static,
}

// ── NVMe Path ─────────────────────────────────────────────────

/// A single NVMe path to a namespace.
///
/// Identifies the controller and ANA group state for this path.
#[derive(Debug, Clone, Copy)]
pub struct NvmePath {
    /// Controller identifier (e.g., index in the NVMe controller registry).
    pub ctrl_id: u32,
    /// ANA group identifier assigned by the controller.
    pub ana_group_id: u32,
    /// Current ANA state for this path.
    pub ana_state: AnaState,
    /// Number of pending I/O operations on this path.
    pub pending_ios: u32,
    /// Total I/O operations submitted via this path.
    pub io_count: u64,
    /// Total I/O errors on this path.
    pub error_count: u64,
    /// Whether this path is currently active (not disabled by admin).
    pub active: bool,
    /// Whether this path slot is occupied.
    pub occupied: bool,
}

impl Default for NvmePath {
    fn default() -> Self {
        Self::new()
    }
}

impl NvmePath {
    /// Create an empty (unoccupied) path slot.
    pub const fn new() -> Self {
        Self {
            ctrl_id: 0,
            ana_group_id: 0,
            ana_state: AnaState::Inaccessible,
            pending_ios: 0,
            io_count: 0,
            error_count: 0,
            active: false,
            occupied: false,
        }
    }

    /// Return whether this path is usable for I/O submission.
    pub fn is_usable(&self) -> bool {
        self.occupied && self.active && self.ana_state.is_io_capable()
    }
}

// ── Multipath Device Statistics ───────────────────────────────

/// Per-multipath-device I/O statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct MultipathStats {
    /// Total I/O requests routed.
    pub total_ios: u64,
    /// I/O requests that succeeded.
    pub successful_ios: u64,
    /// I/O requests that failed (path error).
    pub failed_ios: u64,
    /// Path failover events (switched from a failed path).
    pub failovers: u64,
    /// ANA state change events processed.
    pub ana_changes: u64,
    /// Number of path-not-found errors (no usable path).
    pub no_path_errors: u64,
}

// ── NVMe Multipath Device ─────────────────────────────────────

/// A multipath-managed NVMe namespace.
///
/// Aggregates multiple NVMe paths to the same namespace and
/// implements path selection according to the chosen policy.
pub struct NvmeMultipathDevice {
    /// Namespace ID (NSID) this device represents.
    ns_id: u32,
    /// Human-readable device label (null-terminated, up to 31 chars).
    label: [u8; 32],
    /// Path table.
    paths: [NvmePath; MAX_PATHS],
    /// Number of occupied path slots.
    path_count: usize,
    /// Active path selection policy.
    policy: PathPolicy,
    /// Round-robin cursor (index into paths array).
    rr_cursor: usize,
    /// Whether this device is enabled.
    enabled: bool,
    /// Accumulated statistics.
    stats: MultipathStats,
}

impl NvmeMultipathDevice {
    /// Create a new multipath device for the given namespace ID.
    pub fn new(ns_id: u32) -> Self {
        Self {
            ns_id,
            label: [0u8; 32],
            paths: [const { NvmePath::new() }; MAX_PATHS],
            path_count: 0,
            policy: PathPolicy::RoundRobin,
            rr_cursor: 0,
            enabled: true,
            stats: MultipathStats::default(),
        }
    }

    /// Set a human-readable label for this device.
    pub fn set_label(&mut self, label: &[u8]) {
        let copy_len = label.len().min(31);
        self.label[..copy_len].copy_from_slice(&label[..copy_len]);
        if copy_len < 32 {
            self.label[copy_len] = 0;
        }
    }

    /// Add a path to this multipath device.
    ///
    /// # Arguments
    ///
    /// * `ctrl_id` — Controller index.
    /// * `ana_state` — Initial ANA state for this path.
    /// * `ana_group_id` — ANA group ID reported by the controller.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the path table is full.
    /// - [`Error::AlreadyExists`] if a path for `ctrl_id` already exists.
    pub fn add_path(&mut self, ctrl_id: u32, ana_state: AnaState, ana_group_id: u32) -> Result<()> {
        let already = self.paths[..self.path_count]
            .iter()
            .any(|p| p.occupied && p.ctrl_id == ctrl_id);
        if already {
            return Err(Error::AlreadyExists);
        }
        if self.path_count >= MAX_PATHS {
            return Err(Error::OutOfMemory);
        }
        let slot = self.path_count;
        self.paths[slot] = NvmePath {
            ctrl_id,
            ana_group_id,
            ana_state,
            pending_ios: 0,
            io_count: 0,
            error_count: 0,
            active: true,
            occupied: true,
        };
        self.path_count += 1;
        Ok(())
    }

    /// Remove a path from this device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no path for `ctrl_id` exists.
    pub fn remove_path(&mut self, ctrl_id: u32) -> Result<()> {
        let slot = self.paths[..self.path_count]
            .iter()
            .position(|p| p.occupied && p.ctrl_id == ctrl_id)
            .ok_or(Error::NotFound)?;
        self.paths[slot].occupied = false;
        self.paths[slot].active = false;
        // Compact the table.
        let end = self.path_count;
        for i in slot..end.saturating_sub(1) {
            self.paths[i] = self.paths[i + 1];
        }
        if self.path_count > 0 {
            self.path_count -= 1;
            self.paths[self.path_count] = NvmePath::new();
        }
        Ok(())
    }

    /// Update the ANA state for all paths belonging to `ana_group_id`.
    ///
    /// Called when an ANA Log Page change event is received.
    pub fn update_ana_state(&mut self, ana_group_id: u32, new_state: AnaState) {
        for path in &mut self.paths[..self.path_count] {
            if path.occupied && path.ana_group_id == ana_group_id {
                path.ana_state = new_state;
            }
        }
        self.stats.ana_changes += 1;
    }

    /// Select a path for the next I/O according to the active policy.
    ///
    /// Returns a mutable reference to the selected path and increments
    /// its pending I/O counter.
    ///
    /// # Errors
    ///
    /// - [`Error::Busy`] if the device is disabled.
    /// - [`Error::NotFound`] if no usable path is available.
    pub fn select_path(&mut self) -> Result<u32> {
        if !self.enabled {
            self.stats.no_path_errors += 1;
            return Err(Error::Busy);
        }
        self.stats.total_ios += 1;

        match self.policy {
            PathPolicy::RoundRobin => self.select_round_robin(),
            PathPolicy::LeastQueue => self.select_least_queue(),
            PathPolicy::Static => self.select_static(),
        }
    }

    fn select_round_robin(&mut self) -> Result<u32> {
        let start = self.rr_cursor;
        let count = self.path_count;
        for i in 0..count {
            let idx = (start + i) % count;
            if self.paths[idx].is_usable() {
                self.rr_cursor = (idx + 1) % count;
                self.paths[idx].pending_ios = self.paths[idx].pending_ios.saturating_add(1);
                self.paths[idx].io_count += 1;
                return Ok(self.paths[idx].ctrl_id);
            }
        }
        // Fall back to any non-optimized path.
        self.select_non_optimized_fallback()
    }

    fn select_least_queue(&mut self) -> Result<u32> {
        let mut best_idx: Option<usize> = None;
        let mut best_pending = u32::MAX;
        for i in 0..self.path_count {
            let p = &self.paths[i];
            if p.is_usable() && p.ana_state.is_optimized() && p.pending_ios < best_pending {
                best_pending = p.pending_ios;
                best_idx = Some(i);
            }
        }
        let idx = match best_idx {
            Some(i) => i,
            None => {
                // Fall back.
                return self.select_non_optimized_fallback();
            }
        };
        self.paths[idx].pending_ios = self.paths[idx].pending_ios.saturating_add(1);
        self.paths[idx].io_count += 1;
        Ok(self.paths[idx].ctrl_id)
    }

    fn select_static(&mut self) -> Result<u32> {
        // Prefer first Optimized, then first NonOptimized.
        for i in 0..self.path_count {
            if self.paths[i].is_usable() && self.paths[i].ana_state.is_optimized() {
                self.paths[i].pending_ios = self.paths[i].pending_ios.saturating_add(1);
                self.paths[i].io_count += 1;
                return Ok(self.paths[i].ctrl_id);
            }
        }
        self.select_non_optimized_fallback()
    }

    fn select_non_optimized_fallback(&mut self) -> Result<u32> {
        for i in 0..self.path_count {
            if self.paths[i].is_usable() {
                self.paths[i].pending_ios = self.paths[i].pending_ios.saturating_add(1);
                self.paths[i].io_count += 1;
                self.stats.failovers += 1;
                return Ok(self.paths[i].ctrl_id);
            }
        }
        self.stats.no_path_errors += 1;
        Err(Error::NotFound)
    }

    /// Acknowledge I/O completion on the given controller path.
    ///
    /// Decrements the pending I/O counter and records success or failure.
    pub fn complete_io(&mut self, ctrl_id: u32, success: bool) {
        if let Some(path) = self.paths[..self.path_count]
            .iter_mut()
            .find(|p| p.occupied && p.ctrl_id == ctrl_id)
        {
            path.pending_ios = path.pending_ios.saturating_sub(1);
            if success {
                self.stats.successful_ios += 1;
            } else {
                path.error_count += 1;
                self.stats.failed_ios += 1;
            }
        }
    }

    /// Disable a path (e.g., due to controller failure).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no path for `ctrl_id` exists.
    pub fn disable_path(&mut self, ctrl_id: u32) -> Result<()> {
        let path = self.paths[..self.path_count]
            .iter_mut()
            .find(|p| p.occupied && p.ctrl_id == ctrl_id)
            .ok_or(Error::NotFound)?;
        path.active = false;
        self.stats.failovers += 1;
        Ok(())
    }

    /// Re-enable a path.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no path for `ctrl_id` exists.
    pub fn enable_path(&mut self, ctrl_id: u32) -> Result<()> {
        let path = self.paths[..self.path_count]
            .iter_mut()
            .find(|p| p.occupied && p.ctrl_id == ctrl_id)
            .ok_or(Error::NotFound)?;
        path.active = true;
        Ok(())
    }

    /// Change the path selection policy.
    pub fn set_policy(&mut self, policy: PathPolicy) {
        self.policy = policy;
    }

    /// Return the namespace ID.
    pub const fn ns_id(&self) -> u32 {
        self.ns_id
    }

    /// Return the number of configured paths.
    pub const fn path_count(&self) -> usize {
        self.path_count
    }

    /// Return the number of usable (Optimized or Non-Optimized, active) paths.
    pub fn usable_path_count(&self) -> usize {
        self.paths[..self.path_count]
            .iter()
            .filter(|p| p.is_usable())
            .count()
    }

    /// Return the active policy.
    pub const fn policy(&self) -> PathPolicy {
        self.policy
    }

    /// Return a reference to a path by controller ID.
    pub fn path_by_ctrl(&self, ctrl_id: u32) -> Option<&NvmePath> {
        self.paths[..self.path_count]
            .iter()
            .find(|p| p.occupied && p.ctrl_id == ctrl_id)
    }

    /// Return accumulated statistics.
    pub const fn stats(&self) -> &MultipathStats {
        &self.stats
    }

    /// Return whether the device is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Return the maximum queue depth allowed per path.
    pub const fn max_queue_depth(&self) -> u32 {
        MAX_QUEUE_DEPTH
    }
}

// ── Multipath Registry ────────────────────────────────────────

/// System-wide registry of NVMe multipath devices.
pub struct NvmeMultipathRegistry {
    /// Device slots.
    devices: [Option<NvmeMultipathDevice>; MAX_MP_DEVICES],
    /// Number of registered devices.
    count: usize,
}

impl Default for NvmeMultipathRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl NvmeMultipathRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None,
            ],
            count: 0,
        }
    }

    /// Register a multipath device.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the registry is full.
    /// - [`Error::AlreadyExists`] if a device for `ns_id` already exists.
    pub fn register(&mut self, device: NvmeMultipathDevice) -> Result<usize> {
        let ns_id = device.ns_id();
        let exists = self.devices[..self.count]
            .iter()
            .flatten()
            .any(|d| d.ns_id() == ns_id);
        if exists {
            return Err(Error::AlreadyExists);
        }
        if self.count >= MAX_MP_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.devices[idx] = Some(device);
        self.count += 1;
        Ok(idx)
    }

    /// Get a mutable reference to a device by namespace ID.
    pub fn get_mut_by_nsid(&mut self, ns_id: u32) -> Option<&mut NvmeMultipathDevice> {
        self.devices[..self.count]
            .iter_mut()
            .filter_map(|s| s.as_mut())
            .find(|d| d.ns_id() == ns_id)
    }

    /// Get a shared reference to a device by namespace ID.
    pub fn get_by_nsid(&self, ns_id: u32) -> Option<&NvmeMultipathDevice> {
        self.devices[..self.count]
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|d| d.ns_id() == ns_id)
    }

    /// Return the number of registered devices.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return whether the registry is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}
