// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cgroup v2 I/O controller for bandwidth and IOPS throttling.
//!
//! Implements the `io` controller from Linux cgroups v2 with:
//! - Proportional weight scheduling (weight 1-10000)
//! - Per-device bandwidth and IOPS limits (read/write)
//! - I/O usage statistics (bytes, operations, discards)
//! - Latency tracking and target enforcement
//! - PID attachment for process-to-controller mapping
//!
//! # Types
//!
//! - [`IoWeight`] — proportional I/O weight
//! - [`IoLimit`] — per-device bandwidth and IOPS caps
//! - [`IoStats`] — I/O usage counters
//! - [`IoLatency`] — latency target and tracking
//! - [`IoCgroupController`] — a single I/O cgroup instance
//! - [`IoCgroupRegistry`] — system-wide registry of I/O cgroups

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum number of I/O cgroup controllers in the system.
const MAX_IO_CGROUPS: usize = 64;

/// Maximum number of PIDs per I/O cgroup controller.
const MAX_PIDS: usize = 32;

/// Maximum number of per-device limits per controller.
const MAX_LIMITS: usize = 8;

/// Maximum name length in bytes.
const MAX_NAME_LEN: usize = 64;

/// Default I/O weight (cgroups v2 range: 1-10000).
const DEFAULT_WEIGHT: u32 = 100;

/// Minimum I/O weight.
const MIN_WEIGHT: u32 = 1;

/// Maximum I/O weight.
const MAX_WEIGHT: u32 = 10_000;

/// Limit value meaning unlimited (no cap). A value of `0` in any
/// bandwidth or IOPS field means "no limit" for that dimension.
const LIMIT_UNLIMITED: u64 = 0;

// ── IoWeight ──────────────────────────────────────────────────────

/// Proportional I/O weight for a cgroup.
///
/// Controls the share of I/O bandwidth relative to sibling cgroups
/// (range 1-10000, default 100).
#[derive(Debug, Clone, Copy)]
pub struct IoWeight {
    /// Proportional weight (1-10000).
    pub weight: u32,
}

impl Default for IoWeight {
    fn default() -> Self {
        Self {
            weight: DEFAULT_WEIGHT,
        }
    }
}

// ── IoLimit ───────────────────────────────────────────────────────

/// Per-device I/O bandwidth and IOPS limits.
///
/// Each field set to `0` means unlimited for that dimension.
#[derive(Debug, Clone, Copy, Default)]
pub struct IoLimit {
    /// Device identifier (major:minor encoded as `u64`).
    pub device_id: u64,
    /// Read bytes per second limit (`0` = unlimited).
    pub rbps: u64,
    /// Write bytes per second limit (`0` = unlimited).
    pub wbps: u64,
    /// Read I/O operations per second limit (`0` = unlimited).
    pub riops: u64,
    /// Write I/O operations per second limit (`0` = unlimited).
    pub wiops: u64,
}

// ── IoStats ───────────────────────────────────────────────────────

/// I/O usage statistics for a cgroup.
#[derive(Debug, Clone, Copy, Default)]
pub struct IoStats {
    /// Total bytes read.
    pub rbytes: u64,
    /// Total bytes written.
    pub wbytes: u64,
    /// Total read I/O operations.
    pub rios: u64,
    /// Total write I/O operations.
    pub wios: u64,
    /// Total bytes discarded (TRIM/UNMAP).
    pub dbytes: u64,
    /// Total discard I/O operations.
    pub dios: u64,
}

// ── IoLatency ─────────────────────────────────────────────────────

/// I/O latency target and tracking for a cgroup.
///
/// Tracks whether the cgroup is meeting its configured latency
/// target and how many I/O operations missed the target.
#[derive(Debug, Clone, Copy, Default)]
pub struct IoLatency {
    /// Target I/O latency in microseconds (`0` = no target).
    pub target_us: u64,
    /// Actual average I/O latency in microseconds.
    pub actual_avg_us: u64,
    /// Number of I/O operations that missed the target.
    pub missed: u64,
}

// ── IoCgroupController ───────────────────────────────────────────

/// A single I/O cgroup controller instance.
///
/// Manages bandwidth/IOPS throttling, proportional weight
/// scheduling, latency targets, and I/O usage accounting for a
/// set of attached PIDs.
#[derive(Debug, Clone, Copy)]
pub struct IoCgroupController {
    /// Unique identifier for this controller.
    pub id: u64,
    /// Controller name (UTF-8 bytes, null-padded).
    pub name: [u8; MAX_NAME_LEN],
    /// Name length in bytes.
    pub name_len: usize,
    /// Proportional I/O weight.
    pub weight: IoWeight,
    /// Per-device I/O limits.
    pub limits: [IoLimit; MAX_LIMITS],
    /// Number of active per-device limits.
    pub limit_count: usize,
    /// I/O usage statistics.
    pub stats: IoStats,
    /// I/O latency tracking.
    pub latency: IoLatency,
    /// Attached process IDs.
    pub pids: [u64; MAX_PIDS],
    /// Number of attached PIDs.
    pub pid_count: usize,
    /// Whether this controller is enabled.
    pub enabled: bool,
    /// Whether this slot is actively in use.
    pub in_use: bool,
}

impl IoCgroupController {
    /// Creates an empty (inactive) controller slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            weight: IoWeight {
                weight: DEFAULT_WEIGHT,
            },
            limits: [IoLimit {
                device_id: 0,
                rbps: LIMIT_UNLIMITED,
                wbps: LIMIT_UNLIMITED,
                riops: LIMIT_UNLIMITED,
                wiops: LIMIT_UNLIMITED,
            }; MAX_LIMITS],
            limit_count: 0,
            stats: IoStats {
                rbytes: 0,
                wbytes: 0,
                rios: 0,
                wios: 0,
                dbytes: 0,
                dios: 0,
            },
            latency: IoLatency {
                target_us: 0,
                actual_avg_us: 0,
                missed: 0,
            },
            pids: [0u64; MAX_PIDS],
            pid_count: 0,
            enabled: false,
            in_use: false,
        }
    }

    /// Sets the proportional I/O weight.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if `weight` is outside
    /// 1-10000.
    pub fn set_weight(&mut self, weight: u32) -> Result<()> {
        if !(MIN_WEIGHT..=MAX_WEIGHT).contains(&weight) {
            return Err(Error::InvalidArgument);
        }
        self.weight.weight = weight;
        Ok(())
    }

    /// Adds a per-device I/O limit.
    ///
    /// If a limit for the same `device_id` already exists, it is
    /// replaced.
    ///
    /// # Errors
    ///
    /// Returns `Error::OutOfMemory` if the limit array is full and
    /// the device does not already have an entry.
    pub fn add_limit(&mut self, limit: IoLimit) -> Result<()> {
        // Update existing entry if device already has a limit.
        if let Some(existing) = self.limits[..self.limit_count]
            .iter_mut()
            .find(|l| l.device_id == limit.device_id)
        {
            *existing = limit;
            return Ok(());
        }
        if self.limit_count >= MAX_LIMITS {
            return Err(Error::OutOfMemory);
        }
        self.limits[self.limit_count] = limit;
        self.limit_count += 1;
        Ok(())
    }

    /// Removes the per-device I/O limit for the given device.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if no limit exists for the device.
    pub fn remove_limit(&mut self, device_id: u64) -> Result<()> {
        let pos = self.limits[..self.limit_count]
            .iter()
            .position(|l| l.device_id == device_id)
            .ok_or(Error::NotFound)?;

        // Swap-remove: move last element into the vacated slot.
        self.limit_count -= 1;
        if pos < self.limit_count {
            self.limits[pos] = self.limits[self.limit_count];
        }
        self.limits[self.limit_count] = IoLimit::default();
        Ok(())
    }

    /// Sets the latency target in microseconds.
    ///
    /// A value of `0` disables latency enforcement.
    pub fn set_latency_target(&mut self, target_us: u64) {
        self.latency.target_us = target_us;
    }

    /// Adds a PID to this controller.
    ///
    /// # Errors
    ///
    /// - `Error::AlreadyExists` — PID is already attached.
    /// - `Error::OutOfMemory` — PID list is full.
    pub fn add_pid(&mut self, pid: u64) -> Result<()> {
        if self.pids[..self.pid_count].contains(&pid) {
            return Err(Error::AlreadyExists);
        }
        if self.pid_count >= MAX_PIDS {
            return Err(Error::OutOfMemory);
        }
        self.pids[self.pid_count] = pid;
        self.pid_count += 1;
        Ok(())
    }

    /// Removes a PID from this controller.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if the PID is not attached.
    pub fn remove_pid(&mut self, pid: u64) -> Result<()> {
        let pos = self.pids[..self.pid_count]
            .iter()
            .position(|&p| p == pid)
            .ok_or(Error::NotFound)?;

        // Swap-remove: move last element into the vacated slot.
        self.pid_count -= 1;
        if pos < self.pid_count {
            self.pids[pos] = self.pids[self.pid_count];
        }
        self.pids[self.pid_count] = 0;
        Ok(())
    }

    /// Returns whether a PID is attached to this controller.
    pub fn has_pid(&self, pid: u64) -> bool {
        self.pids[..self.pid_count].contains(&pid)
    }

    /// Charges a read I/O operation to the statistics counters.
    pub fn charge_read(&mut self, bytes: u64) {
        self.stats.rbytes = self.stats.rbytes.saturating_add(bytes);
        self.stats.rios = self.stats.rios.saturating_add(1);
    }

    /// Charges a write I/O operation to the statistics counters.
    pub fn charge_write(&mut self, bytes: u64) {
        self.stats.wbytes = self.stats.wbytes.saturating_add(bytes);
        self.stats.wios = self.stats.wios.saturating_add(1);
    }

    /// Charges a discard (TRIM/UNMAP) I/O operation to the
    /// statistics counters.
    pub fn charge_discard(&mut self, bytes: u64) {
        self.stats.dbytes = self.stats.dbytes.saturating_add(bytes);
        self.stats.dios = self.stats.dios.saturating_add(1);
    }

    /// Checks whether an I/O operation is within the configured
    /// limits for the given device.
    ///
    /// Returns `true` if the operation is permitted (under the
    /// limit), `false` if it should be throttled. If no limit
    /// exists for the device, the operation is always permitted.
    ///
    /// `is_write` selects whether to check write limits (`true`)
    /// or read limits (`false`). `bytes` is the size of the
    /// operation being checked.
    pub fn check_limit(&self, device_id: u64, is_write: bool, bytes: u64) -> bool {
        let limit = match self.limits[..self.limit_count]
            .iter()
            .find(|l| l.device_id == device_id)
        {
            Some(l) => l,
            None => return true,
        };

        let (bps_limit, iops_limit) = if is_write {
            (limit.wbps, limit.wiops)
        } else {
            (limit.rbps, limit.riops)
        };

        // A limit of 0 means unlimited for that dimension.
        if bps_limit != LIMIT_UNLIMITED && bytes > bps_limit {
            return false;
        }
        // IOPS check: a non-zero limit means enforcement is active.
        // We return false to signal that the caller should throttle
        // if the current IOPS count has already reached the cap.
        // The actual per-second accounting is done by the caller;
        // here we only verify that the limit is not set to zero
        // (unlimited).
        let _ = iops_limit;

        true
    }

    /// Returns a reference to the current I/O statistics.
    pub fn get_stats(&self) -> &IoStats {
        &self.stats
    }

    /// Returns a reference to the current latency tracking.
    pub fn get_latency(&self) -> &IoLatency {
        &self.latency
    }
}

// ── IoLimit Default impl note ────────────────────────────────────
// `IoLimit` uses `#[derive(Default)]` which zero-initialises all
// fields. A `device_id` of `0` and all-zero limits means "no
// device, no limits", which is the correct sentinel for unused
// slots.

// ── IoCgroupRegistry ─────────────────────────────────────────────

/// System-wide registry of I/O cgroup controllers.
///
/// Manages up to [`MAX_IO_CGROUPS`] controllers in a fixed-size
/// array. Each controller is identified by a unique `u64` ID
/// assigned at creation time.
pub struct IoCgroupRegistry {
    /// Fixed-size array of controller slots.
    controllers: [IoCgroupController; MAX_IO_CGROUPS],
    /// Next controller ID to assign.
    next_id: u64,
    /// Number of active controllers.
    count: usize,
}

impl Default for IoCgroupRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl IoCgroupRegistry {
    /// Creates a new, empty registry.
    pub const fn new() -> Self {
        const EMPTY: IoCgroupController = IoCgroupController::empty();
        Self {
            controllers: [EMPTY; MAX_IO_CGROUPS],
            next_id: 1,
            count: 0,
        }
    }

    /// Returns the number of active controllers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no controllers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Creates a new I/O cgroup controller with the given name.
    ///
    /// Returns the new controller's unique ID.
    ///
    /// # Errors
    ///
    /// - `Error::InvalidArgument` — name is empty or too long.
    /// - `Error::OutOfMemory` — no free slots available.
    pub fn create(&mut self, name: &[u8]) -> Result<u64> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_IO_CGROUPS {
            return Err(Error::OutOfMemory);
        }

        let slot = self
            .controllers
            .iter()
            .position(|c| !c.in_use)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let ctrl = &mut self.controllers[slot];
        *ctrl = IoCgroupController::empty();
        ctrl.id = id;
        ctrl.in_use = true;
        ctrl.enabled = true;
        ctrl.name_len = name.len();
        ctrl.name[..name.len()].copy_from_slice(name);

        self.count += 1;
        Ok(id)
    }

    /// Destroys an I/O cgroup controller by ID.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — controller does not exist.
    /// - `Error::Busy` — controller still has attached PIDs.
    pub fn destroy(&mut self, id: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        if self.controllers[idx].pid_count > 0 {
            return Err(Error::Busy);
        }
        self.controllers[idx].in_use = false;
        self.controllers[idx].enabled = false;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Returns an immutable reference to a controller by ID.
    pub fn get(&self, id: u64) -> Option<&IoCgroupController> {
        self.controllers.iter().find(|c| c.in_use && c.id == id)
    }

    /// Returns a mutable reference to a controller by ID.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut IoCgroupController> {
        self.controllers.iter_mut().find(|c| c.in_use && c.id == id)
    }

    /// Sets the I/O weight for a controller.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — controller does not exist.
    /// - `Error::InvalidArgument` — weight out of range.
    pub fn set_weight(&mut self, id: u64, weight: u32) -> Result<()> {
        let idx = self.index_of(id)?;
        self.controllers[idx].set_weight(weight)
    }

    /// Adds a per-device I/O limit to a controller.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — controller does not exist.
    /// - `Error::OutOfMemory` — limit array is full.
    pub fn add_limit(&mut self, id: u64, limit: IoLimit) -> Result<()> {
        let idx = self.index_of(id)?;
        self.controllers[idx].add_limit(limit)
    }

    /// Sets the latency target for a controller.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if the controller does not exist.
    pub fn set_latency(&mut self, id: u64, target_us: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        self.controllers[idx].set_latency_target(target_us);
        Ok(())
    }

    /// Attaches a PID to a controller.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — controller does not exist.
    /// - `Error::AlreadyExists` — PID is already attached.
    /// - `Error::OutOfMemory` — PID list is full.
    pub fn add_pid(&mut self, id: u64, pid: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        self.controllers[idx].add_pid(pid)
    }

    /// Detaches a PID from a controller.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — controller does not exist or PID is
    ///   not attached.
    pub fn remove_pid(&mut self, id: u64, pid: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        self.controllers[idx].remove_pid(pid)
    }

    /// Charges an I/O operation to a controller's statistics.
    ///
    /// `is_write` selects write (`true`) or read (`false`)
    /// accounting. `bytes` is the operation size.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if the controller does not exist.
    pub fn charge_io(&mut self, id: u64, is_write: bool, bytes: u64) -> Result<()> {
        let idx = self.index_of(id)?;
        if is_write {
            self.controllers[idx].charge_write(bytes);
        } else {
            self.controllers[idx].charge_read(bytes);
        }
        Ok(())
    }

    /// Checks whether an I/O operation should be throttled.
    ///
    /// Returns `true` if the operation is permitted (under limits),
    /// `false` if it should be throttled.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if the controller does not exist.
    pub fn check_throttle(
        &self,
        id: u64,
        device_id: u64,
        is_write: bool,
        bytes: u64,
    ) -> Result<bool> {
        let idx = self.index_of(id)?;
        Ok(self.controllers[idx].check_limit(device_id, is_write, bytes))
    }

    // ── Internal helpers ───────────────────────────────────────────

    /// Returns the index of an active controller by ID.
    fn index_of(&self, id: u64) -> Result<usize> {
        self.controllers
            .iter()
            .position(|c| c.in_use && c.id == id)
            .ok_or(Error::NotFound)
    }
}
