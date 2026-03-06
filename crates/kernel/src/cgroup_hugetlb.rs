// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Cgroup v2 HugeTLB controller for huge page usage limiting.
//!
//! Implements the `hugetlb` controller from Linux cgroups v2 with:
//! - Per-page-size limits (2 MiB, 1 GiB)
//! - Charge/uncharge accounting for huge page allocation/free
//! - Hierarchical limit enforcement (parent check before child)
//! - Usage statistics: current, max, limit, failcnt per page size
//! - PID attachment for process-to-controller mapping
//!
//! # Types
//!
//! - [`HugePageSize`] — supported huge page sizes
//! - [`HugetlbUsage`] — per-page-size usage and limit tracking
//! - [`HugetlbStats`] — aggregated statistics across page sizes
//! - [`HugetlbCgroup`] — a single HugeTLB cgroup instance
//! - [`HugetlbRegistry`] — system-wide registry of HugeTLB cgroups
//!
//! Reference: Linux `mm/hugetlb_cgroup.c`,
//! `Documentation/admin-guide/cgroup-v2.rst`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum number of HugeTLB cgroup controllers in the system.
const MAX_HUGETLB_CGROUPS: usize = 64;

/// Maximum number of PIDs per HugeTLB cgroup controller.
const MAX_PIDS_PER_GROUP: usize = 32;

/// Maximum name length in bytes.
const MAX_NAME_LEN: usize = 64;

/// Number of supported huge page sizes.
const NUM_PAGE_SIZES: usize = 2;

/// Index for 2 MiB pages in per-size arrays.
const IDX_2MB: usize = 0;

/// Index for 1 GiB pages in per-size arrays.
const IDX_1GB: usize = 1;

/// Size of a 2 MiB huge page in bytes.
const SIZE_2MB: u64 = 2 * 1024 * 1024;

/// Size of a 1 GiB huge page in bytes.
const SIZE_1GB: u64 = 1024 * 1024 * 1024;

/// Limit value meaning unlimited (no cap).
const LIMIT_UNLIMITED: u64 = u64::MAX;

/// Maximum hierarchy depth for parent-chain traversal.
const MAX_HIERARCHY_DEPTH: usize = 16;

// ── HugePageSize ──────────────────────────────────────────────────

/// Supported huge page sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HugePageSize {
    /// 2 MiB (x86_64 PMD-level, aarch64 block).
    Size2M,
    /// 1 GiB (x86_64 PUD-level, aarch64 block).
    Size1G,
}

impl HugePageSize {
    /// Returns the page size in bytes.
    pub const fn bytes(self) -> u64 {
        match self {
            Self::Size2M => SIZE_2MB,
            Self::Size1G => SIZE_1GB,
        }
    }

    /// Returns the array index for this page size.
    const fn index(self) -> usize {
        match self {
            Self::Size2M => IDX_2MB,
            Self::Size1G => IDX_1GB,
        }
    }

    /// Returns the human-readable label for this page size.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Size2M => "2MB",
            Self::Size1G => "1GB",
        }
    }
}

// ── HugetlbUsage ─────────────────────────────────────────────────

/// Per-page-size usage and limit tracking.
///
/// Tracks the current usage, high-water mark, configured limit,
/// and the number of allocation failures due to limit enforcement
/// for a single huge page size.
#[derive(Debug, Clone, Copy)]
pub struct HugetlbUsage {
    /// Current usage in bytes.
    pub current: u64,
    /// Maximum usage ever reached (high-water mark) in bytes.
    pub max_usage: u64,
    /// Configured limit in bytes (`u64::MAX` = unlimited).
    pub limit: u64,
    /// Number of times an allocation was rejected.
    pub failcnt: u64,
    /// Reservation count — pages reserved but not yet faulted.
    pub rsvd_current: u64,
    /// Reservation high-water mark.
    pub rsvd_max_usage: u64,
    /// Reservation limit in bytes.
    pub rsvd_limit: u64,
    /// Reservation failure count.
    pub rsvd_failcnt: u64,
}

impl HugetlbUsage {
    /// Creates a new unlimited usage tracker.
    const fn new() -> Self {
        Self {
            current: 0,
            max_usage: 0,
            limit: LIMIT_UNLIMITED,
            failcnt: 0,
            rsvd_current: 0,
            rsvd_max_usage: 0,
            rsvd_limit: LIMIT_UNLIMITED,
            rsvd_failcnt: 0,
        }
    }

    /// Resets the high-water mark to the current usage.
    pub fn reset_max(&mut self) {
        self.max_usage = self.current;
        self.rsvd_max_usage = self.rsvd_current;
    }

    /// Resets the failure counter to zero.
    pub fn reset_failcnt(&mut self) {
        self.failcnt = 0;
        self.rsvd_failcnt = 0;
    }

    /// Returns whether a charge of `bytes` would exceed the limit.
    pub const fn would_exceed(&self, bytes: u64) -> bool {
        self.limit != LIMIT_UNLIMITED && self.current.saturating_add(bytes) > self.limit
    }

    /// Returns whether a reservation of `bytes` would exceed the
    /// reservation limit.
    pub const fn rsvd_would_exceed(&self, bytes: u64) -> bool {
        self.rsvd_limit != LIMIT_UNLIMITED
            && self.rsvd_current.saturating_add(bytes) > self.rsvd_limit
    }
}

impl Default for HugetlbUsage {
    fn default() -> Self {
        Self::new()
    }
}

// ── HugetlbStats ─────────────────────────────────────────────────

/// Aggregated HugeTLB statistics across all page sizes.
///
/// Provides a snapshot of a cgroup's HugeTLB resource consumption.
#[derive(Debug, Clone, Copy, Default)]
pub struct HugetlbStats {
    /// Total current usage in bytes (sum across all page sizes).
    pub total_current: u64,
    /// Total max usage in bytes (sum across all page sizes).
    pub total_max: u64,
    /// Total failure count (sum across all page sizes).
    pub total_failcnt: u64,
    /// Total reservation current in bytes.
    pub total_rsvd_current: u64,
}

// ── HugetlbCgroup ────────────────────────────────────────────────

/// A single HugeTLB cgroup controller instance.
///
/// Manages huge page usage limits and accounting for a set of
/// attached processes. Each instance tracks per-page-size usage
/// and supports hierarchical limit enforcement.
#[derive(Debug, Clone, Copy)]
pub struct HugetlbCgroup {
    /// Unique identifier for this controller.
    pub id: u64,
    /// Controller name (UTF-8 bytes, null-padded).
    pub name: [u8; MAX_NAME_LEN],
    /// Name length in bytes.
    pub name_len: usize,
    /// Per-page-size usage and limits.
    pub usage: [HugetlbUsage; NUM_PAGE_SIZES],
    /// Attached process IDs.
    pub pids: [u64; MAX_PIDS_PER_GROUP],
    /// Number of attached PIDs.
    pub pid_count: usize,
    /// Parent cgroup index (`u64::MAX` = root / no parent).
    pub parent_id: u64,
    /// Whether this controller is enabled.
    pub enabled: bool,
    /// Whether this slot is actively in use.
    pub in_use: bool,
}

impl HugetlbCgroup {
    /// Creates an empty (inactive) controller slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            usage: [HugetlbUsage::new(); NUM_PAGE_SIZES],
            pids: [0u64; MAX_PIDS_PER_GROUP],
            pid_count: 0,
            parent_id: u64::MAX,
            enabled: false,
            in_use: false,
        }
    }

    /// Returns the per-size usage for the given page size.
    pub fn get_usage(&self, size: HugePageSize) -> &HugetlbUsage {
        &self.usage[size.index()]
    }

    /// Returns a mutable reference to per-size usage.
    pub fn get_usage_mut(&mut self, size: HugePageSize) -> &mut HugetlbUsage {
        &mut self.usage[size.index()]
    }

    /// Sets the limit for a given page size.
    ///
    /// A limit of `u64::MAX` means unlimited.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if `limit` is not page-size
    /// aligned (and is not unlimited).
    pub fn set_limit(&mut self, size: HugePageSize, limit: u64) -> Result<()> {
        if limit != LIMIT_UNLIMITED && limit % size.bytes() != 0 {
            return Err(Error::InvalidArgument);
        }
        self.usage[size.index()].limit = limit;
        Ok(())
    }

    /// Sets the reservation limit for a given page size.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if the limit is not aligned.
    pub fn set_rsvd_limit(&mut self, size: HugePageSize, limit: u64) -> Result<()> {
        if limit != LIMIT_UNLIMITED && limit % size.bytes() != 0 {
            return Err(Error::InvalidArgument);
        }
        self.usage[size.index()].rsvd_limit = limit;
        Ok(())
    }

    /// Attempts to charge `nr_pages` huge pages of the given size.
    ///
    /// Checks both the local limit and returns whether the charge
    /// succeeded locally. The caller must also check parent limits
    /// via [`HugetlbRegistry::try_charge`].
    ///
    /// # Errors
    ///
    /// Returns `Error::OutOfMemory` if the charge would exceed the
    /// configured limit.
    pub fn try_charge_local(&mut self, size: HugePageSize, nr_pages: u64) -> Result<()> {
        let bytes = nr_pages.saturating_mul(size.bytes());
        let usage = &mut self.usage[size.index()];

        if usage.would_exceed(bytes) {
            usage.failcnt = usage.failcnt.saturating_add(1);
            return Err(Error::OutOfMemory);
        }

        usage.current = usage.current.saturating_add(bytes);
        if usage.current > usage.max_usage {
            usage.max_usage = usage.current;
        }
        Ok(())
    }

    /// Uncharges `nr_pages` huge pages of the given size.
    ///
    /// Saturates at zero — will not underflow.
    pub fn uncharge_local(&mut self, size: HugePageSize, nr_pages: u64) {
        let bytes = nr_pages.saturating_mul(size.bytes());
        let usage = &mut self.usage[size.index()];
        usage.current = usage.current.saturating_sub(bytes);
    }

    /// Attempts to reserve `nr_pages` of the given size.
    ///
    /// # Errors
    ///
    /// Returns `Error::OutOfMemory` if the reservation would
    /// exceed the reservation limit.
    pub fn try_reserve_local(&mut self, size: HugePageSize, nr_pages: u64) -> Result<()> {
        let bytes = nr_pages.saturating_mul(size.bytes());
        let usage = &mut self.usage[size.index()];

        if usage.rsvd_would_exceed(bytes) {
            usage.rsvd_failcnt = usage.rsvd_failcnt.saturating_add(1);
            return Err(Error::OutOfMemory);
        }

        usage.rsvd_current = usage.rsvd_current.saturating_add(bytes);
        if usage.rsvd_current > usage.rsvd_max_usage {
            usage.rsvd_max_usage = usage.rsvd_current;
        }
        Ok(())
    }

    /// Unreserves `nr_pages` of the given size.
    pub fn unreserve_local(&mut self, size: HugePageSize, nr_pages: u64) {
        let bytes = nr_pages.saturating_mul(size.bytes());
        let usage = &mut self.usage[size.index()];
        usage.rsvd_current = usage.rsvd_current.saturating_sub(bytes);
    }

    /// Returns aggregated statistics across all page sizes.
    pub fn stats(&self) -> HugetlbStats {
        let mut s = HugetlbStats::default();
        for u in &self.usage {
            s.total_current = s.total_current.saturating_add(u.current);
            s.total_max = s.total_max.saturating_add(u.max_usage);
            s.total_failcnt = s.total_failcnt.saturating_add(u.failcnt);
            s.total_rsvd_current = s.total_rsvd_current.saturating_add(u.rsvd_current);
        }
        s
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
        if self.pid_count >= MAX_PIDS_PER_GROUP {
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

    /// Resets high-water marks for all page sizes.
    pub fn reset_all_max(&mut self) {
        for u in &mut self.usage {
            u.reset_max();
        }
    }

    /// Resets failure counters for all page sizes.
    pub fn reset_all_failcnt(&mut self) {
        for u in &mut self.usage {
            u.reset_failcnt();
        }
    }
}

impl Default for HugetlbCgroup {
    fn default() -> Self {
        Self::empty()
    }
}

// ── HugetlbRegistry ──────────────────────────────────────────────

/// System-wide registry of HugeTLB cgroup controllers.
///
/// Manages creation, lookup, and hierarchical limit enforcement
/// across all HugeTLB cgroups in the system.
pub struct HugetlbRegistry {
    /// Controller slots.
    controllers: [HugetlbCgroup; MAX_HUGETLB_CGROUPS],
    /// Next unique ID to assign.
    next_id: u64,
}

impl HugetlbRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            controllers: [HugetlbCgroup::empty(); MAX_HUGETLB_CGROUPS],
            next_id: 1,
        }
    }

    /// Creates a new HugeTLB cgroup controller.
    ///
    /// # Errors
    ///
    /// - `Error::InvalidArgument` — name is empty or too long.
    /// - `Error::AlreadyExists` — a controller with this name
    ///   already exists.
    /// - `Error::OutOfMemory` — no free slots.
    /// - `Error::NotFound` — parent_id given but not found.
    pub fn create(&mut self, name: &[u8], parent_id: Option<u64>) -> Result<u64> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }

        // Check for duplicate name.
        for c in &self.controllers {
            if c.in_use && c.name_len == name.len() && c.name[..c.name_len] == *name {
                return Err(Error::AlreadyExists);
            }
        }

        // Validate parent exists if specified.
        let pid = match parent_id {
            Some(p) => {
                if !self.controllers.iter().any(|c| c.in_use && c.id == p) {
                    return Err(Error::NotFound);
                }
                p
            }
            None => u64::MAX,
        };

        // Find a free slot.
        let slot = self
            .controllers
            .iter_mut()
            .find(|c| !c.in_use)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id += 1;

        *slot = HugetlbCgroup::empty();
        slot.id = id;
        slot.name[..name.len()].copy_from_slice(name);
        slot.name_len = name.len();
        slot.parent_id = pid;
        slot.enabled = true;
        slot.in_use = true;

        Ok(id)
    }

    /// Removes a HugeTLB cgroup controller by ID.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — no controller with that ID.
    /// - `Error::Busy` — controller still has attached PIDs or
    ///   non-zero usage.
    pub fn remove(&mut self, id: u64) -> Result<()> {
        let idx = self
            .controllers
            .iter()
            .position(|c| c.in_use && c.id == id)
            .ok_or(Error::NotFound)?;

        if self.controllers[idx].pid_count > 0 {
            return Err(Error::Busy);
        }

        // Check that no child references this controller.
        let has_children = self
            .controllers
            .iter()
            .any(|c| c.in_use && c.parent_id == id);
        if has_children {
            return Err(Error::Busy);
        }

        self.controllers[idx] = HugetlbCgroup::empty();
        Ok(())
    }

    /// Returns a reference to a controller by ID.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if not found.
    pub fn get(&self, id: u64) -> Result<&HugetlbCgroup> {
        self.controllers
            .iter()
            .find(|c| c.in_use && c.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns a mutable reference to a controller by ID.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if not found.
    pub fn get_mut(&mut self, id: u64) -> Result<&mut HugetlbCgroup> {
        self.controllers
            .iter_mut()
            .find(|c| c.in_use && c.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns the number of active controllers.
    pub fn count(&self) -> usize {
        self.controllers.iter().filter(|c| c.in_use).count()
    }

    /// Collects the ancestor chain for a controller (bottom-up,
    /// not including the controller itself).
    ///
    /// Returns the number of ancestors written to `chain`.
    fn ancestor_chain(&self, id: u64, chain: &mut [u64; MAX_HIERARCHY_DEPTH]) -> usize {
        let mut count = 0;
        let mut cur = id;

        loop {
            let parent_id = match self.controllers.iter().find(|c| c.in_use && c.id == cur) {
                Some(c) => c.parent_id,
                None => break,
            };

            if parent_id == u64::MAX {
                break;
            }

            if count >= MAX_HIERARCHY_DEPTH {
                break;
            }

            chain[count] = parent_id;
            count += 1;
            cur = parent_id;
        }

        count
    }

    /// Attempts to charge `nr_pages` of `size` to the controller
    /// and all its ancestors (hierarchical enforcement).
    ///
    /// If any ancestor rejects the charge, the entire operation
    /// is rolled back.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — controller ID not found.
    /// - `Error::OutOfMemory` — limit exceeded at some level.
    pub fn try_charge(&mut self, id: u64, size: HugePageSize, nr_pages: u64) -> Result<()> {
        // Build ancestor chain first (avoids borrow issues).
        let mut chain = [0u64; MAX_HIERARCHY_DEPTH];
        let chain_len = self.ancestor_chain(id, &mut chain);

        // Phase 1: validate all levels would accept the charge.
        let bytes = nr_pages.saturating_mul(size.bytes());
        let idx = size.index();

        // Check self.
        let self_ctrl = self
            .controllers
            .iter()
            .find(|c| c.in_use && c.id == id)
            .ok_or(Error::NotFound)?;
        if self_ctrl.usage[idx].would_exceed(bytes) {
            return Err(Error::OutOfMemory);
        }

        // Check all ancestors.
        for &anc_id in &chain[..chain_len] {
            if let Some(anc) = self.controllers.iter().find(|c| c.in_use && c.id == anc_id) {
                if anc.usage[idx].would_exceed(bytes) {
                    return Err(Error::OutOfMemory);
                }
            }
        }

        // Phase 2: apply charges (all validated, safe to commit).
        let ctrl = self
            .controllers
            .iter_mut()
            .find(|c| c.in_use && c.id == id)
            .ok_or(Error::NotFound)?;
        let _ = ctrl.try_charge_local(size, nr_pages);

        for &anc_id in &chain[..chain_len] {
            if let Some(anc) = self
                .controllers
                .iter_mut()
                .find(|c| c.in_use && c.id == anc_id)
            {
                let _ = anc.try_charge_local(size, nr_pages);
            }
        }

        Ok(())
    }

    /// Uncharges `nr_pages` of `size` from the controller and all
    /// its ancestors.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if the controller is not found.
    pub fn uncharge(&mut self, id: u64, size: HugePageSize, nr_pages: u64) -> Result<()> {
        let mut chain = [0u64; MAX_HIERARCHY_DEPTH];
        let chain_len = self.ancestor_chain(id, &mut chain);

        let ctrl = self
            .controllers
            .iter_mut()
            .find(|c| c.in_use && c.id == id)
            .ok_or(Error::NotFound)?;
        ctrl.uncharge_local(size, nr_pages);

        for &anc_id in &chain[..chain_len] {
            if let Some(anc) = self
                .controllers
                .iter_mut()
                .find(|c| c.in_use && c.id == anc_id)
            {
                anc.uncharge_local(size, nr_pages);
            }
        }

        Ok(())
    }

    /// Attempts to reserve `nr_pages` of `size` on the controller
    /// and all ancestors.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — controller not found.
    /// - `Error::OutOfMemory` — reservation limit exceeded.
    pub fn try_reserve(&mut self, id: u64, size: HugePageSize, nr_pages: u64) -> Result<()> {
        let mut chain = [0u64; MAX_HIERARCHY_DEPTH];
        let chain_len = self.ancestor_chain(id, &mut chain);

        let bytes = nr_pages.saturating_mul(size.bytes());
        let idx = size.index();

        // Validate.
        let self_ctrl = self
            .controllers
            .iter()
            .find(|c| c.in_use && c.id == id)
            .ok_or(Error::NotFound)?;
        if self_ctrl.usage[idx].rsvd_would_exceed(bytes) {
            return Err(Error::OutOfMemory);
        }

        for &anc_id in &chain[..chain_len] {
            if let Some(anc) = self.controllers.iter().find(|c| c.in_use && c.id == anc_id) {
                if anc.usage[idx].rsvd_would_exceed(bytes) {
                    return Err(Error::OutOfMemory);
                }
            }
        }

        // Commit.
        let ctrl = self
            .controllers
            .iter_mut()
            .find(|c| c.in_use && c.id == id)
            .ok_or(Error::NotFound)?;
        let _ = ctrl.try_reserve_local(size, nr_pages);

        for &anc_id in &chain[..chain_len] {
            if let Some(anc) = self
                .controllers
                .iter_mut()
                .find(|c| c.in_use && c.id == anc_id)
            {
                let _ = anc.try_reserve_local(size, nr_pages);
            }
        }

        Ok(())
    }

    /// Unreserves `nr_pages` of `size` from the controller and
    /// all ancestors.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if the controller is not found.
    pub fn unreserve(&mut self, id: u64, size: HugePageSize, nr_pages: u64) -> Result<()> {
        let mut chain = [0u64; MAX_HIERARCHY_DEPTH];
        let chain_len = self.ancestor_chain(id, &mut chain);

        let ctrl = self
            .controllers
            .iter_mut()
            .find(|c| c.in_use && c.id == id)
            .ok_or(Error::NotFound)?;
        ctrl.unreserve_local(size, nr_pages);

        for &anc_id in &chain[..chain_len] {
            if let Some(anc) = self
                .controllers
                .iter_mut()
                .find(|c| c.in_use && c.id == anc_id)
            {
                anc.unreserve_local(size, nr_pages);
            }
        }

        Ok(())
    }

    /// Sets the limit for a given controller and page size.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — controller not found.
    /// - `Error::InvalidArgument` — limit not page-aligned.
    pub fn set_limit(&mut self, id: u64, size: HugePageSize, limit: u64) -> Result<()> {
        let ctrl = self.get_mut(id)?;
        ctrl.set_limit(size, limit)
    }

    /// Resets the high-water mark for a controller and page size.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if the controller is not found.
    pub fn reset_max(&mut self, id: u64, size: HugePageSize) -> Result<()> {
        let ctrl = self.get_mut(id)?;
        ctrl.get_usage_mut(size).reset_max();
        Ok(())
    }

    /// Resets the failure counter for a controller and page size.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if the controller is not found.
    pub fn reset_failcnt(&mut self, id: u64, size: HugePageSize) -> Result<()> {
        let ctrl = self.get_mut(id)?;
        ctrl.get_usage_mut(size).reset_failcnt();
        Ok(())
    }

    /// Returns aggregated stats for a controller.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if the controller is not found.
    pub fn stats(&self, id: u64) -> Result<HugetlbStats> {
        let ctrl = self.get(id)?;
        Ok(ctrl.stats())
    }

    /// Returns the per-size usage for a controller.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if the controller is not found.
    pub fn usage(&self, id: u64, size: HugePageSize) -> Result<&HugetlbUsage> {
        let ctrl = self.get(id)?;
        Ok(ctrl.get_usage(size))
    }

    /// Adds a PID to a controller.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — controller not found.
    /// - `Error::AlreadyExists` — PID already attached.
    /// - `Error::OutOfMemory` — PID list full.
    pub fn add_pid(&mut self, id: u64, pid: u64) -> Result<()> {
        let ctrl = self.get_mut(id)?;
        ctrl.add_pid(pid)
    }

    /// Removes a PID from a controller.
    ///
    /// # Errors
    ///
    /// - `Error::NotFound` — controller or PID not found.
    pub fn remove_pid(&mut self, id: u64, pid: u64) -> Result<()> {
        let ctrl = self.get_mut(id)?;
        ctrl.remove_pid(pid)
    }

    /// Enables or disables a controller.
    ///
    /// # Errors
    ///
    /// Returns `Error::NotFound` if the controller is not found.
    pub fn set_enabled(&mut self, id: u64, enabled: bool) -> Result<()> {
        let ctrl = self.get_mut(id)?;
        ctrl.enabled = enabled;
        Ok(())
    }
}

impl Default for HugetlbRegistry {
    fn default() -> Self {
        Self::new()
    }
}
