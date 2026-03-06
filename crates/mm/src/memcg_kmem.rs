// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory cgroup kernel memory accounting.
//!
//! Tracks kernel memory (slab caches, page tables, vmalloc, etc.)
//! charged to individual memory cgroups. This prevents a single cgroup
//! from exhausting kernel memory resources. Each slab allocation, page
//! table page, or vmalloc region can be charged to the allocating
//! cgroup's kernel memory account.
//!
//! # Design
//!
//! ```text
//!  kmalloc(size, GFP_KERNEL_ACCOUNT)
//!       │
//!       ▼
//!  ┌──────────────────────┐
//!  │  KmemAccount          │
//!  │  charge(cgroup, size) │──▶ update usage, check limit
//!  └──────────────────────┘
//!       │
//!       ▼
//!  ┌──────────────────────┐
//!  │  KmemChargeType       │   slab / page_table / vmalloc / stack
//!  └──────────────────────┘
//! ```
//!
//! # Key Types
//!
//! - [`KmemChargeType`] — category of kernel memory charge
//! - [`KmemAccount`] — per-cgroup kernel memory account
//! - [`KmemAccounting`] — the global accounting engine
//! - [`KmemStats`] — per-cgroup kernel memory statistics
//!
//! Reference: Linux `mm/memcontrol.c` (memcg kmem accounting).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum tracked cgroups.
const MAX_CGROUPS: usize = 128;

/// Unlimited kernel memory.
const KMEM_UNLIMITED: u64 = u64::MAX;

/// Number of charge type categories.
const NR_CHARGE_TYPES: usize = 5;

// -------------------------------------------------------------------
// KmemChargeType
// -------------------------------------------------------------------

/// Category of kernel memory being charged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmemChargeType {
    /// Slab object allocation.
    Slab,
    /// Page table page.
    PageTable,
    /// vmalloc allocation.
    Vmalloc,
    /// Kernel stack.
    Stack,
    /// Other kernel allocation.
    Other,
}

impl KmemChargeType {
    /// Returns the index for array storage.
    const fn index(self) -> usize {
        match self {
            Self::Slab => 0,
            Self::PageTable => 1,
            Self::Vmalloc => 2,
            Self::Stack => 3,
            Self::Other => 4,
        }
    }
}

impl Default for KmemChargeType {
    fn default() -> Self {
        Self::Other
    }
}

// -------------------------------------------------------------------
// KmemStats
// -------------------------------------------------------------------

/// Per-cgroup kernel memory statistics.
#[derive(Debug, Clone, Copy)]
pub struct KmemStats {
    /// Usage per charge type (in bytes).
    pub usage_by_type: [u64; NR_CHARGE_TYPES],
    /// Total kernel memory usage (bytes).
    pub total_usage: u64,
    /// Limit (bytes).
    pub limit: u64,
    /// Peak usage (bytes).
    pub peak: u64,
    /// Total charge events.
    pub charges: u64,
    /// Total uncharge events.
    pub uncharges: u64,
    /// Charge failures.
    pub failures: u64,
}

impl KmemStats {
    /// Creates empty stats.
    pub const fn new() -> Self {
        Self {
            usage_by_type: [0; NR_CHARGE_TYPES],
            total_usage: 0,
            limit: KMEM_UNLIMITED,
            peak: 0,
            charges: 0,
            uncharges: 0,
            failures: 0,
        }
    }

    /// Returns usage percentage (0..100).
    pub const fn usage_percent(&self) -> u64 {
        if self.limit == 0 || self.limit == KMEM_UNLIMITED {
            return 0;
        }
        self.total_usage * 100 / self.limit
    }
}

impl Default for KmemStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// KmemAccount
// -------------------------------------------------------------------

/// Per-cgroup kernel memory account.
#[derive(Debug, Clone, Copy)]
pub struct KmemAccount {
    /// Cgroup identifier.
    cgroup_id: u64,
    /// Usage per charge type (bytes).
    usage: [u64; NR_CHARGE_TYPES],
    /// Total usage (bytes).
    total: u64,
    /// Limit (bytes).
    limit: u64,
    /// Peak usage.
    peak: u64,
    /// Charge count.
    charges: u64,
    /// Uncharge count.
    uncharges: u64,
    /// Failure count.
    failures: u64,
    /// Whether the account is active.
    active: bool,
}

impl KmemAccount {
    /// Creates an empty account.
    pub const fn new() -> Self {
        Self {
            cgroup_id: 0,
            usage: [0; NR_CHARGE_TYPES],
            total: 0,
            limit: KMEM_UNLIMITED,
            peak: 0,
            charges: 0,
            uncharges: 0,
            failures: 0,
            active: false,
        }
    }

    /// Creates an account with a limit.
    pub const fn with_limit(cgroup_id: u64, limit: u64) -> Self {
        Self {
            cgroup_id,
            usage: [0; NR_CHARGE_TYPES],
            total: 0,
            limit,
            peak: 0,
            charges: 0,
            uncharges: 0,
            failures: 0,
            active: true,
        }
    }

    /// Returns the cgroup ID.
    pub const fn cgroup_id(&self) -> u64 {
        self.cgroup_id
    }

    /// Returns total usage.
    pub const fn total(&self) -> u64 {
        self.total
    }

    /// Returns the limit.
    pub const fn limit(&self) -> u64 {
        self.limit
    }

    /// Charges kernel memory.
    pub fn charge(&mut self, charge_type: KmemChargeType, bytes: u64) -> Result<()> {
        if self.limit != KMEM_UNLIMITED && self.total + bytes > self.limit {
            self.failures = self.failures.saturating_add(1);
            return Err(Error::OutOfMemory);
        }
        let idx = charge_type.index();
        self.usage[idx] = self.usage[idx].saturating_add(bytes);
        self.total = self.total.saturating_add(bytes);
        if self.total > self.peak {
            self.peak = self.total;
        }
        self.charges = self.charges.saturating_add(1);
        Ok(())
    }

    /// Uncharges kernel memory.
    pub fn uncharge(&mut self, charge_type: KmemChargeType, bytes: u64) {
        let idx = charge_type.index();
        self.usage[idx] = self.usage[idx].saturating_sub(bytes);
        self.total = self.total.saturating_sub(bytes);
        self.uncharges = self.uncharges.saturating_add(1);
    }

    /// Returns statistics for this account.
    pub const fn stats(&self) -> KmemStats {
        KmemStats {
            usage_by_type: self.usage,
            total_usage: self.total,
            limit: self.limit,
            peak: self.peak,
            charges: self.charges,
            uncharges: self.uncharges,
            failures: self.failures,
        }
    }
}

impl Default for KmemAccount {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// KmemAccounting
// -------------------------------------------------------------------

/// Global kernel memory accounting engine.
pub struct KmemAccounting {
    /// Per-cgroup accounts.
    accounts: [KmemAccount; MAX_CGROUPS],
    /// Number of active accounts.
    count: usize,
    /// Whether kmem accounting is enabled globally.
    enabled: bool,
}

impl KmemAccounting {
    /// Creates a new accounting engine (enabled by default).
    pub const fn new() -> Self {
        Self {
            accounts: [const { KmemAccount::new() }; MAX_CGROUPS],
            count: 0,
            enabled: true,
        }
    }

    /// Returns the number of active accounts.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Returns whether accounting is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Registers a cgroup for kmem accounting.
    pub fn register(&mut self, cgroup_id: u64, limit: u64) -> Result<()> {
        for i in 0..self.count {
            if self.accounts[i].cgroup_id == cgroup_id && self.accounts[i].active {
                return Err(Error::AlreadyExists);
            }
        }
        if self.count >= MAX_CGROUPS {
            return Err(Error::OutOfMemory);
        }
        self.accounts[self.count] = KmemAccount::with_limit(cgroup_id, limit);
        self.count += 1;
        Ok(())
    }

    /// Finds the account index.
    fn find(&self, cgroup_id: u64) -> Result<usize> {
        for i in 0..self.count {
            if self.accounts[i].cgroup_id == cgroup_id && self.accounts[i].active {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    /// Charges kernel memory to a cgroup.
    pub fn charge(
        &mut self,
        cgroup_id: u64,
        charge_type: KmemChargeType,
        bytes: u64,
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let idx = self.find(cgroup_id)?;
        self.accounts[idx].charge(charge_type, bytes)
    }

    /// Uncharges kernel memory from a cgroup.
    pub fn uncharge(
        &mut self,
        cgroup_id: u64,
        charge_type: KmemChargeType,
        bytes: u64,
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let idx = self.find(cgroup_id)?;
        self.accounts[idx].uncharge(charge_type, bytes);
        Ok(())
    }

    /// Returns statistics for a cgroup.
    pub fn stats(&self, cgroup_id: u64) -> Result<KmemStats> {
        let idx = self.find(cgroup_id)?;
        Ok(self.accounts[idx].stats())
    }

    /// Sets a new limit for a cgroup.
    pub fn set_limit(&mut self, cgroup_id: u64, limit: u64) -> Result<()> {
        let idx = self.find(cgroup_id)?;
        if limit != KMEM_UNLIMITED && limit < self.accounts[idx].total {
            return Err(Error::Busy);
        }
        self.accounts[idx].limit = limit;
        Ok(())
    }
}

impl Default for KmemAccounting {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Creates a new kmem accounting engine.
pub fn create_accounting() -> KmemAccounting {
    KmemAccounting::new()
}

/// Charges kmem to a cgroup.
pub fn charge_kmem(
    acct: &mut KmemAccounting,
    cgroup_id: u64,
    charge_type: KmemChargeType,
    bytes: u64,
) -> Result<()> {
    acct.charge(cgroup_id, charge_type, bytes)
}

/// Returns kmem stats for a cgroup.
pub fn kmem_stats(acct: &KmemAccounting, cgroup_id: u64) -> Result<KmemStats> {
    acct.stats(cgroup_id)
}
