// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Swap cgroup accounting.
//!
//! Tracks swap usage on a per-cgroup basis. When a page belonging to a
//! memory cgroup is swapped out, the swap entry is charged to that
//! cgroup's swap account. This prevents one cgroup from consuming all
//! available swap at the expense of others, and enables per-cgroup
//! swap limits.
//!
//! # Design
//!
//! ```text
//!  page swapped out
//!       │
//!       ▼
//!  ┌──────────────────┐
//!  │ SwapCgroupMap     │   swap_entry → cgroup_id
//!  │ (per-swap-area)   │
//!  └──────────────────┘
//!       │
//!       ▼
//!  ┌──────────────────┐
//!  │ CgroupSwapAcct   │   cgroup_id → {usage, limit}
//!  │ (per-cgroup)      │
//!  └──────────────────┘
//! ```
//!
//! # Key Types
//!
//! - [`SwapCgroupEntry`] — maps a swap slot to its owning cgroup
//! - [`CgroupSwapAccount`] — per-cgroup swap usage and limits
//! - [`SwapCgroupMap`] — the mapping engine
//!
//! Reference: Linux `mm/swap_cgroup.c`, `mm/memcontrol.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum swap entries tracked.
const MAX_SWAP_ENTRIES: usize = 8192;

/// Maximum cgroups with swap accounts.
const MAX_CGROUPS: usize = 128;

/// Unlimited swap (no per-cgroup limit).
const SWAP_UNLIMITED: u64 = u64::MAX;

// -------------------------------------------------------------------
// SwapCgroupEntry
// -------------------------------------------------------------------

/// Maps a swap slot to its owning cgroup.
#[derive(Debug, Clone, Copy)]
pub struct SwapCgroupEntry {
    /// Swap entry identifier (slot number).
    swap_id: u64,
    /// Owning cgroup identifier.
    cgroup_id: u64,
    /// Whether this entry is in use.
    in_use: bool,
}

impl SwapCgroupEntry {
    /// Creates an empty entry.
    pub const fn new() -> Self {
        Self {
            swap_id: 0,
            cgroup_id: 0,
            in_use: false,
        }
    }

    /// Returns the swap slot ID.
    pub const fn swap_id(&self) -> u64 {
        self.swap_id
    }

    /// Returns the cgroup ID.
    pub const fn cgroup_id(&self) -> u64 {
        self.cgroup_id
    }
}

impl Default for SwapCgroupEntry {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// CgroupSwapAccount
// -------------------------------------------------------------------

/// Per-cgroup swap usage and limit tracking.
#[derive(Debug, Clone, Copy)]
pub struct CgroupSwapAccount {
    /// Cgroup identifier.
    cgroup_id: u64,
    /// Current swap usage (pages).
    usage: u64,
    /// Maximum allowed swap usage (pages).
    limit: u64,
    /// Peak usage (high watermark).
    peak: u64,
    /// Total charge events.
    charges: u64,
    /// Total uncharge events.
    uncharges: u64,
    /// Charge failures (limit exceeded).
    failures: u64,
    /// Whether this account is active.
    active: bool,
}

impl CgroupSwapAccount {
    /// Creates an empty account.
    pub const fn new() -> Self {
        Self {
            cgroup_id: 0,
            usage: 0,
            limit: SWAP_UNLIMITED,
            peak: 0,
            charges: 0,
            uncharges: 0,
            failures: 0,
            active: false,
        }
    }

    /// Creates an account for a cgroup with a limit.
    pub const fn with_limit(cgroup_id: u64, limit: u64) -> Self {
        Self {
            cgroup_id,
            usage: 0,
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

    /// Returns the current swap usage.
    pub const fn usage(&self) -> u64 {
        self.usage
    }

    /// Returns the swap limit.
    pub const fn limit(&self) -> u64 {
        self.limit
    }

    /// Returns the peak usage.
    pub const fn peak(&self) -> u64 {
        self.peak
    }

    /// Returns usage as a percentage of the limit (0..100).
    pub const fn usage_percent(&self) -> u64 {
        if self.limit == 0 || self.limit == SWAP_UNLIMITED {
            return 0;
        }
        self.usage * 100 / self.limit
    }

    /// Attempts to charge `count` pages of swap.
    pub fn charge(&mut self, count: u64) -> Result<()> {
        if self.limit != SWAP_UNLIMITED && self.usage + count > self.limit {
            self.failures = self.failures.saturating_add(1);
            return Err(Error::OutOfMemory);
        }
        self.usage = self.usage.saturating_add(count);
        if self.usage > self.peak {
            self.peak = self.usage;
        }
        self.charges = self.charges.saturating_add(1);
        Ok(())
    }

    /// Uncharges `count` pages of swap.
    pub fn uncharge(&mut self, count: u64) {
        self.usage = self.usage.saturating_sub(count);
        self.uncharges = self.uncharges.saturating_add(1);
    }

    /// Sets a new swap limit.
    pub fn set_limit(&mut self, limit: u64) -> Result<()> {
        if limit < self.usage && limit != SWAP_UNLIMITED {
            return Err(Error::Busy);
        }
        self.limit = limit;
        Ok(())
    }
}

impl Default for CgroupSwapAccount {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// SwapCgroupMap
// -------------------------------------------------------------------

/// Maps swap entries to cgroups and manages per-cgroup accounting.
pub struct SwapCgroupMap {
    /// Swap-to-cgroup entries.
    entries: [SwapCgroupEntry; MAX_SWAP_ENTRIES],
    /// Per-cgroup accounts.
    accounts: [CgroupSwapAccount; MAX_CGROUPS],
    /// Number of active entries.
    entry_count: usize,
    /// Number of active accounts.
    account_count: usize,
}

impl SwapCgroupMap {
    /// Creates an empty map.
    pub const fn new() -> Self {
        Self {
            entries: [const { SwapCgroupEntry::new() }; MAX_SWAP_ENTRIES],
            accounts: [const { CgroupSwapAccount::new() }; MAX_CGROUPS],
            entry_count: 0,
            account_count: 0,
        }
    }

    /// Returns the number of active entries.
    pub const fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Returns the number of active cgroup accounts.
    pub const fn account_count(&self) -> usize {
        self.account_count
    }

    /// Registers a cgroup swap account.
    pub fn register_cgroup(&mut self, cgroup_id: u64, limit: u64) -> Result<()> {
        // Check duplicate.
        for i in 0..self.account_count {
            if self.accounts[i].cgroup_id == cgroup_id && self.accounts[i].active {
                return Err(Error::AlreadyExists);
            }
        }
        if self.account_count >= MAX_CGROUPS {
            return Err(Error::OutOfMemory);
        }
        self.accounts[self.account_count] = CgroupSwapAccount::with_limit(cgroup_id, limit);
        self.account_count += 1;
        Ok(())
    }

    /// Finds the account index for a cgroup.
    fn find_account(&self, cgroup_id: u64) -> Result<usize> {
        for i in 0..self.account_count {
            if self.accounts[i].cgroup_id == cgroup_id && self.accounts[i].active {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    /// Charges a swap entry to a cgroup.
    pub fn charge(&mut self, swap_id: u64, cgroup_id: u64) -> Result<()> {
        let acct_idx = self.find_account(cgroup_id)?;
        self.accounts[acct_idx].charge(1)?;

        // Record the entry.
        for i in 0..MAX_SWAP_ENTRIES {
            if !self.entries[i].in_use {
                self.entries[i] = SwapCgroupEntry {
                    swap_id,
                    cgroup_id,
                    in_use: true,
                };
                self.entry_count += 1;
                return Ok(());
            }
        }
        // Undo charge if no slot available.
        self.accounts[acct_idx].uncharge(1);
        Err(Error::OutOfMemory)
    }

    /// Uncharges a swap entry.
    pub fn uncharge(&mut self, swap_id: u64) -> Result<()> {
        for i in 0..MAX_SWAP_ENTRIES {
            if self.entries[i].in_use && self.entries[i].swap_id == swap_id {
                let cgroup_id = self.entries[i].cgroup_id;
                self.entries[i].in_use = false;
                self.entry_count -= 1;

                if let Ok(acct_idx) = self.find_account(cgroup_id) {
                    self.accounts[acct_idx].uncharge(1);
                }
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the swap usage for a cgroup.
    pub fn cgroup_usage(&self, cgroup_id: u64) -> Result<u64> {
        let idx = self.find_account(cgroup_id)?;
        Ok(self.accounts[idx].usage())
    }

    /// Returns the cgroup account for inspection.
    pub fn cgroup_account(&self, cgroup_id: u64) -> Result<&CgroupSwapAccount> {
        let idx = self.find_account(cgroup_id)?;
        Ok(&self.accounts[idx])
    }
}

impl Default for SwapCgroupMap {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Creates a swap cgroup map.
pub fn create_swap_cgroup_map() -> SwapCgroupMap {
    SwapCgroupMap::new()
}

/// Charges a swap entry to a cgroup.
pub fn charge_swap(map: &mut SwapCgroupMap, swap_id: u64, cgroup_id: u64) -> Result<()> {
    map.charge(swap_id, cgroup_id)
}

/// Returns the swap usage for a cgroup.
pub fn cgroup_swap_usage(map: &SwapCgroupMap, cgroup_id: u64) -> Result<u64> {
    map.cgroup_usage(cgroup_id)
}
