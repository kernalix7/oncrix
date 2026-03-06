// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory limit enforcement.
//!
//! Enforces hard and soft limits on memory usage for processes and
//! cgroups. Soft limits trigger reclaim; hard limits deny allocations.
//! Also implements the high watermark mechanism where a process is
//! throttled when its usage exceeds the high mark.
//!
//! # Design
//!
//! ```text
//!  Allocation request
//!       │
//!       ▼
//!  MemoryLimitChecker::check(entity, amount)
//!       │
//!       ├─ below soft  → allow (no action)
//!       ├─ above soft, below hard → allow + trigger reclaim
//!       ├─ above high  → allow + throttle
//!       └─ above hard  → deny (OutOfMemory)
//! ```
//!
//! # Key Types
//!
//! - [`MemoryLimits`] — soft/high/hard limit values
//! - [`LimitEntity`] — an entity (process or cgroup) with limits
//! - [`MemoryLimitChecker`] — the limit enforcement engine
//! - [`LimitCheckResult`] — outcome of a limit check
//!
//! Reference: Linux `mm/memcontrol.c` (memory.high, memory.max).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum entities tracked.
const MAX_ENTITIES: usize = 512;

/// Unlimited value.
pub const UNLIMITED: u64 = u64::MAX;

// -------------------------------------------------------------------
// MemoryLimits
// -------------------------------------------------------------------

/// Soft, high, and hard memory limits (in pages).
#[derive(Debug, Clone, Copy)]
pub struct MemoryLimits {
    /// Soft limit — reclaim target when exceeded.
    pub soft: u64,
    /// High limit — throttle point.
    pub high: u64,
    /// Hard limit — allocation denied above this.
    pub hard: u64,
}

impl MemoryLimits {
    /// Create limits with all values unlimited.
    pub const fn unlimited() -> Self {
        Self {
            soft: UNLIMITED,
            high: UNLIMITED,
            hard: UNLIMITED,
        }
    }

    /// Create limits with specific values.
    pub const fn new(soft: u64, high: u64, hard: u64) -> Self {
        Self { soft, high, hard }
    }

    /// Validate that soft <= high <= hard.
    pub fn validate(&self) -> Result<()> {
        if self.soft > self.high || self.high > self.hard {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Check whether all limits are unlimited.
    pub const fn is_unlimited(&self) -> bool {
        self.soft == UNLIMITED && self.high == UNLIMITED && self.hard == UNLIMITED
    }
}

impl Default for MemoryLimits {
    fn default() -> Self {
        Self::unlimited()
    }
}

// -------------------------------------------------------------------
// LimitCheckResult
// -------------------------------------------------------------------

/// Outcome of a limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitAction {
    /// Below all limits — proceed normally.
    Allow,
    /// Above soft limit — trigger background reclaim.
    Reclaim,
    /// Above high limit — throttle the caller.
    Throttle,
    /// Above hard limit — deny the allocation.
    Deny,
}

impl LimitAction {
    /// Return a human-readable name.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Reclaim => "reclaim",
            Self::Throttle => "throttle",
            Self::Deny => "deny",
        }
    }
}

/// Full result of a limit check.
#[derive(Debug, Clone, Copy)]
pub struct LimitCheckResult {
    /// Recommended action.
    pub action: LimitAction,
    /// Current usage (pages).
    pub usage: u64,
    /// Limit that was hit (if any).
    pub limit_value: u64,
    /// Overage above the limit.
    pub overage: u64,
}

impl LimitCheckResult {
    /// Create an allow result.
    pub const fn allow(usage: u64) -> Self {
        Self {
            action: LimitAction::Allow,
            usage,
            limit_value: 0,
            overage: 0,
        }
    }

    /// Check whether the allocation should proceed.
    pub const fn should_allow(&self) -> bool {
        !matches!(self.action, LimitAction::Deny)
    }
}

// -------------------------------------------------------------------
// LimitEntity
// -------------------------------------------------------------------

/// An entity subject to memory limits.
#[derive(Debug, Clone, Copy)]
pub struct LimitEntity {
    /// Entity identifier (PID or cgroup ID).
    entity_id: u32,
    /// Current memory usage (pages).
    usage: u64,
    /// Configured limits.
    limits: MemoryLimits,
    /// Whether this entity is active.
    active: bool,
    /// Number of times hard limit was hit.
    hard_hits: u64,
    /// Number of times reclaim was triggered.
    reclaim_events: u64,
}

impl LimitEntity {
    /// Create a new entity with unlimited limits.
    pub const fn new(entity_id: u32) -> Self {
        Self {
            entity_id,
            usage: 0,
            limits: MemoryLimits::unlimited(),
            active: true,
            hard_hits: 0,
            reclaim_events: 0,
        }
    }

    /// Return the entity ID.
    pub const fn entity_id(&self) -> u32 {
        self.entity_id
    }

    /// Return current usage.
    pub const fn usage(&self) -> u64 {
        self.usage
    }

    /// Return the limits.
    pub const fn limits(&self) -> &MemoryLimits {
        &self.limits
    }

    /// Set the limits.
    pub fn set_limits(&mut self, limits: MemoryLimits) -> Result<()> {
        limits.validate()?;
        self.limits = limits;
        Ok(())
    }

    /// Charge pages.
    pub fn charge(&mut self, pages: u64) {
        self.usage = self.usage.saturating_add(pages);
    }

    /// Uncharge pages.
    pub fn uncharge(&mut self, pages: u64) {
        self.usage = self.usage.saturating_sub(pages);
    }

    /// Check limits for the current usage.
    pub fn check(&mut self) -> LimitCheckResult {
        if self.usage > self.limits.hard {
            self.hard_hits += 1;
            LimitCheckResult {
                action: LimitAction::Deny,
                usage: self.usage,
                limit_value: self.limits.hard,
                overage: self.usage - self.limits.hard,
            }
        } else if self.usage > self.limits.high {
            LimitCheckResult {
                action: LimitAction::Throttle,
                usage: self.usage,
                limit_value: self.limits.high,
                overage: self.usage - self.limits.high,
            }
        } else if self.usage > self.limits.soft {
            self.reclaim_events += 1;
            LimitCheckResult {
                action: LimitAction::Reclaim,
                usage: self.usage,
                limit_value: self.limits.soft,
                overage: self.usage - self.limits.soft,
            }
        } else {
            LimitCheckResult::allow(self.usage)
        }
    }

    /// Return hard-limit hit count.
    pub const fn hard_hits(&self) -> u64 {
        self.hard_hits
    }

    /// Whether this entity is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Deactivate.
    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl Default for LimitEntity {
    fn default() -> Self {
        Self::new(0)
    }
}

// -------------------------------------------------------------------
// MemoryLimitChecker
// -------------------------------------------------------------------

/// Memory limit enforcement engine.
pub struct MemoryLimitChecker {
    /// Tracked entities.
    entities: [LimitEntity; MAX_ENTITIES],
    /// Number of entities.
    count: usize,
    /// Total denied allocations.
    total_denials: u64,
}

impl MemoryLimitChecker {
    /// Create a new checker.
    pub const fn new() -> Self {
        Self {
            entities: [const { LimitEntity::new(0) }; MAX_ENTITIES],
            count: 0,
            total_denials: 0,
        }
    }

    /// Register an entity.
    pub fn register(&mut self, entity_id: u32, limits: MemoryLimits) -> Result<()> {
        limits.validate()?;
        if self.count >= MAX_ENTITIES {
            return Err(Error::OutOfMemory);
        }
        let mut entity = LimitEntity::new(entity_id);
        entity.set_limits(limits)?;
        self.entities[self.count] = entity;
        self.count += 1;
        Ok(())
    }

    /// Find an entity by ID.
    pub fn find_mut(&mut self, entity_id: u32) -> Option<&mut LimitEntity> {
        for idx in 0..self.count {
            if self.entities[idx].entity_id() == entity_id && self.entities[idx].is_active() {
                return Some(&mut self.entities[idx]);
            }
        }
        None
    }

    /// Charge pages and check the limit.
    pub fn charge_and_check(&mut self, entity_id: u32, pages: u64) -> Result<LimitCheckResult> {
        let entity = self.find_mut(entity_id).ok_or(Error::NotFound)?;
        entity.charge(pages);
        let result = entity.check();
        if result.action == LimitAction::Deny {
            // Roll back the charge.
            entity.uncharge(pages);
            self.total_denials += 1;
        }
        Ok(result)
    }

    /// Return total denials.
    pub const fn total_denials(&self) -> u64 {
        self.total_denials
    }

    /// Return entity count.
    pub const fn entity_count(&self) -> usize {
        self.count
    }
}

impl Default for MemoryLimitChecker {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Create a limits structure from MiB values.
pub fn limits_from_mib(soft_mib: u64, high_mib: u64, hard_mib: u64) -> MemoryLimits {
    let pages_per_mib = 256; // 1 MiB / 4096
    MemoryLimits::new(
        soft_mib * pages_per_mib,
        high_mib * pages_per_mib,
        hard_mib * pages_per_mib,
    )
}

/// Quick check: is an entity over its hard limit?
pub fn is_over_hard_limit(checker: &mut MemoryLimitChecker, entity_id: u32) -> bool {
    checker
        .find_mut(entity_id)
        .map(|e| e.check().action == LimitAction::Deny)
        .unwrap_or(false)
}

/// Return a summary of limit enforcement state.
pub fn limit_summary(checker: &MemoryLimitChecker) -> &'static str {
    if checker.total_denials() > 0 {
        "memory limits: active denials present"
    } else if checker.entity_count() > 0 {
        "memory limits: enforcing (no denials)"
    } else {
        "memory limits: no entities registered"
    }
}
