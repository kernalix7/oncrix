// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Usercopy hardening subsystem.
//!
//! Validates that all `copy_to_user` and `copy_from_user` operations
//! reference only whitelisted memory regions, preventing kernel
//! information leaks and corruption via unvalidated kernel pointers.
//!
//! Slab caches register their copyable regions at creation time via
//! [`UsercopyTable::register`]. At runtime, [`check_copy_size`]
//! verifies that a given pointer + size falls within a whitelisted
//! region or the current task's kernel stack.
//!
//! Key components:
//! - [`WhitelistedRegion`] — a registered safe-to-copy memory region
//! - [`UsercopyTable`] — global table of whitelisted regions
//! - [`UsercopyPolicy`] — enforcement mode (permissive or enforcing)
//! - [`HardeningStats`] — audit counters for copy checks
//!
//! Reference: `.kernelORG/` — `mm/usercopy.c`.

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Maximum number of whitelisted regions.
const MAX_WHITELISTED_REGIONS: usize = 128;

/// Maximum length of a region name in bytes.
const MAX_REGION_NAME_LEN: usize = 64;

// ── PolicyMode ──────────────────────────────────────────────────

/// Enforcement mode for usercopy checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyMode {
    /// Log violations but allow the copy to proceed.
    #[default]
    Permissive,
    /// Reject violating copies with an error.
    Enforcing,
}

// ── WhitelistedRegion ───────────────────────────────────────────

/// A memory region that has been registered as safe for user-space
/// copy operations.
///
/// Each region is described by an offset within its containing
/// object (e.g., a slab cache object) and a size. An optional
/// `slab_cache_id` ties the region to a specific allocator cache.
#[derive(Clone, Copy)]
pub struct WhitelistedRegion {
    /// Byte offset from the start of the containing object.
    pub start_offset: u32,
    /// Size of the whitelisted region in bytes.
    pub size: u32,
    /// Human-readable name for audit logs (null-padded).
    pub name: [u8; MAX_REGION_NAME_LEN],
    /// Length of valid bytes in `name`.
    name_len: u8,
    /// Optional slab cache identifier.
    ///
    /// `0` means the region is not tied to a specific cache.
    pub slab_cache_id: u16,
    /// Whether this table slot is in use.
    active: bool,
}

impl WhitelistedRegion {
    /// Creates an empty (inactive) region entry.
    const fn empty() -> Self {
        Self {
            start_offset: 0,
            size: 0,
            name: [0u8; MAX_REGION_NAME_LEN],
            name_len: 0,
            slab_cache_id: 0,
            active: false,
        }
    }

    /// Returns the region name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Returns `true` if the region covers the range
    /// `[offset, offset + len)`.
    pub fn contains(&self, offset: u32, len: u32) -> bool {
        offset >= self.start_offset
            && len <= self.size
            && offset - self.start_offset <= self.size - len
    }
}

// ── HardeningStats ──────────────────────────────────────────────

/// Audit counters for usercopy hardening checks.
#[derive(Debug, Clone, Copy, Default)]
pub struct HardeningStats {
    /// Number of copy operations that passed validation.
    pub checks_passed: u64,
    /// Number of copy operations that failed validation.
    pub checks_failed: u64,
    /// Number of violations that were logged (in permissive mode).
    pub violations_logged: u64,
}

// ── UsercopyPolicy ──────────────────────────────────────────────

/// Runtime policy for usercopy enforcement.
///
/// In [`PolicyMode::Permissive`] mode, violations are logged but
/// the copy proceeds. In [`PolicyMode::Enforcing`] mode, violations
/// return an error and the copy is rejected.
#[derive(Debug, Clone, Copy)]
pub struct UsercopyPolicy {
    /// Current enforcement mode.
    pub mode: PolicyMode,
    /// Whether to log violations to the kernel log.
    pub log_violations: bool,
    /// Total number of policy violations observed.
    pub violation_count: u64,
}

impl Default for UsercopyPolicy {
    fn default() -> Self {
        Self {
            mode: PolicyMode::Permissive,
            log_violations: true,
            violation_count: 0,
        }
    }
}

// ── UsercopyTable ───────────────────────────────────────────────

/// Global table of whitelisted memory regions for user-space copies.
///
/// Slab caches and other kernel subsystems register their copyable
/// regions here. The [`check_copy_size`] function consults this
/// table to validate copy operations.
pub struct UsercopyTable {
    /// Array of whitelisted regions.
    regions: [WhitelistedRegion; MAX_WHITELISTED_REGIONS],
    /// Number of active entries.
    count: usize,
    /// Enforcement policy.
    policy: UsercopyPolicy,
    /// Audit statistics.
    stats: HardeningStats,
}

impl Default for UsercopyTable {
    fn default() -> Self {
        Self::new()
    }
}

impl UsercopyTable {
    /// Creates a new empty usercopy table with permissive policy.
    pub const fn new() -> Self {
        Self {
            regions: [WhitelistedRegion::empty(); MAX_WHITELISTED_REGIONS],
            count: 0,
            policy: UsercopyPolicy {
                mode: PolicyMode::Permissive,
                log_violations: true,
                violation_count: 0,
            },
            stats: HardeningStats {
                checks_passed: 0,
                checks_failed: 0,
                violations_logged: 0,
            },
        }
    }

    /// Registers a new whitelisted region.
    ///
    /// # Arguments
    ///
    /// - `start_offset` — byte offset within the containing object
    /// - `size` — size of the whitelisted region in bytes
    /// - `name` — human-readable name (truncated to 64 bytes)
    /// - `slab_cache_id` — optional slab cache identifier (0 = none)
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — `size` is zero.
    /// - [`Error::OutOfMemory`] — the table is full.
    pub fn register(
        &mut self,
        start_offset: u32,
        size: u32,
        name: &[u8],
        slab_cache_id: u16,
    ) -> Result<usize> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_WHITELISTED_REGIONS {
            return Err(Error::OutOfMemory);
        }

        // Find a free slot.
        let slot_idx = self
            .regions
            .iter()
            .position(|r| !r.active)
            .ok_or(Error::OutOfMemory)?;

        let slot = &mut self.regions[slot_idx];
        slot.start_offset = start_offset;
        slot.size = size;
        slot.slab_cache_id = slab_cache_id;
        slot.active = true;

        // Copy name, truncating if necessary.
        let copy_len = name.len().min(MAX_REGION_NAME_LEN);
        slot.name[..copy_len].copy_from_slice(&name[..copy_len]);
        slot.name_len = copy_len as u8;

        self.count += 1;

        Ok(slot_idx)
    }

    /// Unregisters a whitelisted region by its table index.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — index is out of bounds or
    ///   the slot is not active.
    pub fn unregister(&mut self, index: usize) -> Result<()> {
        if index >= MAX_WHITELISTED_REGIONS {
            return Err(Error::InvalidArgument);
        }
        if !self.regions[index].active {
            return Err(Error::InvalidArgument);
        }

        self.regions[index] = WhitelistedRegion::empty();
        self.count = self.count.saturating_sub(1);

        Ok(())
    }

    /// Checks whether a memory range is whitelisted.
    ///
    /// Returns `true` if any registered region with the given
    /// `slab_cache_id` (or any region if `slab_cache_id` is 0)
    /// covers `[offset, offset + len)`.
    pub fn is_whitelisted(&self, offset: u32, len: u32, slab_cache_id: u16) -> bool {
        for region in &self.regions {
            if !region.active {
                continue;
            }
            // Match on slab cache if specified.
            if slab_cache_id != 0 && region.slab_cache_id != slab_cache_id {
                continue;
            }
            if region.contains(offset, len) {
                return true;
            }
        }
        false
    }

    /// Validates a kernel-to-user or user-to-kernel copy operation.
    ///
    /// Checks that the memory range `[offset, offset + size)` falls
    /// within a whitelisted region or the kernel stack bounds. In
    /// enforcing mode, a failed check returns an error; in
    /// permissive mode, a violation is logged but the check succeeds.
    ///
    /// # Arguments
    ///
    /// - `offset` — byte offset of the source/destination
    /// - `size` — number of bytes to copy
    /// - `slab_cache_id` — slab cache owning the object (0 = unknown)
    /// - `stack_start` — start of the current task's kernel stack
    /// - `stack_end` — end of the current task's kernel stack
    /// - `to_user` — `true` for copy-to-user, `false` for
    ///   copy-from-user
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — `size` is zero.
    /// - [`Error::PermissionDenied`] — copy is not whitelisted and
    ///   policy is enforcing.
    pub fn check_copy_size(
        &mut self,
        offset: u32,
        size: u32,
        slab_cache_id: u16,
        stack_start: u64,
        stack_end: u64,
        _to_user: bool,
    ) -> Result<()> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }

        // Check if the range is within the kernel stack.
        let addr = offset as u64;
        let addr_end = addr.saturating_add(size as u64);
        if addr >= stack_start && addr_end <= stack_end {
            self.stats.checks_passed += 1;
            return Ok(());
        }

        // Check the whitelist.
        if self.is_whitelisted(offset, size, slab_cache_id) {
            self.stats.checks_passed += 1;
            return Ok(());
        }

        // Violation detected.
        self.stats.checks_failed += 1;
        self.policy.violation_count += 1;

        if self.policy.log_violations {
            self.stats.violations_logged += 1;
        }

        match self.policy.mode {
            PolicyMode::Permissive => {
                // Allow the copy but record the violation.
                Ok(())
            }
            PolicyMode::Enforcing => Err(Error::PermissionDenied),
        }
    }

    /// Sets the enforcement policy mode.
    pub fn set_mode(&mut self, mode: PolicyMode) {
        self.policy.mode = mode;
    }

    /// Enables or disables violation logging.
    pub fn set_log_violations(&mut self, enabled: bool) {
        self.policy.log_violations = enabled;
    }

    /// Returns the current policy.
    pub fn policy(&self) -> &UsercopyPolicy {
        &self.policy
    }

    /// Returns audit statistics.
    pub fn stats(&self) -> &HardeningStats {
        &self.stats
    }

    /// Returns the number of registered whitelisted regions.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no regions are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
