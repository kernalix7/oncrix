// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Disk quota v2 on-disk format and controller.
//!
//! Implements the Linux VFS quota v2 (vfsv1) on-disk format with:
//! - On-disk header (`QuotaV2Header`) and per-ID records (`DquotEntry`)
//! - LRU dquot cache (`DquotCache`) for fast in-memory lookups
//! - Per-mount quota controller (`QuotaV2Controller`) with charge/uncharge
//!   and soft+grace vs hard limit enforcement
//! - Global registry (`QuotaV2Registry`) for managing per-mount quota state
//!
//! # On-disk format
//!
//! The quota v2 file starts with a [`QuotaV2Header`], followed by a
//! tree-structured index of [`DquotEntry`] records. This module
//! provides the in-memory representation; actual I/O is deferred to
//! the filesystem driver.
//!
//! # References
//!
//! - Linux `fs/quota/quota_v2.c`, `include/linux/dqblk_v2.h`
//! - `quotactl(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Quota v2 file magic number.
pub const QUOTA_V2_MAGIC: u32 = 0xD9C0_1F11;

/// Current quota v2 format version.
pub const QUOTA_V2_VERSION: u32 = 1;

/// Maximum dquot cache entries.
const DQUOT_CACHE_SIZE: usize = 256;

/// Maximum number of mounts with quota enabled.
const MAX_QUOTA_MOUNTS: usize = 16;

/// Default grace period in seconds (7 days).
const DEFAULT_GRACE_PERIOD: u64 = 604_800;

// ---------------------------------------------------------------------------
// On-disk structures
// ---------------------------------------------------------------------------

/// Quota v2 file header (on-disk, at byte offset 0).
///
/// Identifies the quota file format and contains global parameters.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct QuotaV2Header {
    /// Magic number (must be [`QUOTA_V2_MAGIC`]).
    pub magic: u32,
    /// Format version.
    pub version: u32,
    /// Flags (reserved for future use).
    pub flags: u32,
    /// Block size used by the quota file (usually matches FS block size).
    pub block_size: u32,
}

impl QuotaV2Header {
    /// Size of the on-disk header in bytes.
    pub const SIZE: usize = 16;

    /// Parse a header from a byte buffer (at least 16 bytes).
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::SIZE {
            return Err(Error::InvalidArgument);
        }
        let hdr = Self {
            magic: read_u32(buf, 0),
            version: read_u32(buf, 4),
            flags: read_u32(buf, 8),
            block_size: read_u32(buf, 12),
        };
        if hdr.magic != QUOTA_V2_MAGIC {
            return Err(Error::InvalidArgument);
        }
        Ok(hdr)
    }

    /// Serialize the header to a byte buffer (at least 16 bytes).
    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < Self::SIZE {
            return Err(Error::InvalidArgument);
        }
        write_u32(buf, 0, self.magic);
        write_u32(buf, 4, self.version);
        write_u32(buf, 8, self.flags);
        write_u32(buf, 12, self.block_size);
        Ok(())
    }

    /// Create a new header with default values.
    pub fn new(block_size: u32) -> Self {
        Self {
            magic: QUOTA_V2_MAGIC,
            version: QUOTA_V2_VERSION,
            flags: 0,
            block_size,
        }
    }
}

/// On-disk dquot (disk quota) entry for one user or group.
///
/// Contains both resource usage counters and configured limits.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct DquotEntry {
    /// User or group ID this entry tracks.
    pub id: u32,
    /// Number of filesystem blocks currently in use.
    pub blocks_used: u64,
    /// Soft limit for blocks (0 = unlimited).
    pub blocks_limit_soft: u64,
    /// Hard limit for blocks (0 = unlimited).
    pub blocks_limit_hard: u64,
    /// Number of inodes currently in use.
    pub inodes_used: u64,
    /// Soft limit for inodes (0 = unlimited).
    pub inodes_limit_soft: u64,
    /// Hard limit for inodes (0 = unlimited).
    pub inodes_limit_hard: u64,
    /// Timestamp when block grace period expires (0 = not active).
    pub grace_expire_blocks: u64,
    /// Timestamp when inode grace period expires (0 = not active).
    pub grace_expire_inodes: u64,
}

impl DquotEntry {
    /// Size of one on-disk dquot entry in bytes.
    pub const SIZE: usize = 68;

    /// Parse from a byte buffer (at least 68 bytes).
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            id: read_u32(buf, 0),
            blocks_used: read_u64(buf, 4),
            blocks_limit_soft: read_u64(buf, 12),
            blocks_limit_hard: read_u64(buf, 20),
            inodes_used: read_u64(buf, 28),
            inodes_limit_soft: read_u64(buf, 36),
            inodes_limit_hard: read_u64(buf, 44),
            grace_expire_blocks: read_u64(buf, 52),
            grace_expire_inodes: read_u64(buf, 60),
        })
    }

    /// Serialize to a byte buffer (at least 68 bytes).
    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<()> {
        if buf.len() < Self::SIZE {
            return Err(Error::InvalidArgument);
        }
        write_u32(buf, 0, self.id);
        write_u64(buf, 4, self.blocks_used);
        write_u64(buf, 12, self.blocks_limit_soft);
        write_u64(buf, 20, self.blocks_limit_hard);
        write_u64(buf, 28, self.inodes_used);
        write_u64(buf, 36, self.inodes_limit_soft);
        write_u64(buf, 44, self.inodes_limit_hard);
        write_u64(buf, 52, self.grace_expire_blocks);
        write_u64(buf, 60, self.grace_expire_inodes);
        Ok(())
    }

    /// Create a new, empty entry for the given ID.
    pub const fn new(id: u32) -> Self {
        Self {
            id,
            blocks_used: 0,
            blocks_limit_soft: 0,
            blocks_limit_hard: 0,
            inodes_used: 0,
            inodes_limit_soft: 0,
            inodes_limit_hard: 0,
            grace_expire_blocks: 0,
            grace_expire_inodes: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Quota type
// ---------------------------------------------------------------------------

/// Soft and hard limits for blocks and inodes (quota v2 format).
#[derive(Debug, Clone, Copy, Default)]
pub struct QuotaV2Limits {
    /// Soft limit for blocks (0 = unlimited).
    pub blocks_soft: u64,
    /// Hard limit for blocks (0 = unlimited).
    pub blocks_hard: u64,
    /// Soft limit for inodes (0 = unlimited).
    pub inodes_soft: u64,
    /// Hard limit for inodes (0 = unlimited).
    pub inodes_hard: u64,
}

/// Type of quota (user or group).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaV2Type {
    /// Per-user quota.
    User,
    /// Per-group quota.
    Group,
}

// ---------------------------------------------------------------------------
// DquotCache — LRU cache for dquot entries
// ---------------------------------------------------------------------------

/// Cached dquot slot.
#[derive(Clone, Copy)]
struct DquotCacheSlot {
    /// The dquot entry.
    entry: DquotEntry,
    /// Quota type (user or group).
    qtype: QuotaV2Type,
    /// Whether this slot is in use.
    active: bool,
    /// LRU counter (higher = more recently used).
    lru_counter: u64,
}

impl DquotCacheSlot {
    const fn empty() -> Self {
        Self {
            entry: DquotEntry::new(0),
            qtype: QuotaV2Type::User,
            active: false,
            lru_counter: 0,
        }
    }
}

/// LRU cache for dquot entries.
///
/// Holds up to [`DQUOT_CACHE_SIZE`] entries. On eviction, the
/// least-recently-used entry is replaced.
pub struct DquotCache {
    /// Cache slots.
    slots: [DquotCacheSlot; DQUOT_CACHE_SIZE],
    /// Monotonically increasing counter for LRU ordering.
    counter: u64,
    /// Number of active entries.
    count: usize,
}

impl DquotCache {
    /// Create a new, empty cache.
    pub const fn new() -> Self {
        Self {
            slots: [DquotCacheSlot::empty(); DQUOT_CACHE_SIZE],
            counter: 0,
            count: 0,
        }
    }

    /// Look up a cached dquot entry by (id, qtype).
    ///
    /// Returns a copy of the entry if found, and bumps its LRU counter.
    pub fn lookup(&mut self, id: u32, qtype: QuotaV2Type) -> Option<DquotEntry> {
        for slot in self.slots.iter_mut() {
            if slot.active && slot.entry.id == id && slot.qtype == qtype {
                self.counter = self.counter.saturating_add(1);
                slot.lru_counter = self.counter;
                return Some(slot.entry);
            }
        }
        None
    }

    /// Insert or update a dquot entry in the cache.
    ///
    /// If the cache is full, evicts the least-recently-used entry.
    pub fn insert(&mut self, entry: DquotEntry, qtype: QuotaV2Type) {
        self.counter = self.counter.saturating_add(1);

        // Update existing entry if present.
        for slot in self.slots.iter_mut() {
            if slot.active && slot.entry.id == entry.id && slot.qtype == qtype {
                slot.entry = entry;
                slot.lru_counter = self.counter;
                return;
            }
        }

        // Find a free slot or evict LRU.
        let target = if self.count < DQUOT_CACHE_SIZE {
            // Find first inactive slot.
            self.slots.iter().position(|s| !s.active).unwrap_or(0)
        } else {
            self.evict_lru()
        };

        let was_inactive = !self.slots[target].active;
        self.slots[target] = DquotCacheSlot {
            entry,
            qtype,
            active: true,
            lru_counter: self.counter,
        };
        if was_inactive {
            self.count += 1;
        }
    }

    /// Evict the least-recently-used entry. Returns its slot index.
    fn evict_lru(&mut self) -> usize {
        let mut min_lru = u64::MAX;
        let mut min_idx = 0;
        for (i, slot) in self.slots.iter().enumerate() {
            if slot.active && slot.lru_counter < min_lru {
                min_lru = slot.lru_counter;
                min_idx = i;
            }
        }
        self.slots[min_idx].active = false;
        self.count -= 1;
        min_idx
    }

    /// Remove a specific entry from the cache.
    pub fn invalidate(&mut self, id: u32, qtype: QuotaV2Type) {
        for slot in self.slots.iter_mut() {
            if slot.active && slot.entry.id == id && slot.qtype == qtype {
                slot.active = false;
                self.count -= 1;
                return;
            }
        }
    }

    /// Number of active cache entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for DquotCache {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// QuotaV2Controller — per-mount quota state
// ---------------------------------------------------------------------------

/// Quota enforcement result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaCheckResult {
    /// Allocation is within limits.
    Allowed,
    /// Soft limit exceeded; grace period started or running.
    SoftExceeded,
}

/// Per-mount quota controller.
///
/// Manages quota enforcement for a single mounted filesystem.
/// Tracks dquot entries in an LRU cache and enforces soft/hard
/// limits with grace periods.
pub struct QuotaV2Controller {
    /// Dquot cache.
    cache: DquotCache,
    /// Whether user quotas are enabled.
    user_enabled: bool,
    /// Whether group quotas are enabled.
    group_enabled: bool,
    /// Grace period for block soft-limit violations (seconds).
    grace_period_blocks: u64,
    /// Grace period for inode soft-limit violations (seconds).
    grace_period_inodes: u64,
}

impl QuotaV2Controller {
    /// Create a new controller with quotas disabled.
    pub const fn new() -> Self {
        Self {
            cache: DquotCache::new(),
            user_enabled: false,
            group_enabled: false,
            grace_period_blocks: DEFAULT_GRACE_PERIOD,
            grace_period_inodes: DEFAULT_GRACE_PERIOD,
        }
    }

    /// Enable user quotas.
    pub fn enable_user_quota(&mut self) {
        self.user_enabled = true;
    }

    /// Enable group quotas.
    pub fn enable_group_quota(&mut self) {
        self.group_enabled = true;
    }

    /// Disable user quotas.
    pub fn disable_user_quota(&mut self) {
        self.user_enabled = false;
    }

    /// Disable group quotas.
    pub fn disable_group_quota(&mut self) {
        self.group_enabled = false;
    }

    /// Whether quotas are enabled for the given type.
    pub fn is_enabled(&self, qtype: QuotaV2Type) -> bool {
        match qtype {
            QuotaV2Type::User => self.user_enabled,
            QuotaV2Type::Group => self.group_enabled,
        }
    }

    /// Set the grace periods (in seconds).
    pub fn set_grace_periods(&mut self, blocks: u64, inodes: u64) {
        self.grace_period_blocks = blocks;
        self.grace_period_inodes = inodes;
    }

    /// Get or create a dquot entry for the given ID and type.
    ///
    /// If the entry is not in the cache, a new default entry is created.
    pub fn get_dquot(&mut self, id: u32, qtype: QuotaV2Type) -> DquotEntry {
        match self.cache.lookup(id, qtype) {
            Some(entry) => entry,
            None => {
                let entry = DquotEntry::new(id);
                self.cache.insert(entry, qtype);
                entry
            }
        }
    }

    /// Set limits for a specific user or group.
    pub fn set_limits(&mut self, id: u32, qtype: QuotaV2Type, limits: &QuotaV2Limits) {
        let mut entry = self.get_dquot(id, qtype);
        entry.blocks_limit_soft = limits.blocks_soft;
        entry.blocks_limit_hard = limits.blocks_hard;
        entry.inodes_limit_soft = limits.inodes_soft;
        entry.inodes_limit_hard = limits.inodes_hard;
        self.cache.insert(entry, qtype);
    }

    /// Check and charge `blocks` to the quota for (id, qtype).
    ///
    /// Returns [`Error::PermissionDenied`] if the hard limit would be
    /// exceeded, or if the soft limit is exceeded and the grace period
    /// has expired.
    pub fn charge_blocks(
        &mut self,
        id: u32,
        qtype: QuotaV2Type,
        blocks: u64,
        now: u64,
    ) -> Result<QuotaCheckResult> {
        if !self.is_enabled(qtype) {
            return Ok(QuotaCheckResult::Allowed);
        }

        let mut entry = self.get_dquot(id, qtype);
        let new_blocks = entry.blocks_used.saturating_add(blocks);

        // Hard limit check.
        if entry.blocks_limit_hard > 0 && new_blocks > entry.blocks_limit_hard {
            return Err(Error::PermissionDenied);
        }

        let mut result = QuotaCheckResult::Allowed;

        // Soft limit check.
        if entry.blocks_limit_soft > 0 && new_blocks > entry.blocks_limit_soft {
            if entry.grace_expire_blocks == 0 {
                // Start grace period.
                entry.grace_expire_blocks = now.saturating_add(self.grace_period_blocks);
            } else if now >= entry.grace_expire_blocks {
                // Grace period expired — deny.
                return Err(Error::PermissionDenied);
            }
            result = QuotaCheckResult::SoftExceeded;
        }

        entry.blocks_used = new_blocks;
        self.cache.insert(entry, qtype);
        Ok(result)
    }

    /// Check and charge one inode to the quota for (id, qtype).
    pub fn charge_inodes(
        &mut self,
        id: u32,
        qtype: QuotaV2Type,
        count: u64,
        now: u64,
    ) -> Result<QuotaCheckResult> {
        if !self.is_enabled(qtype) {
            return Ok(QuotaCheckResult::Allowed);
        }

        let mut entry = self.get_dquot(id, qtype);
        let new_inodes = entry.inodes_used.saturating_add(count);

        // Hard limit check.
        if entry.inodes_limit_hard > 0 && new_inodes > entry.inodes_limit_hard {
            return Err(Error::PermissionDenied);
        }

        let mut result = QuotaCheckResult::Allowed;

        // Soft limit check.
        if entry.inodes_limit_soft > 0 && new_inodes > entry.inodes_limit_soft {
            if entry.grace_expire_inodes == 0 {
                entry.grace_expire_inodes = now.saturating_add(self.grace_period_inodes);
            } else if now >= entry.grace_expire_inodes {
                return Err(Error::PermissionDenied);
            }
            result = QuotaCheckResult::SoftExceeded;
        }

        entry.inodes_used = new_inodes;
        self.cache.insert(entry, qtype);
        Ok(result)
    }

    /// Release `blocks` from the usage counter for (id, qtype).
    pub fn uncharge_blocks(&mut self, id: u32, qtype: QuotaV2Type, blocks: u64) -> Result<()> {
        if !self.is_enabled(qtype) {
            return Ok(());
        }

        let mut entry = self.get_dquot(id, qtype);
        entry.blocks_used = entry.blocks_used.saturating_sub(blocks);

        // Clear grace if back under soft limit.
        if entry.blocks_limit_soft == 0 || entry.blocks_used <= entry.blocks_limit_soft {
            entry.grace_expire_blocks = 0;
        }

        self.cache.insert(entry, qtype);
        Ok(())
    }

    /// Release inodes from the usage counter for (id, qtype).
    pub fn uncharge_inodes(&mut self, id: u32, qtype: QuotaV2Type, count: u64) -> Result<()> {
        if !self.is_enabled(qtype) {
            return Ok(());
        }

        let mut entry = self.get_dquot(id, qtype);
        entry.inodes_used = entry.inodes_used.saturating_sub(count);

        // Clear grace if back under soft limit.
        if entry.inodes_limit_soft == 0 || entry.inodes_used <= entry.inodes_limit_soft {
            entry.grace_expire_inodes = 0;
        }

        self.cache.insert(entry, qtype);
        Ok(())
    }

    /// Check whether the current usage exceeds any limits without modifying state.
    pub fn check_limits(
        &mut self,
        id: u32,
        qtype: QuotaV2Type,
        now: u64,
    ) -> Result<QuotaCheckResult> {
        if !self.is_enabled(qtype) {
            return Ok(QuotaCheckResult::Allowed);
        }

        let entry = self.get_dquot(id, qtype);

        // Hard limit check.
        if entry.blocks_limit_hard > 0 && entry.blocks_used > entry.blocks_limit_hard {
            return Err(Error::PermissionDenied);
        }
        if entry.inodes_limit_hard > 0 && entry.inodes_used > entry.inodes_limit_hard {
            return Err(Error::PermissionDenied);
        }

        // Soft limit check with grace period.
        let blocks_over =
            entry.blocks_limit_soft > 0 && entry.blocks_used > entry.blocks_limit_soft;
        let inodes_over =
            entry.inodes_limit_soft > 0 && entry.inodes_used > entry.inodes_limit_soft;

        if blocks_over {
            if entry.grace_expire_blocks > 0 && now >= entry.grace_expire_blocks {
                return Err(Error::PermissionDenied);
            }
            return Ok(QuotaCheckResult::SoftExceeded);
        }
        if inodes_over {
            if entry.grace_expire_inodes > 0 && now >= entry.grace_expire_inodes {
                return Err(Error::PermissionDenied);
            }
            return Ok(QuotaCheckResult::SoftExceeded);
        }

        Ok(QuotaCheckResult::Allowed)
    }

    /// Return the dquot cache statistics.
    pub fn cache_entries(&self) -> usize {
        self.cache.len()
    }
}

impl Default for QuotaV2Controller {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// QuotaV2Registry — global multi-mount quota management
// ---------------------------------------------------------------------------

/// Per-mount quota state tracked by the registry.
struct QuotaMountState {
    /// Whether this slot is in use.
    active: bool,
    /// Controller for this mount.
    controller: QuotaV2Controller,
    /// Mount point name (for identification).
    name: [u8; 64],
    /// Name length.
    name_len: usize,
}

impl QuotaMountState {
    const fn empty() -> Self {
        Self {
            active: false,
            controller: QuotaV2Controller::new(),
            name: [0u8; 64],
            name_len: 0,
        }
    }
}

/// Global registry for quota-enabled mount points.
///
/// Manages up to [`MAX_QUOTA_MOUNTS`] mount points, each with its
/// own [`QuotaV2Controller`]. Provides `quotactl`-style operations.
pub struct QuotaV2Registry {
    /// Per-mount quota state.
    mounts: [QuotaMountState; MAX_QUOTA_MOUNTS],
    /// Number of active mounts.
    count: usize,
}

impl QuotaV2Registry {
    /// Create a new, empty registry.
    pub const fn new() -> Self {
        const EMPTY: QuotaMountState = QuotaMountState::empty();
        Self {
            mounts: [EMPTY; MAX_QUOTA_MOUNTS],
            count: 0,
        }
    }

    /// Enable quotas on a mount point. Returns the mount index.
    pub fn enable(&mut self, name: &[u8], qtype: QuotaV2Type) -> Result<usize> {
        // Check if already registered.
        for (i, m) in self.mounts.iter_mut().enumerate() {
            if m.active && m.name_len == name.len() && &m.name[..m.name_len] == name {
                match qtype {
                    QuotaV2Type::User => m.controller.enable_user_quota(),
                    QuotaV2Type::Group => m.controller.enable_group_quota(),
                }
                return Ok(i);
            }
        }

        // Allocate a new slot.
        if self.count >= MAX_QUOTA_MOUNTS {
            return Err(Error::OutOfMemory);
        }
        let slot_idx = self
            .mounts
            .iter()
            .position(|m| !m.active)
            .ok_or(Error::OutOfMemory)?;

        let slot = &mut self.mounts[slot_idx];
        slot.active = true;
        slot.controller = QuotaV2Controller::new();
        let len = name.len().min(64);
        slot.name[..len].copy_from_slice(&name[..len]);
        slot.name_len = len;

        match qtype {
            QuotaV2Type::User => slot.controller.enable_user_quota(),
            QuotaV2Type::Group => slot.controller.enable_group_quota(),
        }

        self.count += 1;
        Ok(slot_idx)
    }

    /// Disable quotas on a mount point for the given type.
    pub fn disable(&mut self, index: usize, qtype: QuotaV2Type) -> Result<()> {
        if index >= MAX_QUOTA_MOUNTS || !self.mounts[index].active {
            return Err(Error::NotFound);
        }
        let m = &mut self.mounts[index];
        match qtype {
            QuotaV2Type::User => m.controller.disable_user_quota(),
            QuotaV2Type::Group => m.controller.disable_group_quota(),
        }

        // If both user and group are disabled, deactivate the slot.
        if !m.controller.is_enabled(QuotaV2Type::User)
            && !m.controller.is_enabled(QuotaV2Type::Group)
        {
            m.active = false;
            m.name_len = 0;
            self.count -= 1;
        }

        Ok(())
    }

    /// Get a mutable reference to the controller for a mount.
    pub fn controller_mut(&mut self, index: usize) -> Result<&mut QuotaV2Controller> {
        if index >= MAX_QUOTA_MOUNTS || !self.mounts[index].active {
            return Err(Error::NotFound);
        }
        Ok(&mut self.mounts[index].controller)
    }

    /// Get an immutable reference to the controller for a mount.
    pub fn controller(&self, index: usize) -> Result<&QuotaV2Controller> {
        if index >= MAX_QUOTA_MOUNTS || !self.mounts[index].active {
            return Err(Error::NotFound);
        }
        Ok(&self.mounts[index].controller)
    }

    /// Perform a quotactl-style operation.
    ///
    /// Sets limits for a user/group on a specific mount point.
    pub fn quotactl(
        &mut self,
        mount_index: usize,
        id: u32,
        qtype: QuotaV2Type,
        limits: &QuotaV2Limits,
    ) -> Result<()> {
        let ctl = self.controller_mut(mount_index)?;
        ctl.set_limits(id, qtype, limits);
        Ok(())
    }

    /// Number of active quota-enabled mounts.
    pub fn mount_count(&self) -> usize {
        self.count
    }

    /// Check if a mount index is active.
    pub fn is_active(&self, index: usize) -> bool {
        index < MAX_QUOTA_MOUNTS && self.mounts[index].active
    }
}

impl Default for QuotaV2Registry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Little-endian helpers
// ---------------------------------------------------------------------------

/// Read a little-endian u32 from `buf` at `offset`.
fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

/// Read a little-endian u64 from `buf` at `offset`.
fn read_u64(buf: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ])
}

/// Write a little-endian u32 to `buf` at `offset`.
fn write_u32(buf: &mut [u8], offset: usize, val: u32) {
    let bytes = val.to_le_bytes();
    buf[offset..offset + 4].copy_from_slice(&bytes);
}

/// Write a little-endian u64 to `buf` at `offset`.
fn write_u64(buf: &mut [u8], offset: usize, val: u64) {
    let bytes = val.to_le_bytes();
    buf[offset..offset + 8].copy_from_slice(&bytes);
}
