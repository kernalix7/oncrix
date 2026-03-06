// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended shared memory operations.
//!
//! Augments the base `shm_ipc` module with:
//! - Huge-page backed segments (`SHM_HUGETLB`).
//! - NUMA-aware allocation policies.
//! - Per-segment memory locking (`SHM_LOCK` / `SHM_UNLOCK`).
//! - Extended `shmctl` commands (`IPC_INFO`, `SHM_INFO`, `SHM_STAT`).
//! - Per-user and global memory accounting.
//!
//! # POSIX Reference
//!
//! See `.TheOpenGroup/susv5-html/functions/shmctl.html` for the
//! authoritative `shmctl` specification.  Huge-page and NUMA features
//! are Linux extensions.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of extended SHM segments.
const SHM_EXT_MAX: usize = 64;

/// Maximum number of users tracked in memory accounting.
const SHM_ACCT_MAX_USERS: usize = 32;

/// Maximum number of NUMA nodes supported.
const NUMA_NODES_MAX: usize = 16;

// ---------------------------------------------------------------------------
// ShmHugeFlags — huge page bitflags
// ---------------------------------------------------------------------------

/// Bitflags controlling huge-page backing for a shared memory segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShmHugeFlags(u32);

impl ShmHugeFlags {
    /// No huge pages (use standard 4 KiB pages).
    pub const NONE: Self = Self(0);
    /// Back the segment with huge pages (size selected by kernel).
    pub const SHM_HUGETLB: Self = Self(1 << 11);
    /// Back the segment with 2 MiB huge pages.
    pub const SHM_HUGE_2MB: Self = Self(21 << 26);
    /// Back the segment with 1 GiB huge pages.
    pub const SHM_HUGE_1GB: Self = Self(30 << 26);

    /// Create from a raw `u32`, masking off unknown bits.
    pub const fn from_raw(raw: u32) -> Self {
        const VALID: u32 = (1 << 11) | (21 << 26) | (30 << 26);
        Self(raw & VALID)
    }

    /// Return the raw bit pattern.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Return `true` if any huge-page flag is set.
    pub const fn is_huge(self) -> bool {
        self.0 != 0
    }

    /// Return the huge-page order (0 = 4 KiB, 9 = 2 MiB, 18 = 1 GiB).
    pub const fn huge_order(self) -> u8 {
        if self.0 & Self::SHM_HUGE_1GB.0 != 0 {
            18
        } else if self.0 & Self::SHM_HUGE_2MB.0 != 0 {
            9
        } else if self.0 & Self::SHM_HUGETLB.0 != 0 {
            9 // default huge-page order = 2 MiB
        } else {
            0
        }
    }

    /// Test whether `other` bits are all present.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

// ---------------------------------------------------------------------------
// ShmNumaPolicy — NUMA allocation policy
// ---------------------------------------------------------------------------

/// NUMA memory allocation policy for a shared memory segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShmNumaPolicy {
    /// Use the system default NUMA policy.
    #[default]
    Default,
    /// Bind all allocations to the specified node mask.
    Bind {
        /// Bitmask of allowed NUMA nodes (bit N = node N allowed).
        node_mask: u32,
    },
    /// Interleave allocations round-robin across the node mask.
    Interleave {
        /// Bitmask of nodes to interleave across.
        node_mask: u32,
    },
    /// Prefer the specified node but fall back to others.
    Preferred {
        /// Preferred NUMA node ID.
        node_id: u8,
    },
}

impl ShmNumaPolicy {
    /// Validate the policy fields.
    ///
    /// Returns `InvalidArgument` for out-of-range node IDs or empty masks.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Default => Ok(()),
            Self::Bind { node_mask } | Self::Interleave { node_mask } => {
                if *node_mask == 0 {
                    return Err(Error::InvalidArgument);
                }
                // Ensure the mask only references valid nodes.
                if *node_mask >> NUMA_NODES_MAX != 0 {
                    return Err(Error::InvalidArgument);
                }
                Ok(())
            }
            Self::Preferred { node_id } => {
                if *node_id as usize >= NUMA_NODES_MAX {
                    return Err(Error::InvalidArgument);
                }
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ShmExtSegment — extended segment metadata
// ---------------------------------------------------------------------------

/// Extended per-segment metadata stored alongside the base SHM segment.
pub struct ShmExtSegment {
    /// Segment ID (matches the base `shm_ipc` segment ID).
    pub segment_id: u32,
    /// Segment size in bytes.
    pub size: u64,
    /// Huge-page order (0 = none, 9 = 2 MiB, 18 = 1 GiB).
    pub huge_page_order: u8,
    /// NUMA allocation policy.
    pub numa_policy: ShmNumaPolicy,
    /// Whether the segment's pages are pinned (`SHM_LOCK`).
    pub locked: bool,
    /// Number of active `shmat` attachments.
    pub nattach: u32,
    /// UID of the owner process.
    pub owner_uid: u32,
    /// Huge-page flags used at creation.
    pub huge_flags: ShmHugeFlags,
    /// Whether this slot is occupied.
    active: bool,
}

impl ShmExtSegment {
    /// Create an empty (inactive) segment slot.
    const fn new() -> Self {
        Self {
            segment_id: 0,
            size: 0,
            huge_page_order: 0,
            numa_policy: ShmNumaPolicy::Default,
            locked: false,
            nattach: 0,
            owner_uid: 0,
            huge_flags: ShmHugeFlags::NONE,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// ShmMemoryAccounting
// ---------------------------------------------------------------------------

/// Memory accounting entry for a single user.
#[derive(Debug, Clone, Copy, Default)]
struct UserAcct {
    /// User ID.
    uid: u32,
    /// Total bytes in SHM segments owned by this user.
    bytes: u64,
    /// Whether this slot is in use.
    active: bool,
}

impl UserAcct {
    const fn new() -> Self {
        Self {
            uid: 0,
            bytes: 0,
            active: false,
        }
    }
}

/// System-wide and per-user accounting for shared memory.
pub struct ShmMemoryAccounting {
    /// Total bytes currently allocated in extended segments.
    pub total_shm_bytes: u64,
    /// Total bytes in locked (pinned) segments.
    pub total_locked_bytes: u64,
    /// Per-user accounting table.
    users: [UserAcct; SHM_ACCT_MAX_USERS],
}

impl ShmMemoryAccounting {
    /// Create a zeroed accounting structure.
    pub const fn new() -> Self {
        Self {
            total_shm_bytes: 0,
            total_locked_bytes: 0,
            users: [const { UserAcct::new() }; SHM_ACCT_MAX_USERS],
        }
    }

    /// Charge `bytes` to `uid`.
    ///
    /// Returns `OutOfMemory` if the per-user table is full.
    pub fn charge(&mut self, uid: u32, bytes: u64) -> Result<()> {
        // Try to find an existing entry.
        for user in self.users.iter_mut() {
            if user.active && user.uid == uid {
                user.bytes = user.bytes.saturating_add(bytes);
                self.total_shm_bytes = self.total_shm_bytes.saturating_add(bytes);
                return Ok(());
            }
        }
        // Allocate a new entry.
        for user in self.users.iter_mut() {
            if !user.active {
                user.uid = uid;
                user.bytes = bytes;
                user.active = true;
                self.total_shm_bytes = self.total_shm_bytes.saturating_add(bytes);
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Release `bytes` from `uid`'s accounting.
    pub fn release(&mut self, uid: u32, bytes: u64) {
        for user in self.users.iter_mut() {
            if user.active && user.uid == uid {
                user.bytes = user.bytes.saturating_sub(bytes);
                self.total_shm_bytes = self.total_shm_bytes.saturating_sub(bytes);
                if user.bytes == 0 {
                    user.active = false;
                }
                return;
            }
        }
    }

    /// Add `bytes` to the locked-bytes counter.
    pub fn lock_bytes(&mut self, bytes: u64) {
        self.total_locked_bytes = self.total_locked_bytes.saturating_add(bytes);
    }

    /// Remove `bytes` from the locked-bytes counter.
    pub fn unlock_bytes(&mut self, bytes: u64) {
        self.total_locked_bytes = self.total_locked_bytes.saturating_sub(bytes);
    }

    /// Return the bytes charged to `uid`, or 0 if none.
    pub fn user_bytes(&self, uid: u32) -> u64 {
        for user in self.users.iter() {
            if user.active && user.uid == uid {
                return user.bytes;
            }
        }
        0
    }
}

impl Default for ShmMemoryAccounting {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ShmExtStats
// ---------------------------------------------------------------------------

/// Aggregate statistics for the extended SHM subsystem.
///
/// Returned by `shmctl_ext` with the `SHM_INFO` command.
#[derive(Debug, Clone, Copy, Default)]
pub struct ShmExtStats {
    /// Total number of active extended segments.
    pub total_segments: u32,
    /// Total pages allocated across all segments.
    pub total_pages: u64,
    /// Total pages that are locked (pinned in RAM).
    pub locked_pages: u64,
    /// Total huge pages used.
    pub huge_pages: u64,
}

// ---------------------------------------------------------------------------
// Extended shmctl command codes
// ---------------------------------------------------------------------------

/// `shmctl` command: retrieve IPC-wide limits and usage.
pub const IPC_INFO: i32 = 3;
/// `shmctl` command: retrieve system-wide SHM usage stats.
pub const SHM_INFO: i32 = 14;
/// `shmctl` command: retrieve segment stats by index.
pub const SHM_STAT: i32 = 13;
/// `shmctl` command: lock segment pages into RAM.
pub const SHM_LOCK: i32 = 11;
/// `shmctl` command: unlock segment pages.
pub const SHM_UNLOCK: i32 = 12;

// ---------------------------------------------------------------------------
// ShmExtRegistry
// ---------------------------------------------------------------------------

/// Registry of extended shared memory segments.
///
/// Holds metadata for up to [`SHM_EXT_MAX`] segments.
pub struct ShmExtRegistry {
    segments: [ShmExtSegment; SHM_EXT_MAX],
    /// Number of active segments.
    count: usize,
    /// Global memory accounting.
    pub accounting: ShmMemoryAccounting,
}

impl ShmExtRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            segments: [const { ShmExtSegment::new() }; SHM_EXT_MAX],
            count: 0,
            accounting: ShmMemoryAccounting::new(),
        }
    }

    /// Return the number of active segments.
    pub const fn count(&self) -> usize {
        self.count
    }

    // -- Internal helpers --------------------------------------------------

    /// Find a free slot.
    fn find_free(&self) -> Option<usize> {
        self.segments.iter().position(|s| !s.active)
    }

    /// Find an active segment by ID.
    fn find_by_id(&self, segment_id: u32) -> Option<usize> {
        self.segments
            .iter()
            .position(|s| s.active && s.segment_id == segment_id)
    }

    /// Return a shared reference to a segment.
    fn get_seg(&self, segment_id: u32) -> Result<&ShmExtSegment> {
        let idx = self.find_by_id(segment_id).ok_or(Error::NotFound)?;
        Ok(&self.segments[idx])
    }

    /// Return a mutable reference to a segment.
    fn get_seg_mut(&mut self, segment_id: u32) -> Result<&mut ShmExtSegment> {
        let idx = self.find_by_id(segment_id).ok_or(Error::NotFound)?;
        Ok(&mut self.segments[idx])
    }

    /// Collect aggregate statistics.
    fn collect_stats(&self) -> ShmExtStats {
        let mut stats = ShmExtStats::default();
        for seg in self.segments.iter() {
            if !seg.active {
                continue;
            }
            stats.total_segments += 1;
            let page_size: u64 = if seg.huge_page_order > 0 {
                1u64 << (seg.huge_page_order as u64 + 12)
            } else {
                4096
            };
            let pages = seg.size.div_ceil(page_size);
            stats.total_pages += pages;
            if seg.locked {
                stats.locked_pages += pages;
            }
            if seg.huge_page_order > 0 {
                stats.huge_pages += pages;
            }
        }
        stats
    }
}

impl Default for ShmExtRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create an extended SHM segment with huge-page and NUMA options.
///
/// `segment_id` is the ID already assigned by the base `shm_ipc` layer.
/// `huge_flags` and `numa_policy` add the extended features.
///
/// Returns `OutOfMemory` if the registry is full.
/// Returns `InvalidArgument` for inconsistent huge-page/NUMA settings.
pub fn shmget_ext(
    registry: &mut ShmExtRegistry,
    segment_id: u32,
    size: u64,
    owner_uid: u32,
    huge_flags: ShmHugeFlags,
    numa_policy: ShmNumaPolicy,
) -> Result<()> {
    if size == 0 {
        return Err(Error::InvalidArgument);
    }

    numa_policy.validate()?;

    // Verify no duplicate ID.
    if registry.find_by_id(segment_id).is_some() {
        return Err(Error::AlreadyExists);
    }

    let idx = registry.find_free().ok_or(Error::OutOfMemory)?;

    // Charge memory to the owner.
    registry.accounting.charge(owner_uid, size)?;

    registry.segments[idx].segment_id = segment_id;
    registry.segments[idx].size = size;
    registry.segments[idx].huge_page_order = huge_flags.huge_order();
    registry.segments[idx].numa_policy = numa_policy;
    registry.segments[idx].locked = false;
    registry.segments[idx].nattach = 0;
    registry.segments[idx].owner_uid = owner_uid;
    registry.segments[idx].huge_flags = huge_flags;
    registry.segments[idx].active = true;
    registry.count += 1;

    Ok(())
}

/// Remove an extended SHM segment entry.
///
/// Called from the base `shmctl(IPC_RMID)` path after the segment's
/// attach count reaches zero.
pub fn shmext_remove(registry: &mut ShmExtRegistry, segment_id: u32) -> Result<()> {
    let idx = registry.find_by_id(segment_id).ok_or(Error::NotFound)?;

    let seg = &registry.segments[idx];
    let uid = seg.owner_uid;
    let size = seg.size;
    let was_locked = seg.locked;

    if was_locked {
        registry.accounting.unlock_bytes(size);
    }
    registry.accounting.release(uid, size);

    registry.segments[idx].active = false;
    registry.count = registry.count.saturating_sub(1);
    Ok(())
}

/// Lock segment pages into RAM (`SHM_LOCK`).
///
/// Requires `is_privileged` or that the caller is the segment owner.
pub fn shm_lock(
    registry: &mut ShmExtRegistry,
    segment_id: u32,
    caller_uid: u32,
    is_privileged: bool,
) -> Result<()> {
    let seg = registry.get_seg_mut(segment_id)?;

    if !is_privileged && seg.owner_uid != caller_uid {
        return Err(Error::PermissionDenied);
    }

    if seg.locked {
        return Ok(()); // Already locked; idempotent.
    }

    let size = seg.size;
    seg.locked = true;
    registry.accounting.lock_bytes(size);
    Ok(())
}

/// Unlock segment pages (`SHM_UNLOCK`).
///
/// Requires `is_privileged` or that the caller is the segment owner.
pub fn shm_unlock(
    registry: &mut ShmExtRegistry,
    segment_id: u32,
    caller_uid: u32,
    is_privileged: bool,
) -> Result<()> {
    let seg = registry.get_seg_mut(segment_id)?;

    if !is_privileged && seg.owner_uid != caller_uid {
        return Err(Error::PermissionDenied);
    }

    if !seg.locked {
        return Ok(()); // Already unlocked; idempotent.
    }

    let size = seg.size;
    seg.locked = false;
    registry.accounting.unlock_bytes(size);
    Ok(())
}

/// Set the NUMA policy for an existing segment.
///
/// The new policy takes effect for subsequent page fault allocations.
/// Existing pages are not migrated (no MPOL_MF_MOVE behaviour here).
pub fn shm_set_numa_policy(
    registry: &mut ShmExtRegistry,
    segment_id: u32,
    caller_uid: u32,
    is_privileged: bool,
    policy: ShmNumaPolicy,
) -> Result<()> {
    policy.validate()?;

    let seg = registry.get_seg_mut(segment_id)?;

    if !is_privileged && seg.owner_uid != caller_uid {
        return Err(Error::PermissionDenied);
    }

    seg.numa_policy = policy;
    Ok(())
}

/// Record an `shmat` attachment.
pub fn shmext_attach(registry: &mut ShmExtRegistry, segment_id: u32) -> Result<()> {
    let seg = registry.get_seg_mut(segment_id)?;
    seg.nattach = seg.nattach.saturating_add(1);
    Ok(())
}

/// Record an `shmdt` detachment.
pub fn shmext_detach(registry: &mut ShmExtRegistry, segment_id: u32) -> Result<()> {
    let seg = registry.get_seg_mut(segment_id)?;
    seg.nattach = seg.nattach.saturating_sub(1);
    Ok(())
}

// ---------------------------------------------------------------------------
// Extended shmctl
// ---------------------------------------------------------------------------

/// Result variants for `shmctl_ext`.
#[derive(Debug)]
pub enum ShmctlExtResult {
    /// IPC_INFO: system-wide IPC limits (returned as raw bytes; stub).
    IpcInfo {
        /// Maximum shared memory segment size.
        shmmax: u64,
        /// Maximum total shared memory pages.
        shmall: u64,
        /// Maximum segment count.
        shmmni: u32,
    },
    /// SHM_INFO: system-wide SHM usage statistics.
    ShmInfo(ShmExtStats),
    /// SHM_STAT: per-segment statistics.
    ShmStat {
        /// Segment ID.
        segment_id: u32,
        /// Segment size.
        size: u64,
        /// Number of attachments.
        nattach: u32,
        /// Whether pages are locked.
        locked: bool,
        /// Huge-page order.
        huge_page_order: u8,
    },
}

/// Extended `shmctl(2)` supporting `IPC_INFO`, `SHM_INFO`, and `SHM_STAT`.
///
/// # Arguments
///
/// - `registry` — extended segment registry.
/// - `shmid` — segment ID (ignored for `IPC_INFO` and `SHM_INFO`).
/// - `cmd` — one of [`IPC_INFO`], [`SHM_INFO`], [`SHM_STAT`],
///            [`SHM_LOCK`], [`SHM_UNLOCK`].
/// - `caller_uid` — UID of the calling process.
/// - `is_privileged` — set when caller has `CAP_IPC_LOCK`.
///
/// Returns a `ShmctlExtResult` describing the outcome.
pub fn shmctl_ext(
    registry: &mut ShmExtRegistry,
    shmid: u32,
    cmd: i32,
    caller_uid: u32,
    is_privileged: bool,
) -> Result<ShmctlExtResult> {
    match cmd {
        IPC_INFO => {
            // Return system-wide IPC limits (hardcoded defaults).
            Ok(ShmctlExtResult::IpcInfo {
                shmmax: 0x2000_0000,
                shmall: 0x0200_0000,
                shmmni: 4096,
            })
        }

        SHM_INFO => {
            let stats = registry.collect_stats();
            Ok(ShmctlExtResult::ShmInfo(stats))
        }

        SHM_STAT => {
            let seg = registry.get_seg(shmid)?;
            Ok(ShmctlExtResult::ShmStat {
                segment_id: seg.segment_id,
                size: seg.size,
                nattach: seg.nattach,
                locked: seg.locked,
                huge_page_order: seg.huge_page_order,
            })
        }

        SHM_LOCK => {
            shm_lock(registry, shmid, caller_uid, is_privileged)?;
            Ok(ShmctlExtResult::ShmStat {
                segment_id: shmid,
                size: registry.get_seg(shmid)?.size,
                nattach: registry.get_seg(shmid)?.nattach,
                locked: true,
                huge_page_order: registry.get_seg(shmid)?.huge_page_order,
            })
        }

        SHM_UNLOCK => {
            shm_unlock(registry, shmid, caller_uid, is_privileged)?;
            Ok(ShmctlExtResult::ShmStat {
                segment_id: shmid,
                size: registry.get_seg(shmid)?.size,
                nattach: registry.get_seg(shmid)?.nattach,
                locked: false,
                huge_page_order: registry.get_seg(shmid)?.huge_page_order,
            })
        }

        _ => Err(Error::InvalidArgument),
    }
}

/// Return per-user accounting for `uid`.
pub fn shm_user_bytes(registry: &ShmExtRegistry, uid: u32) -> u64 {
    registry.accounting.user_bytes(uid)
}

/// Return global SHM accounting totals.
pub fn shm_global_bytes(registry: &ShmExtRegistry) -> (u64, u64) {
    (
        registry.accounting.total_shm_bytes,
        registry.accounting.total_locked_bytes,
    )
}
