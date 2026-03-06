// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory advisory (`madvise` / `process_madvise`).
//!
//! Implements the `madvise(2)` and `process_madvise(2)` system calls
//! that allow processes to advise the kernel about expected memory
//! access patterns. The kernel uses these hints to optimise
//! page-fault behaviour, readahead policy, reclaim priority, and
//! transparent huge page (THP) decisions.
//!
//! # Supported advice values
//!
//! | Category          | Advice                          | Effect |
//! |-------------------|---------------------------------|--------|
//! | Access pattern    | `NORMAL`, `RANDOM`, `SEQUENTIAL`| readahead tuning |
//! | Population        | `WILLNEED`, `DONTNEED`, `FREE` | page-in / reclaim |
//! | Fork inheritance  | `DONTFORK`, `DOFORK`           | VMA flags |
//! | KSM               | `MERGEABLE`, `UNMERGEABLE`     | dedup hints |
//! | THP               | `HUGEPAGE`, `NOHUGEPAGE`       | THP policy |
//! | Reclaim           | `COLD`, `PAGEOUT`              | LRU priority |
//! | Lifecycle         | `REMOVE`                       | discard pages |
//! | Populate          | `POPULATE_READ`, `POPULATE_WRITE` | pre-fault |
//! | Poison            | `HWPOISON`, `SOFT_OFFLINE`     | error injection |
//!
//! # `process_madvise`
//!
//! Linux 5.10+ extension that applies advice to another process
//! identified by `pidfd`. Requires `CAP_SYS_PTRACE` or equivalent
//! permission for cross-process operation.
//!
//! # Key types
//!
//! - [`MadviseAdvice`] — enum of all supported advice values
//! - [`AdviceCategory`] — classification of advice effects
//! - [`VmaRange`] — a virtual memory range with associated advice
//! - [`MadviseStats`] — aggregate statistics
//! - [`MadviseManager`] — the madvise state machine
//!
//! # POSIX / Linux reference
//!
//! - `madvise(2)`, `posix_madvise(3)` — POSIX.1-2024
//! - `process_madvise(2)` — Linux 5.10+
//!
//! Reference: Linux `mm/madvise.c`, `include/uapi/asm-generic/mman.h`.

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────

/// Standard page size in bytes.
const PAGE_SIZE: u64 = 4096;

/// Page alignment mask.
const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

/// Maximum tracked VMA ranges per manager.
const MAX_RANGES: usize = 256;

/// Maximum tracked processes for `process_madvise`.
const MAX_PROCESSES: usize = 64;

/// Maximum number of iovec entries for `process_madvise`.
const MAX_IOVEC: usize = 64;

// ── Raw advice constants ──────────────────────────────────────────

/// No special treatment — default readahead heuristics.
pub const MADV_NORMAL: i32 = 0;
/// Expect random page references — disable readahead.
pub const MADV_RANDOM: i32 = 1;
/// Expect sequential page references — aggressive readahead.
pub const MADV_SEQUENTIAL: i32 = 2;
/// Pages will be needed soon — initiate readahead.
pub const MADV_WILLNEED: i32 = 3;
/// Pages are not needed — may be freed immediately.
pub const MADV_DONTNEED: i32 = 4;
/// Pages may be lazily freed when memory pressure occurs.
pub const MADV_FREE: i32 = 8;
/// Remove the pages entirely (shared/tmpfs mappings).
pub const MADV_REMOVE: i32 = 9;
/// Do not inherit this range across `fork`.
pub const MADV_DONTFORK: i32 = 10;
/// Undo `MADV_DONTFORK` — inherit across `fork`.
pub const MADV_DOFORK: i32 = 11;
/// Mark pages as candidates for Kernel Same-page Merging.
pub const MADV_MERGEABLE: i32 = 12;
/// Undo `MADV_MERGEABLE`.
pub const MADV_UNMERGEABLE: i32 = 13;
/// Enable Transparent Huge Pages for this range.
pub const MADV_HUGEPAGE: i32 = 14;
/// Disable Transparent Huge Pages for this range.
pub const MADV_NOHUGEPAGE: i32 = 15;
/// Mark the range as not worth dumping via core dump.
pub const MADV_DONTDUMP: i32 = 16;
/// Undo `MADV_DONTDUMP` — include in core dumps.
pub const MADV_DODUMP: i32 = 17;
/// Hint that pages are "cold" and less likely to be accessed.
pub const MADV_COLD: i32 = 20;
/// Hint that pages should be reclaimed (paged out) soon.
pub const MADV_PAGEOUT: i32 = 21;
/// Pre-fault readable pages into memory.
pub const MADV_POPULATE_READ: i32 = 22;
/// Pre-fault writable pages into memory.
pub const MADV_POPULATE_WRITE: i32 = 23;
/// Simulate hardware memory corruption (testing).
pub const MADV_HWPOISON: i32 = 100;
/// Simulate soft memory offline (testing).
pub const MADV_SOFT_OFFLINE: i32 = 101;

// ── MadviseAdvice ─────────────────────────────────────────────────

/// Parsed and validated `madvise` advice value.
///
/// Each variant maps 1-to-1 to a `MADV_*` constant. Use
/// [`MadviseAdvice::from_raw`] to construct from a user-supplied
/// integer after validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MadviseAdvice {
    /// No special treatment (default).
    Normal,
    /// Expect random access — disable readahead.
    Random,
    /// Expect sequential access — aggressive readahead.
    Sequential,
    /// Pages will be needed soon — readahead / page-in.
    WillNeed,
    /// Pages are not needed — free immediately.
    DontNeed,
    /// Pages may be lazily freed under memory pressure.
    Free,
    /// Remove pages entirely (shared / tmpfs).
    Remove,
    /// Do not inherit across `fork`.
    DontFork,
    /// Inherit across `fork` (undo `DontFork`).
    DoFork,
    /// Enable KSM merging.
    Mergeable,
    /// Disable KSM merging.
    Unmergeable,
    /// Enable transparent huge pages.
    HugePage,
    /// Disable transparent huge pages.
    NoHugePage,
    /// Do not include in core dumps.
    DontDump,
    /// Include in core dumps (undo `DontDump`).
    DoDump,
    /// Mark pages as cold (move to inactive list).
    Cold,
    /// Reclaim pages soon (page out).
    PageOut,
    /// Pre-fault readable pages.
    PopulateRead,
    /// Pre-fault writable pages.
    PopulateWrite,
    /// Simulate hardware memory corruption.
    HwPoison,
    /// Simulate soft memory offline.
    SoftOffline,
}

impl MadviseAdvice {
    /// Parse a raw `advice` integer into a [`MadviseAdvice`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the value does not
    /// correspond to a known `MADV_*` constant.
    pub fn from_raw(raw: i32) -> Result<Self> {
        match raw {
            MADV_NORMAL => Ok(Self::Normal),
            MADV_RANDOM => Ok(Self::Random),
            MADV_SEQUENTIAL => Ok(Self::Sequential),
            MADV_WILLNEED => Ok(Self::WillNeed),
            MADV_DONTNEED => Ok(Self::DontNeed),
            MADV_FREE => Ok(Self::Free),
            MADV_REMOVE => Ok(Self::Remove),
            MADV_DONTFORK => Ok(Self::DontFork),
            MADV_DOFORK => Ok(Self::DoFork),
            MADV_MERGEABLE => Ok(Self::Mergeable),
            MADV_UNMERGEABLE => Ok(Self::Unmergeable),
            MADV_HUGEPAGE => Ok(Self::HugePage),
            MADV_NOHUGEPAGE => Ok(Self::NoHugePage),
            MADV_DONTDUMP => Ok(Self::DontDump),
            MADV_DODUMP => Ok(Self::DoDump),
            MADV_COLD => Ok(Self::Cold),
            MADV_PAGEOUT => Ok(Self::PageOut),
            MADV_POPULATE_READ => Ok(Self::PopulateRead),
            MADV_POPULATE_WRITE => Ok(Self::PopulateWrite),
            MADV_HWPOISON => Ok(Self::HwPoison),
            MADV_SOFT_OFFLINE => Ok(Self::SoftOffline),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Convert back to the raw `MADV_*` integer.
    pub const fn as_raw(self) -> i32 {
        match self {
            Self::Normal => MADV_NORMAL,
            Self::Random => MADV_RANDOM,
            Self::Sequential => MADV_SEQUENTIAL,
            Self::WillNeed => MADV_WILLNEED,
            Self::DontNeed => MADV_DONTNEED,
            Self::Free => MADV_FREE,
            Self::Remove => MADV_REMOVE,
            Self::DontFork => MADV_DONTFORK,
            Self::DoFork => MADV_DOFORK,
            Self::Mergeable => MADV_MERGEABLE,
            Self::Unmergeable => MADV_UNMERGEABLE,
            Self::HugePage => MADV_HUGEPAGE,
            Self::NoHugePage => MADV_NOHUGEPAGE,
            Self::DontDump => MADV_DONTDUMP,
            Self::DoDump => MADV_DODUMP,
            Self::Cold => MADV_COLD,
            Self::PageOut => MADV_PAGEOUT,
            Self::PopulateRead => MADV_POPULATE_READ,
            Self::PopulateWrite => MADV_POPULATE_WRITE,
            Self::HwPoison => MADV_HWPOISON,
            Self::SoftOffline => MADV_SOFT_OFFLINE,
        }
    }

    /// Classify this advice into a high-level category.
    pub const fn category(self) -> AdviceCategory {
        match self {
            Self::Normal | Self::Random | Self::Sequential => AdviceCategory::AccessPattern,
            Self::WillNeed => AdviceCategory::Populate,
            Self::DontNeed | Self::Free => AdviceCategory::Reclaim,
            Self::Remove => AdviceCategory::Lifecycle,
            Self::DontFork | Self::DoFork => AdviceCategory::ForkInheritance,
            Self::Mergeable | Self::Unmergeable => AdviceCategory::Ksm,
            Self::HugePage | Self::NoHugePage => AdviceCategory::Thp,
            Self::DontDump | Self::DoDump => AdviceCategory::CoreDump,
            Self::Cold | Self::PageOut => AdviceCategory::Reclaim,
            Self::PopulateRead | Self::PopulateWrite => AdviceCategory::Populate,
            Self::HwPoison | Self::SoftOffline => AdviceCategory::Poison,
        }
    }

    /// Whether this advice requires `CAP_SYS_ADMIN` or equivalent.
    pub const fn requires_privilege(self) -> bool {
        matches!(self, Self::HwPoison | Self::SoftOffline | Self::Remove)
    }

    /// Whether this advice is destructive (may discard data).
    pub const fn is_destructive(self) -> bool {
        matches!(
            self,
            Self::DontNeed | Self::Free | Self::Remove | Self::HwPoison | Self::SoftOffline
        )
    }
}

impl Default for MadviseAdvice {
    /// Default advice is [`MadviseAdvice::Normal`].
    fn default() -> Self {
        Self::Normal
    }
}

// ── AdviceCategory ────────────────────────────────────────────────

/// High-level classification of madvise advice values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdviceCategory {
    /// Readahead / access pattern hints (NORMAL, RANDOM, SEQUENTIAL).
    AccessPattern,
    /// Page population / readahead (WILLNEED, POPULATE_*).
    Populate,
    /// Reclaim / discard (DONTNEED, FREE, COLD, PAGEOUT).
    Reclaim,
    /// Mapping lifecycle (REMOVE).
    Lifecycle,
    /// Fork inheritance (DONTFORK, DOFORK).
    ForkInheritance,
    /// Kernel Same-page Merging (MERGEABLE, UNMERGEABLE).
    Ksm,
    /// Transparent Huge Pages (HUGEPAGE, NOHUGEPAGE).
    Thp,
    /// Core dump inclusion (DONTDUMP, DODUMP).
    CoreDump,
    /// Error injection / poison (HWPOISON, SOFT_OFFLINE).
    Poison,
}

// ── ReadaheadPolicy ───────────────────────────────────────────────

/// Readahead policy for a VMA range.
///
/// Derived from `MADV_NORMAL`, `MADV_RANDOM`, `MADV_SEQUENTIAL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadaheadPolicy {
    /// Kernel default heuristics (typically 128 KiB window).
    Normal,
    /// Readahead disabled — expect random access.
    Disabled,
    /// Aggressive readahead — expect sequential access.
    Aggressive,
}

impl Default for ReadaheadPolicy {
    fn default() -> Self {
        Self::Normal
    }
}

// ── VmaAdviceFlags ────────────────────────────────────────────────

/// Per-VMA flags derived from `madvise` advice.
///
/// These flags accumulate as advice calls are applied. Boolean
/// flags represent toggle-type advice (e.g. `DONTFORK` /
/// `DOFORK`).
#[derive(Debug, Clone, Copy)]
pub struct VmaAdviceFlags {
    /// Readahead policy.
    pub readahead: ReadaheadPolicy,
    /// Do not inherit across `fork`.
    pub dont_fork: bool,
    /// Enable KSM merging.
    pub mergeable: bool,
    /// Enable transparent huge pages.
    pub thp_enabled: bool,
    /// Disable transparent huge pages.
    pub thp_disabled: bool,
    /// Exclude from core dumps.
    pub dont_dump: bool,
}

impl VmaAdviceFlags {
    /// Default flags — all hints off, normal readahead.
    const fn empty() -> Self {
        Self {
            readahead: ReadaheadPolicy::Normal,
            dont_fork: false,
            mergeable: false,
            thp_enabled: false,
            thp_disabled: false,
            dont_dump: false,
        }
    }
}

impl Default for VmaAdviceFlags {
    fn default() -> Self {
        Self::empty()
    }
}

// ── VmaRange ──────────────────────────────────────────────────────

/// A tracked virtual memory range with associated advice state.
#[derive(Debug, Clone, Copy)]
pub struct VmaRange {
    /// Start virtual address (page-aligned).
    pub start: u64,
    /// Size in bytes (page-aligned, non-zero when active).
    pub size: u64,
    /// Owning process PID.
    pub pid: u64,
    /// Accumulated advice flags.
    pub flags: VmaAdviceFlags,
    /// Number of pages currently resident.
    pub resident_pages: u64,
    /// Number of pages marked as cold.
    pub cold_pages: u64,
    /// Whether this slot is active.
    pub active: bool,
}

impl VmaRange {
    /// Creates an empty, inactive range.
    const fn empty() -> Self {
        Self {
            start: 0,
            size: 0,
            pid: 0,
            flags: VmaAdviceFlags::empty(),
            resident_pages: 0,
            cold_pages: 0,
            active: false,
        }
    }

    /// End address (exclusive).
    pub const fn end(&self) -> u64 {
        self.start.saturating_add(self.size)
    }

    /// Total pages spanned by this range.
    pub const fn total_pages(&self) -> u64 {
        self.size / PAGE_SIZE
    }

    /// Whether an address falls within this range.
    pub const fn contains(&self, addr: u64) -> bool {
        self.active && addr >= self.start && addr < self.end()
    }

    /// Whether this range overlaps `[start, start+size)`.
    pub const fn overlaps(&self, start: u64, size: u64) -> bool {
        if !self.active || size == 0 {
            return false;
        }
        let end = start.saturating_add(size);
        self.start < end && self.end() > start
    }
}

// ── IoVec ─────────────────────────────────────────────────────────

/// Lightweight `iovec` for `process_madvise` scatter-gather.
#[derive(Debug, Clone, Copy)]
pub struct IoVec {
    /// Base address.
    pub base: u64,
    /// Length in bytes.
    pub len: u64,
}

// ── ProcessPermission ─────────────────────────────────────────────

/// Permission record for cross-process madvise.
#[derive(Debug, Clone, Copy)]
struct ProcessPermission {
    /// The process granting the permission.
    pid: u64,
    /// Whether the caller has CAP_SYS_ADMIN.
    has_cap_sys_admin: bool,
    /// Whether this slot is active.
    active: bool,
}

impl ProcessPermission {
    const fn empty() -> Self {
        Self {
            pid: 0,
            has_cap_sys_admin: false,
            active: false,
        }
    }
}

// ── MadviseStats ──────────────────────────────────────────────────

/// Aggregate madvise statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct MadviseStats {
    /// Total `madvise` calls.
    pub madvise_calls: u64,
    /// Total `process_madvise` calls.
    pub process_madvise_calls: u64,
    /// Successful advice applications.
    pub advice_applied: u64,
    /// Failures due to invalid arguments.
    pub invalid_args: u64,
    /// Failures due to missing VMA.
    pub no_vma_found: u64,
    /// Failures due to insufficient privilege.
    pub permission_denied: u64,
    /// Pages marked as cold by `MADV_COLD`.
    pub pages_cold: u64,
    /// Pages reclaimed by `MADV_PAGEOUT`.
    pub pages_paged_out: u64,
    /// Pages freed by `MADV_DONTNEED`.
    pub pages_freed_dontneed: u64,
    /// Pages freed by `MADV_FREE`.
    pub pages_freed_free: u64,
    /// Pages populated by `MADV_WILLNEED` / `POPULATE_*`.
    pub pages_populated: u64,
    /// Pages removed by `MADV_REMOVE`.
    pub pages_removed: u64,
}

// ── MadviseManager ────────────────────────────────────────────────

/// The madvise state machine.
///
/// Manages per-VMA advice state, applies hint-specific behaviour,
/// and provides the `process_madvise` cross-process interface.
pub struct MadviseManager {
    /// Tracked VMA ranges.
    ranges: [VmaRange; MAX_RANGES],
    /// Number of active ranges.
    range_count: usize,
    /// Process permission records for `process_madvise`.
    permissions: [ProcessPermission; MAX_PROCESSES],
    /// Aggregate statistics.
    stats: MadviseStats,
}

impl Default for MadviseManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MadviseManager {
    /// Creates a new, empty madvise manager.
    pub const fn new() -> Self {
        Self {
            ranges: [VmaRange::empty(); MAX_RANGES],
            range_count: 0,
            permissions: [ProcessPermission::empty(); MAX_PROCESSES],
            stats: MadviseStats {
                madvise_calls: 0,
                process_madvise_calls: 0,
                advice_applied: 0,
                invalid_args: 0,
                no_vma_found: 0,
                permission_denied: 0,
                pages_cold: 0,
                pages_paged_out: 0,
                pages_freed_dontneed: 0,
                pages_freed_free: 0,
                pages_populated: 0,
                pages_removed: 0,
            },
        }
    }

    // ── Range management ──────────────────────────────────────────

    /// Register a VMA range for advice tracking.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the range table is full.
    /// Returns [`Error::InvalidArgument`] if addresses are not
    /// page-aligned or size is zero.
    pub fn register_range(&mut self, start: u64, size: u64, pid: u64) -> Result<()> {
        if start & (PAGE_SIZE - 1) != 0 || size == 0 || size & (PAGE_SIZE - 1) != 0 {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .ranges
            .iter_mut()
            .find(|r| !r.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = VmaRange {
            start,
            size,
            pid,
            flags: VmaAdviceFlags::empty(),
            resident_pages: size / PAGE_SIZE,
            cold_pages: 0,
            active: true,
        };
        self.range_count += 1;
        Ok(())
    }

    /// Unregister a VMA range.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching range exists.
    pub fn unregister_range(&mut self, start: u64, pid: u64) -> Result<()> {
        let range = self
            .ranges
            .iter_mut()
            .find(|r| r.active && r.start == start && r.pid == pid)
            .ok_or(Error::NotFound)?;
        range.active = false;
        self.range_count = self.range_count.saturating_sub(1);
        Ok(())
    }

    /// Update the resident page count for a range.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching range exists.
    pub fn update_resident_pages(&mut self, start: u64, pid: u64, resident: u64) -> Result<()> {
        let range = self
            .ranges
            .iter_mut()
            .find(|r| r.active && r.start == start && r.pid == pid)
            .ok_or(Error::NotFound)?;
        range.resident_pages = resident;
        Ok(())
    }

    // ── Permission management ─────────────────────────────────────

    /// Register a process for cross-process madvise permissions.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the permission table is
    /// full.
    /// Returns [`Error::AlreadyExists`] if the PID is already
    /// registered.
    pub fn register_process(&mut self, pid: u64, has_cap_sys_admin: bool) -> Result<()> {
        if self.permissions.iter().any(|p| p.active && p.pid == pid) {
            return Err(Error::AlreadyExists);
        }

        let slot = self
            .permissions
            .iter_mut()
            .find(|p| !p.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = ProcessPermission {
            pid,
            has_cap_sys_admin,
            active: true,
        };
        Ok(())
    }

    /// Unregister a process permission record.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PID is not registered.
    pub fn unregister_process(&mut self, pid: u64) -> Result<()> {
        let slot = self
            .permissions
            .iter_mut()
            .find(|p| p.active && p.pid == pid)
            .ok_or(Error::NotFound)?;
        slot.active = false;
        Ok(())
    }

    // ── madvise ───────────────────────────────────────────────────

    /// Apply advice to a memory range (`madvise(2)`).
    ///
    /// # Arguments
    ///
    /// - `pid` — calling process.
    /// - `addr` — start of the region (must be page-aligned).
    /// - `len` — length in bytes (rounded up to page boundary).
    /// - `advice` — raw `MADV_*` constant.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — bad alignment, zero length,
    ///   or unknown advice.
    /// - [`Error::NotFound`] — no VMA covers the range.
    /// - [`Error::PermissionDenied`] — privileged advice without
    ///   capability.
    pub fn do_madvise(&mut self, pid: u64, addr: u64, len: u64, advice: i32) -> Result<()> {
        self.stats.madvise_calls += 1;

        if addr & (PAGE_SIZE - 1) != 0 || len == 0 {
            self.stats.invalid_args += 1;
            return Err(Error::InvalidArgument);
        }

        let parsed = match MadviseAdvice::from_raw(advice) {
            Ok(a) => a,
            Err(e) => {
                self.stats.invalid_args += 1;
                return Err(e);
            }
        };

        let aligned_len = page_align_up(len);
        self.apply_advice(pid, addr, aligned_len, parsed, pid)
    }

    // ── process_madvise ───────────────────────────────────────────

    /// Apply advice to another process's memory
    /// (`process_madvise(2)`).
    ///
    /// # Arguments
    ///
    /// - `caller_pid` — PID of the calling process.
    /// - `target_pid` — PID of the target process.
    /// - `iovec` — scatter-gather list of address ranges.
    /// - `iovec_count` — number of valid entries in `iovec`.
    /// - `advice` — raw `MADV_*` constant.
    /// - `flags` — reserved, must be zero.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — bad alignment, zero length,
    ///   unknown advice, non-zero flags, or too many iovecs.
    /// - [`Error::NotFound`] — no VMA covers a requested range.
    /// - [`Error::PermissionDenied`] — caller lacks
    ///   `CAP_SYS_PTRACE` or the advice requires privilege.
    pub fn do_process_madvise(
        &mut self,
        caller_pid: u64,
        target_pid: u64,
        iovec: &[IoVec],
        advice: i32,
        flags: u32,
    ) -> Result<()> {
        self.stats.process_madvise_calls += 1;

        // Flags must be zero (reserved).
        if flags != 0 {
            self.stats.invalid_args += 1;
            return Err(Error::InvalidArgument);
        }

        if iovec.is_empty() || iovec.len() > MAX_IOVEC {
            self.stats.invalid_args += 1;
            return Err(Error::InvalidArgument);
        }

        let parsed = match MadviseAdvice::from_raw(advice) {
            Ok(a) => a,
            Err(e) => {
                self.stats.invalid_args += 1;
                return Err(e);
            }
        };

        // Permission check: same process is always OK.
        if caller_pid != target_pid {
            let has_perm = self
                .permissions
                .iter()
                .any(|p| p.active && p.pid == caller_pid && p.has_cap_sys_admin);
            if !has_perm {
                self.stats.permission_denied += 1;
                return Err(Error::PermissionDenied);
            }
        }

        // Privileged advice check.
        if parsed.requires_privilege() {
            let has_admin = self
                .permissions
                .iter()
                .any(|p| p.active && p.pid == caller_pid && p.has_cap_sys_admin);
            if !has_admin {
                self.stats.permission_denied += 1;
                return Err(Error::PermissionDenied);
            }
        }

        // Apply advice to each iovec entry.
        for entry in iovec {
            if entry.base & (PAGE_SIZE - 1) != 0 || entry.len == 0 {
                self.stats.invalid_args += 1;
                return Err(Error::InvalidArgument);
            }
            let aligned_len = page_align_up(entry.len);
            self.apply_advice(target_pid, entry.base, aligned_len, parsed, caller_pid)?;
        }

        Ok(())
    }

    // ── Core advice application ───────────────────────────────────

    /// Apply a parsed advice to all overlapping ranges.
    fn apply_advice(
        &mut self,
        target_pid: u64,
        addr: u64,
        len: u64,
        advice: MadviseAdvice,
        caller_pid: u64,
    ) -> Result<()> {
        // Privilege check for destructive / admin advice.
        if advice.requires_privilege() {
            let has_admin = self
                .permissions
                .iter()
                .any(|p| p.active && p.pid == caller_pid && p.has_cap_sys_admin);
            if !has_admin {
                self.stats.permission_denied += 1;
                return Err(Error::PermissionDenied);
            }
        }

        let mut found_any = false;

        for i in 0..MAX_RANGES {
            if !self.ranges[i].active || self.ranges[i].pid != target_pid {
                continue;
            }
            if !self.ranges[i].overlaps(addr, len) {
                continue;
            }
            found_any = true;

            self.apply_advice_to_range(i, addr, len, advice);
        }

        if !found_any {
            self.stats.no_vma_found += 1;
            return Err(Error::NotFound);
        }

        self.stats.advice_applied += 1;
        Ok(())
    }

    /// Apply advice to a single range by index.
    fn apply_advice_to_range(&mut self, idx: usize, addr: u64, len: u64, advice: MadviseAdvice) {
        let overlap_pages = self.overlap_page_count(idx, addr, len);

        match advice {
            // Access pattern hints.
            MadviseAdvice::Normal => {
                self.ranges[idx].flags.readahead = ReadaheadPolicy::Normal;
            }
            MadviseAdvice::Random => {
                self.ranges[idx].flags.readahead = ReadaheadPolicy::Disabled;
            }
            MadviseAdvice::Sequential => {
                self.ranges[idx].flags.readahead = ReadaheadPolicy::Aggressive;
            }

            // Population / readahead.
            MadviseAdvice::WillNeed => {
                self.ranges[idx].resident_pages = self.ranges[idx]
                    .resident_pages
                    .saturating_add(overlap_pages)
                    .min(self.ranges[idx].total_pages());
                self.stats.pages_populated += overlap_pages;
            }

            // Reclaim / discard.
            MadviseAdvice::DontNeed => {
                let freed = overlap_pages.min(self.ranges[idx].resident_pages);
                self.ranges[idx].resident_pages =
                    self.ranges[idx].resident_pages.saturating_sub(freed);
                self.ranges[idx].cold_pages = self.ranges[idx].cold_pages.saturating_sub(freed);
                self.stats.pages_freed_dontneed += freed;
            }
            MadviseAdvice::Free => {
                let freed = overlap_pages.min(self.ranges[idx].resident_pages);
                self.ranges[idx].resident_pages =
                    self.ranges[idx].resident_pages.saturating_sub(freed);
                self.stats.pages_freed_free += freed;
            }
            MadviseAdvice::Remove => {
                let removed = overlap_pages.min(self.ranges[idx].resident_pages);
                self.ranges[idx].resident_pages =
                    self.ranges[idx].resident_pages.saturating_sub(removed);
                self.ranges[idx].cold_pages = self.ranges[idx].cold_pages.saturating_sub(removed);
                self.stats.pages_removed += removed;
            }

            // Fork inheritance.
            MadviseAdvice::DontFork => {
                self.ranges[idx].flags.dont_fork = true;
            }
            MadviseAdvice::DoFork => {
                self.ranges[idx].flags.dont_fork = false;
            }

            // KSM.
            MadviseAdvice::Mergeable => {
                self.ranges[idx].flags.mergeable = true;
            }
            MadviseAdvice::Unmergeable => {
                self.ranges[idx].flags.mergeable = false;
            }

            // THP.
            MadviseAdvice::HugePage => {
                self.ranges[idx].flags.thp_enabled = true;
                self.ranges[idx].flags.thp_disabled = false;
            }
            MadviseAdvice::NoHugePage => {
                self.ranges[idx].flags.thp_enabled = false;
                self.ranges[idx].flags.thp_disabled = true;
            }

            // Core dump.
            MadviseAdvice::DontDump => {
                self.ranges[idx].flags.dont_dump = true;
            }
            MadviseAdvice::DoDump => {
                self.ranges[idx].flags.dont_dump = false;
            }

            // Reclaim hints.
            MadviseAdvice::Cold => {
                let new_cold = overlap_pages.min(self.ranges[idx].resident_pages);
                self.ranges[idx].cold_pages = self.ranges[idx]
                    .cold_pages
                    .saturating_add(new_cold)
                    .min(self.ranges[idx].resident_pages);
                self.stats.pages_cold += new_cold;
            }
            MadviseAdvice::PageOut => {
                let paged = overlap_pages.min(self.ranges[idx].resident_pages);
                self.ranges[idx].resident_pages =
                    self.ranges[idx].resident_pages.saturating_sub(paged);
                self.ranges[idx].cold_pages = self.ranges[idx].cold_pages.saturating_sub(paged);
                self.stats.pages_paged_out += paged;
            }

            // Populate.
            MadviseAdvice::PopulateRead | MadviseAdvice::PopulateWrite => {
                self.ranges[idx].resident_pages = self.ranges[idx]
                    .resident_pages
                    .saturating_add(overlap_pages)
                    .min(self.ranges[idx].total_pages());
                self.stats.pages_populated += overlap_pages;
            }

            // Poison (testing / error injection).
            MadviseAdvice::HwPoison | MadviseAdvice::SoftOffline => {
                let poisoned = overlap_pages.min(self.ranges[idx].resident_pages);
                self.ranges[idx].resident_pages =
                    self.ranges[idx].resident_pages.saturating_sub(poisoned);
            }
        }
    }

    /// Compute the number of overlapping pages between a range
    /// and the interval `[addr, addr+len)`.
    fn overlap_page_count(&self, idx: usize, addr: u64, len: u64) -> u64 {
        let r = &self.ranges[idx];
        let end = addr.saturating_add(len);
        let overlap_start = if r.start > addr { r.start } else { addr };
        let overlap_end = if r.end() < end { r.end() } else { end };
        if overlap_end > overlap_start {
            (overlap_end - overlap_start) / PAGE_SIZE
        } else {
            0
        }
    }

    // ── Query helpers ─────────────────────────────────────────────

    /// Look up a range by start address and PID.
    pub fn find_range(&self, start: u64, pid: u64) -> Option<&VmaRange> {
        self.ranges
            .iter()
            .find(|r| r.active && r.start == start && r.pid == pid)
    }

    /// Look up all ranges containing a given address.
    pub fn ranges_containing(&self, addr: u64, pid: u64) -> impl Iterator<Item = &VmaRange> {
        self.ranges
            .iter()
            .filter(move |r| r.pid == pid && r.contains(addr))
    }

    /// Iterate over all active ranges for a process.
    pub fn process_ranges(&self, pid: u64) -> impl Iterator<Item = &VmaRange> {
        self.ranges.iter().filter(move |r| r.active && r.pid == pid)
    }

    /// Number of active ranges.
    pub fn range_count(&self) -> usize {
        self.range_count
    }

    /// Aggregate statistics.
    pub fn stats(&self) -> &MadviseStats {
        &self.stats
    }

    /// Total resident pages across all tracked ranges.
    pub fn total_resident_pages(&self) -> u64 {
        self.ranges
            .iter()
            .filter(|r| r.active)
            .map(|r| r.resident_pages)
            .sum()
    }

    /// Total cold pages across all tracked ranges.
    pub fn total_cold_pages(&self) -> u64 {
        self.ranges
            .iter()
            .filter(|r| r.active)
            .map(|r| r.cold_pages)
            .sum()
    }

    /// Count ranges with a specific readahead policy for a process.
    pub fn count_by_readahead(&self, pid: u64, policy: ReadaheadPolicy) -> usize {
        self.ranges
            .iter()
            .filter(|r| r.active && r.pid == pid && r.flags.readahead == policy)
            .count()
    }

    /// Count ranges marked as mergeable (KSM) for a process.
    pub fn count_mergeable(&self, pid: u64) -> usize {
        self.ranges
            .iter()
            .filter(|r| r.active && r.pid == pid && r.flags.mergeable)
            .count()
    }

    /// Count ranges with THP enabled for a process.
    pub fn count_thp_enabled(&self, pid: u64) -> usize {
        self.ranges
            .iter()
            .filter(|r| r.active && r.pid == pid && r.flags.thp_enabled)
            .count()
    }

    /// Count ranges marked as dont-fork for a process.
    pub fn count_dont_fork(&self, pid: u64) -> usize {
        self.ranges
            .iter()
            .filter(|r| r.active && r.pid == pid && r.flags.dont_fork)
            .count()
    }
}

// ── Helpers ───────────────────────────────────────────────────────

/// Align a value up to the next page boundary.
const fn page_align_up(val: u64) -> u64 {
    (val + PAGE_SIZE - 1) & PAGE_MASK
}
