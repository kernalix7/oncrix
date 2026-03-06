// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `process_madvise` — remote memory advice for another process.
//!
//! Implements the Linux `process_madvise(2)` system call (since Linux 5.10),
//! which allows a process to advise the kernel about memory usage patterns
//! in another process's address space, identified via a pidfd.
//!
//! # Syscall signature
//!
//! ```text
//! ssize_t process_madvise(int pidfd, const struct iovec *iovec,
//!                         size_t vlen, int advice, unsigned int flags);
//! ```
//!
//! # Use cases
//!
//! - **Process management daemons** that proactively reclaim memory from
//!   idle processes (e.g. Android LMKD, systemd-oomd).
//! - **Memory tiering** agents that migrate cold pages to slower memory.
//! - **Container managers** that advise on memory for contained processes.
//!
//! # Permission model
//!
//! The caller must have the right to PTRACE_MODE_READ_REALCREDS on the
//! target process, which effectively means:
//! - Same UID, or
//! - `CAP_SYS_PTRACE` capability.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of `IoVec` entries per call (`UIO_MAXIOV`).
const IOV_MAX: usize = 1024;

/// Maximum total byte count for the address ranges.
const MAX_RANGE_BYTES: u64 = 0x7FFF_F000;

/// Page size for alignment checks (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Page-offset mask (low 12 bits).
const PAGE_MASK: u64 = PAGE_SIZE - 1;

/// Maximum number of VMAs that can be affected in a single call.
const MAX_VMA_WALK: usize = 4096;

/// Syscall number for `process_madvise` (x86_64 Linux ABI).
pub const SYS_PROCESS_MADVISE: u64 = 440;

// ---------------------------------------------------------------------------
// MadvBehavior — memory advice values
// ---------------------------------------------------------------------------

/// Memory advice behavior for `process_madvise`.
///
/// These values correspond to Linux `MADV_*` constants. Only a subset of
/// `madvise(2)` behaviors are permitted for `process_madvise`, since
/// the caller is operating on another process's address space.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MadvBehavior {
    /// Mark pages as cold (deprioritize in reclaim).
    ///
    /// The kernel may move cold pages to the inactive list, making them
    /// more likely to be reclaimed under memory pressure.
    Cold = 20,

    /// Reclaim pages (move to swap or discard clean pages).
    ///
    /// Stronger than `Cold`: the kernel actively reclaims the pages.
    PageOut = 21,

    /// Hint that pages will be needed soon (prefetch / readahead).
    ///
    /// The kernel may initiate readahead for the specified range.
    WillNeed = 3,

    /// Pages are no longer needed (may be discarded).
    ///
    /// For private anonymous mappings, the pages are freed. For
    /// file-backed mappings, dirty pages are dropped.
    DontNeed = 4,

    /// Free pages lazily (reclaim when memory pressure occurs).
    ///
    /// Similar to `DontNeed` but the kernel may keep the pages
    /// around until it needs the memory.
    Free = 8,

    /// Enable Kernel Same-page Merging (KSM) for the range.
    ///
    /// The kernel will periodically scan the pages for duplicates
    /// and merge identical pages into a single copy-on-write page.
    Mergeable = 12,

    /// Disable KSM for the range.
    ///
    /// Pages previously merged via KSM are unmerged (each process
    /// gets its own private copy again).
    Unmergeable = 13,

    /// Collapse pages into transparent huge pages.
    ///
    /// Advisory hint that the kernel should attempt to promote the
    /// range to huge pages.
    Collapse = 25,
}

impl MadvBehavior {
    /// Convert a raw `i32` advice value to a `MadvBehavior`, if it is
    /// one of the values permitted for `process_madvise`.
    pub fn from_raw(advice: i32) -> Result<Self> {
        match advice {
            20 => Ok(Self::Cold),
            21 => Ok(Self::PageOut),
            3 => Ok(Self::WillNeed),
            4 => Ok(Self::DontNeed),
            8 => Ok(Self::Free),
            12 => Ok(Self::Mergeable),
            13 => Ok(Self::Unmergeable),
            25 => Ok(Self::Collapse),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Return the raw `i32` value.
    pub const fn as_raw(&self) -> i32 {
        *self as i32
    }

    /// Return `true` if this advice is destructive (may discard data).
    pub const fn is_destructive(&self) -> bool {
        matches!(self, Self::DontNeed | Self::PageOut | Self::Free)
    }

    /// Return `true` if this advice only affects reclaim priority
    /// (non-destructive).
    pub const fn is_reclaim_hint(&self) -> bool {
        matches!(self, Self::Cold | Self::WillNeed)
    }
}

// ---------------------------------------------------------------------------
// IoVec — scatter-gather element (local copy for this module)
// ---------------------------------------------------------------------------

/// A single I/O vector element (`struct iovec`).
///
/// Used here to describe address ranges in the target process's
/// virtual address space.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IoVec {
    /// Base (virtual) address in the target process.
    pub iov_base: u64,
    /// Length of the region in bytes.
    pub iov_len: u64,
}

impl IoVec {
    /// Create a new `IoVec`.
    pub const fn new(base: u64, len: u64) -> Self {
        Self {
            iov_base: base,
            iov_len: len,
        }
    }

    /// Validate the address range.
    ///
    /// - Base must be page-aligned.
    /// - Length must be non-zero and page-aligned.
    /// - `base + len` must not overflow.
    pub fn validate(&self) -> Result<()> {
        if self.iov_len == 0 {
            return Ok(());
        }

        if self.iov_base & PAGE_MASK != 0 {
            return Err(Error::InvalidArgument);
        }

        if self.iov_len & PAGE_MASK != 0 {
            return Err(Error::InvalidArgument);
        }

        if self.iov_base.checked_add(self.iov_len).is_none() {
            return Err(Error::InvalidArgument);
        }

        Ok(())
    }

    /// Return `true` if the region is zero-length.
    pub const fn is_empty(&self) -> bool {
        self.iov_len == 0
    }

    /// Return the number of pages this range covers.
    pub const fn page_count(&self) -> u64 {
        self.iov_len / PAGE_SIZE
    }
}

// ---------------------------------------------------------------------------
// ProcessMadviseArgs — parameter bundle
// ---------------------------------------------------------------------------

/// Arguments for the `process_madvise` system call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessMadviseArgs {
    /// pidfd referencing the target process.
    pub pidfd: i32,
    /// User-space pointer to the iovec array describing address ranges.
    pub iov: u64,
    /// Number of elements in the iovec array.
    pub iovcnt: u64,
    /// Memory advice to apply (`MADV_*`).
    pub advice: i32,
    /// Reserved flags (must be 0).
    pub flags: u32,
}

impl ProcessMadviseArgs {
    /// Validate the argument bundle.
    ///
    /// # Checks
    ///
    /// - `pidfd` is non-negative.
    /// - `iov` pointer is non-null.
    /// - `iovcnt` is in `1..=IOV_MAX`.
    /// - `advice` is one of the permitted `MadvBehavior` values.
    /// - `flags` is zero (no flags are currently defined).
    pub fn validate(&self) -> Result<MadvBehavior> {
        if self.pidfd < 0 {
            return Err(Error::InvalidArgument);
        }

        if self.iov == 0 {
            return Err(Error::InvalidArgument);
        }

        if self.iovcnt == 0 || self.iovcnt > IOV_MAX as u64 {
            return Err(Error::InvalidArgument);
        }

        // flags must be zero (reserved for future use).
        if self.flags != 0 {
            return Err(Error::InvalidArgument);
        }

        let behavior = MadvBehavior::from_raw(self.advice)?;

        Ok(behavior)
    }
}

// ---------------------------------------------------------------------------
// Permission checking
// ---------------------------------------------------------------------------

/// Credentials for permission checking.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessCredentials {
    /// Real UID of the process.
    pub uid: u32,
    /// Effective UID of the process.
    pub euid: u32,
    /// Real GID of the process.
    pub gid: u32,
    /// Effective GID of the process.
    pub egid: u32,
    /// Whether the process holds CAP_SYS_PTRACE.
    pub has_cap_ptrace: bool,
}

/// Check whether the calling process has PTRACE_MODE_READ_REALCREDS
/// permission on the target process.
///
/// The check passes if:
/// - The caller's UID matches the target's real and saved-set UID, **and**
///   the caller's GID matches the target's real and saved-set GID; or
/// - The caller holds `CAP_SYS_PTRACE`.
fn check_ptrace_permission(caller: &ProcessCredentials, target: &ProcessCredentials) -> Result<()> {
    // CAP_SYS_PTRACE bypasses all checks.
    if caller.has_cap_ptrace {
        return Ok(());
    }

    // Same-user check (PTRACE_MODE_READ_REALCREDS).
    if caller.uid == target.uid
        && caller.uid == target.euid
        && caller.gid == target.gid
        && caller.gid == target.egid
    {
        return Ok(());
    }

    Err(Error::PermissionDenied)
}

// ---------------------------------------------------------------------------
// VMA (Virtual Memory Area) stub
// ---------------------------------------------------------------------------

/// A virtual memory area descriptor (stub).
///
/// In a real kernel, this would be a reference into the target process's
/// `mm_struct` VMA tree.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmaInfo {
    /// Start address of the VMA.
    pub start: u64,
    /// End address (exclusive) of the VMA.
    pub end: u64,
    /// VMA protection flags (PROT_READ | PROT_WRITE | ...).
    pub prot: u32,
    /// Whether the VMA is backed by a file (vs anonymous).
    pub is_file_backed: bool,
    /// Whether the VMA is a shared mapping.
    pub is_shared: bool,
    /// Whether the VMA has pages that are locked in memory.
    pub is_mlocked: bool,
}

impl VmaInfo {
    /// Return the length of this VMA.
    pub const fn len(&self) -> u64 {
        self.end - self.start
    }

    /// Return `true` if this VMA is zero-length.
    pub const fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Check whether the given advice is applicable to this VMA.
    ///
    /// Some advice values are only meaningful for certain VMA types:
    /// - `Mergeable` / `Unmergeable` require anonymous private VMAs.
    /// - `Free` is only valid for anonymous private VMAs.
    /// - `Collapse` requires THP-eligible VMAs.
    pub fn is_advice_applicable(&self, advice: MadvBehavior) -> bool {
        match advice {
            MadvBehavior::Mergeable | MadvBehavior::Unmergeable => {
                // KSM only works on anonymous private mappings.
                !self.is_file_backed && !self.is_shared
            }
            MadvBehavior::Free => {
                // MADV_FREE only valid for anonymous private.
                !self.is_file_backed && !self.is_shared
            }
            MadvBehavior::Collapse => {
                // THP collapse requires sufficiently aligned anon VMAs.
                !self.is_file_backed
            }
            MadvBehavior::Cold
            | MadvBehavior::PageOut
            | MadvBehavior::WillNeed
            | MadvBehavior::DontNeed => {
                // These apply to any VMA type.
                true
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Per-VMA advice application stubs
// ---------------------------------------------------------------------------

/// Apply `MADV_COLD` to a VMA range.
///
/// Moves pages to the inactive list so they are reclaimed sooner.
fn apply_cold(_vma: &VmaInfo, _start: u64, _end: u64) -> Result<u64> {
    let pages = (_end - _start) / PAGE_SIZE;
    Ok(pages)
}

/// Apply `MADV_PAGEOUT` to a VMA range.
///
/// Actively reclaims pages (writes dirty pages to swap, discards clean).
fn apply_pageout(_vma: &VmaInfo, _start: u64, _end: u64) -> Result<u64> {
    let pages = (_end - _start) / PAGE_SIZE;
    Ok(pages)
}

/// Apply `MADV_WILLNEED` to a VMA range.
///
/// Initiates readahead for file-backed pages or faults in anonymous pages.
fn apply_willneed(vma: &VmaInfo, _start: u64, _end: u64) -> Result<u64> {
    if vma.is_file_backed {
        // Initiate readahead for file-backed pages.
        let pages = (_end - _start) / PAGE_SIZE;
        Ok(pages)
    } else {
        // For anonymous pages, there's nothing to prefetch.
        Ok(0)
    }
}

/// Apply `MADV_DONTNEED` to a VMA range.
///
/// For private anonymous mappings, the pages are discarded. For shared
/// or file-backed mappings, the pages are invalidated.
fn apply_dontneed(vma: &VmaInfo, _start: u64, _end: u64) -> Result<u64> {
    if vma.is_mlocked {
        // Cannot discard mlocked pages.
        return Err(Error::InvalidArgument);
    }
    let pages = (_end - _start) / PAGE_SIZE;
    Ok(pages)
}

/// Apply `MADV_FREE` to a VMA range.
///
/// Lazily frees pages — they are kept around until the kernel needs
/// memory, at which point they are discarded without writing to swap.
fn apply_free(vma: &VmaInfo, _start: u64, _end: u64) -> Result<u64> {
    if vma.is_file_backed || vma.is_shared {
        return Err(Error::InvalidArgument);
    }
    let pages = (_end - _start) / PAGE_SIZE;
    Ok(pages)
}

/// Apply `MADV_MERGEABLE` to a VMA range.
///
/// Registers the range with KSM for same-page merging.
fn apply_mergeable(vma: &VmaInfo, _start: u64, _end: u64) -> Result<u64> {
    if vma.is_file_backed || vma.is_shared {
        return Err(Error::InvalidArgument);
    }
    let pages = (_end - _start) / PAGE_SIZE;
    Ok(pages)
}

/// Apply `MADV_UNMERGEABLE` to a VMA range.
///
/// Unregisters the range from KSM, breaking any shared pages.
fn apply_unmergeable(vma: &VmaInfo, _start: u64, _end: u64) -> Result<u64> {
    if vma.is_file_backed || vma.is_shared {
        return Err(Error::InvalidArgument);
    }
    let pages = (_end - _start) / PAGE_SIZE;
    Ok(pages)
}

/// Apply `MADV_COLLAPSE` to a VMA range.
///
/// Attempts to collapse small pages into transparent huge pages.
fn apply_collapse(vma: &VmaInfo, _start: u64, _end: u64) -> Result<u64> {
    if vma.is_file_backed {
        return Err(Error::InvalidArgument);
    }
    let pages = (_end - _start) / PAGE_SIZE;
    Ok(pages)
}

/// Dispatch advice application to the appropriate handler.
fn apply_advice(vma: &VmaInfo, start: u64, end: u64, advice: MadvBehavior) -> Result<u64> {
    match advice {
        MadvBehavior::Cold => apply_cold(vma, start, end),
        MadvBehavior::PageOut => apply_pageout(vma, start, end),
        MadvBehavior::WillNeed => apply_willneed(vma, start, end),
        MadvBehavior::DontNeed => apply_dontneed(vma, start, end),
        MadvBehavior::Free => apply_free(vma, start, end),
        MadvBehavior::Mergeable => apply_mergeable(vma, start, end),
        MadvBehavior::Unmergeable => apply_unmergeable(vma, start, end),
        MadvBehavior::Collapse => apply_collapse(vma, start, end),
    }
}

// ---------------------------------------------------------------------------
// Range-to-VMA intersection
// ---------------------------------------------------------------------------

/// Clamp a requested range `[req_start, req_end)` to a VMA's bounds.
///
/// Returns `Some((clamped_start, clamped_end))` if there is any
/// overlap, or `None` if the range does not intersect the VMA.
fn intersect_range(vma: &VmaInfo, req_start: u64, req_end: u64) -> Option<(u64, u64)> {
    let start = if req_start > vma.start {
        req_start
    } else {
        vma.start
    };
    let end = if req_end < vma.end { req_end } else { vma.end };

    if start < end {
        Some((start, end))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Pidfd resolution stub
// ---------------------------------------------------------------------------

/// Information about a process resolved from a pidfd.
#[derive(Debug, Clone, Copy, Default)]
pub struct PidfdInfo {
    /// The PID of the target process.
    pub pid: u64,
    /// Credentials of the target process.
    pub creds: ProcessCredentials,
    /// Whether the target process is still alive.
    pub alive: bool,
    /// Number of VMAs in the target's address space (stub).
    pub vma_count: usize,
}

/// Resolve a pidfd to process information.
///
/// Stub: in a real kernel, this would look up the `struct pid` associated
/// with the pidfd, then get the process's `task_struct`.
fn resolve_pidfd(pidfd: i32) -> Result<PidfdInfo> {
    if pidfd < 0 {
        return Err(Error::InvalidArgument);
    }

    // Stub: return a placeholder process.
    Ok(PidfdInfo {
        pid: pidfd as u64 + 100,
        creds: ProcessCredentials::default(),
        alive: true,
        vma_count: 0,
    })
}

/// Look up VMAs overlapping a given address range in the target process.
///
/// Stub: in a real kernel, this would walk the target's VMA tree
/// (`find_vma` / `vma_iterator`) under `mmap_lock`.
fn find_vmas_in_range(_target: &PidfdInfo, _start: u64, _end: u64) -> Result<(VmaInfo, usize)> {
    // Stub: return a single VMA covering the entire range.
    Ok((
        VmaInfo {
            start: _start,
            end: _end,
            prot: 0x3, // PROT_READ | PROT_WRITE
            is_file_backed: false,
            is_shared: false,
            is_mlocked: false,
        },
        1,
    ))
}

// ---------------------------------------------------------------------------
// Syscall handler
// ---------------------------------------------------------------------------

/// `process_madvise` — apply memory advice to another process's address
/// space.
///
/// Iterates over the iovec array, where each entry describes an address
/// range in the target process's virtual address space. For each range,
/// the specified advice is applied to all overlapping VMAs.
///
/// # Arguments
///
/// - `pidfd`  — pidfd referencing the target process.
/// - `iov`    — User-space pointer to an array of `IoVec` structures
///              describing address ranges in the target process.
/// - `iovcnt` — Number of elements in the `iov` array.
/// - `advice` — Memory advice to apply (`MADV_COLD`, `MADV_PAGEOUT`,
///              `MADV_WILLNEED`, `MADV_DONTNEED`, `MADV_FREE`,
///              `MADV_MERGEABLE`, `MADV_UNMERGEABLE`, `MADV_COLLAPSE`).
/// - `flags`  — Reserved, must be 0.
///
/// # Returns
///
/// Total number of bytes for which advice was successfully applied.
///
/// # Errors
///
/// - `InvalidArgument` — bad pidfd, iovcnt, advice, flags, or
///   misaligned address ranges.
/// - `PermissionDenied` — the caller lacks PTRACE_MODE_READ_REALCREDS
///   permission on the target process.
/// - `NotFound` — the target process no longer exists.
///
/// # Linux conformance
///
/// Follows the Linux 5.10+ `process_madvise(2)` interface. This syscall
/// has no POSIX counterpart.
pub fn do_process_madvise(
    pidfd: i32,
    iov: u64,
    iovcnt: u64,
    advice: i32,
    flags: u32,
) -> Result<u64> {
    // --- argument validation ---

    let args = ProcessMadviseArgs {
        pidfd,
        iov,
        iovcnt,
        advice,
        flags,
    };
    let behavior = args.validate()?;

    // --- resolve pidfd to target process ---

    let target = resolve_pidfd(pidfd)?;

    if !target.alive {
        return Err(Error::NotFound);
    }

    // --- permission check ---

    // Stub: use default credentials for the caller.
    let caller_creds = ProcessCredentials {
        uid: 0,
        euid: 0,
        gid: 0,
        egid: 0,
        has_cap_ptrace: true,
    };

    check_ptrace_permission(&caller_creds, &target.creds)?;

    // --- copy iovec array from user space ---

    let cnt = iovcnt as usize;

    // Validate the iov pointer region.
    let iov_byte_size = (cnt as u64).checked_mul(16).ok_or(Error::InvalidArgument)?;
    if iov.checked_add(iov_byte_size).is_none() {
        return Err(Error::InvalidArgument);
    }

    // --- process each iovec entry ---

    let mut total_advised: u64 = 0;
    let mut total_range_bytes: u64 = 0;
    let mut vma_walk_count: usize = 0;

    let mut vec_idx: usize = 0;
    while vec_idx < cnt {
        // Stub: in a real kernel, we would copy_from_user each IoVec.
        // Here we create a representative entry.
        let entry_addr = match iov.checked_add((vec_idx as u64) * 16) {
            Some(a) => a,
            None => return Err(Error::InvalidArgument),
        };

        // Stub: construct a representative IoVec.
        // In a real kernel, these would be the actual user values.
        let entry = IoVec::new(entry_addr & !PAGE_MASK, PAGE_SIZE);

        // Validate alignment.
        entry.validate()?;

        if entry.is_empty() {
            vec_idx += 1;
            continue;
        }

        // Running total for MAX_RANGE_BYTES check.
        total_range_bytes = total_range_bytes
            .checked_add(entry.iov_len)
            .ok_or(Error::InvalidArgument)?;
        if total_range_bytes > MAX_RANGE_BYTES {
            return Err(Error::InvalidArgument);
        }

        let range_start = entry.iov_base;
        let range_end = entry.iov_base + entry.iov_len;

        // --- walk VMAs overlapping this range ---

        let (vma, _vma_cnt) = find_vmas_in_range(&target, range_start, range_end)?;

        vma_walk_count += 1;
        if vma_walk_count > MAX_VMA_WALK {
            // Too many VMAs touched — bail out with partial result.
            break;
        }

        // Check that the advice is applicable to this VMA type.
        if !vma.is_advice_applicable(behavior) {
            vec_idx += 1;
            continue;
        }

        // Intersect the requested range with the VMA bounds.
        if let Some((clamped_start, clamped_end)) = intersect_range(&vma, range_start, range_end) {
            match apply_advice(&vma, clamped_start, clamped_end, behavior) {
                Ok(pages) => {
                    total_advised = total_advised.saturating_add(pages * PAGE_SIZE);
                }
                Err(_) => {
                    // Skip VMAs where advice cannot be applied.
                }
            }
        }

        vec_idx += 1;
    }

    Ok(total_advised)
}

// ---------------------------------------------------------------------------
// Convenience wrappers
// ---------------------------------------------------------------------------

/// Apply `MADV_COLD` to address ranges in another process.
///
/// Convenience wrapper around [`do_process_madvise`].
pub fn process_madvise_cold(pidfd: i32, iov: u64, iovcnt: u64) -> Result<u64> {
    do_process_madvise(pidfd, iov, iovcnt, MadvBehavior::Cold as i32, 0)
}

/// Apply `MADV_PAGEOUT` to address ranges in another process.
///
/// Convenience wrapper around [`do_process_madvise`].
pub fn process_madvise_pageout(pidfd: i32, iov: u64, iovcnt: u64) -> Result<u64> {
    do_process_madvise(pidfd, iov, iovcnt, MadvBehavior::PageOut as i32, 0)
}

/// Apply `MADV_WILLNEED` to address ranges in another process.
///
/// Convenience wrapper around [`do_process_madvise`].
pub fn process_madvise_willneed(pidfd: i32, iov: u64, iovcnt: u64) -> Result<u64> {
    do_process_madvise(pidfd, iov, iovcnt, MadvBehavior::WillNeed as i32, 0)
}

/// Apply `MADV_DONTNEED` to address ranges in another process.
///
/// Convenience wrapper around [`do_process_madvise`].
pub fn process_madvise_dontneed(pidfd: i32, iov: u64, iovcnt: u64) -> Result<u64> {
    do_process_madvise(pidfd, iov, iovcnt, MadvBehavior::DontNeed as i32, 0)
}

/// Apply `MADV_FREE` to address ranges in another process.
///
/// Convenience wrapper around [`do_process_madvise`].
pub fn process_madvise_free(pidfd: i32, iov: u64, iovcnt: u64) -> Result<u64> {
    do_process_madvise(pidfd, iov, iovcnt, MadvBehavior::Free as i32, 0)
}

/// Apply `MADV_MERGEABLE` (KSM) to address ranges in another process.
///
/// Convenience wrapper around [`do_process_madvise`].
pub fn process_madvise_mergeable(pidfd: i32, iov: u64, iovcnt: u64) -> Result<u64> {
    do_process_madvise(pidfd, iov, iovcnt, MadvBehavior::Mergeable as i32, 0)
}

/// Apply `MADV_UNMERGEABLE` to address ranges in another process.
///
/// Convenience wrapper around [`do_process_madvise`].
pub fn process_madvise_unmergeable(pidfd: i32, iov: u64, iovcnt: u64) -> Result<u64> {
    do_process_madvise(pidfd, iov, iovcnt, MadvBehavior::Unmergeable as i32, 0)
}

/// Apply `MADV_COLLAPSE` to address ranges in another process.
///
/// Convenience wrapper around [`do_process_madvise`].
pub fn process_madvise_collapse(pidfd: i32, iov: u64, iovcnt: u64) -> Result<u64> {
    do_process_madvise(pidfd, iov, iovcnt, MadvBehavior::Collapse as i32, 0)
}
