// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Get User Pages fast path (lockless).
//!
//! Pins user-space pages without taking the mmap lock by walking
//! page tables under a sequence counter. If the page tables change
//! during the walk (sequence mismatch), the fast path fails and the
//! caller falls back to the slow (locked) path.
//!
//! Handles transparent huge pages (THP) at the PMD level and 1 GiB
//! huge pages at the PUD level, returning the correct number of base
//! pages covered.
//!
//! # Key Types
//!
//! - [`FollFlags`] — FOLL_WRITE / FOLL_GET / FOLL_PIN flags
//! - [`GupFastPage`] — a page pinned via the fast path
//! - [`GupFastRequest`] — parameters for a fast-path GUP call
//! - [`GupFastResult`] — outcome of a fast-path attempt
//! - [`GupFastStats`] — cumulative fast/slow path counters
//! - [`GupFastSubsystem`] — top-level manager
//!
//! Reference: Linux `mm/gup.c` (`get_user_pages_fast`,
//! `internal_get_user_pages_fast`, `gup_pte_range`).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// 2 MiB THP / huge page size.
const PAGE_SIZE_2M: u64 = 2 * 1024 * 1024;

/// 1 GiB huge page size.
const PAGE_SIZE_1G: u64 = 1024 * 1024 * 1024;

/// Maximum pages pinned per fast-path request.
const MAX_FAST_PAGES: usize = 256;

/// Maximum concurrent fast-path requests tracked.
const MAX_FAST_REQUESTS: usize = 64;

/// PTE: present.
const PTE_PRESENT: u64 = 1 << 0;
/// PTE: writable.
const PTE_WRITABLE: u64 = 1 << 1;
/// PTE: huge page.
const PTE_HUGE: u64 = 1 << 7;

/// Mask for physical address extraction.
const PHYS_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// -------------------------------------------------------------------
// FollFlags
// -------------------------------------------------------------------

/// FOLL_* flags controlling fast-path GUP behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FollFlags(u32);

impl FollFlags {
    /// Pin for writing; marks pages dirty on unpin.
    pub const WRITE: Self = Self(1 << 0);
    /// Plain page-reference semantics (get_user_pages).
    pub const GET: Self = Self(1 << 1);
    /// Elevated pin-count semantics (pin_user_pages).
    pub const PIN: Self = Self(1 << 2);
    /// Long-term pin; rejects movable-zone pages.
    pub const LONGTERM: Self = Self(1 << 3);
    /// Allow fast-path through THP.
    pub const ALLOW_THP: Self = Self(1 << 4);

    /// Empty flag set.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Combine two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Check whether specific bits are set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

// -------------------------------------------------------------------
// GupFastPage
// -------------------------------------------------------------------

/// A single page pinned via the fast path.
#[derive(Debug, Clone, Copy)]
pub struct GupFastPage {
    /// Physical address of the pinned page.
    pub phys_addr: u64,
    /// User virtual address.
    pub virt_addr: u64,
    /// Effective page size (4K / 2M / 1G).
    pub page_size: u64,
    /// Pin reference count.
    pin_count: u32,
    /// Flags used to pin.
    flags: FollFlags,
    /// Whether this slot is active.
    active: bool,
}

impl GupFastPage {
    /// Create an empty, inactive page descriptor.
    const fn empty() -> Self {
        Self {
            phys_addr: 0,
            virt_addr: 0,
            page_size: 0,
            pin_count: 0,
            flags: FollFlags::empty(),
            active: false,
        }
    }

    /// Pin reference count.
    pub const fn pin_count(&self) -> u32 {
        self.pin_count
    }

    /// Flags used for pinning.
    pub const fn flags(&self) -> FollFlags {
        self.flags
    }

    /// Whether this slot is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }
}

impl Default for GupFastPage {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// GupFastRequest
// -------------------------------------------------------------------

/// Parameters for a fast-path GUP call.
#[derive(Debug, Clone, Copy)]
pub struct GupFastRequest {
    /// ID of the address space (mm_struct equivalent).
    pub mm_id: u64,
    /// Starting user virtual address.
    pub start_vaddr: u64,
    /// Number of pages to pin.
    pub nr_pages: usize,
    /// FOLL flags.
    pub flags: FollFlags,
    /// Sequence counter snapshot taken before the walk.
    pub seq_before: u64,
}

// -------------------------------------------------------------------
// GupFastResult
// -------------------------------------------------------------------

/// Outcome of a fast-path GUP attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GupFastOutcome {
    /// All requested pages were pinned via the fast path.
    Success,
    /// Sequence counter changed; must retry via the slow path.
    SeqRetry,
    /// A non-present PTE was encountered.
    FaultNeeded,
    /// Write requested but PTE is read-only.
    WriteProtect,
    /// The request exceeded capacity.
    Overflow,
}

/// Result of a completed fast-path GUP attempt.
pub struct GupFastResult {
    /// Request identifier.
    pub request_id: u32,
    /// Outcome.
    pub outcome: GupFastOutcome,
    /// Pages successfully pinned (may be partial on retry).
    pages: [GupFastPage; MAX_FAST_PAGES],
    /// Number of pages actually pinned.
    pinned: usize,
    /// Whether this result slot is active.
    active: bool,
}

impl GupFastResult {
    /// Create an empty, inactive result.
    const fn empty() -> Self {
        Self {
            request_id: 0,
            outcome: GupFastOutcome::Success,
            pages: [GupFastPage::empty(); MAX_FAST_PAGES],
            pinned: 0,
            active: false,
        }
    }

    /// Number of pages pinned.
    pub const fn pinned(&self) -> usize {
        self.pinned
    }

    /// Whether this result is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Read-only access to pinned pages.
    pub fn pages(&self) -> &[GupFastPage] {
        &self.pages[..self.pinned]
    }
}

// -------------------------------------------------------------------
// GupFastStats
// -------------------------------------------------------------------

/// Cumulative fast-path GUP statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct GupFastStats {
    /// Total fast-path attempts.
    pub fast_attempts: u64,
    /// Successful fast-path completions.
    pub fast_success: u64,
    /// Falls back due to sequence mismatch.
    pub seq_retries: u64,
    /// Falls back due to non-present PTE.
    pub fault_fallbacks: u64,
    /// Falls back due to write-protect.
    pub wp_fallbacks: u64,
    /// Total pages pinned via fast path.
    pub pages_pinned_fast: u64,
    /// Total pages unpinned.
    pub pages_unpinned: u64,
    /// THP pages encountered.
    pub thp_encountered: u64,
    /// 1 GiB huge pages encountered.
    pub huge_1g_encountered: u64,
}

// -------------------------------------------------------------------
// GupFastSubsystem
// -------------------------------------------------------------------

/// Top-level manager for fast-path GUP operations.
pub struct GupFastSubsystem {
    /// Tracked fast-path results.
    results: [GupFastResult; MAX_FAST_REQUESTS],
    /// Next request identifier.
    next_id: u32,
    /// Current sequence counter (simulated mmap lock).
    seq_counter: u64,
    /// Cumulative statistics.
    stats: GupFastStats,
}

impl Default for GupFastSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl GupFastSubsystem {
    /// Create a new fast-path GUP subsystem.
    pub const fn new() -> Self {
        Self {
            results: [const { GupFastResult::empty() }; MAX_FAST_REQUESTS],
            next_id: 1,
            seq_counter: 0,
            stats: GupFastStats {
                fast_attempts: 0,
                fast_success: 0,
                seq_retries: 0,
                fault_fallbacks: 0,
                wp_fallbacks: 0,
                pages_pinned_fast: 0,
                pages_unpinned: 0,
                thp_encountered: 0,
                huge_1g_encountered: 0,
            },
        }
    }

    /// Snapshot the current sequence counter before a walk.
    pub const fn seq_snapshot(&self) -> u64 {
        self.seq_counter
    }

    /// Bump the sequence counter (e.g. after mmap change).
    pub fn bump_seq(&mut self) {
        self.seq_counter = self.seq_counter.wrapping_add(1);
    }

    /// Current statistics.
    pub const fn stats(&self) -> &GupFastStats {
        &self.stats
    }

    /// Attempt a fast-path GUP. `ptes` is a slice of raw PTE
    /// values for the requested virtual range (one per page).
    ///
    /// Returns the request ID on success, or signals a fallback
    /// reason via [`GupFastOutcome`].
    pub fn get_user_pages_fast(&mut self, request: &GupFastRequest, ptes: &[u64]) -> Result<u32> {
        self.stats.fast_attempts += 1;

        if request.nr_pages > MAX_FAST_PAGES || ptes.len() < request.nr_pages {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .results
            .iter()
            .position(|r| !r.active)
            .ok_or(Error::OutOfMemory)?;

        let req_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let result = &mut self.results[slot];
        *result = GupFastResult::empty();
        result.request_id = req_id;
        result.active = true;

        // Walk PTEs under the sequence counter snapshot.
        let mut idx = 0;
        while idx < request.nr_pages {
            // Sequence check.
            if request.seq_before != self.seq_counter {
                result.outcome = GupFastOutcome::SeqRetry;
                self.stats.seq_retries += 1;
                return Ok(req_id);
            }

            let raw = ptes[idx];

            // Not present -> fault needed.
            if raw & PTE_PRESENT == 0 {
                result.outcome = GupFastOutcome::FaultNeeded;
                self.stats.fault_fallbacks += 1;
                return Ok(req_id);
            }

            // Write requested but PTE is read-only.
            if request.flags.contains(FollFlags::WRITE) && (raw & PTE_WRITABLE == 0) {
                result.outcome = GupFastOutcome::WriteProtect;
                self.stats.wp_fallbacks += 1;
                return Ok(req_id);
            }

            let is_huge = raw & PTE_HUGE != 0;
            let phys = raw & PHYS_ADDR_MASK;
            let vaddr = request.start_vaddr + (idx as u64) * PAGE_SIZE;

            let (page_size, pages_covered) = if is_huge {
                // Detect 1G vs 2M by alignment.
                if phys % PAGE_SIZE_1G == 0 && vaddr % PAGE_SIZE_1G == 0 {
                    self.stats.huge_1g_encountered += 1;
                    (PAGE_SIZE_1G, (PAGE_SIZE_1G / PAGE_SIZE) as usize)
                } else {
                    self.stats.thp_encountered += 1;
                    (PAGE_SIZE_2M, (PAGE_SIZE_2M / PAGE_SIZE) as usize)
                }
            } else {
                (PAGE_SIZE, 1)
            };

            if result.pinned >= MAX_FAST_PAGES {
                result.outcome = GupFastOutcome::Overflow;
                return Ok(req_id);
            }

            result.pages[result.pinned] = GupFastPage {
                phys_addr: phys,
                virt_addr: vaddr,
                page_size,
                pin_count: 1,
                flags: request.flags,
                active: true,
            };
            result.pinned += 1;
            idx += pages_covered;
        }

        result.outcome = GupFastOutcome::Success;
        self.stats.fast_success += 1;
        self.stats.pages_pinned_fast += result.pinned as u64;
        Ok(req_id)
    }

    /// Retrieve the result for a given request.
    pub fn get_result(&self, request_id: u32) -> Result<&GupFastResult> {
        self.results
            .iter()
            .find(|r| r.active && r.request_id == request_id)
            .ok_or(Error::NotFound)
    }

    /// Unpin all pages in a request and release the result slot.
    pub fn unpin_pages(&mut self, request_id: u32) -> Result<usize> {
        let pos = self
            .results
            .iter()
            .position(|r| r.active && r.request_id == request_id)
            .ok_or(Error::NotFound)?;

        let count = self.results[pos].pinned;
        self.stats.pages_unpinned += count as u64;

        let result = &mut self.results[pos];
        result.active = false;
        result.pinned = 0;
        Ok(count)
    }

    /// Number of active request slots.
    pub fn active_requests(&self) -> usize {
        self.results.iter().filter(|r| r.active).count()
    }
}
