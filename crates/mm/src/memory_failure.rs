// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hardware memory error handling (hwpoison) subsystem.
//!
//! Implements detection, isolation, and recovery for hardware memory
//! errors such as corrected (CE) and uncorrected (UE) ECC failures.
//! When a poisoned page is identified, the handler determines its
//! usage state and takes the appropriate action — from transparent
//! recovery to process termination.
//!
//! Key components:
//! - [`HwpoisonAction`] — outcome of a memory failure recovery attempt
//! - [`PageState`] — describes how a poisoned page was being used
//! - [`MemoryErrorType`] — corrected vs. uncorrected errors
//! - [`PoisonedPage`] — per-page record of a hardware error
//! - [`HwpoisonStats`] — aggregate error and recovery statistics
//! - [`HwpoisonRegistry`] — tracks poisoned page frame numbers
//! - [`MemoryFailureHandler`] — main entry point for failure handling
//!
//! Reference: `.kernelORG/` — `mm/memory-failure.c`.

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Maximum number of poisoned PFNs the registry can track.
const MAX_POISONED_PFNS: usize = 256;

// ── HwpoisonAction ──────────────────────────────────────────────

/// Outcome of a hardware poison recovery attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HwpoisonAction {
    /// Page was successfully recovered (e.g., clean file-backed page
    /// that can be re-read from disk).
    #[default]
    Recovered,
    /// Recovery has been scheduled but not yet completed.
    Delayed,
    /// Recovery failed; affected process must be terminated.
    Failed,
    /// Error was ignored (e.g., free page with no consumers).
    Ignored,
}

// ── PageState ───────────────────────────────────────────────────

/// Describes how a page was being used at the time a hardware error
/// was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PageState {
    /// Page is clean and file-backed (easiest to recover).
    Clean,
    /// Page is dirty (modified data may be lost).
    Dirty,
    /// Page is mapped into one or more user-space address spaces.
    Mapped,
    /// Page belongs to a slab allocator cache.
    Slab,
    /// Page is on an LRU list (reclaimable).
    Lru,
    /// Page is a huge page (2 MiB or 1 GiB).
    HugePage,
    /// Page is free (not allocated).
    Free,
    /// Page state could not be determined.
    #[default]
    Unknown,
}

// ── MemoryErrorType ─────────────────────────────────────────────

/// Classification of a hardware memory error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MemoryErrorType {
    /// Corrected error (CE): ECC hardware fixed the bit flip.
    /// The data is still valid but the DIMM may be degrading.
    #[default]
    Corrected,
    /// Uncorrected error (UE): ECC could not fix the error.
    /// The page data is corrupt.
    Uncorrected,
}

// ── PoisonedPage ────────────────────────────────────────────────

/// Record of a single hardware memory error on a page frame.
#[derive(Debug, Clone, Copy)]
pub struct PoisonedPage {
    /// Page frame number of the affected page.
    pub pfn: u64,
    /// Usage state of the page when the error was detected.
    pub page_state: PageState,
    /// Whether the error was corrected or uncorrected.
    pub error_type: MemoryErrorType,
    /// Timestamp (nanoseconds) when the error was recorded.
    pub timestamp: u64,
    /// Action taken (or attempted) for recovery.
    pub action_taken: HwpoisonAction,
    /// Whether this registry slot is in use.
    active: bool,
}

impl PoisonedPage {
    /// Creates an empty (inactive) poisoned page record.
    const fn empty() -> Self {
        Self {
            pfn: 0,
            page_state: PageState::Unknown,
            error_type: MemoryErrorType::Corrected,
            timestamp: 0,
            action_taken: HwpoisonAction::Ignored,
            active: false,
        }
    }
}

// ── HwpoisonStats ───────────────────────────────────────────────

/// Aggregate hardware poison statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct HwpoisonStats {
    /// Number of corrected (CE) errors recorded.
    pub corrected: u64,
    /// Number of uncorrected (UE) errors recorded.
    pub uncorrected: u64,
    /// Number of pages successfully recovered.
    pub recovered: u64,
    /// Number of pages where recovery failed.
    pub failed: u64,
    /// Number of pages currently isolated (poisoned).
    pub pages_isolated: u64,
}

// ── HwpoisonRegistry ────────────────────────────────────────────

/// Registry of poisoned page frame numbers.
///
/// Maintains a fixed-size array of [`PoisonedPage`] records,
/// supporting add, remove, lookup, and statistics queries.
pub struct HwpoisonRegistry {
    /// Array of poisoned page records.
    entries: [PoisonedPage; MAX_POISONED_PFNS],
    /// Number of active (poisoned) entries.
    count: usize,
    /// Aggregate statistics.
    stats: HwpoisonStats,
}

impl Default for HwpoisonRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl HwpoisonRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            entries: [PoisonedPage::empty(); MAX_POISONED_PFNS],
            count: 0,
            stats: HwpoisonStats {
                corrected: 0,
                uncorrected: 0,
                recovered: 0,
                failed: 0,
                pages_isolated: 0,
            },
        }
    }

    /// Adds a poisoned page to the registry.
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyExists`] — the PFN is already registered.
    /// - [`Error::OutOfMemory`] — the registry is full.
    pub fn add(
        &mut self,
        pfn: u64,
        page_state: PageState,
        error_type: MemoryErrorType,
        timestamp: u64,
        action: HwpoisonAction,
    ) -> Result<()> {
        // Check for duplicate.
        if self.is_poisoned(pfn) {
            return Err(Error::AlreadyExists);
        }

        // Find a free slot.
        let slot = self
            .entries
            .iter_mut()
            .find(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;

        slot.pfn = pfn;
        slot.page_state = page_state;
        slot.error_type = error_type;
        slot.timestamp = timestamp;
        slot.action_taken = action;
        slot.active = true;

        self.count += 1;

        // Update statistics.
        match error_type {
            MemoryErrorType::Corrected => self.stats.corrected += 1,
            MemoryErrorType::Uncorrected => self.stats.uncorrected += 1,
        }
        match action {
            HwpoisonAction::Recovered => self.stats.recovered += 1,
            HwpoisonAction::Failed => self.stats.failed += 1,
            HwpoisonAction::Delayed | HwpoisonAction::Ignored => {}
        }
        self.stats.pages_isolated += 1;

        Ok(())
    }

    /// Removes (unpoisons) a page from the registry.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — the PFN is not registered.
    pub fn remove(&mut self, pfn: u64) -> Result<()> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.active && e.pfn == pfn)
            .ok_or(Error::NotFound)?;

        entry.active = false;
        self.count = self.count.saturating_sub(1);
        self.stats.pages_isolated = self.stats.pages_isolated.saturating_sub(1);

        Ok(())
    }

    /// Returns `true` if the given PFN is currently poisoned.
    pub fn is_poisoned(&self, pfn: u64) -> bool {
        self.entries.iter().any(|e| e.active && e.pfn == pfn)
    }

    /// Returns information about a poisoned page.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — the PFN is not registered.
    pub fn get_info(&self, pfn: u64) -> Result<&PoisonedPage> {
        self.entries
            .iter()
            .find(|e| e.active && e.pfn == pfn)
            .ok_or(Error::NotFound)
    }

    /// Returns aggregate poison statistics.
    pub fn get_stats(&self) -> &HwpoisonStats {
        &self.stats
    }

    /// Returns the number of currently poisoned pages.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no pages are poisoned.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ── MemoryFailureHandler ────────────────────────────────────────

/// Main entry point for handling hardware memory failures.
///
/// Coordinates page isolation, state determination, and recovery
/// actions, recording results in a [`HwpoisonRegistry`].
pub struct MemoryFailureHandler {
    /// Registry of poisoned pages.
    registry: HwpoisonRegistry,
}

impl Default for MemoryFailureHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryFailureHandler {
    /// Creates a new memory failure handler with an empty registry.
    pub const fn new() -> Self {
        Self {
            registry: HwpoisonRegistry::new(),
        }
    }

    /// Handles a memory failure on the given PFN.
    ///
    /// The handler:
    /// 1. Isolates the page (prevents further allocation).
    /// 2. Determines the page's usage state.
    /// 3. Takes the appropriate recovery action based on state and
    ///    error type.
    /// 4. Records the result in the registry.
    ///
    /// # Arguments
    ///
    /// - `pfn` — page frame number of the failed page
    /// - `page_state` — current usage state of the page
    /// - `error_type` — corrected or uncorrected error
    /// - `now_ns` — current timestamp in nanoseconds
    ///
    /// # Returns
    ///
    /// The [`HwpoisonAction`] taken.
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyExists`] — PFN already handled.
    /// - [`Error::OutOfMemory`] — registry is full.
    pub fn handle_failure(
        &mut self,
        pfn: u64,
        page_state: PageState,
        error_type: MemoryErrorType,
        now_ns: u64,
    ) -> Result<HwpoisonAction> {
        if self.registry.is_poisoned(pfn) {
            return Err(Error::AlreadyExists);
        }

        let action = Self::determine_action(page_state, error_type);

        self.registry
            .add(pfn, page_state, error_type, now_ns, action)?;

        Ok(action)
    }

    /// Performs a soft-offline of the given PFN.
    ///
    /// Soft-offline migrates the page's data to a healthy frame and
    /// then isolates the original. This is used for pages with
    /// corrected errors as a preventive measure.
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyExists`] — PFN already poisoned.
    /// - [`Error::OutOfMemory`] — registry is full.
    pub fn soft_offline(&mut self, pfn: u64, now_ns: u64) -> Result<HwpoisonAction> {
        if self.registry.is_poisoned(pfn) {
            return Err(Error::AlreadyExists);
        }

        // Soft-offline always marks as corrected and recovered
        // (the data was migrated successfully in simulation).
        let action = HwpoisonAction::Recovered;
        self.registry.add(
            pfn,
            PageState::Mapped,
            MemoryErrorType::Corrected,
            now_ns,
            action,
        )?;

        Ok(action)
    }

    /// Attempts to recover (unpoison) a previously poisoned page.
    ///
    /// This may be called after a DIMM replacement or when the
    /// firmware reports the error has been resolved.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — PFN is not in the registry.
    pub fn unpoison(&mut self, pfn: u64) -> Result<()> {
        self.registry.remove(pfn)
    }

    /// Returns a reference to the underlying registry.
    pub fn registry(&self) -> &HwpoisonRegistry {
        &self.registry
    }

    /// Returns a mutable reference to the underlying registry.
    pub fn registry_mut(&mut self) -> &mut HwpoisonRegistry {
        &mut self.registry
    }

    /// Determines the recovery action based on page state and error
    /// type.
    fn determine_action(page_state: PageState, error_type: MemoryErrorType) -> HwpoisonAction {
        match (page_state, error_type) {
            // Free pages: simply isolate and ignore.
            (PageState::Free, _) => HwpoisonAction::Ignored,

            // Clean file-backed pages: can be re-read from disk.
            (PageState::Clean, _) => HwpoisonAction::Recovered,

            // LRU reclaimable pages: can be dropped and re-read.
            (PageState::Lru, MemoryErrorType::Corrected) => HwpoisonAction::Recovered,
            (PageState::Lru, MemoryErrorType::Uncorrected) => HwpoisonAction::Delayed,

            // Dirty pages: corrected errors can be flushed; uncorrected
            // means data loss.
            (PageState::Dirty, MemoryErrorType::Corrected) => HwpoisonAction::Recovered,
            (PageState::Dirty, MemoryErrorType::Uncorrected) => HwpoisonAction::Failed,

            // Mapped user pages: corrected can migrate; uncorrected
            // means the process must be killed.
            (PageState::Mapped, MemoryErrorType::Corrected) => HwpoisonAction::Recovered,
            (PageState::Mapped, MemoryErrorType::Uncorrected) => HwpoisonAction::Failed,

            // Slab pages: kernel data structure corruption.
            (PageState::Slab, MemoryErrorType::Corrected) => HwpoisonAction::Delayed,
            (PageState::Slab, MemoryErrorType::Uncorrected) => HwpoisonAction::Failed,

            // Huge pages: complex recovery, defer.
            (PageState::HugePage, MemoryErrorType::Corrected) => HwpoisonAction::Delayed,
            (PageState::HugePage, MemoryErrorType::Uncorrected) => HwpoisonAction::Failed,

            // Unknown state: conservative approach.
            (PageState::Unknown, MemoryErrorType::Corrected) => HwpoisonAction::Delayed,
            (PageState::Unknown, MemoryErrorType::Uncorrected) => HwpoisonAction::Failed,
        }
    }
}
