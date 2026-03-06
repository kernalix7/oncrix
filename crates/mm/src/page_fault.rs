// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page fault handler for the ONCRIX memory management subsystem.
//!
//! Dispatches page faults to the appropriate handler based on fault
//! type and VMA permissions. Supports demand paging, copy-on-write,
//! file-backed faults, and anonymous page faults.
//!
//! - [`FaultInfo`] — describes the faulting address and flags
//! - [`FaultResult`] — outcome of handling a page fault
//! - [`FaultFlags`] — bit flags indicating fault characteristics
//! - [`VmaPermissions`] — permission bits for a virtual memory area
//! - [`PageFaultHandler`] — main fault dispatcher with VMA table
//!
//! Reference: `.kernelORG/` — `mm/memory.c`, `arch/x86/mm/fault.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of VMAs tracked by the fault handler.
const MAX_VMAS: usize = 256;

/// Maximum fault retry count before giving up.
const MAX_FAULT_RETRIES: u32 = 3;

/// Stack guard page region size (one page below each stack).
const _STACK_GUARD_SIZE: u64 = PAGE_SIZE;

// -------------------------------------------------------------------
// FaultFlags
// -------------------------------------------------------------------

/// Bit flags describing the nature of a page fault.
pub struct FaultFlags;

impl FaultFlags {
    /// Fault was caused by a write access.
    pub const WRITE: u32 = 1 << 0;
    /// Fault occurred in user mode.
    pub const USER: u32 = 1 << 1;
    /// Fault was caused by an instruction fetch.
    pub const EXEC: u32 = 1 << 2;
    /// Fault was a protection violation (not page-not-present).
    pub const PROT: u32 = 1 << 3;
    /// Fault should be handled with retries allowed.
    pub const ALLOW_RETRY: u32 = 1 << 4;
    /// Fault is being retried after a previous attempt.
    pub const RETRY: u32 = 1 << 5;
    /// Fault involves a huge page mapping.
    pub const HUGE: u32 = 1 << 6;
    /// Fault should not sleep (non-blocking).
    pub const NOSLEEP: u32 = 1 << 7;
}

// -------------------------------------------------------------------
// FaultResult
// -------------------------------------------------------------------

/// Outcome of handling a page fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultResult {
    /// Fault was successfully handled; instruction can be retried.
    Handled,
    /// Out of memory — no physical frames available.
    Oom,
    /// Segmentation fault — no valid mapping or permission denied.
    Segfault,
    /// Fault handling needs to be retried (e.g., lock contention).
    Retry,
    /// Fault involved a CoW page and was resolved by copy.
    CowResolved,
    /// Fault triggered demand allocation of an anonymous page.
    AnonAllocated,
    /// Fault triggered read-in of a file-backed page.
    FileLoaded,
    /// Fault mapped a zero page (demand zero).
    ZeroPage,
}

// -------------------------------------------------------------------
// FaultType
// -------------------------------------------------------------------

/// Classification of a page fault for dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FaultType {
    /// Anonymous page fault (demand zero or swap-in).
    #[default]
    Anonymous,
    /// File-backed page fault (read from backing store).
    FileBacked,
    /// Copy-on-write fault (shared page written).
    CopyOnWrite,
    /// Stack expansion fault (below current stack pointer).
    StackGrow,
    /// Huge page fault (2 MiB or 1 GiB).
    HugePage,
}

// -------------------------------------------------------------------
// VmaPermissions
// -------------------------------------------------------------------

/// Permission flags for a virtual memory area.
pub struct VmaPermissions;

impl VmaPermissions {
    /// Area is readable.
    pub const READ: u32 = 1 << 0;
    /// Area is writable.
    pub const WRITE: u32 = 1 << 1;
    /// Area is executable.
    pub const EXEC: u32 = 1 << 2;
    /// Area is shared (vs. private/CoW).
    pub const SHARED: u32 = 1 << 3;
    /// Area may grow downward (stack).
    pub const GROWSDOWN: u32 = 1 << 4;
    /// Area is backed by a file.
    pub const FILE: u32 = 1 << 5;
    /// Area uses huge pages.
    pub const HUGEPAGE: u32 = 1 << 6;
    /// Area is locked in memory (mlock).
    pub const LOCKED: u32 = 1 << 7;
}

// -------------------------------------------------------------------
// FaultInfo
// -------------------------------------------------------------------

/// Describes a page fault event.
#[derive(Debug, Clone, Copy)]
pub struct FaultInfo {
    /// Faulting virtual address (from CR2 on x86_64).
    pub address: u64,
    /// Fault flags (combination of [`FaultFlags`] bits).
    pub flags: u32,
    /// Instruction pointer at the time of fault.
    pub ip: u64,
    /// Number of times this fault has been retried.
    pub retry_count: u32,
}

impl FaultInfo {
    /// Create a new fault info descriptor.
    pub fn new(address: u64, flags: u32, ip: u64) -> Self {
        Self {
            address,
            flags,
            ip,
            retry_count: 0,
        }
    }

    /// Check if the fault was caused by a write.
    pub fn is_write(&self) -> bool {
        self.flags & FaultFlags::WRITE != 0
    }

    /// Check if the fault occurred in user mode.
    pub fn is_user(&self) -> bool {
        self.flags & FaultFlags::USER != 0
    }

    /// Check if the fault was an instruction fetch.
    pub fn is_exec(&self) -> bool {
        self.flags & FaultFlags::EXEC != 0
    }

    /// Check if the fault was a protection violation.
    pub fn is_protection(&self) -> bool {
        self.flags & FaultFlags::PROT != 0
    }

    /// Get the page-aligned address of the faulting page.
    pub fn page_address(&self) -> u64 {
        self.address & !(PAGE_SIZE - 1)
    }
}

// -------------------------------------------------------------------
// VmaEntry
// -------------------------------------------------------------------

/// A virtual memory area descriptor for fault handling.
#[derive(Debug, Clone, Copy)]
pub struct VmaEntry {
    /// Start address of the VMA (page-aligned).
    pub start: u64,
    /// End address of the VMA (exclusive, page-aligned).
    pub end: u64,
    /// Permission flags (combination of [`VmaPermissions`] bits).
    pub permissions: u32,
    /// Page frame number of the backing store (0 for anon).
    pub backing_pfn: u64,
    /// Offset into the backing file (in pages).
    pub file_offset: u64,
    /// Reference count of pages mapped in this VMA.
    pub mapped_pages: u64,
    /// Whether this VMA is active.
    pub active: bool,
}

impl VmaEntry {
    /// Create a new empty VMA entry.
    pub const fn empty() -> Self {
        Self {
            start: 0,
            end: 0,
            permissions: 0,
            backing_pfn: 0,
            file_offset: 0,
            mapped_pages: 0,
            active: false,
        }
    }

    /// Check if an address falls within this VMA.
    pub fn contains(&self, addr: u64) -> bool {
        self.active && addr >= self.start && addr < self.end
    }

    /// Check if the VMA is file-backed.
    pub fn is_file_backed(&self) -> bool {
        self.permissions & VmaPermissions::FILE != 0
    }

    /// Check if the VMA is shared.
    pub fn is_shared(&self) -> bool {
        self.permissions & VmaPermissions::SHARED != 0
    }

    /// Check if the VMA is a stack (grows down).
    pub fn is_stack(&self) -> bool {
        self.permissions & VmaPermissions::GROWSDOWN != 0
    }

    /// Check if the VMA uses huge pages.
    pub fn is_hugepage(&self) -> bool {
        self.permissions & VmaPermissions::HUGEPAGE != 0
    }

    /// Size of the VMA in bytes.
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

// -------------------------------------------------------------------
// FaultStatistics
// -------------------------------------------------------------------

/// Statistics about page fault handling.
#[derive(Debug, Clone, Copy, Default)]
pub struct FaultStatistics {
    /// Total number of page faults handled.
    pub total_faults: u64,
    /// Number of minor faults (page already in memory).
    pub minor_faults: u64,
    /// Number of major faults (required I/O).
    pub major_faults: u64,
    /// Number of CoW faults resolved.
    pub cow_faults: u64,
    /// Number of anonymous page allocations.
    pub anon_allocs: u64,
    /// Number of file page loads.
    pub file_loads: u64,
    /// Number of segfaults delivered.
    pub segfaults: u64,
    /// Number of OOM conditions.
    pub oom_events: u64,
    /// Number of retried faults.
    pub retries: u64,
    /// Number of stack growth events.
    pub stack_grows: u64,
}

// -------------------------------------------------------------------
// PageFaultHandler
// -------------------------------------------------------------------

/// Main page fault handler with VMA lookup and dispatch.
///
/// Manages a table of VMAs and dispatches faults to the appropriate
/// handler based on fault type and VMA permissions.
pub struct PageFaultHandler {
    /// VMA table for address lookup.
    vmas: [VmaEntry; MAX_VMAS],
    /// Number of active VMAs.
    vma_count: usize,
    /// Fault handling statistics.
    stats: FaultStatistics,
    /// Currently allocated physical frame count (for tracking).
    allocated_frames: u64,
    /// Total physical frames available.
    total_frames: u64,
}

impl PageFaultHandler {
    /// Create a new page fault handler.
    pub fn new(total_frames: u64) -> Self {
        Self {
            vmas: [VmaEntry::empty(); MAX_VMAS],
            vma_count: 0,
            stats: FaultStatistics::default(),
            allocated_frames: 0,
            total_frames,
        }
    }

    /// Register a VMA for fault handling.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the VMA overlaps an existing one,
    /// or if the table is full.
    pub fn register_vma(&mut self, start: u64, end: u64, permissions: u32) -> Result<usize> {
        if start >= end || start % PAGE_SIZE != 0 || end % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }

        // Check for overlaps with existing VMAs.
        for i in 0..self.vma_count {
            let vma = &self.vmas[i];
            if vma.active && start < vma.end && end > vma.start {
                return Err(Error::AlreadyExists);
            }
        }

        if self.vma_count >= MAX_VMAS {
            return Err(Error::OutOfMemory);
        }

        let idx = self.vma_count;
        self.vmas[idx] = VmaEntry {
            start,
            end,
            permissions,
            backing_pfn: 0,
            file_offset: 0,
            mapped_pages: 0,
            active: true,
        };
        self.vma_count += 1;
        Ok(idx)
    }

    /// Unregister a VMA by index.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the index is out of bounds.
    pub fn unregister_vma(&mut self, idx: usize) -> Result<()> {
        if idx >= self.vma_count || !self.vmas[idx].active {
            return Err(Error::InvalidArgument);
        }
        self.vmas[idx].active = false;
        Ok(())
    }

    /// Find the VMA containing the given address.
    fn find_vma(&self, addr: u64) -> Option<usize> {
        for i in 0..self.vma_count {
            if self.vmas[i].contains(addr) {
                return Some(i);
            }
        }
        None
    }

    /// Find a VMA that might expand to cover the given address (stack growth).
    fn find_expandable_vma(&self, addr: u64) -> Option<usize> {
        for i in 0..self.vma_count {
            let vma = &self.vmas[i];
            if vma.active && vma.is_stack() {
                // Stack VMAs grow downward; check if addr is just below.
                if addr < vma.start && vma.start.saturating_sub(addr) <= PAGE_SIZE * 16 {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Classify the type of fault for dispatch.
    fn classify_fault(&self, info: &FaultInfo, vma_idx: usize) -> FaultType {
        let vma = &self.vmas[vma_idx];

        if vma.is_hugepage() {
            return FaultType::HugePage;
        }

        if info.is_write() && info.is_protection() && !vma.is_shared() {
            return FaultType::CopyOnWrite;
        }

        if vma.is_file_backed() {
            return FaultType::FileBacked;
        }

        FaultType::Anonymous
    }

    /// Check if the fault is permitted by VMA permissions.
    fn check_permissions(&self, info: &FaultInfo, vma_idx: usize) -> bool {
        let vma = &self.vmas[vma_idx];

        if info.is_write() && (vma.permissions & VmaPermissions::WRITE == 0) {
            // Write to a non-writable VMA — only allowed for CoW.
            if !info.is_protection() {
                return false;
            }
        }

        if info.is_exec() && (vma.permissions & VmaPermissions::EXEC == 0) {
            return false;
        }

        if vma.permissions & VmaPermissions::READ == 0 {
            return false;
        }

        true
    }

    /// Handle a page fault.
    ///
    /// This is the main entry point called from the architecture-specific
    /// fault handler. It looks up the faulting address in the VMA table,
    /// checks permissions, classifies the fault, and dispatches to the
    /// appropriate sub-handler.
    ///
    /// # Errors
    ///
    /// Returns `OutOfMemory` if no physical frames are available for
    /// allocation.
    pub fn handle_page_fault(&mut self, info: &FaultInfo) -> Result<FaultResult> {
        self.stats.total_faults += 1;

        // Check retry count.
        if info.retry_count >= MAX_FAULT_RETRIES {
            self.stats.segfaults += 1;
            return Ok(FaultResult::Segfault);
        }

        // Find the VMA containing the faulting address.
        let vma_idx = match self.find_vma(info.page_address()) {
            Some(idx) => idx,
            None => {
                // Try stack expansion.
                if let Some(idx) = self.find_expandable_vma(info.page_address()) {
                    return self.handle_stack_grow(info, idx);
                }
                self.stats.segfaults += 1;
                return Ok(FaultResult::Segfault);
            }
        };

        // Check permissions.
        if !self.check_permissions(info, vma_idx) {
            // Protection violation on a write may be CoW.
            if info.is_write() && info.is_protection() && !self.vmas[vma_idx].is_shared() {
                return self.handle_cow_fault(info, vma_idx);
            }
            self.stats.segfaults += 1;
            return Ok(FaultResult::Segfault);
        }

        // Classify and dispatch.
        let fault_type = self.classify_fault(info, vma_idx);
        match fault_type {
            FaultType::Anonymous => self.handle_anon_fault(info, vma_idx),
            FaultType::FileBacked => self.handle_file_fault(info, vma_idx),
            FaultType::CopyOnWrite => self.handle_cow_fault(info, vma_idx),
            FaultType::StackGrow => self.handle_stack_grow(info, vma_idx),
            FaultType::HugePage => self.handle_huge_fault(info, vma_idx),
        }
    }

    /// Handle an anonymous page fault (demand zero).
    fn handle_anon_fault(&mut self, _info: &FaultInfo, vma_idx: usize) -> Result<FaultResult> {
        if self.allocated_frames >= self.total_frames {
            self.stats.oom_events += 1;
            return Ok(FaultResult::Oom);
        }

        // Allocate a new zeroed page and map it.
        self.allocated_frames += 1;
        self.vmas[vma_idx].mapped_pages += 1;
        self.stats.anon_allocs += 1;
        self.stats.minor_faults += 1;

        Ok(FaultResult::AnonAllocated)
    }

    /// Handle a file-backed page fault.
    fn handle_file_fault(&mut self, _info: &FaultInfo, vma_idx: usize) -> Result<FaultResult> {
        if self.allocated_frames >= self.total_frames {
            self.stats.oom_events += 1;
            return Ok(FaultResult::Oom);
        }

        // Read the page from backing store (simulated).
        self.allocated_frames += 1;
        self.vmas[vma_idx].mapped_pages += 1;
        self.stats.file_loads += 1;
        self.stats.major_faults += 1;

        Ok(FaultResult::FileLoaded)
    }

    /// Handle a copy-on-write fault.
    fn handle_cow_fault(&mut self, _info: &FaultInfo, vma_idx: usize) -> Result<FaultResult> {
        if self.allocated_frames >= self.total_frames {
            self.stats.oom_events += 1;
            return Ok(FaultResult::Oom);
        }

        // Copy the page and remap with write permissions.
        self.allocated_frames += 1;
        self.vmas[vma_idx].mapped_pages += 1;
        self.stats.cow_faults += 1;
        self.stats.minor_faults += 1;

        Ok(FaultResult::CowResolved)
    }

    /// Handle a stack growth fault.
    fn handle_stack_grow(&mut self, info: &FaultInfo, vma_idx: usize) -> Result<FaultResult> {
        if self.allocated_frames >= self.total_frames {
            self.stats.oom_events += 1;
            return Ok(FaultResult::Oom);
        }

        let page_addr = info.page_address();
        let vma = &mut self.vmas[vma_idx];

        // Extend the VMA downward to cover the faulting address.
        if page_addr < vma.start {
            vma.start = page_addr;
        }

        self.allocated_frames += 1;
        vma.mapped_pages += 1;
        self.stats.stack_grows += 1;
        self.stats.minor_faults += 1;

        Ok(FaultResult::AnonAllocated)
    }

    /// Handle a huge page fault.
    fn handle_huge_fault(&mut self, _info: &FaultInfo, vma_idx: usize) -> Result<FaultResult> {
        // Huge pages need 512 contiguous frames (2 MiB).
        let frames_needed = 512;
        if self.allocated_frames + frames_needed > self.total_frames {
            // Fall back to regular pages.
            return self.handle_anon_fault(_info, vma_idx);
        }

        self.allocated_frames += frames_needed;
        self.vmas[vma_idx].mapped_pages += frames_needed;
        self.stats.anon_allocs += 1;
        self.stats.minor_faults += 1;

        Ok(FaultResult::AnonAllocated)
    }

    /// Get fault handling statistics.
    pub fn statistics(&self) -> &FaultStatistics {
        &self.stats
    }

    /// Get the number of active VMAs.
    pub fn vma_count(&self) -> usize {
        self.vmas
            .iter()
            .take(self.vma_count)
            .filter(|v| v.active)
            .count()
    }

    /// Reset fault statistics.
    pub fn reset_statistics(&mut self) {
        self.stats = FaultStatistics::default();
    }

    /// Get a reference to a VMA by index.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the index is out of bounds.
    pub fn get_vma(&self, idx: usize) -> Result<&VmaEntry> {
        if idx >= self.vma_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.vmas[idx])
    }

    /// Update VMA permissions.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the index is out of bounds.
    pub fn set_vma_permissions(&mut self, idx: usize, permissions: u32) -> Result<()> {
        if idx >= self.vma_count || !self.vmas[idx].active {
            return Err(Error::InvalidArgument);
        }
        self.vmas[idx].permissions = permissions;
        Ok(())
    }

    /// Set file backing info for a VMA.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the index is out of bounds.
    pub fn set_vma_backing(
        &mut self,
        idx: usize,
        backing_pfn: u64,
        file_offset: u64,
    ) -> Result<()> {
        if idx >= self.vma_count || !self.vmas[idx].active {
            return Err(Error::InvalidArgument);
        }
        self.vmas[idx].backing_pfn = backing_pfn;
        self.vmas[idx].file_offset = file_offset;
        self.vmas[idx].permissions |= VmaPermissions::FILE;
        Ok(())
    }
}
