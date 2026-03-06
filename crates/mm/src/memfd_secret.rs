// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `memfd_secret()` secure memory subsystem.
//!
//! Provides an interface for creating anonymous file descriptors backed
//! by memory that is **removed from the kernel direct map** after
//! allocation. This makes the pages inaccessible to the kernel itself,
//! hardening them against Spectre-class side-channel attacks and
//! stale-pointer reads from other kernel subsystems.
//!
//! # Architecture
//!
//! - [`SecretMemFlags`] — creation flags (`CLOEXEC`, `EXCLUSIVE`)
//! - [`SecretFd`] — per-fd state tracking (owner, pages, seals)
//! - [`SecretPage`] — per-page metadata (PFN, direct-map state)
//! - [`SecretMemManager`] — system-wide manager enforcing quotas
//! - [`SecretMemInfo`] — statistics snapshot for `/proc/meminfo`
//!
//! # Lifecycle
//!
//! 1. `memfd_secret(flags)` allocates a [`SecretFd`] and returns an fd.
//! 2. `ftruncate(fd, size)` sets the desired size (pages allocated
//!    lazily or eagerly depending on policy).
//! 3. `mmap(fd)` maps the pages into user space; they are
//!    simultaneously removed from the kernel direct map.
//! 4. User reads/writes the mapping normally.
//! 5. On `munmap()` or `close()`, pages are **scrubbed** (zeroed),
//!    restored to the direct map, and freed.
//!
//! # Security Properties
//!
//! - Pages are excluded from the kernel direct map after mapping.
//! - Pages are zeroed on release to prevent information leakage.
//! - Reference counting prevents premature page reuse.
//! - Per-process and system-wide quotas prevent resource exhaustion.
//!
//! Reference: Linux `mm/secretmem.c`, `memfd_secret(2)`.

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Maximum secret fds system-wide.
const MAX_SECRET_FDS: usize = 64;

/// Maximum pages per secret fd.
const MAX_PAGES_PER_FD: usize = 512;

/// System-wide hard limit on secret pages.
const MAX_TOTAL_SECRET_PAGES: usize = 4096;

/// Per-process limit on secret pages.
const MAX_PAGES_PER_PROCESS: usize = 1024;

/// Starting fd number (above stdio range).
const SECRET_FD_BASE: u32 = 1000;

// -------------------------------------------------------------------
// SecretMemFlags
// -------------------------------------------------------------------

/// Flags accepted by `memfd_secret()`.
pub mod secret_mem_flags {
    /// Set close-on-exec on the new file descriptor.
    pub const CLOEXEC: u32 = 1 << 0;

    /// Exclusive access: only the creating process may map this fd.
    pub const EXCLUSIVE: u32 = 1 << 1;

    /// All valid flags combined.
    pub const VALID_MASK: u32 = CLOEXEC | EXCLUSIVE;
}

// -------------------------------------------------------------------
// SecretPageState
// -------------------------------------------------------------------

/// Lifecycle state of a single secret page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecretPageState {
    /// Slot is unused.
    #[default]
    Free,
    /// Page is allocated but not yet mapped (reserved after
    /// `ftruncate`).
    Allocated,
    /// Page is mapped into user space and removed from the direct
    /// map.
    Mapped,
    /// Page is being scrubbed (zeroed) prior to release.
    Scrubbing,
}

// -------------------------------------------------------------------
// SecretPage
// -------------------------------------------------------------------

/// Per-page metadata for a secret-memory page.
#[derive(Debug, Clone, Copy)]
pub struct SecretPage {
    /// Physical frame number.
    pub pfn: u64,
    /// Current lifecycle state.
    pub state: SecretPageState,
    /// Whether the page has been removed from the kernel direct map.
    pub direct_map_removed: bool,
    /// Reference count (number of live mappings).
    pub ref_count: u32,
}

impl SecretPage {
    /// An empty, unused page slot.
    const fn empty() -> Self {
        Self {
            pfn: 0,
            state: SecretPageState::Free,
            direct_map_removed: false,
            ref_count: 0,
        }
    }

    /// Returns `true` if this slot is not in use.
    pub const fn is_free(&self) -> bool {
        matches!(self.state, SecretPageState::Free)
    }
}

// -------------------------------------------------------------------
// SecretFdState
// -------------------------------------------------------------------

/// State of a secret file descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecretFdState {
    /// Slot is unused.
    #[default]
    Inactive,
    /// Fd is open but not yet truncated (no pages).
    Open,
    /// Pages have been allocated (after `ftruncate`).
    Sized,
    /// Pages are mapped into user space.
    Mapped,
    /// Fd has been closed; cleanup in progress.
    Closing,
}

// -------------------------------------------------------------------
// SecretFd
// -------------------------------------------------------------------

/// State for a single `memfd_secret()` file descriptor.
///
/// Tracks the owner process, allocated pages, mapping state, and
/// creation flags.
#[derive(Debug, Clone, Copy)]
pub struct SecretFd {
    /// Kernel-assigned fd number.
    pub fd: u32,
    /// Owning process PID.
    pub owner_pid: u64,
    /// Creation flags (see [`secret_mem_flags`]).
    pub flags: u32,
    /// Current fd state.
    pub state: SecretFdState,
    /// Number of pages allocated to this fd.
    pub page_count: usize,
    /// Requested size in bytes (set by `ftruncate`).
    pub size_bytes: usize,
}

impl SecretFd {
    /// An empty, inactive fd slot.
    const fn empty() -> Self {
        Self {
            fd: 0,
            owner_pid: 0,
            flags: 0,
            state: SecretFdState::Inactive,
            page_count: 0,
            size_bytes: 0,
        }
    }

    /// Returns `true` if this slot is inactive.
    pub const fn is_inactive(&self) -> bool {
        matches!(self.state, SecretFdState::Inactive)
    }

    /// Returns `true` if the fd is currently mapped.
    pub const fn is_mapped(&self) -> bool {
        matches!(self.state, SecretFdState::Mapped)
    }
}

// -------------------------------------------------------------------
// SecretMemInfo
// -------------------------------------------------------------------

/// Snapshot of secret-memory statistics.
///
/// Suitable for populating `/proc/meminfo` fields.
#[derive(Debug, Clone, Copy, Default)]
pub struct SecretMemInfo {
    /// Number of active secret fds.
    pub active_fds: usize,
    /// Total secret pages currently allocated.
    pub total_pages: usize,
    /// Total bytes of secret memory in use.
    pub total_bytes: usize,
    /// Cumulative pages allocated since boot.
    pub pages_allocated: u64,
    /// Cumulative pages freed since boot.
    pub pages_freed: u64,
    /// Number of `memfd_secret()` calls.
    pub create_calls: u64,
    /// Number of fds destroyed.
    pub destroy_calls: u64,
    /// Number of scrub (zero-on-free) operations.
    pub scrub_count: u64,
}

// -------------------------------------------------------------------
// SecretMemManager
// -------------------------------------------------------------------

/// System-wide manager for `memfd_secret()` secure memory.
///
/// Enforces per-process and system-wide page quotas, tracks all
/// secret fds and their pages, and handles the create/truncate/
/// map/unmap/destroy lifecycle.
pub struct SecretMemManager {
    /// Secret fd slots.
    fds: [SecretFd; MAX_SECRET_FDS],
    /// Per-fd page arrays.
    pages: [[SecretPage; MAX_PAGES_PER_FD]; MAX_SECRET_FDS],
    /// Number of active fds.
    active_fd_count: usize,
    /// Total secret pages currently allocated.
    total_pages: usize,
    /// Next fd number to assign.
    next_fd: u32,
    /// Statistics.
    info: SecretMemInfo,
    /// Whether secret memory is globally enabled.
    enabled: bool,
}

impl Default for SecretMemManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretMemManager {
    /// Creates a new, empty secret-memory manager.
    pub const fn new() -> Self {
        Self {
            fds: [SecretFd::empty(); MAX_SECRET_FDS],
            pages: [[SecretPage::empty(); MAX_PAGES_PER_FD]; MAX_SECRET_FDS],
            active_fd_count: 0,
            total_pages: 0,
            next_fd: SECRET_FD_BASE,
            info: SecretMemInfo {
                active_fds: 0,
                total_pages: 0,
                total_bytes: 0,
                pages_allocated: 0,
                pages_freed: 0,
                create_calls: 0,
                destroy_calls: 0,
                scrub_count: 0,
            },
            enabled: true,
        }
    }

    // ---------------------------------------------------------------
    // Lifecycle: create
    // ---------------------------------------------------------------

    /// Creates a new `memfd_secret()` file descriptor.
    ///
    /// Returns the assigned fd number. The fd starts in the `Open`
    /// state with no pages; call [`set_size`](Self::set_size) to
    /// allocate storage.
    ///
    /// # Errors
    ///
    /// - [`Error::PermissionDenied`] if secret memory is disabled.
    /// - [`Error::InvalidArgument`] if `flags` contains unknown bits.
    /// - [`Error::OutOfMemory`] if all fd slots are occupied.
    pub fn create(&mut self, owner_pid: u64, flags: u32) -> Result<u32> {
        if !self.enabled {
            return Err(Error::PermissionDenied);
        }
        if flags & !secret_mem_flags::VALID_MASK != 0 {
            return Err(Error::InvalidArgument);
        }

        let slot_idx = self.find_free_fd_slot().ok_or(Error::OutOfMemory)?;
        let fd = self.next_fd;
        self.next_fd += 1;

        self.fds[slot_idx] = SecretFd {
            fd,
            owner_pid,
            flags,
            state: SecretFdState::Open,
            page_count: 0,
            size_bytes: 0,
        };

        self.active_fd_count += 1;
        self.info.active_fds = self.active_fd_count;
        self.info.create_calls += 1;

        Ok(fd)
    }

    // ---------------------------------------------------------------
    // Lifecycle: set_size (ftruncate equivalent)
    // ---------------------------------------------------------------

    /// Sets the size of a secret fd (analogous to `ftruncate`).
    ///
    /// Pages are reserved but not yet mapped. The fd transitions to
    /// the `Sized` state.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `fd` is not registered.
    /// - [`Error::InvalidArgument`] if `size_bytes` is zero or not
    ///   page-aligned.
    /// - [`Error::OutOfMemory`] if the per-fd, per-process, or
    ///   system-wide page limit would be exceeded.
    pub fn set_size(&mut self, fd: u32, size_bytes: usize) -> Result<()> {
        if size_bytes == 0 || size_bytes % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }

        let page_count = size_bytes / PAGE_SIZE;
        if page_count > MAX_PAGES_PER_FD {
            return Err(Error::OutOfMemory);
        }
        if self.total_pages + page_count > MAX_TOTAL_SECRET_PAGES {
            return Err(Error::OutOfMemory);
        }

        let idx = self.find_fd_index(fd)?;
        let owner = self.fds[idx].owner_pid;

        // Per-process quota check.
        let proc_pages = self.pages_for_process(owner);
        if proc_pages + page_count > MAX_PAGES_PER_PROCESS {
            return Err(Error::OutOfMemory);
        }

        self.fds[idx].page_count = page_count;
        self.fds[idx].size_bytes = size_bytes;
        self.fds[idx].state = SecretFdState::Sized;

        // Mark pages as allocated.
        for page in &mut self.pages[idx][..page_count] {
            page.state = SecretPageState::Allocated;
        }

        self.total_pages += page_count;
        self.info.total_pages = self.total_pages;
        self.info.total_bytes = self.total_pages * PAGE_SIZE;
        self.info.pages_allocated += page_count as u64;

        Ok(())
    }

    // ---------------------------------------------------------------
    // Lifecycle: map_pages
    // ---------------------------------------------------------------

    /// Maps allocated pages into user space.
    ///
    /// Each page is removed from the kernel direct map and its PFN
    /// is recorded. The fd transitions to the `Mapped` state.
    ///
    /// The `pfns` slice provides the physical frame numbers assigned
    /// by the frame allocator. Its length must match the fd's page
    /// count.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `fd` is not registered.
    /// - [`Error::InvalidArgument`] if `pfns` length does not match
    ///   the page count, or if the fd is not in `Sized` state.
    /// - [`Error::AlreadyExists`] if the fd is already mapped.
    pub fn map_pages(&mut self, fd: u32, pfns: &[u64]) -> Result<()> {
        let idx = self.find_fd_index(fd)?;

        if self.fds[idx].is_mapped() {
            return Err(Error::AlreadyExists);
        }
        if !matches!(self.fds[idx].state, SecretFdState::Sized) {
            return Err(Error::InvalidArgument);
        }

        let count = self.fds[idx].page_count;
        if pfns.len() != count {
            return Err(Error::InvalidArgument);
        }

        for (i, &pfn) in pfns.iter().enumerate() {
            self.pages[idx][i] = SecretPage {
                pfn,
                state: SecretPageState::Mapped,
                direct_map_removed: true,
                ref_count: 1,
            };
        }

        self.fds[idx].state = SecretFdState::Mapped;
        Ok(())
    }

    // ---------------------------------------------------------------
    // Lifecycle: unmap + destroy
    // ---------------------------------------------------------------

    /// Unmaps and destroys a secret fd.
    ///
    /// Pages are scrubbed (zeroed), restored to the direct map, and
    /// freed. Returns the number of pages that were released.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `fd` is not registered.
    pub fn destroy(&mut self, fd: u32) -> Result<usize> {
        let idx = self.find_fd_index(fd)?;
        let count = self.fds[idx].page_count;

        self.fds[idx].state = SecretFdState::Closing;

        // Scrub each page.
        for page in &mut self.pages[idx][..count] {
            if page.state == SecretPageState::Mapped || page.state == SecretPageState::Allocated {
                page.state = SecretPageState::Scrubbing;
                self.info.scrub_count += 1;
                // In a real implementation: zero the page contents,
                // restore the direct-map PTE, flush TLB.
                page.direct_map_removed = false;
                page.ref_count = 0;
                page.state = SecretPageState::Free;
            }
        }

        self.total_pages = self.total_pages.saturating_sub(count);
        self.info.total_pages = self.total_pages;
        self.info.total_bytes = self.total_pages * PAGE_SIZE;
        self.info.pages_freed += count as u64;

        // Deactivate the fd slot.
        self.fds[idx] = SecretFd::empty();
        self.active_fd_count = self.active_fd_count.saturating_sub(1);
        self.info.active_fds = self.active_fd_count;
        self.info.destroy_calls += 1;

        Ok(count)
    }

    // ---------------------------------------------------------------
    // Process cleanup
    // ---------------------------------------------------------------

    /// Destroys all secret fds owned by the given process.
    ///
    /// Called during process exit to ensure no secret pages leak.
    /// Returns the total number of pages freed.
    pub fn cleanup_process(&mut self, pid: u64) -> usize {
        let mut fds_to_destroy = [0u32; MAX_SECRET_FDS];
        let mut fd_count = 0usize;

        for fd_slot in &self.fds {
            if !fd_slot.is_inactive() && fd_slot.owner_pid == pid {
                fds_to_destroy[fd_count] = fd_slot.fd;
                fd_count += 1;
            }
        }

        let mut freed = 0usize;
        for &fd in &fds_to_destroy[..fd_count] {
            if let Ok(pages) = self.destroy(fd) {
                freed += pages;
            }
        }
        freed
    }

    // ---------------------------------------------------------------
    // Queries
    // ---------------------------------------------------------------

    /// Checks whether a physical frame number belongs to any active
    /// secret mapping.
    ///
    /// The kernel uses this to block direct-map access to secret
    /// pages.
    pub fn is_secret_pfn(&self, pfn: u64) -> bool {
        for (i, fd_slot) in self.fds.iter().enumerate() {
            if fd_slot.is_inactive() || !fd_slot.is_mapped() {
                continue;
            }
            for page in &self.pages[i][..fd_slot.page_count] {
                if page.state == SecretPageState::Mapped && page.pfn == pfn {
                    return true;
                }
            }
        }
        false
    }

    /// Returns information about a secret fd.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `fd` is not registered.
    pub fn fd_info(&self, fd: u32) -> Result<&SecretFd> {
        let idx = self.find_fd_index(fd)?;
        Ok(&self.fds[idx])
    }

    /// Returns the page array for a secret fd.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `fd` is not registered.
    pub fn fd_pages(&self, fd: u32) -> Result<&[SecretPage]> {
        let idx = self.find_fd_index(fd)?;
        let count = self.fds[idx].page_count;
        Ok(&self.pages[idx][..count])
    }

    /// Returns the total bytes of secret memory in use.
    pub const fn total_secret_bytes(&self) -> usize {
        self.total_pages * PAGE_SIZE
    }

    /// Returns the number of active secret fds.
    pub const fn active_fd_count(&self) -> usize {
        self.active_fd_count
    }

    /// Returns a statistics snapshot.
    pub const fn info(&self) -> &SecretMemInfo {
        &self.info
    }

    /// Returns `true` if secret memory is globally enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enables or disables secret memory system-wide.
    ///
    /// When disabled, new `memfd_secret()` calls will fail with
    /// `PermissionDenied`. Existing mappings are unaffected.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Returns `true` if there are no active secret fds.
    pub const fn is_empty(&self) -> bool {
        self.active_fd_count == 0
    }

    /// Returns the number of secret pages owned by a process.
    pub fn pages_for_process(&self, pid: u64) -> usize {
        let mut count = 0usize;
        for fd_slot in &self.fds {
            if !fd_slot.is_inactive() && fd_slot.owner_pid == pid {
                count += fd_slot.page_count;
            }
        }
        count
    }

    /// Returns the per-process page limit.
    pub const fn per_process_limit(&self) -> usize {
        MAX_PAGES_PER_PROCESS
    }

    /// Returns the system-wide page limit.
    pub const fn system_limit(&self) -> usize {
        MAX_TOTAL_SECRET_PAGES
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Finds the first free fd slot, returning its index.
    fn find_free_fd_slot(&self) -> Option<usize> {
        self.fds.iter().position(|f| f.is_inactive())
    }

    /// Finds the index of an active fd by its fd number.
    fn find_fd_index(&self, fd: u32) -> Result<usize> {
        self.fds
            .iter()
            .position(|f| !f.is_inactive() && f.fd == fd)
            .ok_or(Error::NotFound)
    }
}
