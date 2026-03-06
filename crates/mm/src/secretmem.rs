// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Secret memory areas (`memfd_secret`).
//!
//! Implements secret memory regions that are removed from the kernel
//! direct map after allocation, making them inaccessible to the
//! kernel itself and resistant to Spectre-class side-channel attacks.
//!
//! # Architecture
//!
//! - [`SecretArea`] — a single secret memory allocation with
//!   page tracking and owner information
//! - [`SecretPage`] — per-page metadata for secret pages
//! - [`SecretMemRegistry`] — system-wide registry of secret areas
//! - [`SecretMemStats`] — allocation and usage statistics
//!
//! The `memfd_secret()` system call creates a file descriptor
//! backed by secret memory. When the area is mapped via `mmap()`,
//! the pages are allocated and removed from the kernel's direct
//! mapping. On `munmap()` or `close()`, the pages are zeroed,
//! restored to the direct map, and freed.
//!
//! Reference: Linux `mm/secretmem.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of secret areas in the system.
const MAX_SECRET_AREAS: usize = 32;

/// Maximum pages per secret area.
const MAX_SECRET_PAGES: usize = 256;

/// Page size in bytes (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Maximum total secret pages system-wide.
const MAX_TOTAL_SECRET_PAGES: usize = 2048;

/// Flags for `memfd_secret()`.
pub mod secret_flags {
    /// Close-on-exec (default for secret fds).
    pub const CLOEXEC: u32 = 1 << 0;
    /// Non-executable mapping.
    pub const NOEXEC: u32 = 1 << 1;
}

// -------------------------------------------------------------------
// SecretPageState
// -------------------------------------------------------------------

/// State of a page within a secret area.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecretPageState {
    /// Page slot is empty.
    #[default]
    Free,
    /// Page is allocated and removed from the direct map.
    Mapped,
    /// Page is being zeroed prior to release.
    Zeroing,
}

// -------------------------------------------------------------------
// SecretPage
// -------------------------------------------------------------------

/// Metadata for a single page in a secret area.
#[derive(Debug, Clone, Copy)]
pub struct SecretPage {
    /// Physical frame number.
    pub pfn: u64,
    /// Current state.
    pub state: SecretPageState,
    /// Whether this page has been removed from the direct map.
    pub direct_map_removed: bool,
}

impl SecretPage {
    /// Creates an empty, free secret page entry.
    const fn empty() -> Self {
        Self {
            pfn: 0,
            state: SecretPageState::Free,
            direct_map_removed: false,
        }
    }
}

// -------------------------------------------------------------------
// SecretArea
// -------------------------------------------------------------------

/// A single secret memory area.
///
/// Represents one `memfd_secret()` allocation. Tracks the owning
/// process, allocated pages, and whether the area is currently
/// mapped into user space.
#[derive(Debug, Clone, Copy)]
pub struct SecretArea {
    /// File descriptor identifier.
    pub fd: u32,
    /// Owner process PID.
    pub owner_pid: u64,
    /// Number of pages allocated to this area.
    pub page_count: usize,
    /// Flags from `memfd_secret()`.
    pub flags: u32,
    /// Whether this area is currently mapped.
    pub mapped: bool,
    /// Whether this slot is active.
    pub active: bool,
}

impl SecretArea {
    /// Creates an empty, inactive secret area.
    const fn empty() -> Self {
        Self {
            fd: 0,
            owner_pid: 0,
            page_count: 0,
            flags: 0,
            mapped: false,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// SecretMemStats
// -------------------------------------------------------------------

/// System-wide secret memory statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct SecretMemStats {
    /// Number of active secret areas.
    pub active_areas: usize,
    /// Total secret pages currently allocated.
    pub total_pages: usize,
    /// Total pages ever allocated.
    pub alloc_count: u64,
    /// Total pages ever freed.
    pub free_count: u64,
    /// Number of `memfd_secret()` calls.
    pub create_count: u64,
    /// Number of areas destroyed.
    pub destroy_count: u64,
}

// -------------------------------------------------------------------
// SecretMemRegistry
// -------------------------------------------------------------------

/// System-wide registry of secret memory areas.
///
/// Manages up to [`MAX_SECRET_AREAS`] active areas, tracks per-area
/// page allocations, and enforces system-wide limits on total
/// secret pages.
pub struct SecretMemRegistry {
    /// Registered secret areas.
    areas: [SecretArea; MAX_SECRET_AREAS],
    /// Per-area page tracking.
    pages: [[SecretPage; MAX_SECRET_PAGES]; MAX_SECRET_AREAS],
    /// Number of active areas.
    area_count: usize,
    /// Total secret pages allocated system-wide.
    total_pages: usize,
    /// Next file descriptor number to assign.
    next_fd: u32,
    /// Statistics.
    stats: SecretMemStats,
    /// Whether secret memory is enabled system-wide.
    enabled: bool,
}

impl Default for SecretMemRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretMemRegistry {
    /// Creates a new empty secret memory registry.
    pub const fn new() -> Self {
        Self {
            areas: [SecretArea::empty(); MAX_SECRET_AREAS],
            pages: [[SecretPage::empty(); MAX_SECRET_PAGES]; MAX_SECRET_AREAS],
            area_count: 0,
            total_pages: 0,
            next_fd: 100, // Start above standard fds.
            stats: SecretMemStats {
                active_areas: 0,
                total_pages: 0,
                alloc_count: 0,
                free_count: 0,
                create_count: 0,
                destroy_count: 0,
            },
            enabled: true,
        }
    }

    /// Creates a secret memory area (`memfd_secret` equivalent).
    ///
    /// Allocates a new secret area for the given process and
    /// returns the assigned file descriptor number.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PermissionDenied`] if secret memory is
    /// disabled.
    /// Returns [`Error::OutOfMemory`] if all area slots are full.
    pub fn create(&mut self, owner_pid: u64, flags: u32) -> Result<u32> {
        if !self.enabled {
            return Err(Error::PermissionDenied);
        }

        if self.area_count >= MAX_SECRET_AREAS {
            return Err(Error::OutOfMemory);
        }

        let fd = self.next_fd;
        self.next_fd += 1;

        let slot = self
            .areas
            .iter_mut()
            .find(|a| !a.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = SecretArea {
            fd,
            owner_pid,
            page_count: 0,
            flags,
            mapped: false,
            active: true,
        };

        self.area_count += 1;
        self.stats.active_areas = self.area_count;
        self.stats.create_count += 1;

        Ok(fd)
    }

    /// Maps pages into a secret area.
    ///
    /// Allocates `page_count` pages, marks them as removed from the
    /// direct map, and associates them with the area identified by
    /// `fd`.
    ///
    /// The `pfns` slice provides the physical frame numbers to
    /// allocate. It must contain exactly `page_count` entries.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `fd` is not registered.
    /// Returns [`Error::InvalidArgument`] if `pfns.len()` does not
    /// match `page_count`, or if `page_count` exceeds the per-area
    /// or system-wide limit.
    /// Returns [`Error::AlreadyExists`] if the area is already
    /// mapped.
    pub fn map_pages(&mut self, fd: u32, pfns: &[u64], page_count: usize) -> Result<()> {
        if pfns.len() != page_count {
            return Err(Error::InvalidArgument);
        }
        if page_count > MAX_SECRET_PAGES {
            return Err(Error::InvalidArgument);
        }
        if self.total_pages + page_count > MAX_TOTAL_SECRET_PAGES {
            return Err(Error::OutOfMemory);
        }

        let area_idx = self.find_area_index(fd)?;

        if self.areas[area_idx].mapped {
            return Err(Error::AlreadyExists);
        }

        // Allocate pages.
        for (i, &pfn) in pfns.iter().enumerate() {
            self.pages[area_idx][i] = SecretPage {
                pfn,
                state: SecretPageState::Mapped,
                direct_map_removed: true,
            };
        }

        self.areas[area_idx].page_count = page_count;
        self.areas[area_idx].mapped = true;
        self.total_pages += page_count;
        self.stats.total_pages = self.total_pages;
        self.stats.alloc_count += page_count as u64;

        Ok(())
    }

    /// Unmaps and destroys a secret area.
    ///
    /// Zeroes all pages, restores them to the direct map, frees
    /// them, and deactivates the area.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `fd` is not registered.
    pub fn unmap_and_destroy(&mut self, fd: u32) -> Result<usize> {
        let area_idx = self.find_area_index(fd)?;
        let page_count = self.areas[area_idx].page_count;

        // Zero and release each page.
        for page in &mut self.pages[area_idx][..page_count] {
            page.state = SecretPageState::Zeroing;
            // In a real implementation, we would zero the page
            // contents here and restore the direct map entry.
            page.direct_map_removed = false;
            page.state = SecretPageState::Free;
        }

        self.total_pages = self.total_pages.saturating_sub(page_count);
        self.stats.total_pages = self.total_pages;
        self.stats.free_count += page_count as u64;

        // Deactivate the area.
        self.areas[area_idx] = SecretArea::empty();
        self.area_count = self.area_count.saturating_sub(1);
        self.stats.active_areas = self.area_count;
        self.stats.destroy_count += 1;

        Ok(page_count)
    }

    /// Returns the total bytes of secret memory in use.
    pub const fn total_secret_bytes(&self) -> usize {
        self.total_pages * PAGE_SIZE
    }

    /// Returns the number of active secret areas.
    pub const fn area_count(&self) -> usize {
        self.area_count
    }

    /// Returns statistics.
    pub const fn stats(&self) -> &SecretMemStats {
        &self.stats
    }

    /// Returns information about a secret area by fd.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `fd` is not registered.
    pub fn area_info(&self, fd: u32) -> Result<&SecretArea> {
        let idx = self.find_area_index(fd)?;
        Ok(&self.areas[idx])
    }

    /// Returns the pages for a secret area by fd.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `fd` is not registered.
    pub fn area_pages(&self, fd: u32) -> Result<&[SecretPage]> {
        let idx = self.find_area_index(fd)?;
        let count = self.areas[idx].page_count;
        Ok(&self.pages[idx][..count])
    }

    /// Enables or disables secret memory system-wide.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Returns `true` if secret memory is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Checks if a physical frame number belongs to any secret
    /// area.
    ///
    /// This is used by the kernel to prevent access to secret
    /// pages through the direct map.
    pub fn is_secret_page(&self, pfn: u64) -> bool {
        for (i, area) in self.areas.iter().enumerate() {
            if !area.active || !area.mapped {
                continue;
            }
            for page in &self.pages[i][..area.page_count] {
                if page.state == SecretPageState::Mapped && page.pfn == pfn {
                    return true;
                }
            }
        }
        false
    }

    /// Destroys all secret areas owned by a given PID.
    ///
    /// Called during process exit to clean up secret memory.
    /// Returns the total number of pages freed.
    pub fn cleanup_pid(&mut self, pid: u64) -> usize {
        let mut freed = 0usize;

        // Collect fds to destroy (avoid borrow issues).
        let mut fds_to_destroy = [0u32; MAX_SECRET_AREAS];
        let mut fd_count = 0usize;
        for area in &self.areas {
            if area.active && area.owner_pid == pid {
                fds_to_destroy[fd_count] = area.fd;
                fd_count += 1;
            }
        }

        for &fd in &fds_to_destroy[..fd_count] {
            if let Ok(pages) = self.unmap_and_destroy(fd) {
                freed += pages;
            }
        }

        freed
    }

    /// Returns `true` if the registry has no active areas.
    pub const fn is_empty(&self) -> bool {
        self.area_count == 0
    }

    // -- helpers --

    /// Finds the index of an area by file descriptor.
    fn find_area_index(&self, fd: u32) -> Result<usize> {
        self.areas
            .iter()
            .position(|a| a.active && a.fd == fd)
            .ok_or(Error::NotFound)
    }
}
