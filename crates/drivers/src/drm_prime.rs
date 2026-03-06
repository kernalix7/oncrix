// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DRM PRIME (dma-buf) buffer sharing between GPU and other devices.
//!
//! Implements the PRIME buffer sharing protocol for zero-copy buffer
//! exchange between DRM/KMS, V4L2, and compute subsystems. Each PRIME
//! handle wraps a dma-buf file descriptor and manages the lifecycle of
//! import/export operations, scatter-gather mappings, and reference
//! counting.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────┐              ┌──────────────┐
//! │  Exporter     │ ──export──▶ │  dma-buf fd  │ ──import──▶ │  Importer  │
//! │  (e.g., GPU)  │             │  (PRIME)     │             │  (e.g., V4L2)
//! └──────────────┘              └──────────────┘             └────────────┘
//! ```
//!
//! - **Export**: A device (exporter) creates a dma-buf from a GEM object
//!   and returns a PRIME handle / file descriptor.
//! - **Import**: Another device (importer) takes the fd and maps the
//!   dma-buf into its own address space for zero-copy access.
//!
//! Reference: Linux `drivers/gpu/drm/drm_prime.c`,
//! `include/linux/dma-buf.h`

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Maximum number of PRIME handles tracked globally.
const MAX_PRIME_HANDLES: usize = 128;

/// Maximum number of dma-buf imports per handle.
const MAX_IMPORTS_PER_HANDLE: usize = 8;

/// Maximum scatter-gather entries per dma-buf.
const MAX_SG_ENTRIES: usize = 64;

/// Maximum number of active dma-buf mappings.
const MAX_MAPPINGS: usize = 256;

/// Page size for alignment calculations.
const PAGE_SIZE: u64 = 4096;

// ── PRIME Flags ─────────────────────────────────────────────────

/// Access flags for PRIME buffer operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrimeFlags(u32);

impl PrimeFlags {
    /// No flags.
    pub const NONE: Self = Self(0);

    /// Read access permitted.
    pub const READ: Self = Self(1 << 0);

    /// Write access permitted.
    pub const WRITE: Self = Self(1 << 1);

    /// Read and write access.
    pub const READ_WRITE: Self = Self(0x3);

    /// Allow caching (non-coherent).
    pub const CACHED: Self = Self(1 << 2);

    /// Write-combining mapping.
    pub const WRITE_COMBINE: Self = Self(1 << 3);

    /// Return whether read access is permitted.
    pub fn can_read(self) -> bool {
        self.0 & Self::READ.0 != 0
    }

    /// Return whether write access is permitted.
    pub fn can_write(self) -> bool {
        self.0 & Self::WRITE.0 != 0
    }

    /// Return the raw bits.
    pub fn bits(self) -> u32 {
        self.0
    }
}

impl Default for PrimeFlags {
    fn default() -> Self {
        Self::NONE
    }
}

// ── Scatter-Gather Entry ────────────────────────────────────────

/// A single scatter-gather entry describing a physically contiguous
/// segment of a dma-buf.
#[derive(Debug, Clone, Copy, Default)]
pub struct SgEntry {
    /// Physical address of this segment.
    pub phys_addr: u64,
    /// Length of this segment in bytes.
    pub length: u64,
    /// Offset within the dma-buf.
    pub offset: u64,
}

// ── PRIME Handle ────────────────────────────────────────────────

/// State of a PRIME handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HandleState {
    /// Handle slot is free.
    #[default]
    Free,
    /// Handle is exported and available for import.
    Exported,
    /// Handle has been imported by at least one consumer.
    Imported,
    /// Handle is being torn down.
    Closing,
}

/// A PRIME buffer handle.
///
/// Wraps a dma-buf and tracks its scatter-gather list, size,
/// flags, and import/export state.
#[derive(Clone, Copy)]
pub struct PrimeHandle {
    /// Unique handle ID.
    handle_id: u32,
    /// GEM object handle on the exporter side.
    gem_handle: u32,
    /// File descriptor representation (for userspace).
    fd: i32,
    /// Total buffer size in bytes.
    size: u64,
    /// Scatter-gather table.
    sg_table: [SgEntry; MAX_SG_ENTRIES],
    /// Number of scatter-gather entries.
    sg_count: usize,
    /// Access flags.
    flags: PrimeFlags,
    /// Current state.
    state: HandleState,
    /// Number of active importers.
    import_count: u8,
    /// Device ID of the exporter.
    exporter_device: u32,
}

impl PrimeHandle {
    /// Create an empty handle.
    const fn empty() -> Self {
        Self {
            handle_id: 0,
            gem_handle: 0,
            fd: -1,
            size: 0,
            sg_table: [const {
                SgEntry {
                    phys_addr: 0,
                    length: 0,
                    offset: 0,
                }
            }; MAX_SG_ENTRIES],
            sg_count: 0,
            flags: PrimeFlags::NONE,
            state: HandleState::Free,
            import_count: 0,
            exporter_device: 0,
        }
    }

    /// Return the handle ID.
    pub fn handle_id(&self) -> u32 {
        self.handle_id
    }

    /// Return the GEM handle.
    pub fn gem_handle(&self) -> u32 {
        self.gem_handle
    }

    /// Return the file descriptor.
    pub fn fd(&self) -> i32 {
        self.fd
    }

    /// Return the buffer size.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Return the number of SG entries.
    pub fn sg_count(&self) -> usize {
        self.sg_count
    }

    /// Return a reference to the SG table.
    pub fn sg_table(&self) -> &[SgEntry] {
        &self.sg_table[..self.sg_count]
    }

    /// Return the current state.
    pub fn state(&self) -> HandleState {
        self.state
    }

    /// Return the number of active importers.
    pub fn import_count(&self) -> u8 {
        self.import_count
    }

    /// Return the exporter device ID.
    pub fn exporter_device(&self) -> u32 {
        self.exporter_device
    }
}

// ── dma-buf Import descriptor ───────────────────────────────────

/// A dma-buf import attachment.
///
/// Represents an importer's view of a PRIME handle, including
/// the device-specific mapping information.
#[derive(Debug, Clone, Copy)]
pub struct DmaBufImport {
    /// Handle ID of the imported PRIME buffer.
    handle_id: u32,
    /// Device ID of the importer.
    importer_device: u32,
    /// Device-virtual address where the buffer is mapped.
    device_addr: u64,
    /// Size of the mapped region.
    mapped_size: u64,
    /// Import flags.
    flags: PrimeFlags,
    /// Whether this import is currently active.
    active: bool,
}

impl DmaBufImport {
    /// Create an empty import descriptor.
    const fn empty() -> Self {
        Self {
            handle_id: 0,
            importer_device: 0,
            device_addr: 0,
            mapped_size: 0,
            flags: PrimeFlags::NONE,
            active: false,
        }
    }

    /// Return the handle ID.
    pub fn handle_id(&self) -> u32 {
        self.handle_id
    }

    /// Return the importer device ID.
    pub fn importer_device(&self) -> u32 {
        self.importer_device
    }

    /// Return the device address.
    pub fn device_addr(&self) -> u64 {
        self.device_addr
    }

    /// Return the mapped size.
    pub fn mapped_size(&self) -> u64 {
        self.mapped_size
    }

    /// Return whether this import is active.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

/// A dma-buf export descriptor.
///
/// Contains the information returned to user-space when a GEM
/// object is exported as a PRIME handle.
#[derive(Debug, Clone, Copy)]
pub struct DmaBufExport {
    /// The PRIME handle ID.
    pub handle_id: u32,
    /// File descriptor for the dma-buf.
    pub fd: i32,
    /// Size of the exported buffer.
    pub size: u64,
    /// Flags applied during export.
    pub flags: PrimeFlags,
}

// ── PRIME Registry ──────────────────────────────────────────────

/// DRM PRIME buffer sharing registry.
///
/// Manages the lifecycle of PRIME handles: export from a GEM
/// object, import by other devices, and cleanup on close.
pub struct PrimeRegistry {
    /// PRIME handle table.
    handles: [PrimeHandle; MAX_PRIME_HANDLES],
    /// Number of active handles.
    handle_count: usize,
    /// Import attachment table.
    imports: [DmaBufImport; MAX_MAPPINGS],
    /// Number of active imports.
    import_count: usize,
    /// Next handle ID to allocate.
    next_handle_id: u32,
    /// Next file descriptor to allocate.
    next_fd: i32,
}

impl PrimeRegistry {
    /// Create an empty PRIME registry.
    pub const fn new() -> Self {
        Self {
            handles: [const { PrimeHandle::empty() }; MAX_PRIME_HANDLES],
            handle_count: 0,
            imports: [const { DmaBufImport::empty() }; MAX_MAPPINGS],
            import_count: 0,
            next_handle_id: 1,
            next_fd: 100,
        }
    }

    /// Export a GEM object as a PRIME handle.
    ///
    /// Creates a dma-buf from the specified GEM object and returns
    /// an export descriptor with the PRIME handle ID and fd.
    ///
    /// # Arguments
    ///
    /// * `gem_handle` — GEM buffer object handle from the exporter.
    /// * `device_id` — device ID of the exporting device.
    /// * `size` — buffer size in bytes.
    /// * `sg_entries` — scatter-gather list of physical segments.
    /// * `flags` — access flags.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if size is zero or
    /// sg_entries is empty.
    /// Returns [`Error::OutOfMemory`] if the handle table is full.
    pub fn export_handle(
        &mut self,
        gem_handle: u32,
        device_id: u32,
        size: u64,
        sg_entries: &[SgEntry],
        flags: PrimeFlags,
    ) -> Result<DmaBufExport> {
        if size == 0 || sg_entries.is_empty() {
            return Err(Error::InvalidArgument);
        }

        if self.handle_count >= MAX_PRIME_HANDLES {
            return Err(Error::OutOfMemory);
        }

        let sg_count = sg_entries.len().min(MAX_SG_ENTRIES);
        let handle_id = self.next_handle_id;
        self.next_handle_id = self.next_handle_id.wrapping_add(1);
        let fd = self.next_fd;
        self.next_fd += 1;

        let mut handle = PrimeHandle::empty();
        handle.handle_id = handle_id;
        handle.gem_handle = gem_handle;
        handle.fd = fd;
        handle.size = size;
        handle.sg_table[..sg_count].copy_from_slice(&sg_entries[..sg_count]);
        handle.sg_count = sg_count;
        handle.flags = flags;
        handle.state = HandleState::Exported;
        handle.exporter_device = device_id;

        // Find a free slot.
        let slot = self.find_free_handle_slot().ok_or(Error::OutOfMemory)?;
        self.handles[slot] = handle;
        self.handle_count += 1;

        Ok(DmaBufExport {
            handle_id,
            fd,
            size,
            flags,
        })
    }

    /// Import a PRIME handle by file descriptor.
    ///
    /// Attaches the specified importer device to the dma-buf
    /// referenced by `fd` and returns an import descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no handle matches the fd.
    /// Returns [`Error::OutOfMemory`] if the import table is full.
    pub fn import_fd(
        &mut self,
        fd: i32,
        importer_device: u32,
        device_addr: u64,
        flags: PrimeFlags,
    ) -> Result<DmaBufImport> {
        // Find handle by fd.
        let handle_idx = self.find_handle_by_fd(fd).ok_or(Error::NotFound)?;

        if self.import_count >= MAX_MAPPINGS {
            return Err(Error::OutOfMemory);
        }

        let handle = &mut self.handles[handle_idx];
        handle.state = HandleState::Imported;
        handle.import_count = handle.import_count.saturating_add(1);
        let mapped_size = handle.size;
        let handle_id = handle.handle_id;

        let import = DmaBufImport {
            handle_id,
            importer_device,
            device_addr,
            mapped_size,
            flags,
            active: true,
        };

        // Find a free import slot.
        let slot = self.find_free_import_slot().ok_or(Error::OutOfMemory)?;
        self.imports[slot] = import;
        self.import_count += 1;

        Ok(import)
    }

    /// Map a dma-buf for device access.
    ///
    /// Returns the physical address of the first SG entry suitable
    /// for simple single-segment buffers. For multi-segment buffers,
    /// the caller should iterate the SG table.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the handle is not found.
    pub fn map_dma_buf(&self, handle_id: u32) -> Result<u64> {
        let handle = self.find_handle(handle_id).ok_or(Error::NotFound)?;

        if handle.sg_count == 0 {
            return Err(Error::InvalidArgument);
        }

        // Return the physical address of the first segment,
        // page-aligned.
        let addr = handle.sg_table[0].phys_addr & !(PAGE_SIZE - 1);
        Ok(addr)
    }

    /// Close a PRIME handle.
    ///
    /// Removes all imports and frees the handle slot. Any active
    /// importers are detached.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the handle is not found.
    pub fn close_handle(&mut self, handle_id: u32) -> Result<()> {
        let handle_idx = self.find_handle_index(handle_id).ok_or(Error::NotFound)?;

        // Remove all imports for this handle.
        for i in 0..MAX_MAPPINGS {
            if self.imports[i].active && self.imports[i].handle_id == handle_id {
                self.imports[i].active = false;
                self.import_count = self.import_count.saturating_sub(1);
            }
        }

        // Free the handle slot.
        self.handles[handle_idx].state = HandleState::Free;
        self.handle_count = self.handle_count.saturating_sub(1);

        Ok(())
    }

    // ── Query methods ───────────────────────────────────────

    /// Return the number of active handles.
    pub fn handle_count(&self) -> usize {
        self.handle_count
    }

    /// Return the number of active imports.
    pub fn import_count(&self) -> usize {
        self.import_count
    }

    /// Look up a PRIME handle by ID.
    pub fn find_handle(&self, handle_id: u32) -> Option<&PrimeHandle> {
        for i in 0..MAX_PRIME_HANDLES {
            if self.handles[i].state != HandleState::Free && self.handles[i].handle_id == handle_id
            {
                return Some(&self.handles[i]);
            }
        }
        None
    }

    // ── Internal helpers ────────────────────────────────────

    /// Find a free handle slot.
    fn find_free_handle_slot(&self) -> Option<usize> {
        for i in 0..MAX_PRIME_HANDLES {
            if self.handles[i].state == HandleState::Free {
                return Some(i);
            }
        }
        None
    }

    /// Find a free import slot.
    fn find_free_import_slot(&self) -> Option<usize> {
        for i in 0..MAX_MAPPINGS {
            if !self.imports[i].active {
                return Some(i);
            }
        }
        None
    }

    /// Find a handle by file descriptor.
    fn find_handle_by_fd(&self, fd: i32) -> Option<usize> {
        for i in 0..MAX_PRIME_HANDLES {
            if self.handles[i].state != HandleState::Free && self.handles[i].fd == fd {
                return Some(i);
            }
        }
        None
    }

    /// Find a handle index by ID.
    fn find_handle_index(&self, handle_id: u32) -> Option<usize> {
        for i in 0..MAX_PRIME_HANDLES {
            if self.handles[i].state != HandleState::Free && self.handles[i].handle_id == handle_id
            {
                return Some(i);
            }
        }
        None
    }
}

impl Default for PrimeRegistry {
    fn default() -> Self {
        Self::new()
    }
}
