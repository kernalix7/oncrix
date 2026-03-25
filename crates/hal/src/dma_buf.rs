// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DMA buffer sharing framework.
//!
//! Implements a dma-buf like abstraction for sharing DMA-capable buffers
//! between devices (exporters) and consumers (importers). Each buffer
//! carries a scatter-gather list of physically-contiguous segments,
//! supports import/export semantics with attachment tracking, and
//! provides synchronisation fences for producer/consumer ordering.
//!
//! # Architecture
//!
//! - [`DmaBuf`] — the exported buffer handle with SG list and metadata
//! - [`DmaBufAttachment`] — an importer's reference to a dma-buf
//! - [`ScatterGatherEntry`] — a single physical segment
//! - [`DmaBufFence`] — signalling primitive for async completion
//! - [`DmaBufRegistry`] — system-wide registry of exported buffers
//!
//! # Usage
//!
//! ```ignore
//! let mut registry = DmaBufRegistry::new();
//! let buf = DmaBuf::new(0, 4096, DmaBufFlags::READ_WRITE);
//! registry.register(buf)?;
//! let att = registry.attach(0, 1)?;
//! ```

extern crate alloc;

use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum scatter-gather entries per buffer.
const MAX_SG_ENTRIES: usize = 64;

/// Maximum attachments per buffer.
const MAX_ATTACHMENTS: usize = 16;

/// Maximum fences per buffer.
const MAX_FENCES: usize = 8;

/// Maximum buffers in the global registry.
const MAX_BUFFERS: usize = 64;

/// Page size for alignment calculations.
const PAGE_SIZE: usize = 4096;

// -------------------------------------------------------------------
// DmaBufFlags
// -------------------------------------------------------------------

/// Access permission flags for a DMA buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaBufFlags(u32);

impl DmaBufFlags {
    /// No access.
    pub const NONE: Self = Self(0);
    /// Read access.
    pub const READ: Self = Self(1 << 0);
    /// Write access.
    pub const WRITE: Self = Self(1 << 1);
    /// Read and write access.
    pub const READ_WRITE: Self = Self(0x3);

    /// Returns `true` if read permission is set.
    pub fn can_read(self) -> bool {
        self.0 & Self::READ.0 != 0
    }

    /// Returns `true` if write permission is set.
    pub fn can_write(self) -> bool {
        self.0 & Self::WRITE.0 != 0
    }

    /// Returns the raw flag bits.
    pub fn bits(self) -> u32 {
        self.0
    }
}

impl Default for DmaBufFlags {
    fn default() -> Self {
        Self::NONE
    }
}

// -------------------------------------------------------------------
// SyncDirection
// -------------------------------------------------------------------

/// Direction of a CPU/device sync operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SyncDirection {
    /// Sync for CPU read after device write.
    #[default]
    ForCpu,
    /// Sync for device read after CPU write.
    ForDevice,
}

// -------------------------------------------------------------------
// ScatterGatherEntry
// -------------------------------------------------------------------

/// A single physically-contiguous segment in a scatter-gather list.
///
/// Each entry describes one contiguous physical memory region that
/// is part of a larger (potentially discontiguous) DMA buffer.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ScatterGatherEntry {
    /// Physical base address of this segment.
    pub phys_addr: u64,
    /// Length of this segment in bytes.
    pub length: u32,
    /// Offset within the overall buffer (byte position).
    pub offset: u32,
}

impl Default for ScatterGatherEntry {
    fn default() -> Self {
        Self::new()
    }
}

impl ScatterGatherEntry {
    /// Creates a zeroed scatter-gather entry.
    pub const fn new() -> Self {
        Self {
            phys_addr: 0,
            length: 0,
            offset: 0,
        }
    }

    /// Creates an entry from physical address and length.
    pub const fn from_phys(phys_addr: u64, length: u32, offset: u32) -> Self {
        Self {
            phys_addr,
            length,
            offset,
        }
    }

    /// Returns `true` if this entry is empty / unused.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Returns the end address (exclusive) of this segment.
    pub fn end_addr(&self) -> u64 {
        self.phys_addr.wrapping_add(self.length as u64)
    }
}

// -------------------------------------------------------------------
// ScatterGatherList
// -------------------------------------------------------------------

/// A scatter-gather list describing the physical layout of a DMA buffer.
pub struct ScatterGatherList {
    /// The segment entries.
    entries: [ScatterGatherEntry; MAX_SG_ENTRIES],
    /// Number of valid entries.
    count: usize,
}

impl Default for ScatterGatherList {
    fn default() -> Self {
        Self::new()
    }
}

impl ScatterGatherList {
    /// Creates an empty scatter-gather list.
    pub const fn new() -> Self {
        Self {
            entries: [ScatterGatherEntry::new(); MAX_SG_ENTRIES],
            count: 0,
        }
    }

    /// Adds a segment to the list.
    pub fn add(&mut self, phys_addr: u64, length: u32) -> Result<()> {
        if self.count >= MAX_SG_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let offset = self.total_size() as u32;
        self.entries[self.count] = ScatterGatherEntry::from_phys(phys_addr, length, offset);
        self.count += 1;
        Ok(())
    }

    /// Returns the number of valid entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the list has no entries.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the entry at the given index.
    pub fn get(&self, index: usize) -> Option<&ScatterGatherEntry> {
        if index < self.count {
            Some(&self.entries[index])
        } else {
            None
        }
    }

    /// Returns the total size in bytes across all segments.
    pub fn total_size(&self) -> usize {
        let mut total: usize = 0;
        for i in 0..self.count {
            total = total.wrapping_add(self.entries[i].length as usize);
        }
        total
    }

    /// Returns an iterator over valid entries.
    pub fn iter(&self) -> ScatterGatherIter<'_> {
        ScatterGatherIter {
            list: self,
            index: 0,
        }
    }
}

/// Iterator over scatter-gather entries.
pub struct ScatterGatherIter<'a> {
    list: &'a ScatterGatherList,
    index: usize,
}

impl<'a> Iterator for ScatterGatherIter<'a> {
    type Item = &'a ScatterGatherEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.list.count {
            let entry = &self.list.entries[self.index];
            self.index += 1;
            Some(entry)
        } else {
            None
        }
    }
}

// -------------------------------------------------------------------
// FenceState
// -------------------------------------------------------------------

/// Lifecycle state of a DMA fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FenceState {
    /// Fence has not been signalled.
    #[default]
    Unsignalled,
    /// Fence has been signalled (operation complete).
    Signalled,
    /// Fence was signalled with an error.
    Error,
}

// -------------------------------------------------------------------
// DmaBufFence
// -------------------------------------------------------------------

/// A synchronisation fence for DMA buffer operations.
///
/// Fences are used to order producer/consumer access to a shared
/// buffer. The exporter signals the fence when the GPU/device has
/// finished writing, and importers wait on the fence before reading.
pub struct DmaBufFence {
    /// Unique fence sequence number.
    pub seqno: u64,
    /// Context (e.g., device or ring) that owns this fence.
    pub context: u64,
    /// Current state.
    pub state: FenceState,
    /// Timestamp (monotonic) when the fence was created.
    pub timestamp: u64,
    /// Timestamp when the fence was signalled (0 if unsignalled).
    pub signal_timestamp: u64,
}

impl Default for DmaBufFence {
    fn default() -> Self {
        Self::new()
    }
}

impl DmaBufFence {
    /// Creates a new unsignalled fence.
    pub const fn new() -> Self {
        Self {
            seqno: 0,
            context: 0,
            state: FenceState::Unsignalled,
            timestamp: 0,
            signal_timestamp: 0,
        }
    }

    /// Creates a fence with the given sequence number and context.
    pub const fn with_seqno(seqno: u64, context: u64, timestamp: u64) -> Self {
        Self {
            seqno,
            context,
            state: FenceState::Unsignalled,
            timestamp,
            signal_timestamp: 0,
        }
    }

    /// Returns `true` if the fence has been signalled.
    pub fn is_signalled(&self) -> bool {
        self.state == FenceState::Signalled || self.state == FenceState::Error
    }

    /// Signals the fence as completed.
    pub fn signal(&mut self, timestamp: u64) {
        self.state = FenceState::Signalled;
        self.signal_timestamp = timestamp;
    }

    /// Signals the fence as completed with an error.
    pub fn signal_error(&mut self, timestamp: u64) {
        self.state = FenceState::Error;
        self.signal_timestamp = timestamp;
    }

    /// Waits for the fence by polling (non-blocking check).
    ///
    /// Returns `Ok(true)` if signalled, `Ok(false)` if still pending.
    pub fn poll(&self) -> Result<bool> {
        Ok(self.is_signalled())
    }
}

// -------------------------------------------------------------------
// DmaBufAttachment
// -------------------------------------------------------------------

/// Represents an importer's attachment to a shared DMA buffer.
///
/// Each consuming device creates an attachment to indicate its
/// interest in the buffer. The exporter uses attachment information
/// to decide where to place the buffer's memory.
pub struct DmaBufAttachment {
    /// Identifier of the attached device.
    pub device_id: u32,
    /// Buffer identifier this attachment refers to.
    pub buf_id: u32,
    /// Whether the attachment has mapped the SG table.
    pub mapped: bool,
    /// Access flags for this attachment.
    pub flags: DmaBufFlags,
    /// Device-specific private data.
    pub priv_data: u64,
}

impl Default for DmaBufAttachment {
    fn default() -> Self {
        Self::new()
    }
}

impl DmaBufAttachment {
    /// Creates an empty attachment.
    pub const fn new() -> Self {
        Self {
            device_id: 0,
            buf_id: 0,
            mapped: false,
            flags: DmaBufFlags::NONE,
            priv_data: 0,
        }
    }

    /// Creates an attachment for a specific device and buffer.
    pub const fn for_device(device_id: u32, buf_id: u32, flags: DmaBufFlags) -> Self {
        Self {
            device_id,
            buf_id,
            mapped: false,
            flags,
            priv_data: 0,
        }
    }

    /// Returns `true` if this attachment slot is unused.
    pub fn is_empty(&self) -> bool {
        self.device_id == 0 && self.buf_id == 0
    }

    /// Maps the scatter-gather table for device access.
    pub fn map(&mut self) -> Result<()> {
        if self.mapped {
            return Err(Error::AlreadyExists);
        }
        self.mapped = true;
        Ok(())
    }

    /// Unmaps the scatter-gather table.
    pub fn unmap(&mut self) -> Result<()> {
        if !self.mapped {
            return Err(Error::InvalidArgument);
        }
        self.mapped = false;
        Ok(())
    }
}

// -------------------------------------------------------------------
// MmapFlags
// -------------------------------------------------------------------

/// Flags for mmap operations on DMA buffers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmapFlags(u32);

impl MmapFlags {
    /// Shared mapping (changes visible to all mappers).
    pub const SHARED: Self = Self(1 << 0);
    /// Private copy-on-write mapping.
    pub const PRIVATE: Self = Self(1 << 1);
    /// Mapping is write-combined (for GPU buffers).
    pub const WRITE_COMBINE: Self = Self(1 << 2);
    /// Mapping is cached.
    pub const CACHED: Self = Self(1 << 3);

    /// Returns the raw bits.
    pub fn bits(self) -> u32 {
        self.0
    }

    /// Returns `true` if this is a shared mapping.
    pub fn is_shared(self) -> bool {
        self.0 & Self::SHARED.0 != 0
    }
}

impl Default for MmapFlags {
    fn default() -> Self {
        Self::SHARED
    }
}

// -------------------------------------------------------------------
// MmapRegion
// -------------------------------------------------------------------

/// Describes a virtual mapping of a DMA buffer into a process address space.
pub struct MmapRegion {
    /// Virtual address of the mapping.
    pub vaddr: u64,
    /// Length of the mapping in bytes.
    pub length: usize,
    /// Page offset into the buffer.
    pub page_offset: usize,
    /// Mapping flags.
    pub flags: MmapFlags,
    /// Whether the mapping is currently active.
    pub active: bool,
}

impl Default for MmapRegion {
    fn default() -> Self {
        Self::new()
    }
}

impl MmapRegion {
    /// Creates an empty (inactive) mmap region.
    pub const fn new() -> Self {
        Self {
            vaddr: 0,
            length: 0,
            page_offset: 0,
            flags: MmapFlags::SHARED,
            active: false,
        }
    }

    /// Creates a new mapping.
    pub fn create(vaddr: u64, length: usize, flags: MmapFlags) -> Self {
        Self {
            vaddr,
            length,
            page_offset: 0,
            flags,
            active: true,
        }
    }

    /// Tears down the mapping.
    pub fn destroy(&mut self) {
        self.active = false;
        self.vaddr = 0;
        self.length = 0;
    }
}

// -------------------------------------------------------------------
// DmaBuf
// -------------------------------------------------------------------

/// A shared DMA buffer that can be exported by one device and
/// imported by one or more other devices.
///
/// The buffer owns a scatter-gather list describing its physical
/// pages, a set of attachments (one per importer), and a set of
/// fences for synchronisation.
pub struct DmaBuf {
    /// Unique buffer identifier (assigned by the exporter).
    pub id: u32,
    /// Total buffer size in bytes (page-aligned).
    pub size: usize,
    /// Access flags.
    pub flags: DmaBufFlags,
    /// Exporter device identifier.
    pub exporter_id: u32,
    /// Reference count (number of active importers + exporter).
    pub refcount: u32,
    /// Scatter-gather list for the buffer's physical pages.
    sg_list: ScatterGatherList,
    /// Attached importers.
    attachments: [DmaBufAttachment; MAX_ATTACHMENTS],
    /// Number of active attachments.
    attachment_count: usize,
    /// Synchronisation fences.
    fences: [DmaBufFence; MAX_FENCES],
    /// Number of active fences.
    fence_count: usize,
    /// Current mmap region (if any).
    mmap: MmapRegion,
}

impl Default for DmaBuf {
    fn default() -> Self {
        Self::empty()
    }
}

impl DmaBuf {
    /// Creates an empty, invalid DMA buffer.
    pub const fn empty() -> Self {
        Self {
            id: 0,
            size: 0,
            flags: DmaBufFlags::NONE,
            exporter_id: 0,
            refcount: 0,
            sg_list: ScatterGatherList::new(),
            attachments: [const { DmaBufAttachment::new() }; MAX_ATTACHMENTS],
            attachment_count: 0,
            fences: [const { DmaBufFence::new() }; MAX_FENCES],
            fence_count: 0,
            mmap: MmapRegion::new(),
        }
    }

    /// Creates a new DMA buffer with the given id, size, and flags.
    ///
    /// The size is rounded up to the nearest page boundary.
    pub fn new(id: u32, size: usize, flags: DmaBufFlags) -> Self {
        let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        Self {
            id,
            size: aligned_size,
            flags,
            exporter_id: 0,
            refcount: 1,
            sg_list: ScatterGatherList::new(),
            attachments: [const { DmaBufAttachment::new() }; MAX_ATTACHMENTS],
            attachment_count: 0,
            fences: [const { DmaBufFence::new() }; MAX_FENCES],
            fence_count: 0,
            mmap: MmapRegion::new(),
        }
    }

    /// Returns `true` if this buffer slot is unused.
    pub fn is_empty(&self) -> bool {
        self.id == 0 && self.size == 0
    }

    /// Sets the exporter device identifier.
    pub fn set_exporter(&mut self, device_id: u32) {
        self.exporter_id = device_id;
    }

    // --- Scatter-Gather ---

    /// Adds a physical segment to the buffer's scatter-gather list.
    pub fn add_sg_entry(&mut self, phys_addr: u64, length: u32) -> Result<()> {
        self.sg_list.add(phys_addr, length)
    }

    /// Returns a reference to the scatter-gather list.
    pub fn sg_list(&self) -> &ScatterGatherList {
        &self.sg_list
    }

    /// Validates that the scatter-gather list covers the full buffer size.
    pub fn validate_sg(&self) -> Result<()> {
        let total = self.sg_list.total_size();
        if total < self.size {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    // --- Attachments ---

    /// Attaches a device to this buffer (import).
    pub fn attach(&mut self, device_id: u32, flags: DmaBufFlags) -> Result<usize> {
        if self.attachment_count >= MAX_ATTACHMENTS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.attachment_count;
        self.attachments[idx] = DmaBufAttachment::for_device(device_id, self.id, flags);
        self.attachment_count += 1;
        self.refcount = self.refcount.saturating_add(1);
        Ok(idx)
    }

    /// Detaches a device from this buffer.
    pub fn detach(&mut self, device_id: u32) -> Result<()> {
        let mut found = false;
        for i in 0..self.attachment_count {
            if self.attachments[i].device_id == device_id {
                // Shift remaining attachments
                let count = self.attachment_count;
                for j in i..count.saturating_sub(1) {
                    let src_dev = self.attachments[j + 1].device_id;
                    let src_buf = self.attachments[j + 1].buf_id;
                    let src_mapped = self.attachments[j + 1].mapped;
                    let src_flags = self.attachments[j + 1].flags;
                    let src_priv = self.attachments[j + 1].priv_data;
                    self.attachments[j].device_id = src_dev;
                    self.attachments[j].buf_id = src_buf;
                    self.attachments[j].mapped = src_mapped;
                    self.attachments[j].flags = src_flags;
                    self.attachments[j].priv_data = src_priv;
                }
                self.attachment_count = self.attachment_count.saturating_sub(1);
                self.attachments[self.attachment_count] = DmaBufAttachment::new();
                self.refcount = self.refcount.saturating_sub(1);
                found = true;
                break;
            }
        }
        if found { Ok(()) } else { Err(Error::NotFound) }
    }

    /// Returns the number of active attachments.
    pub fn attachment_count(&self) -> usize {
        self.attachment_count
    }

    /// Returns the attachment at the given index.
    pub fn get_attachment(&self, index: usize) -> Option<&DmaBufAttachment> {
        if index < self.attachment_count {
            Some(&self.attachments[index])
        } else {
            None
        }
    }

    /// Maps the SG table for a specific attachment.
    pub fn map_attachment(&mut self, index: usize) -> Result<()> {
        if index >= self.attachment_count {
            return Err(Error::NotFound);
        }
        self.attachments[index].map()
    }

    /// Unmaps the SG table for a specific attachment.
    pub fn unmap_attachment(&mut self, index: usize) -> Result<()> {
        if index >= self.attachment_count {
            return Err(Error::NotFound);
        }
        self.attachments[index].unmap()
    }

    // --- Fences ---

    /// Adds a synchronisation fence to this buffer.
    pub fn add_fence(&mut self, seqno: u64, context: u64, timestamp: u64) -> Result<usize> {
        if self.fence_count >= MAX_FENCES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.fence_count;
        self.fences[idx] = DmaBufFence::with_seqno(seqno, context, timestamp);
        self.fence_count += 1;
        Ok(idx)
    }

    /// Signals a fence by index.
    pub fn signal_fence(&mut self, index: usize, timestamp: u64) -> Result<()> {
        if index >= self.fence_count {
            return Err(Error::NotFound);
        }
        self.fences[index].signal(timestamp);
        Ok(())
    }

    /// Returns `true` if all fences on this buffer are signalled.
    pub fn all_fences_signalled(&self) -> bool {
        for i in 0..self.fence_count {
            if !self.fences[i].is_signalled() {
                return false;
            }
        }
        true
    }

    /// Returns the number of active fences.
    pub fn fence_count(&self) -> usize {
        self.fence_count
    }

    /// Returns the fence at the given index.
    pub fn get_fence(&self, index: usize) -> Option<&DmaBufFence> {
        if index < self.fence_count {
            Some(&self.fences[index])
        } else {
            None
        }
    }

    // --- Sync ---

    /// Begins a CPU/device sync operation.
    ///
    /// This notifies the framework that a sync is needed before
    /// the CPU or device accesses the buffer. On real hardware this
    /// would issue cache maintenance operations.
    pub fn begin_cpu_access(&self, direction: SyncDirection) -> Result<()> {
        if self.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let _ = direction;
        // On real hardware: cache invalidate (ForCpu) or clean (ForDevice)
        Ok(())
    }

    /// Ends a CPU/device sync operation.
    pub fn end_cpu_access(&self, direction: SyncDirection) -> Result<()> {
        if self.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let _ = direction;
        Ok(())
    }

    // --- Mmap ---

    /// Creates a virtual mapping of this buffer.
    pub fn mmap(&mut self, vaddr: u64, length: usize, flags: MmapFlags) -> Result<()> {
        if self.mmap.active {
            return Err(Error::AlreadyExists);
        }
        if length > self.size {
            return Err(Error::InvalidArgument);
        }
        self.mmap = MmapRegion::create(vaddr, length, flags);
        Ok(())
    }

    /// Destroys the virtual mapping.
    pub fn munmap(&mut self) -> Result<()> {
        if !self.mmap.active {
            return Err(Error::InvalidArgument);
        }
        self.mmap.destroy();
        Ok(())
    }

    /// Returns the current mmap region, if active.
    pub fn mmap_region(&self) -> Option<&MmapRegion> {
        if self.mmap.active {
            Some(&self.mmap)
        } else {
            None
        }
    }
}

// -------------------------------------------------------------------
// ExportInfo
// -------------------------------------------------------------------

/// Information returned when a buffer is exported.
pub struct ExportInfo {
    /// The file descriptor (or handle) for the exported buffer.
    pub fd: u32,
    /// Buffer identifier.
    pub buf_id: u32,
    /// Size of the buffer.
    pub size: usize,
    /// Flags.
    pub flags: DmaBufFlags,
}

impl ExportInfo {
    /// Creates export info for a buffer.
    pub const fn new(fd: u32, buf_id: u32, size: usize, flags: DmaBufFlags) -> Self {
        Self {
            fd,
            buf_id,
            size,
            flags,
        }
    }
}

// -------------------------------------------------------------------
// DmaBufRegistry
// -------------------------------------------------------------------

/// System-wide registry of exported DMA buffers.
///
/// Manages buffer lifecycle, provides export/import operations, and
/// tracks all active buffers for cleanup.
pub struct DmaBufRegistry {
    /// Registered buffers.
    buffers: Vec<DmaBuf>,
    /// Next file descriptor for exports.
    next_fd: u32,
}

impl Default for DmaBufRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl DmaBufRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            buffers: Vec::new(),
            next_fd: 100,
        }
    }

    /// Registers a new buffer in the registry.
    pub fn register(&mut self, buf: DmaBuf) -> Result<()> {
        if self.buffers.len() >= MAX_BUFFERS {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate ID
        for existing in self.buffers.iter() {
            if existing.id == buf.id {
                return Err(Error::AlreadyExists);
            }
        }
        self.buffers.push(buf);
        Ok(())
    }

    /// Exports a buffer, returning export info with a file descriptor.
    pub fn export(&mut self, buf_id: u32, flags: DmaBufFlags) -> Result<ExportInfo> {
        let buf = self.get(buf_id)?;
        let size = buf.size;
        let fd = self.next_fd;
        self.next_fd = self.next_fd.wrapping_add(1);
        Ok(ExportInfo::new(fd, buf_id, size, flags))
    }

    /// Imports (attaches) a device to a buffer by buffer ID.
    pub fn attach(&mut self, buf_id: u32, device_id: u32) -> Result<usize> {
        let buf = self.get_mut(buf_id)?;
        buf.attach(device_id, DmaBufFlags::READ_WRITE)
    }

    /// Detaches a device from a buffer.
    pub fn detach(&mut self, buf_id: u32, device_id: u32) -> Result<()> {
        let buf = self.get_mut(buf_id)?;
        buf.detach(device_id)
    }

    /// Returns a reference to a buffer by ID.
    pub fn get(&self, buf_id: u32) -> Result<&DmaBuf> {
        for buf in self.buffers.iter() {
            if buf.id == buf_id {
                return Ok(buf);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a mutable reference to a buffer by ID.
    pub fn get_mut(&mut self, buf_id: u32) -> Result<&mut DmaBuf> {
        for buf in self.buffers.iter_mut() {
            if buf.id == buf_id {
                return Ok(buf);
            }
        }
        Err(Error::NotFound)
    }

    /// Removes a buffer from the registry.
    pub fn unregister(&mut self, buf_id: u32) -> Result<()> {
        let pos = self.buffers.iter().position(|b| b.id == buf_id);
        match pos {
            Some(idx) => {
                self.buffers.remove(idx);
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Returns the number of registered buffers.
    pub fn len(&self) -> usize {
        self.buffers.len()
    }

    /// Returns `true` if no buffers are registered.
    pub fn is_empty(&self) -> bool {
        self.buffers.is_empty()
    }

    /// Collects IDs of buffers whose fences are all signalled.
    pub fn collect_completed_ids(&self) -> Vec<u32> {
        let mut ids = Vec::new();
        for buf in self.buffers.iter() {
            if buf.all_fences_signalled() && buf.fence_count() > 0 {
                ids.push(buf.id);
            }
        }
        ids
    }
}
