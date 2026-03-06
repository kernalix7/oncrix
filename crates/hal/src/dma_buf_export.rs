// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DMA buffer export/import framework.
//!
//! Provides a mechanism for sharing DMA-capable buffers between devices and
//! subsystems without copying. A `DmaBuf` wraps a physical memory region and
//! exposes map/unmap, CPU-access begin/end, and scatter-gather table export
//! operations. Attachments track which devices are currently using a buffer.
//!
//! # Usage
//!
//! 1. An exporter creates a [`DmaBuf`] via [`DmaBuf::new`].
//! 2. Importers call [`DmaBuf::attach`] to record interest.
//! 3. The importer maps the buffer with [`DmaBuf::map_attachment`].
//! 4. CPU access is serialized with [`DmaBuf::begin_cpu_access`] /
//!    [`DmaBuf::end_cpu_access`].
//!
//! Reference: Linux `drivers/dma-buf/dma-buf.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of attachments per DMA buffer.
const MAX_ATTACHMENTS: usize = 8;

/// Maximum number of scatter-gather segments per buffer.
const MAX_SG_ENTRIES: usize = 16;

/// Maximum number of DMA buffers tracked globally.
const MAX_DMA_BUFS: usize = 32;

// ---------------------------------------------------------------------------
// Scatter-Gather
// ---------------------------------------------------------------------------

/// A single scatter-gather segment (physical address + length).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct SgEntry {
    /// Physical address of this segment.
    pub phys_addr: u64,
    /// Length of this segment in bytes.
    pub length: u32,
    /// Alignment padding.
    pub _pad: u32,
}

/// Scatter-gather table for a DMA buffer.
#[derive(Debug, Clone, Copy)]
pub struct SgTable {
    /// Segment entries.
    pub entries: [SgEntry; MAX_SG_ENTRIES],
    /// Number of valid entries.
    pub nents: usize,
    /// Total byte length across all segments.
    pub total_length: u64,
}

impl SgTable {
    /// Create an empty scatter-gather table.
    pub const fn new() -> Self {
        Self {
            entries: [SgEntry {
                phys_addr: 0,
                length: 0,
                _pad: 0,
            }; MAX_SG_ENTRIES],
            nents: 0,
            total_length: 0,
        }
    }

    /// Append a segment.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn add_entry(&mut self, phys_addr: u64, length: u32) -> Result<()> {
        if self.nents >= MAX_SG_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.nents] = SgEntry {
            phys_addr,
            length,
            _pad: 0,
        };
        self.nents += 1;
        self.total_length += u64::from(length);
        Ok(())
    }
}

impl Default for SgTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DMA Direction
// ---------------------------------------------------------------------------

/// Direction of a DMA transfer (mirrors Linux dma_data_direction).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDirection {
    /// Data moves from device to memory.
    ToDevice,
    /// Data moves from memory to device.
    FromDevice,
    /// Bidirectional transfer.
    Bidirectional,
    /// No data movement (metadata-only).
    None,
}

// ---------------------------------------------------------------------------
// Attachment
// ---------------------------------------------------------------------------

/// A device attachment to a DMA buffer.
#[derive(Debug, Clone, Copy)]
pub struct DmaBufAttachment {
    /// Logical device identifier (e.g. PCI BDF encoded as u32).
    pub device_id: u32,
    /// Direction this attachment was mapped for.
    pub direction: DmaDirection,
    /// Whether this attachment has an active mapping.
    pub mapped: bool,
    /// Scatter-gather table for this attachment's mapping.
    pub sgt: SgTable,
}

impl DmaBufAttachment {
    /// Create a new unmapped attachment.
    pub const fn new(device_id: u32) -> Self {
        Self {
            device_id,
            direction: DmaDirection::None,
            mapped: false,
            sgt: SgTable::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// DMA Buffer
// ---------------------------------------------------------------------------

/// File descriptor handle for a DMA buffer (simplified as a u32 index).
pub type DmaBufFd = u32;

/// Flags for CPU access to a DMA buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuAccessFlags {
    /// CPU will read the buffer.
    Read,
    /// CPU will write the buffer.
    Write,
    /// CPU will read and write the buffer.
    ReadWrite,
}

/// A shared DMA buffer that can be exported to and imported by multiple devices.
#[derive(Debug)]
pub struct DmaBuf {
    /// Unique file descriptor / handle assigned at creation.
    pub fd: DmaBufFd,
    /// Physical base address of the buffer.
    pub phys_base: u64,
    /// Buffer size in bytes.
    pub size: usize,
    /// Identifier of the exporting device.
    pub exporter_id: u32,
    /// Pre-built scatter-gather table from the exporter.
    pub sgt: SgTable,
    /// Active attachments.
    attachments: [Option<DmaBufAttachment>; MAX_ATTACHMENTS],
    /// Number of active attachments.
    attachment_count: usize,
    /// Whether a CPU access session is active.
    cpu_access_active: bool,
    /// Reference count (number of importers + 1 for exporter).
    ref_count: u32,
}

impl DmaBuf {
    /// Create a new DMA buffer for a contiguous physical region.
    ///
    /// # Arguments
    ///
    /// * `fd` — unique handle assigned by the exporter.
    /// * `phys_base` — physical base address.
    /// * `size` — buffer size in bytes.
    /// * `exporter_id` — device ID of the exporter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `size` is zero.
    pub fn new(fd: DmaBufFd, phys_base: u64, size: usize, exporter_id: u32) -> Result<Self> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        let mut sgt = SgTable::new();
        // For a contiguous buffer the entire region is one SG entry.
        sgt.add_entry(phys_base, size as u32)?;

        Ok(Self {
            fd,
            phys_base,
            size,
            exporter_id,
            sgt,
            attachments: [const { None }; MAX_ATTACHMENTS],
            attachment_count: 0,
            cpu_access_active: false,
            ref_count: 1,
        })
    }

    /// Attach a device to this DMA buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the attachment table is full.
    /// Returns [`Error::AlreadyExists`] if the device is already attached.
    pub fn attach(&mut self, device_id: u32) -> Result<()> {
        // Check for duplicate.
        for slot in self.attachments.iter().flatten() {
            if slot.device_id == device_id {
                return Err(Error::AlreadyExists);
            }
        }
        let idx = self
            .attachments
            .iter()
            .position(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;
        self.attachments[idx] = Some(DmaBufAttachment::new(device_id));
        self.attachment_count += 1;
        self.ref_count += 1;
        Ok(())
    }

    /// Detach a device from this DMA buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the device is not attached.
    pub fn detach(&mut self, device_id: u32) -> Result<()> {
        let idx = self
            .attachments
            .iter()
            .position(|s| s.map_or(false, |a| a.device_id == device_id))
            .ok_or(Error::NotFound)?;
        self.attachments[idx] = None;
        self.attachment_count -= 1;
        if self.ref_count > 0 {
            self.ref_count -= 1;
        }
        Ok(())
    }

    /// Map a device attachment and return a reference to its SG table.
    ///
    /// Copies the buffer's SG table into the attachment for use by the device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `device_id` has not been attached.
    /// Returns [`Error::Busy`] if the attachment is already mapped.
    pub fn map_attachment(&mut self, device_id: u32, direction: DmaDirection) -> Result<SgTable> {
        let idx = self
            .attachments
            .iter()
            .position(|s| s.map_or(false, |a| a.device_id == device_id))
            .ok_or(Error::NotFound)?;
        let att = self.attachments[idx].as_mut().ok_or(Error::NotFound)?;
        if att.mapped {
            return Err(Error::Busy);
        }
        att.direction = direction;
        att.mapped = true;
        att.sgt = self.sgt;
        Ok(att.sgt)
    }

    /// Unmap a device attachment.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `device_id` is not attached.
    /// Returns [`Error::InvalidArgument`] if the attachment is not mapped.
    pub fn unmap_attachment(&mut self, device_id: u32) -> Result<()> {
        let idx = self
            .attachments
            .iter()
            .position(|s| s.map_or(false, |a| a.device_id == device_id))
            .ok_or(Error::NotFound)?;
        let att = self.attachments[idx].as_mut().ok_or(Error::NotFound)?;
        if !att.mapped {
            return Err(Error::InvalidArgument);
        }
        att.mapped = false;
        att.direction = DmaDirection::None;
        Ok(())
    }

    /// Begin CPU access to the buffer (serializes with DMA).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if a CPU access session is already active.
    pub fn begin_cpu_access(&mut self, _flags: CpuAccessFlags) -> Result<()> {
        if self.cpu_access_active {
            return Err(Error::Busy);
        }
        self.cpu_access_active = true;
        Ok(())
    }

    /// End a CPU access session, allowing DMA to resume.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if no CPU access session is active.
    pub fn end_cpu_access(&mut self) -> Result<()> {
        if !self.cpu_access_active {
            return Err(Error::InvalidArgument);
        }
        self.cpu_access_active = false;
        Ok(())
    }

    /// Returns the current reference count.
    pub fn ref_count(&self) -> u32 {
        self.ref_count
    }

    /// Returns the number of active attachments.
    pub fn attachment_count(&self) -> usize {
        self.attachment_count
    }

    /// Export the buffer's scatter-gather table.
    pub fn export_sg(&self) -> &SgTable {
        &self.sgt
    }
}

// ---------------------------------------------------------------------------
// Global DMA Buffer Registry
// ---------------------------------------------------------------------------

/// Registry of all exported DMA buffers.
pub struct DmaBufRegistry {
    bufs: [Option<DmaBuf>; MAX_DMA_BUFS],
    count: usize,
    next_fd: DmaBufFd,
}

impl DmaBufRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const NONE: Option<DmaBuf> = None;
        Self {
            bufs: [NONE; MAX_DMA_BUFS],
            count: 0,
            next_fd: 1,
        }
    }

    /// Export a new DMA buffer and return its file descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn export(&mut self, phys_base: u64, size: usize, exporter_id: u32) -> Result<DmaBufFd> {
        let idx = self
            .bufs
            .iter()
            .position(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;
        let fd = self.next_fd;
        self.next_fd = self.next_fd.wrapping_add(1);
        self.bufs[idx] = Some(DmaBuf::new(fd, phys_base, size, exporter_id)?);
        self.count += 1;
        Ok(fd)
    }

    /// Look up a buffer by file descriptor (mutable).
    pub fn get_mut(&mut self, fd: DmaBufFd) -> Option<&mut DmaBuf> {
        self.bufs
            .iter_mut()
            .filter_map(|s| s.as_mut())
            .find(|b| b.fd == fd)
    }

    /// Look up a buffer by file descriptor (immutable).
    pub fn get(&self, fd: DmaBufFd) -> Option<&DmaBuf> {
        self.bufs
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|b| b.fd == fd)
    }

    /// Release a buffer (remove when ref_count reaches zero).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the fd is unknown.
    /// Returns [`Error::Busy`] if other importers still hold references.
    pub fn release(&mut self, fd: DmaBufFd) -> Result<()> {
        let idx = self
            .bufs
            .iter()
            .position(|s| s.as_ref().map_or(false, |b| b.fd == fd))
            .ok_or(Error::NotFound)?;
        let buf = self.bufs[idx].as_ref().ok_or(Error::NotFound)?;
        if buf.ref_count > 1 {
            return Err(Error::Busy);
        }
        self.bufs[idx] = None;
        self.count -= 1;
        Ok(())
    }

    /// Returns the number of exported buffers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no buffers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for DmaBufRegistry {
    fn default() -> Self {
        Self::new()
    }
}
