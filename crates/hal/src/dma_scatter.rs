// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Scatter-gather DMA list management.
//!
//! Provides abstractions for building and managing scatter-gather (SG) lists
//! used in DMA operations. SG lists allow a single DMA transfer to span
//! multiple non-contiguous memory regions, avoiding the need for bounce buffers.

use oncrix_lib::{Error, Result};

/// Maximum number of scatter-gather entries in a single list.
pub const MAX_SG_ENTRIES: usize = 256;

/// Direction of a DMA transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDirection {
    /// Data flows from device to memory (read from device).
    ToDevice,
    /// Data flows from memory to device (write to device).
    FromDevice,
    /// Bidirectional transfer.
    Bidirectional,
}

/// A single scatter-gather entry describing one contiguous memory segment.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ScatterEntry {
    /// Physical address of this segment.
    pub phys_addr: u64,
    /// Length of this segment in bytes.
    pub length: u32,
    /// Flags for this entry (end-of-list, etc.).
    pub flags: u32,
}

impl ScatterEntry {
    /// Flag indicating this is the last entry in the SG list.
    pub const FLAG_END_OF_LIST: u32 = 1 << 0;
    /// Flag indicating this entry has been mapped for DMA.
    pub const FLAG_MAPPED: u32 = 1 << 1;

    /// Creates a new scatter-gather entry.
    ///
    /// # Arguments
    /// * `phys_addr` — Physical base address of the segment.
    /// * `length` — Length in bytes.
    pub const fn new(phys_addr: u64, length: u32) -> Self {
        Self {
            phys_addr,
            length,
            flags: 0,
        }
    }

    /// Returns true if this entry is the last in the SG list.
    pub fn is_end(&self) -> bool {
        self.flags & Self::FLAG_END_OF_LIST != 0
    }

    /// Returns true if this entry has been mapped for DMA.
    pub fn is_mapped(&self) -> bool {
        self.flags & Self::FLAG_MAPPED != 0
    }

    /// Marks this entry as the end of the list.
    pub fn mark_end(&mut self) {
        self.flags |= Self::FLAG_END_OF_LIST;
    }

    /// Marks this entry as mapped.
    pub fn mark_mapped(&mut self) {
        self.flags |= Self::FLAG_MAPPED;
    }
}

impl Default for ScatterEntry {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

/// A scatter-gather list for DMA transfers.
///
/// Manages a fixed-size array of scatter-gather entries that together
/// describe a (potentially non-contiguous) memory region for DMA.
pub struct ScatterList {
    entries: [ScatterEntry; MAX_SG_ENTRIES],
    count: usize,
    direction: DmaDirection,
    total_bytes: u64,
}

impl ScatterList {
    /// Creates a new empty scatter-gather list.
    pub const fn new(direction: DmaDirection) -> Self {
        Self {
            entries: [const { ScatterEntry::new(0, 0) }; MAX_SG_ENTRIES],
            count: 0,
            direction,
            total_bytes: 0,
        }
    }

    /// Returns the number of entries in this list.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns the total byte count across all entries.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Returns the DMA direction for this list.
    pub fn direction(&self) -> DmaDirection {
        self.direction
    }

    /// Returns true if the list has no entries.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Appends a new entry to the scatter-gather list.
    ///
    /// # Errors
    /// Returns `Error::OutOfMemory` if the list is full.
    pub fn append(&mut self, phys_addr: u64, length: u32) -> Result<()> {
        if self.count >= MAX_SG_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        if length == 0 {
            return Err(Error::InvalidArgument);
        }
        self.entries[self.count] = ScatterEntry::new(phys_addr, length);
        self.total_bytes += length as u64;
        self.count += 1;
        Ok(())
    }

    /// Returns a slice over the active entries.
    pub fn entries(&self) -> &[ScatterEntry] {
        &self.entries[..self.count]
    }

    /// Returns a mutable slice over the active entries.
    pub fn entries_mut(&mut self) -> &mut [ScatterEntry] {
        &mut self.entries[..self.count]
    }

    /// Marks the last entry with the end-of-list flag.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if the list is empty.
    pub fn finalize(&mut self) -> Result<()> {
        if self.count == 0 {
            return Err(Error::InvalidArgument);
        }
        self.entries[self.count - 1].mark_end();
        Ok(())
    }

    /// Resets the list, removing all entries.
    pub fn reset(&mut self) {
        self.count = 0;
        self.total_bytes = 0;
    }

    /// Returns the entry at the given index.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if the index is out of range.
    pub fn get(&self, index: usize) -> Result<&ScatterEntry> {
        if index >= self.count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.entries[index])
    }
}

impl Default for ScatterList {
    fn default() -> Self {
        Self::new(DmaDirection::Bidirectional)
    }
}

/// Statistics for scatter-gather DMA operations.
#[derive(Debug, Default, Clone, Copy)]
pub struct SgStats {
    /// Total number of SG lists created.
    pub lists_created: u64,
    /// Total number of SG lists mapped.
    pub lists_mapped: u64,
    /// Total bytes transferred via SG DMA.
    pub bytes_transferred: u64,
    /// Number of mapping failures.
    pub map_errors: u64,
}

impl SgStats {
    /// Creates a new zeroed statistics structure.
    pub const fn new() -> Self {
        Self {
            lists_created: 0,
            lists_mapped: 0,
            bytes_transferred: 0,
            map_errors: 0,
        }
    }
}

/// Scatter-gather DMA controller interface.
///
/// Represents a DMA controller capable of scatter-gather transfers.
pub struct SgDmaController {
    base_addr: u64,
    channel_count: u8,
    stats: SgStats,
}

impl SgDmaController {
    /// Creates a new SG DMA controller instance.
    ///
    /// # Arguments
    /// * `base_addr` — MMIO base address of the DMA controller registers.
    /// * `channel_count` — Number of DMA channels supported.
    pub const fn new(base_addr: u64, channel_count: u8) -> Self {
        Self {
            base_addr,
            channel_count,
            stats: SgStats::new(),
        }
    }

    /// Initializes the DMA controller hardware.
    ///
    /// # Errors
    /// Returns `Error::IoError` if hardware initialization fails.
    pub fn init(&mut self) -> Result<()> {
        if self.base_addr == 0 {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO write to DMA controller reset register at known-valid base_addr.
        unsafe {
            let reset_reg = self.base_addr as *mut u32;
            reset_reg.write_volatile(0x1); // Issue soft reset
        }
        Ok(())
    }

    /// Programs a DMA channel with an SG list and starts the transfer.
    ///
    /// # Arguments
    /// * `channel` — Channel index (0..channel_count).
    /// * `sg` — The scatter-gather list to program.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if channel is out of range or list is empty.
    pub fn start_transfer(&mut self, channel: u8, sg: &mut ScatterList) -> Result<()> {
        if (channel as usize) >= self.channel_count as usize {
            return Err(Error::InvalidArgument);
        }
        if sg.is_empty() {
            return Err(Error::InvalidArgument);
        }
        sg.finalize()?;

        // SAFETY: MMIO writes to channel descriptor registers. base_addr is valid
        // and channel is bounds-checked above.
        unsafe {
            let chan_base = (self.base_addr + 0x100 + (channel as u64) * 0x40) as *mut u32;
            // Write the physical address of first SG entry
            chan_base.write_volatile((sg.entries[0].phys_addr & 0xFFFF_FFFF) as u32);
            chan_base
                .add(1)
                .write_volatile((sg.entries[0].phys_addr >> 32) as u32);
            // Write entry count
            chan_base.add(2).write_volatile(sg.count() as u32);
            // Start the transfer
            chan_base.add(3).write_volatile(0x1);
        }

        self.stats.lists_mapped += 1;
        self.stats.bytes_transferred += sg.total_bytes();
        Ok(())
    }

    /// Returns the current statistics snapshot.
    pub fn stats(&self) -> SgStats {
        self.stats
    }

    /// Returns the number of DMA channels.
    pub fn channel_count(&self) -> u8 {
        self.channel_count
    }

    /// Checks whether a transfer on the given channel has completed.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if channel is out of range.
    /// Returns `Error::Busy` if the transfer is still in progress.
    pub fn poll_completion(&self, channel: u8) -> Result<()> {
        if (channel as usize) >= self.channel_count as usize {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO read from channel status register. Address is valid and
        // channel index is bounds-checked above.
        let status = unsafe {
            let status_reg =
                (self.base_addr + 0x100 + (channel as u64) * 0x40 + 0x10) as *const u32;
            status_reg.read_volatile()
        };
        if status & 0x2 == 0 {
            Err(Error::Busy)
        } else {
            Ok(())
        }
    }
}

impl Default for SgDmaController {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

/// Builds a scatter-gather list from a slice of (address, length) pairs.
///
/// # Errors
/// Returns `Error::OutOfMemory` if there are too many entries.
/// Returns `Error::InvalidArgument` if any length is zero.
pub fn build_sg_list(direction: DmaDirection, segments: &[(u64, u32)]) -> Result<ScatterList> {
    let mut sg = ScatterList::new(direction);
    for &(addr, len) in segments {
        sg.append(addr, len)?;
    }
    Ok(sg)
}

/// Returns the total byte count for a set of scatter-gather segments.
pub fn sg_total_bytes(segments: &[(u64, u32)]) -> u64 {
    segments.iter().map(|&(_, len)| len as u64).sum()
}

/// Validates that all entries in an SG list are properly aligned.
///
/// # Arguments
/// * `sg` — The scatter-gather list to validate.
/// * `alignment` — Required alignment in bytes (must be a power of two).
///
/// # Errors
/// Returns `Error::InvalidArgument` if alignment is not a power of two or any
/// entry is misaligned.
pub fn validate_sg_alignment(sg: &ScatterList, alignment: u32) -> Result<()> {
    if alignment == 0 || (alignment & (alignment - 1)) != 0 {
        return Err(Error::InvalidArgument);
    }
    let mask = (alignment - 1) as u64;
    for entry in sg.entries() {
        if entry.phys_addr & mask != 0 {
            return Err(Error::InvalidArgument);
        }
    }
    Ok(())
}
