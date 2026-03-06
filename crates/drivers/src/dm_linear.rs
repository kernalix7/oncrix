// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Device-mapper linear target.
//!
//! The linear target maps a contiguous range of logical blocks on a
//! virtual device to an offset on an underlying physical device.
//!
//! # Mapping model
//!
//! A `DmLinear` device is composed of one or more [`LinearSegment`]s, each
//! describing:
//!
//! ```text
//! virtual LBA range [start, start+len) → physical_dev[offset, offset+len)
//! ```
//!
//! Segments must not overlap and must together cover a contiguous virtual
//! LBA space starting at 0. Lookups are O(n) in the number of segments.
//!
//! # Use cases
//!
//! - Concatenating multiple block devices into one.
//! - Exposing a sub-range of a block device.
//! - Building higher-level device-mapper targets (LVM, RAID) on top.
//!
//! Reference: Linux `drivers/md/dm-linear.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of segments in a single `DmLinear` device.
pub const DM_LINEAR_MAX_SEGMENTS: usize = 32;

/// Maximum number of `DmLinear` devices in the registry.
pub const MAX_DM_LINEAR_DEVICES: usize = 16;

/// Default block size.
pub const DM_BLOCK_SIZE: u32 = 512;

// ---------------------------------------------------------------------------
// BlockDevice trait
// ---------------------------------------------------------------------------

/// Minimal block device interface used by `DmLinear`.
///
/// Implementors wrap an underlying physical device (NVMe, ATA, RAM disk, etc.).
pub trait BlockDevice {
    /// Read `buf.len()` bytes at byte `offset`.
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<()>;
    /// Write `buf` at byte `offset`.
    fn write(&mut self, offset: u64, buf: &[u8]) -> Result<()>;
    /// Flush any pending writes.
    fn flush(&mut self) -> Result<()>;
    /// Return the device's block size in bytes.
    fn block_size(&self) -> u32;
    /// Return the device's capacity in blocks.
    fn capacity(&self) -> u64;
}

// ---------------------------------------------------------------------------
// LinearSegment
// ---------------------------------------------------------------------------

/// A mapping segment: virtual LBA range → physical device offset.
#[derive(Debug, Clone, Copy)]
pub struct LinearSegment {
    /// First logical block address in this segment's virtual range.
    pub virtual_start: u64,
    /// Number of blocks in this segment.
    pub length: u64,
    /// Physical device index in the backing-device table.
    pub device_idx: usize,
    /// Block offset on the physical device where this segment starts.
    pub physical_start: u64,
}

impl LinearSegment {
    /// Return the last virtual LBA (inclusive) covered by this segment.
    pub const fn virtual_end(&self) -> u64 {
        self.virtual_start
            .saturating_add(self.length)
            .saturating_sub(1)
    }

    /// Return `true` if `lba` falls within this segment.
    pub const fn contains(&self, lba: u64) -> bool {
        lba >= self.virtual_start && lba <= self.virtual_end()
    }

    /// Translate a virtual LBA to a physical LBA on the target device.
    pub const fn translate(&self, virtual_lba: u64) -> u64 {
        self.physical_start + (virtual_lba - self.virtual_start)
    }
}

// ---------------------------------------------------------------------------
// DmLinearStats
// ---------------------------------------------------------------------------

/// I/O statistics for a `DmLinear` device.
#[derive(Debug, Clone, Copy, Default)]
pub struct DmLinearStats {
    /// Read requests.
    pub reads: u64,
    /// Write requests.
    pub writes: u64,
    /// Bytes read.
    pub bytes_read: u64,
    /// Bytes written.
    pub bytes_written: u64,
    /// Mapping lookups that found no segment.
    pub misses: u64,
}

// ---------------------------------------------------------------------------
// DmLinear
// ---------------------------------------------------------------------------

/// Device-mapper linear virtual device.
///
/// Routes I/O to underlying physical devices using a sorted segment table.
pub struct DmLinear<D: BlockDevice> {
    /// Segment map (sorted by `virtual_start`, non-overlapping).
    segments: [Option<LinearSegment>; DM_LINEAR_MAX_SEGMENTS],
    /// Number of segments.
    segment_count: usize,
    /// Backing physical devices.
    devices: [Option<D>; DM_LINEAR_MAX_SEGMENTS],
    /// Block size (must match across all underlying devices).
    block_size: u32,
    /// Whether the virtual device is online.
    online: bool,
    /// I/O statistics.
    stats: DmLinearStats,
}

impl<D: BlockDevice> DmLinear<D> {
    /// Create an empty `DmLinear` device.
    pub fn new(block_size: u32) -> Self {
        const NONE_SEG: Option<LinearSegment> = None;
        Self {
            segments: [NONE_SEG; DM_LINEAR_MAX_SEGMENTS],
            segment_count: 0,
            devices: core::array::from_fn(|_| None),
            block_size,
            online: false,
            stats: DmLinearStats::default(),
        }
    }

    /// Add a segment and its corresponding backing device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the segment table is full.
    /// Returns [`Error::InvalidArgument`] if the segment overlaps an existing one.
    pub fn add_segment(&mut self, segment: LinearSegment, device: D) -> Result<()> {
        if self.segment_count >= DM_LINEAR_MAX_SEGMENTS {
            return Err(Error::OutOfMemory);
        }
        // Check for overlap with existing segments.
        for s in self.segments.iter().flatten() {
            if segment.virtual_start <= s.virtual_end() && segment.virtual_end() >= s.virtual_start
            {
                return Err(Error::InvalidArgument);
            }
        }
        let idx = self.segment_count;
        self.segments[idx] = Some(segment);
        self.devices[idx] = Some(device);
        self.segment_count += 1;
        Ok(())
    }

    /// Bring the device online.
    pub fn init(&mut self) -> Result<()> {
        if self.segment_count == 0 {
            return Err(Error::InvalidArgument);
        }
        self.online = true;
        Ok(())
    }

    /// Take the device offline.
    pub fn shutdown(&mut self) {
        self.online = false;
    }

    /// Return `true` if the device is online.
    pub const fn is_online(&self) -> bool {
        self.online
    }

    /// Find the segment index containing `lba`.
    fn find_segment(&self, lba: u64) -> Option<usize> {
        for (i, seg) in self.segments[..self.segment_count].iter().enumerate() {
            if let Some(s) = seg {
                if s.contains(lba) {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Read `buf.len()` bytes at byte `offset`.
    ///
    /// Handles cross-segment reads by splitting the operation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if not online.
    /// Returns [`Error::NotFound`] if the block range is not mapped.
    pub fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if !self.online {
            return Err(Error::IoError);
        }
        let bs = self.block_size as u64;
        let mut remaining = buf.len();
        let mut buf_offset = 0usize;
        let mut current_offset = offset;

        while remaining > 0 {
            let lba = current_offset / bs;
            let seg_idx = self.find_segment(lba).ok_or_else(|| {
                self.stats.misses += 1;
                Error::NotFound
            })?;
            let seg = self.segments[seg_idx].unwrap();
            // How many bytes are left in this segment?
            let seg_end_byte = (seg.virtual_end() + 1) * bs;
            let available = (seg_end_byte - current_offset) as usize;
            let chunk = remaining.min(available);

            let phys_offset = seg.translate(lba) * bs + (current_offset % bs);
            let dev = self.devices[seg_idx].as_mut().ok_or(Error::IoError)?;
            dev.read(phys_offset, &mut buf[buf_offset..buf_offset + chunk])?;

            buf_offset += chunk;
            current_offset += chunk as u64;
            remaining -= chunk;
        }
        self.stats.reads += 1;
        self.stats.bytes_read += buf.len() as u64;
        Ok(())
    }

    /// Write `buf` at byte `offset`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if not online.
    /// Returns [`Error::NotFound`] if the block range is not mapped.
    pub fn write(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        if !self.online {
            return Err(Error::IoError);
        }
        let bs = self.block_size as u64;
        let mut remaining = buf.len();
        let mut buf_offset = 0usize;
        let mut current_offset = offset;

        while remaining > 0 {
            let lba = current_offset / bs;
            let seg_idx = self.find_segment(lba).ok_or_else(|| {
                self.stats.misses += 1;
                Error::NotFound
            })?;
            let seg = self.segments[seg_idx].unwrap();
            let seg_end_byte = (seg.virtual_end() + 1) * bs;
            let available = (seg_end_byte - current_offset) as usize;
            let chunk = remaining.min(available);

            let phys_offset = seg.translate(lba) * bs + (current_offset % bs);
            let dev = self.devices[seg_idx].as_mut().ok_or(Error::IoError)?;
            dev.write(phys_offset, &buf[buf_offset..buf_offset + chunk])?;

            buf_offset += chunk;
            current_offset += chunk as u64;
            remaining -= chunk;
        }
        self.stats.writes += 1;
        self.stats.bytes_written += buf.len() as u64;
        Ok(())
    }

    /// Flush all backing devices.
    pub fn flush(&mut self) -> Result<()> {
        if !self.online {
            return Err(Error::IoError);
        }
        for dev in self.devices[..self.segment_count].iter_mut().flatten() {
            dev.flush()?;
        }
        Ok(())
    }

    /// Return the total virtual capacity in blocks.
    pub fn capacity(&self) -> u64 {
        self.segments[..self.segment_count]
            .iter()
            .flatten()
            .map(|s| s.length)
            .fold(0u64, |acc, l| acc.saturating_add(l))
    }

    /// Return the block size.
    pub const fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Return the number of segments.
    pub const fn segment_count(&self) -> usize {
        self.segment_count
    }

    /// Return the I/O statistics.
    pub const fn stats(&self) -> DmLinearStats {
        self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = DmLinearStats::default();
    }
}

// ---------------------------------------------------------------------------
// Null backing device for testing / demonstration
// ---------------------------------------------------------------------------

/// A simple in-memory block device backed by a fixed-size buffer.
///
/// Primarily used for testing `DmLinear` without a real disk.
pub struct MemBlockDevice {
    /// Backing buffer virtual address.
    vaddr: u64,
    /// Buffer size in bytes.
    size: u64,
    /// Block size.
    block_size: u32,
}

impl MemBlockDevice {
    /// Create a new `MemBlockDevice`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `vaddr` is 0 or `size` is 0.
    pub fn new(vaddr: u64, size: u64, block_size: u32) -> Result<Self> {
        if vaddr == 0 || size == 0 || block_size == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            vaddr,
            size,
            block_size,
        })
    }
}

impl BlockDevice for MemBlockDevice {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(Error::InvalidArgument)?;
        if end > self.size {
            return Err(Error::InvalidArgument);
        }
        let src = (self.vaddr + offset) as *const u8;
        // SAFETY: Backing memory validated at construction; range checked above.
        unsafe { core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), buf.len()) };
        Ok(())
    }

    fn write(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(Error::InvalidArgument)?;
        if end > self.size {
            return Err(Error::InvalidArgument);
        }
        let dst = (self.vaddr + offset) as *mut u8;
        // SAFETY: Backing memory validated at construction; range checked above.
        unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), dst, buf.len()) };
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn capacity(&self) -> u64 {
        self.size / self.block_size as u64
    }
}
