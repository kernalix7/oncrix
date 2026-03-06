// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Compressed RAM block device (zram) for the ONCRIX kernel.
//!
//! Provides a virtual block device backed by compressed in-memory
//! storage. Pages written to zram are compressed and stored in RAM,
//! reducing memory pressure when used as a swap device.
//!
//! - [`ZramDevice`] — main device with capacity and compression
//! - [`ZramSlot`] — per-slot compressed data storage
//! - [`ComprAlgorithm`] — compression algorithm selection
//! - [`ZramStats`] — device statistics (compression ratio, I/O)
//!
//! Reference: `.kernelORG/` — `drivers/block/zram/`, `mm/zram.rst`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Maximum number of zram devices in the system.
const MAX_ZRAM_DEVICES: usize = 4;

/// Maximum number of slots per zram device.
const MAX_SLOTS_PER_DEVICE: usize = 512;

/// Maximum compressed data size per slot (bytes). If compressed data
/// is larger than this, store uncompressed.
const MAX_COMPRESSED_SIZE: usize = PAGE_SIZE;

/// Inline compressed data buffer size per slot.
const SLOT_INLINE_SIZE: usize = 64;

/// Compression ratio threshold: if compressed size > 75% of original,
/// don't bother compressing.
const COMPRESSION_THRESHOLD: usize = PAGE_SIZE * 3 / 4;

// -------------------------------------------------------------------
// ComprAlgorithm
// -------------------------------------------------------------------

/// Compression algorithm for zram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ComprAlgorithm {
    /// LZO compression (default, fast).
    #[default]
    Lzo,
    /// LZ4 compression (very fast, lower ratio).
    Lz4,
    /// Zstandard compression (better ratio, slower).
    Zstd,
    /// No compression (passthrough).
    None,
}

// -------------------------------------------------------------------
// SlotState
// -------------------------------------------------------------------

/// State of a zram slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SlotState {
    /// Slot is free (no data stored).
    #[default]
    Free,
    /// Slot contains compressed data.
    Compressed,
    /// Slot contains uncompressed data (compression was not beneficial).
    Uncompressed,
    /// Slot contains a zero-filled page (stored as metadata only).
    ZeroFilled,
    /// Slot is being accessed (locked).
    Locked,
}

// -------------------------------------------------------------------
// ZramSlot
// -------------------------------------------------------------------

/// A single zram slot holding compressed page data.
#[derive(Debug, Clone, Copy)]
pub struct ZramSlot {
    /// State of this slot.
    pub state: SlotState,
    /// Original (uncompressed) data size.
    pub orig_size: u32,
    /// Compressed data size (0 for zero-filled pages).
    pub comp_size: u32,
    /// Inline compressed data (for small compressed results).
    pub inline_data: [u8; SLOT_INLINE_SIZE],
    /// Number of read accesses.
    pub read_count: u32,
    /// Number of write accesses.
    pub write_count: u32,
    /// Whether the slot has been accessed since last scan.
    pub accessed: bool,
}

impl ZramSlot {
    /// Create a new empty slot.
    pub const fn empty() -> Self {
        Self {
            state: SlotState::Free,
            orig_size: 0,
            comp_size: 0,
            inline_data: [0u8; SLOT_INLINE_SIZE],
            read_count: 0,
            write_count: 0,
            accessed: false,
        }
    }

    /// Check if the slot is free.
    pub fn is_free(&self) -> bool {
        matches!(self.state, SlotState::Free)
    }

    /// Check if the slot holds a zero page.
    pub fn is_zero(&self) -> bool {
        matches!(self.state, SlotState::ZeroFilled)
    }

    /// Get the compression savings in bytes.
    pub fn savings(&self) -> u32 {
        if self.orig_size > self.comp_size {
            self.orig_size - self.comp_size
        } else {
            0
        }
    }
}

// -------------------------------------------------------------------
// ZramStats
// -------------------------------------------------------------------

/// Statistics for a zram device.
#[derive(Debug, Clone, Copy, Default)]
pub struct ZramStats {
    /// Total original data size stored (bytes).
    pub orig_data_size: u64,
    /// Total compressed data size stored (bytes).
    pub compr_data_size: u64,
    /// Number of read I/O operations.
    pub num_reads: u64,
    /// Number of write I/O operations.
    pub num_writes: u64,
    /// Number of failed reads.
    pub failed_reads: u64,
    /// Number of failed writes.
    pub failed_writes: u64,
    /// Number of zero-filled pages detected.
    pub zero_pages: u64,
    /// Number of pages stored uncompressed (incompressible).
    pub incompressible: u64,
    /// Number of pages where compression was beneficial.
    pub compressed: u64,
    /// Maximum number of slots used concurrently.
    pub max_used_slots: u64,
    /// Current number of used slots.
    pub used_slots: u64,
}

impl ZramStats {
    /// Get the compression ratio as a percentage (100 = no compression).
    pub fn compression_ratio(&self) -> u32 {
        if self.orig_data_size == 0 {
            return 100;
        }
        ((self.compr_data_size * 100) / self.orig_data_size) as u32
    }

    /// Get the total memory saved by compression.
    pub fn memory_saved(&self) -> u64 {
        self.orig_data_size.saturating_sub(self.compr_data_size)
    }
}

// -------------------------------------------------------------------
// ZramDevice
// -------------------------------------------------------------------

/// A compressed RAM block device.
///
/// Acts as a virtual block device where each "sector" corresponds to
/// a page-sized slot. Data written to a slot is compressed and stored
/// in memory. Used primarily as a swap device to reduce I/O to
/// physical storage.
pub struct ZramDevice {
    /// Device index.
    pub device_id: u32,
    /// Total capacity in slots (pages).
    pub capacity: usize,
    /// Compression algorithm.
    pub algorithm: ComprAlgorithm,
    /// Slot storage array.
    slots: [ZramSlot; MAX_SLOTS_PER_DEVICE],
    /// Number of active (non-free) slots.
    active_slots: usize,
    /// Device statistics.
    stats: ZramStats,
    /// Whether the device is initialized and accepting I/O.
    initialized: bool,
    /// Memory limit (0 = unlimited).
    mem_limit: u64,
}

impl ZramDevice {
    /// Create a new zram device.
    pub fn new(device_id: u32, capacity: usize, algorithm: ComprAlgorithm) -> Self {
        let capped = if capacity > MAX_SLOTS_PER_DEVICE {
            MAX_SLOTS_PER_DEVICE
        } else {
            capacity
        };

        Self {
            device_id,
            capacity: capped,
            algorithm,
            slots: [ZramSlot::empty(); MAX_SLOTS_PER_DEVICE],
            active_slots: 0,
            stats: ZramStats::default(),
            initialized: false,
            mem_limit: 0,
        }
    }

    /// Initialize the device for I/O.
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        self.initialized = true;
        Ok(())
    }

    /// Reset the device, freeing all stored data.
    pub fn reset(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }

        for i in 0..self.capacity {
            self.slots[i] = ZramSlot::empty();
        }
        self.active_slots = 0;
        self.stats = ZramStats::default();
        self.initialized = false;
        Ok(())
    }

    /// Set the memory limit for the device.
    pub fn set_mem_limit(&mut self, limit: u64) {
        self.mem_limit = limit;
    }

    /// Write a page to the zram device at the given slot index.
    ///
    /// The data is compressed and stored. If the page is all zeros,
    /// only metadata is stored (zero-page optimization).
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the slot index is out of range,
    /// `OutOfMemory` if the memory limit would be exceeded, or
    /// `Busy` if the device is not initialized.
    pub fn zram_write(&mut self, slot_idx: usize, data: &[u8]) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        if slot_idx >= self.capacity {
            return Err(Error::InvalidArgument);
        }
        if data.len() != PAGE_SIZE {
            return Err(Error::InvalidArgument);
        }

        self.stats.num_writes += 1;

        // Check for zero-filled page.
        if data.iter().all(|&b| b == 0) {
            let was_free = self.slots[slot_idx].is_free();
            self.slots[slot_idx] = ZramSlot {
                state: SlotState::ZeroFilled,
                orig_size: PAGE_SIZE as u32,
                comp_size: 0,
                inline_data: [0u8; SLOT_INLINE_SIZE],
                read_count: 0,
                write_count: 1,
                accessed: true,
            };
            if was_free {
                self.active_slots += 1;
            }
            self.stats.zero_pages += 1;
            self.stats.orig_data_size += PAGE_SIZE as u64;
            self.update_max_slots();
            return Ok(());
        }

        // Simulate compression: compute a simple "compressed size"
        // by counting unique byte values (a rough proxy).
        let comp_size = self.simulate_compression(data);

        // Check memory limit.
        if self.mem_limit > 0 {
            let projected = self.stats.compr_data_size + comp_size as u64;
            if projected > self.mem_limit {
                self.stats.failed_writes += 1;
                return Err(Error::OutOfMemory);
            }
        }

        let was_free = self.slots[slot_idx].is_free();

        // Store compressed or uncompressed.
        let (state, stored_size) = if comp_size <= COMPRESSION_THRESHOLD {
            self.stats.compressed += 1;
            (SlotState::Compressed, comp_size)
        } else {
            self.stats.incompressible += 1;
            (SlotState::Uncompressed, PAGE_SIZE)
        };

        // Copy inline data (first SLOT_INLINE_SIZE bytes as sample).
        let mut inline = [0u8; SLOT_INLINE_SIZE];
        let copy_len = data.len().min(SLOT_INLINE_SIZE);
        inline[..copy_len].copy_from_slice(&data[..copy_len]);

        self.slots[slot_idx] = ZramSlot {
            state,
            orig_size: PAGE_SIZE as u32,
            comp_size: stored_size as u32,
            inline_data: inline,
            read_count: 0,
            write_count: 1,
            accessed: true,
        };

        if was_free {
            self.active_slots += 1;
        }

        self.stats.orig_data_size += PAGE_SIZE as u64;
        self.stats.compr_data_size += stored_size as u64;
        self.update_max_slots();

        Ok(())
    }

    /// Read a page from the zram device at the given slot index.
    ///
    /// The data is decompressed and written to the output buffer.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the slot index is out of range,
    /// `NotFound` if the slot is empty, or `Busy` if the device is
    /// not initialized.
    pub fn zram_read(&mut self, slot_idx: usize, out: &mut [u8]) -> Result<usize> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        if slot_idx >= self.capacity {
            return Err(Error::InvalidArgument);
        }
        if out.len() < PAGE_SIZE {
            return Err(Error::InvalidArgument);
        }

        self.stats.num_reads += 1;

        let slot = &self.slots[slot_idx];
        match slot.state {
            SlotState::Free => {
                self.stats.failed_reads += 1;
                Err(Error::NotFound)
            }
            SlotState::ZeroFilled => {
                // Fill output with zeros.
                for byte in out.iter_mut().take(PAGE_SIZE) {
                    *byte = 0;
                }
                self.slots[slot_idx].read_count += 1;
                self.slots[slot_idx].accessed = true;
                Ok(PAGE_SIZE)
            }
            SlotState::Compressed | SlotState::Uncompressed => {
                // Simulate decompression by filling with inline data pattern.
                let copy_len = SLOT_INLINE_SIZE.min(PAGE_SIZE);
                out[..copy_len].copy_from_slice(&slot.inline_data[..copy_len]);
                for byte in out.iter_mut().take(PAGE_SIZE).skip(copy_len) {
                    *byte = 0;
                }
                self.slots[slot_idx].read_count += 1;
                self.slots[slot_idx].accessed = true;
                Ok(PAGE_SIZE)
            }
            SlotState::Locked => Err(Error::Busy),
        }
    }

    /// Free a slot, releasing its compressed data.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the slot index is out of range.
    pub fn zram_free(&mut self, slot_idx: usize) -> Result<()> {
        if slot_idx >= self.capacity {
            return Err(Error::InvalidArgument);
        }

        let slot = &self.slots[slot_idx];
        if !slot.is_free() {
            let comp = slot.comp_size as u64;
            let orig = slot.orig_size as u64;
            self.stats.compr_data_size = self.stats.compr_data_size.saturating_sub(comp);
            self.stats.orig_data_size = self.stats.orig_data_size.saturating_sub(orig);
            self.active_slots = self.active_slots.saturating_sub(1);
        }

        self.slots[slot_idx] = ZramSlot::empty();
        Ok(())
    }

    /// Get the number of active (non-free) slots.
    pub fn active_slot_count(&self) -> usize {
        self.active_slots
    }

    /// Get the device capacity in slots.
    pub fn slot_capacity(&self) -> usize {
        self.capacity
    }

    /// Check if the device is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get device statistics.
    pub fn statistics(&self) -> &ZramStats {
        &self.stats
    }

    /// Get the state of a specific slot.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the slot index is out of range.
    pub fn slot_state(&self, slot_idx: usize) -> Result<SlotState> {
        if slot_idx >= self.capacity {
            return Err(Error::InvalidArgument);
        }
        Ok(self.slots[slot_idx].state)
    }

    /// Change the compression algorithm (only when device is not initialized).
    ///
    /// # Errors
    ///
    /// Returns `Busy` if the device is currently initialized.
    pub fn set_algorithm(&mut self, algorithm: ComprAlgorithm) -> Result<()> {
        if self.initialized {
            return Err(Error::Busy);
        }
        self.algorithm = algorithm;
        Ok(())
    }

    /// Simulate compression by computing a rough "compressed size".
    ///
    /// Uses byte frequency analysis: fewer unique bytes means better
    /// compression. This is a placeholder for real compression.
    fn simulate_compression(&self, data: &[u8]) -> usize {
        let mut seen = [false; 256];
        let mut unique = 0u32;

        for &byte in data {
            if !seen[byte as usize] {
                seen[byte as usize] = true;
                unique += 1;
            }
        }

        // Estimate: fewer unique bytes = better compression.
        let ratio = unique as usize * PAGE_SIZE / 256;
        ratio.max(SLOT_INLINE_SIZE).min(MAX_COMPRESSED_SIZE)
    }

    /// Update the max used slots statistic.
    fn update_max_slots(&mut self) {
        let current = self.active_slots as u64;
        self.stats.used_slots = current;
        if current > self.stats.max_used_slots {
            self.stats.max_used_slots = current;
        }
    }
}

// -------------------------------------------------------------------
// ZramManager
// -------------------------------------------------------------------

/// Manages multiple zram devices.
pub struct ZramManager {
    /// Registered zram devices.
    devices: [Option<ZramDevice>; MAX_ZRAM_DEVICES],
    /// Number of registered devices.
    device_count: usize,
}

impl ZramManager {
    /// Create a new zram manager.
    pub fn new() -> Self {
        Self {
            devices: [const { None }; MAX_ZRAM_DEVICES],
            device_count: 0,
        }
    }

    /// Create a new zram device.
    ///
    /// # Errors
    ///
    /// Returns `OutOfMemory` if the maximum number of devices is reached.
    pub fn create_device(&mut self, capacity: usize, algorithm: ComprAlgorithm) -> Result<u32> {
        if self.device_count >= MAX_ZRAM_DEVICES {
            return Err(Error::OutOfMemory);
        }

        let id = self.device_count as u32;
        let mut device = ZramDevice::new(id, capacity, algorithm);
        device.init()?;

        self.devices[self.device_count] = Some(device);
        self.device_count += 1;

        Ok(id)
    }

    /// Get a reference to a device by ID.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the device doesn't exist.
    pub fn get_device(&self, id: u32) -> Result<&ZramDevice> {
        let idx = id as usize;
        if idx >= MAX_ZRAM_DEVICES {
            return Err(Error::NotFound);
        }
        self.devices[idx].as_ref().ok_or(Error::NotFound)
    }

    /// Get a mutable reference to a device by ID.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the device doesn't exist.
    pub fn get_device_mut(&mut self, id: u32) -> Result<&mut ZramDevice> {
        let idx = id as usize;
        if idx >= MAX_ZRAM_DEVICES {
            return Err(Error::NotFound);
        }
        self.devices[idx].as_mut().ok_or(Error::NotFound)
    }

    /// Destroy a zram device and free its resources.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the device doesn't exist.
    pub fn destroy_device(&mut self, id: u32) -> Result<()> {
        let idx = id as usize;
        if idx >= MAX_ZRAM_DEVICES {
            return Err(Error::NotFound);
        }
        if self.devices[idx].is_none() {
            return Err(Error::NotFound);
        }
        self.devices[idx] = None;
        Ok(())
    }

    /// Get the number of active devices.
    pub fn device_count(&self) -> usize {
        self.devices.iter().filter(|d| d.is_some()).count()
    }

    /// Get aggregate statistics across all devices.
    pub fn aggregate_stats(&self) -> ZramStats {
        let mut total = ZramStats::default();
        for device in self.devices.iter().flatten() {
            let s = device.statistics();
            total.orig_data_size += s.orig_data_size;
            total.compr_data_size += s.compr_data_size;
            total.num_reads += s.num_reads;
            total.num_writes += s.num_writes;
            total.failed_reads += s.failed_reads;
            total.failed_writes += s.failed_writes;
            total.zero_pages += s.zero_pages;
            total.incompressible += s.incompressible;
            total.compressed += s.compressed;
            total.used_slots += s.used_slots;
            total.max_used_slots += s.max_used_slots;
        }
        total
    }
}
