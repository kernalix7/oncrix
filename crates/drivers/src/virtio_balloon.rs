// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VirtIO balloon device driver.
//!
//! Implements the VirtIO balloon device (device type 5) for dynamic
//! memory management between the guest and host. The host can request
//! the guest to inflate (give back memory) or deflate (reclaim memory)
//! by communicating page frame numbers (PFNs) through virtqueues.
//!
//! # Architecture
//!
//! The balloon device uses three virtqueues:
//! - **inflateq** (queue 0) — guest reports PFNs of pages given to host
//! - **deflateq** (queue 1) — guest reports PFNs of pages reclaimed
//! - **statsq**   (queue 2) — guest reports memory statistics to host
//!
//! # Memory Ballooning Protocol
//!
//! 1. Host sets `num_pages` in device config to desired balloon size
//! 2. Guest detects `num_pages > actual` → inflates by allocating pages
//!    and reporting their PFNs on inflateq
//! 3. Guest detects `num_pages < actual` → deflates by freeing pages
//!    and reporting on deflateq
//! 4. Guest updates `actual` in device config after each operation
//!
//! Reference: VirtIO Specification v1.1, §5.5 (Traditional Memory Balloon).

use oncrix_lib::{Error, Result};

use crate::virtio::{self, VirtioMmio, Virtqueue, status};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// VirtIO balloon device type ID.
pub const VIRTIO_BALLOON_DEVICE_ID: u32 = 5;

/// Maximum PFNs per inflate/deflate batch.
const MAX_PFN_BATCH: usize = 256;

/// Maximum number of balloon devices in the registry.
const MAX_BALLOON_DEVICES: usize = 4;

/// Page size assumed by the balloon protocol (4 KiB).
const BALLOON_PAGE_SIZE: u64 = 4096;

// ---------------------------------------------------------------------------
// BalloonConfig (§5.5.4)
// ---------------------------------------------------------------------------

/// Balloon device configuration space.
///
/// This structure mirrors the device config area at MMIO offset 0x100.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct BalloonConfig {
    /// Number of pages the host wants in the balloon.
    pub num_pages: u32,
    /// Current number of pages in the balloon (driver-writable).
    pub actual: u32,
    /// Free page hint command ID (used with VIRTIO_BALLOON_F_FREE_PAGE_HINT).
    pub free_page_hint_cmd_id: u32,
}

// ---------------------------------------------------------------------------
// BalloonStatTag (§5.5.6.3)
// ---------------------------------------------------------------------------

/// Tag values for balloon memory statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum BalloonStatTag {
    /// Amount of memory swapped in (in bytes).
    SwapIn = 0,
    /// Amount of memory swapped out (in bytes).
    SwapOut = 1,
    /// Number of major page faults.
    MajorFaults = 2,
    /// Number of minor page faults.
    MinorFaults = 3,
    /// Amount of free memory (in bytes).
    FreeMemory = 4,
    /// Total amount of memory (in bytes).
    TotalMemory = 5,
}

// ---------------------------------------------------------------------------
// BalloonStat (§5.5.6.3)
// ---------------------------------------------------------------------------

/// A single memory statistic reported to the host.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct BalloonStat {
    /// Statistic type tag.
    pub tag: u16,
    /// Padding (must be zero).
    _padding: [u8; 6],
    /// Statistic value.
    pub val: u64,
}

impl BalloonStat {
    /// Creates a new balloon statistic.
    pub const fn new(tag: BalloonStatTag, val: u64) -> Self {
        Self {
            tag: tag as u16,
            _padding: [0; 6],
            val,
        }
    }
}

// ---------------------------------------------------------------------------
// VirtioBalloon
// ---------------------------------------------------------------------------

/// VirtIO balloon device driver.
///
/// Manages memory ballooning between the guest and host, inflating
/// to return memory and deflating to reclaim it.
pub struct VirtioBalloon {
    /// MMIO transport.
    mmio: VirtioMmio,
    /// Inflate virtqueue (queue 0).
    inflate_vq: Virtqueue,
    /// Deflate virtqueue (queue 1).
    deflate_vq: Virtqueue,
    /// Device configuration.
    config: BalloonConfig,
    /// PFN buffer for inflate operations.
    inflate_pfns: [u32; MAX_PFN_BATCH],
    /// Number of PFNs in the current inflate batch.
    inflate_count: usize,
    /// PFN buffer for deflate operations.
    deflate_pfns: [u32; MAX_PFN_BATCH],
    /// Number of PFNs in the current deflate batch.
    deflate_count: usize,
    /// Statistics buffer for reporting to host.
    stats: [BalloonStat; 6],
    /// Number of valid stat entries.
    stats_count: usize,
    /// Number of pages currently in the balloon.
    actual_pages: u32,
    /// Number of pages the host has requested.
    requested_pages: u32,
    /// Whether the device has been initialized.
    initialized: bool,
}

impl VirtioBalloon {
    /// Creates a new virtio-balloon driver for a device at `mmio_base`.
    pub const fn new(mmio_base: u64) -> Self {
        Self {
            mmio: VirtioMmio::new(mmio_base),
            inflate_vq: Virtqueue::new(),
            deflate_vq: Virtqueue::new(),
            config: BalloonConfig {
                num_pages: 0,
                actual: 0,
                free_page_hint_cmd_id: 0,
            },
            inflate_pfns: [0u32; MAX_PFN_BATCH],
            inflate_count: 0,
            deflate_pfns: [0u32; MAX_PFN_BATCH],
            deflate_count: 0,
            stats: [BalloonStat {
                tag: 0,
                _padding: [0; 6],
                val: 0,
            }; 6],
            stats_count: 0,
            actual_pages: 0,
            requested_pages: 0,
            initialized: false,
        }
    }

    /// Probes and initializes the virtio-balloon device.
    ///
    /// Follows the VirtIO initialization sequence (§3.1):
    /// 1. Reset device
    /// 2. Set ACKNOWLEDGE + DRIVER status
    /// 3. Feature negotiation
    /// 4. Set FEATURES_OK
    /// 5. Set up virtqueues (inflateq, deflateq)
    /// 6. Set DRIVER_OK
    pub fn init(&mut self) -> Result<()> {
        // Probe — verify magic, version, device type.
        let device_id = self.mmio.probe()?;
        if device_id != VIRTIO_BALLOON_DEVICE_ID {
            return Err(Error::NotFound);
        }

        // Reset.
        self.mmio.reset();

        // Acknowledge.
        self.mmio.set_status(status::ACKNOWLEDGE);
        self.mmio.set_status(status::DRIVER);

        // Feature negotiation — accept no optional features for now.
        let _dev_features = self.mmio.read_device_features(0);
        self.mmio.write_driver_features(0, 0);
        self.mmio.write_driver_features(1, 0);

        // Features OK.
        self.mmio.set_status(status::FEATURES_OK);
        if self.mmio.status() & status::FEATURES_OK == 0 {
            self.mmio.set_status(status::FAILED);
            return Err(Error::IoError);
        }

        // Set up inflate queue (queue 0).
        self.inflate_vq.init();
        self.setup_queue(0)?;

        // Set up deflate queue (queue 1).
        self.deflate_vq.init();
        self.setup_queue(1)?;

        // Read initial configuration.
        self.read_config();

        // Driver OK.
        self.mmio.set_status(status::DRIVER_OK);

        self.initialized = true;
        Ok(())
    }

    /// Sets up a virtqueue at the given queue index.
    fn setup_queue(&mut self, queue_idx: u32) -> Result<()> {
        self.mmio.write32(virtio::mmio_reg::QUEUE_SEL, queue_idx);
        let max_size = self.mmio.read32(virtio::mmio_reg::QUEUE_NUM_MAX);
        if max_size == 0 {
            self.mmio.set_status(status::FAILED);
            return Err(Error::IoError);
        }

        let vq = if queue_idx == 0 {
            &self.inflate_vq
        } else {
            &self.deflate_vq
        };

        let queue_size = (vq.num as u32).min(max_size);
        self.mmio.write32(virtio::mmio_reg::QUEUE_NUM, queue_size);

        // Write descriptor table address.
        let desc_addr = vq.desc.as_ptr() as u64;
        self.mmio
            .write32(virtio::mmio_reg::QUEUE_DESC_LOW, desc_addr as u32);
        self.mmio
            .write32(virtio::mmio_reg::QUEUE_DESC_HIGH, (desc_addr >> 32) as u32);

        // Write available ring address.
        let avail_addr = &vq.avail_flags as *const u16 as u64;
        self.mmio
            .write32(virtio::mmio_reg::QUEUE_AVAIL_LOW, avail_addr as u32);
        self.mmio.write32(
            virtio::mmio_reg::QUEUE_AVAIL_HIGH,
            (avail_addr >> 32) as u32,
        );

        // Write used ring address.
        let used_addr = &vq.used_flags as *const u16 as u64;
        self.mmio
            .write32(virtio::mmio_reg::QUEUE_USED_LOW, used_addr as u32);
        self.mmio
            .write32(virtio::mmio_reg::QUEUE_USED_HIGH, (used_addr >> 32) as u32);

        self.mmio.write32(virtio::mmio_reg::QUEUE_READY, 1);
        Ok(())
    }

    /// Reads the device configuration from MMIO config space.
    fn read_config(&mut self) {
        // Balloon config starts at offset 0x100.
        self.config.num_pages = self.mmio.read32(0x100);
        self.config.actual = self.mmio.read32(0x104);
        self.requested_pages = self.config.num_pages;
    }

    /// Writes the `actual` field back to the device config.
    fn write_actual(&self) {
        self.mmio.write32(0x104, self.actual_pages);
    }

    /// Returns the number of pages the host has requested.
    pub fn requested_pages(&self) -> u32 {
        self.requested_pages
    }

    /// Returns the current number of pages in the balloon.
    pub fn actual_pages(&self) -> u32 {
        self.actual_pages
    }

    /// Returns the balloon size in bytes.
    pub fn balloon_size_bytes(&self) -> u64 {
        u64::from(self.actual_pages) * BALLOON_PAGE_SIZE
    }

    /// Checks if the balloon needs adjustment.
    ///
    /// Returns the difference between requested and actual pages.
    /// Positive means inflate needed, negative means deflate needed.
    pub fn pages_delta(&self) -> i64 {
        i64::from(self.requested_pages) - i64::from(self.actual_pages)
    }

    /// Adds a page frame number to the inflate batch.
    ///
    /// The PFN will be reported to the host when [`submit_inflate`]
    /// is called.
    pub fn add_inflate_pfn(&mut self, pfn: u32) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        if self.inflate_count >= MAX_PFN_BATCH {
            return Err(Error::OutOfMemory);
        }
        self.inflate_pfns[self.inflate_count] = pfn;
        self.inflate_count += 1;
        Ok(())
    }

    /// Submits the current inflate batch to the host.
    ///
    /// Sends all accumulated PFNs on the inflate virtqueue and
    /// updates the `actual` count in device config.
    pub fn submit_inflate(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        if self.inflate_count == 0 {
            return Ok(());
        }

        // Allocate a descriptor for the PFN buffer.
        let desc_idx = self.inflate_vq.alloc_desc()?;
        let pfn_bytes = self.inflate_count * core::mem::size_of::<u32>();

        self.inflate_vq.desc[desc_idx as usize].addr = self.inflate_pfns.as_ptr() as u64;
        self.inflate_vq.desc[desc_idx as usize].len = pfn_bytes as u32;
        self.inflate_vq.desc[desc_idx as usize].flags = 0; // device-readable
        self.inflate_vq.desc[desc_idx as usize].next = 0;

        // Push to available ring and notify.
        self.inflate_vq.push_avail(desc_idx);
        self.mmio.notify(0);

        // Update balloon count.
        self.actual_pages = self.actual_pages.saturating_add(self.inflate_count as u32);
        self.write_actual();
        self.inflate_count = 0;

        Ok(())
    }

    /// Adds a page frame number to the deflate batch.
    ///
    /// The PFN will be reported to the host when [`submit_deflate`]
    /// is called.
    pub fn add_deflate_pfn(&mut self, pfn: u32) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        if self.deflate_count >= MAX_PFN_BATCH {
            return Err(Error::OutOfMemory);
        }
        self.deflate_pfns[self.deflate_count] = pfn;
        self.deflate_count += 1;
        Ok(())
    }

    /// Submits the current deflate batch to the host.
    ///
    /// Sends all accumulated PFNs on the deflate virtqueue and
    /// updates the `actual` count in device config.
    pub fn submit_deflate(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        if self.deflate_count == 0 {
            return Ok(());
        }

        // Allocate a descriptor for the PFN buffer.
        let desc_idx = self.deflate_vq.alloc_desc()?;
        let pfn_bytes = self.deflate_count * core::mem::size_of::<u32>();

        self.deflate_vq.desc[desc_idx as usize].addr = self.deflate_pfns.as_ptr() as u64;
        self.deflate_vq.desc[desc_idx as usize].len = pfn_bytes as u32;
        self.deflate_vq.desc[desc_idx as usize].flags = 0; // device-readable
        self.deflate_vq.desc[desc_idx as usize].next = 0;

        // Push to available ring and notify.
        self.deflate_vq.push_avail(desc_idx);
        self.mmio.notify(1);

        // Update balloon count.
        self.actual_pages = self.actual_pages.saturating_sub(self.deflate_count as u32);
        self.write_actual();
        self.deflate_count = 0;

        Ok(())
    }

    /// Updates memory statistics for reporting to the host.
    pub fn update_stats(
        &mut self,
        free_memory: u64,
        total_memory: u64,
        swap_in: u64,
        swap_out: u64,
        major_faults: u64,
        minor_faults: u64,
    ) {
        self.stats[0] = BalloonStat::new(BalloonStatTag::SwapIn, swap_in);
        self.stats[1] = BalloonStat::new(BalloonStatTag::SwapOut, swap_out);
        self.stats[2] = BalloonStat::new(BalloonStatTag::MajorFaults, major_faults);
        self.stats[3] = BalloonStat::new(BalloonStatTag::MinorFaults, minor_faults);
        self.stats[4] = BalloonStat::new(BalloonStatTag::FreeMemory, free_memory);
        self.stats[5] = BalloonStat::new(BalloonStatTag::TotalMemory, total_memory);
        self.stats_count = 6;
    }

    /// Returns the current statistics buffer.
    pub fn stats(&self) -> &[BalloonStat] {
        &self.stats[..self.stats_count]
    }

    /// Handles a virtio-balloon interrupt.
    ///
    /// Acknowledges the interrupt. Returns `true` if a config change
    /// was detected (bit 1 of ISR), meaning the host changed `num_pages`.
    pub fn handle_irq(&mut self) -> bool {
        if !self.initialized {
            return false;
        }
        let isr = self.mmio.ack_interrupt();
        // Bit 1 = configuration change notification.
        if isr & 2 != 0 {
            self.read_config();
            return true;
        }
        // Bit 0 = used buffer notification — process completions.
        if isr & 1 != 0 {
            // Free completed inflate descriptors.
            while let Some((desc_head, _)) = self.inflate_vq.pop_used() {
                self.inflate_vq.free_desc(desc_head);
            }
            // Free completed deflate descriptors.
            while let Some((desc_head, _)) = self.deflate_vq.pop_used() {
                self.deflate_vq.free_desc(desc_head);
            }
        }
        false
    }

    /// Returns whether the device is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl core::fmt::Debug for VirtioBalloon {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioBalloon")
            .field("initialized", &self.initialized)
            .field("requested_pages", &self.requested_pages)
            .field("actual_pages", &self.actual_pages)
            .field("inflate_pending", &self.inflate_count)
            .field("deflate_pending", &self.deflate_count)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// VirtioBalloonRegistry
// ---------------------------------------------------------------------------

/// Registry that manages multiple [`VirtioBalloon`] devices.
///
/// Supports up to [`MAX_BALLOON_DEVICES`] concurrently registered devices
/// and provides aggregate inflate/deflate operations.
pub struct VirtioBalloonRegistry {
    /// Registered balloon devices (stored as MMIO base addresses).
    devices: [Option<u64>; MAX_BALLOON_DEVICES],
    /// Number of currently registered devices.
    count: usize,
}

impl Default for VirtioBalloonRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioBalloonRegistry {
    /// Creates a new, empty balloon device registry.
    pub const fn new() -> Self {
        Self {
            devices: [None; MAX_BALLOON_DEVICES],
            count: 0,
        }
    }

    /// Registers a balloon device by its MMIO base address.
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if this base address is already registered.
    pub fn register(&mut self, mmio_base: u64) -> Result<()> {
        for slot in &self.devices {
            if *slot == Some(mmio_base) {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in &mut self.devices {
            if slot.is_none() {
                *slot = Some(mmio_base);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns the MMIO base address of the device at the given index.
    pub fn find(&self, index: usize) -> Option<u64> {
        if index < MAX_BALLOON_DEVICES {
            self.devices[index]
        } else {
            None
        }
    }

    /// Returns the number of registered devices.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no devices are registered.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}
