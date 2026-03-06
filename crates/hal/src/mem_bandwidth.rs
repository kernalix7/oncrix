// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory bandwidth monitoring and throttling hardware abstraction.
//!
//! Interfaces with hardware performance counters and memory controller
//! registers to measure and regulate memory bandwidth usage. Used by
//! QoS subsystems to prevent bandwidth starvation between CPU cores,
//! GPU, DMA engines, and other bus masters.
//!
//! # Bandwidth Monitoring
//!
//! Memory controllers typically expose:
//! - Read/write transaction counters per channel
//! - Latency histograms
//! - Per-master bandwidth throttling controls
//!
//! # References
//!
//! - Intel Memory Controller Hub (MCH) specifications
//! - ARM CoreLink DMC-400 Technical Reference Manual

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

/// Memory channel identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemChannel(pub u8);

/// Maximum number of memory channels.
pub const MEM_MAX_CHANNELS: usize = 8;

/// Maximum number of tracked bus masters.
pub const MEM_MAX_MASTERS: usize = 16;

/// Memory bandwidth sample (read + write in bytes per measurement window).
#[derive(Debug, Clone, Copy, Default)]
pub struct BandwidthSample {
    /// Read bandwidth in bytes since last sample.
    pub read_bytes: u64,
    /// Write bandwidth in bytes since last sample.
    pub write_bytes: u64,
    /// Measurement window in nanoseconds.
    pub window_ns: u64,
}

impl BandwidthSample {
    /// Returns total bandwidth in bytes.
    pub fn total_bytes(&self) -> u64 {
        self.read_bytes + self.write_bytes
    }

    /// Returns read bandwidth in MB/s (approximate).
    pub fn read_mbps(&self) -> u64 {
        if self.window_ns == 0 {
            return 0;
        }
        self.read_bytes * 1_000 / self.window_ns.max(1)
    }

    /// Returns write bandwidth in MB/s (approximate).
    pub fn write_mbps(&self) -> u64 {
        if self.window_ns == 0 {
            return 0;
        }
        self.write_bytes * 1_000 / self.window_ns.max(1)
    }
}

/// Bandwidth throttle configuration for a bus master.
#[derive(Debug, Clone, Copy)]
pub struct BandwidthThrottle {
    /// Master identifier (e.g., IOMMU stream ID).
    pub master_id: u32,
    /// Maximum read bandwidth in MB/s (0 = unlimited).
    pub max_read_mbps: u32,
    /// Maximum write bandwidth in MB/s (0 = unlimited).
    pub max_write_mbps: u32,
    /// Whether throttling is enforced.
    pub enabled: bool,
}

impl BandwidthThrottle {
    /// Creates an unlimited bandwidth entry.
    pub const fn unlimited(master_id: u32) -> Self {
        Self {
            master_id,
            max_read_mbps: 0,
            max_write_mbps: 0,
            enabled: false,
        }
    }

    /// Creates a throttled bandwidth entry.
    pub const fn throttled(master_id: u32, max_read: u32, max_write: u32) -> Self {
        Self {
            master_id,
            max_read_mbps: max_read,
            max_write_mbps: max_write,
            enabled: true,
        }
    }
}

/// MMIO memory bandwidth monitor.
pub struct MemBandwidthMonitor {
    /// MMIO base of the memory controller.
    base: usize,
    /// Number of memory channels.
    num_channels: u8,
    /// Per-channel read counter offsets.
    read_ctr_offsets: [usize; MEM_MAX_CHANNELS],
    /// Per-channel write counter offsets.
    write_ctr_offsets: [usize; MEM_MAX_CHANNELS],
    /// Bytes per transaction (bus width / 8 * burst length).
    bytes_per_xact: u64,
    /// Throttle entries.
    throttles: [Option<BandwidthThrottle>; MEM_MAX_MASTERS],
    /// Number of throttle entries.
    num_throttles: usize,
}

impl MemBandwidthMonitor {
    /// Creates a new memory bandwidth monitor.
    pub const fn new(base: usize, num_channels: u8, bytes_per_xact: u64) -> Self {
        Self {
            base,
            num_channels,
            read_ctr_offsets: [0; MEM_MAX_CHANNELS],
            write_ctr_offsets: [0; MEM_MAX_CHANNELS],
            bytes_per_xact,
            throttles: [None; MEM_MAX_MASTERS],
            num_throttles: 0,
        }
    }

    /// Configures register offsets for a channel's read/write counters.
    pub fn set_channel_offsets(
        &mut self,
        channel: MemChannel,
        read_offset: usize,
        write_offset: usize,
    ) -> Result<()> {
        if channel.0 as usize >= MEM_MAX_CHANNELS {
            return Err(Error::InvalidArgument);
        }
        self.read_ctr_offsets[channel.0 as usize] = read_offset;
        self.write_ctr_offsets[channel.0 as usize] = write_offset;
        Ok(())
    }

    /// Reads raw transaction counts from a channel and converts to bytes.
    pub fn sample_channel(&self, channel: MemChannel) -> Result<BandwidthSample> {
        if channel.0 as usize >= self.num_channels as usize {
            return Err(Error::InvalidArgument);
        }
        let ch = channel.0 as usize;
        let read_addr = (self.base + self.read_ctr_offsets[ch]) as *const u64;
        let write_addr = (self.base + self.write_ctr_offsets[ch]) as *const u64;
        // SAFETY: base is a valid memory controller MMIO region. Counter registers
        // are 64-bit aligned and accessed with volatile reads to prevent caching.
        let read_xacts = unsafe { read_addr.read_volatile() };
        let write_xacts = unsafe { write_addr.read_volatile() };
        Ok(BandwidthSample {
            read_bytes: read_xacts * self.bytes_per_xact,
            write_bytes: write_xacts * self.bytes_per_xact,
            window_ns: 0, // Caller fills window_ns based on elapsed time
        })
    }

    /// Registers a bandwidth throttle entry for a bus master.
    pub fn set_throttle(&mut self, throttle: BandwidthThrottle) -> Result<()> {
        if self.num_throttles >= MEM_MAX_MASTERS {
            return Err(Error::OutOfMemory);
        }
        // Check for existing entry
        for entry in self.throttles[..self.num_throttles].iter_mut() {
            if let Some(t) = entry {
                if t.master_id == throttle.master_id {
                    *t = throttle;
                    return Ok(());
                }
            }
        }
        self.throttles[self.num_throttles] = Some(throttle);
        self.num_throttles += 1;
        Ok(())
    }

    /// Returns the throttle configuration for a master.
    pub fn get_throttle(&self, master_id: u32) -> Option<&BandwidthThrottle> {
        self.throttles[..self.num_throttles]
            .iter()
            .find_map(|t| t.as_ref().filter(|t| t.master_id == master_id))
    }

    /// Returns the number of memory channels.
    pub fn num_channels(&self) -> u8 {
        self.num_channels
    }
}

impl Default for MemBandwidthMonitor {
    fn default() -> Self {
        Self::new(0, 2, 64)
    }
}
