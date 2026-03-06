// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory controller (MC) abstraction layer.
//!
//! Provides a hardware-independent interface for:
//!
//! - Enumerating DRAM channels, DIMMs, and rank configurations
//! - Reading memory controller error registers (ECC, parity)
//! - DRAM scrubbing control
//! - Memory controller performance counters
//!
//! Concrete implementations for specific chipsets (Intel IMC, AMD UMC,
//! ARM DMC-620) plug into this abstraction via the [`MemControllerOps`] trait.
//!
//! Reference: JEDEC DDR5 JESD79-5C; Intel SDM Vol. 2 (mce); AMD PPR.

use oncrix_lib::{Error, Result};

/// Maximum memory channels per controller.
pub const MAX_CHANNELS: usize = 8;
/// Maximum DIMMs per channel.
pub const MAX_DIMMS_PER_CHANNEL: usize = 2;
/// Maximum memory controllers in the system.
pub const MAX_CONTROLLERS: usize = 4;

// ── DIMM Geometry ──────────────────────────────────────────────────────────

/// DRAM generation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DramGeneration {
    Ddr4,
    Ddr5,
    LpDdr5,
    Unknown,
}

/// DIMM descriptor.
#[derive(Clone, Copy)]
pub struct DimmInfo {
    /// Whether this slot is populated.
    pub present: bool,
    /// DRAM generation.
    pub generation: DramGeneration,
    /// Total DIMM capacity in MiB.
    pub size_mib: u32,
    /// Number of ranks.
    pub ranks: u8,
    /// ECC capable.
    pub ecc: bool,
    /// Operating frequency in MT/s.
    pub freq_mts: u32,
}

impl DimmInfo {
    const fn empty() -> Self {
        Self {
            present: false,
            generation: DramGeneration::Unknown,
            size_mib: 0,
            ranks: 0,
            ecc: false,
            freq_mts: 0,
        }
    }
}

// ── Memory Error ───────────────────────────────────────────────────────────

/// Classification of a memory error.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MemErrorType {
    /// Single-bit ECC correctable error.
    SingleBitCorrectible,
    /// Multi-bit uncorrectable error.
    MultiBitUncorrectable,
    /// Address/command parity error.
    ParityError,
    /// CRC error on the data bus.
    CrcError,
}

/// A memory error event.
#[derive(Clone, Copy)]
pub struct MemError {
    /// Physical address where the error occurred (if known).
    pub phys_addr: Option<u64>,
    /// Error type.
    pub error_type: MemErrorType,
    /// Controller index.
    pub controller: u8,
    /// Channel index.
    pub channel: u8,
    /// DIMM slot index.
    pub dimm: u8,
    /// Rank index.
    pub rank: u8,
    /// ECC syndrome bits (platform-specific).
    pub syndrome: u32,
}

// ── Error Statistics ───────────────────────────────────────────────────────

/// Per-channel error counters.
#[derive(Default, Clone, Copy)]
pub struct ChannelErrorStats {
    /// Correctable single-bit errors.
    pub correctable: u64,
    /// Uncorrectable multi-bit errors.
    pub uncorrectable: u64,
    /// Parity errors.
    pub parity: u64,
}

impl ChannelErrorStats {
    const fn new() -> Self {
        Self {
            correctable: 0,
            uncorrectable: 0,
            parity: 0,
        }
    }

    /// Record an error.
    pub fn record(&mut self, error: &MemError) {
        match error.error_type {
            MemErrorType::SingleBitCorrectible => self.correctable += 1,
            MemErrorType::MultiBitUncorrectable => self.uncorrectable += 1,
            MemErrorType::ParityError | MemErrorType::CrcError => self.parity += 1,
        }
    }
}

// ── Memory Channel ─────────────────────────────────────────────────────────

/// A single memory channel with its DIMMs.
pub struct MemChannel {
    /// Channel is active.
    pub active: bool,
    /// DIMMs in this channel.
    pub dimms: [DimmInfo; MAX_DIMMS_PER_CHANNEL],
    /// Error statistics.
    pub errors: ChannelErrorStats,
    /// Total channel capacity in MiB.
    pub capacity_mib: u64,
}

impl MemChannel {
    const fn new() -> Self {
        Self {
            active: false,
            dimms: [const { DimmInfo::empty() }; MAX_DIMMS_PER_CHANNEL],
            errors: ChannelErrorStats::new(),
            capacity_mib: 0,
        }
    }

    /// Compute and cache total channel capacity from populated DIMMs.
    pub fn compute_capacity(&mut self) {
        self.capacity_mib = 0;
        for dimm in &self.dimms {
            if dimm.present {
                self.capacity_mib += dimm.size_mib as u64;
            }
        }
    }
}

// ── Scrub Mode ─────────────────────────────────────────────────────────────

/// DRAM patrol scrubbing mode.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ScrubMode {
    /// Hardware patrol scrubbing disabled.
    Disabled,
    /// Hardware patrol scrubbing enabled.
    Enabled,
    /// Demand scrubbing only (on access).
    DemandOnly,
}

// ── Memory Controller ──────────────────────────────────────────────────────

/// Memory controller abstraction.
pub struct MemController {
    /// Controller index in the system.
    index: u8,
    /// MMIO base for register access (0 = no MMIO, uses port I/O).
    mmio_base: Option<usize>,
    /// Memory channels.
    pub channels: [MemChannel; MAX_CHANNELS],
    /// Number of active channels.
    pub channel_count: usize,
    /// Current scrub mode.
    pub scrub_mode: ScrubMode,
    /// Total system memory managed by this controller in MiB.
    pub total_mib: u64,
}

impl MemController {
    /// Create a new memory controller descriptor.
    pub fn new(index: u8, mmio_base: Option<usize>) -> Self {
        Self {
            index,
            mmio_base,
            channels: [const { MemChannel::new() }; MAX_CHANNELS],
            channel_count: 0,
            scrub_mode: ScrubMode::Disabled,
            total_mib: 0,
        }
    }

    /// Register a channel with DIMM population.
    pub fn add_channel(&mut self, dimms: &[DimmInfo]) -> Result<()> {
        if self.channel_count >= MAX_CHANNELS {
            return Err(Error::OutOfMemory);
        }
        let ch = &mut self.channels[self.channel_count];
        ch.active = true;
        for (i, d) in dimms.iter().enumerate().take(MAX_DIMMS_PER_CHANNEL) {
            ch.dimms[i] = *d;
        }
        ch.compute_capacity();
        self.total_mib += ch.capacity_mib;
        self.channel_count += 1;
        Ok(())
    }

    /// Report a memory error and update statistics.
    pub fn report_error(&mut self, error: MemError) -> Result<()> {
        let ch = error.channel as usize;
        if ch >= self.channel_count {
            return Err(Error::InvalidArgument);
        }
        self.channels[ch].errors.record(&error);
        Ok(())
    }

    /// Enable hardware patrol scrubbing.
    ///
    /// # Safety
    /// Writes to the memory controller's scrub control register at `mmio_base`.
    pub unsafe fn enable_scrubbing(&mut self) -> Result<()> {
        let base = self.mmio_base.ok_or(Error::NotImplemented)?;
        // Scrub enable register at offset 0x100 (chipset-specific).
        // SAFETY: base is a valid MMIO region for this controller.
        unsafe { core::ptr::write_volatile((base + 0x100) as *mut u32, 1) }
        self.scrub_mode = ScrubMode::Enabled;
        Ok(())
    }

    /// Disable hardware patrol scrubbing.
    ///
    /// # Safety
    /// Writes to the memory controller's scrub control register.
    pub unsafe fn disable_scrubbing(&mut self) -> Result<()> {
        let base = self.mmio_base.ok_or(Error::NotImplemented)?;
        // SAFETY: base is valid MMIO for this controller.
        unsafe { core::ptr::write_volatile((base + 0x100) as *mut u32, 0) }
        self.scrub_mode = ScrubMode::Disabled;
        Ok(())
    }

    /// Return the controller index.
    pub fn index(&self) -> u8 {
        self.index
    }

    /// Return total correctable errors across all channels.
    pub fn total_correctable_errors(&self) -> u64 {
        self.channels[..self.channel_count]
            .iter()
            .map(|c| c.errors.correctable)
            .sum()
    }

    /// Return total uncorrectable errors across all channels.
    pub fn total_uncorrectable_errors(&self) -> u64 {
        self.channels[..self.channel_count]
            .iter()
            .map(|c| c.errors.uncorrectable)
            .sum()
    }
}

// ── System Memory View ─────────────────────────────────────────────────────

/// System-wide memory controller registry.
pub struct MemControllerRegistry {
    controllers: [Option<MemController>; MAX_CONTROLLERS],
    count: usize,
}

impl MemControllerRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            controllers: [const { None }; MAX_CONTROLLERS],
            count: 0,
        }
    }

    /// Register a memory controller.
    pub fn register(&mut self, mc: MemController) -> Result<()> {
        if self.count >= MAX_CONTROLLERS {
            return Err(Error::OutOfMemory);
        }
        self.controllers[self.count] = Some(mc);
        self.count += 1;
        Ok(())
    }

    /// Get a reference to a controller by index.
    pub fn get(&self, idx: usize) -> Option<&MemController> {
        self.controllers.get(idx)?.as_ref()
    }

    /// Get a mutable reference to a controller.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut MemController> {
        self.controllers.get_mut(idx)?.as_mut()
    }

    /// Return the total system memory in MiB.
    pub fn total_memory_mib(&self) -> u64 {
        self.controllers[..self.count]
            .iter()
            .flatten()
            .map(|mc| mc.total_mib)
            .sum()
    }

    /// Return the count of registered controllers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return true if no controllers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for MemControllerRegistry {
    fn default() -> Self {
        Self::new()
    }
}
