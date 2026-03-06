// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Analog-to-Digital Converter (ADC) hardware abstraction.
//!
//! Provides a unified interface for hardware ADC controllers supporting
//! single-ended and differential input channels, programmable gain amplifiers,
//! sample-and-hold circuits, and DMA-based continuous conversion modes.

use oncrix_lib::{Error, Result};

/// Maximum number of ADC controllers.
pub const MAX_ADC_CONTROLLERS: usize = 4;

/// Maximum number of ADC input channels per controller.
pub const MAX_ADC_CHANNELS: usize = 16;

/// ADC resolution (bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdcResolution {
    /// 8-bit resolution (256 levels).
    Bits8,
    /// 10-bit resolution (1024 levels).
    Bits10,
    /// 12-bit resolution (4096 levels).
    Bits12,
    /// 14-bit resolution (16384 levels).
    Bits14,
    /// 16-bit resolution (65536 levels).
    Bits16,
    /// 24-bit resolution (delta-sigma ADC).
    Bits24,
}

impl AdcResolution {
    /// Returns the resolution in bits.
    pub fn bits(self) -> u8 {
        match self {
            AdcResolution::Bits8 => 8,
            AdcResolution::Bits10 => 10,
            AdcResolution::Bits12 => 12,
            AdcResolution::Bits14 => 14,
            AdcResolution::Bits16 => 16,
            AdcResolution::Bits24 => 24,
        }
    }

    /// Returns the maximum raw sample value (2^bits - 1).
    pub fn max_raw(self) -> u32 {
        (1u32 << self.bits()) - 1
    }
}

/// ADC sampling mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdcSamplingMode {
    /// Single conversion — one sample per trigger.
    Single,
    /// Continuous conversion — automatic re-triggering.
    Continuous,
    /// Scan mode — cycles through a channel list.
    Scan,
    /// DMA-driven continuous mode.
    DmaContinuous,
}

/// ADC channel input mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdcInputMode {
    /// Single-ended input (channel vs. GND).
    SingleEnded,
    /// Differential input (channel+ vs. channel-).
    Differential,
}

/// ADC channel configuration.
#[derive(Debug, Clone, Copy)]
pub struct AdcChannelConfig {
    /// Channel index (0..MAX_ADC_CHANNELS).
    pub channel: u8,
    /// Input mode.
    pub input_mode: AdcInputMode,
    /// Differential negative channel (only for Differential mode).
    pub diff_neg_channel: u8,
    /// Programmable gain amplifier setting (0 = 1x, up to 7 = 128x).
    pub pga_gain: u8,
    /// Sample time in ADC clock cycles.
    pub sample_cycles: u32,
}

impl AdcChannelConfig {
    /// Creates a default single-ended channel configuration.
    pub const fn single_ended(channel: u8) -> Self {
        Self {
            channel,
            input_mode: AdcInputMode::SingleEnded,
            diff_neg_channel: 0,
            pga_gain: 0,
            sample_cycles: 64,
        }
    }

    /// Creates a differential channel configuration.
    pub const fn differential(pos_channel: u8, neg_channel: u8) -> Self {
        Self {
            channel: pos_channel,
            input_mode: AdcInputMode::Differential,
            diff_neg_channel: neg_channel,
            pga_gain: 0,
            sample_cycles: 64,
        }
    }
}

impl Default for AdcChannelConfig {
    fn default() -> Self {
        Self::single_ended(0)
    }
}

/// A single ADC sample.
#[derive(Debug, Clone, Copy, Default)]
pub struct AdcSample {
    /// Channel from which this sample was taken.
    pub channel: u8,
    /// Raw ADC sample value.
    pub raw: u32,
    /// Timestamp in hardware timer ticks (controller-specific).
    pub timestamp: u64,
}

impl AdcSample {
    /// Converts the raw sample to a voltage (milli-Volts) given the reference voltage.
    ///
    /// # Arguments
    /// * `vref_mv` — Reference voltage in milli-Volts.
    /// * `resolution` — ADC resolution.
    pub fn to_mv(&self, vref_mv: u32, resolution: AdcResolution) -> u32 {
        let max = resolution.max_raw();
        if max == 0 {
            return 0;
        }
        (self.raw * vref_mv) / max
    }
}

/// ADC controller statistics.
#[derive(Debug, Default, Clone, Copy)]
pub struct AdcStats {
    /// Total samples converted.
    pub samples: u64,
    /// Number of conversion overrun errors.
    pub overruns: u64,
    /// Number of DMA transfer completions.
    pub dma_completions: u64,
}

impl AdcStats {
    /// Creates a new zeroed statistics structure.
    pub const fn new() -> Self {
        Self {
            samples: 0,
            overruns: 0,
            dma_completions: 0,
        }
    }
}

/// Hardware ADC controller driver.
pub struct AdcController {
    /// Controller index.
    id: u8,
    /// MMIO base address.
    base_addr: u64,
    /// ADC resolution.
    resolution: AdcResolution,
    /// Sampling mode.
    sampling_mode: AdcSamplingMode,
    /// Reference voltage in milli-Volts.
    vref_mv: u32,
    /// Clock rate in Hz.
    clock_hz: u32,
    /// Active channel configurations.
    channels: [AdcChannelConfig; MAX_ADC_CHANNELS],
    /// Number of configured channels.
    channel_count: usize,
    /// Transfer statistics.
    stats: AdcStats,
    /// Whether the controller has been initialized.
    initialized: bool,
}

impl AdcController {
    /// Creates a new ADC controller.
    ///
    /// # Arguments
    /// * `id` — Controller identifier.
    /// * `base_addr` — MMIO base address.
    /// * `resolution` — ADC resolution.
    /// * `vref_mv` — Reference voltage in milli-Volts.
    pub const fn new(id: u8, base_addr: u64, resolution: AdcResolution, vref_mv: u32) -> Self {
        Self {
            id,
            base_addr,
            resolution,
            sampling_mode: AdcSamplingMode::Single,
            vref_mv,
            clock_hz: 1_000_000,
            channels: [const { AdcChannelConfig::single_ended(0) }; MAX_ADC_CHANNELS],
            channel_count: 0,
            stats: AdcStats::new(),
            initialized: false,
        }
    }

    /// Returns the controller ID.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Returns the ADC resolution.
    pub fn resolution(&self) -> AdcResolution {
        self.resolution
    }

    /// Returns the reference voltage in milli-Volts.
    pub fn vref_mv(&self) -> u32 {
        self.vref_mv
    }

    /// Initializes the ADC controller hardware.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if base_addr is zero.
    pub fn init(&mut self) -> Result<()> {
        if self.base_addr == 0 {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO writes to ADC control and configuration registers.
        // base_addr is validated to be non-zero.
        unsafe {
            let ctrl = self.base_addr as *mut u32;
            ctrl.write_volatile(0x1); // ADC reset
            ctrl.write_volatile(0x0); // Release reset

            let cfg = (self.base_addr + 0x04) as *mut u32;
            let res_bits = match self.resolution {
                AdcResolution::Bits8 => 0u32,
                AdcResolution::Bits10 => 1,
                AdcResolution::Bits12 => 2,
                AdcResolution::Bits14 => 3,
                AdcResolution::Bits16 => 4,
                AdcResolution::Bits24 => 5,
            };
            cfg.write_volatile(res_bits);

            let vref = (self.base_addr + 0x08) as *mut u32;
            vref.write_volatile(self.vref_mv);
        }
        self.initialized = true;
        Ok(())
    }

    /// Configures a channel for conversion.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    /// Returns `Error::InvalidArgument` if channel index is invalid.
    pub fn configure_channel(&mut self, config: AdcChannelConfig) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        if (config.channel as usize) >= MAX_ADC_CHANNELS {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO write to ADC channel configuration register.
        // base_addr is non-zero. channel is bounds-checked above.
        unsafe {
            let ch_cfg = (self.base_addr + 0x100 + (config.channel as u64) * 4) as *mut u32;
            let mode_bit = match config.input_mode {
                AdcInputMode::SingleEnded => 0u32,
                AdcInputMode::Differential => 1 << 8,
            };
            ch_cfg.write_volatile(
                (config.pga_gain as u32) | mode_bit | ((config.sample_cycles / 8) << 16),
            );
        }
        if self.channel_count < MAX_ADC_CHANNELS {
            self.channels[self.channel_count] = config;
            self.channel_count += 1;
        }
        Ok(())
    }

    /// Triggers a single conversion on the specified channel.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized or conversion in progress.
    /// Returns `Error::InvalidArgument` if channel is out of range.
    pub fn start_conversion(&self, channel: u8) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        if (channel as usize) >= MAX_ADC_CHANNELS {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO write to ADC conversion trigger register. base_addr is non-zero.
        unsafe {
            let trig = (self.base_addr + 0x10) as *mut u32;
            trig.write_volatile((channel as u32) | 0x80000000); // Channel select + trigger
        }
        Ok(())
    }

    /// Reads the conversion result from the specified channel.
    ///
    /// Polls the "end of conversion" flag, then reads the data register.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized or conversion not complete.
    /// Returns `Error::InvalidArgument` if channel is out of range.
    pub fn read_sample(&mut self, channel: u8) -> Result<AdcSample> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        if (channel as usize) >= MAX_ADC_CHANNELS {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO reads from ADC status and data registers. base_addr is non-zero.
        let (raw, timestamp) = unsafe {
            let sr = (self.base_addr + 0x14) as *const u32;
            let mut timeout = 10_000u32;
            while sr.read_volatile() & 0x1 == 0 {
                timeout -= 1;
                if timeout == 0 {
                    return Err(Error::Busy);
                }
            }
            let dr = (self.base_addr + 0x18 + (channel as u64) * 4) as *const u32;
            let ts = (self.base_addr + 0x1C) as *const u64;
            (dr.read_volatile(), ts.read_volatile())
        };
        self.stats.samples += 1;
        Ok(AdcSample {
            channel,
            raw,
            timestamp,
        })
    }

    /// Returns a copy of the statistics.
    pub fn stats(&self) -> AdcStats {
        self.stats
    }
}

impl Default for AdcController {
    fn default() -> Self {
        Self::new(0, 0, AdcResolution::Bits12, 3300)
    }
}

/// Registry of ADC controllers.
pub struct AdcRegistry {
    controllers: [AdcController; MAX_ADC_CONTROLLERS],
    count: usize,
}

impl AdcRegistry {
    /// Creates a new empty ADC registry.
    pub fn new() -> Self {
        Self {
            controllers: [
                AdcController::new(0, 0, AdcResolution::Bits12, 3300),
                AdcController::new(1, 0, AdcResolution::Bits12, 3300),
                AdcController::new(2, 0, AdcResolution::Bits16, 5000),
                AdcController::new(3, 0, AdcResolution::Bits24, 3300),
            ],
            count: 0,
        }
    }

    /// Registers an ADC controller.
    ///
    /// # Errors
    /// Returns `Error::OutOfMemory` if the registry is full.
    pub fn register(&mut self, ctrl: AdcController) -> Result<()> {
        if self.count >= MAX_ADC_CONTROLLERS {
            return Err(Error::OutOfMemory);
        }
        self.controllers[self.count] = ctrl;
        self.count += 1;
        Ok(())
    }

    /// Returns the number of registered controllers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no controllers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns a mutable reference to the controller at the given index.
    ///
    /// # Errors
    /// Returns `Error::NotFound` if the index is out of range.
    pub fn get_mut(&mut self, index: usize) -> Result<&mut AdcController> {
        if index >= self.count {
            return Err(Error::NotFound);
        }
        Ok(&mut self.controllers[index])
    }
}

impl Default for AdcRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Converts a raw ADC sample to a voltage in milli-Volts.
///
/// # Arguments
/// * `raw` — Raw ADC value.
/// * `max_raw` — Maximum raw value for this resolution.
/// * `vref_mv` — Reference voltage in milli-Volts.
pub fn raw_to_mv(raw: u32, max_raw: u32, vref_mv: u32) -> u32 {
    if max_raw == 0 {
        return 0;
    }
    (raw * vref_mv) / max_raw
}

/// Computes the theoretical noise-free bits for a given signal-to-noise ratio.
///
/// NFB ≈ (ENOB) = (SNR_dB - 1.76) / 6.02
/// Returns noise-free bits multiplied by 100 (fixed-point).
pub fn snr_to_enob_x100(snr_db_x100: u32) -> u32 {
    if snr_db_x100 < 176 {
        return 0;
    }
    (snr_db_x100 - 176) * 100 / 602
}
