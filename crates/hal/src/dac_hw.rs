// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Digital-to-Analog Converter (DAC) hardware abstraction.
//!
//! Provides a unified interface for hardware DAC controllers supporting
//! single-channel and multi-channel output, programmable output ranges,
//! and both static (register-set) and waveform generation modes.

use oncrix_lib::{Error, Result};

/// Maximum number of DAC controllers.
pub const MAX_DAC_CONTROLLERS: usize = 4;

/// Maximum number of DAC output channels per controller.
pub const MAX_DAC_CHANNELS: usize = 8;

/// DAC resolution (bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DacResolution {
    /// 8-bit resolution (256 output levels).
    Bits8,
    /// 10-bit resolution (1024 output levels).
    Bits10,
    /// 12-bit resolution (4096 output levels).
    Bits12,
    /// 16-bit resolution (65536 output levels).
    Bits16,
}

impl DacResolution {
    /// Returns the resolution in bits.
    pub const fn bits(self) -> u8 {
        match self {
            DacResolution::Bits8 => 8,
            DacResolution::Bits10 => 10,
            DacResolution::Bits12 => 12,
            DacResolution::Bits16 => 16,
        }
    }

    /// Returns the maximum raw output code (2^bits - 1).
    pub const fn max_code(self) -> u32 {
        (1u32 << self.bits()) - 1
    }
}

/// DAC output mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DacOutputMode {
    /// Normal output mode — write code directly to output.
    Normal,
    /// Buffered output — output amplifier enabled for driving low-impedance loads.
    Buffered,
    /// Triangle wave generation using hardware auto-generation.
    TriangleWave,
    /// Sawtooth wave generation.
    SawtoothWave,
    /// Noise generation using hardware LFSR.
    Noise,
}

/// DAC trigger source for DMA and waveform modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DacTrigger {
    /// Software trigger (manual register write).
    Software,
    /// Timer 2 trigger.
    Timer2,
    /// Timer 4 trigger.
    Timer4,
    /// Timer 6 trigger.
    Timer6,
    /// External trigger via GPIO pin.
    External,
    /// DMA trigger.
    Dma,
}

/// Configuration for a single DAC channel.
#[derive(Debug, Clone, Copy)]
pub struct DacChannelConfig {
    /// Channel index (0..MAX_DAC_CHANNELS).
    pub channel: u8,
    /// Output mode.
    pub output_mode: DacOutputMode,
    /// Trigger source.
    pub trigger: DacTrigger,
    /// Reference voltage in milli-Volts.
    pub vref_mv: u32,
    /// Initial output code (0..max_code).
    pub initial_code: u32,
}

impl DacChannelConfig {
    /// Creates a default single-channel normal-mode configuration.
    pub const fn new(channel: u8, vref_mv: u32) -> Self {
        Self {
            channel,
            output_mode: DacOutputMode::Normal,
            trigger: DacTrigger::Software,
            vref_mv,
            initial_code: 0,
        }
    }
}

impl Default for DacChannelConfig {
    fn default() -> Self {
        Self::new(0, 3300)
    }
}

/// DAC waveform triangle/sawtooth parameters.
#[derive(Debug, Clone, Copy)]
pub struct DacWaveformParams {
    /// Maximum output code for the waveform peak.
    pub max_code: u32,
    /// Minimum output code for the waveform trough.
    pub min_code: u32,
    /// Increment step per trigger event.
    pub step: u32,
}

impl DacWaveformParams {
    /// Creates waveform params sweeping the full range of the given resolution.
    pub const fn full_range(resolution: DacResolution) -> Self {
        Self {
            max_code: resolution.max_code(),
            min_code: 0,
            step: 1,
        }
    }
}

impl Default for DacWaveformParams {
    fn default() -> Self {
        Self::full_range(DacResolution::Bits12)
    }
}

/// DAC controller statistics.
#[derive(Debug, Default, Clone, Copy)]
pub struct DacStats {
    /// Total individual code writes.
    pub code_writes: u64,
    /// Total DMA transfer completions.
    pub dma_completions: u64,
    /// Number of output underrun events.
    pub underruns: u64,
}

impl DacStats {
    /// Creates a new zeroed statistics structure.
    pub const fn new() -> Self {
        Self {
            code_writes: 0,
            dma_completions: 0,
            underruns: 0,
        }
    }
}

/// Hardware DAC controller driver.
pub struct DacController {
    /// Controller index.
    id: u8,
    /// MMIO base address.
    base_addr: u64,
    /// DAC resolution.
    resolution: DacResolution,
    /// Number of output channels.
    channel_count: u8,
    /// Current output codes per channel.
    current_codes: [u32; MAX_DAC_CHANNELS],
    /// Transfer statistics.
    stats: DacStats,
    /// Whether the controller has been initialized.
    initialized: bool,
}

impl DacController {
    /// Creates a new DAC controller.
    ///
    /// # Arguments
    /// * `id` — Controller identifier.
    /// * `base_addr` — MMIO base address.
    /// * `resolution` — DAC output resolution.
    /// * `channel_count` — Number of output channels.
    pub const fn new(id: u8, base_addr: u64, resolution: DacResolution, channel_count: u8) -> Self {
        Self {
            id,
            base_addr,
            resolution,
            channel_count,
            current_codes: [0u32; MAX_DAC_CHANNELS],
            stats: DacStats::new(),
            initialized: false,
        }
    }

    /// Returns the controller ID.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Returns the DAC resolution.
    pub fn resolution(&self) -> DacResolution {
        self.resolution
    }

    /// Returns the number of output channels.
    pub fn channel_count(&self) -> u8 {
        self.channel_count
    }

    /// Initializes the DAC controller hardware.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if base_addr is zero or channel_count is zero.
    pub fn init(&mut self) -> Result<()> {
        if self.base_addr == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.channel_count == 0 || (self.channel_count as usize) > MAX_DAC_CHANNELS {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO writes to DAC controller reset and configuration registers.
        // base_addr is validated to be non-zero.
        unsafe {
            let ctrl = self.base_addr as *mut u32;
            ctrl.write_volatile(0x1); // Reset
            ctrl.write_volatile(0x0); // Release reset
            let res_reg = (self.base_addr + 0x04) as *mut u32;
            res_reg.write_volatile(self.resolution.bits() as u32);
            let nchan = (self.base_addr + 0x08) as *mut u32;
            nchan.write_volatile(self.channel_count as u32);
        }
        self.initialized = true;
        Ok(())
    }

    /// Configures a DAC output channel.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    /// Returns `Error::InvalidArgument` if channel is out of range.
    pub fn configure_channel(&mut self, config: DacChannelConfig) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        if (config.channel as usize) >= self.channel_count as usize {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO write to DAC channel configuration register.
        // base_addr is non-zero. channel is bounds-checked.
        unsafe {
            let ch_cfg = (self.base_addr + 0x100 + (config.channel as u64) * 8) as *mut u32;
            let mode = match config.output_mode {
                DacOutputMode::Normal => 0u32,
                DacOutputMode::Buffered => 1,
                DacOutputMode::TriangleWave => 2,
                DacOutputMode::SawtoothWave => 3,
                DacOutputMode::Noise => 4,
            };
            let trig = match config.trigger {
                DacTrigger::Software => 0u32,
                DacTrigger::Timer2 => 1,
                DacTrigger::Timer4 => 2,
                DacTrigger::Timer6 => 3,
                DacTrigger::External => 4,
                DacTrigger::Dma => 5,
            };
            ch_cfg.write_volatile(mode | (trig << 4));
            let initial = (self.base_addr + 0x104 + (config.channel as u64) * 8) as *mut u32;
            initial.write_volatile(config.initial_code & self.resolution.max_code());
        }
        self.current_codes[config.channel as usize] = config.initial_code;
        Ok(())
    }

    /// Sets the output code for a DAC channel.
    ///
    /// # Arguments
    /// * `channel` — Channel index.
    /// * `code` — Output code (0..max_code).
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    /// Returns `Error::InvalidArgument` if channel is out of range or code exceeds max.
    pub fn set_code(&mut self, channel: u8, code: u32) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        if (channel as usize) >= self.channel_count as usize {
            return Err(Error::InvalidArgument);
        }
        if code > self.resolution.max_code() {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO write to DAC data holding register. base_addr is non-zero.
        unsafe {
            let dhr = (self.base_addr + 0x200 + (channel as u64) * 4) as *mut u32;
            dhr.write_volatile(code);
        }
        self.current_codes[channel as usize] = code;
        self.stats.code_writes += 1;
        Ok(())
    }

    /// Sets the output voltage for a DAC channel.
    ///
    /// # Arguments
    /// * `channel` — Channel index.
    /// * `voltage_mv` — Target output voltage in milli-Volts.
    /// * `vref_mv` — Reference voltage in milli-Volts.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    /// Returns `Error::InvalidArgument` if voltage exceeds vref.
    pub fn set_voltage_mv(&mut self, channel: u8, voltage_mv: u32, vref_mv: u32) -> Result<()> {
        if voltage_mv > vref_mv {
            return Err(Error::InvalidArgument);
        }
        let max_code = self.resolution.max_code();
        let code = if vref_mv == 0 {
            0
        } else {
            (voltage_mv * max_code) / vref_mv
        };
        self.set_code(channel, code.min(max_code))
    }

    /// Returns the current output code for a channel.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if channel is out of range.
    pub fn current_code(&self, channel: u8) -> Result<u32> {
        if (channel as usize) >= self.channel_count as usize {
            return Err(Error::InvalidArgument);
        }
        Ok(self.current_codes[channel as usize])
    }

    /// Configures waveform generation parameters for a channel.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized.
    /// Returns `Error::InvalidArgument` if channel is out of range.
    pub fn set_waveform_params(&mut self, channel: u8, params: DacWaveformParams) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        if (channel as usize) >= self.channel_count as usize {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: MMIO writes to DAC waveform parameter registers. base_addr is non-zero.
        unsafe {
            let base = (self.base_addr + 0x300 + (channel as u64) * 16) as *mut u32;
            base.write_volatile(params.max_code);
            base.add(1).write_volatile(params.min_code);
            base.add(2).write_volatile(params.step);
        }
        Ok(())
    }

    /// Returns a copy of the statistics.
    pub fn stats(&self) -> DacStats {
        self.stats
    }
}

impl Default for DacController {
    fn default() -> Self {
        Self::new(0, 0, DacResolution::Bits12, 2)
    }
}

/// Registry of DAC controllers.
pub struct DacRegistry {
    controllers: [DacController; MAX_DAC_CONTROLLERS],
    count: usize,
}

impl DacRegistry {
    /// Creates a new empty DAC registry.
    pub fn new() -> Self {
        Self {
            controllers: [
                DacController::new(0, 0, DacResolution::Bits12, 2),
                DacController::new(1, 0, DacResolution::Bits12, 2),
                DacController::new(2, 0, DacResolution::Bits16, 4),
                DacController::new(3, 0, DacResolution::Bits8, 1),
            ],
            count: 0,
        }
    }

    /// Registers a DAC controller.
    ///
    /// # Errors
    /// Returns `Error::OutOfMemory` if the registry is full.
    pub fn register(&mut self, ctrl: DacController) -> Result<()> {
        if self.count >= MAX_DAC_CONTROLLERS {
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
    pub fn get_mut(&mut self, index: usize) -> Result<&mut DacController> {
        if index >= self.count {
            return Err(Error::NotFound);
        }
        Ok(&mut self.controllers[index])
    }
}

impl Default for DacRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Converts a voltage in milli-Volts to a DAC output code.
///
/// # Arguments
/// * `voltage_mv` — Desired output voltage in milli-Volts.
/// * `vref_mv` — Reference voltage in milli-Volts.
/// * `max_code` — Maximum code for the DAC resolution.
pub fn mv_to_code(voltage_mv: u32, vref_mv: u32, max_code: u32) -> u32 {
    if vref_mv == 0 {
        return 0;
    }
    ((voltage_mv as u64 * max_code as u64) / vref_mv as u64) as u32
}

/// Converts a DAC output code back to a voltage in milli-Volts.
///
/// # Arguments
/// * `code` — DAC output code.
/// * `vref_mv` — Reference voltage in milli-Volts.
/// * `max_code` — Maximum code for the DAC resolution.
pub fn code_to_mv(code: u32, vref_mv: u32, max_code: u32) -> u32 {
    if max_code == 0 {
        return 0;
    }
    ((code as u64 * vref_mv as u64) / max_code as u64) as u32
}

/// Returns the LSB step size in micro-Volts for a given resolution and reference.
///
/// LSB = vref_mv * 1000 / (2^bits)
pub fn lsb_uv(vref_mv: u32, resolution: DacResolution) -> u32 {
    let codes = 1u64 << resolution.bits();
    ((vref_mv as u64 * 1000) / codes) as u32
}
