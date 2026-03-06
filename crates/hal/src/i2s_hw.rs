// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! I2S (Inter-IC Sound) audio bus hardware abstraction.
//!
//! Provides a unified interface for I2S bus controllers used to transmit
//! digital audio data between processors and audio codecs. Supports
//! standard I2S, left-justified, right-justified, and TDM formats,
//! with configurable sample rates and bit depths.

use oncrix_lib::{Error, Result};

/// Maximum number of I2S controllers.
pub const MAX_I2S_CONTROLLERS: usize = 4;

/// Maximum TDM slots per frame.
pub const MAX_TDM_SLOTS: usize = 8;

/// I2S audio format / framing standard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I2sFormat {
    /// Standard Philips I2S (1-bit delay, MSB first).
    Standard,
    /// Left-justified (no delay, MSB first).
    LeftJustified,
    /// Right-justified (LSB aligned to frame end).
    RightJustified,
    /// Time-Division Multiplexed (multi-channel I2S).
    Tdm,
    /// PCM short frame sync.
    PcmShort,
    /// PCM long frame sync.
    PcmLong,
}

/// I2S controller role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I2sRole {
    /// Controller generates the bit clock (BCLK) and frame sync (WS/LRCK).
    Master,
    /// Controller receives BCLK and WS from an external master.
    Slave,
}

/// Audio sample rate in Hz.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SampleRate {
    /// 8 kHz (telephony).
    Hz8000 = 8_000,
    /// 16 kHz (wideband audio).
    Hz16000 = 16_000,
    /// 22.05 kHz.
    Hz22050 = 22_050,
    /// 44.1 kHz (CD audio).
    Hz44100 = 44_100,
    /// 48 kHz (professional audio).
    Hz48000 = 48_000,
    /// 96 kHz (high-resolution audio).
    Hz96000 = 96_000,
    /// 192 kHz (studio quality).
    Hz192000 = 192_000,
}

/// Bit depth (bits per sample).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BitDepth {
    /// 16-bit samples.
    Bits16 = 16,
    /// 20-bit samples.
    Bits20 = 20,
    /// 24-bit samples.
    Bits24 = 24,
    /// 32-bit samples.
    Bits32 = 32,
}

/// I2S controller configuration.
#[derive(Debug, Clone, Copy)]
pub struct I2sConfig {
    /// Audio format.
    pub format: I2sFormat,
    /// Controller role.
    pub role: I2sRole,
    /// Sample rate.
    pub sample_rate: SampleRate,
    /// Bit depth.
    pub bit_depth: BitDepth,
    /// Number of channels (1=mono, 2=stereo, up to MAX_TDM_SLOTS for TDM).
    pub channels: u8,
    /// MCLK (master clock) multiplier relative to sample rate.
    pub mclk_multiplier: u32,
}

impl I2sConfig {
    /// Creates a standard stereo I2S configuration.
    pub const fn stereo(sample_rate: SampleRate, bit_depth: BitDepth) -> Self {
        Self {
            format: I2sFormat::Standard,
            role: I2sRole::Master,
            sample_rate,
            bit_depth,
            channels: 2,
            mclk_multiplier: 256,
        }
    }

    /// Computes the bit clock frequency in Hz.
    pub fn bclk_hz(&self) -> u32 {
        self.sample_rate as u32 * self.bit_depth as u32 * self.channels as u32
    }

    /// Computes the master clock frequency in Hz.
    pub fn mclk_hz(&self) -> u32 {
        self.sample_rate as u32 * self.mclk_multiplier
    }
}

impl Default for I2sConfig {
    fn default() -> Self {
        Self::stereo(SampleRate::Hz48000, BitDepth::Bits16)
    }
}

/// I2S transfer statistics.
#[derive(Debug, Default, Clone, Copy)]
pub struct I2sStats {
    /// Total frames transmitted.
    pub frames_tx: u64,
    /// Total frames received.
    pub frames_rx: u64,
    /// Number of TX FIFO underruns.
    pub tx_underruns: u64,
    /// Number of RX FIFO overruns.
    pub rx_overruns: u64,
}

impl I2sStats {
    /// Creates a new zeroed statistics structure.
    pub const fn new() -> Self {
        Self {
            frames_tx: 0,
            frames_rx: 0,
            tx_underruns: 0,
            rx_overruns: 0,
        }
    }
}

/// Hardware I2S controller.
pub struct I2sController {
    /// Controller index.
    id: u8,
    /// MMIO base address.
    base_addr: u64,
    /// Current configuration.
    config: I2sConfig,
    /// Transfer statistics.
    stats: I2sStats,
    /// Whether the controller has been initialized.
    initialized: bool,
    /// Whether audio streaming is active.
    streaming: bool,
}

impl I2sController {
    /// Creates a new I2S controller.
    ///
    /// # Arguments
    /// * `id` — Controller identifier.
    /// * `base_addr` — MMIO base address of the I2S registers.
    pub const fn new(id: u8, base_addr: u64) -> Self {
        Self {
            id,
            base_addr,
            config: I2sConfig::stereo(SampleRate::Hz48000, BitDepth::Bits16),
            stats: I2sStats::new(),
            initialized: false,
            streaming: false,
        }
    }

    /// Returns the controller ID.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Returns the current configuration.
    pub fn config(&self) -> &I2sConfig {
        &self.config
    }

    /// Returns whether audio streaming is active.
    pub fn is_streaming(&self) -> bool {
        self.streaming
    }

    /// Initializes the I2S controller with the given configuration.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if base_addr is zero or channels invalid.
    pub fn init(&mut self, config: I2sConfig) -> Result<()> {
        if self.base_addr == 0 {
            return Err(Error::InvalidArgument);
        }
        if config.channels == 0 || (config.channels as usize) > MAX_TDM_SLOTS {
            return Err(Error::InvalidArgument);
        }
        self.config = config;
        // SAFETY: MMIO write to I2S configuration registers. base_addr is non-zero.
        unsafe {
            let ctrl = self.base_addr as *mut u32;
            ctrl.write_volatile(0); // Disable before reconfiguring
            // Format register
            let fmt_reg = (self.base_addr + 0x04) as *mut u32;
            let fmt_val = match config.format {
                I2sFormat::Standard => 0,
                I2sFormat::LeftJustified => 1,
                I2sFormat::RightJustified => 2,
                I2sFormat::Tdm => 3,
                I2sFormat::PcmShort => 4,
                I2sFormat::PcmLong => 5,
            };
            fmt_reg.write_volatile(fmt_val);
            // Clock/rate register
            let clk_reg = (self.base_addr + 0x08) as *mut u32;
            clk_reg.write_volatile(config.sample_rate as u32);
            // Word size register
            let ws_reg = (self.base_addr + 0x0C) as *mut u32;
            ws_reg.write_volatile(config.bit_depth as u32);
        }
        self.initialized = true;
        Ok(())
    }

    /// Starts audio streaming.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not initialized or already streaming.
    pub fn start(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        if self.streaming {
            return Err(Error::Busy);
        }
        // SAFETY: MMIO write to I2S enable register. base_addr is non-zero.
        unsafe {
            let ctrl = self.base_addr as *mut u32;
            let val = ctrl.read_volatile();
            ctrl.write_volatile(val | 0x1);
        }
        self.streaming = true;
        Ok(())
    }

    /// Stops audio streaming.
    pub fn stop(&mut self) {
        if !self.streaming {
            return;
        }
        // SAFETY: MMIO write to I2S enable register. base_addr is non-zero.
        unsafe {
            let ctrl = self.base_addr as *mut u32;
            let val = ctrl.read_volatile();
            ctrl.write_volatile(val & !0x1);
        }
        self.streaming = false;
    }

    /// Writes audio samples to the TX FIFO.
    ///
    /// # Arguments
    /// * `samples` — Slice of 32-bit sample words (left-aligned).
    ///
    /// # Errors
    /// Returns `Error::Busy` if not streaming.
    /// Returns `Error::WouldBlock` if the TX FIFO is full.
    pub fn write_samples(&mut self, samples: &[u32]) -> Result<usize> {
        if !self.streaming {
            return Err(Error::Busy);
        }
        let mut written = 0;
        // SAFETY: MMIO read/write to I2S TX FIFO and status registers.
        // base_addr is non-zero and was validated during init().
        unsafe {
            let sr = (self.base_addr + 0x10) as *const u32;
            let fifo = (self.base_addr + 0x14) as *mut u32;
            for &sample in samples {
                let status = sr.read_volatile();
                if status & 0x1 != 0 {
                    // TX FIFO full
                    break;
                }
                fifo.write_volatile(sample);
                written += 1;
            }
        }
        self.stats.frames_tx += written as u64;
        if written == 0 {
            return Err(Error::WouldBlock);
        }
        Ok(written)
    }

    /// Reads audio samples from the RX FIFO.
    ///
    /// # Arguments
    /// * `buf` — Output buffer for received 32-bit sample words.
    ///
    /// # Errors
    /// Returns `Error::Busy` if not streaming.
    /// Returns `Error::WouldBlock` if the RX FIFO is empty.
    pub fn read_samples(&mut self, buf: &mut [u32]) -> Result<usize> {
        if !self.streaming {
            return Err(Error::Busy);
        }
        let mut read = 0;
        // SAFETY: MMIO read from I2S RX FIFO. base_addr is non-zero.
        unsafe {
            let sr = (self.base_addr + 0x10) as *const u32;
            let fifo = (self.base_addr + 0x18) as *const u32;
            for slot in buf.iter_mut() {
                let status = sr.read_volatile();
                if status & 0x2 == 0 {
                    // RX FIFO empty
                    break;
                }
                *slot = fifo.read_volatile();
                read += 1;
            }
        }
        self.stats.frames_rx += read as u64;
        if read == 0 {
            return Err(Error::WouldBlock);
        }
        Ok(read)
    }

    /// Returns a copy of the transfer statistics.
    pub fn stats(&self) -> I2sStats {
        self.stats
    }
}

impl Default for I2sController {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

/// Registry of all I2S controllers in the system.
pub struct I2sRegistry {
    controllers: [I2sController; MAX_I2S_CONTROLLERS],
    count: usize,
}

impl I2sRegistry {
    /// Creates a new empty I2S controller registry.
    pub fn new() -> Self {
        Self {
            controllers: [
                I2sController::new(0, 0),
                I2sController::new(1, 0),
                I2sController::new(2, 0),
                I2sController::new(3, 0),
            ],
            count: 0,
        }
    }

    /// Registers an I2S controller.
    ///
    /// # Errors
    /// Returns `Error::OutOfMemory` if the registry is full.
    pub fn register(&mut self, ctrl: I2sController) -> Result<()> {
        if self.count >= MAX_I2S_CONTROLLERS {
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
    pub fn get_mut(&mut self, index: usize) -> Result<&mut I2sController> {
        if index >= self.count {
            return Err(Error::NotFound);
        }
        Ok(&mut self.controllers[index])
    }
}

impl Default for I2sRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes the required BCLK frequency for given audio parameters.
///
/// BCLK = sample_rate * bit_depth * channels
pub fn compute_bclk(sample_rate: u32, bit_depth: u8, channels: u8) -> u32 {
    sample_rate * bit_depth as u32 * channels as u32
}

/// Converts a sample count to a duration in microseconds.
///
/// # Arguments
/// * `samples` — Number of audio frames.
/// * `sample_rate` — Sample rate in Hz.
pub fn samples_to_us(samples: u64, sample_rate: u32) -> u64 {
    if sample_rate == 0 {
        return 0;
    }
    samples * 1_000_000 / sample_rate as u64
}
