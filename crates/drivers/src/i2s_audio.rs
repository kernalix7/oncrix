// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! I2S (Inter-IC Sound) audio codec driver.
//!
//! Implements the I2S serial bus protocol for audio data transfer
//! between a host controller and external audio codecs. Supports
//! standard I2S, left-justified, right-justified, and DSP/TDM
//! framing formats.
//!
//! # Architecture
//!
//! - **I2sController** — manages TX/RX audio buffers and the
//!   hardware I2S interface via MMIO registers.
//! - **AudioBuffer** — fixed-size ring buffer for PCM sample data.
//! - **PcmStream** — represents an open audio stream with
//!   start/stop/pause controls.
//!
//! The driver integrates with the DMA subsystem: the controller
//! exposes DMA-capable buffer addresses for zero-copy transfers
//! when a DMA engine is available.
//!
//! # Supported Configurations
//!
//! - Sample rates: 8000, 16000, 22050, 32000, 44100, 48000,
//!   88200, 96000, 176400, 192000 Hz
//! - Bit depths: 8, 16, 24, 32 bits per sample
//! - Channels: 1 (mono), 2 (stereo), up to 8 (TDM/surround)
//! - Master and slave clock modes
//!
//! Reference: I2S Bus Specification (Philips Semiconductors, 1996).

use oncrix_lib::{Error, Result};

// ── MMIO Register Offsets ────────────────────────────────────────

/// I2S Control register.
const REG_CTRL: u32 = 0x00;

/// I2S Status register.
const REG_STATUS: u32 = 0x04;

/// Clock configuration register.
const REG_CLK_CFG: u32 = 0x08;

/// TX FIFO data register.
const REG_TX_DATA: u32 = 0x0C;

/// RX FIFO data register.
const REG_RX_DATA: u32 = 0x10;

/// TX FIFO level register.
const REG_TX_LEVEL: u32 = 0x14;

/// RX FIFO level register.
const REG_RX_LEVEL: u32 = 0x18;

/// Interrupt mask register.
const REG_INT_MASK: u32 = 0x1C;

/// Interrupt status register.
const REG_INT_STATUS: u32 = 0x20;

/// DMA control register.
const REG_DMA_CTRL: u32 = 0x24;

/// TX DMA address register.
const REG_TX_DMA_ADDR: u32 = 0x28;

/// RX DMA address register.
const REG_RX_DMA_ADDR: u32 = 0x2C;

/// DMA transfer length register.
const REG_DMA_LEN: u32 = 0x30;

// ── Control Register Bits ────────────────────────────────────────

/// Enable the I2S controller.
const CTRL_ENABLE: u32 = 1 << 0;

/// Enable transmitter.
const CTRL_TX_EN: u32 = 1 << 1;

/// Enable receiver.
const CTRL_RX_EN: u32 = 1 << 2;

/// Master mode (1) vs slave mode (0).
const CTRL_MASTER: u32 = 1 << 3;

/// Software reset.
const CTRL_RESET: u32 = 1 << 31;

// ── Status Register Bits ─────────────────────────────────────────

/// TX FIFO empty.
const STATUS_TX_EMPTY: u32 = 1 << 0;

/// TX FIFO full.
const _STATUS_TX_FULL: u32 = 1 << 1;

/// RX FIFO empty.
const _STATUS_RX_EMPTY: u32 = 1 << 2;

/// RX FIFO not empty (data available).
const STATUS_RX_AVAIL: u32 = 1 << 3;

/// TX underrun occurred.
const STATUS_TX_UNDERRUN: u32 = 1 << 4;

/// RX overrun occurred.
const STATUS_RX_OVERRUN: u32 = 1 << 5;

// ── Interrupt Bits ───────────────────────────────────────────────

/// TX FIFO threshold interrupt.
const INT_TX_THRESHOLD: u32 = 1 << 0;

/// RX FIFO threshold interrupt.
const INT_RX_THRESHOLD: u32 = 1 << 1;

/// TX underrun interrupt.
const INT_TX_UNDERRUN: u32 = 1 << 2;

/// RX overrun interrupt.
const INT_RX_OVERRUN: u32 = 1 << 3;

/// DMA transfer complete interrupt.
const INT_DMA_DONE: u32 = 1 << 4;

// ── DMA Control Bits ─────────────────────────────────────────────

/// Enable DMA for TX.
const DMA_TX_EN: u32 = 1 << 0;

/// Enable DMA for RX.
const DMA_RX_EN: u32 = 1 << 1;

// ── Constants ────────────────────────────────────────────────────

/// Maximum number of I2S controllers in the registry.
const MAX_CONTROLLERS: usize = 4;

/// Audio buffer capacity in samples.
const AUDIO_BUFFER_CAPACITY: usize = 4096;

/// Maximum number of open PCM streams.
const MAX_STREAMS: usize = 8;

/// Reset polling timeout (iterations).
const RESET_TIMEOUT: u32 = 100_000;

/// Hardware FIFO depth in samples.
const HW_FIFO_DEPTH: usize = 64;

// ── MMIO Helpers ─────────────────────────────────────────────────

/// Read a 32-bit value from a memory-mapped register.
///
/// # Safety
///
/// `addr` must point to a valid, mapped MMIO register.
unsafe fn mmio_read32(addr: usize) -> u32 {
    // SAFETY: Caller guarantees `addr` is valid MMIO.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Write a 32-bit value to a memory-mapped register.
///
/// # Safety
///
/// `addr` must point to a valid, mapped MMIO register.
unsafe fn mmio_write32(addr: usize, val: u32) {
    // SAFETY: Caller guarantees `addr` is valid MMIO.
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
}

// ── I2S Format ───────────────────────────────────────────────────

/// I2S data framing format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I2sFormat {
    /// Standard Philips I2S: data delayed by 1 BCLK after WS edge.
    Standard,
    /// Left-justified: data starts on the WS transition.
    LeftJustified,
    /// Right-justified: data is right-aligned in the slot.
    RightJustified,
    /// DSP/PCM mode: short frame sync pulse, TDM capable.
    Dsp,
}

impl I2sFormat {
    /// Encode the format into the clock configuration register
    /// value (bits [5:4]).
    fn encode(self) -> u32 {
        match self {
            I2sFormat::Standard => 0b00 << 4,
            I2sFormat::LeftJustified => 0b01 << 4,
            I2sFormat::RightJustified => 0b10 << 4,
            I2sFormat::Dsp => 0b11 << 4,
        }
    }
}

// ── Clock Mode ───────────────────────────────────────────────────

/// I2S clock mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockMode {
    /// Controller generates BCLK and LRCLK (master).
    Master,
    /// Controller receives BCLK and LRCLK from external source.
    Slave,
}

// ── I2S Configuration ────────────────────────────────────────────

/// Configuration for an I2S controller.
#[derive(Debug, Clone, Copy)]
pub struct I2sConfig {
    /// Sample rate in Hz.
    pub sample_rate: u32,
    /// Bits per sample (8, 16, 24, or 32).
    pub bit_depth: u8,
    /// Number of audio channels (1–8).
    pub channels: u8,
    /// Clock mode (master or slave).
    pub clock_mode: ClockMode,
    /// Data framing format.
    pub format: I2sFormat,
    /// MCLK-to-LRCLK ratio (e.g. 256, 384, 512).
    pub mclk_ratio: u16,
}

impl I2sConfig {
    /// Create a default stereo 48 kHz / 16-bit configuration.
    pub const fn default_stereo() -> Self {
        Self {
            sample_rate: 48000,
            bit_depth: 16,
            channels: 2,
            clock_mode: ClockMode::Master,
            format: I2sFormat::Standard,
            mclk_ratio: 256,
        }
    }

    /// Validate the configuration parameters.
    pub fn validate(&self) -> Result<()> {
        // Validate sample rate.
        match self.sample_rate {
            8000 | 16000 | 22050 | 32000 | 44100 | 48000 | 88200 | 96000 | 176400 | 192000 => {}
            _ => return Err(Error::InvalidArgument),
        }

        // Validate bit depth.
        match self.bit_depth {
            8 | 16 | 24 | 32 => {}
            _ => return Err(Error::InvalidArgument),
        }

        // Validate channel count.
        if self.channels == 0 || self.channels > 8 {
            return Err(Error::InvalidArgument);
        }

        // Validate MCLK ratio.
        if self.mclk_ratio == 0 {
            return Err(Error::InvalidArgument);
        }

        Ok(())
    }

    /// Compute the bit clock (BCLK) frequency.
    pub fn bclk_hz(&self) -> u32 {
        self.sample_rate * self.bit_depth as u32 * self.channels as u32
    }

    /// Compute the MCLK frequency from the ratio.
    pub fn mclk_hz(&self) -> u32 {
        self.sample_rate * self.mclk_ratio as u32
    }

    /// Encode the sample rate into the clock config register
    /// value (bits [3:0]).
    fn encode_sample_rate(&self) -> u32 {
        match self.sample_rate {
            8000 => 0x0,
            16000 => 0x1,
            22050 => 0x2,
            32000 => 0x3,
            44100 => 0x4,
            48000 => 0x5,
            88200 => 0x6,
            96000 => 0x7,
            176400 => 0x8,
            192000 => 0x9,
            _ => 0x5, // Default to 48 kHz.
        }
    }

    /// Encode bit depth into the clock config register value
    /// (bits [7:6]).
    fn encode_bit_depth(&self) -> u32 {
        match self.bit_depth {
            8 => 0b00 << 6,
            16 => 0b01 << 6,
            24 => 0b10 << 6,
            32 => 0b11 << 6,
            _ => 0b01 << 6, // Default to 16-bit.
        }
    }

    /// Encode the full clock configuration register value.
    fn encode_clk_cfg(&self) -> u32 {
        let rate = self.encode_sample_rate();
        let fmt = self.format.encode();
        let depth = self.encode_bit_depth();
        let channels = ((self.channels as u32).saturating_sub(1) & 0x07) << 8;
        rate | fmt | depth | channels
    }
}

// ── Audio Buffer ─────────────────────────────────────────────────

/// Fixed-size ring buffer for PCM audio sample data.
pub struct AudioBuffer {
    /// Sample data storage.
    data: [u32; AUDIO_BUFFER_CAPACITY],
    /// Read position (consumer index).
    read_pos: usize,
    /// Write position (producer index).
    write_pos: usize,
    /// Number of samples currently in the buffer.
    count: usize,
}

impl AudioBuffer {
    /// Create an empty audio buffer.
    pub const fn new() -> Self {
        Self {
            data: [0u32; AUDIO_BUFFER_CAPACITY],
            read_pos: 0,
            write_pos: 0,
            count: 0,
        }
    }

    /// Return the buffer capacity in samples.
    pub const fn capacity(&self) -> usize {
        AUDIO_BUFFER_CAPACITY
    }

    /// Return the number of samples currently buffered.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return `true` if the buffer is full.
    pub fn is_full(&self) -> bool {
        self.count >= AUDIO_BUFFER_CAPACITY
    }

    /// Return the number of free sample slots.
    pub fn available(&self) -> usize {
        AUDIO_BUFFER_CAPACITY - self.count
    }

    /// Write a single sample into the buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WouldBlock`] if the buffer is full.
    pub fn write_sample(&mut self, sample: u32) -> Result<()> {
        if self.is_full() {
            return Err(Error::WouldBlock);
        }
        self.data[self.write_pos] = sample;
        self.write_pos = (self.write_pos + 1) % AUDIO_BUFFER_CAPACITY;
        self.count += 1;
        Ok(())
    }

    /// Read a single sample from the buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WouldBlock`] if the buffer is empty.
    pub fn read_sample(&mut self) -> Result<u32> {
        if self.is_empty() {
            return Err(Error::WouldBlock);
        }
        let sample = self.data[self.read_pos];
        self.read_pos = (self.read_pos + 1) % AUDIO_BUFFER_CAPACITY;
        self.count -= 1;
        Ok(sample)
    }

    /// Write multiple samples from a slice into the buffer.
    ///
    /// Returns the number of samples actually written. Does not
    /// return an error if the buffer becomes full mid-write; the
    /// caller should check the return value.
    pub fn write_bulk(&mut self, samples: &[u32]) -> usize {
        let to_write = samples.len().min(self.available());
        let mut i = 0;
        while i < to_write {
            self.data[self.write_pos] = samples[i];
            self.write_pos = (self.write_pos + 1) % AUDIO_BUFFER_CAPACITY;
            self.count += 1;
            i += 1;
        }
        to_write
    }

    /// Read multiple samples into a destination slice.
    ///
    /// Returns the number of samples actually read.
    pub fn read_bulk(&mut self, dest: &mut [u32]) -> usize {
        let to_read = dest.len().min(self.count);
        let mut i = 0;
        while i < to_read {
            dest[i] = self.data[self.read_pos];
            self.read_pos = (self.read_pos + 1) % AUDIO_BUFFER_CAPACITY;
            self.count -= 1;
            i += 1;
        }
        to_read
    }

    /// Reset the buffer to empty state.
    pub fn reset(&mut self) {
        self.read_pos = 0;
        self.write_pos = 0;
        self.count = 0;
    }
}

// ── PCM Stream ───────────────────────────────────────────────────

/// PCM stream direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDirection {
    /// Playback (host → codec).
    Playback,
    /// Capture (codec → host).
    Capture,
}

/// PCM stream state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Stream is closed.
    Closed,
    /// Stream is open but not running.
    Open,
    /// Stream is prepared (buffers allocated).
    Prepared,
    /// Stream is actively running.
    Running,
    /// Stream is paused.
    Paused,
}

/// A PCM audio stream.
#[derive(Debug, Clone, Copy)]
pub struct PcmStream {
    /// Unique stream identifier.
    pub id: u8,
    /// Stream direction (playback or capture).
    pub direction: StreamDirection,
    /// Current state.
    pub state: StreamState,
    /// Configuration snapshot (sample rate, bit depth, channels).
    pub sample_rate: u32,
    /// Bits per sample.
    pub bit_depth: u8,
    /// Channel count.
    pub channels: u8,
    /// Total frames transferred since stream start.
    pub frames_transferred: u64,
    /// Number of underrun events (playback only).
    pub underruns: u32,
    /// Number of overrun events (capture only).
    pub overruns: u32,
}

impl PcmStream {
    /// Create an empty/closed stream.
    const fn empty() -> Self {
        Self {
            id: 0,
            direction: StreamDirection::Playback,
            state: StreamState::Closed,
            sample_rate: 0,
            bit_depth: 0,
            channels: 0,
            frames_transferred: 0,
            underruns: 0,
            overruns: 0,
        }
    }
}

// ── I2S Controller ───────────────────────────────────────────────

/// I2S controller state.
pub struct I2sController {
    /// MMIO base address of the I2S registers.
    mmio_base: u64,
    /// Current configuration.
    config: I2sConfig,
    /// Transmit audio buffer (playback).
    tx_buffer: AudioBuffer,
    /// Receive audio buffer (capture).
    rx_buffer: AudioBuffer,
    /// Whether the controller is enabled.
    enabled: bool,
    /// Whether DMA mode is active.
    dma_enabled: bool,
    /// Open PCM streams.
    streams: [PcmStream; MAX_STREAMS],
    /// Number of active streams.
    stream_count: usize,
    /// Interrupt mask (cached).
    int_mask: u32,
    /// Cumulative TX underrun count.
    tx_underruns: u32,
    /// Cumulative RX overrun count.
    rx_overruns: u32,
}

impl I2sController {
    /// Create a new I2S controller bound to the given MMIO base.
    pub fn new(mmio_base: u64) -> Self {
        Self {
            mmio_base,
            config: I2sConfig::default_stereo(),
            tx_buffer: AudioBuffer::new(),
            rx_buffer: AudioBuffer::new(),
            enabled: false,
            dma_enabled: false,
            streams: [PcmStream::empty(); MAX_STREAMS],
            stream_count: 0,
            int_mask: 0,
            tx_underruns: 0,
            rx_overruns: 0,
        }
    }

    /// Initialize the I2S controller with the given configuration.
    ///
    /// Performs a software reset, programs the clock and format
    /// registers, and enables the controller.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the configuration is
    /// invalid, or [`Error::IoError`] if the reset times out.
    pub fn init(&mut self, config: I2sConfig) -> Result<()> {
        config.validate()?;
        self.config = config;

        // Software reset.
        self.write_reg(REG_CTRL, CTRL_RESET);
        let mut timeout = RESET_TIMEOUT;
        while (self.read_reg(REG_CTRL) & CTRL_RESET) != 0 {
            timeout = timeout.wrapping_sub(1);
            if timeout == 0 {
                return Err(Error::IoError);
            }
        }

        // Program clock configuration.
        let clk_cfg = self.config.encode_clk_cfg();
        self.write_reg(REG_CLK_CFG, clk_cfg);

        // Build control register value.
        let mut ctrl = CTRL_ENABLE;
        if self.config.clock_mode == ClockMode::Master {
            ctrl |= CTRL_MASTER;
        }
        self.write_reg(REG_CTRL, ctrl);

        // Enable default interrupts.
        self.int_mask = INT_TX_THRESHOLD | INT_RX_THRESHOLD | INT_TX_UNDERRUN | INT_RX_OVERRUN;
        self.write_reg(REG_INT_MASK, self.int_mask);

        // Reset buffers.
        self.tx_buffer.reset();
        self.rx_buffer.reset();

        self.enabled = true;
        Ok(())
    }

    /// Read a 32-bit MMIO register.
    fn read_reg(&self, offset: u32) -> u32 {
        let addr = self.mmio_base as usize + offset as usize;
        // SAFETY: mmio_base is assumed to be a valid, mapped I2S
        // controller MMIO region and offset is within range.
        unsafe { mmio_read32(addr) }
    }

    /// Write a 32-bit value to an MMIO register.
    fn write_reg(&mut self, offset: u32, val: u32) {
        let addr = self.mmio_base as usize + offset as usize;
        // SAFETY: mmio_base is assumed to be a valid, mapped I2S
        // controller MMIO region and offset is within range.
        unsafe { mmio_write32(addr, val) }
    }

    /// Enable the transmitter.
    pub fn enable_tx(&mut self) {
        let ctrl = self.read_reg(REG_CTRL);
        self.write_reg(REG_CTRL, ctrl | CTRL_TX_EN);
    }

    /// Disable the transmitter.
    pub fn disable_tx(&mut self) {
        let ctrl = self.read_reg(REG_CTRL);
        self.write_reg(REG_CTRL, ctrl & !CTRL_TX_EN);
    }

    /// Enable the receiver.
    pub fn enable_rx(&mut self) {
        let ctrl = self.read_reg(REG_CTRL);
        self.write_reg(REG_CTRL, ctrl | CTRL_RX_EN);
    }

    /// Disable the receiver.
    pub fn disable_rx(&mut self) {
        let ctrl = self.read_reg(REG_CTRL);
        self.write_reg(REG_CTRL, ctrl & !CTRL_RX_EN);
    }

    /// Open a new PCM stream.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if no stream slots are
    /// available, or [`Error::Busy`] if the controller is not
    /// initialized.
    pub fn open_stream(&mut self, direction: StreamDirection) -> Result<u8> {
        if !self.enabled {
            return Err(Error::Busy);
        }
        if self.stream_count >= MAX_STREAMS {
            return Err(Error::OutOfMemory);
        }

        let id = self.stream_count as u8;
        self.streams[self.stream_count] = PcmStream {
            id,
            direction,
            state: StreamState::Open,
            sample_rate: self.config.sample_rate,
            bit_depth: self.config.bit_depth,
            channels: self.config.channels,
            frames_transferred: 0,
            underruns: 0,
            overruns: 0,
        };
        self.stream_count += 1;
        Ok(id)
    }

    /// Close a PCM stream.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the stream ID is invalid.
    pub fn close_stream(&mut self, stream_id: u8) -> Result<()> {
        let idx = stream_id as usize;
        if idx >= self.stream_count {
            return Err(Error::NotFound);
        }

        // If running, stop first.
        if self.streams[idx].state == StreamState::Running {
            self.stop_stream(stream_id)?;
        }
        self.streams[idx].state = StreamState::Closed;
        Ok(())
    }

    /// Prepare a PCM stream for operation.
    ///
    /// Allocates internal resources and transitions to Prepared
    /// state.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the stream ID is invalid, or
    /// [`Error::InvalidArgument`] if the stream is not in Open
    /// state.
    pub fn prepare_stream(&mut self, stream_id: u8) -> Result<()> {
        let idx = stream_id as usize;
        if idx >= self.stream_count {
            return Err(Error::NotFound);
        }
        if self.streams[idx].state != StreamState::Open {
            return Err(Error::InvalidArgument);
        }

        // Reset counters.
        self.streams[idx].frames_transferred = 0;
        self.streams[idx].underruns = 0;
        self.streams[idx].overruns = 0;

        // Reset appropriate buffer.
        match self.streams[idx].direction {
            StreamDirection::Playback => self.tx_buffer.reset(),
            StreamDirection::Capture => self.rx_buffer.reset(),
        }

        self.streams[idx].state = StreamState::Prepared;
        Ok(())
    }

    /// Start a PCM stream.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the stream ID is invalid, or
    /// [`Error::InvalidArgument`] if not in Prepared or Paused
    /// state.
    pub fn start_stream(&mut self, stream_id: u8) -> Result<()> {
        let idx = stream_id as usize;
        if idx >= self.stream_count {
            return Err(Error::NotFound);
        }

        let state = self.streams[idx].state;
        if state != StreamState::Prepared && state != StreamState::Paused {
            return Err(Error::InvalidArgument);
        }

        let direction = self.streams[idx].direction;
        match direction {
            StreamDirection::Playback => self.enable_tx(),
            StreamDirection::Capture => self.enable_rx(),
        }

        self.streams[idx].state = StreamState::Running;
        Ok(())
    }

    /// Stop a running PCM stream.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the stream ID is invalid, or
    /// [`Error::InvalidArgument`] if not currently running.
    pub fn stop_stream(&mut self, stream_id: u8) -> Result<()> {
        let idx = stream_id as usize;
        if idx >= self.stream_count {
            return Err(Error::NotFound);
        }
        if self.streams[idx].state != StreamState::Running {
            return Err(Error::InvalidArgument);
        }

        let direction = self.streams[idx].direction;
        match direction {
            StreamDirection::Playback => self.disable_tx(),
            StreamDirection::Capture => self.disable_rx(),
        }

        self.streams[idx].state = StreamState::Prepared;
        Ok(())
    }

    /// Pause a running PCM stream.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the stream ID is invalid, or
    /// [`Error::InvalidArgument`] if not currently running.
    pub fn pause_stream(&mut self, stream_id: u8) -> Result<()> {
        let idx = stream_id as usize;
        if idx >= self.stream_count {
            return Err(Error::NotFound);
        }
        if self.streams[idx].state != StreamState::Running {
            return Err(Error::InvalidArgument);
        }

        let direction = self.streams[idx].direction;
        match direction {
            StreamDirection::Playback => self.disable_tx(),
            StreamDirection::Capture => self.disable_rx(),
        }

        self.streams[idx].state = StreamState::Paused;
        Ok(())
    }

    /// Resume a paused PCM stream.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the stream ID is invalid, or
    /// [`Error::InvalidArgument`] if not paused.
    pub fn resume_stream(&mut self, stream_id: u8) -> Result<()> {
        self.start_stream(stream_id)
    }

    /// Write samples to the TX FIFO / buffer for playback.
    ///
    /// Returns the number of samples written. The caller should
    /// retry if fewer samples than expected were accepted.
    pub fn write_samples(&mut self, samples: &[u32]) -> usize {
        self.tx_buffer.write_bulk(samples)
    }

    /// Read captured samples from the RX buffer.
    ///
    /// Returns the number of samples read.
    pub fn read_samples(&mut self, dest: &mut [u32]) -> usize {
        self.rx_buffer.read_bulk(dest)
    }

    /// Feed buffered TX data to the hardware FIFO.
    ///
    /// Call this from the TX threshold interrupt handler or a
    /// polling loop to keep the hardware FIFO fed.
    ///
    /// Returns the number of samples written to the FIFO.
    pub fn drain_tx_to_hw(&mut self) -> usize {
        let tx_level = self.read_reg(REG_TX_LEVEL) as usize;
        let space = HW_FIFO_DEPTH.saturating_sub(tx_level);
        let to_write = space.min(self.tx_buffer.len());

        let mut written = 0;
        while written < to_write {
            if let Ok(sample) = self.tx_buffer.read_sample() {
                self.write_reg(REG_TX_DATA, sample);
                written += 1;
            } else {
                break;
            }
        }
        written
    }

    /// Drain the hardware RX FIFO into the software buffer.
    ///
    /// Call this from the RX threshold interrupt handler.
    ///
    /// Returns the number of samples read from the FIFO.
    pub fn fill_rx_from_hw(&mut self) -> usize {
        let rx_level = self.read_reg(REG_RX_LEVEL) as usize;
        let to_read = rx_level.min(self.rx_buffer.available());

        let mut read_count = 0;
        while read_count < to_read {
            let sample = self.read_reg(REG_RX_DATA);
            if self.rx_buffer.write_sample(sample).is_err() {
                break;
            }
            read_count += 1;
        }
        read_count
    }

    /// Handle an I2S controller interrupt.
    ///
    /// Reads the interrupt status, acknowledges pending interrupts,
    /// and performs the appropriate action.
    ///
    /// Returns the raw interrupt status bits for the caller to
    /// inspect.
    pub fn handle_interrupt(&mut self) -> u32 {
        let status = self.read_reg(REG_INT_STATUS);

        // Acknowledge by writing back status bits.
        self.write_reg(REG_INT_STATUS, status);

        if status & INT_TX_THRESHOLD != 0 {
            self.drain_tx_to_hw();
        }

        if status & INT_RX_THRESHOLD != 0 {
            self.fill_rx_from_hw();
        }

        if status & INT_TX_UNDERRUN != 0 {
            self.tx_underruns += 1;
            // Update active playback streams.
            let mut i = 0;
            while i < self.stream_count {
                if self.streams[i].direction == StreamDirection::Playback
                    && self.streams[i].state == StreamState::Running
                {
                    self.streams[i].underruns += 1;
                }
                i += 1;
            }
        }

        if status & INT_RX_OVERRUN != 0 {
            self.rx_overruns += 1;
            // Update active capture streams.
            let mut i = 0;
            while i < self.stream_count {
                if self.streams[i].direction == StreamDirection::Capture
                    && self.streams[i].state == StreamState::Running
                {
                    self.streams[i].overruns += 1;
                }
                i += 1;
            }
        }

        if status & INT_DMA_DONE != 0 {
            // DMA transfer complete — update frame counts.
            let dma_len = self.read_reg(REG_DMA_LEN) as u64;
            let frames = if self.config.channels > 0 {
                dma_len / self.config.channels as u64
            } else {
                dma_len
            };
            let mut i = 0;
            while i < self.stream_count {
                if self.streams[i].state == StreamState::Running {
                    self.streams[i].frames_transferred += frames;
                }
                i += 1;
            }
        }

        status
    }

    /// Enable DMA mode for transfers.
    ///
    /// When DMA is enabled, data moves directly between memory
    /// buffers and the I2S FIFO without CPU intervention.
    pub fn enable_dma(&mut self, tx_addr: u64, rx_addr: u64, len: u32) {
        self.write_reg(REG_TX_DMA_ADDR, tx_addr as u32);
        self.write_reg(REG_RX_DMA_ADDR, rx_addr as u32);
        self.write_reg(REG_DMA_LEN, len);
        self.write_reg(REG_DMA_CTRL, DMA_TX_EN | DMA_RX_EN);
        self.dma_enabled = true;
    }

    /// Disable DMA mode.
    pub fn disable_dma(&mut self) {
        self.write_reg(REG_DMA_CTRL, 0);
        self.dma_enabled = false;
    }

    /// Return `true` if the controller has been initialized.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Return `true` if DMA mode is active.
    pub fn is_dma_enabled(&self) -> bool {
        self.dma_enabled
    }

    /// Return the current configuration.
    pub fn config(&self) -> &I2sConfig {
        &self.config
    }

    /// Return a reference to a PCM stream by ID.
    pub fn stream(&self, id: u8) -> Option<&PcmStream> {
        let idx = id as usize;
        if idx < self.stream_count {
            Some(&self.streams[idx])
        } else {
            None
        }
    }

    /// Return the number of open streams.
    pub fn stream_count(&self) -> usize {
        self.stream_count
    }

    /// Return the number of TX samples currently buffered.
    pub fn tx_buffered(&self) -> usize {
        self.tx_buffer.len()
    }

    /// Return the number of RX samples currently buffered.
    pub fn rx_buffered(&self) -> usize {
        self.rx_buffer.len()
    }

    /// Check whether the TX FIFO is empty (hardware status).
    pub fn is_tx_empty(&self) -> bool {
        self.read_reg(REG_STATUS) & STATUS_TX_EMPTY != 0
    }

    /// Check whether RX data is available (hardware status).
    pub fn is_rx_available(&self) -> bool {
        self.read_reg(REG_STATUS) & STATUS_RX_AVAIL != 0
    }

    /// Read cumulative TX underrun count.
    pub fn tx_underrun_count(&self) -> u32 {
        self.tx_underruns
    }

    /// Read cumulative RX overrun count.
    pub fn rx_overrun_count(&self) -> u32 {
        self.rx_overruns
    }

    /// Check for and clear hardware error flags.
    ///
    /// Returns `true` if any error was present.
    pub fn check_errors(&mut self) -> bool {
        let status = self.read_reg(REG_STATUS);
        let has_error = (status & (STATUS_TX_UNDERRUN | STATUS_RX_OVERRUN)) != 0;
        if has_error {
            // Clear error bits by writing them back.
            self.write_reg(
                REG_STATUS,
                status & (STATUS_TX_UNDERRUN | STATUS_RX_OVERRUN),
            );
        }
        has_error
    }
}

// ── Registry ─────────────────────────────────────────────────────

/// Registry for discovered I2S controllers.
pub struct I2sRegistry {
    /// Registered controller MMIO base addresses.
    controllers: [Option<u64>; MAX_CONTROLLERS],
    /// Number of registered controllers.
    count: usize,
}

impl Default for I2sRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl I2sRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            controllers: [None; MAX_CONTROLLERS],
            count: 0,
        }
    }

    /// Register an I2S controller by its MMIO base address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, mmio_base: u64) -> Result<usize> {
        if self.count >= MAX_CONTROLLERS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.controllers[idx] = Some(mmio_base);
        self.count += 1;
        Ok(idx)
    }

    /// Get the MMIO base address of a registered controller.
    pub fn get(&self, index: usize) -> Option<u64> {
        if index < self.count {
            self.controllers[index]
        } else {
            None
        }
    }

    /// Return the number of registered controllers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no controllers are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
