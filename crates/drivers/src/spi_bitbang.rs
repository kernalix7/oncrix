// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SPI bit-bang driver.
//!
//! Implements a software SPI master by toggling GPIO lines for
//! SCLK, MOSI, MISO, and CS. Supports all four SPI modes
//! (clock polarity × clock phase), configurable word size, and
//! per-transfer bit timing.
//!
//! # SPI Modes
//!
//! | Mode | CPOL | CPHA | Clock idle | Sample edge |
//! |------|------|------|------------|-------------|
//! |  0   |  0   |  0   | Low        | Rising      |
//! |  1   |  0   |  1   | Low        | Falling     |
//! |  2   |  1   |  0   | High       | Falling     |
//! |  3   |  1   |  1   | High       | Rising      |
//!
//! # Usage
//!
//! ```ignore
//! let mut spi = SpiBitbang::new(cfg, gpio);
//! spi.init()?;
//! let result = spi.transfer(0xAB)?;
//! ```
//!
//! Reference: Linux `drivers/spi/spi-bitbang.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum SPI chip-selects per controller.
const MAX_CS: usize = 4;

/// Maximum registered bit-bang SPI masters.
const MAX_BITBANG_MASTERS: usize = 4;

/// Default half-period delay count (spin-loop iterations).
///
/// A real implementation would use the HAL timer for precise delays.
const DEFAULT_HALF_PERIOD: u32 = 100;

// ---------------------------------------------------------------------------
// SPI Mode (CPOL | CPHA)
// ---------------------------------------------------------------------------

/// SPI clock polarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cpol {
    /// Clock idles low (CPOL = 0).
    IdleLow,
    /// Clock idles high (CPOL = 1).
    IdleHigh,
}

/// SPI clock phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cpha {
    /// Data sampled on the first (leading) clock edge (CPHA = 0).
    LeadingEdge,
    /// Data sampled on the second (trailing) clock edge (CPHA = 1).
    TrailingEdge,
}

/// Combined SPI mode (CPOL × CPHA).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpiMode {
    /// Mode 0: CPOL=0, CPHA=0.
    Mode0,
    /// Mode 1: CPOL=0, CPHA=1.
    Mode1,
    /// Mode 2: CPOL=1, CPHA=0.
    Mode2,
    /// Mode 3: CPOL=1, CPHA=1.
    Mode3,
}

impl SpiMode {
    /// Return the CPOL for this mode.
    pub fn cpol(self) -> Cpol {
        match self {
            Self::Mode0 | Self::Mode1 => Cpol::IdleLow,
            Self::Mode2 | Self::Mode3 => Cpol::IdleHigh,
        }
    }

    /// Return the CPHA for this mode.
    pub fn cpha(self) -> Cpha {
        match self {
            Self::Mode0 | Self::Mode2 => Cpha::LeadingEdge,
            Self::Mode1 | Self::Mode3 => Cpha::TrailingEdge,
        }
    }
}

// ---------------------------------------------------------------------------
// GPIO Pin Reference
// ---------------------------------------------------------------------------

/// A reference to a GPIO pin identified by chip index and line index.
#[derive(Debug, Clone, Copy)]
pub struct GpioPin {
    /// GPIO chip index.
    pub chip: usize,
    /// Line index within the chip.
    pub line: usize,
}

impl GpioPin {
    /// Create a new GPIO pin reference.
    pub const fn new(chip: usize, line: usize) -> Self {
        Self { chip, line }
    }
}

// ---------------------------------------------------------------------------
// Chip-Select Configuration
// ---------------------------------------------------------------------------

/// Configuration for a single SPI chip-select line.
#[derive(Debug, Clone, Copy)]
pub struct CsConfig {
    /// GPIO pin for this chip-select.
    pub pin: GpioPin,
    /// Whether the chip-select is active-low (true for most devices).
    pub active_low: bool,
}

impl CsConfig {
    /// Create a new chip-select config.
    pub const fn new(pin: GpioPin, active_low: bool) -> Self {
        Self { pin, active_low }
    }
}

// ---------------------------------------------------------------------------
// Bit-Bang SPI Configuration
// ---------------------------------------------------------------------------

/// Configuration for a software (bit-bang) SPI master.
#[derive(Debug, Clone, Copy)]
pub struct BitbangConfig {
    /// GPIO pin for the serial clock (SCLK).
    pub sclk: GpioPin,
    /// GPIO pin for master-out, slave-in (MOSI).
    pub mosi: GpioPin,
    /// GPIO pin for master-in, slave-out (MISO).
    pub miso: GpioPin,
    /// SPI mode (CPOL × CPHA).
    pub mode: SpiMode,
    /// Word size in bits (typically 8 or 16).
    pub word_bits: u8,
    /// Spin-loop count for each half clock period.
    pub half_period: u32,
    /// Chip-select configurations (up to [`MAX_CS`]).
    pub cs: [Option<CsConfig>; MAX_CS],
    /// Number of chip-selects configured.
    pub cs_count: usize,
}

impl BitbangConfig {
    /// Create a basic configuration for 8-bit Mode 0 with one chip-select.
    pub fn new_mode0(sclk: GpioPin, mosi: GpioPin, miso: GpioPin, cs_pin: GpioPin) -> Self {
        let mut cs = [const { None }; MAX_CS];
        cs[0] = Some(CsConfig::new(cs_pin, true));
        Self {
            sclk,
            mosi,
            miso,
            mode: SpiMode::Mode0,
            word_bits: 8,
            half_period: DEFAULT_HALF_PERIOD,
            cs,
            cs_count: 1,
        }
    }
}

// ---------------------------------------------------------------------------
// GPIO callback-based pin I/O
// ---------------------------------------------------------------------------

/// GPIO drive/sample callbacks used by the bit-bang engine.
///
/// These are function pointers so the driver does not need a generic
/// parameter, keeping the struct object-safe and `no_std`-friendly.
pub struct GpioCallbacks {
    /// Set pin `(chip, line)` to `value` (0 or 1).
    pub set: fn(chip: usize, line: usize, value: u8),
    /// Read pin `(chip, line)`; returns 0 or 1.
    pub get: fn(chip: usize, line: usize) -> u8,
}

// ---------------------------------------------------------------------------
// Bit-Bang SPI Master
// ---------------------------------------------------------------------------

/// Software SPI master implemented by toggling GPIO lines.
pub struct SpiBitbang {
    /// Static configuration.
    cfg: BitbangConfig,
    /// GPIO callbacks for set/get operations.
    gpio: GpioCallbacks,
    /// Whether the master has been initialised.
    initialized: bool,
    /// Currently asserted chip-select (index), or `None`.
    active_cs: Option<usize>,
    /// Total words transferred.
    transfer_count: u64,
}

impl SpiBitbang {
    /// Create a new bit-bang SPI master.
    pub const fn new(cfg: BitbangConfig, gpio: GpioCallbacks) -> Self {
        Self {
            cfg,
            gpio,
            initialized: false,
            active_cs: None,
            transfer_count: 0,
        }
    }

    // ----- Private pin helpers -----

    fn set_pin(&self, pin: GpioPin, val: u8) {
        (self.gpio.set)(pin.chip, pin.line, val);
    }

    fn get_pin(&self, pin: GpioPin) -> u8 {
        (self.gpio.get)(pin.chip, pin.line)
    }

    fn set_sclk(&self, val: u8) {
        self.set_pin(self.cfg.sclk, val);
    }

    fn set_mosi(&self, val: u8) {
        self.set_pin(self.cfg.mosi, val);
    }

    fn get_miso(&self) -> u8 {
        self.get_pin(self.cfg.miso)
    }

    /// Spin for `half_period` iterations to approximate clock timing.
    fn half_period_delay(&self) {
        let iters = self.cfg.half_period;
        // SAFETY: This is a simple spin-loop used for timing. The
        // compiler hint prevents it from being optimised away.
        for _ in 0..iters {
            core::hint::spin_loop();
        }
    }

    fn clock_idle_level(&self) -> u8 {
        match self.cfg.mode.cpol() {
            Cpol::IdleLow => 0,
            Cpol::IdleHigh => 1,
        }
    }

    // ----- Public API -----

    /// Initialise the SPI master.
    ///
    /// Sets SCLK to the idle level and MOSI low. Validates configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `word_bits` is 0 or > 32.
    pub fn init(&mut self) -> Result<()> {
        if self.cfg.word_bits == 0 || self.cfg.word_bits > 32 {
            return Err(Error::InvalidArgument);
        }
        self.set_sclk(self.clock_idle_level());
        self.set_mosi(0);
        // De-assert all chip-selects.
        for i in 0..self.cfg.cs_count {
            if let Some(cs) = self.cfg.cs[i] {
                let deassert = if cs.active_low { 1 } else { 0 };
                self.set_pin(cs.pin, deassert);
            }
        }
        self.initialized = true;
        Ok(())
    }

    /// Assert chip-select `cs_idx`.
    ///
    /// # Errors
    ///
    /// - [`Error::Busy`] if another chip-select is already asserted.
    /// - [`Error::InvalidArgument`] if `cs_idx` is out of range.
    pub fn cs_assert(&mut self, cs_idx: usize) -> Result<()> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        if self.active_cs.is_some() {
            return Err(Error::Busy);
        }
        if cs_idx >= self.cfg.cs_count {
            return Err(Error::InvalidArgument);
        }
        let cs = self.cfg.cs[cs_idx].ok_or(Error::InvalidArgument)?;
        let assert_val = if cs.active_low { 0 } else { 1 };
        self.set_pin(cs.pin, assert_val);
        self.active_cs = Some(cs_idx);
        Ok(())
    }

    /// De-assert the currently active chip-select.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no chip-select is asserted.
    pub fn cs_deassert(&mut self) -> Result<()> {
        let cs_idx = self.active_cs.ok_or(Error::NotFound)?;
        let cs = self.cfg.cs[cs_idx].ok_or(Error::NotFound)?;
        let deassert_val = if cs.active_low { 1 } else { 0 };
        self.set_pin(cs.pin, deassert_val);
        self.active_cs = None;
        Ok(())
    }

    /// Transfer a single word (up to 32 bits) over the SPI bus.
    ///
    /// Clocks out `word` MSB-first on MOSI and simultaneously clocks in
    /// bits from MISO, returning the received word.
    ///
    /// Clock/phase behaviour follows the configured [`SpiMode`]:
    /// - CPHA=0: data is set up before the first clock edge.
    /// - CPHA=1: data is set up after the first clock edge.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the master is not initialised.
    pub fn transfer(&mut self, word: u32) -> Result<u32> {
        if !self.initialized {
            return Err(Error::Busy);
        }
        let bits = self.cfg.word_bits as u32;
        let idle = self.clock_idle_level();
        let cpha = self.cfg.mode.cpha();
        let mut rx: u32 = 0;

        // For CPHA=1, toggle clock before the first bit.
        if cpha == Cpha::TrailingEdge {
            self.set_sclk(idle ^ 1);
            self.half_period_delay();
        }

        for bit_pos in (0..bits).rev() {
            let tx_bit = ((word >> bit_pos) & 1) as u8;
            self.set_mosi(tx_bit);
            self.half_period_delay();

            // Leading edge: for CPHA=0 this is the sample edge.
            self.set_sclk(idle ^ 1);
            self.half_period_delay();

            if cpha == Cpha::LeadingEdge {
                // Sample MISO on the leading edge.
                let rx_bit = self.get_miso() as u32;
                rx |= rx_bit << bit_pos;
            }

            // Trailing edge: for CPHA=1 this is the sample edge.
            self.set_sclk(idle);
            self.half_period_delay();

            if cpha == Cpha::TrailingEdge {
                let rx_bit = self.get_miso() as u32;
                rx |= rx_bit << bit_pos;
            }
        }

        // Restore clock to idle.
        self.set_sclk(idle);
        self.transfer_count += 1;
        Ok(rx)
    }

    /// Transfer a buffer of bytes, returning received bytes.
    ///
    /// Asserts `cs_idx`, transfers all bytes in `tx`, stores received
    /// bytes into `rx`, then de-asserts CS.
    ///
    /// # Arguments
    ///
    /// - `cs_idx` — chip-select to use.
    /// - `tx` — bytes to transmit.
    /// - `rx` — buffer to receive into (must be same length as `tx`).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `tx.len() != rx.len()`.
    /// - Propagates errors from [`Self::cs_assert`] / [`Self::transfer`].
    pub fn transfer_buf(&mut self, cs_idx: usize, tx: &[u8], rx: &mut [u8]) -> Result<()> {
        if tx.len() != rx.len() {
            return Err(Error::InvalidArgument);
        }
        self.cs_assert(cs_idx)?;
        let mut err: Option<Error> = None;
        for (i, &byte) in tx.iter().enumerate() {
            match self.transfer(byte as u32) {
                Ok(r) => rx[i] = (r & 0xFF) as u8,
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
        }
        // Always de-assert CS regardless of transfer result.
        let _ = self.cs_deassert();
        if let Some(e) = err { Err(e) } else { Ok(()) }
    }

    /// Return the total number of words transferred.
    pub fn transfer_count(&self) -> u64 {
        self.transfer_count
    }

    /// Return whether the master is initialised.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Return the configured SPI mode.
    pub fn mode(&self) -> SpiMode {
        self.cfg.mode
    }

    /// Return the word bit-width.
    pub fn word_bits(&self) -> u8 {
        self.cfg.word_bits
    }
}

// ---------------------------------------------------------------------------
// Bit-Bang SPI Registry
// ---------------------------------------------------------------------------

/// Registry of software SPI masters.
pub struct SpiBitbangRegistry {
    /// Registered masters.
    masters: [Option<SpiBitbang>; MAX_BITBANG_MASTERS],
    /// Number of registered masters.
    count: usize,
}

impl Default for SpiBitbangRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SpiBitbangRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            masters: core::array::from_fn(|_| None),
            count: 0,
        }
    }

    /// Register a new bit-bang SPI master.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, master: SpiBitbang) -> Result<usize> {
        if self.count >= MAX_BITBANG_MASTERS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.masters[idx] = Some(master);
        self.count += 1;
        Ok(idx)
    }

    /// Get a mutable reference to a master by index.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut SpiBitbang> {
        if idx < self.count {
            self.masters[idx].as_mut()
        } else {
            None
        }
    }

    /// Return the number of registered masters.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the registry has no entries.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
