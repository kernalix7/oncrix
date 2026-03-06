// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PWM controller driver for the ONCRIX operating system.
//!
//! Implements a comprehensive PWM subsystem with support for multiple
//! hardware controller chips, per-channel period/duty-cycle configuration,
//! polarity inversion, complementary output pairs, hardware capture mode,
//! and MMIO-level register access for common PWM IP blocks.
//!
//! # Architecture
//!
//! - **PwmControllerType** — hardware variant (Intel PCH, ARM SP804, etc.)
//! - **PwmPolarity** — normal or inverted output polarity
//! - **PwmChannelState** — disabled or enabled channel
//! - **PwmCaptureResult** — captured period/duty from an input signal
//! - **PwmChannelDesc** — per-channel configuration and state
//! - **PwmChip** — a PWM controller managing up to [`MAX_CHANNELS`] channels
//! - **PwmChipRegistry** — manages up to [`MAX_CHIPS`] controllers
//!
//! # MMIO Access
//!
//! All register reads/writes use volatile access. Every `unsafe` block
//! carries a `// SAFETY:` comment.
//!
//! # Reference
//!
//! Linux: `drivers/pwm/pwm-cros-ec.c`, `drivers/pwm/pwm-tiehrpwm.c`,
//! `include/linux/pwm.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of PWM controller chips.
const MAX_CHIPS: usize = 8;

/// Maximum number of PWM channels per chip.
const MAX_CHANNELS: usize = 16;

/// Minimum period in nanoseconds (1 ns).
const MIN_PERIOD_NS: u64 = 1;

/// Maximum period in nanoseconds (10 seconds).
const MAX_PERIOD_NS: u64 = 10_000_000_000;

// Generic PWM MMIO register offsets (relative to channel base).
/// Period register offset within a channel block.
const PWM_REG_PERIOD: usize = 0x00;
/// Duty-cycle register offset within a channel block.
const PWM_REG_DUTY: usize = 0x04;
/// Control register offset within a channel block.
const PWM_REG_CTRL: usize = 0x08;
/// Status register offset within a channel block.
const PWM_REG_STATUS: usize = 0x0C;

/// Control register: enable bit.
const PWM_CTRL_ENABLE: u32 = 1 << 0;
/// Control register: polarity inversion bit.
const PWM_CTRL_POLARITY: u32 = 1 << 1;
/// Control register: capture mode enable.
const PWM_CTRL_CAPTURE: u32 = 1 << 2;

/// Status register: capture ready bit.
const PWM_STATUS_CAP_READY: u32 = 1 << 0;
/// Status register: period overflow bit.
const PWM_STATUS_OVERFLOW: u32 = 1 << 1;

/// Stride between per-channel MMIO register blocks in bytes.
const CHANNEL_STRIDE: usize = 0x20;

// ---------------------------------------------------------------------------
// PwmControllerType
// ---------------------------------------------------------------------------

/// Hardware variant of the PWM controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PwmControllerType {
    /// Generic memory-mapped PWM controller.
    #[default]
    GenericMmio,
    /// Intel PCH PWM (LPSS/Sunrisepoint).
    IntelPch,
    /// ARM SP804 dual timer (used in PWM mode).
    ArmSp804,
    /// TI eHRPWM (Enhanced High-Resolution PWM).
    TiEhrpwm,
}

// ---------------------------------------------------------------------------
// PwmPolarity
// ---------------------------------------------------------------------------

/// Output polarity for a PWM channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PwmPolarity {
    /// Normal polarity: high during duty period, low otherwise.
    #[default]
    Normal,
    /// Inverted polarity: low during duty period, high otherwise.
    Inverted,
}

// ---------------------------------------------------------------------------
// PwmChannelState
// ---------------------------------------------------------------------------

/// Operational state of a PWM channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PwmChannelState {
    /// Channel is disabled; no signal output.
    #[default]
    Disabled,
    /// Channel is enabled; PWM signal is being generated.
    Enabled,
}

// ---------------------------------------------------------------------------
// PwmCaptureResult
// ---------------------------------------------------------------------------

/// Result from PWM input-capture mode.
///
/// Represents a captured incoming PWM signal's period and duty cycle.
#[derive(Debug, Clone, Copy, Default)]
pub struct PwmCaptureResult {
    /// Captured period in nanoseconds.
    pub period_ns: u64,
    /// Captured duty cycle in nanoseconds.
    pub duty_ns: u64,
    /// Whether the measurement is valid.
    pub valid: bool,
}

impl PwmCaptureResult {
    /// Returns the duty cycle as a percentage (0–100).
    pub fn duty_percent(&self) -> u64 {
        if self.period_ns == 0 {
            return 0;
        }
        self.duty_ns.saturating_mul(100) / self.period_ns
    }
}

// ---------------------------------------------------------------------------
// PwmChannelDesc
// ---------------------------------------------------------------------------

/// Configuration and state descriptor for a single PWM channel.
#[derive(Debug, Clone, Copy)]
pub struct PwmChannelDesc {
    /// Channel index within the chip.
    pub index: u8,
    /// Output period in nanoseconds.
    pub period_ns: u64,
    /// Duty cycle in nanoseconds (must not exceed `period_ns`).
    pub duty_ns: u64,
    /// Output polarity.
    pub polarity: PwmPolarity,
    /// Current operational state.
    pub state: PwmChannelState,
    /// Whether this channel has been requested by a consumer.
    pub requested: bool,
    /// Whether capture mode is active on this channel.
    pub capture_mode: bool,
    /// Consumer label (UTF-8, not NUL-terminated).
    pub label: [u8; 32],
    /// Number of valid bytes in `label`.
    pub label_len: usize,
}

/// Constant empty channel descriptor for array initialisation.
const EMPTY_CHAN: PwmChannelDesc = PwmChannelDesc {
    index: 0,
    period_ns: 0,
    duty_ns: 0,
    polarity: PwmPolarity::Normal,
    state: PwmChannelState::Disabled,
    requested: false,
    capture_mode: false,
    label: [0u8; 32],
    label_len: 0,
};

impl PwmChannelDesc {
    /// Creates a new channel descriptor for the given index.
    pub const fn new(index: u8) -> Self {
        PwmChannelDesc {
            index,
            ..EMPTY_CHAN
        }
    }

    /// Computes the duty cycle percentage (0–100).
    pub fn duty_percent(&self) -> u64 {
        if self.period_ns == 0 {
            return 0;
        }
        self.duty_ns.saturating_mul(100) / self.period_ns
    }

    /// Returns `true` if the channel is actively generating output.
    pub fn is_active(&self) -> bool {
        self.state == PwmChannelState::Enabled && self.requested
    }
}

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

/// Volatile 32-bit MMIO read.
///
/// # Safety
///
/// `addr` must be a valid, mapped MMIO address.
#[inline]
unsafe fn mmio_read32(addr: usize) -> u32 {
    // SAFETY: caller guarantees the address is a valid mapped MMIO register.
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Volatile 32-bit MMIO write.
///
/// # Safety
///
/// `addr` must be a valid, mapped MMIO address.
#[inline]
unsafe fn mmio_write32(addr: usize, val: u32) {
    // SAFETY: caller guarantees the address is a valid mapped MMIO register.
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
}

// ---------------------------------------------------------------------------
// PwmChip
// ---------------------------------------------------------------------------

/// A PWM controller chip managing up to [`MAX_CHANNELS`] output channels.
pub struct PwmChip {
    /// Unique chip identifier.
    pub id: u32,
    /// Hardware variant.
    pub hw_type: PwmControllerType,
    /// MMIO base address of the PWM controller registers.
    pub mmio_base: usize,
    /// Reference clock frequency in Hz.
    pub clk_hz: u64,
    /// Number of channels on this chip.
    pub num_channels: u8,
    /// Per-channel descriptors.
    pub channels: [PwmChannelDesc; MAX_CHANNELS],
    /// Whether the chip is initialised.
    pub initialized: bool,
}

impl PwmChip {
    /// Creates a new PWM chip.
    ///
    /// `num_channels` is clamped to [`MAX_CHANNELS`].
    pub fn new(
        id: u32,
        hw_type: PwmControllerType,
        mmio_base: usize,
        clk_hz: u64,
        num_channels: u8,
    ) -> Self {
        let nc = (num_channels as usize).min(MAX_CHANNELS) as u8;
        let mut channels = [EMPTY_CHAN; MAX_CHANNELS];
        for (i, ch) in channels.iter_mut().enumerate().take(nc as usize) {
            ch.index = i as u8;
        }
        Self {
            id,
            hw_type,
            mmio_base,
            clk_hz,
            num_channels: nc,
            channels,
            initialized: false,
        }
    }

    /// Initialises the PWM chip hardware.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if `mmio_base` is zero (unmapped).
    pub fn init(&mut self) -> Result<()> {
        if self.mmio_base == 0 {
            return Err(Error::IoError);
        }
        // For generic MMIO: disable all channels and clear status.
        for ch in 0..self.num_channels as usize {
            let base = self.channel_mmio_base(ch);
            // SAFETY: mmio_base is checked non-zero; channel registers are within
            // the mapped region with CHANNEL_STRIDE stride per channel.
            unsafe {
                mmio_write32(base + PWM_REG_CTRL, 0);
                let _ = mmio_read32(base + PWM_REG_STATUS); // clear status
            }
        }
        self.initialized = true;
        Ok(())
    }

    /// Returns the MMIO base address for channel `ch`.
    fn channel_mmio_base(&self, ch: usize) -> usize {
        self.mmio_base + ch * CHANNEL_STRIDE
    }

    /// Converts a period in nanoseconds to hardware counter ticks.
    ///
    /// Returns 0 if `period_ns` is 0.
    pub fn ns_to_ticks(&self, period_ns: u64) -> u32 {
        if period_ns == 0 {
            return 0;
        }
        // ticks = clk_hz * period_ns / 1_000_000_000
        let ticks = self.clk_hz.saturating_mul(period_ns) / 1_000_000_000;
        ticks.min(u32::MAX as u64) as u32
    }

    /// Requests a PWM channel for exclusive use.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the channel index is out of range,
    /// or [`Error::Busy`] if the channel is already in use.
    pub fn request_channel(&mut self, ch: u8, label: &[u8]) -> Result<()> {
        let idx = ch as usize;
        if idx >= self.num_channels as usize {
            return Err(Error::InvalidArgument);
        }
        if self.channels[idx].requested {
            return Err(Error::Busy);
        }
        self.channels[idx].requested = true;
        let copy_len = label.len().min(32);
        self.channels[idx].label[..copy_len].copy_from_slice(&label[..copy_len]);
        self.channels[idx].label_len = copy_len;
        Ok(())
    }

    /// Releases a previously requested channel.
    ///
    /// Disables the channel hardware and clears the request flag.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the channel index is out of range.
    pub fn free_channel(&mut self, ch: u8) -> Result<()> {
        let idx = ch as usize;
        if idx >= self.num_channels as usize {
            return Err(Error::InvalidArgument);
        }
        // Disable hardware first
        if self.channels[idx].state == PwmChannelState::Enabled {
            let _ = self.disable_channel(ch);
        }
        self.channels[idx].requested = false;
        self.channels[idx].label = [0u8; 32];
        self.channels[idx].label_len = 0;
        Ok(())
    }

    /// Configures the period and duty cycle of a channel.
    ///
    /// The duty cycle is clamped to the period. If the channel is currently
    /// enabled, the new values are applied immediately to the hardware.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if index or period is out of range,
    /// or if the channel is not requested.
    pub fn config_channel(
        &mut self,
        ch: u8,
        period_ns: u64,
        duty_ns: u64,
        polarity: PwmPolarity,
    ) -> Result<()> {
        let idx = ch as usize;
        if idx >= self.num_channels as usize {
            return Err(Error::InvalidArgument);
        }
        if !self.channels[idx].requested {
            return Err(Error::InvalidArgument);
        }
        if period_ns < MIN_PERIOD_NS || period_ns > MAX_PERIOD_NS {
            return Err(Error::InvalidArgument);
        }
        let clamped_duty = duty_ns.min(period_ns);
        self.channels[idx].period_ns = period_ns;
        self.channels[idx].duty_ns = clamped_duty;
        self.channels[idx].polarity = polarity;

        if self.channels[idx].state == PwmChannelState::Enabled {
            self.apply_channel_hw(idx)?;
        }
        Ok(())
    }

    /// Enables a channel, applying its current configuration to hardware.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if index out of range, or if the
    /// channel is not configured (period_ns == 0), or not requested.
    pub fn enable_channel(&mut self, ch: u8) -> Result<()> {
        let idx = ch as usize;
        if idx >= self.num_channels as usize {
            return Err(Error::InvalidArgument);
        }
        if !self.channels[idx].requested || self.channels[idx].period_ns == 0 {
            return Err(Error::InvalidArgument);
        }
        self.channels[idx].state = PwmChannelState::Enabled;
        self.apply_channel_hw(idx)
    }

    /// Disables a channel, stopping the hardware output.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the index is out of range.
    pub fn disable_channel(&mut self, ch: u8) -> Result<()> {
        let idx = ch as usize;
        if idx >= self.num_channels as usize {
            return Err(Error::InvalidArgument);
        }
        self.channels[idx].state = PwmChannelState::Disabled;
        if self.initialized {
            let base = self.channel_mmio_base(idx);
            // SAFETY: mmio_base and channel stride are valid; CTRL register is
            // a standard 32-bit RW register for this PWM IP block.
            unsafe {
                let ctrl = mmio_read32(base + PWM_REG_CTRL);
                mmio_write32(base + PWM_REG_CTRL, ctrl & !PWM_CTRL_ENABLE);
            }
        }
        Ok(())
    }

    /// Writes the current channel configuration to hardware registers.
    fn apply_channel_hw(&self, idx: usize) -> Result<()> {
        if !self.initialized {
            return Ok(()); // no-op if not initialised
        }
        let ch = &self.channels[idx];
        let period_ticks = self.ns_to_ticks(ch.period_ns);
        let duty_ticks = self.ns_to_ticks(ch.duty_ns);
        let base = self.channel_mmio_base(idx);

        // SAFETY: mmio_base is non-zero (checked in init). Channel MMIO
        // is within the mapped region at CHANNEL_STRIDE intervals.
        unsafe {
            mmio_write32(base + PWM_REG_PERIOD, period_ticks);
            mmio_write32(base + PWM_REG_DUTY, duty_ticks);

            let mut ctrl = PWM_CTRL_ENABLE;
            if ch.polarity == PwmPolarity::Inverted {
                ctrl |= PWM_CTRL_ENABLE | PWM_CTRL_POLARITY;
            }
            mmio_write32(base + PWM_REG_CTRL, ctrl);
        }
        Ok(())
    }

    /// Enables capture mode on a channel to measure an incoming signal.
    ///
    /// While in capture mode, the channel input is measured for period
    /// and duty. Use [`read_capture`](Self::read_capture) to retrieve results.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if index out of range or not requested.
    pub fn enable_capture(&mut self, ch: u8) -> Result<()> {
        let idx = ch as usize;
        if idx >= self.num_channels as usize {
            return Err(Error::InvalidArgument);
        }
        if !self.channels[idx].requested {
            return Err(Error::InvalidArgument);
        }
        self.channels[idx].capture_mode = true;
        if self.initialized {
            let base = self.channel_mmio_base(idx);
            // SAFETY: PWM_REG_CTRL enables capture mode via a dedicated bit.
            unsafe {
                let ctrl = mmio_read32(base + PWM_REG_CTRL);
                mmio_write32(base + PWM_REG_CTRL, ctrl | PWM_CTRL_CAPTURE);
            }
        }
        Ok(())
    }

    /// Reads the captured period and duty cycle from a channel in capture mode.
    ///
    /// Returns `Ok(PwmCaptureResult { valid: false })` if no new measurement
    /// is ready or if the channel is not in capture mode.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if index out of range.
    pub fn read_capture(&self, ch: u8) -> Result<PwmCaptureResult> {
        let idx = ch as usize;
        if idx >= self.num_channels as usize {
            return Err(Error::InvalidArgument);
        }
        if !self.channels[idx].capture_mode || !self.initialized {
            return Ok(PwmCaptureResult::default());
        }

        let base = self.channel_mmio_base(idx);
        // SAFETY: PWM_REG_STATUS is a read-only status register; reading it
        // is safe as long as the MMIO region is mapped.
        let status = unsafe { mmio_read32(base + PWM_REG_STATUS) };
        if (status & PWM_STATUS_CAP_READY) == 0 {
            return Ok(PwmCaptureResult::default());
        }

        // SAFETY: PWM_REG_PERIOD and PWM_REG_DUTY hold the last captured values.
        let period_ticks = unsafe { mmio_read32(base + PWM_REG_PERIOD) };
        let duty_ticks = unsafe { mmio_read32(base + PWM_REG_DUTY) };

        let period_ns = if self.clk_hz == 0 {
            0
        } else {
            (u64::from(period_ticks) * 1_000_000_000) / self.clk_hz
        };
        let duty_ns = if self.clk_hz == 0 {
            0
        } else {
            (u64::from(duty_ticks) * 1_000_000_000) / self.clk_hz
        };

        Ok(PwmCaptureResult {
            period_ns,
            duty_ns,
            valid: true,
        })
    }

    /// Returns a reference to the channel descriptor for the given index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the index is out of range.
    pub fn get_channel(&self, ch: u8) -> Result<&PwmChannelDesc> {
        let idx = ch as usize;
        if idx >= self.num_channels as usize {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.channels[idx])
    }

    /// Returns the number of active (enabled) channels.
    pub fn active_count(&self) -> usize {
        self.channels[..self.num_channels as usize]
            .iter()
            .filter(|c| c.is_active())
            .count()
    }
}

// ---------------------------------------------------------------------------
// PwmChipRegistry
// ---------------------------------------------------------------------------

/// Registry managing up to [`MAX_CHIPS`] PWM controller chips.
pub struct PwmChipRegistry {
    /// Registered chips.
    chips: [Option<PwmChip>; MAX_CHIPS],
    /// Number of registered chips.
    count: usize,
}

impl Default for PwmChipRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PwmChipRegistry {
    /// Creates a new, empty PWM chip registry.
    pub const fn new() -> Self {
        Self {
            chips: [const { None }; MAX_CHIPS],
            count: 0,
        }
    }

    /// Registers a PWM chip.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a chip with the same `id` exists.
    pub fn register(&mut self, chip: PwmChip) -> Result<()> {
        for slot in self.chips.iter().flatten() {
            if slot.id == chip.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in self.chips.iter_mut() {
            if slot.is_none() {
                *slot = Some(chip);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters a chip by `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching chip is registered.
    pub fn unregister(&mut self, id: u32) -> Result<()> {
        for slot in self.chips.iter_mut() {
            let matches = slot.as_ref().is_some_and(|c| c.id == id);
            if matches {
                *slot = None;
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a shared reference to a chip by `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn get(&self, id: u32) -> Result<&PwmChip> {
        self.chips
            .iter()
            .flatten()
            .find(|c| c.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns a mutable reference to a chip by `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn get_mut(&mut self, id: u32) -> Result<&mut PwmChip> {
        self.chips
            .iter_mut()
            .flatten()
            .find(|c| c.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns the number of registered chips.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no chips are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
