// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hardware monitoring chip operations.
//!
//! Implements the hwmon device registration layer, per-channel sensor reading,
//! alarm threshold get/set, per-channel attribute naming, and the `hwmon_ops`
//! dispatch table used by individual chip drivers.
//!
//! # Channel types
//!
//! | [`ChanType`] | Unit of `read_raw` value |
//! |---|---|
//! | `Temp` | milli-degrees Celsius |
//! | `Voltage` | millivolts (mV) |
//! | `Fan` | RPM |
//! | `Power` | microwatts (µW) |
//! | `Curr` | milliamps (mA) |
//!
//! # Architecture
//!
//! - [`ChanType`] — sensor class discriminant.
//! - [`ChanAttr`] — attribute kind (input, min, max, crit, alarm, label).
//! - [`HwmonOps`] — dispatch trait implemented by chip drivers.
//! - [`HwmonChannel`] — descriptor for one logical sensor channel.
//! - [`HwmonChipDev`] — a registered chip device with channel list.
//! - [`HwmonRegistry`] — global chip registry with up to 8 chips.
//!
//! Reference: Linux `drivers/hwmon/hwmon.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum label length (including null byte space).
const LABEL_LEN: usize = 24;
/// Maximum channels per chip.
const MAX_CHANNELS: usize = 24;
/// Maximum chips in the registry.
const MAX_CHIPS: usize = 8;
/// Maximum chip name length.
const CHIP_NAME_LEN: usize = 32;

// ---------------------------------------------------------------------------
// ChanType
// ---------------------------------------------------------------------------

/// Classification of a hardware monitoring channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChanType {
    /// Temperature sensor (m°C).
    Temp,
    /// Voltage sensor (mV).
    Voltage,
    /// Fan speed sensor (RPM).
    Fan,
    /// Power sensor (µW).
    Power,
    /// Current sensor (mA).
    Curr,
}

// ---------------------------------------------------------------------------
// ChanAttr
// ---------------------------------------------------------------------------

/// Attribute kind for a sensor channel, analogous to Linux sysfs hwmon attrs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChanAttr {
    /// Current instantaneous reading.
    Input,
    /// Minimum threshold (alarm when reading falls below).
    Min,
    /// Maximum threshold (informational upper bound).
    Max,
    /// Critical threshold (alarm when reading exceeds).
    Crit,
    /// Alarm flag: 1 = threshold violated, 0 = normal.
    Alarm,
    /// Human-readable channel label.
    Label,
}

// ---------------------------------------------------------------------------
// HwmonOps — dispatch trait
// ---------------------------------------------------------------------------

/// Operations that a concrete hwmon chip driver must implement.
///
/// Each method receives the channel index and attribute kind; the driver
/// queries its hardware and returns the requested value or label bytes.
pub trait HwmonOps {
    /// Reads a numeric attribute for the given channel.
    ///
    /// Returns the raw value in channel-type units (see module doc).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the channel/attribute is unsupported.
    fn read_raw(&self, chan: usize, attr: ChanAttr) -> Result<i32>;

    /// Writes a numeric attribute to the given channel (thresholds).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] or [`Error::InvalidArgument`] on error.
    fn write_raw(&mut self, chan: usize, attr: ChanAttr, value: i32) -> Result<()>;

    /// Copies a human-readable label for `chan` into `buf`.
    ///
    /// Returns the number of bytes written. Default: returns 0.
    fn read_label(&self, chan: usize, buf: &mut [u8; LABEL_LEN]) -> usize;
}

// ---------------------------------------------------------------------------
// HwmonChannel
// ---------------------------------------------------------------------------

/// Descriptor for a single logical monitoring channel on a chip.
#[derive(Clone, Copy)]
pub struct HwmonChannel {
    /// Channel sensor type.
    pub chan_type: ChanType,
    /// Channel index on the chip (0-based within the type group).
    pub index: u8,
    /// Human-readable label.
    pub label: [u8; LABEL_LEN],
    /// Number of valid bytes in `label`.
    pub label_len: usize,
    /// Current reading (in channel-type units).
    pub value: i32,
    /// Minimum threshold.
    pub min: i32,
    /// Maximum threshold.
    pub max: i32,
    /// Critical threshold.
    pub crit: i32,
    /// Whether this channel slot is active.
    pub active: bool,
}

/// Constant empty channel for array initialisation.
const EMPTY_CHAN: HwmonChannel = HwmonChannel {
    chan_type: ChanType::Temp,
    index: 0,
    label: [0u8; LABEL_LEN],
    label_len: 0,
    value: 0,
    min: i32::MIN,
    max: i32::MAX,
    crit: i32::MAX,
    active: false,
};

impl HwmonChannel {
    /// Creates a new active channel with a label.
    ///
    /// The label slice is copied up to `LABEL_LEN - 1` bytes.
    pub fn new(chan_type: ChanType, index: u8, label: &[u8]) -> Self {
        let mut ch = EMPTY_CHAN;
        ch.chan_type = chan_type;
        ch.index = index;
        let copy_len = label.len().min(LABEL_LEN - 1);
        ch.label[..copy_len].copy_from_slice(&label[..copy_len]);
        ch.label_len = copy_len;
        ch.active = true;
        ch
    }

    /// Returns the label as a byte slice.
    pub fn label(&self) -> &[u8] {
        &self.label[..self.label_len]
    }

    /// Returns `true` if the current reading is below `min`.
    pub fn is_below_min(&self) -> bool {
        self.min != i32::MIN && self.value < self.min
    }

    /// Returns `true` if the current reading exceeds `crit`.
    pub fn is_above_crit(&self) -> bool {
        self.crit != i32::MAX && self.value > self.crit
    }

    /// Returns `true` if this is a fan channel stalled at 0 RPM.
    pub fn is_fan_fault(&self) -> bool {
        self.chan_type == ChanType::Fan && self.value == 0
    }

    /// Reads the given attribute directly from stored channel state.
    pub fn read_attr(&self, attr: ChanAttr) -> Result<i32> {
        match attr {
            ChanAttr::Input => Ok(self.value),
            ChanAttr::Min => Ok(self.min),
            ChanAttr::Max => Ok(self.max),
            ChanAttr::Crit => Ok(self.crit),
            ChanAttr::Alarm => {
                let alarm = if self.is_below_min() || self.is_above_crit() || self.is_fan_fault() {
                    1
                } else {
                    0
                };
                Ok(alarm)
            }
            ChanAttr::Label => Err(Error::InvalidArgument),
        }
    }

    /// Writes a threshold attribute to the channel state.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for read-only or label attributes.
    pub fn write_attr(&mut self, attr: ChanAttr, value: i32) -> Result<()> {
        match attr {
            ChanAttr::Min => {
                self.min = value;
                Ok(())
            }
            ChanAttr::Max => {
                self.max = value;
                Ok(())
            }
            ChanAttr::Crit => {
                self.crit = value;
                Ok(())
            }
            ChanAttr::Input | ChanAttr::Alarm | ChanAttr::Label => Err(Error::InvalidArgument),
        }
    }
}

// ---------------------------------------------------------------------------
// HwmonChipDev
// ---------------------------------------------------------------------------

/// A registered hwmon chip device with its channel population.
pub struct HwmonChipDev {
    /// Chip device ID (assigned by registry).
    pub id: u8,
    /// Chip name (e.g., b"nct6776").
    pub name: [u8; CHIP_NAME_LEN],
    /// Number of valid bytes in `name`.
    pub name_len: usize,
    /// Channel population.
    channels: [HwmonChannel; MAX_CHANNELS],
    /// Number of registered channels.
    channel_count: usize,
    /// Polling interval in milliseconds.
    pub update_interval_ms: u32,
    /// Whether this chip slot is occupied.
    pub active: bool,
}

/// Constant empty chip for array initialisation.
const EMPTY_CHIP: HwmonChipDev = HwmonChipDev {
    id: 0,
    name: [0u8; CHIP_NAME_LEN],
    name_len: 0,
    channels: [EMPTY_CHAN; MAX_CHANNELS],
    channel_count: 0,
    update_interval_ms: 1000,
    active: false,
};

impl HwmonChipDev {
    /// Creates a new chip device with the given name.
    ///
    /// The name slice is copied up to `CHIP_NAME_LEN - 1` bytes.
    pub fn new(id: u8, name: &[u8], update_interval_ms: u32) -> Self {
        let mut chip = EMPTY_CHIP;
        chip.id = id;
        let copy_len = name.len().min(CHIP_NAME_LEN - 1);
        chip.name[..copy_len].copy_from_slice(&name[..copy_len]);
        chip.name_len = copy_len;
        chip.update_interval_ms = update_interval_ms;
        chip.active = true;
        chip
    }

    /// Returns the chip name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Registers a channel on this chip.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the channel array is full.
    pub fn register_channel(&mut self, chan: HwmonChannel) -> Result<usize> {
        if self.channel_count >= MAX_CHANNELS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.channel_count;
        self.channels[idx] = chan;
        self.channel_count += 1;
        Ok(idx)
    }

    /// Returns a reference to a channel by index.
    pub fn get_channel(&self, idx: usize) -> Option<&HwmonChannel> {
        if idx < self.channel_count && self.channels[idx].active {
            Some(&self.channels[idx])
        } else {
            None
        }
    }

    /// Returns a mutable reference to a channel by index.
    pub fn get_channel_mut(&mut self, idx: usize) -> Option<&mut HwmonChannel> {
        if idx < self.channel_count && self.channels[idx].active {
            Some(&mut self.channels[idx])
        } else {
            None
        }
    }

    /// Reads a channel attribute, dispatching through `ops` for hardware access.
    ///
    /// For `ChanAttr::Input` the driver's `read_raw` is called to get a fresh
    /// value; for threshold/alarm attributes the cached channel state is used.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `chan_idx` is invalid.
    pub fn read_channel<O: HwmonOps>(
        &mut self,
        chan_idx: usize,
        attr: ChanAttr,
        ops: &mut O,
    ) -> Result<i32> {
        if chan_idx >= self.channel_count || !self.channels[chan_idx].active {
            return Err(Error::NotFound);
        }
        if attr == ChanAttr::Input {
            let val = ops.read_raw(chan_idx, attr)?;
            self.channels[chan_idx].value = val;
            return Ok(val);
        }
        self.channels[chan_idx].read_attr(attr)
    }

    /// Sets a threshold attribute on a channel via `ops`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `chan_idx` is invalid.
    pub fn write_channel<O: HwmonOps>(
        &mut self,
        chan_idx: usize,
        attr: ChanAttr,
        value: i32,
        ops: &mut O,
    ) -> Result<()> {
        if chan_idx >= self.channel_count || !self.channels[chan_idx].active {
            return Err(Error::NotFound);
        }
        ops.write_raw(chan_idx, attr, value)?;
        self.channels[chan_idx].write_attr(attr, value)
    }

    /// Returns the number of registered channels.
    pub fn channel_count(&self) -> usize {
        self.channel_count
    }

    /// Builds the sysfs-style attribute name for a channel into `buf`.
    ///
    /// Format: `<type_prefix><channel_index>_<attr_suffix>`
    /// Example: `temp1_input`, `fan2_min`, `in0_crit`.
    ///
    /// Returns the number of bytes written.
    pub fn attr_name(&self, chan_idx: usize, attr: ChanAttr, buf: &mut [u8]) -> usize {
        if chan_idx >= self.channel_count {
            return 0;
        }
        let ch = &self.channels[chan_idx];
        let prefix: &[u8] = match ch.chan_type {
            ChanType::Temp => b"temp",
            ChanType::Voltage => b"in",
            ChanType::Fan => b"fan",
            ChanType::Power => b"power",
            ChanType::Curr => b"curr",
        };
        let suffix: &[u8] = match attr {
            ChanAttr::Input => b"input",
            ChanAttr::Min => b"min",
            ChanAttr::Max => b"max",
            ChanAttr::Crit => b"crit",
            ChanAttr::Alarm => b"alarm",
            ChanAttr::Label => b"label",
        };
        // Build: prefix + (index+1 as decimal) + '_' + suffix
        let mut pos = 0;
        let copy_p = prefix.len().min(buf.len().saturating_sub(pos));
        buf[pos..pos + copy_p].copy_from_slice(&prefix[..copy_p]);
        pos += copy_p;
        // Write channel number (1-based, at most 2 digits).
        let num = ch.index + 1;
        if num >= 10 && pos < buf.len() {
            buf[pos] = b'0' + (num / 10);
            pos += 1;
        }
        if pos < buf.len() {
            buf[pos] = b'0' + (num % 10);
            pos += 1;
        }
        if pos < buf.len() {
            buf[pos] = b'_';
            pos += 1;
        }
        let copy_s = suffix.len().min(buf.len().saturating_sub(pos));
        buf[pos..pos + copy_s].copy_from_slice(&suffix[..copy_s]);
        pos += copy_s;
        pos
    }
}

// ---------------------------------------------------------------------------
// HwmonRegistry
// ---------------------------------------------------------------------------

/// Global hwmon chip registry.
///
/// Manages up to [`MAX_CHIPS`] chip devices and assigns sequential IDs.
pub struct HwmonRegistry {
    chips: [HwmonChipDev; MAX_CHIPS],
    chip_count: usize,
    next_id: u8,
}

impl HwmonRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            chips: [EMPTY_CHIP; MAX_CHIPS],
            chip_count: 0,
            next_id: 1,
        }
    }

    /// Registers a chip, assigning it an auto-incremented ID.
    ///
    /// Returns the assigned chip index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register_chip(&mut self, mut chip: HwmonChipDev) -> Result<usize> {
        if self.chip_count >= MAX_CHIPS {
            return Err(Error::OutOfMemory);
        }
        chip.id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let idx = self.chip_count;
        self.chips[idx] = chip;
        self.chip_count += 1;
        Ok(idx)
    }

    /// Unregisters a chip by registry index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `idx` is invalid.
    pub fn unregister_chip(&mut self, idx: usize) -> Result<()> {
        if idx >= self.chip_count || !self.chips[idx].active {
            return Err(Error::NotFound);
        }
        self.chips[idx].active = false;
        Ok(())
    }

    /// Returns a reference to the chip at `idx`.
    pub fn get_chip(&self, idx: usize) -> Option<&HwmonChipDev> {
        if idx < self.chip_count && self.chips[idx].active {
            Some(&self.chips[idx])
        } else {
            None
        }
    }

    /// Returns a mutable reference to the chip at `idx`.
    pub fn get_chip_mut(&mut self, idx: usize) -> Option<&mut HwmonChipDev> {
        if idx < self.chip_count && self.chips[idx].active {
            Some(&mut self.chips[idx])
        } else {
            None
        }
    }

    /// Returns the number of registered chips.
    pub fn chip_count(&self) -> usize {
        self.chip_count
    }

    /// Returns `true` if no chips are registered.
    pub fn is_empty(&self) -> bool {
        self.chip_count == 0
    }
}

impl Default for HwmonRegistry {
    fn default() -> Self {
        Self::new()
    }
}
