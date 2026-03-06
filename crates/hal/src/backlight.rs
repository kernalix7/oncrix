// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Display backlight control HAL for the ONCRIX operating system.
//!
//! Provides a platform-independent abstraction for managing display backlight
//! brightness. Supports MMIO-based controllers, ACPI backlight control, PWM
//! backlight drivers, and software fade transitions with configurable step
//! sizes and timing.
//!
//! # Architecture
//!
//! - **BacklightType** — hardware backlight mechanism identification
//! - **BrightnessLevel** — brightness value representation with clamping
//! - **FadeState** — state machine for software fade transitions
//! - **BacklightConfig** — hardware configuration for a backlight controller
//! - **BacklightDevice** — a single backlight device
//! - **BacklightEvent** — brightness change notification
//! - **BacklightRegistry** — manages up to [`MAX_BACKLIGHTS`] devices
//!
//! # MMIO Access
//!
//! All register access uses volatile reads/writes via `read_mmio32` /
//! `write_mmio32` helpers.
//!
//! # Reference
//!
//! Linux: `drivers/video/backlight/`, `include/linux/backlight.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of backlight devices in the registry.
const MAX_BACKLIGHTS: usize = 4;

/// Maximum number of pending backlight events.
const MAX_EVENTS: usize = 16;

/// Maximum brightness value for raw hardware.
const HW_MAX_BRIGHTNESS: u32 = 65535;

/// Default maximum brightness level.
const DEFAULT_MAX_BRIGHTNESS: u32 = 255;

/// Default fade step size (brightness units per step).
const DEFAULT_FADE_STEP: u32 = 5;

/// Default fade interval in milliseconds (per step).
const DEFAULT_FADE_INTERVAL_MS: u32 = 20;

// ---------------------------------------------------------------------------
// MMIO register offsets (generic PWM backlight controller)
// ---------------------------------------------------------------------------

/// Brightness level register offset.
const BL_BRIGHTNESS_OFF: usize = 0x00;

/// Maximum brightness register offset (read-only).
const BL_MAX_BRIGHTNESS_OFF: usize = 0x04;

/// Control register offset (enable/disable).
const BL_CTRL_OFF: usize = 0x08;

/// PWM duty cycle register offset.
const BL_PWM_DUTY_OFF: usize = 0x0C;

/// PWM period register offset.
const BL_PWM_PERIOD_OFF: usize = 0x10;

/// Status register offset.
const BL_STATUS_OFF: usize = 0x14;

// ---------------------------------------------------------------------------
// Control register bits
// ---------------------------------------------------------------------------

/// Backlight enable bit.
const BL_CTRL_ENABLE: u32 = 1 << 0;

/// PWM invert bit (invert duty cycle).
const BL_CTRL_INVERT: u32 = 1 << 1;

// ---------------------------------------------------------------------------
// BacklightType
// ---------------------------------------------------------------------------

/// Hardware backlight mechanism identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BacklightType {
    /// Raw register-based backlight (direct brightness register).
    #[default]
    Raw,
    /// Platform-specific backlight (e.g., vendor BIOS interface).
    Platform,
    /// ACPI-controlled backlight (_BCM/_BQC methods).
    Firmware,
    /// PWM (Pulse Width Modulation) controlled backlight.
    Pwm,
}

// ---------------------------------------------------------------------------
// BrightnessLevel
// ---------------------------------------------------------------------------

/// Brightness value representation with range clamping.
///
/// Brightness is stored as an absolute value within [0, max_brightness].
/// Provides conversion to/from percentage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrightnessLevel {
    /// Current brightness value.
    pub value: u32,
    /// Maximum brightness value for this device.
    pub max: u32,
}

impl BrightnessLevel {
    /// Creates a new brightness level clamped to the valid range.
    pub const fn new(value: u32, max: u32) -> Self {
        let clamped = if value > max { max } else { value };
        Self {
            value: clamped,
            max,
        }
    }

    /// Returns the brightness as a percentage (0-100).
    pub fn percent(&self) -> u32 {
        if self.max == 0 {
            return 0;
        }
        (self.value as u64 * 100 / self.max as u64) as u32
    }

    /// Creates a brightness level from a percentage (0-100).
    pub fn from_percent(percent: u32, max: u32) -> Self {
        let clamped = percent.min(100);
        let value = (clamped as u64 * max as u64 / 100) as u32;
        Self { value, max }
    }

    /// Returns `true` if the backlight is completely off.
    pub fn is_off(&self) -> bool {
        self.value == 0
    }

    /// Returns `true` if the backlight is at maximum brightness.
    pub fn is_max(&self) -> bool {
        self.value >= self.max
    }
}

// ---------------------------------------------------------------------------
// FadeDirection
// ---------------------------------------------------------------------------

/// Direction of a brightness fade transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FadeDirection {
    /// Fading brightness up (increasing).
    Up,
    /// Fading brightness down (decreasing).
    Down,
}

// ---------------------------------------------------------------------------
// FadeState
// ---------------------------------------------------------------------------

/// State machine for software-driven brightness fade transitions.
///
/// Manages a gradual brightness change from the current level to a target
/// level, applying `step` brightness units at each `interval_ms` tick.
#[derive(Debug, Clone, Copy)]
pub struct FadeState {
    /// Whether a fade is currently in progress.
    pub active: bool,
    /// Target brightness value.
    pub target: u32,
    /// Step size per tick.
    pub step: u32,
    /// Interval between steps in milliseconds.
    pub interval_ms: u32,
    /// Fade direction.
    pub direction: FadeDirection,
    /// Last step timestamp in nanoseconds.
    pub last_step_ns: u64,
    /// Number of steps completed.
    pub steps_done: u32,
}

impl FadeState {
    /// Creates an inactive fade state.
    pub const fn new() -> Self {
        Self {
            active: false,
            target: 0,
            step: DEFAULT_FADE_STEP,
            interval_ms: DEFAULT_FADE_INTERVAL_MS,
            direction: FadeDirection::Up,
            last_step_ns: 0,
            steps_done: 0,
        }
    }

    /// Initialises a fade from `current` to `target`.
    pub fn start(&mut self, current: u32, target: u32, step: u32, interval_ms: u32) {
        self.active = true;
        self.target = target;
        self.step = step.max(1);
        self.interval_ms = interval_ms.max(1);
        self.direction = if target > current {
            FadeDirection::Up
        } else {
            FadeDirection::Down
        };
        self.last_step_ns = 0;
        self.steps_done = 0;
    }

    /// Advances the fade by one step, returning the new brightness value.
    ///
    /// Returns `None` if the fade is not active or the interval has not
    /// elapsed since the last step.
    pub fn tick(&mut self, current: u32, now_ns: u64) -> Option<u32> {
        if !self.active {
            return None;
        }

        // Check timing.
        let interval_ns = self.interval_ms as u64 * 1_000_000;
        if now_ns.saturating_sub(self.last_step_ns) < interval_ns {
            return None;
        }

        let new_val = match self.direction {
            FadeDirection::Up => {
                let next = current.saturating_add(self.step);
                if next >= self.target {
                    self.active = false;
                    self.target
                } else {
                    next
                }
            }
            FadeDirection::Down => {
                let next = current.saturating_sub(self.step);
                if next <= self.target {
                    self.active = false;
                    self.target
                } else {
                    next
                }
            }
        };

        self.last_step_ns = now_ns;
        self.steps_done += 1;
        Some(new_val)
    }

    /// Cancels any in-progress fade.
    pub fn cancel(&mut self) {
        self.active = false;
    }
}

// ---------------------------------------------------------------------------
// BacklightConfig
// ---------------------------------------------------------------------------

/// Hardware configuration for a backlight controller.
#[derive(Debug, Clone, Copy)]
pub struct BacklightConfig {
    /// MMIO base address (0 for non-MMIO devices).
    pub mmio_base: usize,
    /// MMIO region size in bytes.
    pub mmio_size: usize,
    /// Backlight type.
    pub bl_type: BacklightType,
    /// Maximum brightness supported by the hardware.
    pub max_brightness: u32,
    /// Default brightness level at boot.
    pub default_brightness: u32,
    /// PWM period in nanoseconds (for PWM-type backlights).
    pub pwm_period_ns: u32,
    /// Whether the PWM duty cycle is inverted.
    pub pwm_inverted: bool,
    /// Power-on delay in microseconds.
    pub power_on_delay_us: u32,
}

impl Default for BacklightConfig {
    fn default() -> Self {
        Self {
            mmio_base: 0,
            mmio_size: 0,
            bl_type: BacklightType::Raw,
            max_brightness: DEFAULT_MAX_BRIGHTNESS,
            default_brightness: DEFAULT_MAX_BRIGHTNESS / 2,
            pwm_period_ns: 0,
            pwm_inverted: false,
            power_on_delay_us: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// BacklightEventType
// ---------------------------------------------------------------------------

/// Type of backlight event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BacklightEventType {
    /// Brightness changed.
    BrightnessChanged,
    /// Backlight turned on.
    PowerOn,
    /// Backlight turned off.
    PowerOff,
    /// Fade transition started.
    FadeStarted,
    /// Fade transition completed.
    FadeCompleted,
}

// ---------------------------------------------------------------------------
// BacklightEvent
// ---------------------------------------------------------------------------

/// A backlight state change notification.
#[derive(Debug, Clone, Copy)]
pub struct BacklightEvent {
    /// Device ID that generated the event.
    pub device_id: u32,
    /// Event type.
    pub event_type: BacklightEventType,
    /// Brightness level at time of event.
    pub brightness: u32,
    /// Maximum brightness of the device.
    pub max_brightness: u32,
    /// Timestamp in nanoseconds.
    pub timestamp_ns: u64,
}

/// Constant empty event for array initialisation.
const EMPTY_EVENT: BacklightEvent = BacklightEvent {
    device_id: 0,
    event_type: BacklightEventType::BrightnessChanged,
    brightness: 0,
    max_brightness: 0,
    timestamp_ns: 0,
};

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

/// Reads a 32-bit value from MMIO at `base + offset`.
///
/// # Safety
///
/// The caller must ensure `base + offset` is a valid MMIO address.
#[inline]
unsafe fn read_mmio32(base: usize, offset: usize) -> u32 {
    // SAFETY: caller guarantees the address is valid mapped MMIO.
    unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
}

/// Writes a 32-bit value to MMIO at `base + offset`.
///
/// # Safety
///
/// The caller must ensure `base + offset` is a valid MMIO address.
#[inline]
unsafe fn write_mmio32(base: usize, offset: usize, val: u32) {
    // SAFETY: caller guarantees the address is valid mapped MMIO.
    unsafe { core::ptr::write_volatile((base + offset) as *mut u32, val) }
}

// ---------------------------------------------------------------------------
// BacklightDevice
// ---------------------------------------------------------------------------

/// A single backlight device.
///
/// Manages brightness reading/writing, power state, and software fade
/// transitions for a display backlight.
pub struct BacklightDevice {
    /// Unique device identifier.
    pub id: u32,
    /// Human-readable name (UTF-8).
    pub name: [u8; 32],
    /// Number of valid bytes in [`name`](Self::name).
    pub name_len: usize,
    /// Hardware configuration.
    pub config: BacklightConfig,
    /// Current brightness level.
    pub brightness: BrightnessLevel,
    /// Whether the backlight is currently powered on.
    pub power_on: bool,
    /// Software fade state.
    pub fade: FadeState,
    /// Brightness before the backlight was turned off (for restore).
    pub saved_brightness: u32,
    /// Number of brightness changes.
    pub change_count: u64,
    /// Whether the device is registered and active.
    pub active: bool,
}

impl BacklightDevice {
    /// Creates a new backlight device.
    pub fn new(id: u32, name: &[u8], config: BacklightConfig) -> Self {
        let copy_len = name.len().min(32);
        let mut buf = [0u8; 32];
        buf[..copy_len].copy_from_slice(&name[..copy_len]);
        let brightness = BrightnessLevel::new(config.default_brightness, config.max_brightness);
        Self {
            id,
            name: buf,
            name_len: copy_len,
            config,
            brightness,
            power_on: false,
            fade: FadeState::new(),
            saved_brightness: config.default_brightness,
            change_count: 0,
            active: false,
        }
    }

    /// Initialises the backlight hardware.
    ///
    /// Enables the controller and sets the default brightness.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if MMIO access fails.
    pub fn init(&mut self) -> Result<()> {
        if self.config.mmio_base != 0 {
            // Read hardware maximum brightness.
            // SAFETY: mmio_base non-zero; BL_MAX_BRIGHTNESS_OFF is 32-bit RO.
            let hw_max = unsafe { read_mmio32(self.config.mmio_base, BL_MAX_BRIGHTNESS_OFF) };
            if hw_max > 0 {
                self.config.max_brightness = hw_max.min(HW_MAX_BRIGHTNESS);
                self.brightness.max = self.config.max_brightness;
            }

            // Enable the backlight controller.
            // SAFETY: mmio_base valid; BL_CTRL_OFF is 32-bit RW.
            let mut ctrl = unsafe { read_mmio32(self.config.mmio_base, BL_CTRL_OFF) };
            ctrl |= BL_CTRL_ENABLE;
            if self.config.pwm_inverted {
                ctrl |= BL_CTRL_INVERT;
            }
            unsafe {
                write_mmio32(self.config.mmio_base, BL_CTRL_OFF, ctrl);
            }

            // Set PWM period if applicable.
            if self.config.pwm_period_ns > 0 {
                // SAFETY: mmio_base valid; BL_PWM_PERIOD_OFF is 32-bit RW.
                unsafe {
                    write_mmio32(
                        self.config.mmio_base,
                        BL_PWM_PERIOD_OFF,
                        self.config.pwm_period_ns,
                    );
                }
            }

            // Set initial brightness.
            self.write_hw_brightness(self.brightness.value);
        }

        self.power_on = true;
        self.active = true;
        Ok(())
    }

    /// Returns the current brightness level.
    pub fn get_brightness(&self) -> BrightnessLevel {
        self.brightness
    }

    /// Sets the brightness to an absolute value.
    ///
    /// The value is clamped to [0, max_brightness].
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the device is not active.
    pub fn set_brightness(&mut self, value: u32) -> Result<()> {
        if !self.active {
            return Err(Error::IoError);
        }

        // Cancel any in-progress fade.
        self.fade.cancel();

        let clamped = value.min(self.config.max_brightness);
        self.brightness.value = clamped;
        self.write_hw_brightness(clamped);

        if clamped > 0 && !self.power_on {
            self.power_on = true;
        } else if clamped == 0 {
            self.power_on = false;
        }

        self.change_count += 1;
        Ok(())
    }

    /// Returns the maximum brightness value.
    pub fn get_max_brightness(&self) -> u32 {
        self.config.max_brightness
    }

    /// Initiates a fade transition to the target brightness.
    ///
    /// The fade occurs gradually over multiple ticks. Call
    /// [`tick_fade`](Self::tick_fade) periodically to advance it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the device is not active.
    pub fn fade_to(&mut self, target: u32) -> Result<()> {
        if !self.active {
            return Err(Error::IoError);
        }

        let clamped_target = target.min(self.config.max_brightness);
        if clamped_target == self.brightness.value {
            return Ok(());
        }

        self.fade.start(
            self.brightness.value,
            clamped_target,
            DEFAULT_FADE_STEP,
            DEFAULT_FADE_INTERVAL_MS,
        );
        Ok(())
    }

    /// Initiates a fade transition with custom step size and interval.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the device is not active, or
    /// [`Error::InvalidArgument`] if step or interval is zero.
    pub fn fade_to_custom(&mut self, target: u32, step: u32, interval_ms: u32) -> Result<()> {
        if !self.active {
            return Err(Error::IoError);
        }
        if step == 0 || interval_ms == 0 {
            return Err(Error::InvalidArgument);
        }

        let clamped_target = target.min(self.config.max_brightness);
        self.fade
            .start(self.brightness.value, clamped_target, step, interval_ms);
        Ok(())
    }

    /// Advances the fade transition by one step.
    ///
    /// Returns `true` if the brightness changed, `false` otherwise.
    pub fn tick_fade(&mut self, now_ns: u64) -> bool {
        if let Some(new_val) = self.fade.tick(self.brightness.value, now_ns) {
            self.brightness.value = new_val;
            self.write_hw_brightness(new_val);
            self.change_count += 1;
            true
        } else {
            false
        }
    }

    /// Returns `true` if a fade is currently in progress.
    pub fn is_fading(&self) -> bool {
        self.fade.active
    }

    /// Turns the backlight off, saving the current brightness for later restore.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the device is not active.
    pub fn power_off(&mut self) -> Result<()> {
        if !self.active {
            return Err(Error::IoError);
        }
        self.saved_brightness = self.brightness.value;
        self.brightness.value = 0;
        self.write_hw_brightness(0);
        self.power_on = false;

        if self.config.mmio_base != 0 {
            // SAFETY: mmio_base valid; BL_CTRL_OFF is 32-bit RW.
            let ctrl = unsafe { read_mmio32(self.config.mmio_base, BL_CTRL_OFF) };
            unsafe {
                write_mmio32(self.config.mmio_base, BL_CTRL_OFF, ctrl & !BL_CTRL_ENABLE);
            }
        }
        Ok(())
    }

    /// Restores the backlight to the previously saved brightness.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the device is not active.
    pub fn power_on_restore(&mut self) -> Result<()> {
        if !self.active {
            return Err(Error::IoError);
        }

        if self.config.mmio_base != 0 {
            // SAFETY: mmio_base valid; BL_CTRL_OFF is 32-bit RW.
            let ctrl = unsafe { read_mmio32(self.config.mmio_base, BL_CTRL_OFF) };
            unsafe {
                write_mmio32(self.config.mmio_base, BL_CTRL_OFF, ctrl | BL_CTRL_ENABLE);
            }
        }

        self.brightness.value = self.saved_brightness;
        self.write_hw_brightness(self.saved_brightness);
        self.power_on = true;
        Ok(())
    }

    /// Reads the hardware brightness register.
    pub fn read_hw_brightness(&self) -> u32 {
        if self.config.mmio_base == 0 {
            return self.brightness.value;
        }
        // SAFETY: mmio_base valid; BL_BRIGHTNESS_OFF is 32-bit RO.
        unsafe { read_mmio32(self.config.mmio_base, BL_BRIGHTNESS_OFF) }
    }

    /// Writes the brightness value to the hardware.
    fn write_hw_brightness(&self, value: u32) {
        if self.config.mmio_base == 0 {
            return;
        }

        match self.config.bl_type {
            BacklightType::Pwm => {
                // For PWM backlights, compute duty cycle from brightness.
                let duty = if self.config.max_brightness == 0 {
                    0
                } else {
                    (value as u64 * self.config.pwm_period_ns as u64
                        / self.config.max_brightness as u64) as u32
                };
                let duty = if self.config.pwm_inverted {
                    self.config.pwm_period_ns.saturating_sub(duty)
                } else {
                    duty
                };
                // SAFETY: mmio_base valid; BL_PWM_DUTY_OFF is 32-bit RW.
                unsafe {
                    write_mmio32(self.config.mmio_base, BL_PWM_DUTY_OFF, duty);
                }
            }
            _ => {
                // Direct brightness register write.
                // SAFETY: mmio_base valid; BL_BRIGHTNESS_OFF is 32-bit RW.
                unsafe {
                    write_mmio32(self.config.mmio_base, BL_BRIGHTNESS_OFF, value);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// BacklightRegistry
// ---------------------------------------------------------------------------

/// Registry managing up to [`MAX_BACKLIGHTS`] backlight devices.
pub struct BacklightRegistry {
    /// Registered backlight devices.
    devices: [Option<BacklightDevice>; MAX_BACKLIGHTS],
    /// Number of registered devices.
    count: usize,
    /// Pending events.
    events: [BacklightEvent; MAX_EVENTS],
    /// Number of pending events.
    event_count: usize,
}

impl Default for BacklightRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BacklightRegistry {
    /// Creates a new, empty backlight registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_BACKLIGHTS],
            count: 0,
            events: [EMPTY_EVENT; MAX_EVENTS],
            event_count: 0,
        }
    }

    /// Registers a backlight device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a device with the same id exists.
    pub fn register(&mut self, device: BacklightDevice) -> Result<()> {
        for slot in self.devices.iter().flatten() {
            if slot.id == device.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in self.devices.iter_mut() {
            if slot.is_none() {
                *slot = Some(device);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregisters a backlight device by `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no device with that id exists.
    pub fn unregister(&mut self, id: u32) -> Result<()> {
        for slot in self.devices.iter_mut() {
            let matches = slot.as_ref().is_some_and(|d| d.id == id);
            if matches {
                *slot = None;
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a reference to a device by its `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn get(&self, id: u32) -> Result<&BacklightDevice> {
        self.devices
            .iter()
            .flatten()
            .find(|d| d.id == id)
            .ok_or(Error::NotFound)
    }

    /// Returns a mutable reference to a device by its `id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not registered.
    pub fn get_mut(&mut self, id: u32) -> Result<&mut BacklightDevice> {
        self.devices
            .iter_mut()
            .flatten()
            .find(|d| d.id == id)
            .ok_or(Error::NotFound)
    }

    /// Ticks all active fade transitions.
    ///
    /// Returns the number of devices whose brightness changed.
    pub fn tick_fades(&mut self, now_ns: u64) -> usize {
        let mut changed = 0;
        for slot in self.devices.iter_mut() {
            if let Some(dev) = slot {
                if dev.tick_fade(now_ns) {
                    changed += 1;
                }
            }
        }
        changed
    }

    /// Pushes an event into the event queue.
    pub fn push_event(&mut self, event: BacklightEvent) {
        if self.event_count < MAX_EVENTS {
            self.events[self.event_count] = event;
            self.event_count += 1;
        }
    }

    /// Pops the oldest event from the queue.
    pub fn pop_event(&mut self) -> Option<BacklightEvent> {
        if self.event_count == 0 {
            return None;
        }
        let event = self.events[0];
        let remaining = self.event_count - 1;
        for i in 0..remaining {
            self.events[i] = self.events[i + 1];
        }
        self.event_count -= 1;
        Some(event)
    }

    /// Returns the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the number of pending events.
    pub fn event_count(&self) -> usize {
        self.event_count
    }
}
