// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! LED class driver for the ONCRIX kernel.
//!
//! Provides a generic LED subsystem modeled after the Linux LED class
//! framework. LED devices can be registered, controlled by brightness,
//! and driven by configurable triggers (heartbeat, timer, default-on,
//! transient, etc.).
//!
//! # Architecture
//!
//! - [`LedColor`] — enumeration of standard LED colors.
//! - [`LedTriggerType`] — classification of LED trigger modes.
//! - [`LedTrigger`] — trigger configuration with on/off timing.
//! - [`LedDevice`] — a single LED with brightness, color, trigger,
//!   and blink state.
//! - [`LedRegistry`] — manages up to [`MAX_LEDS`] LED devices with
//!   registration, lookup, and periodic tick processing.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of LED devices in the registry.
const MAX_LEDS: usize = 32;

/// Maximum LED name length in bytes.
const MAX_NAME_LEN: usize = 32;

/// Maximum brightness value (full intensity).
const MAX_BRIGHTNESS: u8 = 255;

/// Default heartbeat on-time in milliseconds.
const HEARTBEAT_ON_MS: u32 = 70;

/// Default heartbeat off-time in milliseconds.
const HEARTBEAT_OFF_MS: u32 = 930;

/// Default timer blink on-time in milliseconds.
const DEFAULT_BLINK_ON_MS: u32 = 500;

/// Default timer blink off-time in milliseconds.
const DEFAULT_BLINK_OFF_MS: u32 = 500;

/// Default transient duration in milliseconds.
const DEFAULT_TRANSIENT_MS: u32 = 1000;

/// Nanoseconds per millisecond.
const _NANOS_PER_MS: u64 = 1_000_000;

// -------------------------------------------------------------------
// LedColor
// -------------------------------------------------------------------

/// Standard LED color classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LedColor {
    /// White LED (default / unspecified).
    #[default]
    White,
    /// Red LED.
    Red,
    /// Green LED.
    Green,
    /// Blue LED.
    Blue,
    /// Amber / yellow LED.
    Amber,
    /// Multi-color (RGB) LED.
    MultiColor,
}

// -------------------------------------------------------------------
// LedTriggerType
// -------------------------------------------------------------------

/// Classification of LED trigger modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LedTriggerType {
    /// No trigger — brightness is set manually.
    #[default]
    None,
    /// LED is on by default (full brightness at registration).
    DefaultOn,
    /// Heartbeat pattern (short flash, long pause).
    Heartbeat,
    /// Periodic timer blink with configurable on/off times.
    Timer,
    /// Transient one-shot pulse (on for a duration, then off).
    Transient,
    /// Activity indicator (flashes on I/O or CPU activity).
    Activity,
}

// -------------------------------------------------------------------
// LedName — fixed-size name buffer
// -------------------------------------------------------------------

/// A fixed-size buffer for LED device names.
#[derive(Clone, Copy)]
pub struct LedName {
    /// Raw bytes (null-padded).
    bytes: [u8; MAX_NAME_LEN],
    /// Actual length.
    len: usize,
}

impl LedName {
    /// Creates a new LED name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the name is empty or
    /// exceeds [`MAX_NAME_LEN`].
    pub fn new(name: &str) -> Result<Self> {
        let b = name.as_bytes();
        if b.is_empty() || b.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut bytes = [0u8; MAX_NAME_LEN];
        bytes[..b.len()].copy_from_slice(b);
        Ok(Self {
            bytes,
            len: b.len(),
        })
    }

    /// Returns the name as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Returns `true` if this name matches the given string.
    pub fn matches(&self, other: &str) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl core::fmt::Debug for LedName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Ok(s) = core::str::from_utf8(self.as_bytes()) {
            write!(f, "\"{}\"", s)
        } else {
            write!(f, "{:?}", self.as_bytes())
        }
    }
}

/// Constant empty name for array initialisation.
const EMPTY_NAME: LedName = LedName {
    bytes: [0u8; MAX_NAME_LEN],
    len: 0,
};

// -------------------------------------------------------------------
// LedTrigger — trigger configuration
// -------------------------------------------------------------------

/// Trigger configuration controlling automatic LED behaviour.
#[derive(Debug, Clone, Copy)]
pub struct LedTrigger {
    /// Type of trigger.
    pub trigger_type: LedTriggerType,
    /// On-time in milliseconds (for timer/heartbeat triggers).
    pub delay_on_ms: u32,
    /// Off-time in milliseconds (for timer/heartbeat triggers).
    pub delay_off_ms: u32,
    /// Whether the trigger is currently active.
    pub active: bool,
}

/// Constant empty trigger for array initialisation.
const EMPTY_TRIGGER: LedTrigger = LedTrigger {
    trigger_type: LedTriggerType::None,
    delay_on_ms: 0,
    delay_off_ms: 0,
    active: false,
};

impl LedTrigger {
    /// Creates a "none" trigger (manual control).
    pub const fn none() -> Self {
        EMPTY_TRIGGER
    }

    /// Creates a "default-on" trigger.
    pub const fn default_on() -> Self {
        Self {
            trigger_type: LedTriggerType::DefaultOn,
            delay_on_ms: 0,
            delay_off_ms: 0,
            active: true,
        }
    }

    /// Creates a heartbeat trigger.
    pub const fn heartbeat() -> Self {
        Self {
            trigger_type: LedTriggerType::Heartbeat,
            delay_on_ms: HEARTBEAT_ON_MS,
            delay_off_ms: HEARTBEAT_OFF_MS,
            active: true,
        }
    }

    /// Creates a timer blink trigger with configurable on/off
    /// durations.
    pub const fn timer(on_ms: u32, off_ms: u32) -> Self {
        Self {
            trigger_type: LedTriggerType::Timer,
            delay_on_ms: on_ms,
            delay_off_ms: off_ms,
            active: true,
        }
    }

    /// Creates a transient one-shot trigger.
    pub const fn transient(duration_ms: u32) -> Self {
        Self {
            trigger_type: LedTriggerType::Transient,
            delay_on_ms: duration_ms,
            delay_off_ms: 0,
            active: true,
        }
    }

    /// Returns the total blink period in milliseconds.
    pub fn period_ms(&self) -> u32 {
        self.delay_on_ms.saturating_add(self.delay_off_ms)
    }
}

// -------------------------------------------------------------------
// BlinkState — internal blink timer state
// -------------------------------------------------------------------

/// Internal state for LED blink timing.
#[derive(Debug, Clone, Copy, Default)]
struct BlinkState {
    /// Whether the LED is currently in the "on" phase of a blink.
    phase_on: bool,
    /// Milliseconds elapsed in the current phase.
    elapsed_ms: u32,
    /// Total blink cycles completed.
    cycle_count: u64,
}

// -------------------------------------------------------------------
// LedDevice
// -------------------------------------------------------------------

/// A single LED device with brightness, color, and trigger control.
#[derive(Debug, Clone)]
pub struct LedDevice {
    /// Unique device identifier.
    pub id: u32,
    /// Human-readable device name.
    pub name: LedName,
    /// Current brightness (0 = off, 255 = maximum).
    brightness: u8,
    /// Maximum supported brightness.
    max_brightness: u8,
    /// LED color classification.
    pub color: LedColor,
    /// Active trigger configuration.
    trigger: LedTrigger,
    /// Internal blink timer state.
    blink: BlinkState,
    /// Whether the LED is registered and active.
    pub registered: bool,
    /// Whether software blink emulation is enabled.
    pub sw_blink: bool,
}

/// Constant empty device for array initialisation.
const EMPTY_LED: LedDevice = LedDevice {
    id: 0,
    name: EMPTY_NAME,
    brightness: 0,
    max_brightness: MAX_BRIGHTNESS,
    color: LedColor::White,
    trigger: EMPTY_TRIGGER,
    blink: BlinkState {
        phase_on: false,
        elapsed_ms: 0,
        cycle_count: 0,
    },
    registered: false,
    sw_blink: true,
};

impl LedDevice {
    /// Creates a new LED device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `name` is invalid.
    pub fn new(id: u32, name: &str, color: LedColor) -> Result<Self> {
        let mut led = EMPTY_LED;
        led.id = id;
        led.name = LedName::new(name)?;
        led.color = color;
        led.registered = true;
        Ok(led)
    }

    /// Returns the current brightness.
    pub fn brightness(&self) -> u8 {
        self.brightness
    }

    /// Sets the brightness.
    ///
    /// The value is clamped to [`max_brightness`](Self::max_brightness).
    pub fn set_brightness(&mut self, value: u8) {
        self.brightness = if value > self.max_brightness {
            self.max_brightness
        } else {
            value
        };
    }

    /// Returns the maximum supported brightness.
    pub fn max_brightness(&self) -> u8 {
        self.max_brightness
    }

    /// Sets the maximum brightness.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `max` is zero.
    pub fn set_max_brightness(&mut self, max: u8) -> Result<()> {
        if max == 0 {
            return Err(Error::InvalidArgument);
        }
        self.max_brightness = max;
        if self.brightness > max {
            self.brightness = max;
        }
        Ok(())
    }

    /// Returns the current trigger configuration.
    pub fn trigger(&self) -> &LedTrigger {
        &self.trigger
    }

    /// Sets a new trigger for the LED.
    ///
    /// Resets the blink state and applies the trigger's initial
    /// effect (e.g., default-on sets full brightness).
    pub fn set_trigger(&mut self, trigger: LedTrigger) {
        self.trigger = trigger;
        self.blink = BlinkState::default();

        match trigger.trigger_type {
            LedTriggerType::DefaultOn => {
                self.brightness = self.max_brightness;
            }
            LedTriggerType::Heartbeat | LedTriggerType::Timer => {
                self.blink.phase_on = true;
                self.brightness = self.max_brightness;
            }
            LedTriggerType::Transient => {
                self.blink.phase_on = true;
                self.brightness = self.max_brightness;
            }
            LedTriggerType::None | LedTriggerType::Activity => {
                self.brightness = 0;
            }
        }
    }

    /// Clears the trigger (returns to manual control, LED off).
    pub fn clear_trigger(&mut self) {
        self.trigger = LedTrigger::none();
        self.blink = BlinkState::default();
        self.brightness = 0;
    }

    /// Starts a one-shot blink: on for `on_ms`, then off.
    pub fn blink_once(&mut self, on_ms: u32) {
        self.trigger = LedTrigger::transient(on_ms);
        self.blink = BlinkState {
            phase_on: true,
            elapsed_ms: 0,
            cycle_count: 0,
        };
        self.brightness = self.max_brightness;
    }

    /// Advances the LED's blink state by `delta_ms` milliseconds.
    ///
    /// This should be called periodically (e.g., from a timer
    /// interrupt handler) to drive trigger-based blinking.
    pub fn tick(&mut self, delta_ms: u32) {
        if !self.trigger.active {
            return;
        }
        match self.trigger.trigger_type {
            LedTriggerType::Timer | LedTriggerType::Heartbeat => {
                self.tick_periodic(delta_ms);
            }
            LedTriggerType::Transient => {
                self.tick_transient(delta_ms);
            }
            LedTriggerType::Activity => {
                self.tick_activity(delta_ms);
            }
            LedTriggerType::None | LedTriggerType::DefaultOn => {}
        }
    }

    /// Notifies the LED of activity (for the activity trigger).
    pub fn notify_activity(&mut self) {
        if self.trigger.trigger_type == LedTriggerType::Activity && self.trigger.active {
            self.brightness = self.max_brightness;
            self.blink.phase_on = true;
            self.blink.elapsed_ms = 0;
        }
    }

    /// Returns the number of completed blink cycles.
    pub fn blink_cycle_count(&self) -> u64 {
        self.blink.cycle_count
    }

    // ── sysfs-like attribute interface ─────────────────────────

    /// Reads an attribute value by name.
    ///
    /// Supported attributes:
    /// - `"brightness"` — current brightness (0–255)
    /// - `"max_brightness"` — maximum brightness
    /// - `"trigger"` — trigger type as integer (0–5)
    /// - `"color"` — color as integer (0–5)
    /// - `"delay_on"` — trigger on-time in ms
    /// - `"delay_off"` — trigger off-time in ms
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the attribute name is unknown.
    pub fn read_attr(&self, attr: &str) -> Result<u32> {
        match attr {
            "brightness" => Ok(u32::from(self.brightness)),
            "max_brightness" => Ok(u32::from(self.max_brightness)),
            "trigger" => Ok(self.trigger.trigger_type as u32),
            "color" => Ok(self.color as u32),
            "delay_on" => Ok(self.trigger.delay_on_ms),
            "delay_off" => Ok(self.trigger.delay_off_ms),
            _ => Err(Error::NotFound),
        }
    }

    /// Writes an attribute value by name.
    ///
    /// Supported attributes:
    /// - `"brightness"` — set brightness (clamped to max)
    /// - `"trigger"` — set trigger type by integer
    /// - `"delay_on"` — set trigger on-time in ms
    /// - `"delay_off"` — set trigger off-time in ms
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the attribute name is unknown,
    /// or [`Error::InvalidArgument`] if the value is out of range.
    pub fn write_attr(&mut self, attr: &str, value: u32) -> Result<()> {
        match attr {
            "brightness" => {
                let val = if value > u32::from(u8::MAX) {
                    u8::MAX
                } else {
                    value as u8
                };
                self.set_brightness(val);
                Ok(())
            }
            "trigger" => {
                let trigger_type = match value {
                    0 => LedTriggerType::None,
                    1 => LedTriggerType::DefaultOn,
                    2 => LedTriggerType::Heartbeat,
                    3 => LedTriggerType::Timer,
                    4 => LedTriggerType::Transient,
                    5 => LedTriggerType::Activity,
                    _ => return Err(Error::InvalidArgument),
                };
                let trigger = match trigger_type {
                    LedTriggerType::None => LedTrigger::none(),
                    LedTriggerType::DefaultOn => LedTrigger::default_on(),
                    LedTriggerType::Heartbeat => LedTrigger::heartbeat(),
                    LedTriggerType::Timer => {
                        LedTrigger::timer(DEFAULT_BLINK_ON_MS, DEFAULT_BLINK_OFF_MS)
                    }
                    LedTriggerType::Transient => LedTrigger::transient(DEFAULT_TRANSIENT_MS),
                    LedTriggerType::Activity => LedTrigger {
                        trigger_type: LedTriggerType::Activity,
                        delay_on_ms: HEARTBEAT_ON_MS,
                        delay_off_ms: HEARTBEAT_OFF_MS,
                        active: true,
                    },
                };
                self.set_trigger(trigger);
                Ok(())
            }
            "delay_on" => {
                self.trigger.delay_on_ms = value;
                Ok(())
            }
            "delay_off" => {
                self.trigger.delay_off_ms = value;
                Ok(())
            }
            _ => Err(Error::NotFound),
        }
    }

    // ── Internal tick helpers ──────────────────────────────────

    /// Drives the periodic blink (timer or heartbeat trigger).
    fn tick_periodic(&mut self, delta_ms: u32) {
        self.blink.elapsed_ms += delta_ms;

        if self.blink.phase_on {
            if self.blink.elapsed_ms >= self.trigger.delay_on_ms {
                self.blink.phase_on = false;
                self.blink.elapsed_ms -= self.trigger.delay_on_ms;
                self.brightness = 0;
            }
        } else if self.blink.elapsed_ms >= self.trigger.delay_off_ms {
            self.blink.phase_on = true;
            self.blink.elapsed_ms -= self.trigger.delay_off_ms;
            self.brightness = self.max_brightness;
            self.blink.cycle_count += 1;
        }
    }

    /// Drives the transient one-shot trigger.
    fn tick_transient(&mut self, delta_ms: u32) {
        if !self.blink.phase_on {
            return;
        }
        self.blink.elapsed_ms += delta_ms;
        if self.blink.elapsed_ms >= self.trigger.delay_on_ms {
            self.blink.phase_on = false;
            self.brightness = 0;
            self.trigger.active = false;
            self.blink.cycle_count += 1;
        }
    }

    /// Drives the activity indicator trigger.
    fn tick_activity(&mut self, delta_ms: u32) {
        if !self.blink.phase_on {
            return;
        }
        self.blink.elapsed_ms += delta_ms;
        if self.blink.elapsed_ms >= self.trigger.delay_on_ms {
            self.blink.phase_on = false;
            self.brightness = 0;
            self.blink.elapsed_ms = 0;
        }
    }
}

// -------------------------------------------------------------------
// LedRegistry
// -------------------------------------------------------------------

/// Registry managing up to [`MAX_LEDS`] LED devices.
///
/// Provides registration, lookup, brightness control, and periodic
/// tick processing for all registered LEDs.
#[derive(Debug)]
pub struct LedRegistry {
    /// Registered LED devices.
    leds: [LedDevice; MAX_LEDS],
    /// Number of registered devices.
    count: usize,
}

impl LedRegistry {
    /// Creates a new empty LED registry.
    pub const fn new() -> Self {
        Self {
            leds: [EMPTY_LED; MAX_LEDS],
            count: 0,
        }
    }

    /// Registers an LED device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AlreadyExists`] if an LED with the same ID
    /// is already registered, or [`Error::OutOfMemory`] if the
    /// registry is full.
    pub fn register(&mut self, led: LedDevice) -> Result<()> {
        for l in &self.leds[..self.count] {
            if l.id == led.id {
                return Err(Error::AlreadyExists);
            }
        }
        if self.count >= MAX_LEDS {
            return Err(Error::OutOfMemory);
        }
        self.leds[self.count] = led;
        self.count += 1;
        Ok(())
    }

    /// Unregisters an LED device by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no LED with the given ID
    /// is registered.
    pub fn unregister(&mut self, led_id: u32) -> Result<()> {
        let idx = self.find_index(led_id)?;
        let last = self.count - 1;
        if idx != last {
            self.leds[idx] = self.leds[last].clone();
        }
        self.leds[last] = EMPTY_LED;
        self.count -= 1;
        Ok(())
    }

    /// Looks up an LED device by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the LED is not registered.
    pub fn get(&self, led_id: u32) -> Result<&LedDevice> {
        let idx = self.find_index(led_id)?;
        Ok(&self.leds[idx])
    }

    /// Returns a mutable reference to an LED device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the LED is not registered.
    pub fn get_mut(&mut self, led_id: u32) -> Result<&mut LedDevice> {
        let idx = self.find_index(led_id)?;
        Ok(&mut self.leds[idx])
    }

    /// Sets the brightness of an LED device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the LED is not registered.
    pub fn set_brightness(&mut self, led_id: u32, value: u8) -> Result<()> {
        let idx = self.find_index(led_id)?;
        self.leds[idx].set_brightness(value);
        Ok(())
    }

    /// Sets the trigger for an LED device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the LED is not registered.
    pub fn set_trigger(&mut self, led_id: u32, trigger: LedTrigger) -> Result<()> {
        let idx = self.find_index(led_id)?;
        self.leds[idx].set_trigger(trigger);
        Ok(())
    }

    /// Advances all LED blink timers by `delta_ms` milliseconds.
    ///
    /// Should be called periodically from a timer interrupt or
    /// kernel tick handler.
    pub fn tick_all(&mut self, delta_ms: u32) {
        for led in &mut self.leds[..self.count] {
            led.tick(delta_ms);
        }
    }

    /// Looks up an LED device by name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no LED with that name exists.
    pub fn find_by_name(&self, name: &str) -> Result<&LedDevice> {
        self.leds[..self.count]
            .iter()
            .find(|l| l.name.matches(name))
            .ok_or(Error::NotFound)
    }

    /// Returns a slice of all registered LED devices.
    pub fn devices(&self) -> &[LedDevice] {
        &self.leds[..self.count]
    }

    /// Returns the number of registered LED devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no LED devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the index of an LED by ID.
    fn find_index(&self, id: u32) -> Result<usize> {
        self.leds[..self.count]
            .iter()
            .position(|l| l.id == id)
            .ok_or(Error::NotFound)
    }
}
