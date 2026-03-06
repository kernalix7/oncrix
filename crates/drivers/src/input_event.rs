// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Input event subsystem (EV_KEY, EV_REL, EV_ABS, EV_SYN).
//!
//! This module implements an input event layer similar to the Linux evdev
//! interface. Input devices (keyboard, mouse, touchscreen, joystick) post
//! events into a per-device ring buffer. Consumers (graphical shell, console)
//! read events from the buffer.
//!
//! # Event Model
//!
//! Each event is a `InputEvent` with three fields:
//! - `event_type`: What kind of event (`EV_KEY`, `EV_REL`, `EV_ABS`, `EV_SYN`).
//! - `code`: Specific event within the type (e.g., `KEY_A`, `REL_X`, `ABS_X`).
//! - `value`: Signed 32-bit value (0/1 for keys; delta for REL; position for ABS).
//!
//! Reference: Linux kernel Documentation/input/input.rst; include/uapi/linux/input.h.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Event Type Codes (EV_*)
// ---------------------------------------------------------------------------

/// EV_SYN: Synchronisation event (end of event frame).
pub const EV_SYN: u16 = 0x00;
/// EV_KEY: Key or button state change.
pub const EV_KEY: u16 = 0x01;
/// EV_REL: Relative axis event (mouse movement, scroll wheel).
pub const EV_REL: u16 = 0x02;
/// EV_ABS: Absolute axis event (touchscreen, joystick).
pub const EV_ABS: u16 = 0x03;
/// EV_MSC: Miscellaneous events.
pub const EV_MSC: u16 = 0x04;
/// EV_SW: Binary switch state.
pub const EV_SW: u16 = 0x05;
/// EV_LED: LED state.
pub const EV_LED: u16 = 0x11;
/// EV_REP: Autorepeat configuration.
pub const EV_REP: u16 = 0x14;

// ---------------------------------------------------------------------------
// Synchronisation codes (EV_SYN)
// ---------------------------------------------------------------------------

/// SYN_REPORT: End of event frame — consumer should process pending events.
pub const SYN_REPORT: u16 = 0;
/// SYN_DROPPED: Buffer overflow — events were dropped; consumer should resync.
pub const SYN_DROPPED: u16 = 3;

// ---------------------------------------------------------------------------
// Key codes (EV_KEY) — subset
// ---------------------------------------------------------------------------

/// Key released.
pub const KEY_STATE_UP: i32 = 0;
/// Key pressed.
pub const KEY_STATE_DOWN: i32 = 1;
/// Key autorepeat.
pub const KEY_STATE_REPEAT: i32 = 2;

/// KEY_ESC: Escape.
pub const KEY_ESC: u16 = 1;
/// KEY_1.
pub const KEY_1: u16 = 2;
/// KEY_A.
pub const KEY_A: u16 = 30;
/// KEY_ENTER: Enter/Return.
pub const KEY_ENTER: u16 = 28;
/// KEY_BACKSPACE.
pub const KEY_BACKSPACE: u16 = 14;
/// KEY_TAB.
pub const KEY_TAB: u16 = 15;
/// KEY_SPACE.
pub const KEY_SPACE: u16 = 57;
/// KEY_LEFTCTRL.
pub const KEY_LEFTCTRL: u16 = 29;
/// KEY_LEFTSHIFT.
pub const KEY_LEFTSHIFT: u16 = 42;
/// KEY_RIGHTSHIFT.
pub const KEY_RIGHTSHIFT: u16 = 54;
/// KEY_LEFTALT.
pub const KEY_LEFTALT: u16 = 56;
/// KEY_CAPSLOCK.
pub const KEY_CAPSLOCK: u16 = 58;
/// KEY_F1.
pub const KEY_F1: u16 = 59;
/// KEY_UP.
pub const KEY_UP: u16 = 103;
/// KEY_LEFT.
pub const KEY_LEFT: u16 = 105;
/// KEY_RIGHT.
pub const KEY_RIGHT: u16 = 106;
/// KEY_DOWN.
pub const KEY_DOWN: u16 = 108;

// ---------------------------------------------------------------------------
// Relative axis codes (EV_REL)
// ---------------------------------------------------------------------------

/// REL_X: Horizontal movement (positive = right).
pub const REL_X: u16 = 0x00;
/// REL_Y: Vertical movement (positive = down).
pub const REL_Y: u16 = 0x01;
/// REL_Z: Depth (3D mice).
pub const REL_Z: u16 = 0x02;
/// REL_WHEEL: Vertical scroll wheel.
pub const REL_WHEEL: u16 = 0x08;
/// REL_HWHEEL: Horizontal scroll wheel.
pub const REL_HWHEEL: u16 = 0x06;

// ---------------------------------------------------------------------------
// Absolute axis codes (EV_ABS)
// ---------------------------------------------------------------------------

/// ABS_X: Absolute X position.
pub const ABS_X: u16 = 0x00;
/// ABS_Y: Absolute Y position.
pub const ABS_Y: u16 = 0x01;
/// ABS_Z: Absolute Z.
pub const ABS_Z: u16 = 0x02;
/// ABS_PRESSURE: Stylus/touch pressure.
pub const ABS_PRESSURE: u16 = 0x18;
/// ABS_MT_SLOT: Multi-touch slot.
pub const ABS_MT_SLOT: u16 = 0x2F;
/// ABS_MT_POSITION_X: MT slot X position.
pub const ABS_MT_POSITION_X: u16 = 0x35;
/// ABS_MT_POSITION_Y: MT slot Y position.
pub const ABS_MT_POSITION_Y: u16 = 0x36;

// ---------------------------------------------------------------------------
// Button codes (EV_KEY for mouse)
// ---------------------------------------------------------------------------

/// BTN_LEFT: Left mouse button.
pub const BTN_LEFT: u16 = 0x110;
/// BTN_RIGHT: Right mouse button.
pub const BTN_RIGHT: u16 = 0x111;
/// BTN_MIDDLE: Middle mouse button.
pub const BTN_MIDDLE: u16 = 0x112;

// ---------------------------------------------------------------------------
// Input Event
// ---------------------------------------------------------------------------

/// A single input event (16 bytes, matches Linux `struct input_event` layout).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InputEvent {
    /// Event type (EV_KEY, EV_REL, EV_ABS, EV_SYN, …).
    pub event_type: u16,
    /// Event code (specific key, axis, etc.).
    pub code: u16,
    /// Event value (key state, delta, or position).
    pub value: i32,
}

impl InputEvent {
    /// Creates a new input event.
    pub const fn new(event_type: u16, code: u16, value: i32) -> Self {
        Self {
            event_type,
            code,
            value,
        }
    }

    /// Creates a SYN_REPORT event (marks end of an event frame).
    pub const fn syn_report() -> Self {
        Self::new(EV_SYN, SYN_REPORT, 0)
    }

    /// Creates a key press event.
    pub const fn key_press(key_code: u16) -> Self {
        Self::new(EV_KEY, key_code, KEY_STATE_DOWN)
    }

    /// Creates a key release event.
    pub const fn key_release(key_code: u16) -> Self {
        Self::new(EV_KEY, key_code, KEY_STATE_UP)
    }

    /// Creates a relative mouse movement event.
    pub const fn rel(axis: u16, delta: i32) -> Self {
        Self::new(EV_REL, axis, delta)
    }

    /// Creates an absolute position event.
    pub const fn abs(axis: u16, position: i32) -> Self {
        Self::new(EV_ABS, axis, position)
    }

    /// Returns `true` if this is a SYN_REPORT event.
    pub const fn is_syn_report(&self) -> bool {
        self.event_type == EV_SYN && self.code == SYN_REPORT
    }
}

// ---------------------------------------------------------------------------
// Absolute Axis Info
// ---------------------------------------------------------------------------

/// Configuration for an absolute axis (min, max, flat, fuzz, resolution).
#[derive(Clone, Copy, Debug, Default)]
pub struct AbsAxisInfo {
    /// Minimum value.
    pub minimum: i32,
    /// Maximum value.
    pub maximum: i32,
    /// Flat zone size (dead zone, e.g., for joysticks).
    pub flat: i32,
    /// Fuzz (noise threshold).
    pub fuzz: i32,
    /// Resolution in units per mm (or per radian for angular axes).
    pub resolution: i32,
}

impl AbsAxisInfo {
    /// Creates axis info for a touchscreen axis.
    pub const fn touchscreen(width: i32, height: i32) -> [Self; 2] {
        [
            Self {
                minimum: 0,
                maximum: width,
                flat: 0,
                fuzz: 0,
                resolution: 1,
            },
            Self {
                minimum: 0,
                maximum: height,
                flat: 0,
                fuzz: 0,
                resolution: 1,
            },
        ]
    }
}

// ---------------------------------------------------------------------------
// Input Event Ring Buffer
// ---------------------------------------------------------------------------

/// Capacity of the per-device event ring buffer.
pub const EVENT_RING_SIZE: usize = 512;

/// Per-device input event ring buffer (SPSC: single producer, single consumer).
pub struct EventBuffer {
    buf: [InputEvent; EVENT_RING_SIZE],
    head: usize,
    tail: usize,
    dropped: u32,
}

impl EventBuffer {
    /// Creates an empty event buffer.
    pub const fn new() -> Self {
        Self {
            buf: [InputEvent {
                event_type: 0,
                code: 0,
                value: 0,
            }; EVENT_RING_SIZE],
            head: 0,
            tail: 0,
            dropped: 0,
        }
    }

    /// Returns `true` if the buffer is empty (no events to read).
    pub const fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    /// Returns `true` if the buffer is full.
    pub const fn is_full(&self) -> bool {
        (self.tail + 1) % EVENT_RING_SIZE == self.head
    }

    /// Posts an event to the buffer.
    ///
    /// If the buffer is full, the event is dropped and a SYN_DROPPED is injected.
    pub fn post(&mut self, event: InputEvent) {
        if self.is_full() {
            self.dropped += 1;
            // Overwrite the oldest event with SYN_DROPPED.
            self.buf[self.tail] = InputEvent::new(EV_SYN, SYN_DROPPED, 0);
            self.tail = (self.tail + 1) % EVENT_RING_SIZE;
            self.head = (self.head + 1) % EVENT_RING_SIZE;
            return;
        }
        self.buf[self.tail] = event;
        self.tail = (self.tail + 1) % EVENT_RING_SIZE;
    }

    /// Reads one event from the buffer.
    ///
    /// Returns `None` if the buffer is empty.
    pub fn read(&mut self) -> Option<InputEvent> {
        if self.is_empty() {
            return None;
        }
        let event = self.buf[self.head];
        self.head = (self.head + 1) % EVENT_RING_SIZE;
        Some(event)
    }

    /// Returns the number of pending events.
    pub fn pending(&self) -> usize {
        (self.tail + EVENT_RING_SIZE - self.head) % EVENT_RING_SIZE
    }

    /// Returns the total number of dropped events since creation.
    pub fn dropped(&self) -> u32 {
        self.dropped
    }
}

impl Default for EventBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Input Device
// ---------------------------------------------------------------------------

/// Input device type classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputDeviceType {
    /// Keyboard (reports EV_KEY with keyboard keycodes).
    Keyboard,
    /// Pointer device (reports EV_REL for relative movement).
    Mouse,
    /// Absolute pointing device (touchscreen, digitizer tablet).
    Touchscreen,
    /// Game controller / joystick.
    Joystick,
}

/// Maximum number of registered input devices.
pub const MAX_INPUT_DEVICES: usize = 16;

/// An input device with a ring buffer and metadata.
pub struct InputDevice {
    /// Device name.
    pub name: &'static str,
    /// Device type.
    pub kind: InputDeviceType,
    /// Event ring buffer.
    pub buf: EventBuffer,
    /// Whether this device is currently enabled.
    pub enabled: bool,
}

impl InputDevice {
    /// Creates a new input device.
    pub const fn new(name: &'static str, kind: InputDeviceType) -> Self {
        Self {
            name,
            kind,
            buf: EventBuffer::new(),
            enabled: false,
        }
    }

    /// Enables this device (start accepting events).
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disables this device (events are dropped until re-enabled).
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Posts an event if the device is enabled.
    pub fn post(&mut self, event: InputEvent) {
        if self.enabled {
            self.buf.post(event);
        }
    }

    /// Posts a key press + SYN_REPORT pair.
    pub fn post_key_press(&mut self, key: u16) {
        self.post(InputEvent::key_press(key));
        self.post(InputEvent::syn_report());
    }

    /// Posts a key release + SYN_REPORT pair.
    pub fn post_key_release(&mut self, key: u16) {
        self.post(InputEvent::key_release(key));
        self.post(InputEvent::syn_report());
    }

    /// Posts relative mouse movement + SYN_REPORT.
    pub fn post_mouse_rel(&mut self, dx: i32, dy: i32) {
        if dx != 0 {
            self.post(InputEvent::rel(REL_X, dx));
        }
        if dy != 0 {
            self.post(InputEvent::rel(REL_Y, dy));
        }
        self.post(InputEvent::syn_report());
    }

    /// Reads one event.
    pub fn read_event(&mut self) -> Option<InputEvent> {
        self.buf.read()
    }
}

// ---------------------------------------------------------------------------
// Input Subsystem Registry
// ---------------------------------------------------------------------------

/// Global input device registry.
pub struct InputSubsystem {
    devices: [Option<InputDevice>; MAX_INPUT_DEVICES],
    count: usize,
}

impl InputSubsystem {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_INPUT_DEVICES],
            count: 0,
        }
    }

    /// Registers a new input device.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if the registry is full.
    pub fn register(&mut self, dev: InputDevice) -> Result<usize> {
        if self.count >= MAX_INPUT_DEVICES {
            return Err(Error::InvalidArgument);
        }
        let idx = self.count;
        self.devices[idx] = Some(dev);
        self.count += 1;
        Ok(idx)
    }

    /// Returns a mutable reference to the device at `index`.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut InputDevice> {
        self.devices[index].as_mut()
    }

    /// Returns a reference to the device at `index`.
    pub fn get(&self, index: usize) -> Option<&InputDevice> {
        self.devices[index].as_ref()
    }

    /// Returns the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for InputSubsystem {
    fn default() -> Self {
        Self::new()
    }
}
