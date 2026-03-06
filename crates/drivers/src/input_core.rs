// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Generic input event subsystem.
//!
//! Provides a unified input event framework modelled after the Linux
//! input subsystem (`/dev/input/eventN`). Input devices report events
//! (key presses, relative motion, absolute coordinates) into a
//! per-device ring buffer. Registered input handlers receive matching
//! events for further processing.
//!
//! # Architecture
//!
//! - [`InputEventType`] -- top-level event type codes (EV_SYN,
//!   EV_KEY, EV_REL, EV_ABS, etc.).
//! - [`InputEvent`] -- a single input event (type + code + value).
//! - [`InputDeviceCaps`] -- capability bitmasks describing which
//!   event types, keys, relative axes, and absolute axes a device
//!   can generate.
//! - [`AbsAxisInfo`] -- range and fuzz/flat parameters for an
//!   absolute axis.
//! - [`InputDevice`] -- a registered input device with event buffer,
//!   capabilities, and grab state.
//! - [`InputHandler`] -- a consumer that receives events matching a
//!   set of event-type capabilities.
//! - [`InputSubsystem`] -- the top-level manager that routes events
//!   from devices to handlers.
//!
//! # Usage
//!
//! ```ignore
//! let mut subsys = InputSubsystem::new();
//! let dev_id = subsys.register_device(b"keyboard0", &caps)?;
//! let hnd_id = subsys.register_handler(b"kbd_handler", handler_caps)?;
//! subsys.report_event(dev_id, InputEvent::key(KEY_A, 1))?;
//! subsys.report_event(dev_id, InputEvent::syn())?;
//! ```

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of input devices.
const MAX_INPUT_DEVICES: usize = 16;

/// Maximum number of input handlers.
const MAX_INPUT_HANDLERS: usize = 8;

/// Size of the per-device event ring buffer.
const EVENT_BUFFER_SIZE: usize = 64;

/// Maximum name length for devices and handlers.
const MAX_NAME_LEN: usize = 32;

/// Maximum number of absolute axes tracked per device.
const MAX_ABS_AXES: usize = 16;

/// Number of u64 words needed for a 256-bit bitmask.
const BITS_WORDS: usize = 4;

// -------------------------------------------------------------------
// InputEventType
// -------------------------------------------------------------------

/// Top-level input event type codes.
///
/// Modelled after the Linux `EV_*` constants from `<linux/input.h>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum InputEventType {
    /// Synchronisation event (marks the end of an event packet).
    Syn = 0x00,
    /// Key/button press or release.
    Key = 0x01,
    /// Relative axis movement (e.g., mouse delta).
    Rel = 0x02,
    /// Absolute axis position (e.g., touchscreen coordinate).
    Abs = 0x03,
    /// Miscellaneous event.
    Misc = 0x04,
    /// Switch event (e.g., lid open/close).
    Switch = 0x05,
    /// LED state change.
    Led = 0x11,
    /// Sound event.
    Sound = 0x12,
    /// Force-feedback effect.
    ForceFeedback = 0x15,
}

impl InputEventType {
    /// Converts a raw `u16` to an [`InputEventType`], returning
    /// `None` for unknown codes.
    pub fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            0x00 => Some(Self::Syn),
            0x01 => Some(Self::Key),
            0x02 => Some(Self::Rel),
            0x03 => Some(Self::Abs),
            0x04 => Some(Self::Misc),
            0x05 => Some(Self::Switch),
            0x11 => Some(Self::Led),
            0x12 => Some(Self::Sound),
            0x15 => Some(Self::ForceFeedback),
            _ => None,
        }
    }
}

// -------------------------------------------------------------------
// Well-known key/button codes
// -------------------------------------------------------------------

/// Synchronisation report code.
pub const SYN_REPORT: u16 = 0;

/// Relative X axis.
pub const REL_X: u16 = 0x00;
/// Relative Y axis.
pub const REL_Y: u16 = 0x01;
/// Relative wheel (scroll).
pub const REL_WHEEL: u16 = 0x08;

/// Absolute X axis.
pub const ABS_X: u16 = 0x00;
/// Absolute Y axis.
pub const ABS_Y: u16 = 0x01;
/// Absolute pressure axis.
pub const ABS_PRESSURE: u16 = 0x18;

/// Key code: A (example).
pub const KEY_A: u16 = 30;
/// Key code: Enter.
pub const KEY_ENTER: u16 = 28;
/// Key code: Escape.
pub const KEY_ESC: u16 = 1;

/// Left mouse button.
pub const BTN_LEFT: u16 = 0x110;
/// Right mouse button.
pub const BTN_RIGHT: u16 = 0x111;
/// Middle mouse button.
pub const BTN_MIDDLE: u16 = 0x112;

// -------------------------------------------------------------------
// InputEvent
// -------------------------------------------------------------------

/// A single input event.
///
/// Combines an event type, type-specific code, and a signed value.
/// For key events, `value` is 1 (press), 0 (release), or 2 (repeat).
/// For relative events, `value` is the delta. For absolute events,
/// `value` is the absolute position.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct InputEvent {
    /// Timestamp in nanoseconds (filled by the subsystem).
    pub timestamp_ns: u64,
    /// Event type (EV_SYN, EV_KEY, EV_REL, EV_ABS, ...).
    pub event_type: u16,
    /// Type-specific event code (e.g., KEY_A, REL_X, ABS_Y).
    pub code: u16,
    /// Event value.
    pub value: i32,
}

impl InputEvent {
    /// Creates a key event.
    pub const fn key(code: u16, value: i32) -> Self {
        Self {
            timestamp_ns: 0,
            event_type: InputEventType::Key as u16,
            code,
            value,
        }
    }

    /// Creates a relative-axis event.
    pub const fn rel(code: u16, value: i32) -> Self {
        Self {
            timestamp_ns: 0,
            event_type: InputEventType::Rel as u16,
            code,
            value,
        }
    }

    /// Creates an absolute-axis event.
    pub const fn abs(code: u16, value: i32) -> Self {
        Self {
            timestamp_ns: 0,
            event_type: InputEventType::Abs as u16,
            code,
            value,
        }
    }

    /// Creates a SYN_REPORT event (packet boundary).
    pub const fn syn() -> Self {
        Self {
            timestamp_ns: 0,
            event_type: InputEventType::Syn as u16,
            code: SYN_REPORT,
            value: 0,
        }
    }

    /// Returns the parsed [`InputEventType`], or `None` if unknown.
    pub fn parsed_type(&self) -> Option<InputEventType> {
        InputEventType::from_raw(self.event_type)
    }
}

// -------------------------------------------------------------------
// EventRingBuffer
// -------------------------------------------------------------------

/// Fixed-size ring buffer for input events.
///
/// Events are appended at the write cursor and consumed from the
/// read cursor. When full, the oldest event is silently dropped.
struct EventRingBuffer {
    /// Event storage.
    events: [InputEvent; EVENT_BUFFER_SIZE],
    /// Read index.
    read: usize,
    /// Write index.
    write: usize,
    /// Number of events currently buffered.
    count: usize,
    /// Total number of events dropped due to overflow.
    drops: u64,
}

impl EventRingBuffer {
    /// Creates an empty ring buffer.
    const fn new() -> Self {
        Self {
            events: [InputEvent {
                timestamp_ns: 0,
                event_type: 0,
                code: 0,
                value: 0,
            }; EVENT_BUFFER_SIZE],
            read: 0,
            write: 0,
            count: 0,
            drops: 0,
        }
    }

    /// Pushes an event into the buffer.
    ///
    /// If the buffer is full, the oldest event is overwritten and
    /// the drop counter is incremented.
    fn push(&mut self, event: InputEvent) {
        if self.count == EVENT_BUFFER_SIZE {
            // Overwrite oldest: advance read pointer.
            self.read = (self.read + 1) % EVENT_BUFFER_SIZE;
            self.drops += 1;
        } else {
            self.count += 1;
        }
        self.events[self.write] = event;
        self.write = (self.write + 1) % EVENT_BUFFER_SIZE;
    }

    /// Pops the oldest event from the buffer.
    fn pop(&mut self) -> Option<InputEvent> {
        if self.count == 0 {
            return None;
        }
        let event = self.events[self.read];
        self.read = (self.read + 1) % EVENT_BUFFER_SIZE;
        self.count -= 1;
        Some(event)
    }

    /// Returns the number of buffered events.
    fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the buffer is empty.
    fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Clears all buffered events.
    fn clear(&mut self) {
        self.read = 0;
        self.write = 0;
        self.count = 0;
    }
}

// -------------------------------------------------------------------
// InputDeviceCaps (capability bitmasks)
// -------------------------------------------------------------------

/// Capability bitmasks for an input device.
///
/// Each bitmask describes which event codes the device can produce
/// for a given event type. The bitmasks are stored as arrays of
/// `u64` words, supporting up to 256 codes per category.
#[derive(Debug, Clone, Copy)]
pub struct InputDeviceCaps {
    /// Bitmask of supported event types (indexed by `InputEventType`).
    pub ev_bits: u32,
    /// Bitmask of supported key/button codes (256 bits).
    pub key_bits: [u64; BITS_WORDS],
    /// Bitmask of supported relative-axis codes (256 bits).
    pub rel_bits: [u64; BITS_WORDS],
    /// Bitmask of supported absolute-axis codes (256 bits).
    pub abs_bits: [u64; BITS_WORDS],
    /// Bitmask of supported misc codes (256 bits).
    pub misc_bits: [u64; BITS_WORDS],
    /// Bitmask of supported LED codes (256 bits).
    pub led_bits: [u64; BITS_WORDS],
}

impl Default for InputDeviceCaps {
    fn default() -> Self {
        Self::new()
    }
}

impl InputDeviceCaps {
    /// Creates an empty capability set.
    pub const fn new() -> Self {
        Self {
            ev_bits: 0,
            key_bits: [0; BITS_WORDS],
            rel_bits: [0; BITS_WORDS],
            abs_bits: [0; BITS_WORDS],
            misc_bits: [0; BITS_WORDS],
            led_bits: [0; BITS_WORDS],
        }
    }

    /// Sets a bit in the event-type bitmask.
    pub fn set_ev_bit(&mut self, ev: InputEventType) {
        self.ev_bits |= 1 << (ev as u32);
    }

    /// Tests whether an event type is supported.
    pub fn has_ev_bit(&self, ev: InputEventType) -> bool {
        self.ev_bits & (1 << (ev as u32)) != 0
    }

    /// Sets a bit in the key bitmask.
    pub fn set_key_bit(&mut self, code: u16) {
        set_bit(&mut self.key_bits, code);
    }

    /// Tests a bit in the key bitmask.
    pub fn has_key_bit(&self, code: u16) -> bool {
        test_bit(&self.key_bits, code)
    }

    /// Sets a bit in the relative-axis bitmask.
    pub fn set_rel_bit(&mut self, code: u16) {
        set_bit(&mut self.rel_bits, code);
    }

    /// Tests a bit in the relative-axis bitmask.
    pub fn has_rel_bit(&self, code: u16) -> bool {
        test_bit(&self.rel_bits, code)
    }

    /// Sets a bit in the absolute-axis bitmask.
    pub fn set_abs_bit(&mut self, code: u16) {
        set_bit(&mut self.abs_bits, code);
    }

    /// Tests a bit in the absolute-axis bitmask.
    pub fn has_abs_bit(&self, code: u16) -> bool {
        test_bit(&self.abs_bits, code)
    }

    /// Returns `true` if the caps match another set (i.e., there is
    /// at least one overlapping event type).
    pub fn matches(&self, other: &Self) -> bool {
        self.ev_bits & other.ev_bits != 0
    }
}

/// Sets a bit in a 256-bit bitmask (array of 4 `u64`).
fn set_bit(bits: &mut [u64; BITS_WORDS], code: u16) {
    let idx = (code as usize) / 64;
    let bit = (code as usize) % 64;
    if idx < BITS_WORDS {
        bits[idx] |= 1u64 << bit;
    }
}

/// Tests a bit in a 256-bit bitmask.
fn test_bit(bits: &[u64; BITS_WORDS], code: u16) -> bool {
    let idx = (code as usize) / 64;
    let bit = (code as usize) % 64;
    if idx < BITS_WORDS {
        bits[idx] & (1u64 << bit) != 0
    } else {
        false
    }
}

// -------------------------------------------------------------------
// AbsAxisInfo
// -------------------------------------------------------------------

/// Calibration and range information for a single absolute axis.
///
/// Modelled after `struct input_absinfo` from the Linux kernel.
#[derive(Debug, Clone, Copy, Default)]
pub struct AbsAxisInfo {
    /// Current value.
    pub value: i32,
    /// Minimum value.
    pub minimum: i32,
    /// Maximum value.
    pub maximum: i32,
    /// Fuzz (noise threshold).
    pub fuzz: i32,
    /// Flat (dead zone around centre).
    pub flat: i32,
    /// Resolution in units per millimetre.
    pub resolution: i32,
}

// -------------------------------------------------------------------
// InputDevice
// -------------------------------------------------------------------

/// A registered input device.
///
/// Each device has a name, capability set, per-device event ring
/// buffer, and optional grab (exclusive access) state.
pub struct InputDevice {
    /// Device identifier (index in the subsystem).
    pub id: u16,
    /// Human-readable name.
    pub name: [u8; MAX_NAME_LEN],
    /// Valid name length.
    pub name_len: u8,
    /// Capability bitmasks.
    pub caps: InputDeviceCaps,
    /// Per-device event ring buffer.
    buffer: EventRingBuffer,
    /// Absolute-axis info array.
    pub abs_info: [AbsAxisInfo; MAX_ABS_AXES],
    /// Whether this device slot is in use.
    pub in_use: bool,
    /// Handler ID that has grabbed this device (u16::MAX = no grab).
    pub grabbed_by: u16,
    /// Total number of events reported through this device.
    pub event_count: u64,
}

impl InputDevice {
    /// Creates an empty, unused device.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            caps: InputDeviceCaps::new(),
            buffer: EventRingBuffer::new(),
            abs_info: [AbsAxisInfo {
                value: 0,
                minimum: 0,
                maximum: 0,
                fuzz: 0,
                flat: 0,
                resolution: 0,
            }; MAX_ABS_AXES],
            in_use: false,
            grabbed_by: u16::MAX,
            event_count: 0,
        }
    }

    /// Returns `true` if the device is exclusively grabbed.
    pub fn is_grabbed(&self) -> bool {
        self.grabbed_by != u16::MAX
    }

    /// Returns the number of buffered (unread) events.
    pub fn buffered_events(&self) -> usize {
        self.buffer.len()
    }

    /// Returns the number of dropped events.
    pub fn dropped_events(&self) -> u64 {
        self.buffer.drops
    }

    /// Sets the absolute-axis info for a given axis code.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the code exceeds
    /// [`MAX_ABS_AXES`].
    pub fn set_abs_info(&mut self, code: u16, info: AbsAxisInfo) -> Result<()> {
        let idx = code as usize;
        if idx >= MAX_ABS_AXES {
            return Err(Error::InvalidArgument);
        }
        self.abs_info[idx] = info;
        Ok(())
    }

    /// Returns the absolute-axis info for a given code.
    pub fn get_abs_info(&self, code: u16) -> Option<&AbsAxisInfo> {
        let idx = code as usize;
        if idx < MAX_ABS_AXES {
            Some(&self.abs_info[idx])
        } else {
            None
        }
    }
}

// -------------------------------------------------------------------
// InputHandler
// -------------------------------------------------------------------

/// A registered input event handler (consumer).
///
/// Handlers declare a set of event-type capabilities. The subsystem
/// routes events from devices whose caps overlap with the handler's
/// caps. Each handler maintains its own receive buffer.
pub struct InputHandler {
    /// Handler identifier (index in the subsystem).
    pub id: u16,
    /// Human-readable name.
    pub name: [u8; MAX_NAME_LEN],
    /// Valid name length.
    pub name_len: u8,
    /// Capabilities this handler is interested in.
    pub caps: InputDeviceCaps,
    /// Per-handler receive buffer.
    buffer: EventRingBuffer,
    /// Whether this handler slot is in use.
    pub in_use: bool,
    /// Total events received.
    pub event_count: u64,
}

impl InputHandler {
    /// Creates an empty, unused handler.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            caps: InputDeviceCaps::new(),
            buffer: EventRingBuffer::new(),
            in_use: false,
            event_count: 0,
        }
    }

    /// Reads and removes the next event from the handler's buffer.
    pub fn read_event(&mut self) -> Option<InputEvent> {
        self.buffer.pop()
    }

    /// Returns the number of buffered events.
    pub fn pending_events(&self) -> usize {
        self.buffer.len()
    }

    /// Returns `true` if the handler has no pending events.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

// -------------------------------------------------------------------
// InputSubsystem
// -------------------------------------------------------------------

/// Top-level input event manager.
///
/// Manages registered devices and handlers, and routes events from
/// devices to matching handlers (or exclusively to a grabbing
/// handler).
pub struct InputSubsystem {
    /// Registered input devices.
    devices: [InputDevice; MAX_INPUT_DEVICES],
    /// Number of registered devices.
    device_count: usize,
    /// Registered input handlers.
    handlers: [InputHandler; MAX_INPUT_HANDLERS],
    /// Number of registered handlers.
    handler_count: usize,
    /// Global timestamp counter (nanoseconds, set externally).
    pub timestamp_ns: u64,
}

impl Default for InputSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl InputSubsystem {
    /// Creates an empty input subsystem.
    pub const fn new() -> Self {
        Self {
            devices: [const { InputDevice::empty() }; MAX_INPUT_DEVICES],
            device_count: 0,
            handlers: [const { InputHandler::empty() }; MAX_INPUT_HANDLERS],
            handler_count: 0,
            timestamp_ns: 0,
        }
    }

    // ── Device registration ─────────────────────────────────────

    /// Registers a new input device with the given name and
    /// capabilities.
    ///
    /// Returns the device's ID (index).
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the device table is full.
    pub fn register_device(&mut self, name: &[u8], caps: &InputDeviceCaps) -> Result<u16> {
        if self.device_count >= MAX_INPUT_DEVICES {
            return Err(Error::OutOfMemory);
        }

        let idx = self.device_count;
        let dev = &mut self.devices[idx];
        dev.id = idx as u16;

        let copy_len = name.len().min(MAX_NAME_LEN);
        dev.name[..copy_len].copy_from_slice(&name[..copy_len]);
        dev.name_len = copy_len as u8;

        dev.caps = *caps;
        dev.buffer.clear();
        dev.in_use = true;
        dev.grabbed_by = u16::MAX;
        dev.event_count = 0;

        self.device_count += 1;
        Ok(idx as u16)
    }

    /// Unregisters a device by its ID.
    ///
    /// Any grab on this device is released.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the ID is out of range
    /// or the device is not registered.
    pub fn unregister_device(&mut self, dev_id: u16) -> Result<()> {
        let idx = dev_id as usize;
        if idx >= self.device_count || !self.devices[idx].in_use {
            return Err(Error::InvalidArgument);
        }
        self.devices[idx].in_use = false;
        self.devices[idx].grabbed_by = u16::MAX;
        self.devices[idx].buffer.clear();
        Ok(())
    }

    /// Returns a shared reference to a registered device.
    pub fn get_device(&self, dev_id: u16) -> Option<&InputDevice> {
        let idx = dev_id as usize;
        if idx < self.device_count && self.devices[idx].in_use {
            Some(&self.devices[idx])
        } else {
            None
        }
    }

    // ── Handler registration ────────────────────────────────────

    /// Registers a new input handler with the given name and
    /// capabilities.
    ///
    /// Returns the handler's ID (index).
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the handler table is full.
    pub fn register_handler(&mut self, name: &[u8], caps: InputDeviceCaps) -> Result<u16> {
        if self.handler_count >= MAX_INPUT_HANDLERS {
            return Err(Error::OutOfMemory);
        }

        let idx = self.handler_count;
        let hnd = &mut self.handlers[idx];
        hnd.id = idx as u16;

        let copy_len = name.len().min(MAX_NAME_LEN);
        hnd.name[..copy_len].copy_from_slice(&name[..copy_len]);
        hnd.name_len = copy_len as u8;

        hnd.caps = caps;
        hnd.buffer.clear();
        hnd.in_use = true;
        hnd.event_count = 0;

        self.handler_count += 1;
        Ok(idx as u16)
    }

    /// Unregisters a handler by its ID.
    ///
    /// Any devices grabbed by this handler are released.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the ID is out of range
    /// or the handler is not registered.
    pub fn unregister_handler(&mut self, hnd_id: u16) -> Result<()> {
        let idx = hnd_id as usize;
        if idx >= self.handler_count || !self.handlers[idx].in_use {
            return Err(Error::InvalidArgument);
        }

        // Release any devices grabbed by this handler.
        for dev in &mut self.devices[..self.device_count] {
            if dev.in_use && dev.grabbed_by == hnd_id {
                dev.grabbed_by = u16::MAX;
            }
        }

        self.handlers[idx].in_use = false;
        self.handlers[idx].buffer.clear();
        Ok(())
    }

    /// Returns a mutable reference to a registered handler.
    pub fn get_handler_mut(&mut self, hnd_id: u16) -> Option<&mut InputHandler> {
        let idx = hnd_id as usize;
        if idx < self.handler_count && self.handlers[idx].in_use {
            Some(&mut self.handlers[idx])
        } else {
            None
        }
    }

    // ── Event reporting ─────────────────────────────────────────

    /// Reports an event from a device.
    ///
    /// The event is timestamped, pushed into the device's buffer,
    /// and dispatched to all matching (or grabbing) handlers.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the device ID is
    /// invalid.
    pub fn report_event(&mut self, dev_id: u16, mut event: InputEvent) -> Result<()> {
        let idx = dev_id as usize;
        if idx >= self.device_count || !self.devices[idx].in_use {
            return Err(Error::InvalidArgument);
        }

        // Timestamp the event.
        event.timestamp_ns = self.timestamp_ns;

        // Update absolute axis state if applicable.
        if event.event_type == InputEventType::Abs as u16 {
            let axis = event.code as usize;
            if axis < MAX_ABS_AXES {
                self.devices[idx].abs_info[axis].value = event.value;
            }
        }

        // Push into the device's ring buffer.
        self.devices[idx].buffer.push(event);
        self.devices[idx].event_count += 1;

        // Dispatch to handlers.
        let grabbed_by = self.devices[idx].grabbed_by;
        let dev_caps = self.devices[idx].caps;

        if grabbed_by != u16::MAX {
            // Exclusive grab: only deliver to the grabbing handler.
            let hnd_idx = grabbed_by as usize;
            if hnd_idx < self.handler_count && self.handlers[hnd_idx].in_use {
                self.handlers[hnd_idx].buffer.push(event);
                self.handlers[hnd_idx].event_count += 1;
            }
        } else {
            // Broadcast to all matching handlers.
            for hnd in &mut self.handlers[..self.handler_count] {
                if hnd.in_use && dev_caps.matches(&hnd.caps) {
                    hnd.buffer.push(event);
                    hnd.event_count += 1;
                }
            }
        }

        Ok(())
    }

    /// Reports a batch of events from a device, ending with an
    /// automatic SYN_REPORT.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the device ID is
    /// invalid.
    pub fn report_events(&mut self, dev_id: u16, events: &[InputEvent]) -> Result<()> {
        for &event in events {
            self.report_event(dev_id, event)?;
        }
        self.report_event(dev_id, InputEvent::syn())?;
        Ok(())
    }

    /// Reads and removes the oldest event from a device's buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the device ID is
    /// invalid.
    pub fn read_device_event(&mut self, dev_id: u16) -> Result<Option<InputEvent>> {
        let idx = dev_id as usize;
        if idx >= self.device_count || !self.devices[idx].in_use {
            return Err(Error::InvalidArgument);
        }
        Ok(self.devices[idx].buffer.pop())
    }

    // ── Grab / release ──────────────────────────────────────────

    /// Grabs a device for exclusive event delivery to a handler.
    ///
    /// While grabbed, only the grabbing handler receives events
    /// from this device. Other handlers are bypassed.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if either ID is out of range.
    /// - [`Error::Busy`] if the device is already grabbed.
    pub fn grab(&mut self, dev_id: u16, hnd_id: u16) -> Result<()> {
        let dev_idx = dev_id as usize;
        if dev_idx >= self.device_count || !self.devices[dev_idx].in_use {
            return Err(Error::InvalidArgument);
        }
        let hnd_idx = hnd_id as usize;
        if hnd_idx >= self.handler_count || !self.handlers[hnd_idx].in_use {
            return Err(Error::InvalidArgument);
        }
        if self.devices[dev_idx].grabbed_by != u16::MAX {
            return Err(Error::Busy);
        }
        self.devices[dev_idx].grabbed_by = hnd_id;
        Ok(())
    }

    /// Releases a device grab.
    ///
    /// The handler must be the one that currently holds the grab.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the device ID is invalid.
    /// - [`Error::PermissionDenied`] if `hnd_id` does not match
    ///   the current grabber.
    pub fn release(&mut self, dev_id: u16, hnd_id: u16) -> Result<()> {
        let dev_idx = dev_id as usize;
        if dev_idx >= self.device_count || !self.devices[dev_idx].in_use {
            return Err(Error::InvalidArgument);
        }
        if self.devices[dev_idx].grabbed_by != hnd_id {
            return Err(Error::PermissionDenied);
        }
        self.devices[dev_idx].grabbed_by = u16::MAX;
        Ok(())
    }

    // ── Query ───────────────────────────────────────────────────

    /// Returns the number of registered devices.
    pub fn device_count(&self) -> usize {
        self.device_count
    }

    /// Returns the number of registered handlers.
    pub fn handler_count(&self) -> usize {
        self.handler_count
    }

    /// Updates the global timestamp (nanoseconds).
    pub fn set_timestamp(&mut self, ns: u64) {
        self.timestamp_ns = ns;
    }

    /// Flushes all events from a device's buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the device ID is
    /// invalid.
    pub fn flush_device(&mut self, dev_id: u16) -> Result<()> {
        let idx = dev_id as usize;
        if idx >= self.device_count || !self.devices[idx].in_use {
            return Err(Error::InvalidArgument);
        }
        self.devices[idx].buffer.clear();
        Ok(())
    }

    /// Flushes all events from a handler's buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the handler ID is
    /// invalid.
    pub fn flush_handler(&mut self, hnd_id: u16) -> Result<()> {
        let idx = hnd_id as usize;
        if idx >= self.handler_count || !self.handlers[idx].in_use {
            return Err(Error::InvalidArgument);
        }
        self.handlers[idx].buffer.clear();
        Ok(())
    }
}
