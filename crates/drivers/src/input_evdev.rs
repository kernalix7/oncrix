// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Input event device layer (evdev).
//!
//! Provides a generic input event abstraction modelled after the Linux
//! `evdev` interface (`/dev/input/eventN`). Input devices report typed
//! events into a per-device ring buffer; registered clients read events
//! in FIFO order. An exclusive "grab" allows one client to consume all
//! events without them being delivered to other clients.
//!
//! # Architecture
//!
//! - [`InputEventType`] — top-level event classification (10 types)
//! - [`InputEvent`] — a single event with type, code, value, timestamp
//! - [`InputDeviceInfo`] — vendor/product identity of a device
//! - [`InputDevice`] — a registered device with capability bitmask and
//!   128-entry event ring buffer
//! - [`EvdevClient`] — a process-side client with its own 64-entry buffer
//! - [`InputSubsystem`] — coordinates up to 16 devices and 32 clients
//!
//! # Usage
//!
//! ```ignore
//! let mut subsys = InputSubsystem::new();
//! let dev_id = subsys.register_device(b"keyboard0", 0x0001, 0x0002)?;
//! let client_id = subsys.open_client(dev_id)?;
//! subsys.report_key(dev_id, 0x001E, 1)?;  // KEY_A pressed
//! subsys.report_syn(dev_id)?;
//! let evt = subsys.read_event(client_id)?;
//! ```
//!
//! Reference: Linux `include/uapi/linux/input.h`,
//!            `drivers/input/evdev.c`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of input devices.
const MAX_DEVICES: usize = 16;

/// Maximum number of evdev clients.
const MAX_CLIENTS: usize = 32;

/// Size of the per-device event ring buffer.
const DEVICE_RING_SIZE: usize = 128;

/// Size of the per-client event buffer.
const CLIENT_BUF_SIZE: usize = 64;

/// Maximum device name length.
const DEVICE_NAME_LEN: usize = 64;

// ---------------------------------------------------------------------------
// InputEventType
// ---------------------------------------------------------------------------

/// Top-level input event type, corresponding to Linux `EV_*` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum InputEventType {
    /// Synchronization event — marks end of event packet.
    Syn = 0x00,
    /// Key or button press/release.
    Key = 0x01,
    /// Relative axis movement (mouse delta, scroll).
    Rel = 0x02,
    /// Absolute axis position (touchscreen, joystick).
    Abs = 0x03,
    /// Miscellaneous event (scan code, etc.).
    Msc = 0x04,
    /// Binary switch state (lid, tablet mode).
    Sw = 0x05,
    /// LED state change.
    Led = 0x11,
    /// Sound output request.
    Snd = 0x12,
    /// Auto-repeat configuration.
    Rep = 0x14,
    /// Force-feedback upload.
    Ff = 0x15,
}

impl Default for InputEventType {
    fn default() -> Self {
        Self::Syn
    }
}

impl InputEventType {
    /// Converts a raw u16 type code to `InputEventType`.
    pub fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            0x00 => Some(Self::Syn),
            0x01 => Some(Self::Key),
            0x02 => Some(Self::Rel),
            0x03 => Some(Self::Abs),
            0x04 => Some(Self::Msc),
            0x05 => Some(Self::Sw),
            0x11 => Some(Self::Led),
            0x12 => Some(Self::Snd),
            0x14 => Some(Self::Rep),
            0x15 => Some(Self::Ff),
            _ => None,
        }
    }

    /// Returns the raw u16 type code.
    pub fn raw(self) -> u16 {
        self as u16
    }
}

// ---------------------------------------------------------------------------
// InputEvent
// ---------------------------------------------------------------------------

/// A single input event.
///
/// The event carries a type, a type-specific code (e.g., key scan code or
/// axis index), a signed value (e.g., 0/1 for key up/down, delta for REL),
/// and a monotonic timestamp tick.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct InputEvent {
    /// Event category.
    pub event_type: InputEventType,
    /// Type-specific event code.
    pub code: u16,
    /// Signed event value.
    pub value: i32,
    /// Monotonic tick at which the event occurred.
    pub timestamp_tick: u64,
}

impl InputEvent {
    /// Creates a new event.
    pub const fn new(event_type: InputEventType, code: u16, value: i32, tick: u64) -> Self {
        Self {
            event_type,
            code,
            value,
            timestamp_tick: tick,
        }
    }

    /// Creates a SYN_REPORT event (end of event packet).
    pub const fn syn(tick: u64) -> Self {
        Self::new(InputEventType::Syn, 0, 0, tick)
    }

    /// Creates a key event (press: value=1, release: value=0, repeat: value=2).
    pub const fn key(code: u16, value: i32, tick: u64) -> Self {
        Self::new(InputEventType::Key, code, value, tick)
    }

    /// Creates a relative axis event.
    pub const fn rel(axis: u16, delta: i32, tick: u64) -> Self {
        Self::new(InputEventType::Rel, axis, delta, tick)
    }

    /// Creates an absolute axis event.
    pub const fn abs(axis: u16, position: i32, tick: u64) -> Self {
        Self::new(InputEventType::Abs, axis, position, tick)
    }
}

// ---------------------------------------------------------------------------
// InputDeviceInfo
// ---------------------------------------------------------------------------

/// Hardware identity information for an input device.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct InputDeviceInfo {
    /// Bus type (e.g., 0x03 = USB, 0x11 = Bluetooth, 0x19 = virtual).
    pub bustype: u16,
    /// USB Vendor ID or equivalent.
    pub vendor: u16,
    /// USB Product ID or equivalent.
    pub product: u16,
    /// Device version.
    pub version: u16,
}

impl InputDeviceInfo {
    /// Creates device identity information.
    pub const fn new(bustype: u16, vendor: u16, product: u16, version: u16) -> Self {
        Self {
            bustype,
            vendor,
            product,
            version,
        }
    }
}

// ---------------------------------------------------------------------------
// EventRing
// ---------------------------------------------------------------------------

/// Fixed-size power-of-2 ring buffer for input events.
struct EventRing<const N: usize> {
    buf: [InputEvent; N],
    head: usize,
    tail: usize,
    count: usize,
}

impl<const N: usize> EventRing<N> {
    const fn new() -> Self {
        Self {
            buf: [InputEvent {
                event_type: InputEventType::Syn,
                code: 0,
                value: 0,
                timestamp_tick: 0,
            }; N],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    fn push(&mut self, event: InputEvent) -> Result<()> {
        if self.count >= N {
            return Err(Error::OutOfMemory);
        }
        self.buf[self.tail] = event;
        self.tail = (self.tail + 1) % N;
        self.count += 1;
        Ok(())
    }

    fn pop(&mut self) -> Option<InputEvent> {
        if self.count == 0 {
            return None;
        }
        let evt = self.buf[self.head];
        self.head = (self.head + 1) % N;
        self.count -= 1;
        Some(evt)
    }

    fn is_empty(&self) -> bool {
        self.count == 0
    }

    fn len(&self) -> usize {
        self.count
    }

    fn flush(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.count = 0;
    }
}

// ---------------------------------------------------------------------------
// InputDevice
// ---------------------------------------------------------------------------

/// A registered input device.
///
/// Each device has a name, hardware identity information, capability
/// bitmask (which event types it can generate), and a 128-entry ring
/// buffer for pending events.
pub struct InputDevice {
    /// Human-readable device name.
    pub name: [u8; DEVICE_NAME_LEN],
    /// Hardware identity.
    pub info: InputDeviceInfo,
    /// Capability bitmask — bit N is set if `InputEventType` with raw=N is supported.
    pub capabilities: u32,
    /// Per-device event ring buffer.
    ring: EventRing<DEVICE_RING_SIZE>,
    /// Whether this device slot is registered.
    pub registered: bool,
    /// ID of the client that has grabbed this device (0 = no grab).
    pub grab_client: u32,
    /// Unique device ID.
    pub id: u32,
}

impl Default for InputDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl InputDevice {
    /// Creates an empty, unregistered device slot.
    pub const fn new() -> Self {
        Self {
            name: [0u8; DEVICE_NAME_LEN],
            info: InputDeviceInfo::new(0, 0, 0, 0),
            capabilities: 0,
            ring: EventRing::new(),
            registered: false,
            grab_client: 0,
            id: 0,
        }
    }

    /// Returns `true` if the device has events pending.
    pub fn has_events(&self) -> bool {
        !self.ring.is_empty()
    }

    /// Returns the number of pending events.
    pub fn pending_count(&self) -> usize {
        self.ring.len()
    }

    /// Pushes an event into the device ring buffer.
    fn push_event(&mut self, event: InputEvent) -> Result<()> {
        self.ring.push(event)
    }

    /// Pops the oldest event from the device ring buffer.
    fn pop_event(&mut self) -> Option<InputEvent> {
        self.ring.pop()
    }

    /// Flushes all events from the device ring buffer.
    pub fn flush(&mut self) {
        self.ring.flush();
    }

    /// Returns `true` if this device supports the given event type.
    pub fn supports(&self, event_type: InputEventType) -> bool {
        let bit = event_type.raw() as u32;
        if bit >= 32 {
            return false;
        }
        self.capabilities & (1 << bit) != 0
    }

    /// Adds an event type to the capability bitmask.
    pub fn add_capability(&mut self, event_type: InputEventType) {
        let bit = event_type.raw() as u32;
        if bit < 32 {
            self.capabilities |= 1 << bit;
        }
    }
}

// ---------------------------------------------------------------------------
// EvdevClient
// ---------------------------------------------------------------------------

/// A client reading events from a specific input device.
///
/// Clients receive copies of events from the device they are attached to.
/// If the device is grabbed by another client, this client receives no events.
pub struct EvdevClient {
    /// Unique client ID.
    pub client_id: u32,
    /// Device this client is reading from.
    pub device_id: u32,
    /// Per-client event buffer.
    event_buf: EventRing<CLIENT_BUF_SIZE>,
    /// Whether this client slot is in use.
    pub active: bool,
    /// Whether this client holds the exclusive grab.
    pub has_grab: bool,
}

impl Default for EvdevClient {
    fn default() -> Self {
        Self::new()
    }
}

impl EvdevClient {
    /// Creates an inactive client slot.
    pub const fn new() -> Self {
        Self {
            client_id: 0,
            device_id: 0,
            event_buf: EventRing::new(),
            active: false,
            has_grab: false,
        }
    }

    /// Delivers an event into this client's buffer.
    pub fn deliver(&mut self, event: InputEvent) -> Result<()> {
        self.event_buf.push(event)
    }

    /// Reads the oldest pending event from this client's buffer.
    pub fn read(&mut self) -> Option<InputEvent> {
        self.event_buf.pop()
    }

    /// Returns `true` if this client has pending events.
    pub fn has_events(&self) -> bool {
        !self.event_buf.is_empty()
    }

    /// Returns the number of pending events.
    pub fn pending_count(&self) -> usize {
        self.event_buf.len()
    }

    /// Flushes all pending events.
    pub fn flush(&mut self) {
        self.event_buf.flush();
    }
}

// ---------------------------------------------------------------------------
// InputSubsystem
// ---------------------------------------------------------------------------

/// The central input event coordinator.
///
/// Manages up to [`MAX_DEVICES`] input devices and [`MAX_CLIENTS`] evdev
/// clients. Events reported to a device are dispatched to all attached
/// clients (unless one client holds an exclusive grab).
pub struct InputSubsystem {
    /// Registered devices.
    devices: [InputDevice; MAX_DEVICES],
    /// Registered clients.
    clients: [EvdevClient; MAX_CLIENTS],
    /// Next device ID counter.
    next_device_id: u32,
    /// Next client ID counter.
    next_client_id: u32,
    /// Current monotonic tick (updated by caller on each event).
    current_tick: u64,
}

impl Default for InputSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl InputSubsystem {
    /// Creates an empty input subsystem.
    pub fn new() -> Self {
        Self {
            devices: [const { InputDevice::new() }; MAX_DEVICES],
            clients: [const { EvdevClient::new() }; MAX_CLIENTS],
            next_device_id: 1,
            next_client_id: 1,
            current_tick: 0,
        }
    }

    // ── Device management ─────────────────────────────────────────────

    /// Registers a new input device.
    ///
    /// `name` is a short ASCII name (e.g., `b"keyboard0"`).
    /// `capabilities` is a bitmask of supported [`InputEventType`]s.
    /// Returns the allocated device ID.
    pub fn register_device(
        &mut self,
        name: &[u8],
        info: InputDeviceInfo,
        capabilities: u32,
    ) -> Result<u32> {
        let slot = self.devices.iter().position(|d| !d.registered);
        let idx = slot.ok_or(Error::OutOfMemory)?;

        let dev = &mut self.devices[idx];
        let copy_len = name.len().min(DEVICE_NAME_LEN - 1);
        dev.name[..copy_len].copy_from_slice(&name[..copy_len]);
        dev.info = info;
        dev.capabilities = capabilities;
        dev.registered = true;
        dev.grab_client = 0;
        dev.id = self.next_device_id;
        self.next_device_id = self.next_device_id.wrapping_add(1);
        Ok(dev.id)
    }

    /// Unregisters a device by ID.
    ///
    /// All clients attached to this device are flushed and closed.
    pub fn unregister_device(&mut self, device_id: u32) -> Result<()> {
        let dev_idx = self.find_device_idx(device_id)?;
        // Flush and detach all clients for this device
        for i in 0..MAX_CLIENTS {
            if self.clients[i].active && self.clients[i].device_id == device_id {
                self.clients[i].flush();
                self.clients[i] = EvdevClient::new();
            }
        }
        self.devices[dev_idx] = InputDevice::new();
        Ok(())
    }

    // ── Client management ─────────────────────────────────────────────

    /// Opens a client for the given device, returning the client ID.
    pub fn open_client(&mut self, device_id: u32) -> Result<u32> {
        // Verify device exists
        let _dev_idx = self.find_device_idx(device_id)?;

        let slot = self.clients.iter().position(|c| !c.active);
        let idx = slot.ok_or(Error::OutOfMemory)?;

        let client = &mut self.clients[idx];
        client.device_id = device_id;
        client.active = true;
        client.has_grab = false;
        client.client_id = self.next_client_id;
        self.next_client_id = self.next_client_id.wrapping_add(1);
        Ok(client.client_id)
    }

    /// Closes and removes a client by ID.
    pub fn close_client(&mut self, client_id: u32) -> Result<()> {
        let idx = self.find_client_idx(client_id)?;
        let device_id = self.clients[idx].device_id;

        // Release grab if held
        if self.clients[idx].has_grab {
            if let Ok(dev_idx) = self.find_device_idx(device_id) {
                self.devices[dev_idx].grab_client = 0;
            }
        }
        self.clients[idx] = EvdevClient::new();
        Ok(())
    }

    // ── Grab support ──────────────────────────────────────────────────

    /// Grants exclusive grab of a device to a client.
    ///
    /// While grabbed, only the grabbing client receives events.
    pub fn grab(&mut self, client_id: u32) -> Result<()> {
        let cli_idx = self.find_client_idx(client_id)?;
        let device_id = self.clients[cli_idx].device_id;
        let dev_idx = self.find_device_idx(device_id)?;

        if self.devices[dev_idx].grab_client != 0 {
            return Err(Error::Busy);
        }
        self.devices[dev_idx].grab_client = client_id;
        self.clients[cli_idx].has_grab = true;
        Ok(())
    }

    /// Releases the exclusive grab held by a client.
    pub fn ungrab(&mut self, client_id: u32) -> Result<()> {
        let cli_idx = self.find_client_idx(client_id)?;
        if !self.clients[cli_idx].has_grab {
            return Err(Error::InvalidArgument);
        }
        let device_id = self.clients[cli_idx].device_id;
        let dev_idx = self.find_device_idx(device_id)?;
        self.devices[dev_idx].grab_client = 0;
        self.clients[cli_idx].has_grab = false;
        Ok(())
    }

    // ── Event reporting ───────────────────────────────────────────────

    /// Updates the current monotonic tick.
    pub fn set_tick(&mut self, tick: u64) {
        self.current_tick = tick;
    }

    /// Reports a generic event from the given device.
    ///
    /// The event is pushed to the device ring and delivered to eligible clients.
    pub fn report_event(
        &mut self,
        device_id: u32,
        event_type: InputEventType,
        code: u16,
        value: i32,
    ) -> Result<()> {
        let event = InputEvent::new(event_type, code, value, self.current_tick);
        let dev_idx = self.find_device_idx(device_id)?;

        self.devices[dev_idx].push_event(event)?;
        let grab_client = self.devices[dev_idx].grab_client;

        // Deliver to clients
        for i in 0..MAX_CLIENTS {
            if !self.clients[i].active || self.clients[i].device_id != device_id {
                continue;
            }
            // If grabbed, only deliver to the grabbing client
            if grab_client != 0 && self.clients[i].client_id != grab_client {
                continue;
            }
            // Silently drop on client buffer full — do not propagate error
            let _ = self.clients[i].deliver(event);
        }
        Ok(())
    }

    /// Reports a key event (press/release/repeat).
    pub fn report_key(&mut self, device_id: u32, key_code: u16, value: i32) -> Result<()> {
        self.report_event(device_id, InputEventType::Key, key_code, value)
    }

    /// Reports a relative axis movement.
    pub fn report_rel(&mut self, device_id: u32, axis: u16, delta: i32) -> Result<()> {
        self.report_event(device_id, InputEventType::Rel, axis, delta)
    }

    /// Reports an absolute axis position.
    pub fn report_abs(&mut self, device_id: u32, axis: u16, position: i32) -> Result<()> {
        self.report_event(device_id, InputEventType::Abs, axis, position)
    }

    /// Reports a SYN_REPORT event, finalizing an event packet.
    pub fn report_syn(&mut self, device_id: u32) -> Result<()> {
        self.report_event(device_id, InputEventType::Syn, 0, 0)
    }

    // ── Event reading ─────────────────────────────────────────────────

    /// Reads the oldest event from a client's buffer.
    ///
    /// Returns `Err(WouldBlock)` if no events are pending.
    pub fn read_event(&mut self, client_id: u32) -> Result<InputEvent> {
        let idx = self.find_client_idx(client_id)?;
        self.clients[idx].read().ok_or(Error::WouldBlock)
    }

    /// Flushes all pending events from a client's buffer.
    pub fn flush_client(&mut self, client_id: u32) -> Result<()> {
        let idx = self.find_client_idx(client_id)?;
        self.clients[idx].flush();
        Ok(())
    }

    // ── Query ─────────────────────────────────────────────────────────

    /// Returns the [`InputDeviceInfo`] for the given device.
    pub fn device_info(&self, device_id: u32) -> Result<InputDeviceInfo> {
        let idx = self.find_device_idx_ref(device_id)?;
        Ok(self.devices[idx].info)
    }

    /// Returns the capability bitmask for the given device.
    pub fn device_capabilities(&self, device_id: u32) -> Result<u32> {
        let idx = self.find_device_idx_ref(device_id)?;
        Ok(self.devices[idx].capabilities)
    }

    /// Returns the number of pending events for a client.
    pub fn client_pending(&self, client_id: u32) -> Result<usize> {
        let idx = self.find_client_idx_ref(client_id)?;
        Ok(self.clients[idx].pending_count())
    }

    /// Returns the number of registered devices.
    pub fn device_count(&self) -> usize {
        self.devices.iter().filter(|d| d.registered).count()
    }

    /// Returns the number of active clients.
    pub fn client_count(&self) -> usize {
        self.clients.iter().filter(|c| c.active).count()
    }

    // ── Internal helpers ──────────────────────────────────────────────

    fn find_device_idx(&mut self, device_id: u32) -> Result<usize> {
        self.devices
            .iter()
            .position(|d| d.registered && d.id == device_id)
            .ok_or(Error::NotFound)
    }

    fn find_device_idx_ref(&self, device_id: u32) -> Result<usize> {
        self.devices
            .iter()
            .position(|d| d.registered && d.id == device_id)
            .ok_or(Error::NotFound)
    }

    fn find_client_idx(&mut self, client_id: u32) -> Result<usize> {
        self.clients
            .iter()
            .position(|c| c.active && c.client_id == client_id)
            .ok_or(Error::NotFound)
    }

    fn find_client_idx_ref(&self, client_id: u32) -> Result<usize> {
        self.clients
            .iter()
            .position(|c| c.active && c.client_id == client_id)
            .ok_or(Error::NotFound)
    }
}
