// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VirtIO input device driver.
//!
//! Implements a VirtIO input device (device type 18) for receiving
//! input events from virtual keyboards, mice, tablets, and other
//! pointing/typing devices via virtqueues.
//!
//! The driver uses two virtqueues:
//! - **eventq** — device writes input events for the driver to consume
//! - **statusq** — driver writes LED/status updates back to the device
//!
//! # Architecture
//!
//! - **VirtioInputConfig** — device configuration space (`repr(C)`)
//! - **InputEventType** — Linux-compatible event type codes
//! - **InputEvent** — single input event (`repr(C)`)
//! - **VirtioInput** — device instance with event ring buffer
//! - **VirtioInputRegistry** — tracks up to 8 input devices
//!
//! Reference: VirtIO Specification v1.1, Section 5.8 (Input Device).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// VirtIO device type for input devices.
pub const VIRTIO_INPUT_DEVICE_TYPE: u32 = 18;

/// Maximum number of events in the event ring buffer.
pub const EVENT_QUEUE_SIZE: usize = 256;

/// Maximum length of a device name in bytes.
pub const MAX_NAME_LEN: usize = 64;

/// Maximum number of concurrently tracked VirtIO input devices.
pub const MAX_VIRTIO_INPUT_DEVICES: usize = 8;

/// Configuration select value: query device name (string).
pub const VIRTIO_INPUT_CFG_ID_NAME: u8 = 0x01;

/// Configuration select value: query serial number (string).
pub const VIRTIO_INPUT_CFG_ID_SERIAL: u8 = 0x02;

/// Configuration select value: query device ID (struct).
pub const VIRTIO_INPUT_CFG_ID_DEVIDS: u8 = 0x03;

/// Configuration select value: query supported properties.
pub const VIRTIO_INPUT_CFG_PROP_BITS: u8 = 0x10;

/// Configuration select value: query supported event types.
pub const VIRTIO_INPUT_CFG_EV_BITS: u8 = 0x11;

/// Configuration select value: query absolute axis info.
pub const VIRTIO_INPUT_CFG_ABS_INFO: u8 = 0x12;

// ---------------------------------------------------------------------------
// VirtIO Input Configuration Space (Section 5.8.4)
// ---------------------------------------------------------------------------

/// VirtIO input device configuration space.
///
/// The `select` and `subsel` fields are written by the driver to
/// query different aspects of device capabilities. The device then
/// populates `size` and `data` with the response.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VirtioInputConfig {
    /// Configuration query selector.
    pub select: u8,
    /// Configuration query sub-selector.
    pub subsel: u8,
    /// Size of the response data in bytes.
    pub size: u8,
    /// Reserved padding bytes.
    pub reserved: [u8; 5],
    /// Response data (up to 128 bytes).
    pub data: [u8; 128],
}

impl VirtioInputConfig {
    /// Create a zeroed configuration space.
    pub const fn new() -> Self {
        Self {
            select: 0,
            subsel: 0,
            size: 0,
            reserved: [0; 5],
            data: [0; 128],
        }
    }

    /// Set the query selector and sub-selector for a configuration
    /// read. The caller should then read the MMIO config space to
    /// obtain the result.
    pub fn query(&mut self, select: u8, subsel: u8) {
        self.select = select;
        self.subsel = subsel;
        self.size = 0;
    }
}

impl Default for VirtioInputConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Input Event Type
// ---------------------------------------------------------------------------

/// Linux-compatible input event types.
///
/// These values mirror the `EV_*` constants from the Linux input
/// subsystem for interoperability with standard input event tooling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum InputEventType {
    /// Synchronization event (marks end of a batch of events).
    Syn = 0x00,
    /// Key press / release event.
    Key = 0x01,
    /// Relative axis movement (e.g., mouse delta).
    Rel = 0x02,
    /// Absolute axis position (e.g., touchscreen coordinate).
    Abs = 0x03,
    /// Miscellaneous event.
    Msc = 0x04,
    /// LED state change event.
    Led = 0x11,
    /// Auto-repeat parameter event.
    Rep = 0x14,
    /// Force-feedback effect event.
    Ff = 0x15,
}

impl InputEventType {
    /// Try to convert a raw `u16` value to an [`InputEventType`].
    ///
    /// Returns [`None`] for unrecognised event types.
    pub fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            0x00 => Some(Self::Syn),
            0x01 => Some(Self::Key),
            0x02 => Some(Self::Rel),
            0x03 => Some(Self::Abs),
            0x04 => Some(Self::Msc),
            0x11 => Some(Self::Led),
            0x14 => Some(Self::Rep),
            0x15 => Some(Self::Ff),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Input Event (Section 5.8.6)
// ---------------------------------------------------------------------------

/// A single input event from a VirtIO input device.
///
/// This 8-byte structure matches the `virtio_input_event` layout
/// defined in the VirtIO specification.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct InputEvent {
    /// Event type code (e.g., `EV_KEY`, `EV_REL`).
    pub event_type: u16,
    /// Event code (key scancode, axis identifier, etc.).
    pub code: u16,
    /// Event value (key state, axis delta/position, etc.).
    pub value: i32,
}

impl InputEvent {
    /// Create a new input event.
    pub const fn new(event_type: u16, code: u16, value: i32) -> Self {
        Self {
            event_type,
            code,
            value,
        }
    }

    /// Return the parsed event type, if recognised.
    pub fn parsed_type(&self) -> Option<InputEventType> {
        InputEventType::from_raw(self.event_type)
    }

    /// Return `true` if this is a synchronization event.
    pub fn is_syn(&self) -> bool {
        self.event_type == InputEventType::Syn as u16
    }
}

// ---------------------------------------------------------------------------
// VirtIO Input Device
// ---------------------------------------------------------------------------

/// A single VirtIO input device instance.
///
/// Maintains a ring buffer of incoming events and the device
/// configuration space. Events are enqueued by
/// [`process_events`](Self::process_events) and dequeued by
/// [`poll_event`](Self::poll_event).
pub struct VirtioInput {
    /// Device identifier.
    pub device_id: u8,
    /// Device configuration space.
    pub config: VirtioInputConfig,
    /// Ring buffer of pending input events.
    event_queue: [InputEvent; EVENT_QUEUE_SIZE],
    /// Write index into the event ring (next slot to fill).
    event_head: usize,
    /// Read index into the event ring (next slot to consume).
    event_tail: usize,
    /// Number of events currently in the ring.
    event_count: usize,
    /// Status queue for LED/feedback updates (capacity mirrors event
    /// queue). Each entry holds an event to send back to the device.
    status_queue: [InputEvent; EVENT_QUEUE_SIZE],
    /// Number of pending status entries.
    status_count: usize,
    /// Human-readable device name (null-padded).
    pub name: [u8; MAX_NAME_LEN],
    /// Length of the valid portion of `name`.
    name_len: usize,
}

impl VirtioInput {
    /// Create a new VirtIO input device with the given identifier.
    pub fn new(device_id: u8) -> Self {
        Self {
            device_id,
            config: VirtioInputConfig::new(),
            event_queue: [InputEvent::new(0, 0, 0); EVENT_QUEUE_SIZE],
            event_head: 0,
            event_tail: 0,
            event_count: 0,
            status_queue: [InputEvent::new(0, 0, 0); EVENT_QUEUE_SIZE],
            status_count: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
        }
    }

    /// Set the device name from a byte slice.
    ///
    /// The name is truncated to [`MAX_NAME_LEN`] bytes.
    pub fn set_name(&mut self, src: &[u8]) {
        let len = if src.len() > MAX_NAME_LEN {
            MAX_NAME_LEN
        } else {
            src.len()
        };
        self.name[..len].copy_from_slice(&src[..len]);
        if len < MAX_NAME_LEN {
            self.name[len..].fill(0);
        }
        self.name_len = len;
    }

    /// Return the device name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Enqueue a batch of input events received from the device.
    ///
    /// Events that arrive when the ring is full are silently dropped.
    /// Returns the number of events successfully enqueued.
    pub fn process_events(&mut self, events: &[InputEvent]) -> usize {
        let mut accepted = 0;
        for ev in events {
            if self.event_count >= EVENT_QUEUE_SIZE {
                break;
            }
            self.event_queue[self.event_head] = *ev;
            self.event_head = (self.event_head + 1) % EVENT_QUEUE_SIZE;
            self.event_count += 1;
            accepted += 1;
        }
        accepted
    }

    /// Dequeue the next input event, if available.
    ///
    /// Returns [`None`] when the event queue is empty.
    pub fn poll_event(&mut self) -> Option<InputEvent> {
        if self.event_count == 0 {
            return None;
        }
        let ev = self.event_queue[self.event_tail];
        self.event_tail = (self.event_tail + 1) % EVENT_QUEUE_SIZE;
        self.event_count -= 1;
        Some(ev)
    }

    /// Return the number of pending events in the queue.
    pub fn pending_events(&self) -> usize {
        self.event_count
    }

    /// Queue a status/LED update to send back to the device.
    ///
    /// Returns [`Error::OutOfMemory`] if the status queue is full.
    pub fn send_status(&mut self, event: InputEvent) -> Result<()> {
        if self.status_count >= EVENT_QUEUE_SIZE {
            return Err(Error::OutOfMemory);
        }
        self.status_queue[self.status_count] = event;
        self.status_count += 1;
        Ok(())
    }

    /// Return the number of pending status updates.
    pub fn pending_status(&self) -> usize {
        self.status_count
    }

    /// Drain all pending status updates.
    ///
    /// In a real implementation this would submit the events to
    /// the statusq virtqueue. Here it simply clears the buffer.
    pub fn flush_status(&mut self) {
        self.status_count = 0;
    }
}

// ---------------------------------------------------------------------------
// VirtIO Input Registry
// ---------------------------------------------------------------------------

/// Registry of VirtIO input devices.
///
/// Tracks up to [`MAX_VIRTIO_INPUT_DEVICES`] devices and provides
/// registration, removal, lookup, and batch polling operations.
pub struct VirtioInputRegistry {
    /// Fixed-size array of device slots.
    devices: [Option<VirtioInput>; MAX_VIRTIO_INPUT_DEVICES],
    /// Number of currently registered devices.
    count: usize,
}

impl Default for VirtioInputRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioInputRegistry {
    /// Create an empty input device registry.
    pub const fn new() -> Self {
        Self {
            devices: [None, None, None, None, None, None, None, None],
            count: 0,
        }
    }

    /// Register a new VirtIO input device.
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a device with the same
    /// `device_id` is already registered.
    pub fn register(&mut self, device: VirtioInput) -> Result<()> {
        for d in self.devices.iter().flatten() {
            if d.device_id == device.device_id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in &mut self.devices {
            if slot.is_none() {
                *slot = Some(device);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a device by its `device_id`.
    ///
    /// Returns [`Error::NotFound`] if no device with that ID exists.
    pub fn unregister(&mut self, device_id: u8) -> Result<()> {
        for slot in &mut self.devices {
            if let Some(d) = slot {
                if d.device_id == device_id {
                    *slot = None;
                    self.count -= 1;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Find a device by its `device_id`.
    pub fn find(&self, device_id: u8) -> Option<&VirtioInput> {
        self.devices
            .iter()
            .find_map(|slot| slot.as_ref().filter(|d| d.device_id == device_id))
    }

    /// Find a device by its `device_id` (mutable).
    pub fn find_mut(&mut self, device_id: u8) -> Option<&mut VirtioInput> {
        self.devices
            .iter_mut()
            .find_map(|slot| slot.as_mut().filter(|d| d.device_id == device_id))
    }

    /// Poll all registered devices and return the first available event.
    ///
    /// Iterates through devices in slot order and returns the first
    /// event found. Returns [`None`] if no device has a pending event.
    pub fn poll_all(&mut self) -> Option<(u8, InputEvent)> {
        for dev in self.devices.iter_mut().flatten() {
            if let Some(ev) = dev.poll_event() {
                return Some((dev.device_id, ev));
            }
        }
        None
    }

    /// Return the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
