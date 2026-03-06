// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! USB hub event handling.
//!
//! Implements USB hub port event processing following the USB 2.0 specification
//! Chapter 11 and USB 3.2 Chapter 10. Handles port status change detection,
//! port enable/disable/reset, device connect/disconnect events, hub descriptor
//! parsing, and per-port power management.
//!
//! # Architecture
//!
//! - [`HubDescriptor`] — parsed USB hub descriptor.
//! - [`PortStatus`] — status and change bits for one downstream port.
//! - [`HubPort`] — full per-port state machine (power, reset, connection).
//! - [`UsbHub`] — a single USB hub device with up to [`MAX_HUB_PORTS`] ports.
//! - [`HubEventQueue`] — fixed-size queue of pending hub events.
//! - [`HubRegistry`] — manages up to [`MAX_HUBS`] concurrent hubs.
//!
//! # Port state transitions
//!
//! ```text
//! Powered → Disconnected
//!        → Connected → Resetting → Enabled → Suspended
//!                                          → Disabled
//!                                          → Disconnected
//! ```
//!
//! Reference: USB 2.0 Spec §11, USB 3.2 Spec §10,
//!            Linux `drivers/usb/core/hub.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of USB hub devices.
pub const MAX_HUBS: usize = 8;

/// Maximum downstream ports per hub (USB 2.0 limits to 7 external).
pub const MAX_HUB_PORTS: usize = 16;

/// Maximum pending hub events in the queue.
pub const MAX_HUB_EVENTS: usize = 64;

/// USB hub class code.
pub const USB_CLASS_HUB: u8 = 0x09;

/// USB 2.0 hub descriptor type.
pub const USB_DT_HUB: u8 = 0x29;

/// USB 3.x SuperSpeed hub descriptor type.
pub const USB_DT_SS_HUB: u8 = 0x2A;

/// Minimum hub descriptor length in bytes.
pub const HUB_DESC_MIN_LEN: usize = 9;

// Port status bits (USB 2.0 Table 11-21 wPortStatus)
/// Port is connected.
pub const PORT_STAT_CONNECTION: u16 = 1 << 0;
/// Port is enabled.
pub const PORT_STAT_ENABLE: u16 = 1 << 1;
/// Port is suspended.
pub const PORT_STAT_SUSPEND: u16 = 1 << 2;
/// Port has an over-current condition.
pub const PORT_STAT_OVERCURRENT: u16 = 1 << 3;
/// Port is in reset.
pub const PORT_STAT_RESET: u16 = 1 << 4;
/// Port is powered.
pub const PORT_STAT_POWER: u16 = 1 << 8;
/// Port has a low-speed device attached.
pub const PORT_STAT_LOW_SPEED: u16 = 1 << 9;
/// Port has a high-speed device attached.
pub const PORT_STAT_HIGH_SPEED: u16 = 1 << 10;

// Port change bits (USB 2.0 Table 11-22 wPortChange)
/// Connection status has changed.
pub const PORT_CHG_CONNECTION: u16 = 1 << 0;
/// Enable status has changed.
pub const PORT_CHG_ENABLE: u16 = 1 << 1;
/// Suspend status has changed.
pub const PORT_CHG_SUSPEND: u16 = 1 << 2;
/// Over-current status has changed.
pub const PORT_CHG_OVERCURRENT: u16 = 1 << 3;
/// Reset has completed.
pub const PORT_CHG_RESET: u16 = 1 << 4;

// ---------------------------------------------------------------------------
// HubSpeed
// ---------------------------------------------------------------------------

/// Speed classification of a USB hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HubSpeed {
    /// Full-speed (12 Mb/s).
    #[default]
    Full,
    /// High-speed (480 Mb/s).
    High,
    /// SuperSpeed (5 Gb/s+).
    Super,
}

// ---------------------------------------------------------------------------
// PortState
// ---------------------------------------------------------------------------

/// State machine for a single hub port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PortState {
    /// Port has no power.
    #[default]
    Unpowered,
    /// Port is powered but no device is detected.
    Disconnected,
    /// A device has been detected; debouncing in progress.
    Debouncing,
    /// Port is being reset.
    Resetting,
    /// Port is enabled and a device is active.
    Enabled,
    /// Port is suspended (device is in low-power mode).
    Suspended,
    /// Port is disabled (device attached but port is off).
    Disabled,
    /// Port has an over-current condition.
    OverCurrent,
}

// ---------------------------------------------------------------------------
// HubDescriptor
// ---------------------------------------------------------------------------

/// Parsed USB hub descriptor (USB 2.0 §11.23.2.1).
#[derive(Debug, Clone, Default)]
pub struct HubDescriptor {
    /// bDescriptorType: `0x29` for USB 2.0, `0x2A` for USB 3.x.
    pub desc_type: u8,
    /// bNbrPorts: number of downstream ports.
    pub num_ports: u8,
    /// wHubCharacteristics: power switching, compound device, over-current flags.
    pub characteristics: u16,
    /// bPwrOn2PwrGood: time (in 2ms units) from port power-on to port power-good.
    pub power_on_to_good: u8,
    /// bHubContrCurrent: hub controller current (mA).
    pub controller_current: u8,
    /// DeviceRemovable bitmask (1 bit per port, bit 0 reserved).
    pub removable: u32,
    /// PortPwrCtrlMask bitmask.
    pub port_power_ctrl_mask: u32,
}

impl HubDescriptor {
    /// Parses a hub descriptor from a raw byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `data` is shorter than
    /// [`HUB_DESC_MIN_LEN`] bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < HUB_DESC_MIN_LEN {
            return Err(Error::InvalidArgument);
        }
        let num_ports = data[2];
        let characteristics = u16::from_le_bytes([data[3], data[4]]);
        let power_on_to_good = data[5];
        let controller_current = data[6];
        // DeviceRemovable is a variable-length bitmask starting at byte 7.
        let removable = if data.len() > 7 {
            u32::from(data[7])
        } else {
            0
        };
        let port_power_ctrl_mask = if data.len() > 8 {
            u32::from(data[8])
        } else {
            0xFF
        };
        Ok(Self {
            desc_type: data[0],
            num_ports: num_ports.min(MAX_HUB_PORTS as u8),
            characteristics,
            power_on_to_good,
            controller_current,
            removable,
            port_power_ctrl_mask,
        })
    }

    /// Returns `true` if the hub uses ganged power switching.
    pub fn ganged_power(&self) -> bool {
        self.characteristics & 0x03 == 0
    }

    /// Returns `true` if the hub is a compound device.
    pub fn is_compound(&self) -> bool {
        self.characteristics & (1 << 2) != 0
    }

    /// Returns `true` if port `n` (1-indexed) is non-removable.
    pub fn is_non_removable(&self, port: u8) -> bool {
        if port == 0 || port > 31 {
            return false;
        }
        self.removable & (1u32 << port) != 0
    }
}

// ---------------------------------------------------------------------------
// PortStatus
// ---------------------------------------------------------------------------

/// Raw port status from a `GetPortStatus` request.
#[derive(Debug, Clone, Copy, Default)]
pub struct PortStatus {
    /// wPortStatus — current status bits.
    pub status: u16,
    /// wPortChange — changed bits since last `ClearPortFeature`.
    pub change: u16,
}

impl PortStatus {
    /// Creates a new port status from raw words.
    pub const fn new(status: u16, change: u16) -> Self {
        Self { status, change }
    }

    /// Parses a 4-byte little-endian `GetPortStatus` response.
    pub fn from_bytes(data: [u8; 4]) -> Self {
        Self {
            status: u16::from_le_bytes([data[0], data[1]]),
            change: u16::from_le_bytes([data[2], data[3]]),
        }
    }

    /// Returns `true` if a device is connected.
    pub fn connected(&self) -> bool {
        self.status & PORT_STAT_CONNECTION != 0
    }

    /// Returns `true` if the port is enabled.
    pub fn enabled(&self) -> bool {
        self.status & PORT_STAT_ENABLE != 0
    }

    /// Returns `true` if the port is powered.
    pub fn powered(&self) -> bool {
        self.status & PORT_STAT_POWER != 0
    }

    /// Returns `true` if the connection status changed.
    pub fn connection_changed(&self) -> bool {
        self.change & PORT_CHG_CONNECTION != 0
    }

    /// Returns `true` if the reset completed.
    pub fn reset_completed(&self) -> bool {
        self.change & PORT_CHG_RESET != 0
    }

    /// Returns `true` if over-current was detected.
    pub fn overcurrent(&self) -> bool {
        self.status & PORT_STAT_OVERCURRENT != 0
    }
}

// ---------------------------------------------------------------------------
// HubPort
// ---------------------------------------------------------------------------

/// Full state for a single downstream hub port.
#[derive(Debug, Clone, Copy)]
pub struct HubPort {
    /// 1-based port number.
    pub port_num: u8,
    /// Current state machine state.
    pub state: PortState,
    /// Last port status snapshot.
    pub last_status: PortStatus,
    /// Number of consecutive reset attempts.
    pub reset_retries: u8,
    /// Address assigned to the connected device (0 = not enumerated).
    pub device_address: u8,
    /// Speed detected at this port.
    pub speed: HubSpeed,
    /// Whether this port is non-removable per the hub descriptor.
    pub non_removable: bool,
}

impl HubPort {
    /// Creates an unpowered port at the given 1-based number.
    pub const fn new(port_num: u8) -> Self {
        Self {
            port_num,
            state: PortState::Unpowered,
            last_status: PortStatus::new(0, 0),
            reset_retries: 0,
            device_address: 0,
            speed: HubSpeed::Full,
            non_removable: false,
        }
    }

    /// Updates port state based on a new [`PortStatus`] snapshot.
    ///
    /// Returns the event that should be queued, if any.
    pub fn update_status(&mut self, new_status: PortStatus) -> Option<HubPortEvent> {
        let was_connected = self.last_status.connected();
        self.last_status = new_status;

        if new_status.connection_changed() {
            if new_status.connected() && !was_connected {
                self.state = PortState::Debouncing;
                self.reset_retries = 0;
                return Some(HubPortEvent::Connected(self.port_num));
            } else if !new_status.connected() && was_connected {
                self.state = PortState::Disconnected;
                self.device_address = 0;
                return Some(HubPortEvent::Disconnected(self.port_num));
            }
        }

        if new_status.reset_completed() && self.state == PortState::Resetting {
            if new_status.enabled() {
                self.state = PortState::Enabled;
                return Some(HubPortEvent::ResetComplete(self.port_num));
            } else {
                return Some(HubPortEvent::ResetFailed(self.port_num));
            }
        }

        if new_status.overcurrent() && self.state != PortState::OverCurrent {
            self.state = PortState::OverCurrent;
            return Some(HubPortEvent::OverCurrent(self.port_num));
        }

        None
    }

    /// Initiates a port reset sequence.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the port is not in a state
    /// that allows reset.
    pub fn begin_reset(&mut self) -> Result<()> {
        match self.state {
            PortState::Debouncing | PortState::Disabled | PortState::Enabled => {
                self.state = PortState::Resetting;
                self.reset_retries += 1;
                Ok(())
            }
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Enables the port after successful reset.
    pub fn enable(&mut self) {
        self.state = PortState::Enabled;
    }

    /// Disables the port.
    pub fn disable(&mut self) {
        self.state = PortState::Disabled;
    }

    /// Suspends the port (device goes to low-power mode).
    pub fn suspend(&mut self) {
        if self.state == PortState::Enabled {
            self.state = PortState::Suspended;
        }
    }

    /// Resumes the port from suspend.
    pub fn resume(&mut self) {
        if self.state == PortState::Suspended {
            self.state = PortState::Enabled;
        }
    }

    /// Powers on the port.
    pub fn power_on(&mut self) {
        if self.state == PortState::Unpowered {
            self.state = PortState::Disconnected;
        }
    }

    /// Powers off the port.
    pub fn power_off(&mut self) {
        self.state = PortState::Unpowered;
        self.device_address = 0;
    }
}

// ---------------------------------------------------------------------------
// HubPortEvent
// ---------------------------------------------------------------------------

/// An event generated by a port status change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubPortEvent {
    /// A device was connected on the given 1-based port number.
    Connected(u8),
    /// A device was disconnected from the given port.
    Disconnected(u8),
    /// A port reset completed successfully.
    ResetComplete(u8),
    /// A port reset failed (port remains disabled).
    ResetFailed(u8),
    /// An over-current condition was detected on the port.
    OverCurrent(u8),
}

// ---------------------------------------------------------------------------
// HubEvent
// ---------------------------------------------------------------------------

/// A hub-level event (combines hub ID with port event).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HubEvent {
    /// Index into the [`HubRegistry`] for the hub that generated this event.
    pub hub_idx: usize,
    /// The port-level event detail.
    pub port_event: HubPortEvent,
}

// ---------------------------------------------------------------------------
// HubEventQueue
// ---------------------------------------------------------------------------

/// Fixed-size ring queue for pending hub events.
pub struct HubEventQueue {
    events: [Option<HubEvent>; MAX_HUB_EVENTS],
    head: usize,
    tail: usize,
    len: usize,
}

impl HubEventQueue {
    /// Creates an empty event queue.
    pub const fn new() -> Self {
        Self {
            events: [const { None }; MAX_HUB_EVENTS],
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    /// Enqueues an event.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the queue is full.
    pub fn push(&mut self, event: HubEvent) -> Result<()> {
        if self.len >= MAX_HUB_EVENTS {
            return Err(Error::OutOfMemory);
        }
        self.events[self.tail] = Some(event);
        self.tail = (self.tail + 1) % MAX_HUB_EVENTS;
        self.len += 1;
        Ok(())
    }

    /// Dequeues and returns the next pending event, or `None` if empty.
    pub fn pop(&mut self) -> Option<HubEvent> {
        if self.len == 0 {
            return None;
        }
        let event = self.events[self.head].take();
        self.head = (self.head + 1) % MAX_HUB_EVENTS;
        self.len -= 1;
        event
    }

    /// Returns the number of pending events.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for HubEventQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// UsbHub
// ---------------------------------------------------------------------------

/// A single USB hub device and its downstream ports.
pub struct UsbHub {
    /// USB device address of this hub (1-127).
    pub device_address: u8,
    /// Parsed hub descriptor.
    pub descriptor: HubDescriptor,
    /// Per-port state.
    ports: [HubPort; MAX_HUB_PORTS],
    /// Hub speed.
    pub speed: HubSpeed,
    /// Whether the hub is active.
    pub active: bool,
}

impl UsbHub {
    /// Creates a hub with the given address and parsed descriptor.
    pub fn new(device_address: u8, descriptor: HubDescriptor, speed: HubSpeed) -> Self {
        let num_ports = descriptor.num_ports as usize;
        let mut hub = Self {
            device_address,
            descriptor,
            ports: [const { HubPort::new(0) }; MAX_HUB_PORTS],
            speed,
            active: true,
        };
        // Initialize per-port state with 1-based port numbers.
        for i in 0..num_ports.min(MAX_HUB_PORTS) {
            hub.ports[i] = HubPort::new((i + 1) as u8);
            hub.ports[i].non_removable = hub.descriptor.is_non_removable((i + 1) as u8);
        }
        hub
    }

    /// Returns the number of downstream ports on this hub.
    pub fn num_ports(&self) -> usize {
        self.descriptor.num_ports as usize
    }

    /// Applies a new [`PortStatus`] to port `port` (1-indexed) and returns any event.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `port` is 0 or exceeds `num_ports`.
    pub fn handle_port_status(
        &mut self,
        port: u8,
        status: PortStatus,
    ) -> Result<Option<HubPortEvent>> {
        if port == 0 || port as usize > self.num_ports() {
            return Err(Error::InvalidArgument);
        }
        let idx = (port - 1) as usize;
        Ok(self.ports[idx].update_status(status))
    }

    /// Begins a reset sequence on port `port` (1-indexed).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the port is out of range or
    /// not in a resettable state.
    pub fn reset_port(&mut self, port: u8) -> Result<()> {
        if port == 0 || port as usize > self.num_ports() {
            return Err(Error::InvalidArgument);
        }
        self.ports[(port - 1) as usize].begin_reset()
    }

    /// Powers on all ports.
    pub fn power_on_all(&mut self) {
        let n = self.num_ports();
        for i in 0..n {
            self.ports[i].power_on();
        }
    }

    /// Powers off all ports.
    pub fn power_off_all(&mut self) {
        let n = self.num_ports();
        for i in 0..n {
            self.ports[i].power_off();
        }
    }

    /// Returns a reference to port state (1-indexed).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `port` is out of range.
    pub fn port(&self, port: u8) -> Result<&HubPort> {
        if port == 0 || port as usize > self.num_ports() {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.ports[(port - 1) as usize])
    }
}

// ---------------------------------------------------------------------------
// HubRegistry
// ---------------------------------------------------------------------------

/// Registry managing all active USB hubs.
pub struct HubRegistry {
    hubs: [Option<UsbHub>; MAX_HUBS],
    count: usize,
    /// Pending hub events.
    pub events: HubEventQueue,
}

impl HubRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self {
            hubs: [const { None }; MAX_HUBS],
            count: 0,
            events: HubEventQueue::new(),
        }
    }

    /// Registers a hub, returning its index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, hub: UsbHub) -> Result<usize> {
        let idx = self
            .hubs
            .iter()
            .position(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;
        self.hubs[idx] = Some(hub);
        self.count += 1;
        Ok(idx)
    }

    /// Removes and returns the hub at `index`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the slot is empty.
    pub fn unregister(&mut self, index: usize) -> Result<UsbHub> {
        if index >= MAX_HUBS {
            return Err(Error::InvalidArgument);
        }
        let hub = self.hubs[index].take().ok_or(Error::NotFound)?;
        self.count -= 1;
        Ok(hub)
    }

    /// Dispatches a port status update to the hub at `hub_idx`, enqueuing
    /// any resulting event.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the hub slot is empty, or propagates
    /// errors from [`UsbHub::handle_port_status`].
    pub fn dispatch_port_status(
        &mut self,
        hub_idx: usize,
        port: u8,
        status: PortStatus,
    ) -> Result<()> {
        if hub_idx >= MAX_HUBS {
            return Err(Error::InvalidArgument);
        }
        let hub = self.hubs[hub_idx].as_mut().ok_or(Error::NotFound)?;
        if let Some(port_event) = hub.handle_port_status(port, status)? {
            self.events.push(HubEvent {
                hub_idx,
                port_event,
            })?;
        }
        Ok(())
    }

    /// Returns a reference to the hub at `index`.
    pub fn get(&self, index: usize) -> Option<&UsbHub> {
        self.hubs.get(index).and_then(|s| s.as_ref())
    }

    /// Returns a mutable reference to the hub at `index`.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut UsbHub> {
        self.hubs.get_mut(index).and_then(|s| s.as_mut())
    }

    /// Returns the number of registered hubs.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no hubs are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for HubRegistry {
    fn default() -> Self {
        Self::new()
    }
}
