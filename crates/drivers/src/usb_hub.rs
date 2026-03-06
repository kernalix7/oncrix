// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! USB hub driver.
//!
//! Implements USB hub class device management (USB 3.2 §10, USB 2.0 §11).
//! A hub exposes a set of downstream ports to which USB devices or
//! additional hubs can be connected. This driver handles hub descriptor
//! parsing, port power management, port status polling, and device
//! attachment/detachment events.
//!
//! # Architecture
//!
//! ```text
//! Root Hub (xHCI / EHCI)
//!   │
//!   ├── Port 0 ── USB Device
//!   └── Port 1 ── UsbHub
//!                   ├── Port 0 ── USB Device
//!                   └── Port 1 ── USB Device
//! ```
//!
//! # Hub Descriptor (USB 2.0 §11.23.2.1)
//!
//! The hub descriptor (bDescriptorType = 0x29 for USB 2.0) contains the
//! number of downstream ports, per-port power and over-current characteristics,
//! and individual port power switching control bits.
//!
//! # Port Status (USB 2.0 §11.24.2.7)
//!
//! `GetPortStatus` returns a 4-byte status word:
//! - Bits[15:0]: wPortStatus — current port status flags.
//! - Bits[31:16]: wPortChange — changed bits (cleared by `ClearPortFeature`).
//!
//! Reference: USB 2.0 Specification, Chapter 11;
//!            USB 3.2 Specification, Chapter 10.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of USB hub devices managed.
pub const MAX_HUBS: usize = 8;

/// Maximum downstream ports per hub (USB 2.0 limits: 7 external).
pub const MAX_PORTS_PER_HUB: usize = 16;

/// USB hub class code.
pub const USB_CLASS_HUB: u8 = 0x09;

/// USB hub descriptor type (USB 2.0).
pub const USB_DT_HUB: u8 = 0x29;

/// USB 3.0 SuperSpeed hub descriptor type.
pub const USB_DT_SS_HUB: u8 = 0x2A;

/// Minimum hub descriptor length (bytes).
pub const HUB_DESC_MIN_LEN: usize = 9;

// ---------------------------------------------------------------------------
// Port status bits (wPortStatus, USB 2.0 Table 11-21)
// ---------------------------------------------------------------------------

/// Port status: connection present.
pub const PORT_STATUS_CONNECTION: u16 = 1 << 0;

/// Port status: port is enabled.
pub const PORT_STATUS_ENABLE: u16 = 1 << 1;

/// Port status: port is suspended.
pub const PORT_STATUS_SUSPEND: u16 = 1 << 2;

/// Port status: over-current condition.
pub const PORT_STATUS_OVERCURRENT: u16 = 1 << 3;

/// Port status: port is in reset.
pub const PORT_STATUS_RESET: u16 = 1 << 4;

/// Port status: port power is on.
pub const PORT_STATUS_POWER: u16 = 1 << 8;

/// Port status: low-speed device attached.
pub const PORT_STATUS_LOW_SPEED: u16 = 1 << 9;

/// Port status: high-speed device attached.
pub const PORT_STATUS_HIGH_SPEED: u16 = 1 << 10;

/// Port status: test mode.
pub const PORT_STATUS_TEST: u16 = 1 << 11;

/// Port status: indicator control.
pub const PORT_STATUS_INDICATOR: u16 = 1 << 12;

// ---------------------------------------------------------------------------
// Port change bits (wPortChange, USB 2.0 Table 11-22)
// ---------------------------------------------------------------------------

/// Port change: connection status changed.
pub const PORT_CHANGE_CONNECTION: u16 = 1 << 0;

/// Port change: enable status changed.
pub const PORT_CHANGE_ENABLE: u16 = 1 << 1;

/// Port change: suspend state changed.
pub const PORT_CHANGE_SUSPEND: u16 = 1 << 2;

/// Port change: over-current changed.
pub const PORT_CHANGE_OVERCURRENT: u16 = 1 << 3;

/// Port change: reset complete.
pub const PORT_CHANGE_RESET: u16 = 1 << 4;

// ---------------------------------------------------------------------------
// Hub features (USB 2.0 Table 11-17)
// ---------------------------------------------------------------------------

/// Hub feature selector: C_HUB_LOCAL_POWER.
pub const HUB_FEATURE_C_LOCAL_POWER: u16 = 0;

/// Hub feature selector: C_HUB_OVER_CURRENT.
pub const HUB_FEATURE_C_OVER_CURRENT: u16 = 1;

/// Port feature: PORT_CONNECTION.
pub const PORT_FEATURE_CONNECTION: u16 = 0;

/// Port feature: PORT_ENABLE.
pub const PORT_FEATURE_ENABLE: u16 = 1;

/// Port feature: PORT_SUSPEND.
pub const PORT_FEATURE_SUSPEND: u16 = 2;

/// Port feature: PORT_OVER_CURRENT (not settable).
pub const PORT_FEATURE_OVER_CURRENT: u16 = 3;

/// Port feature: PORT_RESET.
pub const PORT_FEATURE_RESET: u16 = 4;

/// Port feature: PORT_POWER.
pub const PORT_FEATURE_POWER: u16 = 8;

/// Port feature: C_PORT_CONNECTION.
pub const PORT_FEATURE_C_CONNECTION: u16 = 16;

/// Port feature: C_PORT_ENABLE.
pub const PORT_FEATURE_C_ENABLE: u16 = 17;

/// Port feature: C_PORT_SUSPEND.
pub const PORT_FEATURE_C_SUSPEND: u16 = 18;

/// Port feature: C_PORT_OVER_CURRENT.
pub const PORT_FEATURE_C_OVER_CURRENT: u16 = 19;

/// Port feature: C_PORT_RESET.
pub const PORT_FEATURE_C_RESET: u16 = 20;

// ---------------------------------------------------------------------------
// Hub power switching modes
// ---------------------------------------------------------------------------

/// Hub power switching mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PowerSwitching {
    /// All ports powered at once (ganged).
    #[default]
    Ganged,
    /// Individual port power control.
    Individual,
    /// No power switching (always on).
    None,
}

/// Hub over-current protection mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OverCurrentMode {
    /// Hub-wide over-current protection.
    #[default]
    Global,
    /// Per-port over-current protection.
    PerPort,
    /// No over-current protection.
    None,
}

// ---------------------------------------------------------------------------
// USB speed
// ---------------------------------------------------------------------------

/// USB device speed negotiated at port attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UsbSpeed {
    /// Low speed (1.5 Mbit/s).
    Low,
    /// Full speed (12 Mbit/s).
    #[default]
    Full,
    /// High speed (480 Mbit/s).
    High,
    /// SuperSpeed (5 Gbit/s).
    Super,
    /// SuperSpeed+ (10+ Gbit/s).
    SuperPlus,
}

// ---------------------------------------------------------------------------
// HubDescriptor
// ---------------------------------------------------------------------------

/// Parsed USB 2.0 hub descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct HubDescriptor {
    /// Number of downstream ports.
    pub num_ports: u8,
    /// Hub characteristics word (power switching, OC mode, TT think time).
    pub characteristics: u16,
    /// Time (in 2 ms units) for power to become stable after enabling.
    pub power_on_to_power_good: u8,
    /// Maximum current drawn by the hub controller (in mA, factor of 1).
    pub hub_controller_current: u8,
    /// Device removable bitmask (one bit per port, 1=non-removable).
    pub device_removable: u32,
    /// USB version this hub targets (0x0200 = USB 2.0, 0x0310 = USB 3.1).
    pub usb_version: u16,
}

impl HubDescriptor {
    /// Parse from raw bytes.
    ///
    /// `data` must be at least `HUB_DESC_MIN_LEN` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if data is too short or the
    /// descriptor type byte is incorrect.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < HUB_DESC_MIN_LEN {
            return Err(Error::InvalidArgument);
        }
        // data[0] = bLength, data[1] = bDescriptorType
        if data[1] != USB_DT_HUB && data[1] != USB_DT_SS_HUB {
            return Err(Error::InvalidArgument);
        }
        let num_ports = data[2];
        let characteristics = u16::from_le_bytes([data[3], data[4]]);
        let power_on_to_power_good = data[5];
        let hub_controller_current = data[6];
        // Device removable bitmap starts at data[7].
        let mut device_removable = 0u32;
        let bm_len = ((num_ports as usize + 1) / 8) + 1;
        for i in 0..bm_len.min(4) {
            if 7 + i < data.len() {
                device_removable |= (data[7 + i] as u32) << (i * 8);
            }
        }
        let usb_version = if data[1] == USB_DT_SS_HUB {
            0x0310
        } else {
            0x0200
        };
        Ok(Self {
            num_ports,
            characteristics,
            power_on_to_power_good,
            hub_controller_current,
            device_removable,
            usb_version,
        })
    }

    /// Power switching mode extracted from characteristics word.
    pub fn power_switching(&self) -> PowerSwitching {
        match self.characteristics & 0x03 {
            0 => PowerSwitching::Ganged,
            1 => PowerSwitching::Individual,
            _ => PowerSwitching::None,
        }
    }

    /// Over-current protection mode.
    pub fn over_current_mode(&self) -> OverCurrentMode {
        match (self.characteristics >> 3) & 0x03 {
            0 => OverCurrentMode::Global,
            1 => OverCurrentMode::PerPort,
            _ => OverCurrentMode::None,
        }
    }

    /// Whether port `port` (1-based) is non-removable.
    pub fn is_non_removable(&self, port: u8) -> bool {
        if port == 0 || port > 32 {
            return false;
        }
        (self.device_removable >> port) & 1 == 1
    }

    /// Power-on stabilisation time in milliseconds.
    pub fn power_on_delay_ms(&self) -> u32 {
        u32::from(self.power_on_to_power_good) * 2
    }
}

// ---------------------------------------------------------------------------
// PortState
// ---------------------------------------------------------------------------

/// State of a single downstream hub port.
#[derive(Debug, Clone, Copy, Default)]
pub struct PortState {
    /// Current wPortStatus.
    pub status: u16,
    /// Current wPortChange (pending change bits).
    pub change: u16,
    /// Speed of attached device (valid only when connected).
    pub speed: UsbSpeed,
    /// Whether a device is currently enumerated on this port.
    pub enumerated: bool,
    /// USB address assigned to the downstream device (0 = not assigned).
    pub device_address: u8,
}

impl PortState {
    /// Create an uninitialised port state.
    pub const fn new() -> Self {
        Self {
            status: 0,
            change: 0,
            speed: UsbSpeed::Full,
            enumerated: false,
            device_address: 0,
        }
    }

    /// Update from a raw 4-byte GetPortStatus response.
    pub fn update_from_raw(&mut self, raw: u32) {
        self.status = raw as u16;
        self.change = (raw >> 16) as u16;
        // Infer speed from status bits.
        self.speed = if self.status & PORT_STATUS_LOW_SPEED != 0 {
            UsbSpeed::Low
        } else if self.status & PORT_STATUS_HIGH_SPEED != 0 {
            UsbSpeed::High
        } else {
            UsbSpeed::Full
        };
    }

    /// Whether a device is connected.
    pub fn is_connected(&self) -> bool {
        self.status & PORT_STATUS_CONNECTION != 0
    }

    /// Whether the port is enabled.
    pub fn is_enabled(&self) -> bool {
        self.status & PORT_STATUS_ENABLE != 0
    }

    /// Whether port power is on.
    pub fn is_powered(&self) -> bool {
        self.status & PORT_STATUS_POWER != 0
    }

    /// Whether there is a connection change event pending.
    pub fn has_connection_change(&self) -> bool {
        self.change & PORT_CHANGE_CONNECTION != 0
    }

    /// Whether a reset completed.
    pub fn has_reset_complete(&self) -> bool {
        self.change & PORT_CHANGE_RESET != 0
    }

    /// Clear a specific change bit.
    pub fn clear_change(&mut self, bit: u16) {
        self.change &= !bit;
    }
}

// ---------------------------------------------------------------------------
// UsbHub
// ---------------------------------------------------------------------------

/// A USB hub device instance.
#[derive(Debug)]
pub struct UsbHub {
    /// USB device address of this hub.
    pub device_address: u8,
    /// Hub depth (0 = root hub, 1 = first-level, etc.).
    pub depth: u8,
    /// Parsed hub descriptor.
    pub descriptor: HubDescriptor,
    /// Per-port state.
    ports: [PortState; MAX_PORTS_PER_HUB],
    /// Whether the hub has been fully initialised.
    pub initialized: bool,
    /// TT (Transaction Translator) think time in FS bit times.
    pub tt_think_time: u8,
    /// Total devices connected (including nested hubs).
    pub total_devices: u32,
}

impl UsbHub {
    /// Create a new hub instance from a parsed descriptor.
    pub const fn new(device_address: u8, depth: u8, descriptor: HubDescriptor) -> Self {
        Self {
            device_address,
            depth,
            descriptor,
            ports: [const { PortState::new() }; MAX_PORTS_PER_HUB],
            initialized: false,
            tt_think_time: 0,
            total_devices: 0,
        }
    }

    /// Initialise the hub: power up all ports.
    ///
    /// Must be called after construction. Records that power-on sequencing
    /// has been requested; the caller must wait the hub's `power_on_delay_ms`
    /// before probing ports.
    pub fn init(&mut self) -> Result<()> {
        if self.descriptor.num_ports as usize > MAX_PORTS_PER_HUB {
            return Err(Error::InvalidArgument);
        }
        for i in 0..self.descriptor.num_ports as usize {
            self.ports[i] = PortState::new();
        }
        self.initialized = true;
        Ok(())
    }

    /// Update the state of port `port` (1-based) from a raw status word.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `port` is out of range.
    pub fn update_port_status(&mut self, port: u8, raw: u32) -> Result<()> {
        self.check_port(port)?;
        self.ports[port as usize - 1].update_from_raw(raw);
        Ok(())
    }

    /// Handle a port connection event on `port` (1-based).
    ///
    /// Marks the port as having an attached device and returns the speed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `port` is out of range.
    pub fn handle_connection(&mut self, port: u8) -> Result<UsbSpeed> {
        self.check_port(port)?;
        let idx = port as usize - 1;
        let speed = self.ports[idx].speed;
        self.ports[idx].enumerated = true;
        self.total_devices += 1;
        Ok(speed)
    }

    /// Handle a port disconnection event on `port` (1-based).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `port` is out of range.
    pub fn handle_disconnection(&mut self, port: u8) -> Result<()> {
        self.check_port(port)?;
        let idx = port as usize - 1;
        if self.ports[idx].enumerated {
            self.total_devices = self.total_devices.saturating_sub(1);
        }
        self.ports[idx].enumerated = false;
        self.ports[idx].device_address = 0;
        Ok(())
    }

    /// Assign a USB address to the device on `port` (1-based).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `port` is out of range.
    pub fn assign_address(&mut self, port: u8, address: u8) -> Result<()> {
        self.check_port(port)?;
        self.ports[port as usize - 1].device_address = address;
        Ok(())
    }

    /// Get the state of port `port` (1-based).
    pub fn port_state(&self, port: u8) -> Result<&PortState> {
        self.check_port(port)?;
        Ok(&self.ports[port as usize - 1])
    }

    /// Get a mutable reference to the state of port `port` (1-based).
    pub fn port_state_mut(&mut self, port: u8) -> Result<&mut PortState> {
        self.check_port(port)?;
        Ok(&mut self.ports[port as usize - 1])
    }

    /// Iterate over port states (1-based ports up to `num_ports`).
    pub fn ports(&self) -> &[PortState] {
        &self.ports[..self.descriptor.num_ports as usize]
    }

    /// Number of downstream ports.
    pub fn num_ports(&self) -> u8 {
        self.descriptor.num_ports
    }

    /// Whether this is a SuperSpeed hub.
    pub fn is_superspeed(&self) -> bool {
        self.descriptor.usb_version >= 0x0300
    }

    /// Validate a 1-based port number.
    fn check_port(&self, port: u8) -> Result<()> {
        if port == 0 || port > self.descriptor.num_ports {
            Err(Error::InvalidArgument)
        } else {
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// HubEvent
// ---------------------------------------------------------------------------

/// A hub or port event that needs driver attention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubEvent {
    /// Device connected on port (1-based port number).
    PortConnected(u8),
    /// Device disconnected from port.
    PortDisconnected(u8),
    /// Port reset completed.
    PortResetComplete(u8),
    /// Over-current condition on port.
    PortOverCurrent(u8),
    /// Hub-level over-current.
    HubOverCurrent,
    /// Hub power changed.
    HubPowerChange,
}

/// Decode pending change events for all ports of a hub into a list.
///
/// Scans each port's `change` bits and pushes corresponding
/// [`HubEvent`] values into `events`. Returns the number of events added.
pub fn decode_hub_events(hub: &UsbHub, events: &mut [HubEvent]) -> usize {
    let mut count = 0;
    for p in 1..=hub.num_ports() {
        if count >= events.len() {
            break;
        }
        if let Ok(state) = hub.port_state(p) {
            if state.change & PORT_CHANGE_CONNECTION != 0 {
                if state.is_connected() {
                    events[count] = HubEvent::PortConnected(p);
                } else {
                    events[count] = HubEvent::PortDisconnected(p);
                }
                count += 1;
            }
            if count < events.len() && state.change & PORT_CHANGE_RESET != 0 {
                events[count] = HubEvent::PortResetComplete(p);
                count += 1;
            }
            if count < events.len() && state.change & PORT_CHANGE_OVERCURRENT != 0 {
                events[count] = HubEvent::PortOverCurrent(p);
                count += 1;
            }
        }
    }
    count
}

// ---------------------------------------------------------------------------
// UsbHubRegistry
// ---------------------------------------------------------------------------

/// Global registry of attached USB hubs.
pub struct UsbHubRegistry {
    hubs: [Option<UsbHub>; MAX_HUBS],
    len: usize,
}

impl UsbHubRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            hubs: [const { None }; MAX_HUBS],
            len: 0,
        }
    }

    /// Register a hub.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, hub: UsbHub) -> Result<usize> {
        if self.len >= MAX_HUBS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.len;
        self.hubs[idx] = Some(hub);
        self.len += 1;
        Ok(idx)
    }

    /// Find a hub by device address.
    pub fn find_by_address(&self, addr: u8) -> Option<&UsbHub> {
        for i in 0..self.len {
            if let Some(ref h) = self.hubs[i] {
                if h.device_address == addr {
                    return Some(h);
                }
            }
        }
        None
    }

    /// Find a mutable hub by device address.
    pub fn find_by_address_mut(&mut self, addr: u8) -> Option<&mut UsbHub> {
        for i in 0..self.len {
            if let Some(ref h) = self.hubs[i] {
                if h.device_address == addr {
                    return self.hubs[i].as_mut();
                }
            }
        }
        None
    }

    /// Number of registered hubs.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Iterate over registered hubs.
    pub fn iter(&self) -> impl Iterator<Item = &UsbHub> {
        self.hubs[..self.len].iter().filter_map(|h| h.as_ref())
    }
}

// ---------------------------------------------------------------------------
// USB 3.x SuperSpeed port status extensions (USB 3.2 §10.16.2.6)
// ---------------------------------------------------------------------------

/// SS port status: link state mask (bits [9:5] of wPortStatus).
pub const SS_PORT_STATUS_LINK_STATE_MASK: u16 = 0x01E0;

/// SS port status: link state shift.
pub const SS_PORT_STATUS_LINK_STATE_SHIFT: u16 = 5;

/// SS port status: power state bit.
pub const SS_PORT_STATUS_POWER: u16 = 1 << 9;

/// SS port status: device speed (bits [12:10]).
pub const SS_PORT_STATUS_SPEED_MASK: u16 = 0x1C00;

/// SS port status: speed shift.
pub const SS_PORT_STATUS_SPEED_SHIFT: u16 = 10;

/// SS port change: BH reset complete.
pub const SS_PORT_CHANGE_BH_RESET: u16 = 1 << 5;

/// SS port change: port link state changed.
pub const SS_PORT_CHANGE_LINK_STATE: u16 = 1 << 6;

/// SS port change: port config error.
pub const SS_PORT_CHANGE_CONFIG_ERROR: u16 = 1 << 7;

/// SS port feature: PORT_U1_TIMEOUT.
pub const SS_PORT_FEATURE_U1_TIMEOUT: u16 = 23;

/// SS port feature: PORT_U2_TIMEOUT.
pub const SS_PORT_FEATURE_U2_TIMEOUT: u16 = 24;

/// SS port feature: C_PORT_LINK_STATE.
pub const SS_PORT_FEATURE_C_LINK_STATE: u16 = 25;

/// SS port feature: C_PORT_CONFIG_ERROR.
pub const SS_PORT_FEATURE_C_CONFIG_ERROR: u16 = 26;

/// SS port feature: PORT_REMOTE_WAKE_MASK.
pub const SS_PORT_FEATURE_REMOTE_WAKE_MASK: u16 = 27;

/// SS port feature: BH_PORT_RESET.
pub const SS_PORT_FEATURE_BH_RESET: u16 = 28;

/// SS port feature: C_BH_PORT_RESET.
pub const SS_PORT_FEATURE_C_BH_RESET: u16 = 29;

/// SS port feature: FORCE_LINKPM_ACCEPT.
pub const SS_PORT_FEATURE_FORCE_LINKPM_ACCEPT: u16 = 30;

/// Hub depth feature selector (USB 3.x SetHubDepth command).
pub const HUB_FEATURE_HUB_DEPTH: u16 = 0;

// ---------------------------------------------------------------------------
// USB control transfer structures
// ---------------------------------------------------------------------------

/// USB setup packet (8 bytes, §9.3).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct UsbSetupPacket {
    /// bmRequestType: direction, type, recipient.
    pub request_type: u8,
    /// bRequest: specific request.
    pub request: u8,
    /// wValue: request-specific value.
    pub value: u16,
    /// wIndex: request-specific index.
    pub index: u16,
    /// wLength: number of bytes to transfer in data stage.
    pub length: u16,
}

impl UsbSetupPacket {
    /// Builds a standard SetAddress setup packet.
    pub const fn set_address(address: u8) -> Self {
        Self {
            request_type: 0x00, // host→device, standard, device
            request: USB_REQ_SET_ADDRESS,
            value: address as u16,
            index: 0,
            length: 0,
        }
    }

    /// Builds a GetDescriptor setup packet.
    pub const fn get_descriptor(desc_type: u8, desc_index: u8, lang_id: u16, length: u16) -> Self {
        Self {
            request_type: 0x80, // device→host, standard, device
            request: USB_REQ_GET_DESCRIPTOR,
            value: ((desc_type as u16) << 8) | (desc_index as u16),
            index: lang_id,
            length,
        }
    }

    /// Builds a SetConfiguration setup packet.
    pub const fn set_configuration(config_value: u8) -> Self {
        Self {
            request_type: 0x00,
            request: USB_REQ_SET_CONFIGURATION,
            value: config_value as u16,
            index: 0,
            length: 0,
        }
    }

    /// Builds a SetPortFeature setup packet (hub class request).
    pub const fn set_port_feature(port: u8, feature: u16) -> Self {
        Self {
            request_type: 0x23, // host→device, class, other
            request: USB_REQ_SET_FEATURE,
            value: feature,
            index: port as u16,
            length: 0,
        }
    }

    /// Builds a ClearPortFeature setup packet.
    pub const fn clear_port_feature(port: u8, feature: u16) -> Self {
        Self {
            request_type: 0x23,
            request: USB_REQ_CLEAR_FEATURE,
            value: feature,
            index: port as u16,
            length: 0,
        }
    }

    /// Builds a GetPortStatus setup packet.
    pub const fn get_port_status(port: u8) -> Self {
        Self {
            request_type: 0xA3, // device→host, class, other
            request: USB_REQ_GET_STATUS,
            value: 0,
            index: port as u16,
            length: 4,
        }
    }

    /// Builds a SetHubDepth setup packet (USB 3.x).
    pub const fn set_hub_depth(depth: u8) -> Self {
        Self {
            request_type: 0x20, // host→device, class, device
            request: USB_REQ_SET_HUB_DEPTH,
            value: depth as u16,
            index: 0,
            length: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// USB standard request codes (§9.4)
// ---------------------------------------------------------------------------

/// Standard request: GET_STATUS.
pub const USB_REQ_GET_STATUS: u8 = 0x00;

/// Standard request: CLEAR_FEATURE.
pub const USB_REQ_CLEAR_FEATURE: u8 = 0x01;

/// Standard request: SET_FEATURE.
pub const USB_REQ_SET_FEATURE: u8 = 0x03;

/// Standard request: SET_ADDRESS.
pub const USB_REQ_SET_ADDRESS: u8 = 0x05;

/// Standard request: GET_DESCRIPTOR.
pub const USB_REQ_GET_DESCRIPTOR: u8 = 0x06;

/// Standard request: SET_DESCRIPTOR.
pub const USB_REQ_SET_DESCRIPTOR: u8 = 0x07;

/// Standard request: GET_CONFIGURATION.
pub const USB_REQ_GET_CONFIGURATION: u8 = 0x08;

/// Standard request: SET_CONFIGURATION.
pub const USB_REQ_SET_CONFIGURATION: u8 = 0x09;

/// Hub class request: SET_HUB_DEPTH (USB 3.x).
pub const USB_REQ_SET_HUB_DEPTH: u8 = 0x0C;

// ---------------------------------------------------------------------------
// USB descriptor types (§9.6)
// ---------------------------------------------------------------------------

/// Descriptor type: Device.
pub const USB_DT_DEVICE: u8 = 0x01;

/// Descriptor type: Configuration.
pub const USB_DT_CONFIG: u8 = 0x02;

/// Descriptor type: String.
pub const USB_DT_STRING: u8 = 0x03;

/// Descriptor type: Interface.
pub const USB_DT_INTERFACE: u8 = 0x04;

/// Descriptor type: Endpoint.
pub const USB_DT_ENDPOINT: u8 = 0x05;

/// Descriptor type: Device Qualifier.
pub const USB_DT_DEVICE_QUALIFIER: u8 = 0x06;

// ---------------------------------------------------------------------------
// USB Device Descriptor (§9.6.1)
// ---------------------------------------------------------------------------

/// Parsed USB device descriptor (18 bytes).
#[derive(Debug, Clone, Copy, Default)]
pub struct UsbDeviceDescriptor {
    /// USB specification version (e.g. 0x0200 for USB 2.0).
    pub usb_version: u16,
    /// Device class code.
    pub device_class: u8,
    /// Device subclass code.
    pub device_subclass: u8,
    /// Device protocol code.
    pub device_protocol: u8,
    /// Maximum packet size for endpoint zero.
    pub max_packet_size_ep0: u8,
    /// Vendor ID.
    pub vendor_id: u16,
    /// Product ID.
    pub product_id: u16,
    /// Device release number.
    pub device_version: u16,
    /// Index of manufacturer string descriptor.
    pub manufacturer_idx: u8,
    /// Index of product string descriptor.
    pub product_idx: u8,
    /// Index of serial number string descriptor.
    pub serial_idx: u8,
    /// Number of possible configurations.
    pub num_configurations: u8,
}

impl UsbDeviceDescriptor {
    /// Parse from an 18-byte raw buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the buffer is too short or
    /// the descriptor type byte is wrong.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 18 {
            return Err(Error::InvalidArgument);
        }
        if raw[1] != USB_DT_DEVICE {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            usb_version: u16::from_le_bytes([raw[2], raw[3]]),
            device_class: raw[4],
            device_subclass: raw[5],
            device_protocol: raw[6],
            max_packet_size_ep0: raw[7],
            vendor_id: u16::from_le_bytes([raw[8], raw[9]]),
            product_id: u16::from_le_bytes([raw[10], raw[11]]),
            device_version: u16::from_le_bytes([raw[12], raw[13]]),
            manufacturer_idx: raw[14],
            product_idx: raw[15],
            serial_idx: raw[16],
            num_configurations: raw[17],
        })
    }

    /// Returns true if this device is a hub.
    pub fn is_hub(&self) -> bool {
        self.device_class == USB_CLASS_HUB
    }

    /// Returns the USB major version.
    pub fn usb_major(&self) -> u8 {
        (self.usb_version >> 8) as u8
    }
}

// ---------------------------------------------------------------------------
// Port power control
// ---------------------------------------------------------------------------

/// Port power control operations (issued as SetPortFeature / ClearPortFeature).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortPowerCmd {
    /// Power on the port (SetPortFeature PORT_POWER).
    PowerOn,
    /// Power off the port (ClearPortFeature PORT_POWER).
    PowerOff,
}

impl PortPowerCmd {
    /// Returns the corresponding `UsbSetupPacket` for port `port` (1-based).
    pub fn setup_packet(self, port: u8) -> UsbSetupPacket {
        match self {
            PortPowerCmd::PowerOn => UsbSetupPacket::set_port_feature(port, PORT_FEATURE_POWER),
            PortPowerCmd::PowerOff => UsbSetupPacket::clear_port_feature(port, PORT_FEATURE_POWER),
        }
    }
}

// ---------------------------------------------------------------------------
// Port reset sequence
// ---------------------------------------------------------------------------

/// Tracks the state of an in-progress port reset sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetState {
    /// No reset is in progress.
    Idle,
    /// RESET feature has been set; waiting for PORT_CHANGE_RESET.
    Resetting,
    /// Reset complete; device ready for enumeration.
    Done,
    /// Reset timed out or failed.
    Failed,
}

/// Per-port reset tracking context.
#[derive(Debug, Clone, Copy)]
pub struct PortResetCtx {
    /// 1-based port number.
    pub port: u8,
    /// Current reset state.
    pub state: ResetState,
    /// Number of polling iterations remaining before timeout.
    pub timeout_ticks: u32,
}

impl PortResetCtx {
    /// Creates a new reset context for the given port.
    pub const fn new(port: u8) -> Self {
        Self {
            port,
            state: ResetState::Idle,
            timeout_ticks: 0,
        }
    }

    /// Starts the reset sequence. Returns the SetPortFeature RESET setup packet.
    pub fn start(&mut self) -> UsbSetupPacket {
        self.state = ResetState::Resetting;
        self.timeout_ticks = PORT_RESET_TIMEOUT_TICKS;
        UsbSetupPacket::set_port_feature(self.port, PORT_FEATURE_RESET)
    }

    /// Polls the reset: call with the latest port status/change word.
    ///
    /// Returns the ClearPortFeature C_RESET packet when reset completes,
    /// or `None` if still waiting. Updates `state` to `Done` or `Failed`.
    pub fn poll(&mut self, raw_status: u32) -> Option<UsbSetupPacket> {
        if self.state != ResetState::Resetting {
            return None;
        }
        let change = (raw_status >> 16) as u16;
        if change & PORT_CHANGE_RESET != 0 {
            self.state = ResetState::Done;
            return Some(UsbSetupPacket::clear_port_feature(
                self.port,
                PORT_FEATURE_C_RESET,
            ));
        }
        if self.timeout_ticks == 0 {
            self.state = ResetState::Failed;
            return None;
        }
        self.timeout_ticks -= 1;
        None
    }
}

/// Number of polling ticks before a port reset is considered timed out.
pub const PORT_RESET_TIMEOUT_TICKS: u32 = 200;

/// Minimum delay after reset before addressing a device (USB 2.0: 10 ms).
pub const POST_RESET_DELAY_MS: u32 = 10;

// ---------------------------------------------------------------------------
// USB Device Enumeration
// ---------------------------------------------------------------------------

/// State machine for USB device enumeration.
///
/// Drives the standard enumeration sequence:
/// 1. Get device descriptor (8 bytes to learn max packet size)
/// 2. Set address
/// 3. Get full device descriptor (18 bytes)
/// 4. Get configuration descriptor
/// 5. Set configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnumState {
    /// Enumeration has not started.
    Idle,
    /// Requesting the first 8 bytes of the device descriptor.
    GetDescriptor8,
    /// Setting the device USB address.
    SetAddress,
    /// Requesting the full 18-byte device descriptor.
    GetDescriptorFull,
    /// Requesting the configuration descriptor.
    GetConfig,
    /// Setting the active configuration.
    SetConfig,
    /// Enumeration complete.
    Done,
    /// Enumeration failed.
    Failed,
}

/// USB device enumeration context for a single downstream port.
pub struct EnumContext {
    /// Hub index (from registry) this device is attached to.
    pub hub_idx: usize,
    /// 1-based port number on that hub.
    pub port: u8,
    /// USB address being assigned.
    pub address: u8,
    /// Current enumeration state.
    pub state: EnumState,
    /// Captured device descriptor (populated after GetDescriptorFull).
    pub device_desc: Option<UsbDeviceDescriptor>,
    /// Selected configuration value.
    pub config_value: u8,
}

impl EnumContext {
    /// Creates a new enumeration context.
    pub const fn new(hub_idx: usize, port: u8, address: u8) -> Self {
        Self {
            hub_idx,
            port,
            address,
            state: EnumState::Idle,
            device_desc: None,
            config_value: 1,
        }
    }

    /// Returns the next setup packet to issue, advancing the state machine.
    ///
    /// Call after the previous transfer has completed successfully.
    /// Returns `None` when enumeration is `Done` or `Failed`.
    pub fn next_setup(&mut self) -> Option<UsbSetupPacket> {
        match self.state {
            EnumState::Idle => {
                self.state = EnumState::GetDescriptor8;
                Some(UsbSetupPacket::get_descriptor(USB_DT_DEVICE, 0, 0, 8))
            }
            EnumState::GetDescriptor8 => {
                self.state = EnumState::SetAddress;
                Some(UsbSetupPacket::set_address(self.address))
            }
            EnumState::SetAddress => {
                self.state = EnumState::GetDescriptorFull;
                Some(UsbSetupPacket::get_descriptor(USB_DT_DEVICE, 0, 0, 18))
            }
            EnumState::GetDescriptorFull => {
                self.state = EnumState::GetConfig;
                // Request configuration descriptor (9 bytes header).
                Some(UsbSetupPacket::get_descriptor(USB_DT_CONFIG, 0, 0, 9))
            }
            EnumState::GetConfig => {
                self.state = EnumState::SetConfig;
                Some(UsbSetupPacket::set_configuration(self.config_value))
            }
            EnumState::SetConfig => {
                self.state = EnumState::Done;
                None
            }
            EnumState::Done | EnumState::Failed => None,
        }
    }

    /// Processes a GetDescriptor response buffer for the full device descriptor.
    ///
    /// Should be called when `state == GetDescriptorFull` and the data has arrived.
    pub fn process_device_descriptor(&mut self, raw: &[u8]) -> Result<()> {
        let desc = UsbDeviceDescriptor::parse(raw)?;
        self.device_desc = Some(desc);
        Ok(())
    }

    /// Marks the enumeration as failed.
    pub fn fail(&mut self) {
        self.state = EnumState::Failed;
    }

    /// Returns true if enumeration completed successfully.
    pub fn is_done(&self) -> bool {
        self.state == EnumState::Done
    }
}

// ---------------------------------------------------------------------------
// UsbHub extension: port power and depth
// ---------------------------------------------------------------------------

impl UsbHub {
    /// Issues SetPortFeature POWER for all ports to power them on.
    ///
    /// Returns an array of setup packets to send (one per port).
    /// In a real driver these would be submitted as control transfers.
    pub fn power_on_all_ports(&self) -> [Option<UsbSetupPacket>; MAX_PORTS_PER_HUB] {
        let mut packets = [None; MAX_PORTS_PER_HUB];
        for p in 1..=self.descriptor.num_ports as usize {
            packets[p - 1] = Some(UsbSetupPacket::set_port_feature(
                p as u8,
                PORT_FEATURE_POWER,
            ));
        }
        packets
    }

    /// Issues SetHubDepth for USB 3.x hubs.
    ///
    /// Returns the setup packet to send, or `None` for non-SS hubs.
    pub fn set_depth_packet(&self) -> Option<UsbSetupPacket> {
        if self.is_superspeed() {
            Some(UsbSetupPacket::set_hub_depth(self.depth))
        } else {
            None
        }
    }

    /// Builds a GetPortStatus setup packet for port `port` (1-based).
    pub fn get_port_status_packet(&self, port: u8) -> Result<UsbSetupPacket> {
        self.check_port(port)?;
        Ok(UsbSetupPacket::get_port_status(port))
    }

    /// Starts a port reset on port `port` (1-based).
    ///
    /// Returns the SetPortFeature RESET setup packet and a [`PortResetCtx`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the port is out of range.
    pub fn start_port_reset(&self, port: u8) -> Result<(UsbSetupPacket, PortResetCtx)> {
        self.check_port(port)?;
        let mut ctx = PortResetCtx::new(port);
        let pkt = ctx.start();
        Ok((pkt, ctx))
    }

    /// Returns the USB speed derived from SS port status bits.
    ///
    /// Only meaningful for SuperSpeed hubs (USB 3.x).
    pub fn ss_port_speed(&self, port: u8) -> Result<UsbSpeed> {
        self.check_port(port)?;
        let status = self.ports()[port as usize - 1].status;
        let speed_bits = (status & SS_PORT_STATUS_SPEED_MASK) >> SS_PORT_STATUS_SPEED_SHIFT;
        Ok(match speed_bits {
            1 => UsbSpeed::Full,
            2 => UsbSpeed::High,
            4 => UsbSpeed::Super,
            5 => UsbSpeed::SuperPlus,
            _ => UsbSpeed::Low,
        })
    }
}
