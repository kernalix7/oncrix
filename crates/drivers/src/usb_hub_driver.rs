// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! USB hub driver (port status, reset, power management).
//!
//! Implements the USB hub class driver as defined in USB 2.0 spec Chapter 11
//! and USB 3.2 spec Chapter 10. Manages port status, power-on, reset,
//! suspend/resume, and device attachment detection.
//!
//! # Hub Classes
//!
//! - **USB 2.0 Hub**: bDeviceClass=0x09, control pipe only for hub requests.
//! - **USB 3.x SuperSpeed Hub**: Uses SuperSpeed Hub descriptor, link training.
//!
//! # Hub Descriptor (bDescriptorType = 0x29 for FS/HS, 0x2A for SS)
//!
//! | Offset | Size | Field               |
//! |--------|------|---------------------|
//! |  0     |  1   | bDescLength         |
//! |  1     |  1   | bDescriptorType     |
//! |  2     |  1   | bNbrPorts           |
//! |  3     |  2   | wHubCharacteristics |
//! |  5     |  1   | bPwrOn2PwrGood      |
//! |  6     |  1   | bHubContrCurrent    |
//! |  7     |  N   | DeviceRemovable     |
//!
//! # Port Status Bits (GetPortStatus response)
//!
//! | Bit | Status          | Change                |
//! |-----|-----------------|-----------------------|
//! |  0  | PORT_CONNECTION | C_PORT_CONNECTION     |
//! |  1  | PORT_ENABLE     | C_PORT_ENABLE         |
//! |  2  | PORT_SUSPEND    | C_PORT_SUSPEND        |
//! |  3  | PORT_OVER_CURRENT | C_PORT_OVER_CURRENT |
//! |  4  | PORT_RESET      | C_PORT_RESET          |
//! |  8  | PORT_POWER      | —                     |
//! |  9  | PORT_LOW_SPEED  | —                     |
//! | 10  | PORT_HIGH_SPEED | —                     |
//!
//! Reference: USB 2.0 Specification, Section 11; USB 3.2 Specification, Section 10.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of ports on a USB 2.0 hub.
pub const HUB_MAX_PORTS: usize = 15;
/// Hub descriptor type (USB 2.0).
pub const HUB_DESCRIPTOR_TYPE: u8 = 0x29;
/// SuperSpeed hub descriptor type (USB 3.x).
pub const SS_HUB_DESCRIPTOR_TYPE: u8 = 0x2A;
/// Hub class code.
pub const HUB_CLASS: u8 = 0x09;

// ---------------------------------------------------------------------------
// Hub class request codes (bRequest)
// ---------------------------------------------------------------------------

/// GetStatus (hub or port).
pub const HUB_REQ_GET_STATUS: u8 = 0x00;
/// ClearFeature (hub or port).
pub const HUB_REQ_CLEAR_FEATURE: u8 = 0x01;
/// SetFeature (hub or port).
pub const HUB_REQ_SET_FEATURE: u8 = 0x03;
/// GetDescriptor (hub descriptor).
pub const HUB_REQ_GET_DESCRIPTOR: u8 = 0x06;
/// SetDescriptor.
pub const _HUB_REQ_SET_DESCRIPTOR: u8 = 0x07;
/// ClearTTBuffer.
pub const _HUB_REQ_CLEAR_TT_BUF: u8 = 0x08;
/// ResetTT.
pub const _HUB_REQ_RESET_TT: u8 = 0x09;
/// GetTTState.
pub const _HUB_REQ_GET_TT_STATE: u8 = 0x0A;
/// StopTT.
pub const _HUB_REQ_STOP_TT: u8 = 0x0B;

// ---------------------------------------------------------------------------
// Hub and Port feature selectors (wValue for Set/ClearFeature)
// ---------------------------------------------------------------------------

/// PORT_CONNECTION feature (change only, clear).
pub const PORT_CONNECTION: u16 = 0;
/// PORT_ENABLE feature.
pub const PORT_ENABLE: u16 = 1;
/// PORT_SUSPEND feature.
pub const PORT_SUSPEND: u16 = 2;
/// PORT_OVER_CURRENT feature.
pub const PORT_OVER_CURRENT: u16 = 3;
/// PORT_RESET feature.
pub const PORT_RESET: u16 = 4;
/// PORT_POWER feature.
pub const PORT_POWER: u16 = 8;
/// PORT_LOW_SPEED feature.
pub const _PORT_LOW_SPEED: u16 = 9;
/// C_PORT_CONNECTION change bit.
pub const C_PORT_CONNECTION: u16 = 16;
/// C_PORT_ENABLE change bit.
pub const C_PORT_ENABLE: u16 = 17;
/// C_PORT_SUSPEND change bit.
pub const _C_PORT_SUSPEND: u16 = 18;
/// C_PORT_OVER_CURRENT change bit.
pub const C_PORT_OVER_CURRENT: u16 = 19;
/// C_PORT_RESET change bit.
pub const C_PORT_RESET: u16 = 20;

// ---------------------------------------------------------------------------
// Port status word bits
// ---------------------------------------------------------------------------

/// Port status: device connected.
pub const PS_CONNECTION: u32 = 1 << 0;
/// Port status: port enabled.
pub const PS_ENABLE: u32 = 1 << 1;
/// Port status: suspended.
pub const PS_SUSPEND: u32 = 1 << 2;
/// Port status: over-current.
pub const PS_OVER_CURRENT: u32 = 1 << 3;
/// Port status: reset in progress.
pub const PS_RESET: u32 = 1 << 4;
/// Port status: power enabled.
pub const PS_POWER: u32 = 1 << 8;
/// Port status: low-speed device.
pub const PS_LOW_SPEED: u32 = 1 << 9;
/// Port status: high-speed device.
pub const PS_HIGH_SPEED: u32 = 1 << 10;
/// Port status change: connection change.
pub const PS_C_CONNECTION: u32 = 1 << 16;
/// Port status change: enable change.
pub const PS_C_ENABLE: u32 = 1 << 17;
/// Port status change: reset complete.
pub const PS_C_RESET: u32 = 1 << 20;

// ---------------------------------------------------------------------------
// Hub speed enum
// ---------------------------------------------------------------------------

/// USB device speed reported by hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbSpeed {
    /// Low speed (1.5 Mbps).
    Low,
    /// Full speed (12 Mbps).
    Full,
    /// High speed (480 Mbps).
    High,
    /// SuperSpeed (5+ Gbps).
    Super,
}

// ---------------------------------------------------------------------------
// Port state
// ---------------------------------------------------------------------------

/// State of a single hub port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    /// No device attached.
    Disconnected,
    /// Device attached, pending reset.
    Connected,
    /// Reset in progress.
    Resetting,
    /// Device enabled and ready.
    Enabled,
    /// Port suspended.
    Suspended,
    /// Port disabled due to overcurrent.
    OverCurrent,
}

impl Default for PortState {
    fn default() -> Self {
        Self::Disconnected
    }
}

// ---------------------------------------------------------------------------
// Port info
// ---------------------------------------------------------------------------

/// Runtime information about a hub port.
#[derive(Debug, Clone, Copy, Default)]
pub struct HubPort {
    /// Current port state.
    pub state: PortState,
    /// Last read port status word (status | (change << 16)).
    pub status: u32,
    /// Device address assigned to the attached device (0 if none).
    pub device_address: u8,
    /// Speed of the attached device.
    pub speed: Option<UsbSpeed>,
}

impl HubPort {
    /// Returns `true` if a device is connected.
    pub fn is_connected(&self) -> bool {
        self.status & PS_CONNECTION != 0
    }

    /// Returns `true` if the port has a connection change pending.
    pub fn has_connection_change(&self) -> bool {
        self.status & PS_C_CONNECTION != 0
    }

    /// Returns `true` if reset completed (C_RESET set).
    pub fn reset_complete(&self) -> bool {
        self.status & PS_C_RESET != 0
    }

    /// Decodes device speed from port status bits.
    pub fn decode_speed(status: u32) -> UsbSpeed {
        if status & PS_LOW_SPEED != 0 {
            UsbSpeed::Low
        } else if status & PS_HIGH_SPEED != 0 {
            UsbSpeed::High
        } else {
            UsbSpeed::Full
        }
    }
}

// ---------------------------------------------------------------------------
// Hub descriptor
// ---------------------------------------------------------------------------

/// USB 2.0 hub descriptor.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct HubDescriptor {
    /// Descriptor length.
    pub b_desc_length: u8,
    /// Descriptor type (0x29).
    pub b_descriptor_type: u8,
    /// Number of downstream ports.
    pub b_nbr_ports: u8,
    /// Hub characteristics.
    pub w_hub_characteristics: u16,
    /// Power-on to power-good time (in 2 ms units).
    pub b_pwr_on_2_pwr_good: u8,
    /// Max current requirements (mA).
    pub b_hub_contr_current: u8,
    /// Device removable bitmask (1 bit per port, max 8 for 7-port hub + root).
    pub device_removable: u8,
    /// Port power control mask.
    pub port_pwr_ctrl_mask: u8,
}

// ---------------------------------------------------------------------------
// Hub driver
// ---------------------------------------------------------------------------

/// USB hub driver state.
pub struct UsbHubDriver {
    /// USB device address of the hub.
    pub device_address: u8,
    /// Number of ports on this hub.
    pub num_ports: u8,
    /// Hub descriptor.
    pub descriptor: HubDescriptor,
    /// Per-port state.
    pub ports: [HubPort; HUB_MAX_PORTS],
    /// Whether the hub is initialized.
    pub initialized: bool,
}

impl UsbHubDriver {
    /// Creates a new hub driver for the given USB device address.
    pub const fn new(device_address: u8) -> Self {
        Self {
            device_address,
            num_ports: 0,
            descriptor: HubDescriptor {
                b_desc_length: 0,
                b_descriptor_type: HUB_DESCRIPTOR_TYPE,
                b_nbr_ports: 0,
                w_hub_characteristics: 0,
                b_pwr_on_2_pwr_good: 0,
                b_hub_contr_current: 0,
                device_removable: 0,
                port_pwr_ctrl_mask: 0,
            },
            ports: [HubPort {
                state: PortState::Disconnected,
                status: 0,
                device_address: 0,
                speed: None,
            }; HUB_MAX_PORTS],
            initialized: false,
        }
    }

    /// Initializes the hub: reads descriptor and powers on all ports.
    ///
    /// `get_hub_descriptor` must issue a GetDescriptor(Hub) control transfer.
    /// `set_port_feature` must issue a SetFeature(port, feature) control transfer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `num_ports` exceeds `HUB_MAX_PORTS`.
    pub fn init<F, G>(
        &mut self,
        descriptor: HubDescriptor,
        mut set_port_feature: F,
        _get_port_status: G,
    ) -> Result<()>
    where
        F: FnMut(u8, u16) -> Result<()>,
        G: FnMut(u8) -> Result<u32>,
    {
        if descriptor.b_nbr_ports as usize > HUB_MAX_PORTS {
            return Err(Error::InvalidArgument);
        }
        self.descriptor = descriptor;
        self.num_ports = descriptor.b_nbr_ports;

        // Power on all downstream ports.
        for port in 1..=self.num_ports {
            set_port_feature(port, PORT_POWER)?;
        }
        // Wait for power-on delay: bPwrOn2PwrGood × 2 ms.
        // (Actual delay handled by the controller; we just record the value.)

        self.initialized = true;
        Ok(())
    }

    /// Resets a port and waits for reset completion.
    ///
    /// `set_feature` issues SetFeature(port, PORT_RESET).
    /// `get_status` reads the port status.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `port` is out of range.
    /// Returns [`Error::IoError`] if reset does not complete.
    pub fn reset_port<F, G>(&mut self, port: u8, set_feature: F, get_status: G) -> Result<UsbSpeed>
    where
        F: Fn(u8, u16) -> Result<()>,
        G: Fn(u8) -> Result<u32>,
    {
        if port == 0 || port as usize > self.num_ports as usize {
            return Err(Error::InvalidArgument);
        }
        let idx = (port - 1) as usize;
        self.ports[idx].state = PortState::Resetting;

        // Issue PORT_RESET.
        set_feature(port, PORT_RESET)?;

        // Poll for C_PORT_RESET (timeout after 500 ms equivalent iterations).
        for _ in 0..50_000u32 {
            let status = get_status(port)?;
            if status & PS_C_RESET != 0 {
                // Clear the change bit.
                set_feature(port, C_PORT_RESET)?;
                self.ports[idx].status = status;
                let speed = HubPort::decode_speed(status);
                self.ports[idx].speed = Some(speed);
                self.ports[idx].state = PortState::Enabled;
                return Ok(speed);
            }
        }
        self.ports[idx].state = PortState::Disconnected;
        Err(Error::IoError)
    }

    /// Handles a port status change event.
    ///
    /// Returns a bitmask of ports with pending changes (bit 1 = port 1, etc.).
    ///
    /// `get_port_status` reads the 32-bit port status word for a given port.
    pub fn handle_status_change<G>(&mut self, get_port_status: G) -> u16
    where
        G: Fn(u8) -> Result<u32>,
    {
        let mut changed_ports = 0u16;
        for port in 1..=self.num_ports {
            let idx = (port - 1) as usize;
            if let Ok(status) = get_port_status(port) {
                if status != self.ports[idx].status {
                    self.ports[idx].status = status;
                    if status & (PS_C_CONNECTION | PS_C_ENABLE | PS_C_RESET) != 0 {
                        changed_ports |= 1 << port;
                    }
                    // Update state based on status.
                    if status & PS_CONNECTION == 0 {
                        self.ports[idx].state = PortState::Disconnected;
                        self.ports[idx].speed = None;
                    } else if status & PS_ENABLE != 0 {
                        self.ports[idx].state = PortState::Enabled;
                    }
                }
            }
        }
        changed_ports
    }

    /// Returns the state of a port (1-based).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `port` is out of range.
    pub fn port_state(&self, port: u8) -> Result<PortState> {
        if port == 0 || port as usize > self.num_ports as usize {
            return Err(Error::InvalidArgument);
        }
        Ok(self.ports[(port - 1) as usize].state)
    }

    /// Returns `true` if the hub is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for UsbHubDriver {
    fn default() -> Self {
        Self::new(0)
    }
}
