// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Bluetooth HCI (Host Controller Interface) abstraction.
//!
//! Provides core data structures and device management for Bluetooth
//! controllers, including HCI command/event/ACL data transport,
//! device scanning, connection management, and a registry for
//! managing multiple Bluetooth adapters.
//!
//! # Supported Bluetooth versions
//!
//! | Version | Status  |
//! |---------|---------|
//! | 4.0     | Defined |
//! | 4.1     | Defined |
//! | 4.2     | Defined |
//! | 5.0     | Defined |
//! | 5.1     | Defined |
//! | 5.2     | Default |
//! | 5.3     | Defined |
//!
//! # Design
//!
//! [`BtDevice`] represents a single Bluetooth controller with HCI
//! command/event exchange, scanning, and connection capabilities.
//! [`BtRegistry`] manages up to 4 adapters, identified by
//! monotonically increasing IDs.  All state is stored in fixed-size
//! arrays suitable for a `#![no_std]` kernel environment.

use oncrix_lib::{Error, Result};

// =========================================================================
// Constants
// =========================================================================

/// Maximum number of Bluetooth adapters managed by the registry.
const MAX_BT_DEVICES: usize = 4;

/// Maximum number of discovered peers tracked per registry.
const MAX_BT_PEERS: usize = 16;

/// Maximum HCI command parameter length.
const _HCI_CMD_PARAM_LEN: usize = 255;

/// Maximum HCI event parameter length.
const _HCI_EVT_PARAM_LEN: usize = 255;

/// Maximum HCI ACL data payload length.
const _HCI_ACL_DATA_LEN: usize = 1024;

/// Maximum Bluetooth device name length (per spec).
const _BT_NAME_LEN: usize = 248;

// =========================================================================
// Enumerations
// =========================================================================

/// Bluetooth specification version.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum BtVersion {
    /// Bluetooth 4.0 (LE introduction).
    Bt40,
    /// Bluetooth 4.1.
    Bt41,
    /// Bluetooth 4.2.
    Bt42,
    /// Bluetooth 5.0.
    Bt50,
    /// Bluetooth 5.1.
    Bt51,
    /// Bluetooth 5.2.
    #[default]
    Bt52,
    /// Bluetooth 5.3.
    Bt53,
}

/// Bluetooth controller operational state.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum BtState {
    /// Controller is powered off.
    #[default]
    Off,
    /// Controller is initializing (reset in progress).
    Initializing,
    /// Controller is on and idle.
    On,
    /// Controller is scanning for nearby devices.
    Scanning,
    /// Controller is establishing a connection.
    Connecting,
    /// Controller has an active connection.
    Connected,
}

/// Bluetooth device address type.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum BtAddrType {
    /// Public device address (from IEEE registration).
    #[default]
    Public,
    /// Random device address (static or resolvable).
    Random,
}

/// HCI packet type indicator.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum HciPacketType {
    /// HCI command packet (host to controller).
    #[default]
    Command,
    /// ACL data packet.
    AclData,
    /// SCO data packet.
    ScoData,
    /// HCI event packet (controller to host).
    Event,
}

// =========================================================================
// Bluetooth Address
// =========================================================================

/// A 48-bit Bluetooth device address (BD_ADDR).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BtAddress {
    /// 6-byte device address in little-endian order.
    pub addr: [u8; 6],
    /// Address type (public or random).
    pub addr_type: BtAddrType,
}

// =========================================================================
// HCI Structures
// =========================================================================

/// HCI command packet.
///
/// Commands are sent from the host to the Bluetooth controller.
/// The opcode encodes both the OGF (Opcode Group Field) and OCF
/// (Opcode Command Field).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct HciCommand {
    /// Command opcode (OGF << 10 | OCF).
    pub opcode: u16,
    /// Number of valid parameter bytes.
    pub param_len: u8,
    /// Parameter data buffer.
    pub params: [u8; 255],
}

impl HciCommand {
    /// Extracts the Opcode Group Field (upper 6 bits of the opcode).
    pub fn ogf(&self) -> u16 {
        self.opcode >> 10
    }

    /// Extracts the Opcode Command Field (lower 10 bits of the opcode).
    pub fn ocf(&self) -> u16 {
        self.opcode & 0x03FF
    }
}

/// HCI event packet.
///
/// Events are sent from the Bluetooth controller to the host to
/// indicate command completion, status changes, or asynchronous
/// notifications.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct HciEvent {
    /// Event code identifying the event type.
    pub event_code: u8,
    /// Number of valid parameter bytes.
    pub param_len: u8,
    /// Parameter data buffer.
    pub params: [u8; 255],
}

/// HCI ACL (Asynchronous Connection-Less) data packet.
///
/// Used for transferring data over established Bluetooth connections.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct HciAclData {
    /// Connection handle (12 bits, from controller).
    pub handle: u16,
    /// Packet boundary and broadcast flags.
    pub flags: u8,
    /// Number of valid data bytes.
    pub data_len: u16,
    /// Data payload buffer.
    pub data: [u8; 1024],
}

// =========================================================================
// BtDevice
// =========================================================================

/// A Bluetooth controller device.
///
/// Represents a single Bluetooth adapter with HCI transport, device
/// state management, scanning, and connection capabilities.
pub struct BtDevice {
    /// Unique device identifier assigned by the registry.
    id: u64,
    /// Device Bluetooth address.
    addr: BtAddress,
    /// Current operational state.
    state: BtState,
    /// Bluetooth specification version supported.
    version: BtVersion,
    /// Local device name (Bluetooth friendly name).
    name: [u8; 248],
    /// Number of valid bytes in [`name`](Self::name).
    name_len: usize,
    /// Whether this device slot is in use.
    in_use: bool,
}

impl BtDevice {
    /// Initializes the Bluetooth controller.
    ///
    /// Transitions the controller from [`BtState::Off`] through
    /// [`BtState::Initializing`] to [`BtState::On`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the controller is
    /// already initialized (not in [`BtState::Off`]).
    pub fn init(&mut self) -> Result<()> {
        if self.state != BtState::Off {
            return Err(Error::InvalidArgument);
        }
        self.state = BtState::Initializing;
        // Stub: in a real driver this would send HCI_Reset and wait
        // for the command-complete event.
        self.state = BtState::On;
        Ok(())
    }

    /// Resets the Bluetooth controller back to [`BtState::Off`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the controller is
    /// already off.
    pub fn reset(&mut self) -> Result<()> {
        if self.state == BtState::Off {
            return Err(Error::InvalidArgument);
        }
        self.state = BtState::Off;
        Ok(())
    }

    /// Sends an HCI command to the controller.
    ///
    /// Validates that the controller is powered on and the parameter
    /// length does not exceed the buffer.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the controller is off or the
    ///   parameter length exceeds 255.
    pub fn send_command(&mut self, cmd: &HciCommand) -> Result<()> {
        if self.state == BtState::Off {
            return Err(Error::InvalidArgument);
        }
        if cmd.param_len as usize > 255 {
            return Err(Error::InvalidArgument);
        }
        // Stub: a real driver would write to the HCI transport.
        Ok(())
    }

    /// Receives an HCI event from the controller.
    ///
    /// In a real driver this would dequeue an event from the
    /// controller's event queue.  Here we return an empty event.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the controller is off.
    pub fn recv_event(&self) -> Result<HciEvent> {
        if self.state == BtState::Off {
            return Err(Error::InvalidArgument);
        }
        // Stub: no event available.
        Ok(HciEvent {
            event_code: 0,
            param_len: 0,
            params: [0u8; 255],
        })
    }

    /// Sends an HCI ACL data packet to the controller.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the controller is not
    ///   connected or data length exceeds the buffer.
    pub fn send_acl(&mut self, data: &HciAclData) -> Result<()> {
        if self.state != BtState::Connected {
            return Err(Error::InvalidArgument);
        }
        if data.data_len as usize > 1024 {
            return Err(Error::InvalidArgument);
        }
        // Stub: a real driver would write to the HCI ACL transport.
        Ok(())
    }

    /// Receives an HCI ACL data packet from the controller.
    ///
    /// In a real driver this would dequeue data from the ACL receive
    /// buffer.  Here we return an empty packet.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the controller is not
    /// connected.
    pub fn recv_acl(&self) -> Result<HciAclData> {
        if self.state != BtState::Connected {
            return Err(Error::InvalidArgument);
        }
        Ok(HciAclData {
            handle: 0,
            flags: 0,
            data_len: 0,
            data: [0u8; 1024],
        })
    }

    /// Starts scanning for nearby Bluetooth devices.
    ///
    /// Transitions the controller to [`BtState::Scanning`].
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the controller is off.
    /// - [`Error::Busy`] if already scanning or connecting.
    pub fn start_scan(&mut self) -> Result<()> {
        match self.state {
            BtState::Off | BtState::Initializing => {
                return Err(Error::InvalidArgument);
            }
            BtState::Scanning | BtState::Connecting => {
                return Err(Error::Busy);
            }
            BtState::On | BtState::Connected => {}
        }
        self.state = BtState::Scanning;
        Ok(())
    }

    /// Stops an active scan.
    ///
    /// Returns the controller to [`BtState::On`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the controller is not
    /// currently scanning.
    pub fn stop_scan(&mut self) -> Result<()> {
        if self.state != BtState::Scanning {
            return Err(Error::InvalidArgument);
        }
        self.state = BtState::On;
        Ok(())
    }

    /// Initiates a connection to a remote Bluetooth device.
    ///
    /// Transitions through [`BtState::Connecting`] to
    /// [`BtState::Connected`] and returns a connection handle.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the controller is off or
    ///   initializing.
    /// - [`Error::Busy`] if already connecting or connected.
    pub fn connect(&mut self, _addr: &BtAddress) -> Result<u16> {
        match self.state {
            BtState::Off | BtState::Initializing => {
                return Err(Error::InvalidArgument);
            }
            BtState::Connecting | BtState::Connected => {
                return Err(Error::Busy);
            }
            BtState::On | BtState::Scanning => {}
        }
        self.state = BtState::Connecting;
        // Stub: a real driver would send HCI_Create_Connection and
        // wait for the connection-complete event.
        self.state = BtState::Connected;
        // Return a stub connection handle.
        Ok(1)
    }

    /// Disconnects an active connection by handle.
    ///
    /// Returns the controller to [`BtState::On`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the controller is not
    /// currently connected.
    pub fn disconnect(&mut self, _handle: u16) -> Result<()> {
        if self.state != BtState::Connected {
            return Err(Error::InvalidArgument);
        }
        self.state = BtState::On;
        Ok(())
    }

    /// Returns the current operational state.
    pub fn state(&self) -> BtState {
        self.state
    }

    /// Returns the device Bluetooth address.
    pub fn addr(&self) -> &BtAddress {
        &self.addr
    }

    /// Returns the Bluetooth version supported by this controller.
    pub fn version(&self) -> BtVersion {
        self.version
    }

    /// Returns the local device name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// =========================================================================
// BtPeerInfo
// =========================================================================

/// Information about a discovered or connected remote Bluetooth device.
#[derive(Clone, Copy)]
pub struct BtPeerInfo {
    /// Remote device address.
    pub addr: BtAddress,
    /// Remote device name (Bluetooth friendly name).
    pub name: [u8; 248],
    /// Number of valid bytes in [`name`](Self::name).
    pub name_len: usize,
    /// Received signal strength indicator (dBm).
    pub rssi: i8,
    /// Whether the peer is currently connected.
    pub connected: bool,
    /// Connection handle (valid only when connected).
    pub handle: u16,
}

// =========================================================================
// BtRegistry
// =========================================================================

/// Registry for managing multiple Bluetooth controller devices.
///
/// Supports up to [`MAX_BT_DEVICES`] (4) adapters and tracks up to
/// [`MAX_BT_PEERS`] (16) discovered peers.  Each device is identified
/// by a unique monotonically increasing ID assigned at registration.
pub struct BtRegistry {
    /// Registered Bluetooth controllers.
    devices: [BtDevice; MAX_BT_DEVICES],
    /// Number of active devices.
    count: usize,
    /// Next device ID to assign.
    next_id: u64,
    /// Discovered remote peers.
    peers: [BtPeerInfo; MAX_BT_PEERS],
    /// Number of valid entries in the peer table.
    peer_count: usize,
}

impl Default for BtRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BtRegistry {
    /// Creates an empty Bluetooth registry.
    pub const fn new() -> Self {
        const DEFAULT_DEVICE: BtDevice = BtDevice {
            id: 0,
            addr: BtAddress {
                addr: [0; 6],
                addr_type: BtAddrType::Public,
            },
            state: BtState::Off,
            version: BtVersion::Bt52,
            name: [0u8; 248],
            name_len: 0,
            in_use: false,
        };

        const DEFAULT_PEER: BtPeerInfo = BtPeerInfo {
            addr: BtAddress {
                addr: [0; 6],
                addr_type: BtAddrType::Public,
            },
            name: [0u8; 248],
            name_len: 0,
            rssi: 0,
            connected: false,
            handle: 0,
        };

        Self {
            devices: [DEFAULT_DEVICE; MAX_BT_DEVICES],
            count: 0,
            next_id: 1,
            peers: [DEFAULT_PEER; MAX_BT_PEERS],
            peer_count: 0,
        }
    }

    /// Registers a new Bluetooth adapter with the given address.
    ///
    /// Returns the unique device ID on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, addr: &BtAddress) -> Result<u64> {
        let slot = self
            .devices
            .iter()
            .position(|d| !d.in_use)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id += 1;

        self.devices[slot] = BtDevice {
            id,
            addr: *addr,
            state: BtState::Off,
            version: BtVersion::default(),
            name: [0u8; 248],
            name_len: 0,
            in_use: true,
        };
        self.count += 1;

        Ok(id)
    }

    /// Unregisters a Bluetooth adapter by ID.
    ///
    /// Marks the device slot as free.  Does nothing if the ID is
    /// not found.
    pub fn unregister(&mut self, id: u64) {
        if let Some(dev) = self.devices.iter_mut().find(|d| d.in_use && d.id == id) {
            dev.in_use = false;
            dev.state = BtState::Off;
            self.count -= 1;
        }
    }

    /// Returns an immutable reference to a device by ID.
    ///
    /// Returns `None` if the device is not found.
    pub fn get(&self, id: u64) -> Option<&BtDevice> {
        self.devices.iter().find(|d| d.in_use && d.id == id)
    }

    /// Returns a mutable reference to a device by ID.
    ///
    /// Returns `None` if the device is not found.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut BtDevice> {
        self.devices.iter_mut().find(|d| d.in_use && d.id == id)
    }

    /// Returns a slice of discovered peers.
    pub fn discovered_peers(&self) -> &[BtPeerInfo] {
        &self.peers[..self.peer_count]
    }

    /// Clears the discovered peers table.
    pub fn clear_peers(&mut self) {
        self.peer_count = 0;
    }

    /// Returns the number of registered Bluetooth adapters.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` when no adapters are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
