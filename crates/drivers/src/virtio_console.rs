// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VirtIO console device driver.
//!
//! Implements a VirtIO console device (device type 3) using the MMIO
//! transport. Supports multiple console ports with independent read
//! and write buffers, as well as the control channel for port
//! management (add, remove, open, close, resize).
//!
//! Each port has a 4 KiB receive buffer and a 4 KiB transmit buffer.
//! The control channel uses [`ConsoleControl`] messages to coordinate
//! port lifecycle between the driver and the device.
//!
//! Reference: VirtIO Specification v1.1, §5.3 (Console Device).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// VirtIO console device type ID (§5.3).
pub const VIRTIO_CONSOLE_DEVICE_ID: u32 = 3;

/// Maximum number of ports per console device.
const MAX_PORTS: usize = 4;

/// Per-port buffer size in bytes.
const PORT_BUF_SIZE: usize = 4096;

/// Port name maximum length.
const PORT_NAME_LEN: usize = 32;

/// Maximum number of console devices in the registry.
const MAX_CONSOLES: usize = 4;

// ---------------------------------------------------------------------------
// Feature bits (§5.3.3)
// ---------------------------------------------------------------------------

/// Negotiable feature bits for virtio-console devices.
pub struct VirtioConsoleFeatures;

impl VirtioConsoleFeatures {
    /// Device supports multiple ports.
    pub const MULTIPORT: u32 = 1 << 1;

    /// Device supports emergency write for early boot output.
    pub const EMERG_WRITE: u32 = 1 << 2;

    /// Device reports console size (rows/columns) in config space.
    pub const SIZE: u32 = 1 << 0;
}

// ---------------------------------------------------------------------------
// Console control message (§5.3.6.1)
// ---------------------------------------------------------------------------

/// A virtio console control message exchanged on the control queues.
///
/// Used to manage port lifecycle: adding/removing ports, opening and
/// closing connections, and signaling readiness.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct ConsoleControl {
    /// Port identifier.
    pub id: u32,
    /// Event type (see [`ConsoleControlEvent`]).
    pub event: u16,
    /// Event-specific value.
    pub value: u16,
}

// ---------------------------------------------------------------------------
// Console control events (§5.3.6.1)
// ---------------------------------------------------------------------------

/// Console control event types.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ConsoleControlEvent {
    /// Device/driver is ready.
    #[default]
    DeviceReady,
    /// A new port has been added by the device.
    DeviceAdd,
    /// A port has been removed by the device.
    DeviceRemove,
    /// Port is ready for communication.
    PortReady,
    /// Port is designated as the primary console.
    ConsolePort,
    /// Console size has changed (rows/columns).
    Resize,
    /// Port has been opened.
    Open,
    /// Port has been closed.
    Close,
}

impl ConsoleControlEvent {
    /// Convert a raw u16 event value to a [`ConsoleControlEvent`].
    fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            0 => Some(Self::DeviceReady),
            1 => Some(Self::DeviceAdd),
            2 => Some(Self::DeviceRemove),
            3 => Some(Self::PortReady),
            4 => Some(Self::ConsolePort),
            5 => Some(Self::Resize),
            6 => Some(Self::Open),
            7 => Some(Self::Close),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Console port
// ---------------------------------------------------------------------------

/// A single console port with independent RX/TX buffers.
pub struct ConsolePort {
    /// Port identifier.
    pub id: u32,
    /// Human-readable port name (UTF-8, not null-terminated).
    pub name: [u8; PORT_NAME_LEN],
    /// Number of valid bytes in `name`.
    pub name_len: usize,
    /// Receive ring buffer.
    rx_buf: [u8; PORT_BUF_SIZE],
    /// Number of bytes available for reading in `rx_buf`.
    rx_count: usize,
    /// Transmit ring buffer.
    tx_buf: [u8; PORT_BUF_SIZE],
    /// Number of bytes pending in `tx_buf`.
    tx_count: usize,
    /// Whether this port is currently open.
    pub open: bool,
    /// Whether the host-side of this port is connected.
    pub host_connected: bool,
}

impl ConsolePort {
    /// Create a new closed, empty port with the given `id`.
    const fn new(id: u32) -> Self {
        Self {
            id,
            name: [0u8; PORT_NAME_LEN],
            name_len: 0,
            rx_buf: [0u8; PORT_BUF_SIZE],
            rx_count: 0,
            tx_buf: [0u8; PORT_BUF_SIZE],
            tx_count: 0,
            open: false,
            host_connected: false,
        }
    }

    /// Write data to the port's transmit buffer.
    ///
    /// Returns the number of bytes actually written (may be less than
    /// `data.len()` if the buffer is nearly full).
    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        if !self.open {
            return Err(Error::IoError);
        }

        let space = self.tx_space();
        if space == 0 {
            return Err(Error::Busy);
        }

        let count = data.len().min(space);
        self.tx_buf[self.tx_count..self.tx_count + count].copy_from_slice(&data[..count]);
        self.tx_count += count;
        Ok(count)
    }

    /// Read data from the port's receive buffer.
    ///
    /// Returns the number of bytes actually read (may be less than
    /// `buf.len()` if fewer bytes are available).
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.open {
            return Err(Error::IoError);
        }

        if self.rx_count == 0 {
            return Ok(0);
        }

        let count = buf.len().min(self.rx_count);
        buf[..count].copy_from_slice(&self.rx_buf[..count]);

        // Shift remaining data to the front of the buffer.
        let remaining = self.rx_count - count;
        if remaining > 0 {
            self.rx_buf.copy_within(count..self.rx_count, 0);
        }
        self.rx_count = remaining;
        Ok(count)
    }

    /// Return the number of bytes available for reading.
    pub fn rx_available(&self) -> usize {
        self.rx_count
    }

    /// Return the number of bytes of free space in the transmit buffer.
    pub fn tx_space(&self) -> usize {
        PORT_BUF_SIZE - self.tx_count
    }

    /// Flush the transmit buffer, marking all pending data as sent.
    ///
    /// In a real driver this would push the data through the TX
    /// virtqueue to the device; here we simply clear the buffer.
    pub fn flush(&mut self) -> Result<()> {
        if !self.open {
            return Err(Error::IoError);
        }
        self.tx_count = 0;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// VirtIO console device
// ---------------------------------------------------------------------------

/// VirtIO console device driver.
///
/// Manages up to [`MAX_PORTS`] console ports. Each port has
/// independent RX/TX buffers. A control channel handles port
/// lifecycle events from the device.
pub struct VirtioConsole {
    /// MMIO base address for the device.
    base_addr: u64,
    /// Console ports.
    ports: [ConsolePort; MAX_PORTS],
    /// Number of active ports.
    port_count: usize,
    /// Negotiated feature bits.
    features: u32,
    /// Current device status byte.
    status: u8,
    /// Whether the device is currently in use.
    in_use: bool,
}

impl VirtioConsole {
    /// Create a new, uninitialized virtio-console device.
    pub const fn new() -> Self {
        Self {
            base_addr: 0,
            ports: [
                ConsolePort::new(0),
                ConsolePort::new(1),
                ConsolePort::new(2),
                ConsolePort::new(3),
            ],
            port_count: 0,
            features: 0,
            status: 0,
            in_use: false,
        }
    }

    /// Initialize the console device at the given MMIO `base_addr`
    /// with the negotiated `features`.
    ///
    /// Sets up the first port (port 0) as the default console and
    /// marks the device as in-use.
    pub fn init(&mut self, base_addr: u64, features: u32) -> Result<()> {
        if self.in_use {
            return Err(Error::Busy);
        }

        self.base_addr = base_addr;
        self.features = features;
        self.status = 0;

        // Reset all ports.
        self.ports.iter_mut().enumerate().for_each(|(i, port)| {
            *port = ConsolePort::new(i as u32);
        });
        self.port_count = 0;

        // Open the default port (port 0).
        self.ports[0].open = true;
        self.ports[0].host_connected = true;
        self.port_count = 1;

        self.in_use = true;
        Ok(())
    }

    /// Write data to a specific port.
    ///
    /// Returns the number of bytes written to the port's TX buffer.
    pub fn write_port(&mut self, port_id: u32, data: &[u8]) -> Result<usize> {
        if !self.in_use {
            return Err(Error::IoError);
        }

        let port = self.get_port_mut(port_id)?;
        port.write(data)
    }

    /// Read data from a specific port.
    ///
    /// Returns the number of bytes read from the port's RX buffer.
    pub fn read_port(&mut self, port_id: u32, buf: &mut [u8]) -> Result<usize> {
        if !self.in_use {
            return Err(Error::IoError);
        }

        let port = self.get_port_mut(port_id)?;
        port.read(buf)
    }

    /// Handle a control message from the device.
    ///
    /// Dispatches the control message to the appropriate handler
    /// based on the event type.
    pub fn handle_control(&mut self, ctrl: &ConsoleControl) -> Result<()> {
        if !self.in_use {
            return Err(Error::IoError);
        }

        let event = ConsoleControlEvent::from_raw(ctrl.event).ok_or(Error::InvalidArgument)?;

        match event {
            ConsoleControlEvent::DeviceReady => {
                // Device is ready — nothing to do on our side.
                Ok(())
            }
            ConsoleControlEvent::DeviceAdd => {
                let id = ctrl.id;
                if (id as usize) < MAX_PORTS && self.port_count < MAX_PORTS {
                    self.ports[id as usize] = ConsolePort::new(id);
                    self.port_count += 1;
                    Ok(())
                } else {
                    Err(Error::InvalidArgument)
                }
            }
            ConsoleControlEvent::DeviceRemove => {
                let id = ctrl.id;
                if (id as usize) < MAX_PORTS {
                    self.ports[id as usize].open = false;
                    self.ports[id as usize].host_connected = false;
                    self.port_count = self.port_count.saturating_sub(1);
                    Ok(())
                } else {
                    Err(Error::InvalidArgument)
                }
            }
            ConsoleControlEvent::PortReady => {
                let id = ctrl.id;
                if (id as usize) < MAX_PORTS {
                    self.ports[id as usize].host_connected = true;
                    Ok(())
                } else {
                    Err(Error::InvalidArgument)
                }
            }
            ConsoleControlEvent::ConsolePort => {
                // Mark the port as the primary console.
                // For now, no special handling beyond acknowledgement.
                Ok(())
            }
            ConsoleControlEvent::Resize => {
                // Console resize — upper layers handle the actual
                // terminal resize. We just acknowledge here.
                Ok(())
            }
            ConsoleControlEvent::Open => self.open_port(ctrl.id),
            ConsoleControlEvent::Close => self.close_port(ctrl.id),
        }
    }

    /// Open a port, making it available for I/O.
    pub fn open_port(&mut self, port_id: u32) -> Result<()> {
        let port = self.get_port_mut(port_id)?;
        if port.open {
            return Err(Error::AlreadyExists);
        }
        port.open = true;
        Ok(())
    }

    /// Close a port, flushing any pending data.
    pub fn close_port(&mut self, port_id: u32) -> Result<()> {
        let port = self.get_port_mut(port_id)?;
        if !port.open {
            return Err(Error::IoError);
        }
        port.tx_count = 0;
        port.rx_count = 0;
        port.open = false;
        Ok(())
    }

    /// Handle a virtio-console interrupt.
    ///
    /// Returns the number of events processed (0 if the device is not
    /// in use or no events were pending).
    pub fn handle_interrupt(&mut self) -> Result<u32> {
        if !self.in_use {
            return Ok(0);
        }

        // In a full implementation this would read the ISR status
        // register and process used buffers from the RX and control
        // queues. For now, return 0 events processed.
        Ok(0)
    }

    /// Check whether the device is in use.
    pub fn is_in_use(&self) -> bool {
        self.in_use
    }

    /// Return the number of active ports.
    pub fn port_count(&self) -> usize {
        self.port_count
    }

    /// Return the negotiated feature bits.
    pub fn features(&self) -> u32 {
        self.features
    }

    /// Return the MMIO base address.
    pub fn base_addr(&self) -> u64 {
        self.base_addr
    }

    /// Return a mutable reference to a port by ID.
    fn get_port_mut(&mut self, port_id: u32) -> Result<&mut ConsolePort> {
        let idx = port_id as usize;
        if idx >= MAX_PORTS {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.ports[idx])
    }
}

impl Default for VirtioConsole {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for VirtioConsole {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtioConsole")
            .field("base_addr", &self.base_addr)
            .field("port_count", &self.port_count)
            .field("features", &self.features)
            .field("status", &self.status)
            .field("in_use", &self.in_use)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Console device registry
// ---------------------------------------------------------------------------

/// Registry for VirtIO console devices.
///
/// Supports up to [`MAX_CONSOLES`] devices. Provides registration
/// and lookup by index.
pub struct VirtioConsoleRegistry {
    /// Registered console devices.
    consoles: [VirtioConsole; MAX_CONSOLES],
    /// Number of registered devices.
    count: usize,
}

impl Default for VirtioConsoleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioConsoleRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            consoles: [
                VirtioConsole::new(),
                VirtioConsole::new(),
                VirtioConsole::new(),
                VirtioConsole::new(),
            ],
            count: 0,
        }
    }

    /// Register a new console device, returning its index.
    pub fn register(&mut self, console: VirtioConsole) -> Result<usize> {
        if self.count >= MAX_CONSOLES {
            return Err(Error::Busy);
        }
        let idx = self.count;
        self.consoles[idx] = console;
        self.count += 1;
        Ok(idx)
    }

    /// Get an immutable reference to a registered console by index.
    pub fn get(&self, index: usize) -> Option<&VirtioConsole> {
        if index < self.count {
            Some(&self.consoles[index])
        } else {
            None
        }
    }

    /// Get a mutable reference to a registered console by index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut VirtioConsole> {
        if index < self.count {
            Some(&mut self.consoles[index])
        } else {
            None
        }
    }

    /// Return the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
