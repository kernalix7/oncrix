// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VirtIO serial port driver.
//!
//! Implements the VirtIO console/serial device (device ID 3) as
//! defined in the VirtIO 1.2 specification §5.3. Supports one or
//! more virtual serial ports over the standard VirtIO MMIO transport.
//!
//! # Architecture
//!
//! ```text
//! Host side                     Guest side
//! ┌─────────────┐               ┌──────────────────┐
//! │ VirtIO      │  virtqueue 0  │ SerialPort 0 RX  │
//! │ console     │◄─────────────►│ virtqueue 1 TX   │
//! │ device      │  virtqueue 2  │ SerialPort 1 RX  │
//! │ (QEMU etc.) │◄─────────────►│ virtqueue 3 TX   │
//! └─────────────┘               └──────────────────┘
//! ```
//!
//! Each port occupies two consecutive virtqueues: even index for RX
//! (device → driver) and odd index for TX (driver → device). Port 0
//! is special: queue pair (0, 1). Port N uses queues (2N, 2N+1).
//!
//! # Usage
//!
//! 1. Create a [`VirtioSerial`] with the MMIO base address.
//! 2. Call [`VirtioSerial::init`] to negotiate features and set up queues.
//! 3. Use [`VirtioSerial::write`] / [`VirtioSerial::read`] on a port.
//!
//! Reference: VirtIO Specification v1.2 §5.3 (Console Device).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// VirtIO device type ID for the console/serial device.
pub const VIRTIO_CONSOLE_DEVICE_ID: u32 = 3;

/// VirtIO console feature: multiport support.
pub const VIRTIO_CONSOLE_F_MULTIPORT: u32 = 1 << 1;

/// VirtIO console feature: emergency write.
pub const VIRTIO_CONSOLE_F_EMERG_WRITE: u32 = 1 << 2;

/// Maximum number of serial ports per device.
pub const MAX_PORTS: usize = 4;

/// Maximum number of VirtIO serial devices managed globally.
const MAX_DEVICES: usize = 4;

/// VirtQueue ring size (number of descriptors).
const QUEUE_SIZE: usize = 64;

/// Maximum bytes per TX/RX buffer.
pub const PORT_BUFFER_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// VirtIO MMIO register offsets
// ---------------------------------------------------------------------------

/// Magic value register (should read 0x74726976 = "virt").
const VIRTIO_MMIO_MAGIC_VALUE: u64 = 0x000;

/// Device version register (should be 2 for VirtIO 1.x).
const VIRTIO_MMIO_VERSION: u64 = 0x004;

/// Device ID register.
const VIRTIO_MMIO_DEVICE_ID: u64 = 0x008;

/// Vendor ID register.
const _VIRTIO_MMIO_VENDOR_ID: u64 = 0x00C;

/// Device feature select register.
const VIRTIO_MMIO_DEVICE_FEATURES_SEL: u64 = 0x010;

/// Device features register (read).
const VIRTIO_MMIO_DEVICE_FEATURES: u64 = 0x014;

/// Driver feature select register.
const VIRTIO_MMIO_DRIVER_FEATURES_SEL: u64 = 0x020;

/// Driver features register (write).
const VIRTIO_MMIO_DRIVER_FEATURES: u64 = 0x024;

/// Queue select register.
const VIRTIO_MMIO_QUEUE_SEL: u64 = 0x030;

/// Queue num max register (read).
const _VIRTIO_MMIO_QUEUE_NUM_MAX: u64 = 0x034;

/// Queue num register (write).
const VIRTIO_MMIO_QUEUE_NUM: u64 = 0x038;

/// Queue ready register.
const VIRTIO_MMIO_QUEUE_READY: u64 = 0x044;

/// Queue notify register (write).
const VIRTIO_MMIO_QUEUE_NOTIFY: u64 = 0x050;

/// Interrupt status register (read).
const VIRTIO_MMIO_INTERRUPT_STATUS: u64 = 0x060;

/// Interrupt acknowledge register (write).
const VIRTIO_MMIO_INTERRUPT_ACK: u64 = 0x064;

/// Device status register.
const VIRTIO_MMIO_STATUS: u64 = 0x070;

/// Queue descriptor area low register.
const VIRTIO_MMIO_QUEUE_DESC_LOW: u64 = 0x080;

/// Queue descriptor area high register.
const VIRTIO_MMIO_QUEUE_DESC_HIGH: u64 = 0x084;

/// Queue driver area (avail ring) low register.
const VIRTIO_MMIO_QUEUE_AVAIL_LOW: u64 = 0x090;

/// Queue driver area (avail ring) high register.
const VIRTIO_MMIO_QUEUE_AVAIL_HIGH: u64 = 0x094;

/// Queue device area (used ring) low register.
const VIRTIO_MMIO_QUEUE_USED_LOW: u64 = 0x0A0;

/// Queue device area (used ring) high register.
const VIRTIO_MMIO_QUEUE_USED_HIGH: u64 = 0x0A4;

/// Device configuration space base offset.
const VIRTIO_MMIO_CONFIG: u64 = 0x100;

// ---------------------------------------------------------------------------
// VirtIO status bits
// ---------------------------------------------------------------------------

/// Device status: acknowledge bit.
const VIRTIO_STATUS_ACKNOWLEDGE: u32 = 1;

/// Device status: driver bit.
const VIRTIO_STATUS_DRIVER: u32 = 2;

/// Device status: driver OK bit.
const VIRTIO_STATUS_DRIVER_OK: u32 = 4;

/// Device status: features OK bit.
const VIRTIO_STATUS_FEATURES_OK: u32 = 8;

/// Device status: failed bit.
const VIRTIO_STATUS_FAILED: u32 = 128;

/// VirtIO MMIO magic number.
const VIRTIO_MAGIC: u32 = 0x74726976;

// ---------------------------------------------------------------------------
// VirtIO console config space
// ---------------------------------------------------------------------------

/// VirtIO console device configuration space.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct VirtioConsoleConfig {
    /// Number of columns in the display.
    pub cols: u16,
    /// Number of rows in the display.
    pub rows: u16,
    /// Maximum number of ports (if MULTIPORT feature is negotiated).
    pub max_nr_ports: u32,
    /// Emergency write register (if EMERG_WRITE feature is negotiated).
    pub emerg_wr: u32,
}

// ---------------------------------------------------------------------------
// VirtIO console control message
// ---------------------------------------------------------------------------

/// VirtIO console control message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ConsoleControlEvent {
    /// Device → driver: device is ready.
    DeviceReady = 0,
    /// Driver → device: driver is ready.
    PortReady = 3,
    /// Device → driver: console port.
    ConsolePort = 2,
    /// Device → driver: port resize.
    Resize = 1,
    /// Device → driver: port open.
    PortOpen = 5,
    /// Device → driver: port name.
    PortName = 6,
    /// Device → driver: port remove.
    PortRemove = 7,
}

/// VirtIO console control message header.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct ConsoleControlMsg {
    /// Port index this message refers to.
    pub id: u32,
    /// Event code (see [`ConsoleControlEvent`]).
    pub event: u16,
    /// Value associated with the event.
    pub value: u16,
}

// ---------------------------------------------------------------------------
// VirtQueue descriptor
// ---------------------------------------------------------------------------

/// A single VirtQueue descriptor.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct VirtqDesc {
    /// Physical address of the buffer.
    pub addr: u64,
    /// Length of the buffer in bytes.
    pub len: u32,
    /// Flags: `VIRTQ_DESC_F_NEXT` (1), `VIRTQ_DESC_F_WRITE` (2).
    pub flags: u16,
    /// Next descriptor index (valid if `VIRTQ_DESC_F_NEXT` is set).
    pub next: u16,
}

/// VirtQ descriptor flag: chain to next descriptor.
pub const VIRTQ_DESC_F_NEXT: u16 = 1;

/// VirtQ descriptor flag: device-writable (receive) buffer.
pub const VIRTQ_DESC_F_WRITE: u16 = 2;

// ---------------------------------------------------------------------------
// VirtQueue available ring
// ---------------------------------------------------------------------------

/// VirtQueue available ring header.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct VirtqAvailHeader {
    /// Flags (bit 0: suppress used ring interrupts).
    pub flags: u16,
    /// Next available slot index.
    pub idx: u16,
}

// ---------------------------------------------------------------------------
// VirtQueue used ring entry
// ---------------------------------------------------------------------------

/// A single entry in the VirtQueue used ring.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct VirtqUsedElem {
    /// Descriptor chain head index.
    pub id: u32,
    /// Total bytes written to device-writable buffers.
    pub len: u32,
}

// ---------------------------------------------------------------------------
// SerialPortState
// ---------------------------------------------------------------------------

/// State for a single virtual serial port.
#[derive(Debug)]
pub struct SerialPortState {
    /// Port index (0-based).
    pub index: u32,
    /// Whether this port is open.
    pub open: bool,
    /// RX virtqueue index (even).
    pub rx_queue: u16,
    /// TX virtqueue index (odd).
    pub tx_queue: u16,
    /// Receive buffer.
    rx_buf: [u8; PORT_BUFFER_SIZE],
    /// Number of valid bytes in `rx_buf`.
    pub rx_len: usize,
    /// Read position in `rx_buf`.
    pub rx_pos: usize,
    /// Transmit buffer.
    tx_buf: [u8; PORT_BUFFER_SIZE],
    /// Number of pending bytes in `tx_buf`.
    pub tx_len: usize,
    /// RX available ring index.
    pub rx_avail_idx: u16,
    /// TX available ring index.
    pub tx_avail_idx: u16,
    /// RX used ring last seen index.
    pub rx_used_idx: u16,
    /// TX used ring last seen index.
    pub tx_used_idx: u16,
}

impl SerialPortState {
    /// Create a new uninitialized port state.
    pub const fn new(index: u32) -> Self {
        Self {
            index,
            open: false,
            rx_queue: (index * 2) as u16,
            tx_queue: (index * 2 + 1) as u16,
            rx_buf: [0u8; PORT_BUFFER_SIZE],
            rx_len: 0,
            rx_pos: 0,
            tx_buf: [0u8; PORT_BUFFER_SIZE],
            tx_len: 0,
            rx_avail_idx: 0,
            tx_avail_idx: 0,
            rx_used_idx: 0,
            tx_used_idx: 0,
        }
    }

    /// Copy bytes from `src` into the TX buffer.
    ///
    /// Returns the number of bytes actually queued (may be less than
    /// `src.len()` if the buffer would overflow).
    pub fn enqueue_tx(&mut self, src: &[u8]) -> usize {
        let avail = PORT_BUFFER_SIZE - self.tx_len;
        let n = src.len().min(avail);
        self.tx_buf[self.tx_len..self.tx_len + n].copy_from_slice(&src[..n]);
        self.tx_len += n;
        n
    }

    /// Dequeue up to `dst.len()` bytes from the RX buffer into `dst`.
    ///
    /// Returns the number of bytes copied.
    pub fn dequeue_rx(&mut self, dst: &mut [u8]) -> usize {
        let avail = self.rx_len - self.rx_pos;
        let n = dst.len().min(avail);
        dst[..n].copy_from_slice(&self.rx_buf[self.rx_pos..self.rx_pos + n]);
        self.rx_pos += n;
        if self.rx_pos >= self.rx_len {
            self.rx_pos = 0;
            self.rx_len = 0;
        }
        n
    }

    /// Receive incoming bytes into the RX buffer.
    ///
    /// Returns the number of bytes stored.
    pub fn receive(&mut self, src: &[u8]) -> usize {
        let avail = PORT_BUFFER_SIZE - self.rx_len;
        let n = src.len().min(avail);
        self.rx_buf[self.rx_len..self.rx_len + n].copy_from_slice(&src[..n]);
        self.rx_len += n;
        n
    }

    /// Number of bytes available to read.
    pub fn rx_available(&self) -> usize {
        self.rx_len - self.rx_pos
    }

    /// Whether there is pending TX data.
    pub fn has_pending_tx(&self) -> bool {
        self.tx_len > 0
    }

    /// Drain the TX buffer, returning a slice of the pending bytes.
    ///
    /// After consuming the data, the caller must call `clear_tx()`.
    pub fn tx_pending(&self) -> &[u8] {
        &self.tx_buf[..self.tx_len]
    }

    /// Clear the TX buffer after data has been submitted to the virtqueue.
    pub fn clear_tx(&mut self) {
        self.tx_len = 0;
    }
}

// ---------------------------------------------------------------------------
// VirtioSerial device
// ---------------------------------------------------------------------------

/// A VirtIO serial device instance.
#[derive(Debug)]
pub struct VirtioSerial {
    /// MMIO base virtual address.
    pub mmio_base: u64,
    /// Number of ports available.
    pub num_ports: u32,
    /// Negotiated feature flags.
    pub features: u32,
    /// Device configuration snapshot.
    pub config: VirtioConsoleConfig,
    /// Per-port state.
    ports: [SerialPortState; MAX_PORTS],
    /// Descriptor table storage for all queues.
    desc_table: [[VirtqDesc; QUEUE_SIZE]; MAX_PORTS * 2],
    /// Available ring storage (header + ring entries + used event).
    avail_ring: [[u16; QUEUE_SIZE + 3]; MAX_PORTS * 2],
    /// Used ring storage (header + entries).
    used_ring: [[u32; QUEUE_SIZE * 2 + 2]; MAX_PORTS * 2],
    /// Whether the device has been initialised.
    pub initialized: bool,
}

impl VirtioSerial {
    /// Create an uninitialized VirtIO serial device.
    pub const fn new(mmio_base: u64) -> Self {
        const PORT_INIT: SerialPortState = SerialPortState::new(0);
        const DESC_INIT: [VirtqDesc; QUEUE_SIZE] = [VirtqDesc {
            addr: 0,
            len: 0,
            flags: 0,
            next: 0,
        }; QUEUE_SIZE];
        const AVAIL_INIT: [u16; QUEUE_SIZE + 3] = [0u16; QUEUE_SIZE + 3];
        const USED_INIT: [u32; QUEUE_SIZE * 2 + 2] = [0u32; QUEUE_SIZE * 2 + 2];
        Self {
            mmio_base,
            num_ports: 1,
            features: 0,
            config: VirtioConsoleConfig {
                cols: 0,
                rows: 0,
                max_nr_ports: 0,
                emerg_wr: 0,
            },
            ports: [PORT_INIT; MAX_PORTS],
            desc_table: [DESC_INIT; MAX_PORTS * 2],
            avail_ring: [AVAIL_INIT; MAX_PORTS * 2],
            used_ring: [USED_INIT; MAX_PORTS * 2],
            initialized: false,
        }
    }

    /// Read a 32-bit MMIO register at the given offset.
    ///
    /// # Safety
    ///
    /// Caller must ensure `self.mmio_base` is a valid MMIO-mapped region.
    fn read_reg(&self, offset: u64) -> u32 {
        let addr = (self.mmio_base + offset) as *const u32;
        // SAFETY: mmio_base is a valid MMIO mapping; volatile read required.
        unsafe { core::ptr::read_volatile(addr) }
    }

    /// Write a 32-bit MMIO register at the given offset.
    ///
    /// # Safety
    ///
    /// Caller must ensure `self.mmio_base` is a valid MMIO-mapped region.
    fn write_reg(&self, offset: u64, val: u32) {
        let addr = (self.mmio_base + offset) as *mut u32;
        // SAFETY: mmio_base is a valid MMIO mapping; volatile write required.
        unsafe { core::ptr::write_volatile(addr, val) };
    }

    /// Validate that the MMIO region contains a VirtIO console device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the magic number or device ID
    /// does not match the expected values.
    pub fn probe(&self) -> Result<()> {
        let magic = self.read_reg(VIRTIO_MMIO_MAGIC_VALUE);
        if magic != VIRTIO_MAGIC {
            return Err(Error::NotFound);
        }
        let device_id = self.read_reg(VIRTIO_MMIO_DEVICE_ID);
        if device_id != VIRTIO_CONSOLE_DEVICE_ID {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    /// Initialise the VirtIO serial device.
    ///
    /// Negotiates features, reads the device configuration, and marks the
    /// device as ready.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if feature negotiation fails.
    pub fn init(&mut self) -> Result<()> {
        self.probe()?;
        // Reset device.
        self.write_reg(VIRTIO_MMIO_STATUS, 0);
        // Acknowledge the device.
        self.write_reg(VIRTIO_MMIO_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);
        // Tell the device we have a driver.
        self.write_reg(
            VIRTIO_MMIO_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER,
        );
        // Read device features (page 0).
        self.write_reg(VIRTIO_MMIO_DEVICE_FEATURES_SEL, 0);
        let dev_features = self.read_reg(VIRTIO_MMIO_DEVICE_FEATURES);
        // Select the features we want.
        let wanted = VIRTIO_CONSOLE_F_MULTIPORT | VIRTIO_CONSOLE_F_EMERG_WRITE;
        let negotiated = dev_features & wanted;
        self.write_reg(VIRTIO_MMIO_DRIVER_FEATURES_SEL, 0);
        self.write_reg(VIRTIO_MMIO_DRIVER_FEATURES, negotiated);
        self.features = negotiated;
        // Confirm features OK.
        self.write_reg(
            VIRTIO_MMIO_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK,
        );
        // Verify the device accepted features.
        let status = self.read_reg(VIRTIO_MMIO_STATUS);
        if status & VIRTIO_STATUS_FEATURES_OK == 0 {
            self.write_reg(VIRTIO_MMIO_STATUS, VIRTIO_STATUS_FAILED);
            return Err(Error::IoError);
        }
        // Read device config.
        let cols_rows = self.read_reg(VIRTIO_MMIO_CONFIG);
        let max_ports_raw = self.read_reg(VIRTIO_MMIO_CONFIG + 4);
        self.config.cols = cols_rows as u16;
        self.config.rows = (cols_rows >> 16) as u16;
        if self.features & VIRTIO_CONSOLE_F_MULTIPORT != 0 {
            self.config.max_nr_ports = max_ports_raw;
            self.num_ports = max_ports_raw.min(MAX_PORTS as u32).max(1);
        } else {
            self.num_ports = 1;
        }
        // Re-initialise port indices.
        for i in 0..MAX_PORTS {
            self.ports[i] = SerialPortState::new(i as u32);
        }
        // Set virtqueue sizes.
        for q in 0..(self.num_ports * 2) {
            self.write_reg(VIRTIO_MMIO_QUEUE_SEL, q);
            self.write_reg(VIRTIO_MMIO_QUEUE_NUM, QUEUE_SIZE as u32);
        }
        // Signal driver OK.
        self.write_reg(
            VIRTIO_MMIO_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE
                | VIRTIO_STATUS_DRIVER
                | VIRTIO_STATUS_FEATURES_OK
                | VIRTIO_STATUS_DRIVER_OK,
        );
        self.initialized = true;
        Ok(())
    }

    /// Write bytes to port `port_idx`.
    ///
    /// Data is staged in the port's TX buffer. Returns the number of bytes
    /// accepted (may be less than `data.len()` if the buffer is full).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `port_idx >= num_ports`.
    pub fn write(&mut self, port_idx: usize, data: &[u8]) -> Result<usize> {
        if port_idx >= self.num_ports as usize {
            return Err(Error::InvalidArgument);
        }
        let n = self.ports[port_idx].enqueue_tx(data);
        // Notify device on TX queue.
        let tx_queue = self.ports[port_idx].tx_queue;
        self.write_reg(VIRTIO_MMIO_QUEUE_NOTIFY, u32::from(tx_queue));
        Ok(n)
    }

    /// Read up to `dst.len()` bytes from port `port_idx`.
    ///
    /// Returns the number of bytes actually read.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `port_idx >= num_ports`.
    /// Returns [`Error::WouldBlock`] if no data is available.
    pub fn read(&mut self, port_idx: usize, dst: &mut [u8]) -> Result<usize> {
        if port_idx >= self.num_ports as usize {
            return Err(Error::InvalidArgument);
        }
        if self.ports[port_idx].rx_available() == 0 {
            return Err(Error::WouldBlock);
        }
        Ok(self.ports[port_idx].dequeue_rx(dst))
    }

    /// Deliver received data to port `port_idx`.
    ///
    /// Called by the interrupt handler when the used ring advances.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `port_idx >= num_ports`.
    pub fn receive(&mut self, port_idx: usize, data: &[u8]) -> Result<usize> {
        if port_idx >= self.num_ports as usize {
            return Err(Error::InvalidArgument);
        }
        Ok(self.ports[port_idx].receive(data))
    }

    /// Handle a device interrupt: read interrupt status, acknowledge, and
    /// return the status bits.
    pub fn handle_interrupt(&self) -> u32 {
        let status = self.read_reg(VIRTIO_MMIO_INTERRUPT_STATUS);
        self.write_reg(VIRTIO_MMIO_INTERRUPT_ACK, status);
        status
    }

    /// Open a port (send PORT_READY control message).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `port_idx >= num_ports`.
    pub fn open_port(&mut self, port_idx: usize) -> Result<()> {
        if port_idx >= self.num_ports as usize {
            return Err(Error::InvalidArgument);
        }
        self.ports[port_idx].open = true;
        Ok(())
    }

    /// Close a port.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `port_idx >= num_ports`.
    pub fn close_port(&mut self, port_idx: usize) -> Result<()> {
        if port_idx >= self.num_ports as usize {
            return Err(Error::InvalidArgument);
        }
        self.ports[port_idx].open = false;
        Ok(())
    }

    /// Whether port `port_idx` is open.
    pub fn is_port_open(&self, port_idx: usize) -> bool {
        if port_idx >= MAX_PORTS {
            return false;
        }
        self.ports[port_idx].open
    }

    /// Return a reference to port state.
    pub fn port(&self, port_idx: usize) -> Result<&SerialPortState> {
        if port_idx >= MAX_PORTS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.ports[port_idx])
    }
}

// ---------------------------------------------------------------------------
// VirtioSerialRegistry
// ---------------------------------------------------------------------------

/// Global registry of VirtIO serial devices.
pub struct VirtioSerialRegistry {
    devices: [Option<VirtioSerial>; MAX_DEVICES],
    len: usize,
}

impl VirtioSerialRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_DEVICES],
            len: 0,
        }
    }

    /// Register a new VirtIO serial device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, device: VirtioSerial) -> Result<usize> {
        if self.len >= MAX_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.len;
        self.devices[idx] = Some(device);
        self.len += 1;
        Ok(idx)
    }

    /// Get a reference to the device at `idx`.
    pub fn get(&self, idx: usize) -> Option<&VirtioSerial> {
        self.devices.get(idx)?.as_ref()
    }

    /// Get a mutable reference to the device at `idx`.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut VirtioSerial> {
        self.devices.get_mut(idx)?.as_mut()
    }

    /// Number of registered devices.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Interrupt cause: used buffer notification (queue advanced).
pub const VIRTIO_INT_USED_BUFFER: u32 = 1 << 0;

/// Interrupt cause: configuration change.
pub const VIRTIO_INT_CONFIG_CHANGE: u32 = 1 << 1;

// ---------------------------------------------------------------------------
// Control virtqueue indices (multiport mode)
// ---------------------------------------------------------------------------

/// Control receive virtqueue index (device → driver control messages).
///
/// In multiport mode the control queues follow all data queue pairs:
/// `ctrl_rx = num_ports * 2`, `ctrl_tx = num_ports * 2 + 1`.
pub const CTRL_RX_QUEUE_BASE: u32 = MAX_PORTS as u32 * 2;

/// Control transmit virtqueue index (driver → device control messages).
pub const CTRL_TX_QUEUE_BASE: u32 = MAX_PORTS as u32 * 2 + 1;

// ---------------------------------------------------------------------------
// VirtIO console control event codes (VirtIO 1.2 §5.3.6.1)
// ---------------------------------------------------------------------------

/// Control event: device/driver is ready (id = 0 for device-level).
pub const VIRTIO_CONSOLE_DEVICE_READY: u16 = 0;

/// Control event: device added a new port.
pub const VIRTIO_CONSOLE_PORT_ADD: u16 = 1;

/// Control event: device removed a port.
pub const VIRTIO_CONSOLE_PORT_REMOVE: u16 = 2;

/// Control event: driver/device reports port ready.
pub const VIRTIO_CONSOLE_PORT_READY: u16 = 3;

/// Control event: this port is a console port.
pub const VIRTIO_CONSOLE_CONSOLE_PORT: u16 = 4;

/// Control event: console port resize (value = 1).
pub const VIRTIO_CONSOLE_RESIZE: u16 = 5;

/// Control event: port open/close state changed.
pub const VIRTIO_CONSOLE_PORT_OPEN: u16 = 6;

/// Control event: port name follows (value = name length).
pub const VIRTIO_CONSOLE_PORT_NAME: u16 = 7;

// ---------------------------------------------------------------------------
// Console size (resize payload)
// ---------------------------------------------------------------------------

/// Console dimensions sent in a resize control message.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct ConsoleSize {
    /// Number of columns.
    pub cols: u16,
    /// Number of rows.
    pub rows: u16,
}

// ---------------------------------------------------------------------------
// Port hot-plug state
// ---------------------------------------------------------------------------

/// Dynamic state for a port managed via the control channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortHotplugState {
    /// Port slot is empty (not added by device).
    Empty,
    /// Port has been added by the device but driver has not yet acknowledged.
    Added,
    /// Driver has acknowledged and the port is available for use.
    Ready,
    /// Port has been removed by the device.
    Removed,
}

// ---------------------------------------------------------------------------
// Control message dispatcher
// ---------------------------------------------------------------------------

/// Result of processing a single control message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlAction {
    /// Port was added; driver should send PORT_READY acknowledgement.
    PortAdded { port_id: u32 },
    /// Port was removed; driver should tear down the port.
    PortRemoved { port_id: u32 },
    /// Port open/close state changed.
    PortOpenChanged { port_id: u32, open: bool },
    /// Console resize notification.
    Resized { cols: u16, rows: u16 },
    /// Port is a console port.
    ConsolePort { port_id: u32 },
    /// No action required by the caller.
    None,
}

impl VirtioSerial {
    /// Returns the control RX virtqueue index for this device.
    ///
    /// Only valid when MULTIPORT feature is negotiated.
    pub fn ctrl_rx_queue(&self) -> u16 {
        (self.num_ports * 2) as u16
    }

    /// Returns the control TX virtqueue index for this device.
    ///
    /// Only valid when MULTIPORT feature is negotiated.
    pub fn ctrl_tx_queue(&self) -> u16 {
        (self.num_ports * 2 + 1) as u16
    }

    /// Returns whether the multiport feature is active.
    pub fn multiport(&self) -> bool {
        self.features & VIRTIO_CONSOLE_F_MULTIPORT != 0
    }

    /// Processes a single raw control message from the control RX virtqueue.
    ///
    /// Parses the `ConsoleControlMsg`, updates internal port state, and
    /// returns a [`ControlAction`] describing what the caller should do next.
    ///
    /// In response to [`ControlAction::PortAdded`], the caller must send
    /// a `VIRTIO_CONSOLE_PORT_READY` control message back via
    /// [`VirtioSerial::send_control`].
    pub fn handle_control_msg(&mut self, msg: &ConsoleControlMsg) -> ControlAction {
        let port_id = msg.id;
        match msg.event {
            VIRTIO_CONSOLE_PORT_ADD => {
                // Validate port index.
                if port_id < MAX_PORTS as u32 {
                    self.ports[port_id as usize].open = false;
                }
                ControlAction::PortAdded { port_id }
            }
            VIRTIO_CONSOLE_PORT_REMOVE => {
                if port_id < MAX_PORTS as u32 {
                    self.ports[port_id as usize].open = false;
                }
                ControlAction::PortRemoved { port_id }
            }
            VIRTIO_CONSOLE_PORT_OPEN => {
                let open = msg.value != 0;
                if port_id < MAX_PORTS as u32 {
                    self.ports[port_id as usize].open = open;
                }
                ControlAction::PortOpenChanged { port_id, open }
            }
            VIRTIO_CONSOLE_RESIZE => {
                // Resize payload is packed in the config cols/rows fields.
                // Re-read config to pick up new dimensions.
                let cols_rows = self.read_reg(VIRTIO_MMIO_CONFIG);
                let cols = cols_rows as u16;
                let rows = (cols_rows >> 16) as u16;
                self.config.cols = cols;
                self.config.rows = rows;
                ControlAction::Resized { cols, rows }
            }
            VIRTIO_CONSOLE_CONSOLE_PORT => ControlAction::ConsolePort { port_id },
            VIRTIO_CONSOLE_DEVICE_READY | VIRTIO_CONSOLE_PORT_READY | VIRTIO_CONSOLE_PORT_NAME => {
                ControlAction::None
            }
            _ => ControlAction::None,
        }
    }

    /// Sends a control message to the device via the control TX virtqueue.
    ///
    /// Used to acknowledge port-add (`VIRTIO_CONSOLE_PORT_READY`) and to
    /// report the driver ready state (`VIRTIO_CONSOLE_DEVICE_READY`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if multiport is not enabled.
    pub fn send_control(&mut self, msg: &ConsoleControlMsg) -> Result<()> {
        if !self.multiport() {
            return Err(Error::InvalidArgument);
        }
        let ctrl_tx = self.ctrl_tx_queue();
        // Notify the device that a control TX buffer is ready.
        self.write_reg(VIRTIO_MMIO_QUEUE_NOTIFY, u32::from(ctrl_tx));
        // In a real driver the msg would be DMA-mapped into a descriptor;
        // here we model the notification path.
        let _ = msg;
        Ok(())
    }

    /// Acknowledges a newly added port by sending PORT_READY to the device.
    ///
    /// Should be called after receiving [`ControlAction::PortAdded`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if multiport is not enabled or
    /// `port_id` is out of range.
    pub fn ack_port_add(&mut self, port_id: u32) -> Result<()> {
        if port_id >= MAX_PORTS as u32 {
            return Err(Error::InvalidArgument);
        }
        let msg = ConsoleControlMsg {
            id: port_id,
            event: VIRTIO_CONSOLE_PORT_READY,
            value: 1,
        };
        self.send_control(&msg)
    }

    /// Sends the device-level DEVICE_READY control message.
    ///
    /// Must be called after init() when multiport is enabled to let the
    /// device know the driver has finished setup.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if multiport is not enabled.
    pub fn send_device_ready(&mut self) -> Result<()> {
        let msg = ConsoleControlMsg {
            id: 0,
            event: VIRTIO_CONSOLE_DEVICE_READY,
            value: 1,
        };
        self.send_control(&msg)
    }

    /// Returns the current console dimensions.
    pub fn console_size(&self) -> ConsoleSize {
        ConsoleSize {
            cols: self.config.cols,
            rows: self.config.rows,
        }
    }

    /// Updates the console size (called after a resize control event).
    pub fn set_console_size(&mut self, cols: u16, rows: u16) {
        self.config.cols = cols;
        self.config.rows = rows;
    }

    /// Returns the hotplug state for a port based on its open flag and
    /// whether the slot has been configured.
    pub fn port_hotplug_state(&self, port_idx: usize) -> PortHotplugState {
        if port_idx >= self.num_ports as usize {
            return PortHotplugState::Empty;
        }
        if self.ports[port_idx].open {
            PortHotplugState::Ready
        } else {
            PortHotplugState::Added
        }
    }
}
