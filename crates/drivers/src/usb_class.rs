// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! USB Device Class driver framework.
//!
//! Provides a common abstraction layer for USB class drivers. Each
//! USB device class (CDC, HID, Mass Storage, etc.) is identified by
//! its class/subclass/protocol triple in the interface descriptor.
//! When a USB device is enumerated, the class registry probes each
//! registered class driver to find the best match.
//!
//! # Architecture
//!
//! - **UsbClassCode** — USB-IF class code enumeration.
//! - **UsbDescriptor** — raw descriptor bytes (repr(C)).
//! - **UsbInterfaceDesc** / **UsbEndpointDesc** — typed descriptors
//!   decoded from the configuration descriptor.
//! - **UsbClassDriver** — a registered class driver with match and
//!   probe/disconnect callbacks (modelled as indices into a platform
//!   dispatch table to avoid function-pointer ABI issues in no_std).
//! - **UsbClassRegistry** — up to 16 class drivers, match-and-probe.
//!
//! Reference: USB 3.2 Specification, §9.6; USB Class Specifications.

use oncrix_lib::{Error, Result};

// ── USB class codes ───────────────────────────────────────────

/// USB-IF defined class codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbClassCode {
    /// Audio class (0x01) — microphones, speakers.
    Audio,
    /// Communications Device Class (0x02) — serial, modem.
    Cdc,
    /// Human Interface Device (0x03) — keyboard, mouse.
    Hid,
    /// Physical Interface Device (0x05) — force-feedback.
    Physical,
    /// Still Image (0x06) — cameras.
    Image,
    /// Printer class (0x07).
    Printer,
    /// Mass Storage class (0x08) — USB flash drives.
    MassStorage,
    /// Hub class (0x09).
    Hub,
    /// CDC-Data (0x0A) — data interface for CDC devices.
    CdcData,
    /// Video class (0x0E) — webcams.
    Video,
    /// Wireless Controller (0xE0) — Bluetooth.
    Wireless,
    /// Vendor-specific (0xFF).
    Vendor,
    /// Unknown class code.
    Unknown(u8),
}

impl UsbClassCode {
    /// Return the raw USB-IF class code byte.
    pub fn code(self) -> u8 {
        match self {
            Self::Audio => 0x01,
            Self::Cdc => 0x02,
            Self::Hid => 0x03,
            Self::Physical => 0x05,
            Self::Image => 0x06,
            Self::Printer => 0x07,
            Self::MassStorage => 0x08,
            Self::Hub => 0x09,
            Self::CdcData => 0x0A,
            Self::Video => 0x0E,
            Self::Wireless => 0xE0,
            Self::Vendor => 0xFF,
            Self::Unknown(c) => c,
        }
    }

    /// Decode a class code from a raw byte.
    pub fn from_code(code: u8) -> Self {
        match code {
            0x01 => Self::Audio,
            0x02 => Self::Cdc,
            0x03 => Self::Hid,
            0x05 => Self::Physical,
            0x06 => Self::Image,
            0x07 => Self::Printer,
            0x08 => Self::MassStorage,
            0x09 => Self::Hub,
            0x0A => Self::CdcData,
            0x0E => Self::Video,
            0xE0 => Self::Wireless,
            0xFF => Self::Vendor,
            other => Self::Unknown(other),
        }
    }
}

// ── USB descriptor ────────────────────────────────────────────

/// Raw USB descriptor as it appears in the configuration descriptor
/// byte stream.
///
/// The first two bytes are common to all USB descriptors:
/// `bLength` and `bDescriptorType`. The remaining bytes are
/// type-specific.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UsbDescriptor {
    /// Total length of this descriptor in bytes.
    pub length: u8,
    /// Descriptor type (e.g. 0x04 = interface, 0x05 = endpoint).
    pub descriptor_type: u8,
    /// Type-specific descriptor data (up to 253 bytes).
    pub data: [u8; 253],
}

impl Default for UsbDescriptor {
    fn default() -> Self {
        Self::new()
    }
}

impl UsbDescriptor {
    /// Create an empty USB descriptor.
    pub fn new() -> Self {
        Self {
            length: 2,
            descriptor_type: 0,
            data: [0u8; 253],
        }
    }
}

// ── Interface descriptor ──────────────────────────────────────

/// Decoded USB Interface Descriptor (bDescriptorType = 0x04).
///
/// Carries the class/subclass/protocol triple used for class driver
/// matching, and metadata about the interface's endpoints.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UsbInterfaceDesc {
    /// bInterfaceNumber — zero-based interface index.
    pub num: u8,
    /// bAlternateSetting — alternate setting index.
    pub alt_setting: u8,
    /// bNumEndpoints — number of endpoints in this interface.
    pub num_endpoints: u8,
    /// bInterfaceClass — USB class code.
    pub class: u8,
    /// bInterfaceSubClass — USB subclass code.
    pub subclass: u8,
    /// bInterfaceProtocol — USB protocol code.
    pub protocol: u8,
    /// iInterface — string descriptor index (0 = no string).
    pub string_idx: u8,
}

impl UsbInterfaceDesc {
    /// Return the parsed class code as a [`UsbClassCode`].
    pub fn class_code(&self) -> UsbClassCode {
        UsbClassCode::from_code(self.class)
    }
}

// ── Endpoint descriptor ───────────────────────────────────────

/// Decoded USB Endpoint Descriptor (bDescriptorType = 0x05).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UsbEndpointDesc {
    /// bEndpointAddress — endpoint number + direction bit.
    pub address: u8,
    /// bmAttributes — transfer type (bits 1:0): 0=ctrl,1=iso,
    /// 2=bulk,3=int.
    pub attributes: u8,
    /// wMaxPacketSize — maximum packet size for this endpoint.
    pub max_packet_size: u16,
    /// bInterval — polling interval for interrupt endpoints (ms).
    pub interval: u8,
}

impl UsbEndpointDesc {
    /// Return `true` if this is an IN endpoint (device→host).
    pub fn is_in(&self) -> bool {
        self.address & 0x80 != 0
    }

    /// Return `true` if this is an OUT endpoint (host→device).
    pub fn is_out(&self) -> bool {
        !self.is_in()
    }

    /// Return the endpoint number (bits 3:0 of address).
    pub fn number(&self) -> u8 {
        self.address & 0x0F
    }

    /// Return the transfer type (bits 1:0 of attributes).
    pub fn transfer_type(&self) -> u8 {
        self.attributes & 0x03
    }
}

// ── Class driver ──────────────────────────────────────────────

/// A registered USB class driver.
///
/// Class drivers are identified by their class code and an optional
/// subclass/protocol filter. When a device is enumerated, the
/// registry calls `match_device` then `probe_idx` on each
/// registered driver in registration order.
///
/// Probe and disconnect callbacks are represented as indices into
/// a platform dispatch table to avoid raw function pointers in
/// `no_std` code.
#[derive(Debug, Clone, Copy)]
pub struct UsbClassDriver {
    /// Primary USB class code this driver handles.
    pub class_code: UsbClassCode,
    /// Subclass filter (0xFF = match any).
    pub subclass_filter: u8,
    /// Protocol filter (0xFF = match any).
    pub protocol_filter: u8,
    /// Driver name (up to 31 bytes + NUL).
    pub name: [u8; 32],
    /// Index into the platform probe callback table.
    pub probe_idx: u8,
    /// Index into the platform disconnect callback table.
    pub disconnect_idx: u8,
    /// Whether this driver slot is occupied.
    pub active: bool,
}

impl Default for UsbClassDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl UsbClassDriver {
    /// Create an empty class driver entry.
    pub const fn new() -> Self {
        Self {
            class_code: UsbClassCode::Unknown(0),
            subclass_filter: 0xFF,
            protocol_filter: 0xFF,
            name: [0u8; 32],
            probe_idx: 0,
            disconnect_idx: 0,
            active: false,
        }
    }

    /// Return `true` if this driver matches the given interface
    /// descriptor.
    ///
    /// Matches when:
    /// - class codes are equal, AND
    /// - subclass filter is 0xFF (any) or matches `iface.subclass`, AND
    /// - protocol filter is 0xFF (any) or matches `iface.protocol`.
    pub fn match_device(&self, iface: &UsbInterfaceDesc) -> bool {
        if self.class_code.code() != iface.class {
            return false;
        }
        if self.subclass_filter != 0xFF && self.subclass_filter != iface.subclass {
            return false;
        }
        if self.protocol_filter != 0xFF && self.protocol_filter != iface.protocol {
            return false;
        }
        true
    }
}

// ── Device info used during probe/disconnect ──────────────────

/// Minimal device information passed to the probe callback.
#[derive(Debug, Clone, Copy)]
pub struct UsbDeviceInfo {
    /// USB device address (1–127).
    pub address: u8,
    /// Vendor ID.
    pub vendor_id: u16,
    /// Product ID.
    pub product_id: u16,
    /// Matched interface descriptor.
    pub interface: UsbInterfaceDesc,
}

// ── Statistics ────────────────────────────────────────────────

/// USB class framework operational statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct UsbClassStats {
    /// Total probe calls issued.
    pub probes: u64,
    /// Total disconnect calls issued.
    pub disconnects: u64,
    /// Total probe errors.
    pub errors: u64,
}

// ── Class registry ────────────────────────────────────────────

/// Maximum number of registered USB class drivers.
const MAX_CLASS_DRIVERS: usize = 16;

/// USB class driver registry.
///
/// Stores up to [`MAX_CLASS_DRIVERS`] (16) class drivers. When a
/// USB device interface is presented, `match_and_probe` iterates
/// the table and dispatches the first match.
pub struct UsbClassRegistry {
    /// Registered class drivers.
    drivers: [UsbClassDriver; MAX_CLASS_DRIVERS],
    /// Number of registered drivers.
    count: usize,
    /// Statistics.
    stats: UsbClassStats,
}

impl Default for UsbClassRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl UsbClassRegistry {
    /// Create an empty USB class registry.
    pub fn new() -> Self {
        Self {
            drivers: [const { UsbClassDriver::new() }; MAX_CLASS_DRIVERS],
            count: 0,
            stats: UsbClassStats::default(),
        }
    }

    /// Register a USB class driver.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the registry is full.
    /// - [`Error::AlreadyExists`] if a driver with the same class,
    ///   subclass, and protocol is already registered.
    pub fn register(&mut self, driver: UsbClassDriver) -> Result<usize> {
        // Duplicate check (class + subclass + protocol triple).
        let dup = self.drivers[..self.count].iter().any(|d| {
            d.active
                && d.class_code.code() == driver.class_code.code()
                && d.subclass_filter == driver.subclass_filter
                && d.protocol_filter == driver.protocol_filter
        });
        if dup {
            return Err(Error::AlreadyExists);
        }
        if self.count >= MAX_CLASS_DRIVERS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.drivers[idx] = driver;
        self.drivers[idx].active = true;
        self.count += 1;
        Ok(idx)
    }

    /// Unregister a class driver by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `idx` is out of range or
    /// the slot is inactive.
    pub fn unregister(&mut self, idx: usize) -> Result<()> {
        if idx >= self.count || !self.drivers[idx].active {
            return Err(Error::NotFound);
        }
        self.drivers[idx].active = false;
        Ok(())
    }

    /// Match an interface descriptor against all registered drivers
    /// and invoke the probe callback of the first matching driver.
    ///
    /// Returns the probe callback index on match, or `None` if no
    /// driver matches.
    pub fn match_and_probe(&mut self, device: &UsbDeviceInfo) -> Option<u8> {
        let mut i = 0usize;
        while i < self.count {
            if self.drivers[i].active && self.drivers[i].match_device(&device.interface) {
                self.stats.probes += 1;
                return Some(self.drivers[i].probe_idx);
            }
            i += 1;
        }
        None
    }

    /// Notify a class driver of device disconnection.
    ///
    /// Finds the driver that was probed for `device` and returns
    /// its disconnect callback index.
    ///
    /// Returns `None` if no matching driver is found.
    pub fn disconnect(&mut self, device: &UsbDeviceInfo) -> Option<u8> {
        let mut i = 0usize;
        while i < self.count {
            if self.drivers[i].active && self.drivers[i].match_device(&device.interface) {
                self.stats.disconnects += 1;
                return Some(self.drivers[i].disconnect_idx);
            }
            i += 1;
        }
        None
    }

    /// Record a probe error.
    pub fn record_error(&mut self) {
        self.stats.errors += 1;
    }

    /// Return the number of registered class drivers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return the operational statistics.
    pub fn stats(&self) -> &UsbClassStats {
        &self.stats
    }

    /// Return a reference to the driver at `index`.
    pub fn get(&self, index: usize) -> Option<&UsbClassDriver> {
        if index < self.count && self.drivers[index].active {
            Some(&self.drivers[index])
        } else {
            None
        }
    }
}

// ── Common class driver factories ─────────────────────────────

/// Build a HID class driver entry for keyboards (subclass 1,
/// protocol 1).
pub fn hid_keyboard_driver(probe_idx: u8, disconnect_idx: u8) -> UsbClassDriver {
    let mut d = UsbClassDriver::new();
    d.class_code = UsbClassCode::Hid;
    d.subclass_filter = 0x01; // Boot Interface subclass
    d.protocol_filter = 0x01; // Keyboard protocol
    d.probe_idx = probe_idx;
    d.disconnect_idx = disconnect_idx;
    let name = b"hid-keyboard";
    d.name[..name.len()].copy_from_slice(name);
    d
}

/// Build a HID class driver entry for mice (subclass 1,
/// protocol 2).
pub fn hid_mouse_driver(probe_idx: u8, disconnect_idx: u8) -> UsbClassDriver {
    let mut d = UsbClassDriver::new();
    d.class_code = UsbClassCode::Hid;
    d.subclass_filter = 0x01; // Boot Interface subclass
    d.protocol_filter = 0x02; // Mouse protocol
    d.probe_idx = probe_idx;
    d.disconnect_idx = disconnect_idx;
    let name = b"hid-mouse";
    d.name[..name.len()].copy_from_slice(name);
    d
}

/// Build a Mass Storage class driver entry (Bulk-Only Transport).
pub fn mass_storage_driver(probe_idx: u8, disconnect_idx: u8) -> UsbClassDriver {
    let mut d = UsbClassDriver::new();
    d.class_code = UsbClassCode::MassStorage;
    d.subclass_filter = 0x06; // SCSI transparent command set
    d.protocol_filter = 0x50; // Bulk-Only Transport
    d.probe_idx = probe_idx;
    d.disconnect_idx = disconnect_idx;
    let name = b"usb-storage";
    d.name[..name.len()].copy_from_slice(name);
    d
}

/// Build a CDC-ACM (serial modem) class driver entry.
pub fn cdc_acm_driver(probe_idx: u8, disconnect_idx: u8) -> UsbClassDriver {
    let mut d = UsbClassDriver::new();
    d.class_code = UsbClassCode::Cdc;
    d.subclass_filter = 0x02; // Abstract Control Model
    d.protocol_filter = 0x01; // AT command set
    d.probe_idx = probe_idx;
    d.disconnect_idx = disconnect_idx;
    let name = b"cdc-acm";
    d.name[..name.len()].copy_from_slice(name);
    d
}
