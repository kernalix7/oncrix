// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! USB descriptor parsing — device, configuration, interface, endpoint,
//! and string descriptors.
//!
//! # USB Descriptor Hierarchy
//!
//! ```text
//! Device Descriptor
//!   └─ Configuration Descriptor(s)
//!        └─ Interface Descriptor(s) [+ Interface Association]
//!             └─ Endpoint Descriptor(s)
//!                  └─ (optional) SuperSpeed Companion Descriptor
//! ```
//!
//! All descriptors share a common two-byte prefix: `bLength` and
//! `bDescriptorType`. The parser walks a flat byte buffer following
//! these length-prefixed records.
//!
//! # Descriptor Types
//!
//! | Value | Name |
//! |-------|------|
//! | 0x01  | Device |
//! | 0x02  | Configuration |
//! | 0x03  | String |
//! | 0x04  | Interface |
//! | 0x05  | Endpoint |
//! | 0x06  | Device_Qualifier |
//! | 0x0B  | Interface Association |
//! | 0x30  | SuperSpeed Endpoint Companion |
//!
//! Reference: USB 3.2 Specification, Chapter 9 (USB Device Framework);
//! USB 2.0 Specification §9.6.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Descriptor type constants
// ---------------------------------------------------------------------------

/// Descriptor type: Device.
pub const DT_DEVICE: u8 = 0x01;
/// Descriptor type: Configuration.
pub const DT_CONFIG: u8 = 0x02;
/// Descriptor type: String.
pub const DT_STRING: u8 = 0x03;
/// Descriptor type: Interface.
pub const DT_INTERFACE: u8 = 0x04;
/// Descriptor type: Endpoint.
pub const DT_ENDPOINT: u8 = 0x05;
/// Descriptor type: Device Qualifier.
pub const DT_DEVICE_QUALIFIER: u8 = 0x06;
/// Descriptor type: Interface Association.
pub const DT_INTERFACE_ASSOC: u8 = 0x0B;
/// Descriptor type: SuperSpeed Endpoint Companion.
pub const DT_SS_EP_COMPANION: u8 = 0x30;
/// Descriptor type: HID.
pub const DT_HID: u8 = 0x21;

// Minimum expected descriptor lengths.
const LEN_DEVICE: u8 = 18;
const LEN_CONFIG: u8 = 9;
const LEN_INTERFACE: u8 = 9;
const LEN_ENDPOINT: u8 = 7;
const LEN_IAD: u8 = 8;
const LEN_SS_COMPANION: u8 = 6;

// Endpoint direction bit.
/// Endpoint address bit 7: IN (device → host) when set.
pub const EP_DIR_IN: u8 = 0x80;
/// Mask for endpoint number (bits 3:0).
pub const EP_NUM_MASK: u8 = 0x0F;

// Endpoint transfer type (bmAttributes bits 1:0).
/// Transfer type: Control.
pub const EP_TYPE_CONTROL: u8 = 0x00;
/// Transfer type: Isochronous.
pub const EP_TYPE_ISOC: u8 = 0x01;
/// Transfer type: Bulk.
pub const EP_TYPE_BULK: u8 = 0x02;
/// Transfer type: Interrupt.
pub const EP_TYPE_INTERRUPT: u8 = 0x03;
/// Mask for transfer type field.
pub const EP_TYPE_MASK: u8 = 0x03;

// Configuration attributes.
/// Configuration attribute: self-powered.
pub const CFG_SELF_POWERED: u8 = 1 << 6;
/// Configuration attribute: remote wakeup.
pub const CFG_REMOTE_WAKEUP: u8 = 1 << 5;

/// Maximum number of interfaces parsed per configuration.
pub const MAX_INTERFACES: usize = 8;
/// Maximum number of endpoints parsed per interface.
pub const MAX_ENDPOINTS: usize = 8;
/// Maximum number of string descriptors cached.
pub const MAX_STRINGS: usize = 16;
/// Maximum string length in UTF-16LE code units.
pub const MAX_STRING_LEN: usize = 64;

// ---------------------------------------------------------------------------
// Descriptor structures
// ---------------------------------------------------------------------------

/// Parsed USB Device Descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct DeviceDescriptor {
    /// USB specification release (BCD, e.g. 0x0200 = USB 2.0).
    pub bcd_usb: u16,
    /// Device class code.
    pub device_class: u8,
    /// Device subclass code.
    pub device_subclass: u8,
    /// Device protocol code.
    pub device_protocol: u8,
    /// Max packet size for endpoint zero (8, 16, 32, or 64 bytes).
    pub max_packet_size0: u8,
    /// Vendor identifier.
    pub id_vendor: u16,
    /// Product identifier.
    pub id_product: u16,
    /// Device release (BCD).
    pub bcd_device: u16,
    /// Manufacturer string index (0 = none).
    pub i_manufacturer: u8,
    /// Product string index (0 = none).
    pub i_product: u8,
    /// Serial number string index (0 = none).
    pub i_serial: u8,
    /// Number of possible configurations.
    pub num_configurations: u8,
}

/// Parsed USB Configuration Descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConfigDescriptor {
    /// Total length of this configuration and all sub-descriptors.
    pub total_length: u16,
    /// Number of interfaces in this configuration.
    pub num_interfaces: u8,
    /// Configuration value (bConfigurationValue) used in SET_CONFIGURATION.
    pub config_value: u8,
    /// Configuration string index (0 = none).
    pub i_configuration: u8,
    /// Attributes bitmap (see `CFG_SELF_POWERED`, `CFG_REMOTE_WAKEUP`).
    pub attributes: u8,
    /// Maximum power in 2 mA units (USB 2.0) or 8 mA units (USB 3.0).
    pub max_power: u8,
}

impl ConfigDescriptor {
    /// Return `true` if the device is self-powered in this configuration.
    pub fn is_self_powered(&self) -> bool {
        self.attributes & CFG_SELF_POWERED != 0
    }

    /// Return `true` if remote wakeup is supported.
    pub fn supports_remote_wakeup(&self) -> bool {
        self.attributes & CFG_REMOTE_WAKEUP != 0
    }
}

/// Parsed USB Interface Descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct InterfaceDescriptor {
    /// Interface number (zero-indexed).
    pub interface_number: u8,
    /// Alternate setting number.
    pub alternate_setting: u8,
    /// Number of endpoints (excluding EP0).
    pub num_endpoints: u8,
    /// Interface class code.
    pub interface_class: u8,
    /// Interface subclass code.
    pub interface_subclass: u8,
    /// Interface protocol code.
    pub interface_protocol: u8,
    /// Interface string index (0 = none).
    pub i_interface: u8,
}

/// Parsed USB Endpoint Descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct EndpointDescriptor {
    /// Endpoint address (bit 7 = direction, bits 3:0 = endpoint number).
    pub endpoint_address: u8,
    /// Attributes (bits 1:0 = transfer type; bits 5:2 for isoc).
    pub attributes: u8,
    /// Maximum packet size (including multiplier for HS/SS).
    pub max_packet_size: u16,
    /// Polling interval in frames or microframes.
    pub interval: u8,
}

impl EndpointDescriptor {
    /// Return `true` if this is an IN endpoint (device → host).
    pub fn is_in(&self) -> bool {
        self.endpoint_address & EP_DIR_IN != 0
    }

    /// Return the endpoint number (0–15).
    pub fn number(&self) -> u8 {
        self.endpoint_address & EP_NUM_MASK
    }

    /// Return the transfer type.
    pub fn transfer_type(&self) -> u8 {
        self.attributes & EP_TYPE_MASK
    }

    /// Return `true` if this is a bulk endpoint.
    pub fn is_bulk(&self) -> bool {
        self.transfer_type() == EP_TYPE_BULK
    }

    /// Return `true` if this is an interrupt endpoint.
    pub fn is_interrupt(&self) -> bool {
        self.transfer_type() == EP_TYPE_INTERRUPT
    }

    /// Return `true` if this is an isochronous endpoint.
    pub fn is_isoc(&self) -> bool {
        self.transfer_type() == EP_TYPE_ISOC
    }
}

/// Parsed USB Interface Association Descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct InterfaceAssocDescriptor {
    /// First interface number in the association.
    pub first_interface: u8,
    /// Number of contiguous interfaces in the association.
    pub interface_count: u8,
    /// Function class code.
    pub function_class: u8,
    /// Function subclass code.
    pub function_subclass: u8,
    /// Function protocol code.
    pub function_protocol: u8,
    /// Function string index.
    pub i_function: u8,
}

/// Parsed USB SuperSpeed Endpoint Companion Descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct SsEpCompanion {
    /// Maximum number of packets the endpoint can send/receive per burst.
    pub max_burst: u8,
    /// bmAttributes (bulk streams or isoc mult).
    pub attributes: u8,
    /// Total bytes per service interval for periodic endpoints.
    pub bytes_per_interval: u16,
}

/// A cached USB string descriptor (UTF-16LE code units).
#[derive(Debug, Clone, Copy)]
pub struct StringEntry {
    /// String index (from the device descriptor fields).
    pub index: u8,
    /// Language ID (e.g. 0x0409 = English US).
    pub lang_id: u16,
    /// UTF-16LE code units.
    pub data: [u16; MAX_STRING_LEN],
    /// Number of valid code units.
    pub len: u8,
    /// Whether this slot is populated.
    pub valid: bool,
}

impl StringEntry {
    const EMPTY: Self = Self {
        index: 0,
        lang_id: 0,
        data: [0u16; MAX_STRING_LEN],
        len: 0,
        valid: false,
    };
}

// ---------------------------------------------------------------------------
// Parsed interface with endpoints
// ---------------------------------------------------------------------------

/// A fully-parsed interface including its endpoint list.
#[derive(Debug, Clone, Copy)]
pub struct ParsedInterface {
    /// Interface descriptor.
    pub descriptor: InterfaceDescriptor,
    /// Endpoint descriptors.
    pub endpoints: [EndpointDescriptor; MAX_ENDPOINTS],
    /// Number of valid endpoints.
    pub endpoint_count: u8,
}

impl ParsedInterface {
    const EMPTY: Self = Self {
        descriptor: InterfaceDescriptor {
            interface_number: 0,
            alternate_setting: 0,
            num_endpoints: 0,
            interface_class: 0,
            interface_subclass: 0,
            interface_protocol: 0,
            i_interface: 0,
        },
        endpoints: [EndpointDescriptor {
            endpoint_address: 0,
            attributes: 0,
            max_packet_size: 0,
            interval: 0,
        }; MAX_ENDPOINTS],
        endpoint_count: 0,
    };
}

// ---------------------------------------------------------------------------
// Descriptor parser
// ---------------------------------------------------------------------------

/// USB descriptor buffer parser.
///
/// Wraps a raw byte slice and provides iterator-style access to individual
/// descriptors, along with typed decode functions for each descriptor type.
pub struct DescriptorParser<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> DescriptorParser<'a> {
    /// Create a new parser for the given buffer.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    /// Return the current byte offset within the buffer.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Return `true` if the parser has consumed the entire buffer.
    pub fn is_done(&self) -> bool {
        self.offset >= self.buf.len()
    }

    /// Peek at the type of the next descriptor without advancing.
    ///
    /// Returns `None` if fewer than 2 bytes remain.
    pub fn peek_type(&self) -> Option<u8> {
        if self.offset + 1 < self.buf.len() {
            Some(self.buf[self.offset + 1])
        } else {
            None
        }
    }

    /// Advance past the current descriptor without decoding it.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the descriptor is malformed (zero length).
    pub fn skip(&mut self) -> Result<()> {
        let len = self.current_length()?;
        self.offset += len;
        Ok(())
    }

    /// Return the raw bytes of the current descriptor.
    fn current_bytes(&self) -> Result<&[u8]> {
        let len = self.current_length()?;
        Ok(&self.buf[self.offset..self.offset + len])
    }

    fn current_length(&self) -> Result<usize> {
        if self.offset >= self.buf.len() {
            return Err(Error::NotFound);
        }
        let len = self.buf[self.offset] as usize;
        if len < 2 || self.offset + len > self.buf.len() {
            return Err(Error::InvalidArgument);
        }
        Ok(len)
    }

    /// Decode a Device Descriptor at the current position.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the descriptor type or length is wrong.
    pub fn parse_device(&mut self) -> Result<DeviceDescriptor> {
        let bytes = self.current_bytes()?;
        if bytes[1] != DT_DEVICE || bytes[0] < LEN_DEVICE {
            return Err(Error::InvalidArgument);
        }
        let d = DeviceDescriptor {
            bcd_usb: u16::from_le_bytes([bytes[2], bytes[3]]),
            device_class: bytes[4],
            device_subclass: bytes[5],
            device_protocol: bytes[6],
            max_packet_size0: bytes[7],
            id_vendor: u16::from_le_bytes([bytes[8], bytes[9]]),
            id_product: u16::from_le_bytes([bytes[10], bytes[11]]),
            bcd_device: u16::from_le_bytes([bytes[12], bytes[13]]),
            i_manufacturer: bytes[14],
            i_product: bytes[15],
            i_serial: bytes[16],
            num_configurations: bytes[17],
        };
        self.offset += bytes[0] as usize;
        Ok(d)
    }

    /// Decode a Configuration Descriptor at the current position.
    pub fn parse_config(&mut self) -> Result<ConfigDescriptor> {
        let bytes = self.current_bytes()?;
        if bytes[1] != DT_CONFIG || bytes[0] < LEN_CONFIG {
            return Err(Error::InvalidArgument);
        }
        let d = ConfigDescriptor {
            total_length: u16::from_le_bytes([bytes[2], bytes[3]]),
            num_interfaces: bytes[4],
            config_value: bytes[5],
            i_configuration: bytes[6],
            attributes: bytes[7],
            max_power: bytes[8],
        };
        self.offset += bytes[0] as usize;
        Ok(d)
    }

    /// Decode an Interface Descriptor at the current position.
    pub fn parse_interface(&mut self) -> Result<InterfaceDescriptor> {
        let bytes = self.current_bytes()?;
        if bytes[1] != DT_INTERFACE || bytes[0] < LEN_INTERFACE {
            return Err(Error::InvalidArgument);
        }
        let d = InterfaceDescriptor {
            interface_number: bytes[2],
            alternate_setting: bytes[3],
            num_endpoints: bytes[4],
            interface_class: bytes[5],
            interface_subclass: bytes[6],
            interface_protocol: bytes[7],
            i_interface: bytes[8],
        };
        self.offset += bytes[0] as usize;
        Ok(d)
    }

    /// Decode an Endpoint Descriptor at the current position.
    pub fn parse_endpoint(&mut self) -> Result<EndpointDescriptor> {
        let bytes = self.current_bytes()?;
        if bytes[1] != DT_ENDPOINT || bytes[0] < LEN_ENDPOINT {
            return Err(Error::InvalidArgument);
        }
        let d = EndpointDescriptor {
            endpoint_address: bytes[2],
            attributes: bytes[3],
            max_packet_size: u16::from_le_bytes([bytes[4], bytes[5]]),
            interval: bytes[6],
        };
        self.offset += bytes[0] as usize;
        Ok(d)
    }

    /// Decode an Interface Association Descriptor at the current position.
    pub fn parse_iad(&mut self) -> Result<InterfaceAssocDescriptor> {
        let bytes = self.current_bytes()?;
        if bytes[1] != DT_INTERFACE_ASSOC || bytes[0] < LEN_IAD {
            return Err(Error::InvalidArgument);
        }
        let d = InterfaceAssocDescriptor {
            first_interface: bytes[2],
            interface_count: bytes[3],
            function_class: bytes[4],
            function_subclass: bytes[5],
            function_protocol: bytes[6],
            i_function: bytes[7],
        };
        self.offset += bytes[0] as usize;
        Ok(d)
    }

    /// Decode a SuperSpeed Endpoint Companion Descriptor.
    pub fn parse_ss_companion(&mut self) -> Result<SsEpCompanion> {
        let bytes = self.current_bytes()?;
        if bytes[1] != DT_SS_EP_COMPANION || bytes[0] < LEN_SS_COMPANION {
            return Err(Error::InvalidArgument);
        }
        let d = SsEpCompanion {
            max_burst: bytes[2],
            attributes: bytes[3],
            bytes_per_interval: u16::from_le_bytes([bytes[4], bytes[5]]),
        };
        self.offset += bytes[0] as usize;
        Ok(d)
    }

    /// Parse a complete configuration descriptor block (config + interfaces +
    /// endpoints) starting at the current offset.
    ///
    /// Returns the configuration and a list of parsed interfaces.
    pub fn parse_full_config(
        &mut self,
    ) -> Result<(ConfigDescriptor, [ParsedInterface; MAX_INTERFACES], usize)> {
        let cfg = self.parse_config()?;
        let mut interfaces = [ParsedInterface::EMPTY; MAX_INTERFACES];
        let mut iface_count = 0usize;

        while !self.is_done() {
            let dt = match self.peek_type() {
                Some(t) => t,
                None => break,
            };
            match dt {
                DT_INTERFACE => {
                    if iface_count >= MAX_INTERFACES {
                        self.skip()?;
                        continue;
                    }
                    let iface = self.parse_interface()?;
                    let ep_count = iface.num_endpoints as usize;
                    let mut parsed = ParsedInterface::EMPTY;
                    parsed.descriptor = iface;

                    let mut ep_idx = 0usize;
                    while ep_idx < ep_count && !self.is_done() {
                        let ept = self.peek_type().unwrap_or(0);
                        if ept == DT_ENDPOINT {
                            if ep_idx < MAX_ENDPOINTS {
                                parsed.endpoints[ep_idx] = self.parse_endpoint()?;
                                ep_idx += 1;
                            } else {
                                self.skip()?;
                            }
                        } else if ept == DT_INTERFACE || ept == DT_CONFIG {
                            break;
                        } else {
                            self.skip()?;
                        }
                    }
                    parsed.endpoint_count = ep_idx as u8;
                    interfaces[iface_count] = parsed;
                    iface_count += 1;
                }
                DT_CONFIG => break,
                _ => {
                    self.skip()?;
                }
            }
        }

        Ok((cfg, interfaces, iface_count))
    }
}

// ---------------------------------------------------------------------------
// String descriptor cache
// ---------------------------------------------------------------------------

/// In-memory cache of fetched USB string descriptors.
pub struct StringCache {
    entries: [StringEntry; MAX_STRINGS],
    count: usize,
}

impl StringCache {
    /// Create an empty cache.
    pub const fn new() -> Self {
        Self {
            entries: [StringEntry::EMPTY; MAX_STRINGS],
            count: 0,
        }
    }

    /// Parse and cache a raw string descriptor response.
    ///
    /// `raw` must start at the bLength byte. Stores the first
    /// `MAX_STRING_LEN` code units.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `raw` is too short or has wrong descriptor type.
    /// - `OutOfMemory` if the cache is full.
    /// - `AlreadyExists` if the `(index, lang_id)` pair is already cached.
    pub fn insert(&mut self, index: u8, lang_id: u16, raw: &[u8]) -> Result<()> {
        if raw.len() < 2 || raw[1] != DT_STRING {
            return Err(Error::InvalidArgument);
        }
        let blen = raw[0] as usize;
        if blen < 2 || blen > raw.len() {
            return Err(Error::InvalidArgument);
        }

        for entry in &self.entries[..self.count] {
            if entry.valid && entry.index == index && entry.lang_id == lang_id {
                return Err(Error::AlreadyExists);
            }
        }
        if self.count >= MAX_STRINGS {
            return Err(Error::OutOfMemory);
        }

        let mut data = [0u16; MAX_STRING_LEN];
        let payload = &raw[2..blen];
        let words = payload.len() / 2;
        let copy_len = words.min(MAX_STRING_LEN);
        for i in 0..copy_len {
            data[i] = u16::from_le_bytes([payload[i * 2], payload[i * 2 + 1]]);
        }

        let slot = self.count;
        self.entries[slot] = StringEntry {
            index,
            lang_id,
            data,
            len: copy_len as u8,
            valid: true,
        };
        self.count += 1;
        Ok(())
    }

    /// Look up a cached string by `(index, lang_id)`.
    ///
    /// Returns a slice of UTF-16LE code units, or `None` if not cached.
    pub fn get(&self, index: u8, lang_id: u16) -> Option<&[u16]> {
        for entry in &self.entries[..self.count] {
            if entry.valid && entry.index == index && entry.lang_id == lang_id {
                return Some(&entry.data[..entry.len as usize]);
            }
        }
        None
    }

    /// Return the number of cached strings.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Return `true` if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for StringCache {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn device_descriptor_bytes() -> [u8; 18] {
        [
            18, DT_DEVICE, 0x00, 0x02, // bcdUSB 2.00
            0x00, // bDeviceClass
            0x00, // bDeviceSubClass
            0x00, // bDeviceProtocol
            64,   // bMaxPacketSize0
            0x86, 0x80, // idVendor 0x8086
            0x34, 0x12, // idProduct 0x1234
            0x00, 0x01, // bcdDevice 1.00
            1, 2, 3, // iManufacturer, iProduct, iSerial
            1, // bNumConfigurations
        ]
    }

    fn config_descriptor_bytes() -> [u8; 9] {
        [9, DT_CONFIG, 25, 0, 1, 1, 0, 0xC0, 50]
    }

    fn interface_descriptor_bytes() -> [u8; 9] {
        [9, DT_INTERFACE, 0, 0, 1, 0x08, 0x06, 0x50, 0]
    }

    fn endpoint_descriptor_bytes() -> [u8; 7] {
        [7, DT_ENDPOINT, 0x81, EP_TYPE_BULK, 0x40, 0x00, 0]
    }

    #[test]
    fn parse_device_descriptor() {
        let buf = device_descriptor_bytes();
        let mut parser = DescriptorParser::new(&buf);
        let dev = parser.parse_device().unwrap();
        assert_eq!(dev.bcd_usb, 0x0200);
        assert_eq!(dev.id_vendor, 0x8086);
        assert_eq!(dev.id_product, 0x1234);
        assert_eq!(dev.num_configurations, 1);
        assert!(parser.is_done());
    }

    #[test]
    fn parse_config_descriptor() {
        let buf = config_descriptor_bytes();
        let mut parser = DescriptorParser::new(&buf);
        let cfg = parser.parse_config().unwrap();
        assert_eq!(cfg.num_interfaces, 1);
        assert_eq!(cfg.config_value, 1);
        assert!(cfg.is_self_powered());
    }

    #[test]
    fn parse_interface_descriptor() {
        let buf = interface_descriptor_bytes();
        let mut parser = DescriptorParser::new(&buf);
        let iface = parser.parse_interface().unwrap();
        assert_eq!(iface.interface_class, 0x08); // mass storage
        assert_eq!(iface.num_endpoints, 1);
    }

    #[test]
    fn parse_endpoint_descriptor() {
        let buf = endpoint_descriptor_bytes();
        let mut parser = DescriptorParser::new(&buf);
        let ep = parser.parse_endpoint().unwrap();
        assert!(ep.is_in());
        assert_eq!(ep.number(), 1);
        assert!(ep.is_bulk());
        assert_eq!(ep.max_packet_size, 64);
    }

    #[test]
    fn endpoint_type_helpers() {
        let bulk = EndpointDescriptor {
            endpoint_address: 0x01,
            attributes: EP_TYPE_BULK,
            max_packet_size: 512,
            interval: 0,
        };
        assert!(!bulk.is_in());
        assert!(bulk.is_bulk());
        assert!(!bulk.is_interrupt());

        let intr = EndpointDescriptor {
            endpoint_address: 0x83,
            attributes: EP_TYPE_INTERRUPT,
            max_packet_size: 8,
            interval: 10,
        };
        assert!(intr.is_in());
        assert!(intr.is_interrupt());
        assert_eq!(intr.number(), 3);
    }

    #[test]
    fn string_cache_insert_and_get() {
        let mut cache = StringCache::new();
        // Raw string descriptor: bLength=4, bDescriptorType=3, 'A' in UTF-16LE.
        let raw = [4u8, DT_STRING, b'A', 0x00];
        cache.insert(1, 0x0409, &raw).unwrap();
        let s = cache.get(1, 0x0409).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0], b'A' as u16);
    }

    #[test]
    fn string_cache_duplicate_rejected() {
        let mut cache = StringCache::new();
        let raw = [4u8, DT_STRING, b'X', 0x00];
        cache.insert(2, 0x0409, &raw).unwrap();
        assert_eq!(
            cache.insert(2, 0x0409, &raw).unwrap_err(),
            Error::AlreadyExists
        );
    }

    #[test]
    fn string_cache_not_found() {
        let cache = StringCache::new();
        assert!(cache.get(1, 0x0409).is_none());
    }

    #[test]
    fn parse_wrong_type_returns_error() {
        let buf = interface_descriptor_bytes();
        let mut parser = DescriptorParser::new(&buf);
        // Trying to parse as device descriptor should fail.
        assert!(parser.parse_device().is_err());
    }
}
