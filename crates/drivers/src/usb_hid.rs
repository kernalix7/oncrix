// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! USB Human Interface Device (HID) class driver.
//!
//! Implements the USB HID specification for handling input devices
//! such as keyboards, mice, gamepads, and other generic HID-class
//! peripherals. The driver parses HID report descriptors to extract
//! individual fields and processes incoming interrupt-IN reports.
//!
//! # Architecture
//!
//! - **HidDescriptor** -- HID class descriptor (per USB HID 1.11)
//! - **HidReport** -- parsed report with field extraction
//! - **HidDevice** -- single HID device with report processing
//! - **HidRegistry** -- tracks up to 16 attached HID devices
//!
//! Reference: USB HID Specification 1.11, USB HID Usage Tables 1.4.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// USB interface class code for HID.
pub const HID_CLASS: u8 = 0x03;

/// HID subclass code for boot interface.
pub const HID_SUBCLASS_BOOT: u8 = 0x01;

/// HID protocol code for keyboard.
pub const HID_PROTOCOL_KEYBOARD: u8 = 0x01;

/// HID protocol code for mouse.
pub const HID_PROTOCOL_MOUSE: u8 = 0x02;

/// Maximum number of fields in a single HID report.
const MAX_REPORT_FIELDS: usize = 16;

/// Maximum report data size in bytes.
const MAX_REPORT_DATA: usize = 64;

/// Maximum number of fields in a HID report descriptor.
const MAX_DESCRIPTOR_FIELDS: usize = 32;

/// Maximum number of concurrently tracked HID devices.
pub const MAX_HID_DEVICES: usize = 16;

// ---------------------------------------------------------------------------
// HID Descriptor (repr(C), per USB HID 1.11 section 6.2.1)
// ---------------------------------------------------------------------------

/// USB HID class descriptor.
///
/// This 9-byte structure is returned alongside the standard USB
/// interface descriptor and describes the HID report descriptor
/// associated with the interface.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct HidDescriptor {
    /// Total size of this descriptor in bytes.
    pub b_length: u8,
    /// Descriptor type (0x21 for HID).
    pub b_descriptor_type: u8,
    /// HID specification release number in BCD (e.g. 0x0111 = 1.11).
    pub bcd_hid: u16,
    /// Country code for localised hardware (0 = not localised).
    pub b_country_code: u8,
    /// Number of class descriptors (at least 1 for report descriptor).
    pub b_num_descriptors: u8,
    /// Type of the first class descriptor (0x22 = report).
    pub b_report_descriptor_type: u8,
    /// Total size of the report descriptor in bytes.
    pub w_report_descriptor_length: u16,
}

// ---------------------------------------------------------------------------
// HID Usage Pages (USB HID Usage Tables 1.4, section 3)
// ---------------------------------------------------------------------------

/// HID usage page identifiers.
///
/// A usage page defines a top-level category of controls and data.
/// Only the most common pages are enumerated here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HidUsagePage {
    /// Generic Desktop page (0x01): pointers, mice, joysticks, keyboards.
    #[default]
    GenericDesktop,
    /// Keyboard/Keypad page (0x07).
    Keyboard,
    /// LED page (0x08).
    Led,
    /// Button page (0x09).
    Button,
}

impl HidUsagePage {
    /// Convert a raw 16-bit usage page value to an enum variant.
    pub fn from_u16(value: u16) -> Self {
        match value {
            0x01 => Self::GenericDesktop,
            0x07 => Self::Keyboard,
            0x08 => Self::Led,
            0x09 => Self::Button,
            _ => Self::GenericDesktop,
        }
    }

    /// Return the raw 16-bit value for this usage page.
    pub fn to_u16(self) -> u16 {
        match self {
            Self::GenericDesktop => 0x01,
            Self::Keyboard => 0x07,
            Self::Led => 0x08,
            Self::Button => 0x09,
        }
    }
}

// ---------------------------------------------------------------------------
// HID Usages (within a usage page)
// ---------------------------------------------------------------------------

/// HID usage identifiers within a usage page.
///
/// Usages identify the specific control or data field purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HidUsage {
    /// Pointer (Generic Desktop 0x01).
    #[default]
    Pointer,
    /// Mouse (Generic Desktop 0x02).
    Mouse,
    /// Joystick (Generic Desktop 0x04).
    Joystick,
    /// Keyboard (Generic Desktop 0x06).
    Keyboard,
    /// X axis (Generic Desktop 0x30).
    X,
    /// Y axis (Generic Desktop 0x31).
    Y,
    /// Scroll wheel (Generic Desktop 0x38).
    Wheel,
    /// Primary button (Button page 0x01).
    ButtonPrimary,
    /// Secondary button (Button page 0x02).
    ButtonSecondary,
    /// Tertiary button (Button page 0x03).
    ButtonTertiary,
}

impl HidUsage {
    /// Convert a raw usage ID (within a usage page) to an enum variant.
    pub fn from_u16(value: u16) -> Self {
        match value {
            0x01 => Self::Pointer,
            0x02 => Self::Mouse,
            0x04 => Self::Joystick,
            0x06 => Self::Keyboard,
            0x30 => Self::X,
            0x31 => Self::Y,
            0x38 => Self::Wheel,
            // Button page usages overlap with generic desktop IDs,
            // but are disambiguated by the caller's usage page context.
            _ => Self::Pointer,
        }
    }

    /// Create a button usage from a 1-based button index.
    pub fn button_from_index(index: u16) -> Self {
        match index {
            1 => Self::ButtonPrimary,
            2 => Self::ButtonSecondary,
            3 => Self::ButtonTertiary,
            _ => Self::ButtonPrimary,
        }
    }
}

// ---------------------------------------------------------------------------
// HID Report Field
// ---------------------------------------------------------------------------

/// A single field within a HID report.
///
/// Each field describes one data item in the report: its usage,
/// position within the byte stream, size, and logical range.
#[derive(Debug, Clone, Copy, Default)]
pub struct HidReportField {
    /// Usage page this field belongs to.
    pub usage_page: HidUsagePage,
    /// Specific usage within the page.
    pub usage: HidUsage,
    /// Bit offset from the start of the report data.
    pub bit_offset: u16,
    /// Size of this field in bits.
    pub bit_size: u8,
    /// Minimum logical value the field can report.
    pub logical_min: i32,
    /// Maximum logical value the field can report.
    pub logical_max: i32,
    /// If `true`, the field is an array (selector); otherwise variable.
    pub is_array: bool,
}

// ---------------------------------------------------------------------------
// HID Report
// ---------------------------------------------------------------------------

/// A parsed HID report with raw data and field descriptors.
///
/// Provides methods to extract individual field values from the
/// raw report data by consulting the field's bit offset and size.
pub struct HidReport {
    /// Report ID (0 if the device uses a single default report).
    pub report_id: u8,
    /// Parsed fields in this report.
    pub fields: [HidReportField; MAX_REPORT_FIELDS],
    /// Number of valid fields.
    pub field_count: usize,
    /// Raw report data bytes.
    pub data: [u8; MAX_REPORT_DATA],
    /// Number of valid data bytes.
    pub data_len: usize,
}

impl Default for HidReport {
    fn default() -> Self {
        Self {
            report_id: 0,
            fields: [HidReportField::default(); MAX_REPORT_FIELDS],
            field_count: 0,
            data: [0u8; MAX_REPORT_DATA],
            data_len: 0,
        }
    }
}

impl HidReport {
    /// Create an empty HID report with the given report ID.
    pub fn new(report_id: u8) -> Self {
        Self {
            report_id,
            ..Self::default()
        }
    }

    /// Add a field descriptor to this report.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the maximum number of fields
    /// has been reached.
    pub fn add_field(&mut self, field: HidReportField) -> Result<()> {
        if self.field_count >= MAX_REPORT_FIELDS {
            return Err(Error::OutOfMemory);
        }
        self.fields[self.field_count] = field;
        self.field_count += 1;
        Ok(())
    }

    /// Extract the value of a field at the given bit offset and size.
    ///
    /// Reads `bit_size` bits starting at `bit_offset` from the report
    /// data and returns the value as a sign-extended `i32`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the field extends beyond
    /// the available data or `bit_size` exceeds 32.
    pub fn parse_field(&self, bit_offset: u16, bit_size: u8) -> Result<i32> {
        if bit_size == 0 || bit_size > 32 {
            return Err(Error::InvalidArgument);
        }

        let end_bit = bit_offset as usize + bit_size as usize;
        let end_byte = end_bit.div_ceil(8);
        if end_byte > self.data_len {
            return Err(Error::InvalidArgument);
        }

        let mut value: u32 = 0;
        for i in 0..bit_size as usize {
            let abs_bit = bit_offset as usize + i;
            let byte_idx = abs_bit / 8;
            let bit_idx = abs_bit % 8;
            if self.data[byte_idx] & (1 << bit_idx) != 0 {
                value |= 1 << i;
            }
        }

        // Sign-extend if the high bit is set.
        if bit_size < 32 && (value & (1 << (bit_size - 1))) != 0 {
            let mask = !((1u32 << bit_size) - 1);
            value |= mask;
        }

        Ok(value as i32)
    }

    /// Store raw report data.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `data` exceeds
    /// [`MAX_REPORT_DATA`] bytes.
    pub fn set_data(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > MAX_REPORT_DATA {
            return Err(Error::InvalidArgument);
        }
        self.data[..data.len()].copy_from_slice(data);
        self.data_len = data.len();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// HID Device Type
// ---------------------------------------------------------------------------

/// Classification of a HID device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HidDeviceType {
    /// Standard keyboard.
    Keyboard,
    /// Standard mouse or pointing device.
    Mouse,
    /// Gamepad or joystick.
    Gamepad,
    /// Generic or unrecognised HID device.
    #[default]
    Generic,
}

// ---------------------------------------------------------------------------
// HID Device
// ---------------------------------------------------------------------------

/// A single USB HID device.
///
/// Encapsulates device classification, report descriptor fields,
/// endpoint configuration, and methods for processing incoming
/// interrupt-IN reports.
pub struct HidDevice {
    /// Device type classification.
    pub device_type: HidDeviceType,
    /// Parsed report descriptor fields.
    pub report_descriptor: [HidReportField; MAX_DESCRIPTOR_FIELDS],
    /// Number of valid descriptor fields.
    pub descriptor_field_count: usize,
    /// Interrupt-IN endpoint address.
    pub endpoint: u8,
    /// Polling interval in milliseconds.
    pub poll_interval_ms: u8,
    /// Device identifier within the registry.
    pub device_id: u8,
    /// Whether the device is currently connected.
    pub connected: bool,
}

impl HidDevice {
    /// Create a new HID device.
    pub fn new(device_id: u8, device_type: HidDeviceType, endpoint: u8, poll_ms: u8) -> Self {
        Self {
            device_type,
            report_descriptor: [HidReportField::default(); MAX_DESCRIPTOR_FIELDS],
            descriptor_field_count: 0,
            endpoint,
            poll_interval_ms: poll_ms,
            device_id,
            connected: true,
        }
    }

    /// Add a field to the report descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the maximum number of
    /// descriptor fields has been reached.
    pub fn add_report_field(&mut self, field: HidReportField) -> Result<()> {
        if self.descriptor_field_count >= MAX_DESCRIPTOR_FIELDS {
            return Err(Error::OutOfMemory);
        }
        self.report_descriptor[self.descriptor_field_count] = field;
        self.descriptor_field_count += 1;
        Ok(())
    }

    /// Process an incoming interrupt-IN report.
    ///
    /// Parses the raw `data` against the stored report descriptor
    /// fields and returns a [`HidReport`] with the extracted values.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the device is not connected.
    /// - [`Error::InvalidArgument`] if `data` is empty or too large.
    pub fn process_report(&self, data: &[u8]) -> Result<HidReport> {
        if !self.connected {
            return Err(Error::NotFound);
        }
        if data.is_empty() || data.len() > MAX_REPORT_DATA {
            return Err(Error::InvalidArgument);
        }

        let mut report = HidReport::new(0);
        report.set_data(data)?;

        // Copy descriptor fields into the report.
        let count = self.descriptor_field_count.min(MAX_REPORT_FIELDS);
        for i in 0..count {
            report.add_field(self.report_descriptor[i])?;
        }

        Ok(report)
    }
}

// ---------------------------------------------------------------------------
// HID Registry
// ---------------------------------------------------------------------------

/// Registry of attached USB HID devices.
///
/// Tracks up to [`MAX_HID_DEVICES`] devices and provides lookup,
/// registration, removal, and interrupt dispatch operations.
pub struct HidRegistry {
    /// Fixed-size array of device slots.
    devices: [Option<HidDevice>; MAX_HID_DEVICES],
    /// Number of currently registered devices.
    count: usize,
}

impl Default for HidRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl HidRegistry {
    /// Create an empty HID device registry.
    pub const fn new() -> Self {
        const NONE: Option<HidDevice> = None;
        Self {
            devices: [NONE; MAX_HID_DEVICES],
            count: 0,
        }
    }

    /// Register a new HID device.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the registry is full.
    /// - [`Error::AlreadyExists`] if a device with the same
    ///   `device_id` is already registered.
    pub fn register(&mut self, device: HidDevice) -> Result<()> {
        // Check for duplicates.
        for slot in self.devices.iter().flatten() {
            if slot.device_id == device.device_id {
                return Err(Error::AlreadyExists);
            }
        }
        // Find an empty slot.
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
    /// # Errors
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
    pub fn find(&self, device_id: u8) -> Option<&HidDevice> {
        self.devices
            .iter()
            .find_map(|slot| slot.as_ref().filter(|d| d.device_id == device_id))
    }

    /// Find a mutable reference to a device by its `device_id`.
    pub fn find_mut(&mut self, device_id: u8) -> Option<&mut HidDevice> {
        self.devices
            .iter_mut()
            .find_map(|slot| slot.as_mut().filter(|d| d.device_id == device_id))
    }

    /// Process an interrupt for a specific device.
    ///
    /// Looks up the device by `device_id`, then delegates to
    /// [`HidDevice::process_report`].
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no device with that ID exists.
    /// - Propagates errors from [`HidDevice::process_report`].
    pub fn process_interrupt(&self, device_id: u8, data: &[u8]) -> Result<HidReport> {
        let device = self.find(device_id).ok_or(Error::NotFound)?;
        device.process_report(data)
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
