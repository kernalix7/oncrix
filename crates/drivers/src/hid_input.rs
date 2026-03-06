// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! HID input device driver.
//!
//! Processes USB/Bluetooth HID (Human Interface Device) input data.
//! Parses HID report descriptors to extract field definitions, then
//! translates incoming reports into structured input events
//! (key presses, mouse movements, button states).
//!
//! # Architecture
//!
//! - [`HidFieldType`] -- classification of a report field (input,
//!   output, feature).
//! - [`HidField`] -- a single field within a HID report, describing
//!   its usage page, usage ID, bit offset/size, and logical range.
//! - [`ReportDescriptor`] -- a parsed HID report descriptor containing
//!   an array of fields.
//! - [`HidReport`] -- a single incoming HID report with raw data and
//!   extracted field values.
//! - [`InputEvent`] -- a translated input event (key, relative axis,
//!   absolute axis, button).
//! - [`HidDevice`] -- a single HID device with descriptor parsing
//!   and report processing.
//! - [`HidDeviceRegistry`] -- manages up to [`MAX_DEVICES`] HID
//!   devices.
//!
//! Reference: USB HID Specification 1.11,
//!            USB HID Usage Tables 1.4,
//!            Linux `drivers/hid/hid-input.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of HID devices.
const MAX_DEVICES: usize = 16;

/// Maximum number of fields per report descriptor.
const MAX_FIELDS: usize = 64;

/// Maximum report data size in bytes.
const MAX_REPORT_DATA: usize = 64;

/// Maximum number of pending input events per device.
const MAX_EVENTS: usize = 32;

/// Maximum number of report IDs per device.
const MAX_REPORT_IDS: usize = 16;

/// Maximum device name length.
const MAX_NAME_LEN: usize = 64;

/// Maximum report descriptor raw size in bytes.
const MAX_DESCRIPTOR_SIZE: usize = 512;

// ---------------------------------------------------------------------------
// HID Usage Pages
// ---------------------------------------------------------------------------

/// Common HID usage page identifiers.
pub mod usage_page {
    /// Generic Desktop page (0x01): pointers, mice, joysticks, keyboards.
    pub const GENERIC_DESKTOP: u16 = 0x01;
    /// Simulation Controls page (0x02).
    pub const SIMULATION: u16 = 0x02;
    /// VR Controls page (0x03).
    pub const VR: u16 = 0x03;
    /// Sport Controls page (0x04).
    pub const SPORT: u16 = 0x04;
    /// Game Controls page (0x05).
    pub const GAME: u16 = 0x05;
    /// Generic Device Controls page (0x06).
    pub const GENERIC_DEVICE: u16 = 0x06;
    /// Keyboard/Keypad page (0x07).
    pub const KEYBOARD: u16 = 0x07;
    /// LED page (0x08).
    pub const LED: u16 = 0x08;
    /// Button page (0x09).
    pub const BUTTON: u16 = 0x09;
    /// Consumer page (0x0C): media keys, volume, etc.
    pub const CONSUMER: u16 = 0x0C;
}

/// Common Generic Desktop usages.
pub mod usage_desktop {
    /// Pointer usage (mouse/trackpad).
    pub const POINTER: u16 = 0x01;
    /// Mouse usage.
    pub const MOUSE: u16 = 0x02;
    /// Joystick usage.
    pub const JOYSTICK: u16 = 0x04;
    /// Gamepad usage.
    pub const GAMEPAD: u16 = 0x05;
    /// Keyboard usage.
    pub const KEYBOARD: u16 = 0x06;
    /// Keypad usage.
    pub const KEYPAD: u16 = 0x07;
    /// X axis.
    pub const X: u16 = 0x30;
    /// Y axis.
    pub const Y: u16 = 0x31;
    /// Z axis.
    pub const Z: u16 = 0x32;
    /// Wheel.
    pub const WHEEL: u16 = 0x38;
}

// ---------------------------------------------------------------------------
// HidFieldType
// ---------------------------------------------------------------------------

/// Classification of a HID report field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HidFieldType {
    /// Input field (device to host, e.g., button state, axis value).
    #[default]
    Input,
    /// Output field (host to device, e.g., LED indicator).
    Output,
    /// Feature field (bidirectional configuration).
    Feature,
}

// ---------------------------------------------------------------------------
// HidFieldFlags
// ---------------------------------------------------------------------------

/// HID report field attribute flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HidFieldFlags(pub u32);

impl HidFieldFlags {
    /// Data (0) vs. Constant (1).
    pub const CONSTANT: u32 = 1 << 0;
    /// Array (0) vs. Variable (1).
    pub const VARIABLE: u32 = 1 << 1;
    /// Absolute (0) vs. Relative (1).
    pub const RELATIVE: u32 = 1 << 2;
    /// No Wrap (0) vs. Wrap (1).
    pub const WRAP: u32 = 1 << 3;
    /// Linear (0) vs. Non-Linear (1).
    pub const NON_LINEAR: u32 = 1 << 4;

    /// Creates new field flags.
    pub const fn new(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns `true` if the given flag is set.
    pub fn has(self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    /// Returns `true` if this is a variable field.
    pub fn is_variable(self) -> bool {
        self.has(Self::VARIABLE)
    }

    /// Returns `true` if this is a relative field (e.g., mouse delta).
    pub fn is_relative(self) -> bool {
        self.has(Self::RELATIVE)
    }
}

// ---------------------------------------------------------------------------
// HidField
// ---------------------------------------------------------------------------

/// A single field within a HID report.
///
/// Each field describes one logical value in a report: its usage
/// page, usage ID, bit position, size, logical range, and flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct HidField {
    /// Field type (input, output, feature).
    pub field_type: HidFieldType,
    /// Usage page for this field.
    pub usage_page: u16,
    /// Usage ID within the usage page.
    pub usage_id: u16,
    /// Report ID this field belongs to (0 if no report IDs).
    pub report_id: u8,
    /// Bit offset within the report data.
    pub bit_offset: u32,
    /// Size of this field in bits.
    pub bit_size: u32,
    /// Logical minimum value.
    pub logical_min: i32,
    /// Logical maximum value.
    pub logical_max: i32,
    /// Physical minimum value.
    pub physical_min: i32,
    /// Physical maximum value.
    pub physical_max: i32,
    /// Field attribute flags.
    pub flags: HidFieldFlags,
}

/// Constant empty field for array initialisation.
const EMPTY_FIELD: HidField = HidField {
    field_type: HidFieldType::Input,
    usage_page: 0,
    usage_id: 0,
    report_id: 0,
    bit_offset: 0,
    bit_size: 0,
    logical_min: 0,
    logical_max: 0,
    physical_min: 0,
    physical_max: 0,
    flags: HidFieldFlags(0),
};

impl HidField {
    /// Extracts the field value from raw report data.
    ///
    /// Returns the value as a signed integer, sign-extended from
    /// the field's bit size.
    pub fn extract_value(&self, data: &[u8]) -> i32 {
        let byte_offset = (self.bit_offset / 8) as usize;
        let bit_start = (self.bit_offset % 8) as usize;
        let bits = self.bit_size as usize;

        if bits == 0 || byte_offset >= data.len() {
            return 0;
        }

        // Collect enough bytes to cover the field.
        let mut raw: u32 = 0;
        let bytes_needed = (bit_start + bits + 7) / 8;
        for i in 0..bytes_needed.min(4) {
            if byte_offset + i < data.len() {
                raw |= (data[byte_offset + i] as u32) << (i * 8);
            }
        }

        // Extract the bits.
        raw >>= bit_start;
        let mask = if bits >= 32 {
            u32::MAX
        } else {
            (1u32 << bits) - 1
        };
        let unsigned_val = raw & mask;

        // Sign-extend if the field can be negative.
        if self.logical_min < 0 && bits < 32 {
            let sign_bit = 1u32 << (bits - 1);
            if unsigned_val & sign_bit != 0 {
                return (unsigned_val | !mask) as i32;
            }
        }
        unsigned_val as i32
    }
}

// ---------------------------------------------------------------------------
// ReportDescriptor
// ---------------------------------------------------------------------------

/// A parsed HID report descriptor.
///
/// Contains the array of fields extracted from the raw descriptor
/// bytes using the HID report descriptor parser.
pub struct ReportDescriptor {
    /// Parsed fields.
    fields: [HidField; MAX_FIELDS],
    /// Number of valid fields.
    field_count: usize,
    /// Raw descriptor bytes.
    raw: [u8; MAX_DESCRIPTOR_SIZE],
    /// Length of raw descriptor.
    raw_len: usize,
    /// Total report size in bits (for report ID 0).
    pub report_size_bits: u32,
}

impl ReportDescriptor {
    /// Creates a new empty report descriptor.
    pub const fn new() -> Self {
        Self {
            fields: [EMPTY_FIELD; MAX_FIELDS],
            field_count: 0,
            raw: [0u8; MAX_DESCRIPTOR_SIZE],
            raw_len: 0,
            report_size_bits: 0,
        }
    }

    /// Stores the raw descriptor bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `data` exceeds the
    /// maximum descriptor size.
    pub fn set_raw(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > MAX_DESCRIPTOR_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.raw[..data.len()].copy_from_slice(data);
        self.raw_len = data.len();
        Ok(())
    }

    /// Adds a field to the descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the field array is full.
    pub fn add_field(&mut self, field: HidField) -> Result<()> {
        if self.field_count >= MAX_FIELDS {
            return Err(Error::OutOfMemory);
        }
        self.fields[self.field_count] = field;
        self.field_count += 1;
        // Update total report size.
        let field_end = field.bit_offset + field.bit_size;
        if field_end > self.report_size_bits {
            self.report_size_bits = field_end;
        }
        Ok(())
    }

    /// Returns the slice of parsed fields.
    pub fn fields(&self) -> &[HidField] {
        &self.fields[..self.field_count]
    }

    /// Returns the number of fields.
    pub fn field_count(&self) -> usize {
        self.field_count
    }

    /// Returns the report size in bytes (rounded up from bits).
    pub fn report_size_bytes(&self) -> usize {
        (self.report_size_bits as usize + 7) / 8
    }

    /// Finds all fields matching a given usage page.
    ///
    /// Returns the number of matching fields written to `out`.
    pub fn find_by_usage_page(&self, page: u16, out: &mut [usize]) -> usize {
        let mut count = 0;
        for (i, f) in self.fields[..self.field_count].iter().enumerate() {
            if f.usage_page == page && count < out.len() {
                out[count] = i;
                count += 1;
            }
        }
        count
    }
}

impl Default for ReportDescriptor {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// InputEventType
// ---------------------------------------------------------------------------

/// Type of translated input event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InputEventType {
    /// Key press/release event.
    #[default]
    Key,
    /// Relative axis movement (e.g., mouse delta).
    RelativeAxis,
    /// Absolute axis position (e.g., joystick, touchscreen).
    AbsoluteAxis,
    /// Button press/release.
    Button,
    /// Synchronisation event (report boundary).
    Sync,
}

// ---------------------------------------------------------------------------
// InputEvent
// ---------------------------------------------------------------------------

/// A translated input event from HID report processing.
#[derive(Debug, Clone, Copy, Default)]
pub struct InputEvent {
    /// Event type.
    pub event_type: InputEventType,
    /// Event code (key code, axis code, button number).
    pub code: u16,
    /// Event value (1 = pressed, 0 = released, or axis value).
    pub value: i32,
    /// Timestamp in nanoseconds.
    pub timestamp_ns: u64,
}

// ---------------------------------------------------------------------------
// HidReport
// ---------------------------------------------------------------------------

/// A single incoming HID report with raw data.
#[derive(Clone, Copy)]
pub struct HidReport {
    /// Report ID (0 if the device does not use report IDs).
    pub report_id: u8,
    /// Raw report data.
    pub data: [u8; MAX_REPORT_DATA],
    /// Length of valid data.
    pub data_len: usize,
    /// Timestamp when the report was received.
    pub timestamp_ns: u64,
}

impl HidReport {
    /// Creates a new report from raw data.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `data` exceeds the
    /// maximum report size.
    pub fn new(report_id: u8, data: &[u8], timestamp_ns: u64) -> Result<Self> {
        if data.len() > MAX_REPORT_DATA {
            return Err(Error::InvalidArgument);
        }
        let mut buf = [0u8; MAX_REPORT_DATA];
        buf[..data.len()].copy_from_slice(data);
        Ok(Self {
            report_id,
            data: buf,
            data_len: data.len(),
            timestamp_ns,
        })
    }

    /// Returns the report data as a slice.
    pub fn data(&self) -> &[u8] {
        &self.data[..self.data_len]
    }
}

impl core::fmt::Debug for HidReport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HidReport")
            .field("report_id", &self.report_id)
            .field("data_len", &self.data_len)
            .field("timestamp_ns", &self.timestamp_ns)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// HidDeviceType
// ---------------------------------------------------------------------------

/// Classification of a HID device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HidDeviceType {
    /// Unknown or unclassified HID device.
    #[default]
    Unknown,
    /// Keyboard.
    Keyboard,
    /// Mouse.
    Mouse,
    /// Gamepad/joystick.
    Gamepad,
    /// Touchscreen.
    Touchscreen,
    /// Tablet/digitiser.
    Tablet,
    /// Consumer control (media keys).
    Consumer,
}

// ---------------------------------------------------------------------------
// HidDevice
// ---------------------------------------------------------------------------

/// A single HID input device.
///
/// Manages the report descriptor, processes incoming reports, and
/// translates them into input events.
pub struct HidDevice {
    /// Unique device identifier.
    pub id: u32,
    /// Device name.
    pub name: [u8; MAX_NAME_LEN],
    /// Number of valid bytes in name.
    pub name_len: usize,
    /// USB vendor ID.
    pub vendor_id: u16,
    /// USB product ID.
    pub product_id: u16,
    /// Device type classification.
    pub device_type: HidDeviceType,
    /// Parsed report descriptor.
    pub descriptor: ReportDescriptor,
    /// Pending input events (ring buffer).
    events: [InputEvent; MAX_EVENTS],
    /// Write index into the event buffer.
    event_head: usize,
    /// Read index into the event buffer.
    event_tail: usize,
    /// Whether this device is active.
    pub active: bool,
    /// Total reports processed.
    pub report_count: u64,
}

impl HidDevice {
    /// Creates a new HID device.
    pub fn new(id: u32, name: &[u8], vendor_id: u16, product_id: u16) -> Self {
        let copy_len = name.len().min(MAX_NAME_LEN);
        let mut name_buf = [0u8; MAX_NAME_LEN];
        name_buf[..copy_len].copy_from_slice(&name[..copy_len]);

        Self {
            id,
            name: name_buf,
            name_len: copy_len,
            vendor_id,
            product_id,
            device_type: HidDeviceType::Unknown,
            descriptor: ReportDescriptor::new(),
            events: [InputEvent::default(); MAX_EVENTS],
            event_head: 0,
            event_tail: 0,
            active: false,
            report_count: 0,
        }
    }

    /// Initialises the device after the report descriptor is parsed.
    ///
    /// Classifies the device type based on the descriptor fields.
    pub fn init(&mut self) -> Result<()> {
        self.classify_device();
        self.active = true;
        Ok(())
    }

    /// Processes an incoming HID report and generates input events.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the device is not active.
    pub fn process_report(&mut self, report: &HidReport) -> Result<usize> {
        if !self.active {
            return Err(Error::Busy);
        }
        self.report_count += 1;
        let mut event_count = 0;

        // Collect events from descriptor fields before mutating self (push_event).
        let mut pending = [InputEvent::default(); MAX_FIELDS];
        let mut pending_count = 0;
        for field in self.descriptor.fields() {
            if field.field_type != HidFieldType::Input {
                continue;
            }
            if field.flags.has(HidFieldFlags::CONSTANT) {
                continue;
            }
            let value = field.extract_value(report.data());
            let event_type = if field.flags.is_relative() {
                InputEventType::RelativeAxis
            } else if field.usage_page == usage_page::KEYBOARD
                || field.usage_page == usage_page::BUTTON
            {
                InputEventType::Key
            } else {
                InputEventType::AbsoluteAxis
            };
            pending[pending_count] = InputEvent {
                event_type,
                code: field.usage_id,
                value,
                timestamp_ns: report.timestamp_ns,
            };
            pending_count += 1;
        }
        for event in &pending[..pending_count] {
            self.push_event(*event);
            event_count += 1;
        }

        // Sync event to mark end of report.
        self.push_event(InputEvent {
            event_type: InputEventType::Sync,
            code: 0,
            value: 0,
            timestamp_ns: report.timestamp_ns,
        });
        event_count += 1;

        Ok(event_count)
    }

    /// Pops the oldest input event from the queue.
    ///
    /// Returns `None` if the queue is empty.
    pub fn pop_event(&mut self) -> Option<InputEvent> {
        if self.event_head == self.event_tail {
            return None;
        }
        let event = self.events[self.event_tail];
        self.event_tail = (self.event_tail + 1) % MAX_EVENTS;
        Some(event)
    }

    /// Returns the number of pending events.
    pub fn event_count(&self) -> usize {
        if self.event_head >= self.event_tail {
            self.event_head - self.event_tail
        } else {
            MAX_EVENTS - self.event_tail + self.event_head
        }
    }

    // -- internal ---------------------------------------------------------

    fn push_event(&mut self, event: InputEvent) {
        self.events[self.event_head] = event;
        self.event_head = (self.event_head + 1) % MAX_EVENTS;
        if self.event_head == self.event_tail {
            self.event_tail = (self.event_tail + 1) % MAX_EVENTS;
        }
    }

    fn classify_device(&mut self) {
        for field in self.descriptor.fields() {
            if field.usage_page == usage_page::GENERIC_DESKTOP {
                match field.usage_id {
                    usage_desktop::KEYBOARD | usage_desktop::KEYPAD => {
                        self.device_type = HidDeviceType::Keyboard;
                        return;
                    }
                    usage_desktop::MOUSE | usage_desktop::POINTER => {
                        self.device_type = HidDeviceType::Mouse;
                        return;
                    }
                    usage_desktop::GAMEPAD | usage_desktop::JOYSTICK => {
                        self.device_type = HidDeviceType::Gamepad;
                        return;
                    }
                    _ => {}
                }
            } else if field.usage_page == usage_page::CONSUMER {
                self.device_type = HidDeviceType::Consumer;
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// HidDeviceRegistry
// ---------------------------------------------------------------------------

/// Registry managing up to [`MAX_DEVICES`] HID devices.
pub struct HidDeviceRegistry {
    /// Registered devices.
    devices: [Option<HidDevice>; MAX_DEVICES],
    /// Number of registered devices.
    count: usize,
}

impl HidDeviceRegistry {
    /// Creates a new empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_DEVICES],
            count: 0,
        }
    }

    /// Registers a HID device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a device with the same ID exists.
    pub fn register(&mut self, device: HidDevice) -> Result<()> {
        for slot in self.devices.iter().flatten() {
            if slot.id == device.id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in self.devices.iter_mut() {
            if slot.is_none() {
                *slot = Some(device);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Returns a reference to a device by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not found.
    pub fn get(&self, id: u32) -> Result<&HidDevice> {
        for slot in self.devices.iter().flatten() {
            if slot.id == id {
                return Ok(slot);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns a mutable reference to a device by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not found.
    pub fn get_mut(&mut self, id: u32) -> Result<&mut HidDevice> {
        for slot in self.devices.iter_mut() {
            if let Some(d) = slot {
                if d.id == id {
                    return Ok(d);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for HidDeviceRegistry {
    fn default() -> Self {
        Self::new()
    }
}
