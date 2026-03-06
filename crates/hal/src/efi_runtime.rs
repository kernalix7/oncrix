// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! EFI Runtime Services interface.
//!
//! Provides a safe, no_std abstraction over the UEFI Runtime Services table,
//! following the UEFI Specification 2.10 (section 8). Runtime services remain
//! accessible after `ExitBootServices` and are used for NVRAM variable access,
//! time-of-day management, capsule updates, and monotonic counters.
//!
//! # Architecture
//!
//! - [`EfiStatus`] — UEFI status codes mapped to ONCRIX [`Error`] variants.
//! - [`EfiGuid`] — 128-bit globally unique identifier (RFC 4122 variant).
//! - [`EfiTime`] — UEFI time structure (date + time + timezone + daylight).
//! - [`EfiTimeCapabilities`] — resolution and accuracy of the hardware RTC.
//! - [`VariableAttributes`] — NVRAM variable persistence and access flags.
//! - [`EfiVariable`] — a single NVRAM variable (name + GUID + data).
//! - [`VariableStore`] — in-kernel shadow of up to [`MAX_VARIABLES`] EFI
//!   variables with get/set/delete and iteration.
//! - [`CapsuleHeader`] — UEFI capsule update header stub.
//! - [`EfiRuntimeServices`] — top-level struct combining variable store,
//!   time, monotonic counter, reset control, and capsule stubs.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of EFI variables in the in-kernel store.
const MAX_VARIABLES: usize = 64;

/// Maximum EFI variable name length in UTF-16 code units.
const MAX_VAR_NAME_LEN: usize = 128;

/// Maximum EFI variable data size in bytes.
const MAX_VAR_DATA: usize = 512;

/// EFI variable namespace GUID for global variables (EFI_GLOBAL_VARIABLE).
pub const EFI_GLOBAL_VARIABLE_GUID: EfiGuid = EfiGuid {
    data1: 0x8BE4_DF61,
    data2: 0x93CA,
    data3: 0x11D2,
    data4: [0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C],
};

/// EFI Capsule flags: persist across reset.
pub const CAPSULE_FLAGS_PERSIST_ACROSS_RESET: u32 = 0x0001_0000;

/// EFI Capsule flags: populate system table.
pub const CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE: u32 = 0x0002_0000;

/// EFI Capsule flags: initiate reset.
pub const CAPSULE_FLAGS_INITIATE_RESET: u32 = 0x0004_0000;

// -------------------------------------------------------------------
// EfiStatus
// -------------------------------------------------------------------

/// UEFI status codes (UINTN-wide on target, represented as u64 here).
///
/// Error codes have bit 63 set; warning codes have bit 63 clear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum EfiStatus {
    /// Operation completed successfully.
    Success = 0,
    /// Image was loaded, but did not match the target's list.
    LoadError = 0x8000_0000_0000_0001,
    /// A parameter was incorrect.
    InvalidParameter = 0x8000_0000_0000_0002,
    /// The operation is not supported.
    Unsupported = 0x8000_0000_0000_0003,
    /// The buffer was not large enough.
    BufferTooSmall = 0x8000_0000_0000_0005,
    /// There is no data pending.
    NotReady = 0x8000_0000_0000_0006,
    /// The physical device reported an error.
    DeviceError = 0x8000_0000_0000_0007,
    /// The resource has run out.
    OutOfResources = 0x8000_0000_0000_0009,
    /// An item was not found.
    NotFound = 0x8000_0000_0000_000E,
    /// Access was denied.
    AccessDenied = 0x8000_0000_0000_000F,
    /// A timeout occurred.
    Timeout = 0x8000_0000_0000_0012,
    /// An aborted operation.
    Aborted = 0x8000_0000_0000_0015,
    /// Security violation.
    SecurityViolation = 0x8000_0000_0000_001A,
}

impl EfiStatus {
    /// Returns `true` if this status indicates success.
    #[inline]
    pub fn is_success(self) -> bool {
        self == Self::Success
    }

    /// Returns `true` if this is an error status (bit 63 set).
    #[inline]
    pub fn is_error(self) -> bool {
        (self as u64) & 0x8000_0000_0000_0000 != 0
    }

    /// Converts to a kernel [`Result`], mapping error codes to
    /// [`oncrix_lib::Error`] variants.
    pub fn to_result(self) -> Result<()> {
        match self {
            Self::Success => Ok(()),
            Self::InvalidParameter => Err(Error::InvalidArgument),
            Self::Unsupported => Err(Error::NotImplemented),
            Self::BufferTooSmall | Self::OutOfResources => Err(Error::OutOfMemory),
            Self::NotFound => Err(Error::NotFound),
            Self::AccessDenied | Self::SecurityViolation => Err(Error::PermissionDenied),
            Self::DeviceError | Self::LoadError => Err(Error::IoError),
            Self::NotReady | Self::Timeout => Err(Error::Busy),
            Self::Aborted => Err(Error::Interrupted),
        }
    }
}

// -------------------------------------------------------------------
// EfiGuid
// -------------------------------------------------------------------

/// A 128-bit EFI GUID as defined in the UEFI specification.
///
/// Stored in the mixed-endian layout used by UEFI (data1/data2/data3
/// in little-endian, data4 as a raw byte array).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct EfiGuid {
    /// First component (32 bits, little-endian).
    pub data1: u32,
    /// Second component (16 bits, little-endian).
    pub data2: u16,
    /// Third component (16 bits, little-endian).
    pub data3: u16,
    /// Fourth component (8 bytes, big-endian).
    pub data4: [u8; 8],
}

impl EfiGuid {
    /// Creates a new GUID from its four components.
    pub const fn new(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> Self {
        Self {
            data1: d1,
            data2: d2,
            data3: d3,
            data4: d4,
        }
    }

    /// Returns `true` if this is the nil (all-zero) GUID.
    pub fn is_nil(self) -> bool {
        self.data1 == 0 && self.data2 == 0 && self.data3 == 0 && self.data4 == [0u8; 8]
    }
}

impl Default for EfiGuid {
    fn default() -> Self {
        Self {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0u8; 8],
        }
    }
}

// -------------------------------------------------------------------
// EfiTime
// -------------------------------------------------------------------

/// UEFI time representation (`EFI_TIME`).
///
/// Covers dates from year 1900 to 9999. Timezone is in minutes offset
/// from UTC (–1440 to +1440); [`EFI_UNSPECIFIED_TIMEZONE`] means local.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct EfiTime {
    /// Year (1900–9999).
    pub year: u16,
    /// Month (1–12).
    pub month: u8,
    /// Day (1–31).
    pub day: u8,
    /// Hour (0–23).
    pub hour: u8,
    /// Minute (0–59).
    pub minute: u8,
    /// Second (0–59).
    pub second: u8,
    /// Pad byte (must be 0).
    pub pad1: u8,
    /// Nanoseconds (0–999_999_999).
    pub nanosecond: u32,
    /// Timezone offset in minutes from UTC, or [`EFI_UNSPECIFIED_TIMEZONE`].
    pub timezone: i16,
    /// Daylight saving adjustment flags.
    pub daylight: u8,
    /// Pad byte (must be 0).
    pub pad2: u8,
}

/// Timezone value indicating local time (no UTC offset known).
pub const EFI_UNSPECIFIED_TIMEZONE: i16 = 0x07FF;

/// Daylight flag: adjust clock for DST.
pub const EFI_TIME_ADJUST_DAYLIGHT: u8 = 0x01;

/// Daylight flag: clock is currently in DST.
pub const EFI_TIME_IN_DAYLIGHT: u8 = 0x02;

impl EfiTime {
    /// Returns `true` if the time fields are within valid UEFI ranges.
    pub fn is_valid(&self) -> bool {
        self.year >= 1900
            && self.year <= 9999
            && self.month >= 1
            && self.month <= 12
            && self.day >= 1
            && self.day <= 31
            && self.hour <= 23
            && self.minute <= 59
            && self.second <= 59
            && self.nanosecond <= 999_999_999
            && (self.timezone == EFI_UNSPECIFIED_TIMEZONE
                || (self.timezone >= -1440 && self.timezone <= 1440))
    }
}

// -------------------------------------------------------------------
// EfiTimeCapabilities
// -------------------------------------------------------------------

/// Hardware clock resolution and accuracy (`EFI_TIME_CAPABILITIES`).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct EfiTimeCapabilities {
    /// Resolution of the clock in counts per second (e.g. 1 Hz = 1).
    pub resolution: u32,
    /// Clock accuracy in parts per million × 1e6 (e.g. 50 ppm = 50_000_000).
    pub accuracy: u32,
    /// Whether a time `Set` operation clears the sub-second counter.
    pub sets_to_zero: bool,
}

// -------------------------------------------------------------------
// VariableAttributes
// -------------------------------------------------------------------

/// UEFI NVRAM variable attribute flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VariableAttributes(pub u32);

impl VariableAttributes {
    /// Variable persists across power cycles (stored in NVRAM).
    pub const NON_VOLATILE: Self = Self(0x0000_0001);
    /// Variable is accessible during boot services.
    pub const BOOTSERVICE_ACCESS: Self = Self(0x0000_0002);
    /// Variable is accessible at runtime (after ExitBootServices).
    pub const RUNTIME_ACCESS: Self = Self(0x0000_0004);
    /// Variable contains hardware error records.
    pub const HARDWARE_ERROR_RECORD: Self = Self(0x0000_0008);
    /// Variable is authenticated (time-based).
    pub const TIME_BASED_AUTHENTICATED: Self = Self(0x0000_0020);
    /// Variable is append-only.
    pub const APPEND_WRITE: Self = Self(0x0000_0040);

    /// Returns `true` if `other` flags are all set in `self`.
    #[inline]
    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns the union of `self` and `other`.
    #[inline]
    pub fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

// -------------------------------------------------------------------
// EfiVariable
// -------------------------------------------------------------------

/// An EFI NVRAM variable (name + GUID + attributes + data).
///
/// Variable names in UEFI are UCS-2 (UTF-16LE); here stored as raw
/// `u16` code units, not null-terminated.
#[derive(Clone, Copy)]
pub struct EfiVariable {
    /// Variable name as UTF-16LE code units.
    pub name: [u16; MAX_VAR_NAME_LEN],
    /// Number of valid code units in [`name`](Self::name).
    pub name_len: usize,
    /// Vendor GUID namespace.
    pub guid: EfiGuid,
    /// Access and persistence attributes.
    pub attributes: VariableAttributes,
    /// Variable data bytes.
    pub data: [u8; MAX_VAR_DATA],
    /// Number of valid bytes in [`data`](Self::data).
    pub data_len: usize,
    /// Whether this slot is occupied.
    pub occupied: bool,
}

impl EfiVariable {
    /// Creates a new variable with the given name (UTF-16 units), GUID,
    /// attributes, and data.
    ///
    /// Returns [`Error::InvalidArgument`] if the name or data exceed their
    /// maximum lengths.
    pub fn new(
        name: &[u16],
        guid: EfiGuid,
        attributes: VariableAttributes,
        data: &[u8],
    ) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_VAR_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if data.len() > MAX_VAR_DATA {
            return Err(Error::InvalidArgument);
        }
        let mut name_buf = [0u16; MAX_VAR_NAME_LEN];
        name_buf[..name.len()].copy_from_slice(name);
        let mut data_buf = [0u8; MAX_VAR_DATA];
        data_buf[..data.len()].copy_from_slice(data);
        Ok(Self {
            name: name_buf,
            name_len: name.len(),
            guid,
            attributes,
            data: data_buf,
            data_len: data.len(),
            occupied: true,
        })
    }

    /// Returns the variable name as a slice of UTF-16 code units.
    pub fn name_units(&self) -> &[u16] {
        &self.name[..self.name_len]
    }

    /// Returns the variable data as a byte slice.
    pub fn data_bytes(&self) -> &[u8] {
        &self.data[..self.data_len]
    }

    /// Returns `true` if this variable's name and GUID match the given values.
    pub fn matches(&self, name: &[u16], guid: &EfiGuid) -> bool {
        &self.name[..self.name_len] == name && &self.guid == guid
    }
}

impl Default for EfiVariable {
    fn default() -> Self {
        Self {
            name: [0u16; MAX_VAR_NAME_LEN],
            name_len: 0,
            guid: EfiGuid::default(),
            attributes: VariableAttributes::default(),
            data: [0u8; MAX_VAR_DATA],
            data_len: 0,
            occupied: false,
        }
    }
}

// -------------------------------------------------------------------
// VariableStore
// -------------------------------------------------------------------

/// In-kernel shadow store for EFI NVRAM variables.
///
/// Holds up to [`MAX_VARIABLES`] variables. On real hardware, get/set
/// calls would delegate to the firmware's `GetVariable`/`SetVariable`
/// runtime service. This store provides a pure-Rust, no-firmware
/// implementation suitable for emulation and early boot.
pub struct VariableStore {
    /// Variable slots.
    vars: [EfiVariable; MAX_VARIABLES],
    /// Number of occupied slots.
    count: usize,
}

impl VariableStore {
    /// Creates a new, empty variable store.
    pub const fn new() -> Self {
        Self {
            vars: [EfiVariable {
                name: [0u16; MAX_VAR_NAME_LEN],
                name_len: 0,
                guid: EfiGuid {
                    data1: 0,
                    data2: 0,
                    data3: 0,
                    data4: [0u8; 8],
                },
                attributes: VariableAttributes(0),
                data: [0u8; MAX_VAR_DATA],
                data_len: 0,
                occupied: false,
            }; MAX_VARIABLES],
            count: 0,
        }
    }

    /// Retrieves the value of a variable.
    ///
    /// Writes the variable's attributes and data into `attributes` and
    /// `data_out`. Returns the number of bytes written.
    ///
    /// Returns [`Error::NotFound`] if no matching variable exists, or
    /// [`Error::OutOfMemory`] if `data_out` is too small.
    pub fn get_variable(
        &self,
        name: &[u16],
        guid: &EfiGuid,
        attributes: &mut VariableAttributes,
        data_out: &mut [u8],
    ) -> Result<usize> {
        let var = self
            .vars
            .iter()
            .find(|v| v.occupied && v.matches(name, guid))
            .ok_or(Error::NotFound)?;

        if data_out.len() < var.data_len {
            return Err(Error::OutOfMemory);
        }
        data_out[..var.data_len].copy_from_slice(var.data_bytes());
        *attributes = var.attributes;
        Ok(var.data_len)
    }

    /// Creates or updates a variable.
    ///
    /// If a variable with the same (name, GUID) already exists it is
    /// overwritten. If `data` is empty and the variable exists, it is
    /// deleted.
    ///
    /// Returns [`Error::OutOfMemory`] if the store is full and a new
    /// variable would need to be created, or [`Error::InvalidArgument`]
    /// if the name or data exceed limits.
    pub fn set_variable(
        &mut self,
        name: &[u16],
        guid: EfiGuid,
        attributes: VariableAttributes,
        data: &[u8],
    ) -> Result<()> {
        // Delete request (empty data + existing variable).
        if data.is_empty() {
            return self.delete_variable(name, &guid);
        }

        // Overwrite existing.
        for var in self.vars.iter_mut() {
            if var.occupied && var.matches(name, &guid) {
                if data.len() > MAX_VAR_DATA {
                    return Err(Error::InvalidArgument);
                }
                var.data[..data.len()].copy_from_slice(data);
                var.data_len = data.len();
                var.attributes = attributes;
                return Ok(());
            }
        }

        // Create new.
        if self.count >= MAX_VARIABLES {
            return Err(Error::OutOfMemory);
        }
        let new_var = EfiVariable::new(name, guid, attributes, data)?;
        for slot in self.vars.iter_mut() {
            if !slot.occupied {
                *slot = new_var;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Deletes the variable identified by (`name`, `guid`).
    ///
    /// Returns [`Error::NotFound`] if no matching variable exists.
    pub fn delete_variable(&mut self, name: &[u16], guid: &EfiGuid) -> Result<()> {
        for var in self.vars.iter_mut() {
            if var.occupied && var.matches(name, guid) {
                *var = EfiVariable::default();
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Iterates variables in the store, returning the next variable name
    /// and GUID after the given (`name`, `guid`) pair.
    ///
    /// Pass an empty `name` slice and a nil GUID to start enumeration.
    /// Returns [`Error::NotFound`] when there are no more variables.
    pub fn get_next_variable_name(
        &self,
        name: &[u16],
        guid: &EfiGuid,
        name_out: &mut [u16; MAX_VAR_NAME_LEN],
        name_out_len: &mut usize,
        guid_out: &mut EfiGuid,
    ) -> Result<()> {
        let occupied: &[_] = &self.vars;
        let mut iter = occupied.iter().filter(|v| v.occupied);

        if name.is_empty() && guid.is_nil() {
            // Return the first variable.
            let first = iter.next().ok_or(Error::NotFound)?;
            name_out[..first.name_len].copy_from_slice(first.name_units());
            *name_out_len = first.name_len;
            *guid_out = first.guid;
            return Ok(());
        }

        // Find the current entry, then return the next.
        let mut found_current = false;
        for var in occupied.iter().filter(|v| v.occupied) {
            if found_current {
                name_out[..var.name_len].copy_from_slice(var.name_units());
                *name_out_len = var.name_len;
                *guid_out = var.guid;
                return Ok(());
            }
            if var.matches(name, guid) {
                found_current = true;
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of variables in the store.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns an iterator over occupied variables.
    pub fn iter(&self) -> impl Iterator<Item = &EfiVariable> {
        self.vars.iter().filter(|v| v.occupied)
    }
}

impl Default for VariableStore {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// CapsuleHeader
// -------------------------------------------------------------------

/// UEFI firmware capsule header (`EFI_CAPSULE_HEADER`).
///
/// Capsule updates allow firmware images to be passed to the firmware
/// on the next reset. This struct represents the header only; actual
/// payload delivery is firmware-specific.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CapsuleHeader {
    /// GUID identifying the capsule type.
    pub capsule_guid: EfiGuid,
    /// Size of this header in bytes (must be `size_of::<CapsuleHeader>()`).
    pub header_size: u32,
    /// Capsule flags (see `CAPSULE_FLAGS_*` constants).
    pub flags: u32,
    /// Total size of the capsule (header + payload) in bytes.
    pub capsule_image_size: u32,
}

impl CapsuleHeader {
    /// Returns `true` if the persist-across-reset flag is set.
    #[inline]
    pub fn persists_across_reset(&self) -> bool {
        self.flags & CAPSULE_FLAGS_PERSIST_ACROSS_RESET != 0
    }

    /// Returns `true` if the initiate-reset flag is set.
    #[inline]
    pub fn initiates_reset(&self) -> bool {
        self.flags & CAPSULE_FLAGS_INITIATE_RESET != 0
    }

    /// Returns the payload size in bytes (total size minus header).
    pub fn payload_size(&self) -> u32 {
        self.capsule_image_size.saturating_sub(self.header_size)
    }
}

// -------------------------------------------------------------------
// EfiResetType
// -------------------------------------------------------------------

/// UEFI reset types for `ResetSystem`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EfiResetType {
    /// Perform a cold reset.
    #[default]
    Cold,
    /// Perform a warm reset (processor only).
    Warm,
    /// Power off the system.
    Shutdown,
    /// Platform-specific reset.
    PlatformSpecific,
}

// -------------------------------------------------------------------
// EfiRuntimeServices
// -------------------------------------------------------------------

/// Top-level EFI Runtime Services abstraction.
///
/// Combines:
/// - NVRAM [`VariableStore`] for `Get/SetVariable` and `GetNextVariableName`.
/// - Software clock for `GetTime` / `SetTime`.
/// - Monotonic counter (`GetNextMonotonicCount`).
/// - Reset control (`ResetSystem`).
/// - Capsule update stub (`QueryCapsuleCapabilities` / `UpdateCapsule`).
pub struct EfiRuntimeServices {
    /// NVRAM variable shadow store.
    pub variables: VariableStore,
    /// Current time (software shadow; real HW would read CMOS/HPET).
    current_time: EfiTime,
    /// Hardware clock capabilities.
    time_capabilities: EfiTimeCapabilities,
    /// Monotonic counter value (increments on each call).
    monotonic_counter: u64,
    /// Monotonic counter high word (survives resets in real firmware).
    monotonic_high: u32,
    /// Whether runtime services have been initialised.
    initialised: bool,
    /// Maximum capsule size the platform supports (0 = unsupported).
    max_capsule_size: u64,
    /// Whether virtual address mapping has been applied.
    virtual_mode: bool,
}

impl EfiRuntimeServices {
    /// Creates a new, uninitialised EFI Runtime Services instance.
    pub const fn new() -> Self {
        Self {
            variables: VariableStore::new(),
            current_time: EfiTime {
                year: 2026,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
                pad1: 0,
                nanosecond: 0,
                timezone: EFI_UNSPECIFIED_TIMEZONE,
                daylight: 0,
                pad2: 0,
            },
            time_capabilities: EfiTimeCapabilities {
                resolution: 1,
                accuracy: 50_000_000,
                sets_to_zero: true,
            },
            monotonic_counter: 0,
            monotonic_high: 0,
            initialised: false,
            max_capsule_size: 0,
            virtual_mode: false,
        }
    }

    /// Initialises the runtime services subsystem.
    ///
    /// Sets the maximum supported capsule size and marks the services
    /// as ready.
    ///
    /// Returns [`Error::Busy`] if already initialised.
    pub fn init(&mut self, max_capsule_size: u64) -> Result<()> {
        if self.initialised {
            return Err(Error::Busy);
        }
        self.max_capsule_size = max_capsule_size;
        self.initialised = true;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Time services
    // ------------------------------------------------------------------

    /// Returns the current time and hardware clock capabilities.
    ///
    /// Returns [`Error::Busy`] if not initialised.
    pub fn get_time(&self) -> Result<(EfiTime, EfiTimeCapabilities)> {
        if !self.initialised {
            return Err(Error::Busy);
        }
        Ok((self.current_time, self.time_capabilities))
    }

    /// Sets the current time.
    ///
    /// Returns [`Error::InvalidArgument`] if `time` contains out-of-range
    /// fields, or [`Error::Busy`] if not initialised.
    pub fn set_time(&mut self, time: EfiTime) -> Result<()> {
        if !self.initialised {
            return Err(Error::Busy);
        }
        if !time.is_valid() {
            return Err(Error::InvalidArgument);
        }
        self.current_time = time;
        if self.time_capabilities.sets_to_zero {
            self.current_time.nanosecond = 0;
        }
        Ok(())
    }

    /// Advances the software clock by `delta_ns` nanoseconds.
    ///
    /// This is a kernel-internal helper; real hardware uses CMOS/RTC
    /// interrupts. Only nanoseconds and seconds are updated (minute/hour
    /// rollover not implemented for brevity).
    pub fn advance_time(&mut self, delta_ns: u64) {
        let total_ns = u64::from(self.current_time.nanosecond).saturating_add(delta_ns);
        self.current_time.nanosecond = (total_ns % 1_000_000_000) as u32;
        let extra_secs = (total_ns / 1_000_000_000) as u32;
        let new_secs = u32::from(self.current_time.second).saturating_add(extra_secs);
        self.current_time.second = (new_secs % 60) as u8;
        let extra_mins = new_secs / 60;
        let new_mins = u32::from(self.current_time.minute).saturating_add(extra_mins);
        self.current_time.minute = (new_mins % 60) as u8;
        let extra_hours = new_mins / 60;
        let new_hours = u32::from(self.current_time.hour).saturating_add(extra_hours);
        self.current_time.hour = (new_hours % 24) as u8;
    }

    // ------------------------------------------------------------------
    // Monotonic counter
    // ------------------------------------------------------------------

    /// Returns the next monotonic counter value.
    ///
    /// The counter is guaranteed to be strictly increasing within a
    /// session. The high 32 bits are preserved across warm resets in
    /// real firmware (here software-only).
    ///
    /// Returns [`Error::Busy`] if not initialised.
    pub fn get_next_monotonic_count(&mut self) -> Result<u64> {
        if !self.initialised {
            return Err(Error::Busy);
        }
        let low = self.monotonic_counter & 0xFFFF_FFFF;
        if low == 0xFFFF_FFFF {
            // Low word wrapped — increment high word.
            self.monotonic_high = self.monotonic_high.wrapping_add(1);
        }
        self.monotonic_counter = self.monotonic_counter.wrapping_add(1);
        Ok((u64::from(self.monotonic_high) << 32) | (self.monotonic_counter & 0xFFFF_FFFF))
    }

    /// Returns the current monotonic counter value without incrementing.
    pub fn peek_monotonic_count(&self) -> u64 {
        (u64::from(self.monotonic_high) << 32) | (self.monotonic_counter & 0xFFFF_FFFF)
    }

    // ------------------------------------------------------------------
    // Variable services (delegation to VariableStore)
    // ------------------------------------------------------------------

    /// Gets an EFI variable (delegates to [`VariableStore::get_variable`]).
    pub fn get_variable(
        &self,
        name: &[u16],
        guid: &EfiGuid,
        attributes: &mut VariableAttributes,
        data_out: &mut [u8],
    ) -> Result<usize> {
        self.variables
            .get_variable(name, guid, attributes, data_out)
    }

    /// Sets an EFI variable (delegates to [`VariableStore::set_variable`]).
    pub fn set_variable(
        &mut self,
        name: &[u16],
        guid: EfiGuid,
        attributes: VariableAttributes,
        data: &[u8],
    ) -> Result<()> {
        self.variables.set_variable(name, guid, attributes, data)
    }

    /// Enumerates variables (delegates to
    /// [`VariableStore::get_next_variable_name`]).
    pub fn get_next_variable_name(
        &self,
        name: &[u16],
        guid: &EfiGuid,
        name_out: &mut [u16; MAX_VAR_NAME_LEN],
        name_out_len: &mut usize,
        guid_out: &mut EfiGuid,
    ) -> Result<()> {
        self.variables
            .get_next_variable_name(name, guid, name_out, name_out_len, guid_out)
    }

    // ------------------------------------------------------------------
    // Reset
    // ------------------------------------------------------------------

    /// Initiates a system reset.
    ///
    /// On real hardware this writes to the firmware reset register. In a
    /// no_std environment we return [`Error::NotImplemented`] — the caller
    /// must invoke the architecture-specific reset sequence.
    ///
    /// Returns [`Error::NotImplemented`] always (caller performs the reset).
    pub fn reset_system(
        &self,
        reset_type: EfiResetType,
        status: EfiStatus,
        _data: &[u8],
    ) -> Result<()> {
        // In a real implementation:
        //   - Cold/Warm: outb(0xFE, 0x64)  [PS/2 reset line]
        //   - Shutdown: ACPI S5 write
        // Return Unsupported to signal caller must use arch-specific path.
        let _ = (reset_type, status);
        Err(Error::NotImplemented)
    }

    // ------------------------------------------------------------------
    // Capsule update
    // ------------------------------------------------------------------

    /// Queries whether a capsule can be processed by the firmware.
    ///
    /// Returns the maximum capsule size supported and whether the update
    /// requires a reset.
    ///
    /// Returns [`Error::NotImplemented`] if capsule updates are not
    /// supported (max_capsule_size == 0).
    pub fn query_capsule_capabilities(&self, header: &CapsuleHeader) -> Result<(u64, bool)> {
        if self.max_capsule_size == 0 {
            return Err(Error::NotImplemented);
        }
        if u64::from(header.capsule_image_size) > self.max_capsule_size {
            return Err(Error::OutOfMemory);
        }
        let needs_reset = header.persists_across_reset() || header.initiates_reset();
        Ok((self.max_capsule_size, needs_reset))
    }

    /// Passes a capsule to the firmware for processing on next reset.
    ///
    /// Validates the header and records acceptance. The actual capsule
    /// payload delivery is deferred to firmware at reset.
    ///
    /// Returns [`Error::NotImplemented`] if capsule updates are not
    /// supported, or [`Error::InvalidArgument`] if the header is
    /// malformed (header_size < 28 or image too large).
    pub fn update_capsule(&self, header: &CapsuleHeader) -> Result<()> {
        if self.max_capsule_size == 0 {
            return Err(Error::NotImplemented);
        }
        // Minimum valid EFI_CAPSULE_HEADER size is 28 bytes.
        if header.header_size < 28 {
            return Err(Error::InvalidArgument);
        }
        if u64::from(header.capsule_image_size) > self.max_capsule_size {
            return Err(Error::OutOfMemory);
        }
        if header.capsule_guid.is_nil() {
            return Err(Error::InvalidArgument);
        }
        // In a real implementation: store the scatter-gather list in a
        // firmware-accessible buffer and set the CapsuleUpdateData EFI
        // variable, then call firmware's UpdateCapsule() pointer.
        Ok(())
    }

    // ------------------------------------------------------------------
    // Virtual address mapping
    // ------------------------------------------------------------------

    /// Applies virtual memory mapping to runtime service pointers.
    ///
    /// Called once after `ExitBootServices` to update firmware pointers
    /// to their virtual addresses. Marks the services as being in virtual
    /// mode; subsequent calls return [`Error::AlreadyExists`].
    ///
    /// Returns [`Error::AlreadyExists`] if already in virtual mode.
    pub fn set_virtual_address_map(&mut self) -> Result<()> {
        if self.virtual_mode {
            return Err(Error::AlreadyExists);
        }
        // In a real implementation: iterate the UEFI memory map and call
        // the firmware's SetVirtualAddressMap() with translated descriptors.
        self.virtual_mode = true;
        Ok(())
    }

    /// Returns `true` if virtual address mapping has been applied.
    pub fn is_virtual_mode(&self) -> bool {
        self.virtual_mode
    }

    /// Returns `true` if the services have been initialised.
    pub fn is_initialised(&self) -> bool {
        self.initialised
    }
}

impl Default for EfiRuntimeServices {
    fn default() -> Self {
        Self::new()
    }
}
