// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SMBIOS/DMI table parser.
//!
//! The System Management BIOS (SMBIOS) specification defines a set of
//! data structures that provide information about the system hardware.
//! Firmware populates these tables and makes them available to the OS
//! via a well-known entry point structure.
//!
//! This module parses the SMBIOS entry point (both 32-bit and 64-bit
//! variants), walks the structure table, and decodes common structure
//! types:
//!
//! - **Type 0** — BIOS Information (vendor, version, release date)
//! - **Type 1** — System Information (manufacturer, product, serial, UUID)
//! - **Type 4** — Processor Information (family, speed, core count)
//! - **Type 17** — Memory Device (size, speed, form factor, type)
//!
//! # Usage
//!
//! ```ignore
//! let ep = parse_entry_point(data)?;
//! let mut info = SmbiosInfo::empty();
//! parse_structures(table_data, ep.table_length as usize, &mut info)?;
//! ```
//!
//! Reference: SMBIOS Specification 3.6.0 (DMTF DSP0134).

use oncrix_lib::{Error, Result};

// ── Signatures ────────────────────────────────────────────────────

/// 32-bit SMBIOS entry point anchor: `_SM_`.
const SM_ANCHOR: [u8; 4] = *b"_SM_";

/// 32-bit intermediate anchor: `_DMI_`.
const DMI_ANCHOR: [u8; 5] = *b"_DMI_";

/// 64-bit SMBIOS 3.x entry point anchor: `_SM3_`.
const SM3_ANCHOR: [u8; 5] = *b"_SM3_";

// ── Limits ────────────────────────────────────────────────────────

/// Maximum number of BIOS info entries we parse.
const MAX_BIOS_ENTRIES: usize = 2;

/// Maximum number of system info entries we parse.
const MAX_SYSTEM_ENTRIES: usize = 2;

/// Maximum number of processor info entries we parse.
const MAX_PROCESSOR_ENTRIES: usize = 64;

/// Maximum number of memory device entries we parse.
const MAX_MEMORY_ENTRIES: usize = 128;

/// Maximum string length extracted from SMBIOS string tables.
const MAX_STRING_LEN: usize = 64;

/// Maximum number of strings per structure.
const MAX_STRINGS_PER_STRUCT: usize = 16;

/// Minimum 32-bit entry point size.
const EP32_MIN_SIZE: usize = 31;

/// Minimum 64-bit entry point size.
const EP64_MIN_SIZE: usize = 24;

// ── Entry Point Version ──────────────────────────────────────────

/// SMBIOS entry point version (32-bit vs 64-bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryPointVersion {
    /// 32-bit SMBIOS 2.x entry point (`_SM_`).
    V2,
    /// 64-bit SMBIOS 3.x entry point (`_SM3_`).
    V3,
}

// ── Entry Point ──────────────────────────────────────────────────

/// Parsed SMBIOS entry point information.
#[derive(Debug, Clone, Copy)]
pub struct SmbiosEntryPoint {
    /// Entry point version (32-bit or 64-bit).
    pub version: EntryPointVersion,
    /// SMBIOS major version number.
    pub major_ver: u8,
    /// SMBIOS minor version number.
    pub minor_ver: u8,
    /// Physical address of the structure table.
    pub table_address: u64,
    /// Total length of the structure table in bytes.
    pub table_length: u32,
    /// Number of SMBIOS structures (0 if unknown, e.g. 3.x).
    pub structure_count: u16,
}

// ── Structure Header ─────────────────────────────────────────────

/// Common header at the start of every SMBIOS structure.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct SmbiosHeader {
    /// Structure type identifier.
    pub type_id: u8,
    /// Length of the formatted area (excluding string section).
    pub length: u8,
    /// Unique handle for this structure instance.
    pub handle: u16,
}

/// Size of the SMBIOS structure header.
const HEADER_SIZE: usize = core::mem::size_of::<SmbiosHeader>();

// ── SMBIOS String Helper ─────────────────────────────────────────

/// A fixed-size buffer holding a single SMBIOS string.
#[derive(Clone, Copy)]
pub struct SmbiosString {
    /// UTF-8 bytes of the string.
    buf: [u8; MAX_STRING_LEN],
    /// Actual length in bytes.
    len: usize,
}

impl SmbiosString {
    /// Create an empty SMBIOS string.
    pub const fn empty() -> Self {
        Self {
            buf: [0u8; MAX_STRING_LEN],
            len: 0,
        }
    }

    /// Return the string as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Return the length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Return `true` if the string is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl core::fmt::Debug for SmbiosString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = core::str::from_utf8(self.as_bytes()).unwrap_or("<invalid>");
        write!(f, "\"{}\"", s)
    }
}

// ── Type 0: BIOS Information ─────────────────────────────────────

/// SMBIOS Type 0 — BIOS Information.
#[derive(Debug, Clone, Copy)]
pub struct SmbiosType0 {
    /// Structure handle.
    pub handle: u16,
    /// BIOS vendor name.
    pub vendor: SmbiosString,
    /// BIOS version string.
    pub version: SmbiosString,
    /// BIOS release date string.
    pub release_date: SmbiosString,
    /// BIOS starting address segment.
    pub starting_segment: u16,
    /// BIOS ROM size (in 64 KB units, actual = (n+1) * 64 KB).
    pub rom_size: u8,
    /// BIOS characteristics flags.
    pub characteristics: u64,
}

impl SmbiosType0 {
    /// Create an empty Type 0 entry.
    const fn empty() -> Self {
        Self {
            handle: 0,
            vendor: SmbiosString::empty(),
            version: SmbiosString::empty(),
            release_date: SmbiosString::empty(),
            starting_segment: 0,
            rom_size: 0,
            characteristics: 0,
        }
    }

    /// Return the ROM size in bytes.
    pub fn rom_size_bytes(&self) -> u32 {
        (self.rom_size as u32 + 1) * 64 * 1024
    }
}

// ── Type 1: System Information ───────────────────────────────────

/// A 128-bit UUID stored as raw bytes.
#[derive(Clone, Copy)]
pub struct Uuid {
    /// Raw UUID bytes (16 bytes, mixed-endian per SMBIOS spec).
    pub bytes: [u8; 16],
}

impl Uuid {
    /// An all-zeros UUID indicating "not present".
    pub const ZERO: Self = Self { bytes: [0u8; 16] };

    /// Return `true` if the UUID is all zeros.
    pub fn is_zero(&self) -> bool {
        self.bytes == [0u8; 16]
    }

    /// Return `true` if the UUID is all 0xFF (not settable).
    pub fn is_not_settable(&self) -> bool {
        self.bytes == [0xFF; 16]
    }
}

impl core::fmt::Debug for Uuid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let b = &self.bytes;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-\
             {:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[3],
            b[2],
            b[1],
            b[0],
            b[5],
            b[4],
            b[7],
            b[6],
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15],
        )
    }
}

/// SMBIOS Type 1 — System Information.
#[derive(Debug, Clone, Copy)]
pub struct SmbiosType1 {
    /// Structure handle.
    pub handle: u16,
    /// System manufacturer.
    pub manufacturer: SmbiosString,
    /// Product name.
    pub product_name: SmbiosString,
    /// Version string.
    pub version: SmbiosString,
    /// Serial number.
    pub serial_number: SmbiosString,
    /// System UUID.
    pub uuid: Uuid,
    /// Wake-up type.
    pub wakeup_type: u8,
    /// SKU number string.
    pub sku_number: SmbiosString,
    /// Family string.
    pub family: SmbiosString,
}

impl SmbiosType1 {
    /// Create an empty Type 1 entry.
    const fn empty() -> Self {
        Self {
            handle: 0,
            manufacturer: SmbiosString::empty(),
            product_name: SmbiosString::empty(),
            version: SmbiosString::empty(),
            serial_number: SmbiosString::empty(),
            uuid: Uuid::ZERO,
            wakeup_type: 0,
            sku_number: SmbiosString::empty(),
            family: SmbiosString::empty(),
        }
    }
}

// ── Type 4: Processor Information ────────────────────────────────

/// Processor family identifier (subset of common values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProcessorFamily {
    /// Other / unknown.
    Other = 0x01,
    /// Intel 8086.
    Intel8086 = 0x03,
    /// Intel Pentium.
    Pentium = 0x0B,
    /// Intel Pentium Pro.
    PentiumPro = 0x0C,
    /// Intel Core 2.
    Core2 = 0x1F,
    /// AMD Athlon 64.
    Athlon64 = 0x53,
    /// Intel Xeon.
    Xeon = 0xB3,
    /// ARM.
    Arm = 0x78,
}

impl ProcessorFamily {
    /// Convert a raw byte to a `ProcessorFamily`.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x03 => ProcessorFamily::Intel8086,
            0x0B => ProcessorFamily::Pentium,
            0x0C => ProcessorFamily::PentiumPro,
            0x1F => ProcessorFamily::Core2,
            0x53 => ProcessorFamily::Athlon64,
            0x78 => ProcessorFamily::Arm,
            0xB3 => ProcessorFamily::Xeon,
            _ => ProcessorFamily::Other,
        }
    }
}

/// Processor status (lower nibble of status byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessorStatus {
    /// Unknown.
    Unknown,
    /// CPU enabled.
    Enabled,
    /// CPU disabled by user.
    DisabledByUser,
    /// CPU disabled by BIOS.
    DisabledByBios,
    /// CPU idle (waiting to be enabled).
    Idle,
    /// Other status.
    Other,
}

impl ProcessorStatus {
    /// Decode from the raw status byte.
    pub fn from_byte(b: u8) -> Self {
        match b & 0x07 {
            0x00 => ProcessorStatus::Unknown,
            0x01 => ProcessorStatus::Enabled,
            0x02 => ProcessorStatus::DisabledByUser,
            0x03 => ProcessorStatus::DisabledByBios,
            0x04 => ProcessorStatus::Idle,
            _ => ProcessorStatus::Other,
        }
    }
}

/// SMBIOS Type 4 — Processor Information.
#[derive(Debug, Clone, Copy)]
pub struct SmbiosType4 {
    /// Structure handle.
    pub handle: u16,
    /// Socket designation string.
    pub designation: SmbiosString,
    /// Processor family identifier.
    pub family: ProcessorFamily,
    /// Processor manufacturer string.
    pub manufacturer: SmbiosString,
    /// Processor version string.
    pub version: SmbiosString,
    /// Maximum speed in MHz.
    pub max_speed_mhz: u16,
    /// Current speed in MHz.
    pub current_speed_mhz: u16,
    /// Processor status.
    pub status: ProcessorStatus,
    /// Number of cores per socket.
    pub core_count: u16,
    /// Number of enabled cores.
    pub core_enabled: u16,
    /// Number of threads per socket.
    pub thread_count: u16,
    /// External clock frequency in MHz.
    pub external_clock_mhz: u16,
    /// Processor ID (8 bytes, CPUID value).
    pub processor_id: u64,
}

impl SmbiosType4 {
    /// Create an empty Type 4 entry.
    const fn empty() -> Self {
        Self {
            handle: 0,
            designation: SmbiosString::empty(),
            family: ProcessorFamily::Other,
            manufacturer: SmbiosString::empty(),
            version: SmbiosString::empty(),
            max_speed_mhz: 0,
            current_speed_mhz: 0,
            status: ProcessorStatus::Unknown,
            core_count: 0,
            core_enabled: 0,
            thread_count: 0,
            external_clock_mhz: 0,
            processor_id: 0,
        }
    }
}

// ── Type 17: Memory Device ───────────────────────────────────────

/// Memory form factor (SMBIOS Type 17 field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryFormFactor {
    /// Other / unknown.
    Other,
    /// DIMM (Dual Inline Memory Module).
    Dimm,
    /// SO-DIMM (Small Outline DIMM).
    SoDimm,
    /// SIMM (Single Inline Memory Module).
    Simm,
    /// RIMM (Rambus Inline Memory Module).
    Rimm,
}

impl MemoryFormFactor {
    /// Decode from the raw form factor byte.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x09 => MemoryFormFactor::Dimm,
            0x0D => MemoryFormFactor::SoDimm,
            0x03 => MemoryFormFactor::Simm,
            0x06 => MemoryFormFactor::Rimm,
            _ => MemoryFormFactor::Other,
        }
    }
}

/// Memory type (SMBIOS Type 17 field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    /// Other / unknown.
    Other,
    /// DDR3 SDRAM.
    Ddr3,
    /// DDR4 SDRAM.
    Ddr4,
    /// DDR5 SDRAM.
    Ddr5,
    /// LPDDR4.
    Lpddr4,
    /// LPDDR5.
    Lpddr5,
}

impl MemoryType {
    /// Decode from the raw memory type byte.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x18 => MemoryType::Ddr3,
            0x1A => MemoryType::Ddr4,
            0x22 => MemoryType::Ddr5,
            0x1E => MemoryType::Lpddr4,
            0x23 => MemoryType::Lpddr5,
            _ => MemoryType::Other,
        }
    }
}

/// SMBIOS Type 17 — Memory Device.
#[derive(Debug, Clone, Copy)]
pub struct SmbiosType17 {
    /// Structure handle.
    pub handle: u16,
    /// Physical memory array handle (parent).
    pub array_handle: u16,
    /// Total width in bits (including ECC).
    pub total_width: u16,
    /// Data width in bits.
    pub data_width: u16,
    /// Memory size in MB (0xFFFF means use extended size field).
    pub size_mb: u32,
    /// Form factor.
    pub form_factor: MemoryFormFactor,
    /// Memory type.
    pub memory_type: MemoryType,
    /// Speed in MT/s (megatransfers per second).
    pub speed_mts: u16,
    /// Configured speed in MT/s.
    pub configured_speed_mts: u16,
    /// Device locator string.
    pub device_locator: SmbiosString,
    /// Bank locator string.
    pub bank_locator: SmbiosString,
    /// Manufacturer string.
    pub manufacturer: SmbiosString,
    /// Part number string.
    pub part_number: SmbiosString,
}

impl SmbiosType17 {
    /// Create an empty Type 17 entry.
    const fn empty() -> Self {
        Self {
            handle: 0,
            array_handle: 0,
            total_width: 0,
            data_width: 0,
            size_mb: 0,
            form_factor: MemoryFormFactor::Other,
            memory_type: MemoryType::Other,
            speed_mts: 0,
            configured_speed_mts: 0,
            device_locator: SmbiosString::empty(),
            bank_locator: SmbiosString::empty(),
            manufacturer: SmbiosString::empty(),
            part_number: SmbiosString::empty(),
        }
    }

    /// Return the memory size in bytes.
    pub fn size_bytes(&self) -> u64 {
        self.size_mb as u64 * 1024 * 1024
    }
}

// ── Aggregate Info ───────────────────────────────────────────────

/// Aggregated SMBIOS information parsed from the structure table.
pub struct SmbiosInfo {
    /// Entry point metadata.
    pub entry_point: SmbiosEntryPoint,
    /// Parsed Type 0 (BIOS) entries.
    pub bios: [SmbiosType0; MAX_BIOS_ENTRIES],
    /// Number of valid BIOS entries.
    pub bios_count: usize,
    /// Parsed Type 1 (System) entries.
    pub system: [SmbiosType1; MAX_SYSTEM_ENTRIES],
    /// Number of valid system entries.
    pub system_count: usize,
    /// Parsed Type 4 (Processor) entries.
    pub processors: [SmbiosType4; MAX_PROCESSOR_ENTRIES],
    /// Number of valid processor entries.
    pub processor_count: usize,
    /// Parsed Type 17 (Memory Device) entries.
    pub memory: [SmbiosType17; MAX_MEMORY_ENTRIES],
    /// Number of valid memory entries.
    pub memory_count: usize,
}

impl SmbiosInfo {
    /// Create an empty info container.
    pub fn empty() -> Self {
        Self {
            entry_point: SmbiosEntryPoint {
                version: EntryPointVersion::V2,
                major_ver: 0,
                minor_ver: 0,
                table_address: 0,
                table_length: 0,
                structure_count: 0,
            },
            bios: [SmbiosType0::empty(); MAX_BIOS_ENTRIES],
            bios_count: 0,
            system: [SmbiosType1::empty(); MAX_SYSTEM_ENTRIES],
            system_count: 0,
            processors: [SmbiosType4::empty(); MAX_PROCESSOR_ENTRIES],
            processor_count: 0,
            memory: [SmbiosType17::empty(); MAX_MEMORY_ENTRIES],
            memory_count: 0,
        }
    }

    /// Return total system memory in MB across all memory devices.
    pub fn total_memory_mb(&self) -> u64 {
        let mut total: u64 = 0;
        let mut i = 0;
        while i < self.memory_count {
            total += self.memory[i].size_mb as u64;
            i += 1;
        }
        total
    }

    /// Return total number of enabled processor cores.
    pub fn total_cores_enabled(&self) -> u32 {
        let mut total: u32 = 0;
        let mut i = 0;
        while i < self.processor_count {
            total += self.processors[i].core_enabled as u32;
            i += 1;
        }
        total
    }

    /// Return total number of processor threads.
    pub fn total_threads(&self) -> u32 {
        let mut total: u32 = 0;
        let mut i = 0;
        while i < self.processor_count {
            total += self.processors[i].thread_count as u32;
            i += 1;
        }
        total
    }
}

// ── String Table Parser ──────────────────────────────────────────

/// Parsed string table from an SMBIOS structure.
struct StringTable {
    /// Strings extracted from the table.
    strings: [SmbiosString; MAX_STRINGS_PER_STRUCT],
    /// Number of valid strings.
    count: usize,
    /// Total bytes consumed by the string section (including
    /// terminating double-NUL).
    consumed: usize,
}

impl StringTable {
    /// Create an empty string table.
    const fn empty() -> Self {
        Self {
            strings: [SmbiosString::empty(); MAX_STRINGS_PER_STRUCT],
            count: 0,
            consumed: 0,
        }
    }
}

/// Parse the unformatted (string) section that follows a structure.
///
/// The string section starts immediately after the formatted area
/// and consists of NUL-terminated ASCII strings followed by an
/// additional NUL byte (double-NUL terminator).
fn parse_string_table(data: &[u8]) -> StringTable {
    let mut table = StringTable::empty();
    let mut offset = 0;

    // Handle empty string section (starts with double NUL).
    if data.len() >= 2 && data[0] == 0 && data[1] == 0 {
        table.consumed = 2;
        return table;
    }

    while offset < data.len() && table.count < MAX_STRINGS_PER_STRUCT {
        // Find the NUL terminator for this string.
        let start = offset;
        while offset < data.len() && data[offset] != 0 {
            offset += 1;
        }

        if offset == start {
            // Empty string means end of string section.
            // Consume the final NUL.
            offset += 1;
            break;
        }

        // Copy string bytes into the fixed buffer.
        let str_len = (offset - start).min(MAX_STRING_LEN);
        let mut s = SmbiosString::empty();
        let mut i = 0;
        while i < str_len {
            s.buf[i] = data[start + i];
            i += 1;
        }
        s.len = str_len;
        table.strings[table.count] = s;
        table.count += 1;

        // Skip the NUL terminator of this string.
        if offset < data.len() {
            offset += 1;
        }
    }

    table.consumed = offset;
    table
}

/// Retrieve a string by 1-based index from the string table.
fn get_string(table: &StringTable, index: u8) -> SmbiosString {
    if index == 0 || (index as usize) > table.count {
        return SmbiosString::empty();
    }
    table.strings[(index as usize) - 1]
}

// ── Entry Point Parser ───────────────────────────────────────────

/// Validate a checksum over a byte range.
fn validate_checksum(data: &[u8], len: usize) -> bool {
    if data.len() < len {
        return false;
    }
    data[..len].iter().fold(0u8, |acc, &b| acc.wrapping_add(b)) == 0
}

/// Parse a 32-bit SMBIOS entry point (`_SM_`).
fn parse_entry_point_32(data: &[u8]) -> Result<SmbiosEntryPoint> {
    if data.len() < EP32_MIN_SIZE {
        return Err(Error::InvalidArgument);
    }

    // Check anchor `_SM_` at offset 0.
    if data[0..4] != SM_ANCHOR {
        return Err(Error::InvalidArgument);
    }

    // Entry point length at offset 5.
    let ep_length = data[5] as usize;
    if ep_length < EP32_MIN_SIZE || data.len() < ep_length {
        return Err(Error::InvalidArgument);
    }

    // Validate entry point checksum.
    if !validate_checksum(data, ep_length) {
        return Err(Error::InvalidArgument);
    }

    // Check intermediate anchor `_DMI_` at offset 16.
    if data[16..21] != DMI_ANCHOR {
        return Err(Error::InvalidArgument);
    }

    let major_ver = data[6];
    let minor_ver = data[7];

    // Structure table length at offset 22 (u16 LE).
    let table_length = read_u16_le(data, 22);

    // Structure table address at offset 24 (u32 LE).
    let table_address = read_u32_le(data, 24) as u64;

    // Number of structures at offset 28 (u16 LE).
    let structure_count = read_u16_le(data, 28);

    Ok(SmbiosEntryPoint {
        version: EntryPointVersion::V2,
        major_ver,
        minor_ver,
        table_address,
        table_length: table_length as u32,
        structure_count,
    })
}

/// Parse a 64-bit SMBIOS 3.x entry point (`_SM3_`).
fn parse_entry_point_64(data: &[u8]) -> Result<SmbiosEntryPoint> {
    if data.len() < EP64_MIN_SIZE {
        return Err(Error::InvalidArgument);
    }

    // Check anchor `_SM3_` at offset 0.
    if data[0..5] != SM3_ANCHOR {
        return Err(Error::InvalidArgument);
    }

    // Entry point length at offset 6.
    let ep_length = data[6] as usize;
    if ep_length < EP64_MIN_SIZE || data.len() < ep_length {
        return Err(Error::InvalidArgument);
    }

    // Validate checksum.
    if !validate_checksum(data, ep_length) {
        return Err(Error::InvalidArgument);
    }

    let major_ver = data[7];
    let minor_ver = data[8];

    // Maximum structure table length at offset 12 (u32 LE).
    let table_length = read_u32_le(data, 12);

    // Structure table address at offset 16 (u64 LE).
    let table_address = read_u64_le(data, 16);

    Ok(SmbiosEntryPoint {
        version: EntryPointVersion::V3,
        major_ver,
        minor_ver,
        table_address,
        table_length,
        structure_count: 0, // SMBIOS 3.x does not provide a count.
    })
}

/// Parse an SMBIOS entry point from raw memory.
///
/// Accepts both 32-bit (`_SM_`) and 64-bit (`_SM3_`) formats.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if the data does not contain
/// a valid SMBIOS entry point.
pub fn parse_entry_point(data: &[u8]) -> Result<SmbiosEntryPoint> {
    if data.len() < 5 {
        return Err(Error::InvalidArgument);
    }

    // Try 64-bit first (SMBIOS 3.x).
    if data.len() >= EP64_MIN_SIZE && data[0..5] == SM3_ANCHOR {
        return parse_entry_point_64(data);
    }

    // Fall back to 32-bit.
    if data.len() >= EP32_MIN_SIZE && data[0..4] == SM_ANCHOR {
        return parse_entry_point_32(data);
    }

    Err(Error::InvalidArgument)
}

// ── Structure Walker ─────────────────────────────────────────────

/// Read a `u16` in little-endian from `data` at `offset`.
fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

/// Read a `u32` in little-endian from `data` at `offset`.
fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// Read a `u64` in little-endian from `data` at `offset`.
fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    if offset + 8 > data.len() {
        return 0;
    }
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

/// Parse a Type 0 (BIOS Information) structure.
fn parse_type0(data: &[u8], header: &SmbiosHeader, strings: &StringTable) -> SmbiosType0 {
    let mut entry = SmbiosType0::empty();
    entry.handle = header.handle;

    // Vendor string index at offset 4.
    if data.len() > 4 {
        entry.vendor = get_string(strings, data[4]);
    }
    // Version string index at offset 5.
    if data.len() > 5 {
        entry.version = get_string(strings, data[5]);
    }
    // Starting address segment at offset 6 (u16 LE).
    entry.starting_segment = read_u16_le(data, 6);
    // Release date string index at offset 8.
    if data.len() > 8 {
        entry.release_date = get_string(strings, data[8]);
    }
    // ROM size at offset 9.
    if data.len() > 9 {
        entry.rom_size = data[9];
    }
    // Characteristics at offset 10 (u64 LE).
    entry.characteristics = read_u64_le(data, 10);

    entry
}

/// Parse a Type 1 (System Information) structure.
fn parse_type1(data: &[u8], header: &SmbiosHeader, strings: &StringTable) -> SmbiosType1 {
    let mut entry = SmbiosType1::empty();
    entry.handle = header.handle;

    // Manufacturer string index at offset 4.
    if data.len() > 4 {
        entry.manufacturer = get_string(strings, data[4]);
    }
    // Product name string index at offset 5.
    if data.len() > 5 {
        entry.product_name = get_string(strings, data[5]);
    }
    // Version string index at offset 6.
    if data.len() > 6 {
        entry.version = get_string(strings, data[6]);
    }
    // Serial number string index at offset 7.
    if data.len() > 7 {
        entry.serial_number = get_string(strings, data[7]);
    }
    // UUID at offset 8 (16 bytes).
    if data.len() >= 24 {
        let mut uuid = Uuid::ZERO;
        let mut i = 0;
        while i < 16 {
            uuid.bytes[i] = data[8 + i];
            i += 1;
        }
        entry.uuid = uuid;
    }
    // Wake-up type at offset 24.
    if data.len() > 24 {
        entry.wakeup_type = data[24];
    }
    // SKU number string index at offset 25.
    if data.len() > 25 {
        entry.sku_number = get_string(strings, data[25]);
    }
    // Family string index at offset 26.
    if data.len() > 26 {
        entry.family = get_string(strings, data[26]);
    }

    entry
}

/// Parse a Type 4 (Processor Information) structure.
fn parse_type4(data: &[u8], header: &SmbiosHeader, strings: &StringTable) -> SmbiosType4 {
    let mut entry = SmbiosType4::empty();
    entry.handle = header.handle;

    // Socket designation string index at offset 4.
    if data.len() > 4 {
        entry.designation = get_string(strings, data[4]);
    }
    // Processor type at offset 5 (skip, not in our struct).
    // Processor family at offset 6.
    if data.len() > 6 {
        entry.family = ProcessorFamily::from_byte(data[6]);
    }
    // Manufacturer string index at offset 7.
    if data.len() > 7 {
        entry.manufacturer = get_string(strings, data[7]);
    }
    // Processor ID at offset 8 (u64 LE).
    entry.processor_id = read_u64_le(data, 8);
    // Version string index at offset 16.
    if data.len() > 16 {
        entry.version = get_string(strings, data[16]);
    }
    // Voltage at offset 17 (skip).
    // External clock at offset 18 (u16 LE).
    entry.external_clock_mhz = read_u16_le(data, 18);
    // Max speed at offset 20 (u16 LE).
    entry.max_speed_mhz = read_u16_le(data, 20);
    // Current speed at offset 22 (u16 LE).
    entry.current_speed_mhz = read_u16_le(data, 22);
    // Status at offset 24.
    if data.len() > 24 {
        entry.status = ProcessorStatus::from_byte(data[24]);
    }
    // Core count at offset 35 (SMBIOS 2.5+).
    if data.len() > 35 {
        entry.core_count = data[35] as u16;
    }
    // Core enabled at offset 36.
    if data.len() > 36 {
        entry.core_enabled = data[36] as u16;
    }
    // Thread count at offset 37.
    if data.len() > 37 {
        entry.thread_count = data[37] as u16;
    }

    // SMBIOS 3.0+ has 2-byte core/thread counts at offsets 42-47.
    if data.len() >= 48 {
        let core_count2 = read_u16_le(data, 42);
        let core_enabled2 = read_u16_le(data, 44);
        let thread_count2 = read_u16_le(data, 46);
        // Use extended values if the 1-byte fields are 0xFF.
        if entry.core_count == 0xFF && core_count2 > 0 {
            entry.core_count = core_count2;
        }
        if entry.core_enabled == 0xFF && core_enabled2 > 0 {
            entry.core_enabled = core_enabled2;
        }
        if entry.thread_count == 0xFF && thread_count2 > 0 {
            entry.thread_count = thread_count2;
        }
    }

    entry
}

/// Parse a Type 17 (Memory Device) structure.
fn parse_type17(data: &[u8], header: &SmbiosHeader, strings: &StringTable) -> SmbiosType17 {
    let mut entry = SmbiosType17::empty();
    entry.handle = header.handle;

    // Physical memory array handle at offset 4 (u16 LE).
    entry.array_handle = read_u16_le(data, 4);
    // Total width at offset 8 (u16 LE).
    entry.total_width = read_u16_le(data, 8);
    // Data width at offset 10 (u16 LE).
    entry.data_width = read_u16_le(data, 10);
    // Size at offset 12 (u16 LE).
    let raw_size = read_u16_le(data, 12);
    if raw_size == 0xFFFF {
        // Use extended size at offset 28 (u32 LE, in MB).
        if data.len() >= 32 {
            entry.size_mb = read_u32_le(data, 28);
        }
    } else if raw_size != 0x7FFF && raw_size != 0 {
        // Bit 15: 0 = MB, 1 = KB.
        if raw_size & 0x8000 != 0 {
            // Size in KB, convert to MB (round down).
            entry.size_mb = (raw_size & 0x7FFF) as u32 / 1024;
        } else {
            entry.size_mb = raw_size as u32;
        }
    }
    // Form factor at offset 14.
    if data.len() > 14 {
        entry.form_factor = MemoryFormFactor::from_byte(data[14]);
    }
    // Device locator string index at offset 16.
    if data.len() > 16 {
        entry.device_locator = get_string(strings, data[16]);
    }
    // Bank locator string index at offset 17.
    if data.len() > 17 {
        entry.bank_locator = get_string(strings, data[17]);
    }
    // Memory type at offset 18.
    if data.len() > 18 {
        entry.memory_type = MemoryType::from_byte(data[18]);
    }
    // Speed at offset 21 (u16 LE, MT/s).
    entry.speed_mts = read_u16_le(data, 21);
    // Manufacturer string index at offset 23.
    if data.len() > 23 {
        entry.manufacturer = get_string(strings, data[23]);
    }
    // Part number string index at offset 26.
    if data.len() > 26 {
        entry.part_number = get_string(strings, data[26]);
    }
    // Configured memory speed at offset 32 (u16 LE, MT/s).
    if data.len() >= 34 {
        entry.configured_speed_mts = read_u16_le(data, 32);
    }

    entry
}

// ── Main Table Parser ────────────────────────────────────────────

/// Walk the SMBIOS structure table and parse known types.
///
/// `data` must point to the start of the structure table with at
/// least `table_length` bytes available.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if the table data is too
/// small to contain even one header.
pub fn parse_structures(data: &[u8], table_length: usize, info: &mut SmbiosInfo) -> Result<()> {
    let bound = table_length.min(data.len());
    if bound < HEADER_SIZE {
        return Err(Error::InvalidArgument);
    }

    let mut offset = 0;

    while offset + HEADER_SIZE <= bound {
        // Read the structure header.
        // SAFETY: offset + HEADER_SIZE <= bound <= data.len().
        // SmbiosHeader is repr(C, packed), read_unaligned handles
        // alignment.
        let header =
            unsafe { core::ptr::read_unaligned(data.as_ptr().add(offset) as *const SmbiosHeader) };

        let formatted_len = header.length as usize;
        if formatted_len < HEADER_SIZE {
            // Corrupt header — bail out.
            break;
        }

        // The formatted area extends from offset to
        // offset + formatted_len.
        let formatted_end = offset + formatted_len;
        if formatted_end > bound {
            break;
        }

        // Parse the string table that follows the formatted area.
        let string_data = if formatted_end < bound {
            &data[formatted_end..bound]
        } else {
            &[] as &[u8]
        };
        let strings = parse_string_table(string_data);

        // Total structure size = formatted + string section.
        let struct_total = formatted_len + strings.consumed;

        // Decode by type.
        let struct_data = &data[offset..formatted_end.min(data.len())];
        match header.type_id {
            0 if info.bios_count < MAX_BIOS_ENTRIES => {
                info.bios[info.bios_count] = parse_type0(struct_data, &header, &strings);
                info.bios_count += 1;
            }
            1 if info.system_count < MAX_SYSTEM_ENTRIES => {
                info.system[info.system_count] = parse_type1(struct_data, &header, &strings);
                info.system_count += 1;
            }
            4 if info.processor_count < MAX_PROCESSOR_ENTRIES => {
                info.processors[info.processor_count] = parse_type4(struct_data, &header, &strings);
                info.processor_count += 1;
            }
            17 if info.memory_count < MAX_MEMORY_ENTRIES => {
                info.memory[info.memory_count] = parse_type17(struct_data, &header, &strings);
                info.memory_count += 1;
            }
            127 => {
                // End-of-Table structure (Type 127). Stop walking.
                break;
            }
            _ => {
                // Skip unknown structure types.
            }
        }

        offset += struct_total;
    }

    Ok(())
}

// ── Scan for SMBIOS Entry Point ──────────────────────────────────

/// Search for the SMBIOS entry point in the standard BIOS ROM area.
///
/// Scans memory region `0xF0000`–`0xFFFFF` on 16-byte boundaries
/// for either `_SM_` or `_SM3_` anchors.
///
/// # Safety
///
/// The caller must ensure the memory range is identity-mapped and
/// readable in the current address space.
pub unsafe fn find_entry_point() -> Option<u64> {
    // SAFETY: Scanning well-known BIOS memory region in Ring 0.
    // The caller guarantees this region is identity-mapped.
    unsafe {
        let mut addr = 0xF0000u64;
        while addr < 0x100000 {
            let ptr = addr as *const u8;

            // Check for 64-bit anchor `_SM3_` first.
            let mut is_sm3 = true;
            let mut i = 0;
            while i < 5 {
                if *ptr.add(i) != SM3_ANCHOR[i] {
                    is_sm3 = false;
                    break;
                }
                i += 1;
            }
            if is_sm3 {
                return Some(addr);
            }

            // Check for 32-bit anchor `_SM_`.
            let mut is_sm = true;
            i = 0;
            while i < 4 {
                if *ptr.add(i) != SM_ANCHOR[i] {
                    is_sm = false;
                    break;
                }
                i += 1;
            }
            if is_sm {
                return Some(addr);
            }

            addr += 16;
        }
    }

    None
}

// ── Registry ─────────────────────────────────────────────────────

/// Maximum number of SMBIOS info snapshots we can store.
const MAX_SNAPSHOTS: usize = 2;

/// Registry for SMBIOS information snapshots.
///
/// Typically only one snapshot is needed (from the boot-time scan),
/// but a second slot is available for firmware updates or testing.
pub struct SmbiosRegistry {
    /// Entry point addresses for each registered snapshot.
    entries: [Option<u64>; MAX_SNAPSHOTS],
    /// Number of registered snapshots.
    count: usize,
}

impl Default for SmbiosRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SmbiosRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_SNAPSHOTS],
            count: 0,
        }
    }

    /// Register an SMBIOS entry point address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, entry_point_addr: u64) -> Result<usize> {
        if self.count >= MAX_SNAPSHOTS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.entries[idx] = Some(entry_point_addr);
        self.count += 1;
        Ok(idx)
    }

    /// Get the entry point address for a registered snapshot.
    pub fn get(&self, index: usize) -> Option<u64> {
        if index < self.count {
            self.entries[index]
        } else {
            None
        }
    }

    /// Return the number of registered snapshots.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no snapshots are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
