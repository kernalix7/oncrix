// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ACPI firmware tables parser.
//!
//! Extends the basic ACPI table parser in [`crate::acpi`] with support
//! for a wider range of ACPI tables needed for platform initialisation:
//! FADT, DSDT, SSDT, MCFG, SRAT, DMAR, BGRT, and HPET description table.
//!
//! # Table hierarchy
//!
//! ```text
//! RSDP → XSDT ─┬── FADT → DSDT
//!               ├── MADT (APIC)
//!               ├── MCFG   (PCIe config space)
//!               ├── SRAT   (NUMA memory affinity)
//!               ├── DMAR   (Intel VT-d IOMMU)
//!               ├── HPET   (High Precision Event Timer)
//!               ├── BGRT   (Boot Graphics Resource Table)
//!               └── SSDT × N (secondary description tables)
//! ```
//!
//! All table structures are `#[repr(C, packed)]` and must be accessed
//! through `read_unaligned` to avoid UB on unaligned fields.
//!
//! Reference: ACPI Specification 6.5 (ASWG);
//!            UEFI Specification 2.10 §4.6 (BGRT).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Common ACPI table header
// ---------------------------------------------------------------------------

/// Standard ACPI System Description Table (SDT) header (36 bytes).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct AcpiTableHeader {
    /// 4-byte ASCII signature.
    pub signature: [u8; 4],
    /// Total length of the table including the header.
    pub length: u32,
    /// Revision number.
    pub revision: u8,
    /// Checksum: all bytes of the table must sum to 0.
    pub checksum: u8,
    /// OEM identifier.
    pub oem_id: [u8; 6],
    /// OEM table identifier.
    pub oem_table_id: [u8; 8],
    /// OEM revision.
    pub oem_revision: u32,
    /// Creator identifier.
    pub creator_id: [u8; 4],
    /// Creator revision.
    pub creator_revision: u32,
}

impl AcpiTableHeader {
    /// Size of the ACPI table header.
    pub const SIZE: usize = core::mem::size_of::<AcpiTableHeader>();
}

// ---------------------------------------------------------------------------
// Known ACPI table signatures
// ---------------------------------------------------------------------------

/// FADT signature: `"FACP"`.
pub const FADT_SIGNATURE: [u8; 4] = *b"FACP";

/// DSDT signature: `"DSDT"`.
pub const DSDT_SIGNATURE: [u8; 4] = *b"DSDT";

/// SSDT signature: `"SSDT"`.
pub const SSDT_SIGNATURE: [u8; 4] = *b"SSDT";

/// MADT/APIC signature: `"APIC"`.
pub const MADT_SIGNATURE: [u8; 4] = *b"APIC";

/// MCFG signature: `"MCFG"`.
pub const MCFG_SIGNATURE: [u8; 4] = *b"MCFG";

/// SRAT signature: `"SRAT"`.
pub const SRAT_SIGNATURE: [u8; 4] = *b"SRAT";

/// DMAR signature: `"DMAR"`.
pub const DMAR_SIGNATURE: [u8; 4] = *b"DMAR";

/// HPET table signature: `"HPET"`.
pub const HPET_TABLE_SIGNATURE: [u8; 4] = *b"HPET";

/// BGRT signature: `"BGRT"`.
pub const BGRT_SIGNATURE: [u8; 4] = *b"BGRT";

/// XSDT signature: `"XSDT"`.
pub const XSDT_SIGNATURE: [u8; 4] = *b"XSDT";

// ---------------------------------------------------------------------------
// Generic address structure
// ---------------------------------------------------------------------------

/// ACPI Generic Address Structure (GAS).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C, packed)]
pub struct AcpiGas {
    /// Address space ID (0=system memory, 1=I/O, 2=PCI config, ...).
    pub address_space_id: u8,
    /// Register bit width.
    pub register_bit_width: u8,
    /// Bit offset within the register.
    pub register_bit_offset: u8,
    /// Access size (0=undefined, 1=byte, 2=word, 3=dword, 4=qword).
    pub access_size: u8,
    /// 64-bit address.
    pub address: u64,
}

impl AcpiGas {
    /// Whether this GAS describes a system memory region.
    pub fn is_system_memory(&self) -> bool {
        self.address_space_id == 0
    }

    /// Whether this GAS describes an I/O port region.
    pub fn is_io_port(&self) -> bool {
        self.address_space_id == 1
    }
}

// ---------------------------------------------------------------------------
// FADT (Fixed ACPI Description Table)
// ---------------------------------------------------------------------------

/// FADT (Fixed ACPI Description Table) — selected fields only.
///
/// The full FADT is very large; we parse the fields used for OSPM
/// initialisation. Field layout follows ACPI 6.5 Table 5-9.
#[derive(Debug, Clone, Copy, Default)]
pub struct Fadt {
    /// Physical address of the DSDT.
    pub dsdt_address: u64,
    /// Preferred PM profile (1=desktop, 2=mobile, 3=workstation, etc.).
    pub preferred_pm_profile: u8,
    /// SCI interrupt vector.
    pub sci_interrupt: u16,
    /// SMI command port.
    pub smi_command: u32,
    /// ACPI enable command value.
    pub acpi_enable: u8,
    /// ACPI disable command value.
    pub acpi_disable: u8,
    /// PM1a event block address (GAS).
    pub pm1a_event_block: AcpiGas,
    /// PM1b event block address (GAS, may be zero).
    pub pm1b_event_block: AcpiGas,
    /// PM1a control block address (GAS).
    pub pm1a_ctrl_block: AcpiGas,
    /// PM1b control block address (GAS).
    pub pm1b_ctrl_block: AcpiGas,
    /// PM timer block address (GAS).
    pub pm_timer_block: AcpiGas,
    /// FADT flags word.
    pub flags: u32,
    /// FADT minor version.
    pub minor_version: u8,
}

impl Fadt {
    /// FADT flag: WBINVD instruction supported.
    pub const FLAG_WBINVD: u32 = 1 << 0;

    /// FADT flag: C1 power state supported.
    pub const FLAG_C1_SUPPORTED: u32 = 1 << 2;

    /// FADT flag: system supports sleep states S3.
    pub const FLAG_SLP_BUTTON: u32 = 1 << 5;

    /// FADT flag: RTC S4 wake.
    pub const FLAG_RTC_S4: u32 = 1 << 7;

    /// FADT flag: 32-bit PM timer (vs 24-bit).
    pub const FLAG_TMR_VAL_EXT: u32 = 1 << 8;

    /// FADT flag: RESET_REG supported.
    pub const FLAG_RESET_REG_SUP: u32 = 1 << 10;

    /// FADT flag: hardware-reduced ACPI.
    pub const FLAG_HW_REDUCED_ACPI: u32 = 1 << 20;

    /// Whether the platform has hardware-reduced ACPI (no hardware PM registers).
    pub fn is_hw_reduced(&self) -> bool {
        self.flags & Self::FLAG_HW_REDUCED_ACPI != 0
    }

    /// Whether the PM timer is 32 bits wide.
    pub fn pm_timer_32bit(&self) -> bool {
        self.flags & Self::FLAG_TMR_VAL_EXT != 0
    }
}

/// Parse a FADT from raw table bytes.
///
/// `data` must be a slice of the full FADT, starting at offset 0.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `data` is too short or the
/// signature does not match.
pub fn parse_fadt(data: &[u8]) -> Result<Fadt> {
    if data.len() < AcpiTableHeader::SIZE + 100 {
        return Err(Error::InvalidArgument);
    }
    // Verify signature.
    if data[..4] != FADT_SIGNATURE {
        return Err(Error::InvalidArgument);
    }
    verify_table_checksum(data)?;

    // FADT v1 fields start at offset 36 (after standard header).
    // We read offset-by-offset to handle packed misalignment.
    let fadt_smi_command = read_u32(data, 48);
    let acpi_enable = data[52];
    let acpi_disable = data[53];
    let sci_interrupt = read_u16(data, 46);
    let preferred_pm_profile = data[45];
    let fadt_flags = read_u32(data, 112);

    // DSDT physical address: prefer X_DSDT (ACPI 2.0+, offset 140) over
    // DSDT (offset 40) when available and non-zero.
    let dsdt32 = read_u32(data, 40) as u64;
    let dsdt64 = if data.len() >= 148 {
        read_u64(data, 140)
    } else {
        0
    };
    let dsdt_address = if dsdt64 != 0 { dsdt64 } else { dsdt32 };

    // PM1a event block GAS (ACPI 2.0+, offset 148).
    let pm1a_event = if data.len() >= 160 {
        read_gas(data, 148)
    } else {
        AcpiGas::default()
    };
    let pm1b_event = if data.len() >= 172 {
        read_gas(data, 160)
    } else {
        AcpiGas::default()
    };
    let pm1a_ctrl = if data.len() >= 184 {
        read_gas(data, 172)
    } else {
        AcpiGas::default()
    };
    let pm1b_ctrl = if data.len() >= 196 {
        read_gas(data, 184)
    } else {
        AcpiGas::default()
    };
    let pm_timer = if data.len() >= 232 {
        read_gas(data, 208)
    } else {
        AcpiGas::default()
    };
    let minor_version = if data.len() > 131 { data[131] } else { 0 };

    Ok(Fadt {
        dsdt_address,
        preferred_pm_profile,
        sci_interrupt,
        smi_command: fadt_smi_command,
        acpi_enable,
        acpi_disable,
        pm1a_event_block: pm1a_event,
        pm1b_event_block: pm1b_event,
        pm1a_ctrl_block: pm1a_ctrl,
        pm1b_ctrl_block: pm1b_ctrl,
        pm_timer_block: pm_timer,
        flags: fadt_flags,
        minor_version,
    })
}

// ---------------------------------------------------------------------------
// MCFG (PCI Express Memory Mapped Config Space)
// ---------------------------------------------------------------------------

/// MCFG allocation entry — one per PCI segment.
#[derive(Debug, Clone, Copy, Default)]
pub struct McfgEntry {
    /// Base physical address of the enhanced config region.
    pub base_address: u64,
    /// PCI segment group number.
    pub segment_group: u16,
    /// First bus number covered by this entry.
    pub start_bus: u8,
    /// Last bus number covered by this entry.
    pub end_bus: u8,
}

impl McfgEntry {
    /// Physical address of the config space for the given bus/device/function.
    pub fn config_address(&self, bus: u8, device: u8, function: u8) -> Option<u64> {
        if bus < self.start_bus || bus > self.end_bus {
            return None;
        }
        let bus_off = (bus - self.start_bus) as u64;
        let addr = self.base_address
            + (bus_off << 20)
            + ((device as u64 & 0x1F) << 15)
            + ((function as u64 & 0x07) << 12);
        Some(addr)
    }
}

/// Maximum MCFG entries we parse.
const MAX_MCFG_ENTRIES: usize = 8;

/// Parsed MCFG table.
#[derive(Debug, Default)]
pub struct Mcfg {
    /// Parsed allocation entries.
    pub entries: [McfgEntry; MAX_MCFG_ENTRIES],
    /// Number of valid entries.
    pub count: usize,
}

impl Mcfg {
    /// Look up the MCFG entry covering `segment` and `bus`.
    pub fn find(&self, segment: u16, bus: u8) -> Option<&McfgEntry> {
        for i in 0..self.count {
            let e = &self.entries[i];
            if e.segment_group == segment && bus >= e.start_bus && bus <= e.end_bus {
                return Some(e);
            }
        }
        None
    }
}

/// Parse an MCFG table from raw bytes.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if signature is wrong or data too short.
pub fn parse_mcfg(data: &[u8]) -> Result<Mcfg> {
    if data.len() < AcpiTableHeader::SIZE + 8 {
        return Err(Error::InvalidArgument);
    }
    if data[..4] != MCFG_SIGNATURE {
        return Err(Error::InvalidArgument);
    }
    verify_table_checksum(data)?;
    // Each MCFG allocation record starts at offset 44 (after header + 8 reserved).
    const ENTRY_SIZE: usize = 16;
    let entries_start = AcpiTableHeader::SIZE + 8;
    let available = data.len().saturating_sub(entries_start);
    let num_entries = (available / ENTRY_SIZE).min(MAX_MCFG_ENTRIES);
    let mut mcfg = Mcfg::default();
    for i in 0..num_entries {
        let off = entries_start + i * ENTRY_SIZE;
        if off + ENTRY_SIZE > data.len() {
            break;
        }
        mcfg.entries[i] = McfgEntry {
            base_address: read_u64(data, off),
            segment_group: read_u16(data, off + 8),
            start_bus: data[off + 10],
            end_bus: data[off + 11],
        };
        mcfg.count += 1;
    }
    Ok(mcfg)
}

// ---------------------------------------------------------------------------
// HPET description table
// ---------------------------------------------------------------------------

/// HPET description table (ACPI extension).
#[derive(Debug, Clone, Copy, Default)]
pub struct HpetTable {
    /// Event timer block ID (hardware implementation info).
    pub event_timer_block_id: u32,
    /// Main counter address (GAS).
    pub base_address: AcpiGas,
    /// HPET sequence number (0-based, for multiple HPETs).
    pub hpet_number: u8,
    /// Minimum tick period in femtoseconds.
    pub main_counter_minimum_tick: u16,
    /// Page protection and OEM attribute.
    pub page_protection: u8,
}

/// Parse an HPET description table.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if signature is wrong or data too short.
pub fn parse_hpet_table(data: &[u8]) -> Result<HpetTable> {
    const MIN_LEN: usize = AcpiTableHeader::SIZE + 20;
    if data.len() < MIN_LEN {
        return Err(Error::InvalidArgument);
    }
    if data[..4] != HPET_TABLE_SIGNATURE {
        return Err(Error::InvalidArgument);
    }
    verify_table_checksum(data)?;
    let base = AcpiTableHeader::SIZE;
    Ok(HpetTable {
        event_timer_block_id: read_u32(data, base),
        base_address: read_gas(data, base + 4),
        hpet_number: data[base + 16],
        main_counter_minimum_tick: read_u16(data, base + 17),
        page_protection: data[base + 19],
    })
}

// ---------------------------------------------------------------------------
// BGRT (Boot Graphics Resource Table)
// ---------------------------------------------------------------------------

/// BGRT image type: BMP.
pub const BGRT_IMAGE_TYPE_BMP: u8 = 0;

/// BGRT status: image is valid.
pub const BGRT_STATUS_VALID: u8 = 1;

/// Parsed Boot Graphics Resource Table.
#[derive(Debug, Clone, Copy, Default)]
pub struct Bgrt {
    /// BGRT spec version (must be 1).
    pub version: u16,
    /// Status flags (bit 0 = image valid).
    pub status: u8,
    /// Image type (0 = BMP).
    pub image_type: u8,
    /// Physical address of the image data.
    pub image_address: u64,
    /// X offset of the image on screen.
    pub offset_x: u32,
    /// Y offset of the image on screen.
    pub offset_y: u32,
}

impl Bgrt {
    /// Whether the boot graphics image is valid.
    pub fn is_valid(&self) -> bool {
        self.status & BGRT_STATUS_VALID != 0
    }
}

/// Parse a BGRT table from raw bytes.
pub fn parse_bgrt(data: &[u8]) -> Result<Bgrt> {
    const MIN_LEN: usize = AcpiTableHeader::SIZE + 18;
    if data.len() < MIN_LEN {
        return Err(Error::InvalidArgument);
    }
    if data[..4] != BGRT_SIGNATURE {
        return Err(Error::InvalidArgument);
    }
    verify_table_checksum(data)?;
    let base = AcpiTableHeader::SIZE;
    Ok(Bgrt {
        version: read_u16(data, base),
        status: data[base + 2],
        image_type: data[base + 3],
        image_address: read_u64(data, base + 4),
        offset_x: read_u32(data, base + 12),
        offset_y: read_u32(data, base + 16),
    })
}

// ---------------------------------------------------------------------------
// SRAT (System Resource Affinity Table)
// ---------------------------------------------------------------------------

/// SRAT structure type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SratType {
    /// Local APIC/SAPIC affinity.
    LocalApicAffinity = 0,
    /// Memory affinity.
    MemoryAffinity = 1,
    /// Local x2APIC affinity.
    LocalX2ApicAffinity = 2,
}

/// A single SRAT memory affinity entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct SratMemAffinity {
    /// NUMA proximity domain.
    pub proximity_domain: u32,
    /// Base physical address.
    pub base_address: u64,
    /// Length of the region.
    pub length: u64,
    /// Flags (bit 0 = enabled, bit 1 = hot-plug, bit 2 = non-volatile).
    pub flags: u32,
}

impl SratMemAffinity {
    /// Whether this region is enabled.
    pub fn is_enabled(&self) -> bool {
        self.flags & 1 != 0
    }

    /// Whether this region supports hot-plug.
    pub fn is_hotplug(&self) -> bool {
        self.flags & 2 != 0
    }

    /// Whether this region is non-volatile memory.
    pub fn is_non_volatile(&self) -> bool {
        self.flags & 4 != 0
    }
}

/// Maximum SRAT memory affinity entries parsed.
const MAX_SRAT_MEM: usize = 16;

/// Parsed SRAT table — memory affinity entries only.
#[derive(Debug, Default)]
pub struct Srat {
    /// Memory affinity entries.
    pub mem_entries: [SratMemAffinity; MAX_SRAT_MEM],
    /// Number of valid memory affinity entries.
    pub mem_count: usize,
}

/// Parse a SRAT table from raw bytes.
///
/// Only memory affinity entries (type 1) are parsed; APIC affinity
/// entries are counted but not stored.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if signature or length is wrong.
pub fn parse_srat(data: &[u8]) -> Result<Srat> {
    if data.len() < AcpiTableHeader::SIZE + 12 {
        return Err(Error::InvalidArgument);
    }
    if data[..4] != SRAT_SIGNATURE {
        return Err(Error::InvalidArgument);
    }
    verify_table_checksum(data)?;
    let mut srat = Srat::default();
    // Sub-structures start after header (36) + 12 reserved bytes.
    let mut offset = AcpiTableHeader::SIZE + 12;
    while offset + 2 <= data.len() {
        let stype = data[offset];
        let slen = data[offset + 1] as usize;
        if slen < 2 || offset + slen > data.len() {
            break;
        }
        if stype == SratType::MemoryAffinity as u8 && slen >= 40 {
            if srat.mem_count < MAX_SRAT_MEM {
                let prox = read_u32(data, offset + 2);
                let base = read_u64(data, offset + 8);
                let len = read_u64(data, offset + 16);
                let flags = read_u32(data, offset + 28);
                srat.mem_entries[srat.mem_count] = SratMemAffinity {
                    proximity_domain: prox,
                    base_address: base,
                    length: len,
                    flags,
                };
                srat.mem_count += 1;
            }
        }
        offset += slen;
    }
    Ok(srat)
}

// ---------------------------------------------------------------------------
// XSDT walker
// ---------------------------------------------------------------------------

/// Maximum table entries we track from the XSDT.
const MAX_XSDT_ENTRIES: usize = 64;

/// Parsed XSDT — contains physical addresses of all SDTs.
#[derive(Debug)]
pub struct Xsdt {
    /// Physical addresses of system description tables.
    pub entries: [u64; MAX_XSDT_ENTRIES],
    /// Number of valid entries.
    pub count: usize,
}

impl Default for Xsdt {
    fn default() -> Self {
        Self {
            entries: [0u64; MAX_XSDT_ENTRIES],
            count: 0,
        }
    }
}

impl Xsdt {
    /// Iterate over entry addresses.
    pub fn iter(&self) -> &[u64] {
        &self.entries[..self.count]
    }
}

/// Parse an XSDT from raw bytes.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if the signature or length is wrong.
pub fn parse_xsdt(data: &[u8]) -> Result<Xsdt> {
    if data.len() < AcpiTableHeader::SIZE {
        return Err(Error::InvalidArgument);
    }
    if data[..4] != XSDT_SIGNATURE {
        return Err(Error::InvalidArgument);
    }
    verify_table_checksum(data)?;
    let table_len = read_u32(data, 4) as usize;
    let entries_len = table_len.saturating_sub(AcpiTableHeader::SIZE);
    let num = (entries_len / 8).min(MAX_XSDT_ENTRIES);
    let mut xsdt = Xsdt::default();
    for i in 0..num {
        let off = AcpiTableHeader::SIZE + i * 8;
        if off + 8 > data.len() {
            break;
        }
        xsdt.entries[i] = read_u64(data, off);
        xsdt.count += 1;
    }
    Ok(xsdt)
}

// ---------------------------------------------------------------------------
// Table registry
// ---------------------------------------------------------------------------

/// A located ACPI table: signature + physical address.
#[derive(Debug, Clone, Copy, Default)]
pub struct AcpiTableRef {
    /// 4-byte table signature.
    pub signature: [u8; 4],
    /// Physical address of the table.
    pub phys_addr: u64,
    /// Table length in bytes.
    pub length: u32,
}

impl AcpiTableRef {
    /// Whether this entry is valid (signature != 0).
    pub fn is_valid(&self) -> bool {
        self.signature != [0u8; 4]
    }
}

/// Maximum tables we track in the firmware registry.
const MAX_TABLES: usize = 64;

/// Registry of discovered ACPI tables.
pub struct FirmwareAcpiRegistry {
    tables: [AcpiTableRef; MAX_TABLES],
    count: usize,
}

impl FirmwareAcpiRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            tables: [AcpiTableRef {
                signature: [0u8; 4],
                phys_addr: 0,
                length: 0,
            }; MAX_TABLES],
            count: 0,
        }
    }

    /// Add a table reference.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn add(&mut self, sig: [u8; 4], phys_addr: u64, length: u32) -> Result<()> {
        if self.count >= MAX_TABLES {
            return Err(Error::OutOfMemory);
        }
        self.tables[self.count] = AcpiTableRef {
            signature: sig,
            phys_addr,
            length,
        };
        self.count += 1;
        Ok(())
    }

    /// Find the first table with the given signature.
    pub fn find(&self, sig: &[u8; 4]) -> Option<&AcpiTableRef> {
        for i in 0..self.count {
            if &self.tables[i].signature == sig {
                return Some(&self.tables[i]);
            }
        }
        None
    }

    /// Number of registered tables.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterate over all table references.
    pub fn iter(&self) -> &[AcpiTableRef] {
        &self.tables[..self.count]
    }
}

// ---------------------------------------------------------------------------
// Checksum verification
// ---------------------------------------------------------------------------

/// Verify the ACPI checksum of `data`.
///
/// All bytes must sum to zero (mod 256).
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if the checksum fails.
pub fn verify_table_checksum(data: &[u8]) -> Result<()> {
    let sum: u8 = data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    if sum != 0 {
        Err(Error::InvalidArgument)
    } else {
        Ok(())
    }
}

/// Verify only the first `len` bytes of a potentially longer slice.
pub fn verify_partial_checksum(data: &[u8], len: usize) -> Result<()> {
    if data.len() < len {
        return Err(Error::InvalidArgument);
    }
    verify_table_checksum(&data[..len])
}

// ---------------------------------------------------------------------------
// Read helpers (handle packed struct alignment)
// ---------------------------------------------------------------------------

/// Read a `u16` from `data` at `offset` (little-endian, unaligned-safe).
fn read_u16(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

/// Read a `u32` from `data` at `offset` (little-endian, unaligned-safe).
fn read_u32(data: &[u8], offset: usize) -> u32 {
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

/// Read a `u64` from `data` at `offset` (little-endian, unaligned-safe).
fn read_u64(data: &[u8], offset: usize) -> u64 {
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

/// Read an `AcpiGas` from `data` at `offset` (12 bytes).
fn read_gas(data: &[u8], offset: usize) -> AcpiGas {
    if offset + 12 > data.len() {
        return AcpiGas::default();
    }
    AcpiGas {
        address_space_id: data[offset],
        register_bit_width: data[offset + 1],
        register_bit_offset: data[offset + 2],
        access_size: data[offset + 3],
        address: read_u64(data, offset + 4),
    }
}

// ---------------------------------------------------------------------------
// RSDP (Root System Description Pointer)
// ---------------------------------------------------------------------------

/// RSDP magic signature: `"RSD PTR "` (8 bytes including trailing space).
pub const RSDP_SIGNATURE: [u8; 8] = *b"RSD PTR ";

/// RSDP v2.0+ structure length.
pub const RSDP_V2_LENGTH: usize = 36;

/// RSDP v1.0 structure length (first 20 bytes are checksummed).
pub const RSDP_V1_LENGTH: usize = 20;

/// BIOS Extended Data Area (EBDA) pointer address (16-bit segment at 0x40E).
#[cfg(target_arch = "x86_64")]
pub const EBDA_SEG_PTR: u64 = 0x40E;

/// Start of the BIOS ROM area to scan for RSDP.
pub const BIOS_ROM_START: u64 = 0xE0000;

/// End of the BIOS ROM area.
pub const BIOS_ROM_END: u64 = 0xFFFFF;

/// RSDP is aligned to a 16-byte boundary within search areas.
pub const RSDP_ALIGN: u64 = 16;

/// Parsed RSDP information.
#[derive(Debug, Clone, Copy, Default)]
pub struct RsdpInfo {
    /// ACPI revision (0 = v1.0, 2 = v2.0+).
    pub revision: u8,
    /// Physical address of the RSDT (32-bit pointer, valid for all revisions).
    pub rsdt_address: u32,
    /// Physical address of the XSDT (64-bit, valid only when `revision >= 2`).
    pub xsdt_address: u64,
    /// Total length of this RSDP structure.
    pub length: u32,
    /// Physical address at which the RSDP was found.
    pub found_at: u64,
}

impl RsdpInfo {
    /// Returns true if the XSDT address is valid (v2.0+).
    pub fn has_xsdt(&self) -> bool {
        self.revision >= 2 && self.xsdt_address != 0
    }
}

/// Parse and validate an RSDP from a raw byte slice.
///
/// Validates signature, v1.0 checksum (first 20 bytes), and — for revision
/// ≥ 2 — the extended checksum over the full 36-byte structure.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] on signature mismatch or checksum failure.
pub fn parse_rsdp(data: &[u8]) -> Result<RsdpInfo> {
    if data.len() < RSDP_V1_LENGTH {
        return Err(Error::InvalidArgument);
    }
    // Validate 8-byte signature.
    if data[..8] != RSDP_SIGNATURE {
        return Err(Error::InvalidArgument);
    }
    // Validate v1 checksum over first 20 bytes.
    let sum: u8 = data[..RSDP_V1_LENGTH]
        .iter()
        .fold(0u8, |acc, &b| acc.wrapping_add(b));
    if sum != 0 {
        return Err(Error::InvalidArgument);
    }

    let revision = data[15];
    let rsdt_address = read_u32(data, 16);

    // ACPI 2.0+: extended structure.
    let (xsdt_address, length) = if revision >= 2 && data.len() >= RSDP_V2_LENGTH {
        let len = read_u32(data, 20);
        let check_len = (len as usize).min(data.len());
        // Extended checksum covers full structure.
        let ext_sum: u8 = data[..check_len]
            .iter()
            .fold(0u8, |acc, &b| acc.wrapping_add(b));
        if ext_sum != 0 {
            return Err(Error::InvalidArgument);
        }
        (read_u64(data, 24), len)
    } else {
        (0u64, RSDP_V1_LENGTH as u32)
    };

    Ok(RsdpInfo {
        revision,
        rsdt_address,
        xsdt_address,
        length,
        found_at: 0,
    })
}

/// Locate the RSDP by scanning the BIOS ROM area (0xE0000–0xFFFFF).
///
/// `read_phys` is a callback that maps a physical address to a slice of
/// at least `len` bytes. Returns the first valid RSDP found.
///
/// In a real kernel this function runs before the memory map is set up,
/// scanning physical memory directly.
///
/// # Errors
///
/// Returns [`Error::NotFound`] if no valid RSDP is present in the scan area.
pub fn locate_rsdp_bios<F>(read_phys: F) -> Result<RsdpInfo>
where
    F: Fn(u64, usize) -> Option<&'static [u8]>,
{
    let mut phys = BIOS_ROM_START;
    while phys < BIOS_ROM_END {
        if let Some(slice) = read_phys(phys, RSDP_V2_LENGTH) {
            if let Ok(mut info) = parse_rsdp(slice) {
                info.found_at = phys;
                return Ok(info);
            }
        }
        phys += RSDP_ALIGN;
    }
    Err(Error::NotFound)
}

/// Locate the RSDP from a pointer provided by firmware (e.g., UEFI SystemTable).
///
/// `phys_addr` is the physical address hint provided by the bootloader.
///
/// # Errors
///
/// Returns [`Error::NotFound`] if the address does not contain a valid RSDP.
pub fn locate_rsdp_from_ptr<F>(phys_addr: u64, read_phys: F) -> Result<RsdpInfo>
where
    F: Fn(u64, usize) -> Option<&'static [u8]>,
{
    let slice = read_phys(phys_addr, RSDP_V2_LENGTH).ok_or(Error::NotFound)?;
    let mut info = parse_rsdp(slice)?;
    info.found_at = phys_addr;
    Ok(info)
}

// ---------------------------------------------------------------------------
// RSDT (Root System Description Table — 32-bit pointer version)
// ---------------------------------------------------------------------------

/// RSDT signature: `"RSDT"`.
pub const RSDT_SIGNATURE: [u8; 4] = *b"RSDT";

/// Maximum RSDT entries parsed.
const MAX_RSDT_ENTRIES: usize = 64;

/// Parsed RSDT — 32-bit physical addresses of all SDTs.
#[derive(Debug)]
pub struct Rsdt {
    /// Physical addresses of system description tables (32-bit).
    pub entries: [u32; MAX_RSDT_ENTRIES],
    /// Number of valid entries.
    pub count: usize,
}

impl Default for Rsdt {
    fn default() -> Self {
        Self {
            entries: [0u32; MAX_RSDT_ENTRIES],
            count: 0,
        }
    }
}

impl Rsdt {
    /// Iterate over entry addresses (as u64 for uniform handling).
    pub fn iter_u64(&self) -> impl Iterator<Item = u64> + '_ {
        self.entries[..self.count].iter().map(|&a| a as u64)
    }
}

/// Parse an RSDT from raw bytes.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if the signature, checksum, or length
/// is invalid.
pub fn parse_rsdt(data: &[u8]) -> Result<Rsdt> {
    if data.len() < AcpiTableHeader::SIZE {
        return Err(Error::InvalidArgument);
    }
    if data[..4] != RSDT_SIGNATURE {
        return Err(Error::InvalidArgument);
    }
    verify_table_checksum(data)?;
    let table_len = read_u32(data, 4) as usize;
    let entries_len = table_len.saturating_sub(AcpiTableHeader::SIZE);
    let num = (entries_len / 4).min(MAX_RSDT_ENTRIES);
    let mut rsdt = Rsdt::default();
    for i in 0..num {
        let off = AcpiTableHeader::SIZE + i * 4;
        if off + 4 > data.len() {
            break;
        }
        rsdt.entries[i] = read_u32(data, off);
        rsdt.count += 1;
    }
    Ok(rsdt)
}

// ---------------------------------------------------------------------------
// Generic table header validation
// ---------------------------------------------------------------------------

/// Validates an ACPI table header: checks minimum length, signature, and
/// the full table checksum.
///
/// # Arguments
///
/// * `data` — raw bytes of the table (must be at least `AcpiTableHeader::SIZE`).
/// * `expected_sig` — expected 4-byte signature, or `None` to skip signature check.
/// * `min_length` — minimum total byte length beyond the header.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] on any validation failure.
pub fn validate_table_header(
    data: &[u8],
    expected_sig: Option<&[u8; 4]>,
    min_length: usize,
) -> Result<u32> {
    if data.len() < AcpiTableHeader::SIZE + min_length {
        return Err(Error::InvalidArgument);
    }
    if let Some(sig) = expected_sig {
        if &data[..4] != sig {
            return Err(Error::InvalidArgument);
        }
    }
    let table_len = read_u32(data, 4);
    if (table_len as usize) < AcpiTableHeader::SIZE + min_length {
        return Err(Error::InvalidArgument);
    }
    verify_table_checksum(&data[..(table_len as usize).min(data.len())])?;
    Ok(table_len)
}

// ---------------------------------------------------------------------------
// AcpiTable trait
// ---------------------------------------------------------------------------

/// Trait for parsed ACPI table types.
///
/// Provides a common interface for signature introspection and validation.
pub trait AcpiTable {
    /// Returns the 4-byte ACPI table signature.
    fn signature() -> [u8; 4]
    where
        Self: Sized;

    /// Parses and validates the table from a raw byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the data is invalid.
    fn parse(data: &[u8]) -> Result<Self>
    where
        Self: Sized;

    /// Returns the OEM identifier extracted from this table's header bytes.
    ///
    /// Default implementation returns an all-zero array (override if needed).
    fn oem_id(&self) -> [u8; 6] {
        [0u8; 6]
    }
}

// AcpiTable implementations for existing parsed types.

impl AcpiTable for Fadt {
    fn signature() -> [u8; 4] {
        FADT_SIGNATURE
    }
    fn parse(data: &[u8]) -> Result<Self> {
        parse_fadt(data)
    }
}

impl AcpiTable for Mcfg {
    fn signature() -> [u8; 4] {
        MCFG_SIGNATURE
    }
    fn parse(data: &[u8]) -> Result<Self> {
        parse_mcfg(data)
    }
}

impl AcpiTable for HpetTable {
    fn signature() -> [u8; 4] {
        HPET_TABLE_SIGNATURE
    }
    fn parse(data: &[u8]) -> Result<Self> {
        parse_hpet_table(data)
    }
}

impl AcpiTable for Bgrt {
    fn signature() -> [u8; 4] {
        BGRT_SIGNATURE
    }
    fn parse(data: &[u8]) -> Result<Self> {
        parse_bgrt(data)
    }
}

impl AcpiTable for Srat {
    fn signature() -> [u8; 4] {
        SRAT_SIGNATURE
    }
    fn parse(data: &[u8]) -> Result<Self> {
        parse_srat(data)
    }
}

impl AcpiTable for Xsdt {
    fn signature() -> [u8; 4] {
        XSDT_SIGNATURE
    }
    fn parse(data: &[u8]) -> Result<Self> {
        parse_xsdt(data)
    }
}

impl AcpiTable for Rsdt {
    fn signature() -> [u8; 4] {
        RSDT_SIGNATURE
    }
    fn parse(data: &[u8]) -> Result<Self> {
        parse_rsdt(data)
    }
}

// ---------------------------------------------------------------------------
// MADT (Multiple APIC Description Table)
// ---------------------------------------------------------------------------

/// MADT flags: dual 8259 PICs installed.
pub const MADT_FLAG_PCAT_COMPAT: u32 = 1 << 0;

/// MADT entry type: Processor Local APIC.
pub const MADT_TYPE_LOCAL_APIC: u8 = 0;

/// MADT entry type: I/O APIC.
pub const MADT_TYPE_IO_APIC: u8 = 1;

/// MADT entry type: Interrupt Source Override.
pub const MADT_TYPE_INT_SRC_OVERRIDE: u8 = 2;

/// MADT entry type: NMI Source.
pub const MADT_TYPE_NMI_SOURCE: u8 = 3;

/// MADT entry type: Local APIC NMI.
pub const MADT_TYPE_LOCAL_APIC_NMI: u8 = 4;

/// MADT entry type: Local APIC Address Override.
pub const MADT_TYPE_LOCAL_APIC_ADDR_OVERRIDE: u8 = 5;

/// MADT entry type: Processor Local x2APIC.
pub const MADT_TYPE_LOCAL_X2APIC: u8 = 9;

/// MADT entry type: Local x2APIC NMI.
pub const MADT_TYPE_LOCAL_X2APIC_NMI: u8 = 10;

// MADT local APIC flags.
/// Local APIC flags: processor is enabled.
pub const MADT_LAPIC_FLAG_ENABLED: u32 = 1 << 0;

/// Local APIC flags: processor can be online-capable.
pub const MADT_LAPIC_FLAG_ONLINE_CAPABLE: u32 = 1 << 1;

/// MPS INTI flags: polarity mask.
pub const MPS_INTI_POLARITY_MASK: u16 = 0x03;

/// MPS INTI flags: active-high polarity.
pub const MPS_INTI_POLARITY_ACTIVE_HIGH: u16 = 0x01;

/// MPS INTI flags: active-low polarity.
pub const MPS_INTI_POLARITY_ACTIVE_LOW: u16 = 0x03;

/// MPS INTI flags: trigger mode mask.
pub const MPS_INTI_TRIGGER_MASK: u16 = 0x0C;

/// MPS INTI flags: edge-triggered.
pub const MPS_INTI_TRIGGER_EDGE: u16 = 0x04;

/// MPS INTI flags: level-triggered.
pub const MPS_INTI_TRIGGER_LEVEL: u16 = 0x0C;

/// A processor Local APIC entry (MADT type 0).
#[derive(Debug, Clone, Copy)]
pub struct MadtLocalApic {
    /// ACPI processor UID.
    pub acpi_processor_uid: u8,
    /// APIC ID.
    pub apic_id: u8,
    /// Flags (see `MADT_LAPIC_FLAG_*`).
    pub flags: u32,
}

impl MadtLocalApic {
    /// Whether this processor is enabled.
    pub fn is_enabled(&self) -> bool {
        self.flags & MADT_LAPIC_FLAG_ENABLED != 0
    }

    /// Whether this processor is online-capable but currently disabled.
    pub fn is_online_capable(&self) -> bool {
        self.flags & MADT_LAPIC_FLAG_ONLINE_CAPABLE != 0
    }
}

/// An I/O APIC entry (MADT type 1).
#[derive(Debug, Clone, Copy)]
pub struct MadtIoApic {
    /// I/O APIC ID.
    pub io_apic_id: u8,
    /// Physical address of the I/O APIC registers.
    pub io_apic_address: u32,
    /// Global system interrupt base (first GSI serviced by this I/O APIC).
    pub global_irq_base: u32,
}

/// An Interrupt Source Override entry (MADT type 2).
///
/// Overrides the standard ISA IRQ-to-GSI mapping for a specific IRQ.
#[derive(Debug, Clone, Copy)]
pub struct MadtIntSrcOverride {
    /// Bus source (0 = ISA).
    pub bus: u8,
    /// Source IRQ number.
    pub source_irq: u8,
    /// Global system interrupt this IRQ is mapped to.
    pub global_irq: u32,
    /// MPS INTI flags (polarity and trigger mode).
    pub flags: u16,
}

impl MadtIntSrcOverride {
    /// Returns the polarity for this interrupt.
    pub fn polarity(&self) -> u16 {
        self.flags & MPS_INTI_POLARITY_MASK
    }

    /// Returns the trigger mode for this interrupt.
    pub fn trigger_mode(&self) -> u16 {
        self.flags & MPS_INTI_TRIGGER_MASK
    }

    /// Whether this interrupt uses active-low polarity.
    pub fn is_active_low(&self) -> bool {
        self.polarity() == MPS_INTI_POLARITY_ACTIVE_LOW
    }

    /// Whether this interrupt is level-triggered.
    pub fn is_level_triggered(&self) -> bool {
        self.trigger_mode() == MPS_INTI_TRIGGER_LEVEL
    }
}

/// An NMI Source entry (MADT type 3).
#[derive(Debug, Clone, Copy)]
pub struct MadtNmiSource {
    /// MPS INTI flags.
    pub flags: u16,
    /// Global system interrupt for the NMI.
    pub global_irq: u32,
}

/// A Local APIC NMI entry (MADT type 4).
#[derive(Debug, Clone, Copy)]
pub struct MadtLocalApicNmi {
    /// ACPI processor UID (0xFF = all processors).
    pub acpi_processor_uid: u8,
    /// MPS INTI flags.
    pub flags: u16,
    /// Local APIC LINT# pin (0 or 1).
    pub lint: u8,
}

/// A Local APIC Address Override entry (MADT type 5).
#[derive(Debug, Clone, Copy)]
pub struct MadtLocalApicAddrOverride {
    /// 64-bit physical address of the local APIC.
    pub local_apic_address: u64,
}

/// A Processor Local x2APIC entry (MADT type 9).
#[derive(Debug, Clone, Copy)]
pub struct MadtLocalX2Apic {
    /// x2APIC ID.
    pub x2apic_id: u32,
    /// Flags (see `MADT_LAPIC_FLAG_*`).
    pub flags: u32,
    /// ACPI processor UID.
    pub acpi_processor_uid: u32,
}

impl MadtLocalX2Apic {
    /// Whether this processor is enabled.
    pub fn is_enabled(&self) -> bool {
        self.flags & MADT_LAPIC_FLAG_ENABLED != 0
    }
}

/// An MADT entry (discriminated union).
#[derive(Debug, Clone, Copy)]
pub enum MadtEntry {
    /// Processor Local APIC.
    LocalApic(MadtLocalApic),
    /// I/O APIC.
    IoApic(MadtIoApic),
    /// Interrupt Source Override.
    IntSrcOverride(MadtIntSrcOverride),
    /// NMI Source.
    NmiSource(MadtNmiSource),
    /// Local APIC NMI.
    LocalApicNmi(MadtLocalApicNmi),
    /// Local APIC Address Override.
    LocalApicAddrOverride(MadtLocalApicAddrOverride),
    /// Local x2APIC.
    LocalX2Apic(MadtLocalX2Apic),
    /// Unknown or unsupported entry type.
    Unknown { entry_type: u8, length: u8 },
}

/// Maximum MADT entries parsed.
pub const MAX_MADT_ENTRIES: usize = 256;

/// Parsed MADT table.
pub struct Madt {
    /// Physical address of the local APIC (may be overridden by type-5 entry).
    pub local_apic_address: u64,
    /// MADT flags (see `MADT_FLAG_*`).
    pub flags: u32,
    /// Parsed MADT entries.
    pub entries: [MadtEntry; MAX_MADT_ENTRIES],
    /// Number of valid entries.
    pub count: usize,
}

impl Madt {
    /// Returns the effective local APIC base address, accounting for
    /// any type-5 address override entry.
    pub fn effective_lapic_address(&self) -> u64 {
        for i in 0..self.count {
            if let MadtEntry::LocalApicAddrOverride(ov) = self.entries[i] {
                return ov.local_apic_address;
            }
        }
        self.local_apic_address
    }

    /// Iterates over all Local APIC entries.
    pub fn local_apics(&self) -> impl Iterator<Item = &MadtLocalApic> {
        self.entries[..self.count].iter().filter_map(|e| {
            if let MadtEntry::LocalApic(la) = e {
                Some(la)
            } else {
                None
            }
        })
    }

    /// Iterates over all I/O APIC entries.
    pub fn io_apics(&self) -> impl Iterator<Item = &MadtIoApic> {
        self.entries[..self.count].iter().filter_map(|e| {
            if let MadtEntry::IoApic(ia) = e {
                Some(ia)
            } else {
                None
            }
        })
    }

    /// Iterates over all Interrupt Source Override entries.
    pub fn int_overrides(&self) -> impl Iterator<Item = &MadtIntSrcOverride> {
        self.entries[..self.count].iter().filter_map(|e| {
            if let MadtEntry::IntSrcOverride(iso) = e {
                Some(iso)
            } else {
                None
            }
        })
    }

    /// Returns the number of enabled logical processors.
    pub fn enabled_cpu_count(&self) -> usize {
        let lapic = self.entries[..self.count]
            .iter()
            .filter(|e| matches!(e, MadtEntry::LocalApic(la) if la.is_enabled()))
            .count();
        let x2apic = self.entries[..self.count]
            .iter()
            .filter(|e| matches!(e, MadtEntry::LocalX2Apic(xa) if xa.is_enabled()))
            .count();
        lapic + x2apic
    }

    /// Returns true if legacy 8259 PICs are present.
    pub fn has_8259(&self) -> bool {
        self.flags & MADT_FLAG_PCAT_COMPAT != 0
    }
}

/// Parse a MADT table from raw bytes.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if the signature, checksum, or entry
/// structure is invalid.
pub fn parse_madt(data: &[u8]) -> Result<Madt> {
    validate_table_header(data, Some(&MADT_SIGNATURE), 8)?;

    let local_apic_address = read_u32(data, AcpiTableHeader::SIZE) as u64;
    let flags = read_u32(data, AcpiTableHeader::SIZE + 4);

    // Entries follow the header + 8-byte MADT-specific fields.
    let mut offset = AcpiTableHeader::SIZE + 8;
    let table_end = (read_u32(data, 4) as usize).min(data.len());

    // We use a fixed-size array; initialize with a placeholder.
    const INIT_ENTRY: MadtEntry = MadtEntry::Unknown {
        entry_type: 0xFF,
        length: 0,
    };
    let mut entries = [INIT_ENTRY; MAX_MADT_ENTRIES];
    let mut count = 0usize;

    while offset + 2 <= table_end && count < MAX_MADT_ENTRIES {
        let entry_type = data[offset];
        let entry_len = data[offset + 1] as usize;

        if entry_len < 2 || offset + entry_len > table_end {
            break;
        }

        let entry = match entry_type {
            MADT_TYPE_LOCAL_APIC if entry_len >= 8 => MadtEntry::LocalApic(MadtLocalApic {
                acpi_processor_uid: data[offset + 2],
                apic_id: data[offset + 3],
                flags: read_u32(data, offset + 4),
            }),
            MADT_TYPE_IO_APIC if entry_len >= 12 => {
                MadtEntry::IoApic(MadtIoApic {
                    io_apic_id: data[offset + 2],
                    // offset+3 is reserved
                    io_apic_address: read_u32(data, offset + 4),
                    global_irq_base: read_u32(data, offset + 8),
                })
            }
            MADT_TYPE_INT_SRC_OVERRIDE if entry_len >= 10 => {
                MadtEntry::IntSrcOverride(MadtIntSrcOverride {
                    bus: data[offset + 2],
                    source_irq: data[offset + 3],
                    global_irq: read_u32(data, offset + 4),
                    flags: read_u16(data, offset + 8),
                })
            }
            MADT_TYPE_NMI_SOURCE if entry_len >= 8 => MadtEntry::NmiSource(MadtNmiSource {
                flags: read_u16(data, offset + 2),
                global_irq: read_u32(data, offset + 4),
            }),
            MADT_TYPE_LOCAL_APIC_NMI if entry_len >= 6 => {
                MadtEntry::LocalApicNmi(MadtLocalApicNmi {
                    acpi_processor_uid: data[offset + 2],
                    flags: read_u16(data, offset + 3),
                    lint: data[offset + 5],
                })
            }
            MADT_TYPE_LOCAL_APIC_ADDR_OVERRIDE if entry_len >= 12 => {
                MadtEntry::LocalApicAddrOverride(MadtLocalApicAddrOverride {
                    local_apic_address: read_u64(data, offset + 4),
                })
            }
            MADT_TYPE_LOCAL_X2APIC if entry_len >= 16 => {
                MadtEntry::LocalX2Apic(MadtLocalX2Apic {
                    // offset+2..3 reserved
                    x2apic_id: read_u32(data, offset + 4),
                    flags: read_u32(data, offset + 8),
                    acpi_processor_uid: read_u32(data, offset + 12),
                })
            }
            _ => MadtEntry::Unknown {
                entry_type,
                length: entry_len as u8,
            },
        };

        entries[count] = entry;
        count += 1;
        offset += entry_len;
    }

    Ok(Madt {
        local_apic_address,
        flags,
        entries,
        count,
    })
}

impl AcpiTable for Madt {
    fn signature() -> [u8; 4] {
        MADT_SIGNATURE
    }
    fn parse(data: &[u8]) -> Result<Self> {
        parse_madt(data)
    }
}

// ---------------------------------------------------------------------------
// SLIT (System Locality Information Table)
// ---------------------------------------------------------------------------

/// SLIT signature: `"SLIT"`.
pub const SLIT_SIGNATURE: [u8; 4] = *b"SLIT";

/// Maximum number of NUMA localities in the SLIT.
pub const SLIT_MAX_LOCALITIES: usize = 8;

/// Parsed SLIT — relative memory access latency matrix.
///
/// `matrix[i][j]` is the normalized latency from locality `i` to locality `j`.
/// A value of 10 means "native" (same locality). Higher values indicate
/// proportionally greater latency.
pub struct Slit {
    /// Number of system localities (rows/columns in the matrix).
    pub num_localities: usize,
    /// Latency matrix (row-major, `[from][to]`).
    pub matrix: [[u8; SLIT_MAX_LOCALITIES]; SLIT_MAX_LOCALITIES],
}

impl Slit {
    /// Returns the latency entry from locality `from` to locality `to`.
    ///
    /// Returns 255 (unreachable) if the indices are out of bounds.
    pub fn latency(&self, from: usize, to: usize) -> u8 {
        if from >= self.num_localities || to >= self.num_localities {
            return 255;
        }
        self.matrix[from][to]
    }

    /// Returns true if locality `from` can access locality `to`.
    ///
    /// A value of 255 means the localities are not reachable from each other.
    pub fn is_reachable(&self, from: usize, to: usize) -> bool {
        self.latency(from, to) != 255
    }
}

/// Parse a SLIT table from raw bytes.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if the signature, checksum, or
/// matrix dimensions are invalid.
pub fn parse_slit(data: &[u8]) -> Result<Slit> {
    validate_table_header(data, Some(&SLIT_SIGNATURE), 8)?;

    let num_localities_raw = read_u64(data, AcpiTableHeader::SIZE) as usize;
    if num_localities_raw == 0 || num_localities_raw > SLIT_MAX_LOCALITIES {
        return Err(Error::InvalidArgument);
    }

    let matrix_start = AcpiTableHeader::SIZE + 8;
    let matrix_size = num_localities_raw * num_localities_raw;
    if matrix_start + matrix_size > data.len() {
        return Err(Error::InvalidArgument);
    }

    let mut matrix = [[255u8; SLIT_MAX_LOCALITIES]; SLIT_MAX_LOCALITIES];
    for from in 0..num_localities_raw {
        for to in 0..num_localities_raw {
            let idx = matrix_start + from * num_localities_raw + to;
            matrix[from][to] = data[idx];
        }
    }

    Ok(Slit {
        num_localities: num_localities_raw,
        matrix,
    })
}

impl AcpiTable for Slit {
    fn signature() -> [u8; 4] {
        SLIT_SIGNATURE
    }
    fn parse(data: &[u8]) -> Result<Self> {
        parse_slit(data)
    }
}
