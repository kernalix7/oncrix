// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ACPI table parsing: RSDP, RSDT/XSDT, MADT, FADT.
//!
//! This module provides parsers for the core ACPI system description tables
//! used during early boot to enumerate hardware topology.
//!
//! # Tables
//!
//! | Table | Signature  | Purpose                                  |
//! |-------|------------|------------------------------------------|
//! | RSDP  | `"RSD PTR "` | Root pointer — locates RSDT/XSDT       |
//! | XSDT  | `"XSDT"`   | Extended (64-bit) System Description Table |
//! | RSDT  | `"RSDT"`   | Root System Description Table (32-bit)  |
//! | MADT  | `"APIC"`   | Multiple APIC Description Table          |
//! | FADT  | `"FACP"`   | Fixed ACPI Description Table             |
//!
//! All structures are `repr(C, packed)` because ACPI tables are not
//! guaranteed to be naturally aligned in firmware memory.
//!
//! Reference: ACPI Specification 6.5, §5.2.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------

/// RSDP signature bytes: `"RSD PTR "` (8 bytes, note trailing space).
pub const RSDP_SIGNATURE: [u8; 8] = *b"RSD PTR ";

/// XSDT table signature.
pub const XSDT_SIGNATURE: [u8; 4] = *b"XSDT";

/// RSDT table signature.
pub const RSDT_SIGNATURE: [u8; 4] = *b"RSDT";

/// MADT (APIC) table signature.
pub const MADT_SIGNATURE: [u8; 4] = *b"APIC";

/// FADT table signature.
pub const FADT_SIGNATURE: [u8; 4] = *b"FACP";

// ---------------------------------------------------------------------------
// Common ACPI table header
// ---------------------------------------------------------------------------

/// Standard ACPI System Description Table header (36 bytes).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct AcpiTableHeader {
    /// 4-byte ASCII signature.
    pub signature: [u8; 4],
    /// Total table length including this header.
    pub length: u32,
    /// Revision number.
    pub revision: u8,
    /// Checksum: sum of all bytes mod 256 must be 0.
    pub checksum: u8,
    /// OEM identifier (6 ASCII bytes).
    pub oem_id: [u8; 6],
    /// OEM table identifier (8 ASCII bytes).
    pub oem_table_id: [u8; 8],
    /// OEM revision.
    pub oem_revision: u32,
    /// Creator ID.
    pub creator_id: u32,
    /// Creator revision.
    pub creator_revision: u32,
}

/// Validate an ACPI table checksum.
///
/// Returns `Ok(())` if the checksum is valid, `Err(Error::InvalidArgument)` otherwise.
pub fn validate_checksum(data: &[u8]) -> Result<()> {
    let sum: u8 = data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    if sum != 0 {
        Err(Error::InvalidArgument)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RSDP
// ---------------------------------------------------------------------------

/// Root System Description Pointer (ACPI 2.0+, 36 bytes).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Rsdp {
    /// Signature `"RSD PTR "`.
    pub signature: [u8; 8],
    /// Checksum for the first 20 bytes.
    pub checksum: u8,
    /// OEM identifier.
    pub oem_id: [u8; 6],
    /// Revision: 0 = ACPI 1.0, 2 = ACPI 2.0+.
    pub revision: u8,
    /// Physical address of the RSDT (32-bit; ACPI 1.0).
    pub rsdt_address: u32,
    // ACPI 2.0+ extended fields:
    /// Total length of this structure.
    pub length: u32,
    /// Physical address of the XSDT (64-bit; ACPI 2.0+).
    pub xsdt_address: u64,
    /// Checksum for the extended fields.
    pub extended_checksum: u8,
    /// Reserved.
    pub reserved: [u8; 3],
}

/// Parsed RSDP information.
#[derive(Debug, Clone, Copy)]
pub struct RsdpInfo {
    /// ACPI revision (0 = 1.0, 2 = 2.0+).
    pub revision: u8,
    /// Physical address of the RSDT (may be 0 for ACPI 2.0+).
    pub rsdt_paddr: u32,
    /// Physical address of the XSDT (0 for ACPI 1.0).
    pub xsdt_paddr: u64,
}

/// Parse and validate the RSDP from a byte slice.
///
/// `data` must contain at least `size_of::<Rsdp>()` bytes.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if the data is too short, the
/// signature does not match, or the checksum is invalid.
pub fn parse_rsdp(data: &[u8]) -> Result<RsdpInfo> {
    if data.len() < core::mem::size_of::<Rsdp>() {
        return Err(Error::InvalidArgument);
    }
    // SAFETY: Length verified above; Rsdp is repr(C, packed) so unaligned
    // access is well-defined.
    let rsdp = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const Rsdp) };

    if rsdp.signature != RSDP_SIGNATURE {
        return Err(Error::InvalidArgument);
    }
    // Validate first 20-byte checksum (ACPI 1.0).
    validate_checksum(&data[..20])?;

    // ACPI 2.0+ extended checksum.
    if rsdp.revision >= 2 {
        if data.len() < 36 {
            return Err(Error::InvalidArgument);
        }
        validate_checksum(&data[..36])?;
    }

    Ok(RsdpInfo {
        revision: rsdp.revision,
        rsdt_paddr: rsdp.rsdt_address,
        xsdt_paddr: if rsdp.revision >= 2 {
            rsdp.xsdt_address
        } else {
            0
        },
    })
}

// ---------------------------------------------------------------------------
// XSDT
// ---------------------------------------------------------------------------

/// Parsed XSDT — contains 64-bit pointers to other ACPI tables.
#[derive(Debug, Clone)]
pub struct XsdtInfo {
    /// Number of table pointers in the XSDT.
    pub entry_count: usize,
    /// Physical addresses of all tables pointed to by the XSDT (up to 32).
    pub entries: [u64; 32],
}

/// Parse an XSDT from its in-memory bytes.
///
/// `data` must be the complete XSDT including its header.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] on signature mismatch or checksum error.
pub fn parse_xsdt(data: &[u8]) -> Result<XsdtInfo> {
    let hdr_size = core::mem::size_of::<AcpiTableHeader>();
    if data.len() < hdr_size {
        return Err(Error::InvalidArgument);
    }
    // SAFETY: Length verified; repr(C, packed), unaligned read is fine.
    let hdr = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const AcpiTableHeader) };
    if hdr.signature != XSDT_SIGNATURE {
        return Err(Error::InvalidArgument);
    }
    let table_len = hdr.length as usize;
    if data.len() < table_len {
        return Err(Error::InvalidArgument);
    }
    validate_checksum(&data[..table_len])?;

    let body = &data[hdr_size..table_len];
    let raw_count = body.len() / 8;
    let entry_count = raw_count.min(32);
    let mut entries = [0u64; 32];
    for (i, chunk) in body.chunks_exact(8).take(entry_count).enumerate() {
        entries[i] = u64::from_le_bytes(chunk.try_into().unwrap_or([0u8; 8]));
    }
    Ok(XsdtInfo {
        entry_count,
        entries,
    })
}

// ---------------------------------------------------------------------------
// MADT
// ---------------------------------------------------------------------------

/// MADT header fields (beyond the common SDT header).
#[derive(Debug, Clone, Copy)]
pub struct MadtHeader {
    /// Physical address of the Local APIC.
    pub lapic_address: u32,
    /// Flags bit 0: PC-AT-compatible dual 8259 PICs present.
    pub flags: u32,
    /// Whether legacy 8259 PICs are present.
    pub has_8259: bool,
}

/// MADT interrupt controller structure types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MadtEntryType {
    /// Processor Local APIC.
    LocalApic = 0,
    /// I/O APIC.
    IoApic = 1,
    /// Interrupt Source Override.
    IntSrcOverride = 2,
    /// NMI Source.
    NmiSource = 3,
    /// Local APIC NMI.
    LocalApicNmi = 4,
    /// Local APIC Address Override.
    LocalApicAddrOverride = 5,
    /// Processor Local x2APIC.
    LocalX2Apic = 9,
    /// Unknown.
    Unknown = 0xFF,
}

/// A parsed Local APIC entry from the MADT.
#[derive(Debug, Clone, Copy)]
pub struct MadtLocalApic {
    /// ACPI processor UID.
    pub acpi_uid: u8,
    /// APIC ID.
    pub apic_id: u8,
    /// Flags bit 0: processor is usable.
    pub enabled: bool,
    /// Flags bit 1: online-capable (can be brought online).
    pub online_capable: bool,
}

/// A parsed I/O APIC entry from the MADT.
#[derive(Debug, Clone, Copy)]
pub struct MadtIoApic {
    /// I/O APIC ID.
    pub id: u8,
    /// Physical base address.
    pub address: u32,
    /// Global system interrupt base.
    pub gsi_base: u32,
}

/// A parsed Interrupt Source Override from the MADT.
#[derive(Debug, Clone, Copy)]
pub struct MadtIntSrcOverride {
    /// Bus source (0 = ISA).
    pub bus: u8,
    /// IRQ source on that bus.
    pub source: u8,
    /// Global system interrupt this maps to.
    pub global_sys_int: u32,
    /// Polarity flags (bits 1:0).
    pub polarity: u8,
    /// Trigger mode flags (bits 3:2).
    pub trigger_mode: u8,
}

/// Maximum entries we collect from the MADT.
const MAX_LAPICS: usize = 256;
const MAX_IOAPICS: usize = 8;
const MAX_OVERRIDES: usize = 16;

/// Parsed MADT.
#[derive(Debug)]
pub struct MadtInfo {
    /// MADT header fields.
    pub header: MadtHeader,
    /// Local APIC entries.
    pub local_apics: [MadtLocalApic; MAX_LAPICS],
    /// Number of valid `local_apics`.
    pub local_apic_count: usize,
    /// I/O APIC entries.
    pub io_apics: [MadtIoApic; MAX_IOAPICS],
    /// Number of valid `io_apics`.
    pub io_apic_count: usize,
    /// Interrupt source overrides.
    pub overrides: [MadtIntSrcOverride; MAX_OVERRIDES],
    /// Number of valid `overrides`.
    pub override_count: usize,
}

/// Parse a MADT from its in-memory bytes.
///
/// `data` must be the complete MADT including the common SDT header.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] on bad signature, short data, or bad checksum.
pub fn parse_madt(data: &[u8]) -> Result<MadtInfo> {
    let sdt_hdr_size = core::mem::size_of::<AcpiTableHeader>();
    if data.len() < sdt_hdr_size + 8 {
        return Err(Error::InvalidArgument);
    }
    // SAFETY: Size verified; packed struct, unaligned read OK.
    let hdr = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const AcpiTableHeader) };
    if hdr.signature != MADT_SIGNATURE {
        return Err(Error::InvalidArgument);
    }
    let table_len = hdr.length as usize;
    if data.len() < table_len {
        return Err(Error::InvalidArgument);
    }
    validate_checksum(&data[..table_len])?;

    // MADT-specific header fields follow the common header.
    let lapic_addr = u32::from_le_bytes([
        data[sdt_hdr_size],
        data[sdt_hdr_size + 1],
        data[sdt_hdr_size + 2],
        data[sdt_hdr_size + 3],
    ]);
    let flags = u32::from_le_bytes([
        data[sdt_hdr_size + 4],
        data[sdt_hdr_size + 5],
        data[sdt_hdr_size + 6],
        data[sdt_hdr_size + 7],
    ]);

    let madt_hdr = MadtHeader {
        lapic_address: lapic_addr,
        flags,
        has_8259: flags & 1 != 0,
    };

    const ZERO_LAPIC: MadtLocalApic = MadtLocalApic {
        acpi_uid: 0,
        apic_id: 0,
        enabled: false,
        online_capable: false,
    };
    const ZERO_IOAPIC: MadtIoApic = MadtIoApic {
        id: 0,
        address: 0,
        gsi_base: 0,
    };
    const ZERO_OVERRIDE: MadtIntSrcOverride = MadtIntSrcOverride {
        bus: 0,
        source: 0,
        global_sys_int: 0,
        polarity: 0,
        trigger_mode: 0,
    };

    let mut info = MadtInfo {
        header: madt_hdr,
        local_apics: [ZERO_LAPIC; MAX_LAPICS],
        local_apic_count: 0,
        io_apics: [ZERO_IOAPIC; MAX_IOAPICS],
        io_apic_count: 0,
        overrides: [ZERO_OVERRIDE; MAX_OVERRIDES],
        override_count: 0,
    };

    let mut offset = sdt_hdr_size + 8;
    while offset + 2 <= table_len {
        let entry_type = data[offset];
        let entry_len = data[offset + 1] as usize;
        if entry_len < 2 || offset + entry_len > table_len {
            break;
        }
        let entry = &data[offset..offset + entry_len];
        match entry_type {
            0 if entry_len >= 8 => {
                if info.local_apic_count < MAX_LAPICS {
                    let f = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
                    info.local_apics[info.local_apic_count] = MadtLocalApic {
                        acpi_uid: entry[2],
                        apic_id: entry[3],
                        enabled: f & 1 != 0,
                        online_capable: f & 2 != 0,
                    };
                    info.local_apic_count += 1;
                }
            }
            1 if entry_len >= 12 => {
                if info.io_apic_count < MAX_IOAPICS {
                    let addr = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
                    let gsi = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
                    info.io_apics[info.io_apic_count] = MadtIoApic {
                        id: entry[2],
                        address: addr,
                        gsi_base: gsi,
                    };
                    info.io_apic_count += 1;
                }
            }
            2 if entry_len >= 10 => {
                if info.override_count < MAX_OVERRIDES {
                    let gsi = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
                    let intf = u16::from_le_bytes([entry[8], entry[9]]);
                    info.overrides[info.override_count] = MadtIntSrcOverride {
                        bus: entry[2],
                        source: entry[3],
                        global_sys_int: gsi,
                        polarity: (intf & 0x3) as u8,
                        trigger_mode: ((intf >> 2) & 0x3) as u8,
                    };
                    info.override_count += 1;
                }
            }
            _ => {}
        }
        offset += entry_len;
    }
    Ok(info)
}

// ---------------------------------------------------------------------------
// FADT (minimal)
// ---------------------------------------------------------------------------

/// Minimal parsed FADT fields needed by the HAL.
#[derive(Debug, Clone, Copy, Default)]
pub struct FadtInfo {
    /// Physical address of the FACS.
    pub facs_address: u32,
    /// Physical address of the DSDT.
    pub dsdt_address: u32,
    /// SMI command port.
    pub smi_cmd: u16,
    /// ACPI enable value to write to SMI_CMD.
    pub acpi_enable: u8,
    /// ACPI disable value.
    pub acpi_disable: u8,
    /// PM1a event block address.
    pub pm1a_evt_blk: u32,
    /// PM1b event block address.
    pub pm1b_evt_blk: u32,
    /// PM1a control block address.
    pub pm1a_ctrl_blk: u32,
}

/// Parse a FADT from its in-memory bytes (minimal fields only).
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] on bad signature, short data, or checksum error.
pub fn parse_fadt(data: &[u8]) -> Result<FadtInfo> {
    let sdt_hdr_size = core::mem::size_of::<AcpiTableHeader>();
    if data.len() < sdt_hdr_size + 72 {
        return Err(Error::InvalidArgument);
    }
    // SAFETY: Size verified above.
    let hdr = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const AcpiTableHeader) };
    if hdr.signature != FADT_SIGNATURE {
        return Err(Error::InvalidArgument);
    }
    let table_len = hdr.length as usize;
    if data.len() < table_len {
        return Err(Error::InvalidArgument);
    }
    validate_checksum(&data[..table_len])?;

    let d = &data[sdt_hdr_size..];
    let facs = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
    let dsdt = u32::from_le_bytes([d[4], d[5], d[6], d[7]]);
    let smi_cmd = u16::from_le_bytes([d[16], d[17]]);
    let acpi_enable = d[18];
    let acpi_disable = d[19];
    let pm1a_evt = u32::from_le_bytes([d[32], d[33], d[34], d[35]]);
    let pm1b_evt = u32::from_le_bytes([d[36], d[37], d[38], d[39]]);
    let pm1a_ctrl = u32::from_le_bytes([d[40], d[41], d[42], d[43]]);

    Ok(FadtInfo {
        facs_address: facs,
        dsdt_address: dsdt,
        smi_cmd,
        acpi_enable,
        acpi_disable,
        pm1a_evt_blk: pm1a_evt,
        pm1b_evt_blk: pm1b_evt,
        pm1a_ctrl_blk: pm1a_ctrl,
    })
}
