// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ACPI table parsing (RSDP, XSDT, MADT).
//!
//! The Advanced Configuration and Power Interface tables provide
//! hardware description data. The kernel reads these tables during
//! early boot to discover the Local APIC, I/O APIC addresses, and
//! the number of CPUs.
//!
//! This module only *parses* the tables from memory. It does not
//! perform any hardware configuration itself.

use oncrix_lib::{Error, Result};

/// RSDP signature: `"RSD PTR "` (8 bytes).
const RSDP_SIGNATURE: [u8; 8] = *b"RSD PTR ";

/// XSDT signature: `"XSDT"`.
const XSDT_SIGNATURE: [u8; 4] = *b"XSDT";

/// MADT (APIC) signature: `"APIC"`.
const MADT_SIGNATURE: [u8; 4] = *b"APIC";

// ── RSDP ───────────────────────────────────────────────────────

/// Root System Description Pointer (ACPI 2.0+).
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Rsdp {
    /// `"RSD PTR "`.
    pub signature: [u8; 8],
    /// Checksum for the first 20 bytes.
    pub checksum: u8,
    /// OEM identifier.
    pub oem_id: [u8; 6],
    /// Revision (0 = ACPI 1.0, 2 = ACPI 2.0+).
    pub revision: u8,
    /// Physical address of the RSDT (32-bit, ACPI 1.0).
    pub rsdt_address: u32,
    // ACPI 2.0+ extended fields:
    /// Length of the entire RSDP structure.
    pub length: u32,
    /// Physical address of the XSDT (64-bit).
    pub xsdt_address: u64,
    /// Extended checksum (entire structure).
    pub extended_checksum: u8,
    /// Reserved bytes.
    pub reserved: [u8; 3],
}

/// Validate and parse an RSDP from memory.
///
/// `data` must point to at least 36 bytes.
pub fn parse_rsdp(data: &[u8]) -> Result<RsdpInfo> {
    if data.len() < core::mem::size_of::<Rsdp>() {
        return Err(Error::InvalidArgument);
    }

    // SAFETY: Size verified above (data.len() >= size_of::<Rsdp>()).
    // Rsdp is repr(C, packed), so read_unaligned handles alignment.
    let rsdp = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const Rsdp) };

    // Validate signature.
    if rsdp.signature != RSDP_SIGNATURE {
        return Err(Error::InvalidArgument);
    }

    // Validate checksum (first 20 bytes for ACPI 1.0).
    let sum: u8 = data[..20].iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    if sum != 0 {
        return Err(Error::InvalidArgument);
    }

    // ACPI 2.0+ has extended checksum over full structure.
    if rsdp.revision >= 2 {
        let full_sum: u8 = data[..36].iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        if full_sum != 0 {
            return Err(Error::InvalidArgument);
        }
    }

    Ok(RsdpInfo {
        revision: rsdp.revision,
        rsdt_address: rsdp.rsdt_address as u64,
        xsdt_address: if rsdp.revision >= 2 {
            rsdp.xsdt_address
        } else {
            0
        },
    })
}

/// Parsed RSDP information.
#[derive(Debug, Clone, Copy)]
pub struct RsdpInfo {
    /// ACPI revision (0 = 1.0, 2 = 2.0+).
    pub revision: u8,
    /// Physical address of the RSDT.
    pub rsdt_address: u64,
    /// Physical address of the XSDT (0 if ACPI 1.0).
    pub xsdt_address: u64,
}

// ── SDT Header ─────────────────────────────────────────────────

/// Common ACPI System Description Table header.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct SdtHeader {
    /// 4-byte signature (e.g., `"XSDT"`, `"APIC"`).
    pub signature: [u8; 4],
    /// Total table length including header.
    pub length: u32,
    /// Revision.
    pub revision: u8,
    /// Checksum (all bytes in the table sum to 0).
    pub checksum: u8,
    /// OEM ID.
    pub oem_id: [u8; 6],
    /// OEM table ID.
    pub oem_table_id: [u8; 8],
    /// OEM revision.
    pub oem_revision: u32,
    /// Creator ID.
    pub creator_id: u32,
    /// Creator revision.
    pub creator_revision: u32,
}

/// Size of the SDT header.
pub const SDT_HEADER_SIZE: usize = core::mem::size_of::<SdtHeader>();

/// Validate an SDT header checksum.
pub fn validate_sdt_checksum(data: &[u8], length: usize) -> bool {
    if data.len() < length {
        return false;
    }
    data[..length]
        .iter()
        .fold(0u8, |acc, &b| acc.wrapping_add(b))
        == 0
}

// ── XSDT ───────────────────────────────────────────────────────

/// Maximum number of XSDT entries we can parse.
const MAX_XSDT_ENTRIES: usize = 32;

/// Parse the XSDT and extract table physical addresses.
///
/// Returns an array of physical addresses of other ACPI tables.
pub fn parse_xsdt(data: &[u8]) -> Result<([u64; MAX_XSDT_ENTRIES], usize)> {
    if data.len() < SDT_HEADER_SIZE {
        return Err(Error::InvalidArgument);
    }

    // SAFETY: data.len() >= SDT_HEADER_SIZE verified above.
    // SdtHeader is repr(C, packed), so read_unaligned handles alignment.
    let header = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const SdtHeader) };

    if header.signature != XSDT_SIGNATURE {
        return Err(Error::InvalidArgument);
    }

    let length = header.length as usize;
    if !validate_sdt_checksum(data, length) {
        return Err(Error::InvalidArgument);
    }

    // Entries start after the header; each is a 64-bit physical address.
    let entries_start = SDT_HEADER_SIZE;
    let entries_bytes = length.saturating_sub(entries_start);
    let entry_count = entries_bytes / 8;

    let mut addrs = [0u64; MAX_XSDT_ENTRIES];
    let count = entry_count.min(MAX_XSDT_ENTRIES);

    for (i, addr) in addrs.iter_mut().enumerate().take(count) {
        let offset = entries_start + i * 8;
        if offset + 8 <= data.len() {
            // SAFETY: Bounds checked.
            *addr = unsafe { core::ptr::read_unaligned(data.as_ptr().add(offset) as *const u64) };
        }
    }

    Ok((addrs, count))
}

// ── MADT ───────────────────────────────────────────────────────

/// MADT entry types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MadtEntryType {
    /// Processor Local APIC.
    LocalApic = 0,
    /// I/O APIC.
    IoApic = 1,
    /// Interrupt Source Override.
    InterruptOverride = 2,
    /// Non-Maskable Interrupt source.
    Nmi = 3,
    /// Local APIC NMI.
    LocalApicNmi = 4,
}

/// Processor Local APIC entry from the MADT.
#[derive(Debug, Clone, Copy)]
pub struct MadtLocalApic {
    /// ACPI processor ID.
    pub acpi_id: u8,
    /// Local APIC ID.
    pub apic_id: u8,
    /// Flags (bit 0: enabled, bit 1: online capable).
    pub flags: u32,
}

/// I/O APIC entry from the MADT.
#[derive(Debug, Clone, Copy)]
pub struct MadtIoApic {
    /// I/O APIC ID.
    pub id: u8,
    /// Physical base address of the I/O APIC.
    pub address: u32,
    /// Global system interrupt base.
    pub gsi_base: u32,
}

/// Interrupt Source Override entry from the MADT.
#[derive(Debug, Clone, Copy)]
pub struct MadtOverride {
    /// Bus source (always 0 = ISA).
    pub bus: u8,
    /// IRQ source.
    pub irq_source: u8,
    /// Global system interrupt.
    pub gsi: u32,
    /// Flags (polarity, trigger mode).
    pub flags: u16,
}

/// Maximum number of CPUs we support.
const MAX_CPUS: usize = 64;
/// Maximum number of I/O APICs.
const MAX_IO_APICS: usize = 8;
/// Maximum interrupt source overrides.
const MAX_OVERRIDES: usize = 16;

/// Parsed MADT information.
#[derive(Debug)]
pub struct MadtInfo {
    /// Local APIC base address.
    pub local_apic_address: u32,
    /// Processor Local APIC entries.
    pub local_apics: [MadtLocalApic; MAX_CPUS],
    /// Number of Local APIC entries.
    pub local_apic_count: usize,
    /// I/O APIC entries.
    pub io_apics: [MadtIoApic; MAX_IO_APICS],
    /// Number of I/O APIC entries.
    pub io_apic_count: usize,
    /// Interrupt source overrides.
    pub overrides: [MadtOverride; MAX_OVERRIDES],
    /// Number of override entries.
    pub override_count: usize,
}

impl MadtInfo {
    /// Create an empty MADT info.
    const fn empty() -> Self {
        Self {
            local_apic_address: 0,
            local_apics: [MadtLocalApic {
                acpi_id: 0,
                apic_id: 0,
                flags: 0,
            }; MAX_CPUS],
            local_apic_count: 0,
            io_apics: [MadtIoApic {
                id: 0,
                address: 0,
                gsi_base: 0,
            }; MAX_IO_APICS],
            io_apic_count: 0,
            overrides: [MadtOverride {
                bus: 0,
                irq_source: 0,
                gsi: 0,
                flags: 0,
            }; MAX_OVERRIDES],
            override_count: 0,
        }
    }

    /// Return the number of enabled CPUs.
    pub fn enabled_cpu_count(&self) -> usize {
        self.local_apics[..self.local_apic_count]
            .iter()
            .filter(|a| a.flags & 1 != 0)
            .count()
    }
}

/// Parse the MADT (Multiple APIC Description Table).
///
/// Extracts Local APIC, I/O APIC, and interrupt source override
/// entries from the table data.
pub fn parse_madt(data: &[u8]) -> Result<MadtInfo> {
    if data.len() < SDT_HEADER_SIZE + 8 {
        return Err(Error::InvalidArgument);
    }

    // SAFETY: data.len() >= SDT_HEADER_SIZE + 8 verified above.
    // SdtHeader is repr(C, packed), so read_unaligned handles alignment.
    let header = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const SdtHeader) };

    if header.signature != MADT_SIGNATURE {
        return Err(Error::InvalidArgument);
    }

    let length = header.length as usize;
    if !validate_sdt_checksum(data, length) {
        return Err(Error::InvalidArgument);
    }

    let mut info = MadtInfo::empty();

    // Local APIC address is at offset 36 (right after SDT header).
    if data.len() >= SDT_HEADER_SIZE + 4 {
        // SAFETY: Bounds verified: data.len() >= SDT_HEADER_SIZE + 4.
        info.local_apic_address =
            unsafe { core::ptr::read_unaligned(data.as_ptr().add(SDT_HEADER_SIZE) as *const u32) };
    }

    // Entries start at offset 44 (SDT header + 4 byte LAPIC addr + 4 byte flags).
    let entries_start = SDT_HEADER_SIZE + 8;
    let mut offset = entries_start;

    // Use the minimum of header.length and data.len() to prevent OOB
    // reads when the ACPI table is truncated or the buffer is smaller
    // than the header claims.
    let bound = length.min(data.len());

    while offset + 2 <= bound {
        let entry_type = data[offset];
        let entry_len = data[offset + 1] as usize;

        if entry_len < 2 || offset + entry_len > bound {
            break;
        }

        match entry_type {
            0 if entry_len >= 8 && info.local_apic_count < MAX_CPUS => {
                // SAFETY: Bounds checked: offset + 8 <= offset + entry_len <= bound <= data.len().
                info.local_apics[info.local_apic_count] = MadtLocalApic {
                    acpi_id: data[offset + 2],
                    apic_id: data[offset + 3],
                    flags: unsafe {
                        core::ptr::read_unaligned(data.as_ptr().add(offset + 4) as *const u32)
                    },
                };
                info.local_apic_count += 1;
            }
            1 if entry_len >= 12 && info.io_apic_count < MAX_IO_APICS => {
                // SAFETY: Bounds checked: offset + 12 <= offset + entry_len <= bound <= data.len().
                info.io_apics[info.io_apic_count] = MadtIoApic {
                    id: data[offset + 2],
                    address: unsafe {
                        core::ptr::read_unaligned(data.as_ptr().add(offset + 4) as *const u32)
                    },
                    gsi_base: unsafe {
                        core::ptr::read_unaligned(data.as_ptr().add(offset + 8) as *const u32)
                    },
                };
                info.io_apic_count += 1;
            }
            2 if entry_len >= 10 && info.override_count < MAX_OVERRIDES => {
                // SAFETY: Bounds checked: offset + 10 <= offset + entry_len <= bound <= data.len().
                info.overrides[info.override_count] = MadtOverride {
                    bus: data[offset + 2],
                    irq_source: data[offset + 3],
                    gsi: unsafe {
                        core::ptr::read_unaligned(data.as_ptr().add(offset + 4) as *const u32)
                    },
                    flags: unsafe {
                        core::ptr::read_unaligned(data.as_ptr().add(offset + 8) as *const u16)
                    },
                };
                info.override_count += 1;
            }
            _ => {} // Skip unknown entry types.
        }

        offset += entry_len;
    }

    Ok(info)
}

/// Search for the RSDP in standard BIOS memory regions.
///
/// Scans the EBDA (Extended BIOS Data Area) and the main BIOS
/// ROM region (0xE0000-0xFFFFF) for the RSDP signature.
///
/// Returns the physical address of the RSDP if found.
///
/// # Safety
///
/// The caller must ensure the memory regions are identity-mapped
/// and accessible.
pub unsafe fn find_rsdp() -> Option<u64> {
    // SAFETY: Scanning well-known BIOS memory regions in Ring 0.
    unsafe {
        // Search main BIOS area: 0xE0000 - 0xFFFFF (on 16-byte boundaries).
        let mut addr = 0xE0000u64;
        while addr < 0x100000 {
            let ptr = addr as *const [u8; 8];
            if *ptr == RSDP_SIGNATURE {
                return Some(addr);
            }
            addr += 16;
        }
    }

    None
}
