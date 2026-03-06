// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PCI capability structure parser.
//!
//! Walks the PCI configuration-space capability list and parses the
//! structures for the most commonly used standard capabilities and
//! extended capabilities (PCIe).
//!
//! # Standard Capabilities (Type 0/1, offset < 256)
//!
//! Each entry in the singly-linked list starts with:
//! - `[0]` Capability ID (1 byte)
//! - `[1]` Next capability pointer (1 byte, 0 = end of list)
//!
//! # Extended Capabilities (PCIe, offset ≥ 0x100)
//!
//! Extended capability headers are 4 bytes:
//! - `[1:0]` Capability ID (16-bit)
//! - `[3:2]` Next capability pointer (12-bit) and version (4-bit)
//!
//! # Capability IDs parsed
//!
//! | ID   | Name                            |
//! |------|---------------------------------|
//! | 0x01 | Power Management (PCI PM)       |
//! | 0x02 | AGP (obsolete, recognized)      |
//! | 0x04 | Slot Identification             |
//! | 0x05 | MSI                             |
//! | 0x09 | Vendor Specific                 |
//! | 0x0D | PCI Hot-plug                    |
//! | 0x10 | PCI Express                     |
//! | 0x11 | MSI-X                           |
//! | 0x12 | SATA HBA                        |
//! | 0x13 | AF (Advanced Features)          |
//!
//! # Extended Capability IDs parsed
//!
//! | ID     | Name                          |
//! |--------|-------------------------------|
//! | 0x0001 | Advanced Error Reporting (AER)|
//! | 0x0002 | Virtual Channel               |
//! | 0x000B | Vendor Specific Extended      |
//! | 0x000D | Access Control Services (ACS) |
//! | 0x0010 | SR-IOV                        |
//! | 0x0018 | Latency Tolerance Reporting   |
//! | 0x001E | L1 PM Substates               |
//!
//! Reference: PCI Local Bus Specification 3.0 §6.7;
//!            PCI Express Base Specification 5.0 §7.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Standard capability IDs
// ---------------------------------------------------------------------------

/// Capability ID: Power Management Interface.
pub const CAP_ID_PM: u8 = 0x01;

/// Capability ID: AGP.
pub const CAP_ID_AGP: u8 = 0x02;

/// Capability ID: Vital Product Data.
pub const CAP_ID_VPD: u8 = 0x03;

/// Capability ID: Slot Identification.
pub const CAP_ID_SLOTID: u8 = 0x04;

/// Capability ID: MSI.
pub const CAP_ID_MSI: u8 = 0x05;

/// Capability ID: CompactPCI Hot Swap.
pub const CAP_ID_CHSWP: u8 = 0x06;

/// Capability ID: PCI-X.
pub const CAP_ID_PCIX: u8 = 0x07;

/// Capability ID: HyperTransport.
pub const CAP_ID_HT: u8 = 0x08;

/// Capability ID: Vendor Specific.
pub const CAP_ID_VNDR: u8 = 0x09;

/// Capability ID: Debug Port.
pub const CAP_ID_DBG: u8 = 0x0A;

/// Capability ID: CompactPCI Resource Control.
pub const CAP_ID_CCRC: u8 = 0x0B;

/// Capability ID: Hot-Plug.
pub const CAP_ID_SHPC: u8 = 0x0C;

/// Capability ID: Subsystem Vendor/Device ID.
pub const CAP_ID_SSVID: u8 = 0x0D;

/// Capability ID: AGP 8×.
pub const CAP_ID_AGP3: u8 = 0x0E;

/// Capability ID: PCI Bridge Subsystem.
pub const CAP_ID_PBSV: u8 = 0x0F;

/// Capability ID: PCI Express.
pub const CAP_ID_PCIE: u8 = 0x10;

/// Capability ID: MSI-X.
pub const CAP_ID_MSIX: u8 = 0x11;

/// Capability ID: Serial ATA.
pub const CAP_ID_SATA: u8 = 0x12;

/// Capability ID: Advanced Features.
pub const CAP_ID_AF: u8 = 0x13;

/// Capability ID: Enhanced Allocation.
pub const CAP_ID_EA: u8 = 0x14;

// ---------------------------------------------------------------------------
// PCIe Extended capability IDs
// ---------------------------------------------------------------------------

/// Extended capability ID: Advanced Error Reporting.
pub const ECAP_ID_AER: u16 = 0x0001;

/// Extended capability ID: Virtual Channel.
pub const ECAP_ID_VC: u16 = 0x0002;

/// Extended capability ID: Device Serial Number.
pub const ECAP_ID_DSN: u16 = 0x0003;

/// Extended capability ID: Power Budgeting.
pub const ECAP_ID_PB: u16 = 0x0004;

/// Extended capability ID: Root Complex Link Declaration.
pub const ECAP_ID_RCLD: u16 = 0x0005;

/// Extended capability ID: Root Complex Internal Link Control.
pub const ECAP_ID_RILC: u16 = 0x0006;

/// Extended capability ID: Root Complex Event Collector.
pub const ECAP_ID_RCEC: u16 = 0x0007;

/// Extended capability ID: Multi-Function Virtual Channel.
pub const ECAP_ID_MFVC: u16 = 0x0008;

/// Extended capability ID: Vendor Specific Extended.
pub const ECAP_ID_VSEC: u16 = 0x000B;

/// Extended capability ID: Configuration Access Correlation.
pub const ECAP_ID_CAC: u16 = 0x000C;

/// Extended capability ID: Access Control Services.
pub const ECAP_ID_ACS: u16 = 0x000D;

/// Extended capability ID: Alternative Routing-ID Interpretation.
pub const ECAP_ID_ARI: u16 = 0x000E;

/// Extended capability ID: Address Translation Services.
pub const ECAP_ID_ATS: u16 = 0x000F;

/// Extended capability ID: SR-IOV.
pub const ECAP_ID_SRIOV: u16 = 0x0010;

/// Extended capability ID: Multicast.
pub const ECAP_ID_MCAST: u16 = 0x0012;

/// Extended capability ID: Page Request Interface.
pub const ECAP_ID_PRI: u16 = 0x0013;

/// Extended capability ID: Resizable BAR.
pub const ECAP_ID_RBAR: u16 = 0x0015;

/// Extended capability ID: Downstream Port Containment.
pub const ECAP_ID_DPC: u16 = 0x001D;

/// Extended capability ID: L1 PM Substates.
pub const ECAP_ID_L1PM: u16 = 0x001E;

/// Extended capability ID: Precision Time Measurement.
pub const ECAP_ID_PTM: u16 = 0x001F;

/// Extended capability ID: M-PCIe.
pub const ECAP_ID_MPCIE: u16 = 0x0023;

/// Extended capability ID: FRS Queuing.
pub const ECAP_ID_FRS: u16 = 0x0024;

// ---------------------------------------------------------------------------
// Capability location
// ---------------------------------------------------------------------------

/// Location of a standard PCI capability within config space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapLocation {
    /// Byte offset in PCI config space (must be ≥ 0x40).
    pub offset: u8,
    /// Capability ID.
    pub cap_id: u8,
}

/// Location of a PCIe extended capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtCapLocation {
    /// Byte offset in PCIe config space (≥ 0x100).
    pub offset: u16,
    /// Extended capability ID (16-bit).
    pub cap_id: u16,
    /// Capability version (4-bit).
    pub version: u8,
}

// ---------------------------------------------------------------------------
// Parsed capability structures
// ---------------------------------------------------------------------------

/// Parsed PCI Power Management capability.
#[derive(Debug, Clone, Copy, Default)]
pub struct PmCap {
    /// Capability offset.
    pub offset: u8,
    /// PMC: Power Management Capabilities register.
    pub pmc: u16,
    /// PMCSR: Power Management Control/Status register.
    pub pmcsr: u16,
}

impl PmCap {
    /// D-state extracted from PMCSR bits[1:0].
    pub fn d_state(&self) -> u8 {
        (self.pmcsr & 0x03) as u8
    }

    /// Whether the device supports PME from D3cold.
    pub fn supports_pme_d3cold(&self) -> bool {
        self.pmc & (1 << 15) != 0
    }

    /// Whether PME is currently asserted.
    pub fn pme_asserted(&self) -> bool {
        self.pmcsr & (1 << 15) != 0
    }

    /// Maximum power state supported (0=D0..3=D3hot).
    pub fn max_d_state(&self) -> u8 {
        // D3cold support is in PMC bit 9; D1/D2 in bits 9:10 (after D0/D1/D2 in PMC[11:9]).
        let mut max = 0u8;
        if self.pmc & (1 << 9) != 0 {
            max = max.max(1);
        }
        if self.pmc & (1 << 10) != 0 {
            max = max.max(2);
        }
        max.max(3) // D3hot always supported per spec
    }
}

/// PCIe device type from the PCIE capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PcieDeviceType {
    /// PCIe Endpoint.
    Endpoint = 0,
    /// Legacy PCIe Endpoint.
    LegacyEndpoint = 1,
    /// Root Port of a PCIe Root Complex.
    RootPort = 4,
    /// Upstream Port of a Switch.
    UpstreamPort = 5,
    /// Downstream Port of a Switch.
    DownstreamPort = 6,
    /// PCIe-to-PCI/X Bridge.
    PcieToPciBridge = 7,
    /// PCI/X-to-PCIe Bridge.
    PciToPcieBridge = 8,
    /// Root Complex Integrated Endpoint.
    RcIntegratedEndpoint = 9,
    /// Root Complex Event Collector.
    RcEventCollector = 10,
    /// Unknown type.
    Unknown = 0xFF,
}

impl PcieDeviceType {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Endpoint,
            1 => Self::LegacyEndpoint,
            4 => Self::RootPort,
            5 => Self::UpstreamPort,
            6 => Self::DownstreamPort,
            7 => Self::PcieToPciBridge,
            8 => Self::PciToPcieBridge,
            9 => Self::RcIntegratedEndpoint,
            10 => Self::RcEventCollector,
            _ => Self::Unknown,
        }
    }
}

/// Parsed PCIe capability.
#[derive(Debug, Clone, Copy, Default)]
pub struct PcieCap {
    /// Capability offset.
    pub offset: u8,
    /// PCIe Capability register (version, device type, slot).
    pub pcie_cap_reg: u16,
    /// Device Capabilities register.
    pub dev_cap: u32,
    /// Device Control register.
    pub dev_ctrl: u16,
    /// Device Status register.
    pub dev_status: u16,
    /// Link Capabilities register.
    pub link_cap: u32,
    /// Link Control register.
    pub link_ctrl: u16,
    /// Link Status register.
    pub link_status: u16,
    /// Device Capabilities 2 register.
    pub dev_cap2: u32,
    /// Link Capabilities 2 register.
    pub link_cap2: u32,
}

impl PcieCap {
    /// PCIe capability version (1 or 2).
    pub fn version(&self) -> u8 {
        (self.pcie_cap_reg & 0x0F) as u8
    }

    /// Device type from the PCIe capability register.
    pub fn device_type(&self) -> PcieDeviceType {
        PcieDeviceType::from_u8(((self.pcie_cap_reg >> 4) & 0x0F) as u8)
    }

    /// Whether the device has a slot (for RP/switch ports).
    pub fn has_slot(&self) -> bool {
        self.pcie_cap_reg & (1 << 8) != 0
    }

    /// Maximum payload size supported (log2 in bytes, e.g. 0=128B, 1=256B).
    pub fn max_payload_size_supported(&self) -> u8 {
        (self.dev_cap & 0x07) as u8
    }

    /// Current negotiated link speed (1=2.5GT/s, 2=5GT/s, 3=8GT/s, 4=16GT/s, 5=32GT/s).
    pub fn current_link_speed(&self) -> u8 {
        (self.link_status & 0x0F) as u8
    }

    /// Negotiated link width (×1, ×2, ×4, ×8, ×16, ×32).
    pub fn negotiated_link_width(&self) -> u8 {
        ((self.link_status >> 4) & 0x3F) as u8
    }

    /// Whether the link is active.
    pub fn link_active(&self) -> bool {
        self.link_status & (1 << 13) != 0
    }
}

/// Parsed vendor-specific capability.
#[derive(Debug, Clone, Copy, Default)]
pub struct VendorSpecCap {
    /// Capability offset.
    pub offset: u8,
    /// Vendor-specific length byte.
    pub length: u8,
}

/// Parsed AER (Advanced Error Reporting) extended capability.
#[derive(Debug, Clone, Copy, Default)]
pub struct AerCap {
    /// Extended capability offset.
    pub offset: u16,
    /// Uncorrectable Error Status register.
    pub uncorrectable_status: u32,
    /// Uncorrectable Error Mask register.
    pub uncorrectable_mask: u32,
    /// Correctable Error Status register.
    pub correctable_status: u32,
    /// Correctable Error Mask register.
    pub correctable_mask: u32,
    /// Advanced Error Capabilities and Control register.
    pub cap_control: u32,
}

/// Parsed SR-IOV extended capability.
#[derive(Debug, Clone, Copy, Default)]
pub struct SriovCap {
    /// Extended capability offset.
    pub offset: u16,
    /// SR-IOV Capabilities register.
    pub sriov_cap: u32,
    /// SR-IOV Control register.
    pub sriov_ctrl: u16,
    /// Total VFs.
    pub total_vfs: u16,
    /// Initial VFs.
    pub initial_vfs: u16,
    /// Num VFs (currently active).
    pub num_vfs: u16,
    /// VF stride.
    pub vf_stride: u16,
    /// First VF Offset.
    pub first_vf_offset: u16,
    /// VF Device ID.
    pub vf_device_id: u16,
}

impl SriovCap {
    /// Whether SR-IOV VFs are currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.sriov_ctrl & 1 != 0
    }
}

// ---------------------------------------------------------------------------
// CapabilityList
// ---------------------------------------------------------------------------

/// Maximum capabilities stored in a scan result.
const MAX_CAPS: usize = 32;

/// Maximum extended capabilities stored in a scan result.
const MAX_ECAPS: usize = 32;

/// Result of scanning a device's capability list.
#[derive(Debug, Default)]
pub struct CapabilityList {
    /// Standard capability locations.
    pub caps: [Option<CapLocation>; MAX_CAPS],
    /// Number of standard capabilities found.
    pub cap_count: usize,
    /// Extended capability locations.
    pub ecaps: [Option<ExtCapLocation>; MAX_ECAPS],
    /// Number of extended capabilities found.
    pub ecap_count: usize,
}

impl CapabilityList {
    /// Find a standard capability by ID.
    pub fn find(&self, id: u8) -> Option<&CapLocation> {
        for i in 0..self.cap_count {
            if let Some(ref c) = self.caps[i] {
                if c.cap_id == id {
                    return Some(c);
                }
            }
        }
        None
    }

    /// Find an extended capability by ID.
    pub fn find_ecap(&self, id: u16) -> Option<&ExtCapLocation> {
        for i in 0..self.ecap_count {
            if let Some(ref e) = self.ecaps[i] {
                if e.cap_id == id {
                    return Some(e);
                }
            }
        }
        None
    }

    /// Whether a standard capability is present.
    pub fn has(&self, id: u8) -> bool {
        self.find(id).is_some()
    }

    /// Whether an extended capability is present.
    pub fn has_ecap(&self, id: u16) -> bool {
        self.find_ecap(id).is_some()
    }
}

// ---------------------------------------------------------------------------
// Capability scanner
// ---------------------------------------------------------------------------

/// Scan the standard PCI capability list in a 256-byte config space.
///
/// `config` must be exactly 256 bytes (standard PCI config space).
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `config.len() < 64`.
pub fn scan_capabilities(config: &[u8]) -> Result<CapabilityList> {
    if config.len() < 64 {
        return Err(Error::InvalidArgument);
    }
    let mut list = CapabilityList::default();
    // Status register bit[4]: capabilities list supported.
    let status = u16::from_le_bytes([config[0x06], config[0x07]]);
    if status & (1 << 4) == 0 {
        return Ok(list);
    }
    // Header type determines capabilities pointer offset.
    let header_type = config[0x0E] & 0x7F;
    let cap_ptr_off: usize = if header_type == 2 { 0x14 } else { 0x34 };
    if cap_ptr_off >= config.len() {
        return Ok(list);
    }
    let mut ptr = config[cap_ptr_off] & 0xFC;
    for _ in 0..48 {
        if ptr < 0x40 {
            break;
        }
        let off = ptr as usize;
        if off + 2 > config.len() {
            break;
        }
        let id = config[off];
        let next = config[off + 1] & 0xFC;
        if list.cap_count < MAX_CAPS {
            list.caps[list.cap_count] = Some(CapLocation {
                offset: ptr,
                cap_id: id,
            });
            list.cap_count += 1;
        }
        ptr = next;
    }
    Ok(list)
}

/// Scan PCIe extended capabilities in a 4096-byte extended config space.
///
/// Extended capabilities occupy offsets 0x100–0xFFF. `ecfg` must be at
/// least 0x100 bytes; for full PCIe extended config space it should be
/// 4096 bytes.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `ecfg.len() < 0x100`.
pub fn scan_extended_capabilities(ecfg: &[u8]) -> Result<CapabilityList> {
    if ecfg.len() < 0x100 {
        return Err(Error::InvalidArgument);
    }
    let mut list = CapabilityList::default();
    let mut offset: usize = 0x100;
    for _ in 0..48 {
        if offset + 4 > ecfg.len() || offset < 0x100 {
            break;
        }
        let dword = u32::from_le_bytes([
            ecfg[offset],
            ecfg[offset + 1],
            ecfg[offset + 2],
            ecfg[offset + 3],
        ]);
        let cap_id = (dword & 0xFFFF) as u16;
        let version = ((dword >> 16) & 0x0F) as u8;
        let next = ((dword >> 20) & 0xFFF) as u16;
        // cap_id == 0 with next == 0 means end of list (or absent).
        if cap_id == 0 && next == 0 {
            break;
        }
        if list.ecap_count < MAX_ECAPS {
            list.ecaps[list.ecap_count] = Some(ExtCapLocation {
                offset: offset as u16,
                cap_id,
                version,
            });
            list.ecap_count += 1;
        }
        if next < 0x100 {
            break;
        }
        offset = next as usize;
    }
    Ok(list)
}

// ---------------------------------------------------------------------------
// Individual capability parsers
// ---------------------------------------------------------------------------

/// Parse the PCI Power Management capability at `offset` in `config`.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if the data is too short.
pub fn parse_pm_cap(config: &[u8], offset: u8) -> Result<PmCap> {
    let off = offset as usize;
    if off + 8 > config.len() {
        return Err(Error::InvalidArgument);
    }
    Ok(PmCap {
        offset,
        pmc: u16::from_le_bytes([config[off + 2], config[off + 3]]),
        pmcsr: u16::from_le_bytes([config[off + 4], config[off + 5]]),
    })
}

/// Parse the PCIe capability at `offset` in `config`.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if the data is too short.
pub fn parse_pcie_cap(config: &[u8], offset: u8) -> Result<PcieCap> {
    let off = offset as usize;
    if off + 20 > config.len() {
        return Err(Error::InvalidArgument);
    }
    let pcie_cap_reg = u16::from_le_bytes([config[off + 2], config[off + 3]]);
    let dev_cap = u32::from_le_bytes([
        config[off + 4],
        config[off + 5],
        config[off + 6],
        config[off + 7],
    ]);
    let dev_ctrl = u16::from_le_bytes([config[off + 8], config[off + 9]]);
    let dev_status = u16::from_le_bytes([config[off + 10], config[off + 11]]);
    let link_cap = u32::from_le_bytes([
        config[off + 12],
        config[off + 13],
        config[off + 14],
        config[off + 15],
    ]);
    let link_ctrl = u16::from_le_bytes([config[off + 16], config[off + 17]]);
    let link_status = u16::from_le_bytes([config[off + 18], config[off + 19]]);
    let dev_cap2 = if off + 36 <= config.len() {
        u32::from_le_bytes([
            config[off + 32],
            config[off + 33],
            config[off + 34],
            config[off + 35],
        ])
    } else {
        0
    };
    let link_cap2 = if off + 48 <= config.len() {
        u32::from_le_bytes([
            config[off + 44],
            config[off + 45],
            config[off + 46],
            config[off + 47],
        ])
    } else {
        0
    };
    Ok(PcieCap {
        offset,
        pcie_cap_reg,
        dev_cap,
        dev_ctrl,
        dev_status,
        link_cap,
        link_ctrl,
        link_status,
        dev_cap2,
        link_cap2,
    })
}

/// Parse the AER extended capability at `offset` in `ecfg`.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if the data is too short.
pub fn parse_aer_cap(ecfg: &[u8], offset: u16) -> Result<AerCap> {
    let off = offset as usize;
    if off + 44 > ecfg.len() {
        return Err(Error::InvalidArgument);
    }
    let r = |o: usize| {
        u32::from_le_bytes([
            ecfg[off + o],
            ecfg[off + o + 1],
            ecfg[off + o + 2],
            ecfg[off + o + 3],
        ])
    };
    Ok(AerCap {
        offset,
        uncorrectable_status: r(4),
        uncorrectable_mask: r(8),
        correctable_status: r(16),
        correctable_mask: r(20),
        cap_control: r(24),
    })
}

/// Parse the SR-IOV extended capability at `offset` in `ecfg`.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if the data is too short.
pub fn parse_sriov_cap(ecfg: &[u8], offset: u16) -> Result<SriovCap> {
    let off = offset as usize;
    if off + 36 > ecfg.len() {
        return Err(Error::InvalidArgument);
    }
    let r32 = |o: usize| {
        u32::from_le_bytes([
            ecfg[off + o],
            ecfg[off + o + 1],
            ecfg[off + o + 2],
            ecfg[off + o + 3],
        ])
    };
    let r16 = |o: usize| u16::from_le_bytes([ecfg[off + o], ecfg[off + o + 1]]);
    Ok(SriovCap {
        offset,
        sriov_cap: r32(4),
        sriov_ctrl: r16(8),
        total_vfs: r16(14),
        initial_vfs: r16(12),
        num_vfs: r16(16),
        vf_stride: r16(20),
        first_vf_offset: r16(18),
        vf_device_id: r16(24),
    })
}

/// Parse a vendor-specific capability at `offset` in `config`.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if the data is too short.
pub fn parse_vendor_spec_cap(config: &[u8], offset: u8) -> Result<VendorSpecCap> {
    let off = offset as usize;
    if off + 3 > config.len() {
        return Err(Error::InvalidArgument);
    }
    Ok(VendorSpecCap {
        offset,
        length: config[off + 2],
    })
}

// ---------------------------------------------------------------------------
// High-level helper: scan and parse all known capabilities
// ---------------------------------------------------------------------------

/// Extended capability ID: PASID (Process Address Space ID).
pub const ECAP_ID_PASID: u16 = 0x001B;

// ---------------------------------------------------------------------------
// Additional parsed capability structures
// ---------------------------------------------------------------------------

/// Parsed MSI capability.
#[derive(Debug, Clone, Copy, Default)]
pub struct MsiCap {
    /// Capability offset in standard config space.
    pub offset: u8,
    /// Message Control register (enable, 64-bit, per-vector masking, etc.).
    pub msg_ctrl: u16,
    /// Message Address lower 32 bits.
    pub msg_addr_lo: u32,
    /// Message Address upper 32 bits (only valid for 64-bit MSI).
    pub msg_addr_hi: u32,
    /// Message Data register.
    pub msg_data: u16,
    /// `true` if this device supports 64-bit MSI addresses.
    pub is_64bit: bool,
    /// Number of message vectors requested (1 << MC bits[4:2]).
    pub requested_vectors: u8,
}

impl MsiCap {
    /// Returns `true` if MSI is currently enabled (MC bit 0).
    pub fn is_enabled(&self) -> bool {
        self.msg_ctrl & 1 != 0
    }

    /// Returns the number of allocated vectors (1 << MC bits[6:4]).
    pub fn allocated_vectors(&self) -> u8 {
        1u8 << ((self.msg_ctrl >> 4) & 0x7)
    }
}

/// Parsed MSI-X capability.
#[derive(Debug, Clone, Copy, Default)]
pub struct MsixCap {
    /// Capability offset.
    pub offset: u8,
    /// Message Control register.
    pub msg_ctrl: u16,
    /// Table Offset/BIR: bits 2:0 = BAR index, bits 31:3 = dword-aligned offset.
    pub table_offset: u32,
    /// PBA Offset/BIR: bits 2:0 = BAR index, bits 31:3 = dword-aligned offset.
    pub pba_offset: u32,
}

impl MsixCap {
    /// Number of table entries (MC bits[10:0] + 1).
    pub fn table_size(&self) -> u16 {
        (self.msg_ctrl & 0x07FF) + 1
    }

    /// BAR index for the MSI-X table.
    pub fn table_bir(&self) -> u8 {
        (self.table_offset & 0x7) as u8
    }

    /// Byte offset within the BAR for the MSI-X table.
    pub fn table_byte_offset(&self) -> u32 {
        self.table_offset & !0x7
    }

    /// BAR index for the MSI-X PBA.
    pub fn pba_bir(&self) -> u8 {
        (self.pba_offset & 0x7) as u8
    }

    /// Byte offset within the BAR for the MSI-X PBA.
    pub fn pba_byte_offset(&self) -> u32 {
        self.pba_offset & !0x7
    }

    /// Returns `true` if MSI-X is enabled (MC bit 15).
    pub fn is_enabled(&self) -> bool {
        self.msg_ctrl & (1 << 15) != 0
    }
}

/// Parsed ACS (Access Control Services) extended capability.
#[derive(Debug, Clone, Copy, Default)]
pub struct AcsCap {
    /// Extended capability offset.
    pub offset: u16,
    /// Capability version.
    pub version: u8,
    /// ACS Capability Register.
    pub cap: u16,
    /// ACS Control Register.
    pub ctrl: u16,
}

impl AcsCap {
    /// Returns `true` if ACS Source Validation is enabled.
    pub fn source_validation_enabled(&self) -> bool {
        self.ctrl & (1 << 0) != 0
    }

    /// Returns `true` if ACS Translation Blocking is enabled.
    pub fn translation_blocking_enabled(&self) -> bool {
        self.ctrl & (1 << 2) != 0
    }

    /// Returns `true` if ACS P2P Request Redirect is enabled.
    pub fn p2p_redirect_enabled(&self) -> bool {
        self.ctrl & (1 << 3) != 0
    }
}

/// Parsed PASID (Process Address Space ID) extended capability.
#[derive(Debug, Clone, Copy, Default)]
pub struct PasidCap {
    /// Extended capability offset.
    pub offset: u16,
    /// Capability version.
    pub version: u8,
    /// PASID Capability Register.
    pub cap: u16,
    /// PASID Control Register.
    pub ctrl: u16,
}

impl PasidCap {
    /// Returns `true` if PASID is enabled (Control bit 0).
    pub fn is_enabled(&self) -> bool {
        self.ctrl & 1 != 0
    }

    /// Returns the maximum PASID width supported (bits 12:8 of cap register).
    pub fn max_pasid_width(&self) -> u8 {
        ((self.cap >> 8) & 0x1F) as u8
    }
}

// ---------------------------------------------------------------------------
// PciCap enum — typed standard capability
// ---------------------------------------------------------------------------

/// A typed PCI standard capability parsed from config space bytes.
#[derive(Debug, Clone, Copy)]
pub enum PciCap {
    /// Power Management.
    PowerManagement(PmCap),
    /// MSI.
    Msi(MsiCap),
    /// MSI-X.
    MsiX(MsixCap),
    /// PCI Express.
    PciExpress(PcieCap),
    /// Vendor Specific.
    VendorSpecific(VendorSpecCap),
    /// Unknown/unparsed capability (ID, offset).
    Unknown(u8, u8),
}

impl PciCap {
    /// Returns the configuration space offset of this capability.
    pub fn cap_offset(&self) -> u8 {
        match self {
            PciCap::PowerManagement(c) => c.offset,
            PciCap::Msi(c) => c.offset,
            PciCap::MsiX(c) => c.offset,
            PciCap::PciExpress(c) => c.offset,
            PciCap::VendorSpecific(c) => c.offset,
            PciCap::Unknown(_, off) => *off,
        }
    }

    /// Returns the capability ID byte.
    pub fn cap_id(&self) -> u8 {
        match self {
            PciCap::PowerManagement(_) => CAP_ID_PM,
            PciCap::Msi(_) => CAP_ID_MSI,
            PciCap::MsiX(_) => CAP_ID_MSIX,
            PciCap::PciExpress(_) => CAP_ID_PCIE,
            PciCap::VendorSpecific(_) => CAP_ID_VNDR,
            PciCap::Unknown(id, _) => *id,
        }
    }
}

// ---------------------------------------------------------------------------
// PcieExtCap enum — typed extended capability
// ---------------------------------------------------------------------------

/// A typed PCIe extended capability.
#[derive(Debug, Clone, Copy)]
pub enum PcieExtCap {
    /// Advanced Error Reporting.
    Aer(AerCap),
    /// Access Control Services.
    Acs(AcsCap),
    /// SR-IOV.
    SrIov(SriovCap),
    /// PASID.
    Pasid(PasidCap),
    /// Unknown/unparsed (ID, offset).
    Unknown(u16, u16),
}

impl PcieExtCap {
    /// Returns the extended capability offset (≥ 0x100).
    pub fn ext_offset(&self) -> u16 {
        match self {
            PcieExtCap::Aer(c) => c.offset,
            PcieExtCap::Acs(c) => c.offset,
            PcieExtCap::SrIov(c) => c.offset,
            PcieExtCap::Pasid(c) => c.offset,
            PcieExtCap::Unknown(_, off) => *off,
        }
    }

    /// Returns the extended capability ID.
    pub fn ext_id(&self) -> u16 {
        match self {
            PcieExtCap::Aer(_) => ECAP_ID_AER,
            PcieExtCap::Acs(_) => ECAP_ID_ACS,
            PcieExtCap::SrIov(_) => ECAP_ID_SRIOV,
            PcieExtCap::Pasid(_) => ECAP_ID_PASID,
            PcieExtCap::Unknown(id, _) => *id,
        }
    }
}

// ---------------------------------------------------------------------------
// Slice-based cap parsers (MSI, MSI-X, ACS, PASID)
// ---------------------------------------------------------------------------

/// Parses the MSI capability at `offset` in `config`.
///
/// # Errors
/// Returns [`Error::InvalidArgument`] if the buffer is too short.
pub fn parse_msi_cap(config: &[u8], offset: u8) -> Result<MsiCap> {
    let off = offset as usize;
    if off + 10 > config.len() {
        return Err(Error::InvalidArgument);
    }
    let msg_ctrl = u16::from_le_bytes([config[off + 2], config[off + 3]]);
    let is_64bit = msg_ctrl & (1 << 7) != 0;
    let requested_vectors = 1u8 << ((msg_ctrl >> 1) & 0x7);
    let msg_addr_lo = u32::from_le_bytes([
        config[off + 4],
        config[off + 5],
        config[off + 6],
        config[off + 7],
    ]);
    let (msg_addr_hi, msg_data) = if is_64bit {
        if off + 14 > config.len() {
            return Err(Error::InvalidArgument);
        }
        let hi = u32::from_le_bytes([
            config[off + 8],
            config[off + 9],
            config[off + 10],
            config[off + 11],
        ]);
        let data = u16::from_le_bytes([config[off + 12], config[off + 13]]);
        (hi, data)
    } else {
        if off + 10 > config.len() {
            return Err(Error::InvalidArgument);
        }
        let data = u16::from_le_bytes([config[off + 8], config[off + 9]]);
        (0, data)
    };
    Ok(MsiCap {
        offset,
        msg_ctrl,
        msg_addr_lo,
        msg_addr_hi,
        msg_data,
        is_64bit,
        requested_vectors,
    })
}

/// Parses the MSI-X capability at `offset` in `config`.
///
/// # Errors
/// Returns [`Error::InvalidArgument`] if the buffer is too short.
pub fn parse_msix_cap(config: &[u8], offset: u8) -> Result<MsixCap> {
    let off = offset as usize;
    if off + 12 > config.len() {
        return Err(Error::InvalidArgument);
    }
    let msg_ctrl = u16::from_le_bytes([config[off + 2], config[off + 3]]);
    let table_offset = u32::from_le_bytes([
        config[off + 4],
        config[off + 5],
        config[off + 6],
        config[off + 7],
    ]);
    let pba_offset = u32::from_le_bytes([
        config[off + 8],
        config[off + 9],
        config[off + 10],
        config[off + 11],
    ]);
    Ok(MsixCap {
        offset,
        msg_ctrl,
        table_offset,
        pba_offset,
    })
}

/// Parses the ACS extended capability at `offset` in `ecfg`.
///
/// # Errors
/// Returns [`Error::InvalidArgument`] if the buffer is too short.
pub fn parse_acs_cap(ecfg: &[u8], offset: u16) -> Result<AcsCap> {
    let off = offset as usize;
    if off + 8 > ecfg.len() {
        return Err(Error::InvalidArgument);
    }
    let dw0 = u32::from_le_bytes([ecfg[off], ecfg[off + 1], ecfg[off + 2], ecfg[off + 3]]);
    let version = ((dw0 >> 16) & 0xF) as u8;
    let cap = u16::from_le_bytes([ecfg[off + 4], ecfg[off + 5]]);
    let ctrl = u16::from_le_bytes([ecfg[off + 6], ecfg[off + 7]]);
    Ok(AcsCap {
        offset,
        version,
        cap,
        ctrl,
    })
}

/// Parses the PASID extended capability at `offset` in `ecfg`.
///
/// # Errors
/// Returns [`Error::InvalidArgument`] if the buffer is too short.
pub fn parse_pasid_cap(ecfg: &[u8], offset: u16) -> Result<PasidCap> {
    let off = offset as usize;
    if off + 8 > ecfg.len() {
        return Err(Error::InvalidArgument);
    }
    let dw0 = u32::from_le_bytes([ecfg[off], ecfg[off + 1], ecfg[off + 2], ecfg[off + 3]]);
    let version = ((dw0 >> 16) & 0xF) as u8;
    let cap = u16::from_le_bytes([ecfg[off + 4], ecfg[off + 5]]);
    let ctrl = u16::from_le_bytes([ecfg[off + 6], ecfg[off + 7]]);
    Ok(PasidCap {
        offset,
        version,
        cap,
        ctrl,
    })
}

// ---------------------------------------------------------------------------
// High-level finders (slice-based, no I/O port dependency)
// ---------------------------------------------------------------------------

/// Walks the standard PCI capability list in `config` and returns the first
/// capability matching `cap_id` as a typed [`PciCap`].
///
/// # Parameters
/// - `config`: At least 64-byte PCI configuration space slice.
/// - `cap_id`: The `CAP_ID_*` constant to search for.
///
/// # Returns
/// `Ok(Some(cap))` if found, `Ok(None)` if not present.
///
/// # Errors
/// Returns [`Error::InvalidArgument`] if `config` is too short.
pub fn pci_find_capability(config: &[u8], cap_id: u8) -> Result<Option<PciCap>> {
    let cap_list = scan_capabilities(config)?;
    let loc = match cap_list.find(cap_id) {
        Some(l) => *l,
        None => return Ok(None),
    };
    let cap = match cap_id {
        CAP_ID_PM => {
            let pm = parse_pm_cap(config, loc.offset)?;
            PciCap::PowerManagement(pm)
        }
        CAP_ID_MSI => {
            let msi = parse_msi_cap(config, loc.offset)?;
            PciCap::Msi(msi)
        }
        CAP_ID_MSIX => {
            let msix = parse_msix_cap(config, loc.offset)?;
            PciCap::MsiX(msix)
        }
        CAP_ID_PCIE => {
            let pcie = parse_pcie_cap(config, loc.offset)?;
            PciCap::PciExpress(pcie)
        }
        CAP_ID_VNDR => {
            let vndr = parse_vendor_spec_cap(config, loc.offset)?;
            PciCap::VendorSpecific(vndr)
        }
        other => PciCap::Unknown(other, loc.offset),
    };
    Ok(Some(cap))
}

/// Walks the PCIe extended capability list in `ecfg` and returns the first
/// extended capability matching `ecap_id` as a typed [`PcieExtCap`].
///
/// # Parameters
/// - `ecfg`: At least 256-byte PCIe extended config space slice (ideally 4096 bytes).
/// - `ecap_id`: The `ECAP_ID_*` constant to search for.
///
/// # Returns
/// `Ok(Some(cap))` if found, `Ok(None)` if not present.
///
/// # Errors
/// Returns [`Error::InvalidArgument`] if `ecfg.len() < 0x100`.
pub fn pci_find_ext_capability(ecfg: &[u8], ecap_id: u16) -> Result<Option<PcieExtCap>> {
    let ecap_list = scan_extended_capabilities(ecfg)?;
    let loc = match ecap_list.find_ecap(ecap_id) {
        Some(l) => *l,
        None => return Ok(None),
    };
    let cap = match ecap_id {
        ECAP_ID_AER => {
            let aer = parse_aer_cap(ecfg, loc.offset)?;
            PcieExtCap::Aer(aer)
        }
        ECAP_ID_ACS => {
            let acs = parse_acs_cap(ecfg, loc.offset)?;
            PcieExtCap::Acs(acs)
        }
        ECAP_ID_SRIOV => {
            let sriov = parse_sriov_cap(ecfg, loc.offset)?;
            PcieExtCap::SrIov(sriov)
        }
        ECAP_ID_PASID => {
            let pasid = parse_pasid_cap(ecfg, loc.offset)?;
            PcieExtCap::Pasid(pasid)
        }
        other => PcieExtCap::Unknown(other, loc.offset),
    };
    Ok(Some(cap))
}

// ---------------------------------------------------------------------------
// ParsedCapabilities (full set)
// ---------------------------------------------------------------------------

/// All parsed standard and extended capabilities for one PCI function.
#[derive(Debug, Default)]
pub struct ParsedCapabilities {
    /// Power Management capability, if present.
    pub pm: Option<PmCap>,
    /// PCIe capability, if present.
    pub pcie: Option<PcieCap>,
    /// MSI capability, if present.
    pub msi: Option<MsiCap>,
    /// MSI-X capability, if present.
    pub msix: Option<MsixCap>,
    /// MSI capability offset (kept for backward compatibility).
    pub msi_offset: Option<u8>,
    /// MSI-X capability offset (kept for backward compatibility).
    pub msix_offset: Option<u8>,
    /// Vendor-specific capability, if present.
    pub vendor_spec: Option<VendorSpecCap>,
    /// AER extended capability, if present.
    pub aer: Option<AerCap>,
    /// ACS extended capability, if present.
    pub acs: Option<AcsCap>,
    /// SR-IOV extended capability, if present.
    pub sriov: Option<SriovCap>,
    /// PASID extended capability, if present.
    pub pasid: Option<PasidCap>,
    /// Raw capability list (all offsets).
    pub cap_list: CapabilityList,
}

/// Scan and parse all known capabilities from a 4096-byte PCIe config space.
///
/// The first 256 bytes are the standard config space; bytes 256–4095 are
/// the extended config space. If `cfg` is only 256 bytes, extended
/// capabilities are not parsed.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `cfg.len() < 64`.
pub fn parse_all_capabilities(cfg: &[u8]) -> Result<ParsedCapabilities> {
    let mut result = ParsedCapabilities::default();
    let cap_list = scan_capabilities(cfg)?;
    // Also scan extended capabilities if we have enough data.
    let ecap_list = if cfg.len() >= 0x100 {
        scan_extended_capabilities(cfg)?
    } else {
        CapabilityList::default()
    };
    // Merge ecap list into cap_list.
    let mut merged = cap_list;
    for i in 0..ecap_list.ecap_count {
        if merged.ecap_count < MAX_ECAPS {
            merged.ecaps[merged.ecap_count] = ecap_list.ecaps[i];
            merged.ecap_count += 1;
        }
    }
    // Parse individual standard caps.
    if let Some(loc) = merged.find(CAP_ID_PM) {
        result.pm = parse_pm_cap(cfg, loc.offset).ok();
    }
    if let Some(loc) = merged.find(CAP_ID_PCIE) {
        result.pcie = parse_pcie_cap(cfg, loc.offset).ok();
    }
    if let Some(loc) = merged.find(CAP_ID_MSI) {
        let off = loc.offset;
        result.msi_offset = Some(off);
        result.msi = parse_msi_cap(cfg, off).ok();
    }
    if let Some(loc) = merged.find(CAP_ID_MSIX) {
        let off = loc.offset;
        result.msix_offset = Some(off);
        result.msix = parse_msix_cap(cfg, off).ok();
    }
    if let Some(loc) = merged.find(CAP_ID_VNDR) {
        result.vendor_spec = parse_vendor_spec_cap(cfg, loc.offset).ok();
    }
    // Parse extended caps.
    if let Some(loc) = merged.find_ecap(ECAP_ID_AER) {
        result.aer = parse_aer_cap(cfg, loc.offset).ok();
    }
    if let Some(loc) = merged.find_ecap(ECAP_ID_ACS) {
        result.acs = parse_acs_cap(cfg, loc.offset).ok();
    }
    if let Some(loc) = merged.find_ecap(ECAP_ID_SRIOV) {
        result.sriov = parse_sriov_cap(cfg, loc.offset).ok();
    }
    if let Some(loc) = merged.find_ecap(ECAP_ID_PASID) {
        result.pasid = parse_pasid_cap(cfg, loc.offset).ok();
    }
    result.cap_list = merged;
    Ok(result)
}
