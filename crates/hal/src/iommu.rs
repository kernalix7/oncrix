// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IOMMU (Intel VT-d style) DMA remapping module.
//!
//! Provides an abstraction over the Intel VT-d IOMMU hardware for
//! DMA remapping, device isolation, and interrupt remapping. The
//! IOMMU translates device-virtual addresses (IOVAs) issued by
//! PCI/PCIe devices into physical addresses, protecting the system
//! from rogue DMA.
//!
//! # Architecture
//!
//! - Root table → context table → I/O page tables (multi-level)
//! - Each PCI device (identified by bus/device/function) gets a
//!   context entry pointing to its own I/O page table.
//! - The IOMMU hardware walks these tables on every DMA access.
//!
//! # Usage
//!
//! ```ignore
//! let mut iommu = IommuDevice::new(mmio_base);
//! iommu.init()?;
//! iommu.map_device(bdf, iova, phys, size, true)?;
//! ```

use oncrix_lib::{Error, Result};

// ── MMIO Register Offsets ────────────────────────────────────

/// Version register (32-bit, read-only).
const _REG_VER: u32 = 0x00;

/// Capability register (64-bit, read-only).
const REG_CAP: u32 = 0x08;

/// Extended capability register (64-bit, read-only).
const REG_ECAP: u32 = 0x10;

/// Global command register (32-bit, read-write).
const REG_GCMD: u32 = 0x18;

/// Global status register (32-bit, read-only).
const REG_GSTS: u32 = 0x1C;

/// Root table address register (64-bit, read-write).
const REG_RTADDR: u32 = 0x20;

/// Context command register (64-bit, read-write).
const REG_CCMD: u32 = 0x28;

/// Fault status register (32-bit, read-write-clear).
const REG_FSTS: u32 = 0x34;

/// Fault event control register (32-bit, read-write).
const _REG_FECTL: u32 = 0x38;

/// Fault event data register (32-bit, read-write).
const _REG_FEDATA: u32 = 0x3C;

/// Fault event address register (32-bit, read-write).
const _REG_FEADDR: u32 = 0x40;

/// Invalidation queue head register (64-bit, read-only).
const _REG_IQH: u32 = 0x80;

/// Invalidation queue tail register (64-bit, read-write).
const _REG_IQT: u32 = 0x88;

/// Invalidation queue address register (64-bit, read-write).
const _REG_IQA: u32 = 0x90;

// ── Capability register bits ─────────────────────────────────

/// Number of domains supported (bits 2:0 of CAP).
const CAP_ND_MASK: u64 = 0x07;

/// Supported adjusted guest address widths (bits 11:8 of CAP).
const CAP_SAGAW_MASK: u64 = 0x1F << 8;

/// Shift for SAGAW field.
const CAP_SAGAW_SHIFT: u32 = 8;

/// Number of fault recording registers (bits 47:40 of CAP).
const _CAP_NFR_MASK: u64 = 0xFF << 40;

/// Shift for NFR field.
const _CAP_NFR_SHIFT: u32 = 40;

/// Caching mode (bit 7 of CAP).
const CAP_CM: u64 = 1 << 7;

/// Page walk coherency (bit 5 of ECAP).
const ECAP_PWC: u64 = 1 << 5;

/// Queued invalidation support (bit 1 of ECAP).
const _ECAP_QI: u64 = 1 << 1;

// ── Global command / status bits ─────────────────────────────

/// Translation enable (bit 31 of GCMD).
const GCMD_TE: u64 = 1 << 31;

/// Set root table pointer (bit 30 of GCMD).
const GCMD_SRTP: u64 = 1 << 30;

/// Translation enabled status (bit 31 of GSTS).
const GSTS_TES: u64 = 1 << 31;

/// Root table pointer set status (bit 30 of GSTS).
const GSTS_RTPS: u64 = 1 << 30;

/// Context cache invalidate command (bit 63 of CCMD).
const CCMD_ICC: u64 = 1 << 63;

/// Global invalidation for context cache (bits 62:61 = 01).
const CCMD_CIRG_GLOBAL: u64 = 1 << 61;

// ── Fault status bits ────────────────────────────────────────

/// Primary pending fault (bit 0 of FSTS).
const FSTS_PPF: u64 = 1 << 0;

/// Fault overflow (bit 1 of FSTS).
const _FSTS_PFO: u64 = 1 << 1;

// ── I/O page table entry bits ────────────────────────────────

/// Present bit for I/O page table entries.
const IOPT_PRESENT: u64 = 1 << 0;

/// Read permission bit.
const IOPT_READ: u64 = 1 << 1;

/// Write permission bit.
const IOPT_WRITE: u64 = 1 << 2;

/// Mask for the physical address field (bits 51:12).
const IOPT_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// ── Domain count decoding ────────────────────────────────────

/// Decode the number of domains from the ND field (bits 2:0).
fn decode_num_domains(nd: u64) -> u32 {
    match nd & CAP_ND_MASK {
        0 => 0,
        1 => 16,
        2 => 64,
        3 => 256,
        4 => 1024,
        5 => 4096,
        6 => 16384,
        7 => 65536,
        _ => 0,
    }
}

/// Maximum number of DMA mappings tracked per IOMMU device.
const MAX_MAPPINGS: usize = 256;

/// Maximum number of IOMMU units in the system.
const MAX_IOMMU_UNITS: usize = 4;

// ── MMIO Helpers ─────────────────────────────────────────────

/// Read a 64-bit value from a memory-mapped I/O address.
///
/// # Safety
///
/// The caller must ensure that `addr` points to a valid,
/// mapped MMIO register within the IOMMU register block.
/// The address must be 8-byte aligned.
#[inline]
unsafe fn read_mmio64(addr: u64) -> u64 {
    // SAFETY: caller guarantees addr is a valid MMIO register
    // address within a mapped IOMMU BAR region.
    unsafe { core::ptr::read_volatile(addr as *const u64) }
}

/// Write a 64-bit value to a memory-mapped I/O address.
///
/// # Safety
///
/// The caller must ensure that `addr` points to a valid,
/// mapped MMIO register within the IOMMU register block.
/// The address must be 8-byte aligned.
#[inline]
unsafe fn write_mmio64(addr: u64, val: u64) {
    // SAFETY: caller guarantees addr is a valid MMIO register
    // address within a mapped IOMMU BAR region.
    unsafe {
        core::ptr::write_volatile(addr as *mut u64, val);
    }
}

// ── DMA Remapping Structures ─────────────────────────────────

/// A root or context table entry for DMA remapping.
///
/// Each entry is 128 bits (16 bytes) as defined by the VT-d
/// specification. The `lo` quadword contains the present bit
/// and the table pointer; `hi` contains additional attributes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DmarEntry {
    /// Lower 64 bits: present (bit 0) + table address (bits 63:12).
    pub lo: u64,
    /// Upper 64 bits: domain ID, address width, fault policy.
    pub hi: u64,
}

impl Default for DmarEntry {
    fn default() -> Self {
        Self::new()
    }
}

impl DmarEntry {
    /// Create an empty (not-present) DMAR entry.
    pub const fn new() -> Self {
        Self { lo: 0, hi: 0 }
    }

    /// Create a present root/context entry pointing to `addr`.
    ///
    /// The address must be 4 KiB-aligned (bits 11:0 are zero).
    /// Sets the present bit (bit 0) in the lower quadword.
    pub const fn with_address(addr: u64) -> Self {
        Self {
            lo: (addr & IOPT_ADDR_MASK) | 1,
            hi: 0,
        }
    }

    /// Return whether this entry is present.
    pub const fn is_present(&self) -> bool {
        self.lo & 1 != 0
    }

    /// Return the table/page address stored in this entry.
    pub const fn address(&self) -> u64 {
        self.lo & IOPT_ADDR_MASK
    }

    /// Set the domain ID in the upper quadword (bits 23:8).
    pub fn set_domain_id(&mut self, domain: u16) {
        self.hi = (self.hi & !0x00FF_FF00) | ((domain as u64) << 8);
    }

    /// Return the domain ID from the upper quadword.
    pub fn domain_id(&self) -> u16 {
        ((self.hi >> 8) & 0xFFFF) as u16
    }

    /// Set the address width field (bits 4:2 of hi) for a
    /// context entry. Common values: 1=30-bit, 2=39-bit,
    /// 3=48-bit, 4=57-bit AGAW.
    pub fn set_address_width(&mut self, agaw: u8) {
        self.hi = (self.hi & !0x1C) | (((agaw & 0x07) as u64) << 2);
    }
}

// ── I/O Page Table Entry ─────────────────────────────────────

/// An I/O page table entry for DMA address translation.
///
/// Similar in layout to a CPU page table entry but used by the
/// IOMMU hardware. Each entry is 64 bits (8 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoPageTableEntry {
    /// Raw entry value: present (bit 0), read (bit 1),
    /// write (bit 2), address (bits 51:12).
    pub value: u64,
}

impl IoPageTableEntry {
    /// Create an empty (not-present) I/O page table entry.
    pub const fn new() -> Self {
        Self { value: 0 }
    }

    /// Create a present entry mapping to `phys_addr` with the
    /// specified permissions.
    ///
    /// The physical address must be 4 KiB-aligned.
    pub const fn with_mapping(phys_addr: u64, read: bool, write: bool) -> Self {
        let mut v = (phys_addr & IOPT_ADDR_MASK) | IOPT_PRESENT;
        if read {
            v |= IOPT_READ;
        }
        if write {
            v |= IOPT_WRITE;
        }
        Self { value: v }
    }

    /// Return whether this entry is present.
    pub const fn is_present(&self) -> bool {
        self.value & IOPT_PRESENT != 0
    }

    /// Return whether read permission is granted.
    pub const fn is_readable(&self) -> bool {
        self.value & IOPT_READ != 0
    }

    /// Return whether write permission is granted.
    pub const fn is_writable(&self) -> bool {
        self.value & IOPT_WRITE != 0
    }

    /// Return the physical address this entry points to.
    pub const fn address(&self) -> u64 {
        self.value & IOPT_ADDR_MASK
    }

    /// Clear the entry (mark as not-present).
    pub fn clear(&mut self) {
        self.value = 0;
    }
}

// ── IOMMU Capability ─────────────────────────────────────────

/// Parsed IOMMU capabilities from the CAP and ECAP registers.
#[derive(Debug, Clone, Copy)]
pub struct IommuCapability {
    /// Supported adjusted guest address widths (SAGAW).
    /// Bit 1 = 30-bit, bit 2 = 39-bit, bit 3 = 48-bit,
    /// bit 4 = 57-bit.
    pub supported_agws: u8,
    /// Maximum number of domains the IOMMU supports.
    pub num_domains: u32,
    /// Whether the hardware supports page walk coherency.
    pub page_walk_coherency: bool,
    /// Whether caching mode is active (software must
    /// explicitly invalidate caches).
    pub caching_mode: bool,
    /// Raw CAP register value.
    pub raw_cap: u64,
    /// Raw ECAP register value.
    pub raw_ecap: u64,
}

impl Default for IommuCapability {
    fn default() -> Self {
        Self::new()
    }
}

impl IommuCapability {
    /// Create a zeroed capability structure.
    pub const fn new() -> Self {
        Self {
            supported_agws: 0,
            num_domains: 0,
            page_walk_coherency: false,
            caching_mode: false,
            raw_cap: 0,
            raw_ecap: 0,
        }
    }

    /// Parse capabilities from raw CAP and ECAP register values.
    pub fn from_registers(cap: u64, ecap: u64) -> Self {
        let sagaw = ((cap & CAP_SAGAW_MASK) >> CAP_SAGAW_SHIFT) as u8;
        let nd = decode_num_domains(cap);
        Self {
            supported_agws: sagaw,
            num_domains: nd,
            page_walk_coherency: ecap & ECAP_PWC != 0,
            caching_mode: cap & CAP_CM != 0,
            raw_cap: cap,
            raw_ecap: ecap,
        }
    }

    /// Return the best (widest) supported address width in bits.
    ///
    /// Returns 0 if no address widths are supported.
    pub fn best_agaw_bits(&self) -> u8 {
        if self.supported_agws & (1 << 4) != 0 {
            57
        } else if self.supported_agws & (1 << 3) != 0 {
            48
        } else if self.supported_agws & (1 << 2) != 0 {
            39
        } else if self.supported_agws & (1 << 1) != 0 {
            30
        } else {
            0
        }
    }
}

// ── DMA Mapping ──────────────────────────────────────────────

/// A single DMA address mapping entry.
///
/// Records the mapping of a device-virtual (IOVA) range to a
/// physical address range, along with the owning device BDF
/// and access permissions.
#[derive(Debug, Clone, Copy)]
pub struct DmaMapping {
    /// Base I/O virtual address (device-side).
    pub iova_base: u64,
    /// Base physical address (host-side).
    pub phys_base: u64,
    /// Size of the mapped region in bytes.
    pub size: u64,
    /// PCI device identifier (bus/device/function packed as
    /// `bus << 8 | devfn`).
    pub device_id: u16,
    /// Whether the device is allowed to read from this region.
    pub read: bool,
    /// Whether the device is allowed to write to this region.
    pub write: bool,
    /// Whether this mapping slot is in use.
    pub active: bool,
}

impl Default for DmaMapping {
    fn default() -> Self {
        Self::new()
    }
}

impl DmaMapping {
    /// Create an empty (inactive) mapping entry.
    pub const fn new() -> Self {
        Self {
            iova_base: 0,
            phys_base: 0,
            size: 0,
            device_id: 0,
            read: false,
            write: false,
            active: false,
        }
    }
}

// ── IOMMU Fault ──────────────────────────────────────────────

/// Describes a DMA translation fault reported by the IOMMU.
#[derive(Debug, Clone, Copy)]
pub struct IommuFault {
    /// Fault reason code from the hardware.
    pub fault_reason: u8,
    /// Source device identifier (BDF) that caused the fault.
    pub source_id: u16,
    /// Faulting device-virtual address.
    pub fault_addr: u64,
}

// ── IOMMU Device ─────────────────────────────────────────────

/// Driver for a single IOMMU (Intel VT-d) hardware unit.
///
/// Manages the IOMMU MMIO registers, root/context tables, and
/// DMA mappings. Each IOMMU unit protects a segment of the PCI
/// bus topology.
pub struct IommuDevice {
    /// Physical base address of the IOMMU MMIO register block.
    mmio_base: u64,
    /// Parsed hardware capabilities.
    capabilities: IommuCapability,
    /// Whether DMA remapping is enabled.
    enabled: bool,
    /// Number of faults recorded since initialisation.
    fault_count: u64,
    /// Active DMA mappings.
    mappings: [DmaMapping; MAX_MAPPINGS],
    /// Number of active mappings.
    mapping_count: usize,
    /// Physical address of the root table (4 KiB-aligned).
    root_table_phys: u64,
}

impl IommuDevice {
    /// Create a new IOMMU device driver for the unit at the
    /// given MMIO base address.
    ///
    /// The device is created in a disabled state. Call
    /// [`IommuDevice::init`] to read capabilities and enable
    /// translation.
    pub fn new(mmio_base: u64) -> Self {
        Self {
            mmio_base,
            capabilities: IommuCapability::new(),
            enabled: false,
            fault_count: 0,
            mappings: [DmaMapping::new(); MAX_MAPPINGS],
            mapping_count: 0,
            root_table_phys: 0,
        }
    }

    /// Initialise the IOMMU hardware.
    ///
    /// Reads the CAP and ECAP registers to determine hardware
    /// capabilities, sets the root table pointer, and enables
    /// DMA translation.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `mmio_base` is zero.
    /// - [`Error::IoError`] if the hardware does not report
    ///   any supported address widths.
    pub fn init(&mut self) -> Result<()> {
        if self.mmio_base == 0 {
            return Err(Error::InvalidArgument);
        }

        // Read capability registers.
        let cap = self.read_reg(REG_CAP);
        let ecap = self.read_reg(REG_ECAP);
        self.capabilities = IommuCapability::from_registers(cap, ecap);

        if self.capabilities.supported_agws == 0 {
            return Err(Error::IoError);
        }

        // Set root table pointer (assumes root_table_phys has
        // been configured by the memory manager before init).
        if self.root_table_phys != 0 {
            self.write_reg(REG_RTADDR, self.root_table_phys);

            // Issue "set root table pointer" command.
            let cmd = self.read_reg(REG_GCMD) | GCMD_SRTP;
            self.write_reg(REG_GCMD, cmd);

            // Poll until RTPS is set in GSTS.
            let mut retries = 1000u32;
            while self.read_reg(REG_GSTS) & GSTS_RTPS == 0 {
                retries = retries.saturating_sub(1);
                if retries == 0 {
                    return Err(Error::IoError);
                }
            }
        }

        // Enable translation.
        let cmd = self.read_reg(REG_GCMD) | GCMD_TE;
        self.write_reg(REG_GCMD, cmd);

        // Poll until TES is set in GSTS.
        let mut retries = 1000u32;
        while self.read_reg(REG_GSTS) & GSTS_TES == 0 {
            retries = retries.saturating_sub(1);
            if retries == 0 {
                return Err(Error::IoError);
            }
        }

        self.enabled = true;
        Ok(())
    }

    /// Read a 64-bit IOMMU register at the given offset.
    pub fn read_reg(&self, offset: u32) -> u64 {
        // SAFETY: mmio_base is the IOMMU register BAR base
        // address, mapped into kernel virtual memory. The
        // offset is within the IOMMU register block (<4 KiB).
        unsafe { read_mmio64(self.mmio_base + offset as u64) }
    }

    /// Write a 64-bit value to an IOMMU register at the given
    /// offset.
    pub fn write_reg(&mut self, offset: u32, val: u64) {
        // SAFETY: mmio_base is the IOMMU register BAR base
        // address, mapped into kernel virtual memory. The
        // offset is within the IOMMU register block (<4 KiB).
        unsafe {
            write_mmio64(self.mmio_base + offset as u64, val);
        }
    }

    /// Set the physical address of the root table.
    ///
    /// Must be called before [`IommuDevice::init`] if the root
    /// table has been allocated. The address must be 4 KiB
    /// aligned.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the address is
    /// not 4 KiB-aligned.
    pub fn set_root_table(&mut self, phys: u64) -> Result<()> {
        if phys & 0xFFF != 0 {
            return Err(Error::InvalidArgument);
        }
        self.root_table_phys = phys;
        Ok(())
    }

    /// Map a device's IOVA range to physical memory.
    ///
    /// Records a DMA mapping for the PCI device identified by
    /// `bdf` (bus/device/function). The mapping translates
    /// device accesses to `[iova .. iova+size)` into
    /// `[phys .. phys+size)`.
    ///
    /// # Arguments
    ///
    /// * `bdf` — PCI bus/device/function identifier.
    /// * `iova` — Device-virtual base address.
    /// * `phys` — Physical base address.
    /// * `size` — Size of the region in bytes.
    /// * `write` — Whether write access is permitted.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `size` is zero or
    ///   addresses are not 4 KiB-aligned.
    /// - [`Error::AlreadyExists`] if a mapping for this
    ///   BDF + IOVA already exists.
    /// - [`Error::OutOfMemory`] if the mapping table is full.
    pub fn map_device(
        &mut self,
        bdf: u16,
        iova: u64,
        phys: u64,
        size: u64,
        write: bool,
    ) -> Result<()> {
        if size == 0 || iova & 0xFFF != 0 || phys & 0xFFF != 0 {
            return Err(Error::InvalidArgument);
        }

        // Check for duplicate mapping.
        let exists = self.mappings[..self.mapping_count]
            .iter()
            .any(|m| m.active && m.device_id == bdf && m.iova_base == iova);
        if exists {
            return Err(Error::AlreadyExists);
        }

        // Find a free slot.
        let slot = self
            .mappings
            .iter()
            .position(|m| !m.active)
            .ok_or(Error::OutOfMemory)?;

        self.mappings[slot] = DmaMapping {
            iova_base: iova,
            phys_base: phys,
            size,
            device_id: bdf,
            read: true,
            write,
            active: true,
        };

        if slot >= self.mapping_count {
            self.mapping_count = slot + 1;
        }

        Ok(())
    }

    /// Remove a DMA mapping for a device.
    ///
    /// Looks up and removes the mapping for the given `bdf` and
    /// `iova` base address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching mapping exists.
    pub fn unmap_device(&mut self, bdf: u16, iova: u64) -> Result<()> {
        let slot = self.mappings[..self.mapping_count]
            .iter()
            .position(|m| m.active && m.device_id == bdf && m.iova_base == iova)
            .ok_or(Error::NotFound)?;

        self.mappings[slot].active = false;

        // Shrink mapping_count if possible.
        while self.mapping_count > 0 && !self.mappings[self.mapping_count - 1].active {
            self.mapping_count -= 1;
        }

        Ok(())
    }

    /// Invalidate the IOMMU context cache (global invalidation).
    ///
    /// Forces the IOMMU to re-read context table entries from
    /// memory. Must be called after modifying context tables.
    pub fn invalidate_context(&mut self) {
        let cmd = CCMD_ICC | CCMD_CIRG_GLOBAL;
        self.write_reg(REG_CCMD, cmd);

        // Poll until ICC is cleared (invalidation complete).
        let mut retries = 1000u32;
        while self.read_reg(REG_CCMD) & CCMD_ICC != 0 {
            retries = retries.saturating_sub(1);
            if retries == 0 {
                break;
            }
        }
    }

    /// Invalidate the IOMMU IOTLB (global invalidation).
    ///
    /// Forces the IOMMU to discard all cached address
    /// translations. Must be called after modifying I/O page
    /// tables.
    pub fn invalidate_iotlb(&mut self) {
        // The IOTLB invalidation register offset is obtained
        // from ECAP bits 15:8 (IRO field) * 16 + 0x08.
        let iro = ((self.capabilities.raw_ecap >> 8) & 0xFF) as u32;
        let iotlb_offset = iro * 16 + 0x08;

        // Global invalidation: set IVT (bit 63) + IIRG=01
        // (bits 61:60) + drain reads/writes (bits 49:48).
        let cmd: u64 = (1u64 << 63) | (1u64 << 60) | (3u64 << 48);
        self.write_reg(iotlb_offset, cmd);

        // Poll until IVT is cleared.
        let mut retries = 1000u32;
        while self.read_reg(iotlb_offset) & (1u64 << 63) != 0 {
            retries = retries.saturating_sub(1);
            if retries == 0 {
                break;
            }
        }
    }

    /// Check for and read a pending DMA translation fault.
    ///
    /// Returns `Some(IommuFault)` if a fault is pending, or
    /// `None` if no faults are recorded.
    pub fn handle_fault(&mut self) -> Option<IommuFault> {
        let fsts = self.read_reg(REG_FSTS);

        if fsts & FSTS_PPF == 0 {
            return None;
        }

        // Fault recording register index from FSTS bits 15:8.
        let fri = ((fsts >> 8) & 0xFF) as u32;

        // Fault recording registers start at CAP.FRO * 16.
        // FRO is CAP bits 33:24.
        let fro = ((self.capabilities.raw_cap >> 24) & 0x3FF) as u32;
        let fr_base = fro * 16;
        let fr_offset = fr_base + fri * 16;

        // Read the 128-bit fault recording register.
        let fr_lo = self.read_reg(fr_offset);
        let fr_hi = self.read_reg(fr_offset + 8);

        // Extract fields from the fault record.
        let fault_reason = ((fr_hi >> 32) & 0xFF) as u8;
        let source_id = (fr_hi & 0xFFFF) as u16;
        // Fault address is in the lower quadword (bits 63:12
        // hold the page address).
        let fault_addr = fr_lo & IOPT_ADDR_MASK;

        // Clear the fault by writing 1 to bit 63 of fr_hi.
        self.write_reg(fr_offset + 8, fr_hi | (1u64 << 63));

        // Clear PPF in FSTS by writing 1.
        self.write_reg(REG_FSTS, FSTS_PPF);

        self.fault_count += 1;

        Some(IommuFault {
            fault_reason,
            source_id,
            fault_addr,
        })
    }

    /// Return the parsed hardware capabilities.
    pub fn capabilities(&self) -> &IommuCapability {
        &self.capabilities
    }

    /// Return whether DMA translation is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Return the total number of faults recorded.
    pub fn fault_count(&self) -> u64 {
        self.fault_count
    }

    /// Return the MMIO base address.
    pub fn mmio_base(&self) -> u64 {
        self.mmio_base
    }

    /// Return the number of active DMA mappings.
    pub fn mapping_count(&self) -> usize {
        self.mapping_count
    }

    /// Look up a DMA mapping by device BDF and IOVA.
    ///
    /// Returns a reference to the matching [`DmaMapping`] if
    /// found, or `None` otherwise.
    pub fn find_mapping(&self, bdf: u16, iova: u64) -> Option<&DmaMapping> {
        self.mappings[..self.mapping_count]
            .iter()
            .find(|m| m.active && m.device_id == bdf && m.iova_base == iova)
    }
}

// ── IOMMU Registry ───────────────────────────────────────────

/// Registry of IOMMU hardware units in the system.
///
/// Supports up to [`MAX_IOMMU_UNITS`] (4) IOMMU devices,
/// typically discovered through the ACPI DMAR table.
pub struct IommuRegistry {
    /// Registered IOMMU devices.
    units: [Option<IommuDevice>; MAX_IOMMU_UNITS],
    /// Number of registered units.
    count: usize,
}

impl Default for IommuRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl IommuRegistry {
    /// Create an empty IOMMU registry.
    pub const fn new() -> Self {
        Self {
            units: [None, None, None, None],
            count: 0,
        }
    }

    /// Register a new IOMMU device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, device: IommuDevice) -> Result<usize> {
        if self.count >= MAX_IOMMU_UNITS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.units[idx] = Some(device);
        self.count += 1;
        Ok(idx)
    }

    /// Look up an IOMMU device by index.
    pub fn get(&self, index: usize) -> Option<&IommuDevice> {
        if index < self.count {
            self.units[index].as_ref()
        } else {
            None
        }
    }

    /// Look up a mutable reference to an IOMMU device by index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut IommuDevice> {
        if index < self.count {
            self.units[index].as_mut()
        } else {
            None
        }
    }

    /// Return the number of registered IOMMU units.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Find the IOMMU unit responsible for a given MMIO base.
    pub fn find_by_base(&self, mmio_base: u64) -> Option<&IommuDevice> {
        self.units[..self.count]
            .iter()
            .filter_map(|u| u.as_ref())
            .find(|dev| dev.mmio_base() == mmio_base)
    }
}
