// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Intel VT-d IOMMU driver.
//!
//! Implements Intel Virtualization Technology for Directed I/O (VT-d),
//! providing DMA remapping for hardware isolation and protection. Manages
//! the Root/Context tables, Translation-Lookaside Buffers (IOTLB), and
//! interrupt remapping.

use oncrix_lib::{Error, Result};

/// VT-d MMIO register offsets (relative to remapping hardware unit base).
const REG_VER: u32 = 0x00; // Version
const REG_CAP: u32 = 0x08; // Capability
const REG_ECAP: u32 = 0x10; // Extended capability
const REG_GCMD: u32 = 0x18; // Global command
const REG_GSTS: u32 = 0x1C; // Global status
const REG_RTADDR: u32 = 0x20; // Root table address
const REG_CCMD: u32 = 0x28; // Context command
const REG_FSTS: u32 = 0x34; // Fault status
const REG_FECTL: u32 = 0x38; // Fault event control
const REG_FEDATA: u32 = 0x3C; // Fault event data
const REG_FEADDR: u32 = 0x40; // Fault event address
const REG_PMEN: u32 = 0x64; // Protected memory enable
const REG_PLMBASE: u32 = 0x68; // Protected low memory base
const REG_PLMLIMIT: u32 = 0x6C; // Protected low memory limit
const REG_PHMBASE: u32 = 0x70; // Protected high memory base
const REG_PHMLIMIT: u32 = 0x78; // Protected high memory limit
const REG_IQH: u32 = 0x80; // Invalidation queue head
const REG_IQT: u32 = 0x88; // Invalidation queue tail
const REG_IQA: u32 = 0x90; // Invalidation queue address
const REG_IRTA: u32 = 0xB8; // Interrupt remapping table address

/// Global Command register bits.
const GCMD_TE: u32 = 1 << 31; // Translation enable
const GCMD_SRTP: u32 = 1 << 30; // Set root table pointer
const GCMD_SFL: u32 = 1 << 29; // Set fault log
const GCMD_EAFL: u32 = 1 << 28; // Enable advanced fault logging
const GCMD_WBF: u32 = 1 << 27; // Write buffer flush
const GCMD_QIE: u32 = 1 << 26; // Queued invalidation enable
const GCMD_IRE: u32 = 1 << 25; // Interrupt remapping enable
const GCMD_SIRTP: u32 = 1 << 24; // Set interrupt remap table pointer
const GCMD_CFI: u32 = 1 << 23; // Compatibility format interrupt

/// Global Status register bits.
const GSTS_TES: u32 = 1 << 31; // Translation enable status
const GSTS_RTPS: u32 = 1 << 30; // Root table pointer status
const GSTS_FLS: u32 = 1 << 29; // Fault log status
const GSTS_QIES: u32 = 1 << 26; // Queued invalidation enable status
const GSTS_IRES: u32 = 1 << 25; // Interrupt remapping enable status

/// Fault Status register bits.
const FSTS_PFO: u32 = 1 << 0; // Primary fault overflow
const FSTS_PPF: u32 = 1 << 1; // Primary pending fault
const FSTS_IQE: u32 = 1 << 4; // Invalidation queue error
const FSTS_ICE: u32 = 1 << 5; // Invalidation completion error
const FSTS_ITE: u32 = 1 << 6; // Invalidation time-out error
const FSTS_PRO: u32 = 1 << 7; // Page request overflow

/// Maximum number of IOMMU hardware units.
const MAX_UNITS: usize = 4;

/// IOMMU domain ID (16-bit, 0xFFFF reserved).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DomainId(pub u16);

impl DomainId {
    /// Invalid domain sentinel.
    pub const INVALID: DomainId = DomainId(0xFFFF);
}

/// Root table entry in `#[repr(C)]` for DMA.
/// Each entry points to a context table for a PCI bus.
#[repr(C)]
pub struct RootEntry {
    /// Low 64 bits: context table pointer + present bit.
    pub lo: u64,
    /// High 64 bits: reserved.
    pub hi: u64,
}

impl RootEntry {
    pub const fn new() -> Self {
        Self { lo: 0, hi: 0 }
    }
}

impl Default for RootEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Context table entry in `#[repr(C)]` for DMA.
/// Each entry maps a PCI function to a domain.
#[repr(C)]
pub struct ContextEntry {
    /// Low 64 bits: domain ID, address width, SLPTPTR, present.
    pub lo: u64,
    /// High 64 bits: domain ID (upper bits), attributes.
    pub hi: u64,
}

impl ContextEntry {
    pub const fn new() -> Self {
        Self { lo: 0, hi: 0 }
    }

    /// Mark this entry as present with the given domain ID and SLPTPTR.
    pub fn set_present(&mut self, domain_id: DomainId, slptptr: u64, aw: u8) {
        // bit 0 = present, bits 1:2 = TT (10=multi-level page table),
        // bits 3:6 = AW (address width), bits 63:12 = SLPTPTR >> 12.
        self.lo = 1 | (2 << 1) | ((aw as u64 & 0xF) << 3) | (slptptr & !0xFFF);
        self.hi = domain_id.0 as u64;
    }
}

impl Default for ContextEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// A single Intel VT-d remapping hardware unit.
pub struct IntelIommuUnit {
    /// MMIO base address of this unit.
    mmio_base: usize,
    /// Translation is enabled.
    te_enabled: bool,
    /// Interrupt remapping is enabled.
    ir_enabled: bool,
    /// Queued invalidation is enabled.
    qi_enabled: bool,
    /// Physical address of the root table.
    root_table_phys: u64,
}

impl IntelIommuUnit {
    /// Create a new IOMMU unit.
    pub fn new(mmio_base: usize) -> Self {
        Self {
            mmio_base,
            te_enabled: false,
            ir_enabled: false,
            qi_enabled: false,
            root_table_phys: 0,
        }
    }

    /// Initialize the unit: flush buffers, set root table, enable translation.
    pub fn init(&mut self, root_table_phys: u64) -> Result<()> {
        self.root_table_phys = root_table_phys;
        self.write_buffer_flush()?;
        self.set_root_table(root_table_phys)?;
        self.enable_translation()?;
        Ok(())
    }

    /// Issue a write buffer flush command.
    pub fn write_buffer_flush(&mut self) -> Result<()> {
        let cap = self.read64(REG_CAP);
        // Check if write buffer flush is required (bit 4 in CAP).
        if (cap & (1 << 4)) != 0 {
            self.write32(REG_GCMD, GCMD_WBF);
            let mut tries = 0u32;
            loop {
                if (self.read32(REG_GSTS) & GCMD_WBF) == 0 {
                    break;
                }
                tries += 1;
                if tries > 100_000 {
                    return Err(Error::Busy);
                }
                core::hint::spin_loop();
            }
        }
        Ok(())
    }

    /// Set the root table pointer.
    fn set_root_table(&mut self, phys: u64) -> Result<()> {
        self.write64(REG_RTADDR, phys);
        self.write32(REG_GCMD, GCMD_SRTP);
        let mut tries = 0u32;
        loop {
            if (self.read32(REG_GSTS) & GSTS_RTPS) != 0 {
                return Ok(());
            }
            tries += 1;
            if tries > 100_000 {
                return Err(Error::Busy);
            }
            core::hint::spin_loop();
        }
    }

    /// Enable DMA remapping.
    fn enable_translation(&mut self) -> Result<()> {
        self.write32(REG_GCMD, GCMD_TE);
        let mut tries = 0u32;
        loop {
            if (self.read32(REG_GSTS) & GSTS_TES) != 0 {
                self.te_enabled = true;
                return Ok(());
            }
            tries += 1;
            if tries > 100_000 {
                return Err(Error::Busy);
            }
            core::hint::spin_loop();
        }
    }

    /// Disable DMA remapping.
    pub fn disable_translation(&mut self) -> Result<()> {
        let gsts = self.read32(REG_GSTS);
        self.write32(REG_GCMD, gsts & !GCMD_TE);
        let mut tries = 0u32;
        loop {
            if (self.read32(REG_GSTS) & GSTS_TES) == 0 {
                self.te_enabled = false;
                return Ok(());
            }
            tries += 1;
            if tries > 100_000 {
                return Err(Error::Busy);
            }
            core::hint::spin_loop();
        }
    }

    /// Handle an IOMMU fault interrupt.
    pub fn handle_fault(&mut self) -> u32 {
        let fsts = self.read32(REG_FSTS);
        // Clear fault status by writing 1 to set bits.
        self.write32(REG_FSTS, fsts);
        fsts
    }

    /// Return the hardware version.
    pub fn version(&self) -> u32 {
        self.read32(REG_VER)
    }

    /// Return whether translation is enabled.
    pub fn is_te_enabled(&self) -> bool {
        self.te_enabled
    }

    // --- MMIO helpers ---

    fn read32(&self, offset: u32) -> u32 {
        let addr = (self.mmio_base + offset as usize) as *const u32;
        // SAFETY: mmio_base is a valid VT-d IOMMU MMIO region; all offsets
        // are 4-byte aligned within the 256-byte register space.
        unsafe { core::ptr::read_volatile(addr) }
    }

    fn read64(&self, offset: u32) -> u64 {
        let lo = self.read32(offset) as u64;
        let hi = self.read32(offset + 4) as u64;
        lo | (hi << 32)
    }

    fn write32(&mut self, offset: u32, val: u32) {
        let addr = (self.mmio_base + offset as usize) as *mut u32;
        // SAFETY: Volatile write to a hardware register in the VT-d MMIO space.
        unsafe { core::ptr::write_volatile(addr, val) }
    }

    fn write64(&mut self, offset: u32, val: u64) {
        self.write32(offset, (val & 0xFFFF_FFFF) as u32);
        self.write32(offset + 4, ((val >> 32) & 0xFFFF_FFFF) as u32);
    }
}

/// Intel IOMMU global driver managing all hardware units.
pub struct IntelIommu {
    /// Hardware units.
    units: [Option<IntelIommuUnit>; MAX_UNITS],
    /// Number of units.
    num_units: usize,
}

impl IntelIommu {
    /// Create a new IOMMU manager.
    pub const fn new() -> Self {
        Self {
            units: [const { None }; MAX_UNITS],
            num_units: 0,
        }
    }

    /// Register a hardware unit.
    pub fn add_unit(&mut self, unit: IntelIommuUnit) -> Result<()> {
        if self.num_units >= MAX_UNITS {
            return Err(Error::OutOfMemory);
        }
        self.units[self.num_units] = Some(unit);
        self.num_units += 1;
        Ok(())
    }

    /// Initialize all registered units.
    pub fn init_all(&mut self, root_table_phys: u64) -> Result<()> {
        for unit_opt in self.units[..self.num_units].iter_mut() {
            if let Some(unit) = unit_opt {
                unit.init(root_table_phys)?;
            }
        }
        Ok(())
    }

    /// Return the number of hardware units.
    pub fn num_units(&self) -> usize {
        self.num_units
    }
}

impl Default for IntelIommu {
    fn default() -> Self {
        Self::new()
    }
}
