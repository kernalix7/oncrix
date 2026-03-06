// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IOMMU hardware base abstraction (Intel VT-d / AMD-Vi unified interface).
//!
//! Provides a common interface for IOMMU hardware programming.  This module
//! sits below the higher-level `iommu.rs` (which handles ACPI table discovery
//! and page table management) and exposes raw register access patterns.
//!
//! # Supported hardware
//!
//! - Intel Virtualization Technology for Directed I/O (VT-d)
//! - AMD I/O Memory Management Unit (AMD-Vi / IOMMU)
//!
//! # IOMMU roles
//!
//! 1. **DMA remapping** — translate device I/O virtual addresses to physical
//!    addresses, preventing rogue DMA.
//! 2. **Interrupt remapping** — isolate per-VM interrupt delivery.
//! 3. **Scalable/pasid mode** — per-process address space isolation (SRIOV).
//!
//! Reference: Intel VT-d Architecture Specification Rev 4.1;
//! AMD I/O Virtualization Technology (IOMMU) Specification Rev 3.05.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Intel VT-d MMIO Register Offsets
// ---------------------------------------------------------------------------

/// VT-d Version register (32-bit, RO).
pub const VTD_REG_VER: u32 = 0x000;
/// VT-d Capability register (64-bit, RO).
pub const VTD_REG_CAP: u32 = 0x008;
/// VT-d Extended Capability register (64-bit, RO).
pub const VTD_REG_ECAP: u32 = 0x010;
/// VT-d Global Command register (32-bit, RW).
pub const VTD_REG_GCMD: u32 = 0x018;
/// VT-d Global Status register (32-bit, RO).
pub const VTD_REG_GSTS: u32 = 0x01C;
/// VT-d Root Table Address register (64-bit, RW).
pub const VTD_REG_RTADDR: u32 = 0x020;
/// VT-d Context Command register (64-bit, RW).
pub const VTD_REG_CCMD: u32 = 0x028;
/// VT-d Fault Status register (32-bit, RW1C).
pub const VTD_REG_FSTS: u32 = 0x034;
/// VT-d Fault Event Control register (32-bit, RW).
pub const VTD_REG_FECTL: u32 = 0x038;
/// VT-d IOTLB Invalidation register (64-bit, RW).
pub const VTD_REG_IOTLB_IVLD: u32 = 0x108;

// ---------------------------------------------------------------------------
// Intel VT-d Global Command bits
// ---------------------------------------------------------------------------

/// GCMD: Translation Enable.
pub const VTD_GCMD_TE: u32 = 1 << 31;
/// GCMD: Root Table Pointer valid.
pub const VTD_GCMD_SRTP: u32 = 1 << 30;
/// GCMD: Flush Write Buffer.
pub const VTD_GCMD_WBF: u32 = 1 << 27;
/// GCMD: Interrupt Remapping Enable.
pub const VTD_GCMD_IRE: u32 = 1 << 25;

// ---------------------------------------------------------------------------
// Intel VT-d Global Status bits
// ---------------------------------------------------------------------------

/// GSTS: Translation Enable Status.
pub const VTD_GSTS_TES: u32 = 1 << 31;
/// GSTS: Root Table Pointer Status.
pub const VTD_GSTS_RTPS: u32 = 1 << 30;
/// GSTS: Write Buffer Flush Status.
pub const VTD_GSTS_WBFS: u32 = 1 << 27;
/// GSTS: Interrupt Remapping Enable Status.
pub const VTD_GSTS_IRES: u32 = 1 << 25;

// ---------------------------------------------------------------------------
// AMD-Vi MMIO Register Offsets
// ---------------------------------------------------------------------------

/// AMD-Vi Device Table Base Address register (64-bit, RW).
pub const AMDIOMMU_REG_DEVTBL_BASE: u32 = 0x000;
/// AMD-Vi Command Buffer Base Address register (64-bit, RW).
pub const AMDIOMMU_REG_CMDBUF_BASE: u32 = 0x008;
/// AMD-Vi Event Log Base Address register (64-bit, RW).
pub const AMDIOMMU_REG_EVTLOG_BASE: u32 = 0x010;
/// AMD-Vi Control register (64-bit, RW).
pub const AMDIOMMU_REG_CTRL: u32 = 0x018;
/// AMD-Vi Exclusion Base register (64-bit, RW).
pub const AMDIOMMU_REG_EXCL_BASE: u32 = 0x020;
/// AMD-Vi Status register (64-bit, RW1C).
pub const AMDIOMMU_REG_STATUS: u32 = 0x2020;

// ---------------------------------------------------------------------------
// AMD-Vi Control register bits
// ---------------------------------------------------------------------------

/// CTRL: IOMMU Enable.
pub const AMDIOMMU_CTRL_IOMMU_EN: u64 = 1 << 0;
/// CTRL: Event Log Enable.
pub const AMDIOMMU_CTRL_EVT_EN: u64 = 1 << 1;
/// CTRL: Event Interrupt Enable.
pub const AMDIOMMU_CTRL_EVT_INT_EN: u64 = 1 << 2;
/// CTRL: Command Buffer Enable.
pub const AMDIOMMU_CTRL_CMDBUF_EN: u64 = 1 << 12;

// ---------------------------------------------------------------------------
// Spin limit
// ---------------------------------------------------------------------------

const STATUS_WAIT_ITERS: u32 = 100_000;

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

/// Read a 32-bit MMIO register.
///
/// # Safety
///
/// `base` must be a valid IOMMU MMIO region and `offset` a valid register.
unsafe fn read32(base: u64, offset: u32) -> u32 {
    // SAFETY: Volatile read from IOMMU MMIO region.
    unsafe { core::ptr::read_volatile((base + offset as u64) as *const u32) }
}

/// Write a 32-bit value to an MMIO register.
///
/// # Safety
///
/// Same as [`read32`].
unsafe fn write32(base: u64, offset: u32, val: u32) {
    // SAFETY: Volatile write to IOMMU MMIO region.
    unsafe { core::ptr::write_volatile((base + offset as u64) as *mut u32, val) }
}

/// Read a 64-bit MMIO register.
///
/// # Safety
///
/// Same as [`read32`].
unsafe fn read64(base: u64, offset: u32) -> u64 {
    // SAFETY: Volatile read from IOMMU MMIO region.
    unsafe { core::ptr::read_volatile((base + offset as u64) as *const u64) }
}

/// Write a 64-bit value to an MMIO register.
///
/// # Safety
///
/// Same as [`read32`].
unsafe fn write64(base: u64, offset: u32, val: u64) {
    // SAFETY: Volatile write to IOMMU MMIO region.
    unsafe { core::ptr::write_volatile((base + offset as u64) as *mut u64, val) }
}

// ---------------------------------------------------------------------------
// IommuKind
// ---------------------------------------------------------------------------

/// IOMMU hardware variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IommuKind {
    /// Intel VT-d.
    IntelVtd,
    /// AMD I/O Memory Management Unit.
    AmdVi,
}

// ---------------------------------------------------------------------------
// IommuHw
// ---------------------------------------------------------------------------

/// Low-level IOMMU hardware register interface.
pub struct IommuHw {
    /// MMIO base address.
    base: u64,
    /// Hardware variant.
    kind: IommuKind,
}

impl IommuHw {
    /// Create a new [`IommuHw`] instance.
    pub const fn new(base: u64, kind: IommuKind) -> Self {
        Self { base, kind }
    }

    /// Return the IOMMU variant.
    pub const fn kind(&self) -> IommuKind {
        self.kind
    }

    /// Return the MMIO base address.
    pub const fn base(&self) -> u64 {
        self.base
    }

    // ---- Intel VT-d specific -----------------------------------------------

    /// Read VT-d Capability register (64-bit).
    pub fn vtd_capabilities(&self) -> Result<u64> {
        if self.kind != IommuKind::IntelVtd {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: VT-d CAP register read from valid MMIO base.
        Ok(unsafe { read64(self.base, VTD_REG_CAP) })
    }

    /// Enable VT-d DMA remapping.
    pub fn vtd_enable_translation(&self) -> Result<()> {
        if self.kind != IommuKind::IntelVtd {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: Writing VT-d GCMD to enable DMA remapping.
        unsafe {
            let gsts = read32(self.base, VTD_REG_GSTS);
            if (gsts & VTD_GSTS_RTPS) == 0 {
                return Err(Error::IoError);
            }
            write32(self.base, VTD_REG_GCMD, VTD_GCMD_TE);
        }
        // Wait for TES to be set
        for _ in 0..STATUS_WAIT_ITERS {
            // SAFETY: Reading VT-d GSTS register.
            let gsts = unsafe { read32(self.base, VTD_REG_GSTS) };
            if (gsts & VTD_GSTS_TES) != 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Disable VT-d DMA remapping.
    pub fn vtd_disable_translation(&self) -> Result<()> {
        if self.kind != IommuKind::IntelVtd {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: Clearing TE bit in VT-d GCMD.
        unsafe {
            let gcmd = read32(self.base, VTD_REG_GSTS) & !VTD_GCMD_TE;
            write32(self.base, VTD_REG_GCMD, gcmd);
        }
        Ok(())
    }

    /// Set the VT-d root table pointer and issue SRTP command.
    pub fn vtd_set_root_table(&self, phys_addr: u64) -> Result<()> {
        if self.kind != IommuKind::IntelVtd {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: Writing root table address and SRTP command to VT-d.
        unsafe {
            write64(self.base, VTD_REG_RTADDR, phys_addr);
            let gsts = read32(self.base, VTD_REG_GSTS);
            write32(self.base, VTD_REG_GCMD, gsts | VTD_GCMD_SRTP);
        }
        // Wait for RTPS
        for _ in 0..STATUS_WAIT_ITERS {
            // SAFETY: Reading VT-d GSTS.
            let gsts = unsafe { read32(self.base, VTD_REG_GSTS) };
            if (gsts & VTD_GSTS_RTPS) != 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Issue a VT-d context cache global invalidation.
    pub fn vtd_invalidate_context_cache(&self) -> Result<()> {
        if self.kind != IommuKind::IntelVtd {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: Writing context invalidation command to VT-d.
        // Global invalidate: bit 63 = Invalidate Context Cache, bits 1:0 = 01 (global).
        let ccmd: u64 = (1u64 << 63) | 0x01;
        unsafe { write64(self.base, VTD_REG_CCMD, ccmd) };
        // Wait for ICC bit to clear
        for _ in 0..STATUS_WAIT_ITERS {
            // SAFETY: Reading VT-d CCMD status bit.
            let v = unsafe { read64(self.base, VTD_REG_CCMD) };
            if (v >> 63) == 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Flush the VT-d write buffer.
    pub fn vtd_flush_write_buffer(&self) -> Result<()> {
        if self.kind != IommuKind::IntelVtd {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: Issuing write buffer flush to VT-d.
        unsafe {
            let gsts = read32(self.base, VTD_REG_GSTS);
            write32(self.base, VTD_REG_GCMD, gsts | VTD_GCMD_WBF);
        }
        for _ in 0..STATUS_WAIT_ITERS {
            // SAFETY: Reading VT-d GSTS to check WBF completion.
            let gsts = unsafe { read32(self.base, VTD_REG_GSTS) };
            if (gsts & VTD_GSTS_WBFS) == 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    // ---- AMD-Vi specific ---------------------------------------------------

    /// Read AMD-Vi Control register.
    pub fn amdvi_control(&self) -> Result<u64> {
        if self.kind != IommuKind::AmdVi {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: Reading AMD-Vi control register from valid MMIO base.
        Ok(unsafe { read64(self.base, AMDIOMMU_REG_CTRL) })
    }

    /// Enable AMD-Vi IOMMU translation.
    pub fn amdvi_enable(&self) -> Result<()> {
        if self.kind != IommuKind::AmdVi {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: Writing AMD-Vi control register to enable IOMMU.
        unsafe {
            let ctrl = read64(self.base, AMDIOMMU_REG_CTRL);
            write64(self.base, AMDIOMMU_REG_CTRL, ctrl | AMDIOMMU_CTRL_IOMMU_EN);
        }
        Ok(())
    }

    /// Disable AMD-Vi IOMMU translation.
    pub fn amdvi_disable(&self) -> Result<()> {
        if self.kind != IommuKind::AmdVi {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: Clearing IOMMU enable bit in AMD-Vi control register.
        unsafe {
            let ctrl = read64(self.base, AMDIOMMU_REG_CTRL);
            write64(self.base, AMDIOMMU_REG_CTRL, ctrl & !AMDIOMMU_CTRL_IOMMU_EN);
        }
        Ok(())
    }

    /// Set the AMD-Vi device table base address.
    pub fn amdvi_set_device_table(&self, phys_addr: u64, size_bits: u8) -> Result<()> {
        if self.kind != IommuKind::AmdVi {
            return Err(Error::InvalidArgument);
        }
        if size_bits > 7 {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: Writing device table base and size to AMD-Vi register.
        let reg_val = (phys_addr & !0xFFF) | size_bits as u64;
        unsafe { write64(self.base, AMDIOMMU_REG_DEVTBL_BASE, reg_val) };
        Ok(())
    }
}
