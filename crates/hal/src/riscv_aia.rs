// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RISC-V Advanced Interrupt Architecture (AIA) support.
//!
//! The RISC-V AIA specification extends the basic PLIC model with:
//!
//! - **APLIC** — Advanced Platform-Level Interrupt Controller, which
//!   replaces the PLIC for wired interrupt delivery and adds MSI forwarding.
//! - **IMSIC** — Incoming Message Signaled Interrupt Controller, which
//!   handles MSI delivery to each hart via a dedicated MMIO page.
//!
//! This module implements APLIC domain initialization, source configuration,
//! and IMSIC interrupt file management.
//!
//! Reference: RISC-V AIA Specification (riscv-aia), Draft 1.0.

use oncrix_lib::{Error, Result};

// ── APLIC Register Offsets ─────────────────────────────────────────────────

/// Domain Configuration Register.
pub const APLIC_DOMAINCFG: u32 = 0x0000;
/// Source Configuration Registers base (one per interrupt source).
pub const APLIC_SOURCECFG: u32 = 0x0004;
/// Machine-level MSI Address Configuration Lo.
pub const APLIC_MMSICFGADDR: u32 = 0x1BC0;
/// Machine-level MSI Address Configuration Hi.
pub const APLIC_MMSICFGADDRH: u32 = 0x1BC4;
/// Interrupt Pending bits base (32 per register).
pub const APLIC_SETIPNUM: u32 = 0x1CDC;
/// Set Interrupt Enable base.
pub const APLIC_SETIENUM: u32 = 0x1EDC;
/// Interrupt Target Registers base.
pub const APLIC_TARGET: u32 = 0x3004;

// ── APLIC Domain Configuration bits ───────────────────────────────────────

/// IE (Interrupt Enable) bit in DOMAINCFG.
const APLIC_DOMAINCFG_IE: u32 = 1 << 8;
/// DM (Delivery Mode) MSI mode bit.
const APLIC_DOMAINCFG_DM: u32 = 1 << 2;

// ── Source Configuration values ────────────────────────────────────────────

/// Inactive — source is disabled.
pub const APLIC_SOURCECFG_INACTIVE: u32 = 0;
/// Detached — source exists but not forwarded.
pub const APLIC_SOURCECFG_DETACHED: u32 = 1;
/// Rising edge triggered.
pub const APLIC_SOURCECFG_EDGE_RISE: u32 = 4;
/// Falling edge triggered.
pub const APLIC_SOURCECFG_EDGE_FALL: u32 = 5;
/// Level high triggered.
pub const APLIC_SOURCECFG_LEVEL_HIGH: u32 = 6;
/// Level low triggered.
pub const APLIC_SOURCECFG_LEVEL_LOW: u32 = 7;

/// Maximum interrupt sources per APLIC domain.
const MAX_SOURCES: usize = 1023;
/// Maximum IMSIC interrupt files (harts) supported.
const MAX_IMSIC_FILES: usize = 16;

// ── MMIO helpers ───────────────────────────────────────────────────────────

/// Read a 32-bit register.
///
/// # Safety
/// `base + offset` must be a valid, mapped MMIO address.
#[inline]
unsafe fn read32(base: usize, offset: u32) -> u32 {
    // SAFETY: caller guarantees base+offset is valid MMIO.
    unsafe { core::ptr::read_volatile((base + offset as usize) as *const u32) }
}

/// Write a 32-bit register.
///
/// # Safety
/// `base + offset` must be a valid, mapped MMIO address.
#[inline]
unsafe fn write32(base: usize, offset: u32, val: u32) {
    // SAFETY: caller guarantees base+offset is valid MMIO.
    unsafe { core::ptr::write_volatile((base + offset as usize) as *mut u32, val) }
}

// ── APLIC Domain ───────────────────────────────────────────────────────────

/// APLIC domain controller.
pub struct AplicDomain {
    base: usize,
    num_sources: usize,
    msi_mode: bool,
}

impl AplicDomain {
    /// Create an APLIC domain handle.
    ///
    /// # Safety
    /// `base` must be the MMIO base address of a valid APLIC domain,
    /// mapped with device memory attributes. `num_sources` must not
    /// exceed the hardware's actual source count.
    pub unsafe fn new(base: usize, num_sources: usize, msi_mode: bool) -> Self {
        Self {
            base,
            num_sources: num_sources.min(MAX_SOURCES),
            msi_mode,
        }
    }

    /// Initialize the APLIC domain.
    pub fn init(&mut self) -> Result<()> {
        let mut cfg = APLIC_DOMAINCFG_IE;
        if self.msi_mode {
            cfg |= APLIC_DOMAINCFG_DM;
        }
        // SAFETY: self.base is valid MMIO.
        unsafe { write32(self.base, APLIC_DOMAINCFG, cfg) }
        Ok(())
    }

    /// Configure a source's trigger type.
    pub fn set_source_cfg(&mut self, source: u32, mode: u32) -> Result<()> {
        if source == 0 || source as usize > self.num_sources {
            return Err(Error::InvalidArgument);
        }
        let offset = APLIC_SOURCECFG + (source - 1) * 4;
        // SAFETY: offset within APLIC SOURCECFG range.
        unsafe { write32(self.base, offset, mode) }
        Ok(())
    }

    /// Enable a source by number.
    pub fn enable_source(&mut self, source: u32) -> Result<()> {
        if source == 0 || source as usize > self.num_sources {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: SETIENUM register.
        unsafe { write32(self.base, APLIC_SETIENUM, source) }
        Ok(())
    }

    /// Set the target hart index and priority for an interrupt source.
    pub fn set_target(&mut self, source: u32, hart: u32, priority: u32) -> Result<()> {
        if source == 0 || source as usize > self.num_sources {
            return Err(Error::InvalidArgument);
        }
        let offset = APLIC_TARGET + (source - 1) * 4;
        // Target register: hart_idx[18:12] | guest_idx[11:9] | iprio[7:0]
        let val = ((hart & 0x7F) << 18) | (priority & 0xFF);
        // SAFETY: offset within APLIC TARGET range.
        unsafe { write32(self.base, offset, val) }
        Ok(())
    }

    /// Configure the MSI address for machine-level delivery.
    pub fn set_msi_addr(&mut self, addr: u64) -> Result<()> {
        // SAFETY: MMSICFGADDR registers.
        unsafe {
            write32(self.base, APLIC_MMSICFGADDR, addr as u32);
            write32(self.base, APLIC_MMSICFGADDRH, (addr >> 32) as u32);
        }
        Ok(())
    }

    /// Inject an interrupt by source number (software trigger).
    pub fn inject(&mut self, source: u32) -> Result<()> {
        if source == 0 || source as usize > self.num_sources {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: SETIPNUM register.
        unsafe { write32(self.base, APLIC_SETIPNUM, source) }
        Ok(())
    }

    /// Query whether a source is pending.
    pub fn is_pending(&self, source: u32) -> bool {
        if source == 0 || source as usize > self.num_sources {
            return false;
        }
        let reg_idx = (source - 1) / 32;
        let bit = 1u32 << ((source - 1) % 32);
        // pending registers are at 0x1C00, 32 bits each
        let offset = 0x1C00 + reg_idx * 4;
        // SAFETY: offset within APLIC pending range.
        let val = unsafe { read32(self.base, offset) };
        val & bit != 0
    }
}

// ── IMSIC Interrupt File ───────────────────────────────────────────────────

/// IMSIC interrupt file for a single hart.
///
/// Each hart has one machine-level interrupt file. Writing an interrupt
/// identity to the `seteipnum_le` register triggers the corresponding
/// MSI at the hart.
pub struct ImsicFile {
    base: usize,
}

impl ImsicFile {
    /// Offset of the `seteipnum_le` register within a file page.
    const SETEIPNUM_LE: u32 = 0x00;
    /// Offset of `eithreshold` — enable threshold CSR mirror (write-only MMIO).
    const EITHRESHOLD: u32 = 0x18;

    /// Create an IMSIC interrupt file handle.
    ///
    /// # Safety
    /// `base` must be the MMIO base of a valid IMSIC interrupt file page
    /// (4 KiB, naturally aligned).
    pub unsafe fn new(base: usize) -> Self {
        Self { base }
    }

    /// Deliver an MSI with the given interrupt identity.
    pub fn deliver(&self, eiid: u32) {
        // SAFETY: seteipnum_le is a write-only trigger register.
        unsafe { write32(self.base, Self::SETEIPNUM_LE, eiid) }
    }

    /// Set the interrupt enable threshold.
    pub fn set_threshold(&self, threshold: u32) {
        // SAFETY: eithreshold within IMSIC file page.
        unsafe { write32(self.base, Self::EITHRESHOLD, threshold) }
    }
}

// ── AIA Controller ─────────────────────────────────────────────────────────

/// High-level RISC-V AIA interrupt controller.
pub struct RiscvAia {
    aplic: AplicDomain,
    imsic_files: [Option<ImsicFile>; MAX_IMSIC_FILES],
    imsic_count: usize,
}

impl RiscvAia {
    /// Create a new AIA controller.
    ///
    /// # Safety
    /// `aplic_base` must be valid MMIO for the APLIC domain.
    pub unsafe fn new(aplic_base: usize, num_sources: usize, msi_mode: bool) -> Self {
        // SAFETY: caller guarantees aplic_base valid.
        let aplic = unsafe { AplicDomain::new(aplic_base, num_sources, msi_mode) };
        Self {
            aplic,
            imsic_files: [const { None }; MAX_IMSIC_FILES],
            imsic_count: 0,
        }
    }

    /// Register an IMSIC interrupt file for a hart.
    ///
    /// # Safety
    /// `file_base` must be the MMIO base of the hart's IMSIC file page.
    pub unsafe fn add_imsic_file(&mut self, file_base: usize) -> Result<()> {
        if self.imsic_count >= MAX_IMSIC_FILES {
            return Err(Error::OutOfMemory);
        }
        // SAFETY: caller guarantees file_base valid.
        self.imsic_files[self.imsic_count] = Some(unsafe { ImsicFile::new(file_base) });
        self.imsic_count += 1;
        Ok(())
    }

    /// Initialize APLIC domain.
    pub fn init(&mut self) -> Result<()> {
        self.aplic.init()
    }

    /// Enable an interrupt source with default edge-rise trigger.
    pub fn enable_source(&mut self, source: u32) -> Result<()> {
        self.aplic
            .set_source_cfg(source, APLIC_SOURCECFG_EDGE_RISE)?;
        self.aplic.enable_source(source)?;
        self.aplic.set_target(source, 0, 1)?;
        Ok(())
    }

    /// Deliver an MSI to a specific hart.
    pub fn send_msi(&self, hart: usize, eiid: u32) -> Result<()> {
        if hart >= self.imsic_count {
            return Err(Error::InvalidArgument);
        }
        if let Some(ref f) = self.imsic_files[hart] {
            f.deliver(eiid);
        }
        Ok(())
    }
}
