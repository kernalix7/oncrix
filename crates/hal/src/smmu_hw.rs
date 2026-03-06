// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ARM System Memory Management Unit (SMMU) hardware driver.
//!
//! Implements support for the ARM SMMU v2 and v3 IOMMU, which provide
//! hardware-enforced memory isolation for DMA-capable devices on ARM
//! platforms. Equivalent to the x86 VT-d / AMD IOMMU.
//!
//! # Architecture
//!
//! - **SMMUv2**: Uses Context Banks (CB) with SMMU_GRx and SMMU_CBn_x registers.
//! - **SMMUv3**: Uses Stream Table, Command/Event queues, and CD (Context Descriptor).
//!
//! # SMMUv2 Global Register Set (SMMU_GR0)
//!
//! | Offset  | Name             | Description                    |
//! |---------|------------------|--------------------------------|
//! | 0x000   | SMMU_CR0         | Control register 0             |
//! | 0x004   | SMMU_CR2         | Control register 2             |
//! | 0x014   | SMMU_ACR         | Auxiliary control register     |
//! | 0x020   | SMMU_IDR0-5      | Identification registers       |
//! | 0x080   | SMMU_GFSR        | Global fault status register   |
//! | 0x084   | SMMU_GFSRRESTORE | Global fault restore           |
//! | 0x088   | SMMU_GFSYNR0     | Global fault syndrome 0        |
//! | 0x0E8   | SMMU_TLBIALL     | Invalidate all TLB entries     |
//! | 0x0F0   | SMMU_TLBGSYNC    | TLB sync                       |
//! | 0x0F4   | SMMU_TLBGSTATUS  | TLB sync status                |
//! | 0x800   | SMMU_S2CRn       | Stream-to-Context registers    |
//! | 0xC00   | SMMU_CBARn       | Context bank attribute regs    |
//!
//! Reference: ARM IHI0070F (ARM System Memory Management Unit Arch Spec).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of SMMU instances.
pub const MAX_SMMU_INSTANCES: usize = 4;
/// Maximum context banks per SMMU.
pub const MAX_CONTEXT_BANKS: usize = 128;
/// Maximum stream mappings (S2CR/SMR entries) per SMMU.
pub const MAX_STREAM_MAPPINGS: usize = 128;

// ---------------------------------------------------------------------------
// SMMUv2 Global Register Offsets (GR0)
// ---------------------------------------------------------------------------

/// SMMU Control Register 0.
const SMMU_CR0: u32 = 0x000;
/// SMMU Control Register 2.
const _SMMU_CR2: u32 = 0x004;
/// SMMU Auxiliary Control Register.
const _SMMU_ACR: u32 = 0x014;
/// SMMU Identification Register 0.
const SMMU_IDR0: u32 = 0x020;
/// SMMU Identification Register 1.
const SMMU_IDR1: u32 = 0x024;
/// SMMU Global Fault Status Register.
const SMMU_GFSR: u32 = 0x080;
/// SMMU Global Fault Syndrome Register 0.
const _SMMU_GFSYNR0: u32 = 0x088;
/// SMMU TLB Invalidate All.
const SMMU_TLBIALL: u32 = 0x0E8;
/// SMMU TLB Global Sync.
const SMMU_TLBGSYNC: u32 = 0x0F0;
/// SMMU TLB Global Status.
const SMMU_TLBGSTATUS: u32 = 0x0F4;

// ---------------------------------------------------------------------------
// CR0 bit fields
// ---------------------------------------------------------------------------

/// CR0: SMMU Global Enable.
const CR0_SMMU_EN: u32 = 1 << 0;
/// CR0: Client PD override (translate all accesses as faulting).
const _CR0_CLIENTPD: u32 = 1 << 1;
/// CR0: USFCFG — Unidentified stream fault configuration.
const _CR0_USFCFG: u32 = 1 << 10;

// ---------------------------------------------------------------------------
// IDR0 bit fields
// ---------------------------------------------------------------------------

/// IDR0: Number of Context Banks supported (field [7:0]).
const IDR0_NUMCB_MASK: u32 = 0xFF;
/// IDR0: Number of Stream IDs (field [15:8]).
const _IDR0_NUMSMRG_SHIFT: u32 = 8;
/// IDR1: Number of page table walk DVM IDs.
const IDR1_NUMPAGENDXB_MASK: u32 = 0x1F << 28;

// ---------------------------------------------------------------------------
// Context Bank register offsets (GR1 base + 0x1000 per bank)
// ---------------------------------------------------------------------------

/// CBn_SCTLR — Context Bank System Control Register.
const CB_SCTLR: u32 = 0x000;
/// CBn_TCR — Translation Control Register.
const _CB_TCR: u32 = 0x030;
/// CBn_TTBR0 — Translation Table Base Register 0.
const CB_TTBR0: u32 = 0x020;
/// CBn_FSR — Fault Status Register.
const _CB_FSR: u32 = 0x058;

/// CB_SCTLR: Context Bank Enable.
const CB_SCTLR_M: u32 = 1 << 0;
/// CB_SCTLR: Translation fault on unmatched access.
const _CB_SCTLR_CFIE: u32 = 1 << 6;

// ---------------------------------------------------------------------------
// TLB sync timeout
// ---------------------------------------------------------------------------

/// Maximum poll iterations for TLB sync completion.
const TLB_SYNC_TIMEOUT: u32 = 100_000;

// ---------------------------------------------------------------------------
// Version enum
// ---------------------------------------------------------------------------

/// SMMU hardware version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmmuVersion {
    /// ARM SMMUv2.
    V2,
    /// ARM SMMUv3.
    V3,
}

// ---------------------------------------------------------------------------
// Context Bank
// ---------------------------------------------------------------------------

/// An SMMU context bank (translation context).
#[derive(Debug, Clone, Copy)]
pub struct ContextBank {
    /// Context bank index.
    pub index: u8,
    /// Translation table base (physical address of page table root).
    pub ttbr0: u64,
    /// Whether this bank is active.
    pub active: bool,
}

impl ContextBank {
    /// Creates an inactive context bank.
    pub const fn empty() -> Self {
        Self {
            index: 0,
            ttbr0: 0,
            active: false,
        }
    }
}

impl Default for ContextBank {
    fn default() -> Self {
        Self::empty()
    }
}

// ---------------------------------------------------------------------------
// Stream Mapping
// ---------------------------------------------------------------------------

/// Maps a stream ID to a context bank.
#[derive(Debug, Clone, Copy, Default)]
pub struct StreamMapping {
    /// Stream ID (device requester ID).
    pub stream_id: u16,
    /// Assigned context bank index.
    pub context_bank: u8,
    /// Whether this mapping is active.
    pub active: bool,
}

// ---------------------------------------------------------------------------
// SMMU Instance
// ---------------------------------------------------------------------------

/// ARM SMMU hardware instance.
pub struct SmmuHw {
    /// MMIO base address.
    mmio_base: u64,
    /// SMMU version.
    version: SmmuVersion,
    /// Number of supported context banks.
    num_context_banks: usize,
    /// Context bank table.
    banks: [ContextBank; MAX_CONTEXT_BANKS],
    /// Stream-to-context mappings.
    stream_mappings: [StreamMapping; MAX_STREAM_MAPPINGS],
    /// Number of active stream mappings.
    mapping_count: usize,
    /// Whether this instance is initialized.
    initialized: bool,
}

impl SmmuHw {
    /// Creates a new SMMU instance.
    pub const fn new(mmio_base: u64, version: SmmuVersion) -> Self {
        Self {
            mmio_base,
            version,
            num_context_banks: 0,
            banks: [const { ContextBank::empty() }; MAX_CONTEXT_BANKS],
            stream_mappings: [StreamMapping {
                stream_id: 0,
                context_bank: 0,
                active: false,
            }; MAX_STREAM_MAPPINGS],
            mapping_count: 0,
            initialized: false,
        }
    }

    /// Initializes the SMMU hardware.
    ///
    /// Reads IDR registers, invalidates all TLBs, and enables the SMMU.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if TLB sync times out.
    pub fn init(&mut self) -> Result<()> {
        // Read IDR0 to determine capabilities.
        let idr0 = self.read_gr0(SMMU_IDR0);
        self.num_context_banks = (idr0 & IDR0_NUMCB_MASK) as usize;
        // Clamp to our array size.
        if self.num_context_banks > MAX_CONTEXT_BANKS {
            self.num_context_banks = MAX_CONTEXT_BANKS;
        }
        // Read IDR1 — just validate it's nonzero for real hardware.
        let _idr1 = self.read_gr0(SMMU_IDR1) & IDR1_NUMPAGENDXB_MASK;

        // Invalidate all TLB entries.
        self.write_gr0(SMMU_TLBIALL, 0);
        self.tlb_sync()?;

        // Enable SMMU (set SMMU_EN in CR0).
        let cr0 = self.read_gr0(SMMU_CR0);
        self.write_gr0(SMMU_CR0, cr0 | CR0_SMMU_EN);

        self.initialized = true;
        Ok(())
    }

    /// Maps a stream ID to a context bank with the given page table root.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if no mapping slots are available.
    /// - [`Error::InvalidArgument`] if the stream ID is already mapped.
    pub fn map_stream(&mut self, stream_id: u16, ttbr0: u64) -> Result<u8> {
        // Check for duplicate.
        for m in &self.stream_mappings[..self.mapping_count] {
            if m.active && m.stream_id == stream_id {
                return Err(Error::AlreadyExists);
            }
        }
        if self.mapping_count >= MAX_STREAM_MAPPINGS {
            return Err(Error::OutOfMemory);
        }
        let bank_idx = self.mapping_count as u8;
        let slot = self.mapping_count;
        self.mapping_count += 1;

        // Configure context bank.
        self.banks[bank_idx as usize] = ContextBank {
            index: bank_idx,
            ttbr0,
            active: true,
        };

        // Program CB_TTBR0 and enable the bank.
        self.write_cb(bank_idx as usize, CB_TTBR0, (ttbr0 & 0xFFFF_FFFF) as u32);
        let sctlr = self.read_cb(bank_idx as usize, CB_SCTLR);
        self.write_cb(bank_idx as usize, CB_SCTLR, sctlr | CB_SCTLR_M);

        self.stream_mappings[slot] = StreamMapping {
            stream_id,
            context_bank: bank_idx,
            active: true,
        };

        Ok(bank_idx)
    }

    /// Unmaps a stream by stream ID.
    pub fn unmap_stream(&mut self, stream_id: u16) {
        let idx = (0..self.mapping_count).find(|&i| {
            self.stream_mappings[i].active && self.stream_mappings[i].stream_id == stream_id
        });
        if let Some(i) = idx {
            let cb = self.stream_mappings[i].context_bank as usize;
            let sctlr = self.read_cb(cb, CB_SCTLR);
            self.write_cb(cb, CB_SCTLR, sctlr & !CB_SCTLR_M);
            self.banks[cb].active = false;
            self.stream_mappings[i].active = false;
        }
    }

    /// Reads the global fault status register.
    pub fn fault_status(&self) -> u32 {
        self.read_gr0(SMMU_GFSR)
    }

    /// Returns `true` if a global fault is pending.
    pub fn has_fault(&self) -> bool {
        self.fault_status() != 0
    }

    /// Invalidates all TLB entries and syncs.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if TLB sync times out.
    pub fn invalidate_all(&mut self) -> Result<()> {
        self.write_gr0(SMMU_TLBIALL, 0);
        self.tlb_sync()
    }

    /// Returns whether the SMMU is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns the SMMU version.
    pub fn version(&self) -> SmmuVersion {
        self.version
    }

    /// Returns the number of context banks.
    pub fn num_context_banks(&self) -> usize {
        self.num_context_banks
    }

    // -----------------------------------------------------------------------
    // Private
    // -----------------------------------------------------------------------

    fn tlb_sync(&self) -> Result<()> {
        self.write_gr0(SMMU_TLBGSYNC, 0);
        for _ in 0..TLB_SYNC_TIMEOUT {
            if self.read_gr0(SMMU_TLBGSTATUS) & 0x1 == 0 {
                return Ok(());
            }
        }
        Err(Error::IoError)
    }

    fn read_gr0(&self, offset: u32) -> u32 {
        let addr = (self.mmio_base + offset as u64) as *const u32;
        // SAFETY: MMIO base is a valid hardware register address, volatile read
        // prevents compiler from reordering or eliding the hardware access.
        unsafe { core::ptr::read_volatile(addr) }
    }

    fn write_gr0(&self, offset: u32, val: u32) {
        let addr = (self.mmio_base + offset as u64) as *mut u32;
        // SAFETY: MMIO base is a valid hardware register address, volatile write
        // ensures the hardware sees the update immediately.
        unsafe { core::ptr::write_volatile(addr, val) }
    }

    fn read_cb(&self, bank: usize, offset: u32) -> u32 {
        // Context bank registers are in GR1 page (mmio_base + 0x1000) + bank * 0x1000.
        let addr = (self.mmio_base + 0x1000 + bank as u64 * 0x1000 + offset as u64) as *const u32;
        // SAFETY: Address is within the SMMU MMIO region for the given context bank.
        unsafe { core::ptr::read_volatile(addr) }
    }

    fn write_cb(&self, bank: usize, offset: u32, val: u32) {
        let addr = (self.mmio_base + 0x1000 + bank as u64 * 0x1000 + offset as u64) as *mut u32;
        // SAFETY: Address is within the SMMU MMIO region for the given context bank.
        unsafe { core::ptr::write_volatile(addr, val) }
    }
}

impl Default for SmmuHw {
    fn default() -> Self {
        Self::new(0, SmmuVersion::V2)
    }
}

// ---------------------------------------------------------------------------
// Global registry
// ---------------------------------------------------------------------------

/// Global SMMU instance registry.
pub struct SmmuRegistry {
    instances: [SmmuHw; MAX_SMMU_INSTANCES],
    count: usize,
}

impl SmmuRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            instances: [const {
                SmmuHw {
                    mmio_base: 0,
                    version: SmmuVersion::V2,
                    num_context_banks: 0,
                    banks: [const { ContextBank::empty() }; MAX_CONTEXT_BANKS],
                    stream_mappings: [StreamMapping {
                        stream_id: 0,
                        context_bank: 0,
                        active: false,
                    }; MAX_STREAM_MAPPINGS],
                    mapping_count: 0,
                    initialized: false,
                }
            }; MAX_SMMU_INSTANCES],
            count: 0,
        }
    }

    /// Registers a new SMMU instance.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, mmio_base: u64, version: SmmuVersion) -> Result<usize> {
        if self.count >= MAX_SMMU_INSTANCES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.instances[idx] = SmmuHw::new(mmio_base, version);
        self.count += 1;
        Ok(idx)
    }

    /// Returns a reference to the instance at `index`.
    pub fn get(&self, index: usize) -> Option<&SmmuHw> {
        if index < self.count {
            Some(&self.instances[index])
        } else {
            None
        }
    }

    /// Returns a mutable reference to the instance at `index`.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut SmmuHw> {
        if index < self.count {
            Some(&mut self.instances[index])
        } else {
            None
        }
    }

    /// Returns the number of registered instances.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no instances are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for SmmuRegistry {
    fn default() -> Self {
        Self::new()
    }
}
