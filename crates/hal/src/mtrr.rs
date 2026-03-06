// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory Type Range Registers (MTRR).
//!
//! MTRRs define the caching behaviour for physical memory regions.
//! They are configured through x86 MSRs and apply to physical addresses
//! before the processor's page-table PAT overrides.
//!
//! # Register layout
//!
//! | MSR | Description |
//! |-----|-------------|
//! | `IA32_MTRR_CAP` (0xFE) | Read-only capabilities |
//! | `IA32_MTRR_DEF_TYPE` (0x2FF) | Default type + enable bits |
//! | `IA32_MTRR_FIX64K_00000` (0x250) | Fixed 64 KiB range 0–512 KiB |
//! | `IA32_MTRR_FIX16K_80000` (0x258) | Fixed 16 KiB ranges |
//! | `IA32_MTRR_FIX4K_C0000`..`0x26F` | Fixed 4 KiB ranges |
//! | `IA32_MTRR_PHYSBASEn` / `PHYSMASKn` | Variable ranges |

use oncrix_lib::{Error, Result};

// ── MSR addresses ────────────────────────────────────────────────────────────

/// IA32_MTRR_CAP MSR — capabilities (read-only).
const MSR_MTRR_CAP: u32 = 0xFE;

/// IA32_MTRR_DEF_TYPE MSR — default memory type + enable flags.
const MSR_MTRR_DEF_TYPE: u32 = 0x2FF;

/// IA32_MTRR_FIX64K_00000 — fixed range for 0–512 KiB (64 KiB granule).
const MSR_MTRR_FIX64K: u32 = 0x250;

/// IA32_MTRR_FIX16K_80000 — fixed range for 512 KiB–640 KiB (16 KiB granule).
const MSR_MTRR_FIX16K_80000: u32 = 0x258;

/// IA32_MTRR_FIX16K_A0000 — fixed range for 640 KiB–768 KiB.
const MSR_MTRR_FIX16K_A0000: u32 = 0x259;

/// First IA32_MTRR_FIX4K MSR (0xC0000–0xFFFFF in 4 KiB sub-ranges).
const MSR_MTRR_FIX4K_BASE: u32 = 0x268;

/// IA32_MTRR_PHYSBASEn base MSR (pairs: BASE at 2n, MASK at 2n+1).
const MSR_MTRR_PHYSBASE0: u32 = 0x200;

/// Maximum variable MTRR pairs we handle.
const MAX_VARIABLE_MTRR: usize = 16;

// ── Bit fields ───────────────────────────────────────────────────────────────

/// MTRR_CAP: number of variable MTRR pairs (bits 7:0).
const MTRR_CAP_VCNT_MASK: u64 = 0xFF;

/// MTRR_CAP: fixed-range MTRR supported (bit 8).
const MTRR_CAP_FIX: u64 = 1 << 8;

/// MTRR_CAP: write-combining memory type supported (bit 10).
const MTRR_CAP_WC: u64 = 1 << 10;

/// MTRR_DEF_TYPE: default memory type (bits 2:0).
const MTRR_DEF_TYPE_MASK: u64 = 0x7;

/// MTRR_DEF_TYPE: fixed MTRRs enable (bit 10).
const MTRR_DEF_FIXED_ENABLE: u64 = 1 << 10;

/// MTRR_DEF_TYPE: MTRR enable (bit 11).
const MTRR_DEF_ENABLE: u64 = 1 << 11;

/// PHYSMASK: valid bit (bit 11).
const PHYSMASK_VALID: u64 = 1 << 11;

/// Bits 11:0 of PHYSBASE are reserved (type in bits 7:0, bits 11:8 reserved).
const PHYSBASE_TYPE_MASK: u64 = 0xFF;

/// Physical address mask for PHYSBASE (bits above 11 are the base address).
const PHYSBASE_ADDR_MASK: u64 = !0xFFF;

// ── MtrrType ─────────────────────────────────────────────────────────────────

/// Memory type encoded in MTRR registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MtrrType {
    /// Uncacheable — all reads/writes bypass cache.
    Uc = 0,
    /// Write-Combining — writes combined in buffers before writeback.
    Wc = 1,
    /// Write-Through — reads cached; writes update cache and memory.
    Wt = 4,
    /// Write-Protected — reads cached; writes cause exception.
    Wp = 5,
    /// Write-Back — fully cacheable; writes update cache only.
    Wb = 6,
}

impl MtrrType {
    /// Decode from a raw 3-bit field.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for unknown encodings.
    pub fn from_raw(v: u8) -> Result<Self> {
        match v & 0x7 {
            0 => Ok(Self::Uc),
            1 => Ok(Self::Wc),
            4 => Ok(Self::Wt),
            5 => Ok(Self::Wp),
            6 => Ok(Self::Wb),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Return the raw 3-bit encoding.
    pub fn as_raw(self) -> u8 {
        self as u8
    }
}

// ── MtrrFixedRange ───────────────────────────────────────────────────────────

/// A fixed MTRR range descriptor.
#[derive(Debug, Clone, Copy)]
pub struct MtrrFixedRange {
    /// MSR address for this fixed range.
    pub msr: u32,
    /// Physical start address of this range.
    pub base: u64,
    /// Granule size in bytes (4 KiB / 16 KiB / 64 KiB).
    pub granule: u64,
    /// Raw 64-bit MSR value (8 sub-ranges × 8-bit type).
    pub raw: u64,
}

impl MtrrFixedRange {
    /// Return the memory type for the sub-range at `offset` (0–7).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if offset > 7 or the encoded
    /// type is unrecognised.
    pub fn get_type(&self, offset: usize) -> Result<MtrrType> {
        if offset > 7 {
            return Err(Error::InvalidArgument);
        }
        let byte = ((self.raw >> (offset * 8)) & 0xFF) as u8;
        MtrrType::from_raw(byte)
    }

    /// Set the memory type for the sub-range at `offset` (0–7).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if offset > 7.
    pub fn set_type(&mut self, offset: usize, mtype: MtrrType) -> Result<()> {
        if offset > 7 {
            return Err(Error::InvalidArgument);
        }
        let shift = offset * 8;
        self.raw &= !(0xFF << shift);
        self.raw |= (mtype.as_raw() as u64) << shift;
        Ok(())
    }
}

// ── MtrrVariableRange ────────────────────────────────────────────────────────

/// A variable-range MTRR pair (PHYSBASEn / PHYSMASKn).
#[derive(Debug, Clone, Copy)]
pub struct MtrrVariableRange {
    /// Variable MTRR index (0-based).
    pub index: u8,
    /// Physical base address (page-aligned).
    pub base: u64,
    /// Physical mask (page-aligned; describes range size).
    pub mask: u64,
    /// Memory type for this range.
    pub mtype: MtrrType,
    /// Whether this MTRR is active.
    pub valid: bool,
}

impl MtrrVariableRange {
    /// Return the size of this range in bytes.
    ///
    /// Computed as `~mask + 1` masked to 52 physical address bits.
    pub fn size(&self) -> u64 {
        let inverted = (!self.mask) & 0x000F_FFFF_FFFF_F000;
        inverted + 1
    }
}

// ── MtrrCapabilities ─────────────────────────────────────────────────────────

/// Capabilities read from IA32_MTRR_CAP.
#[derive(Debug, Clone, Copy)]
pub struct MtrrCapabilities {
    /// Number of variable MTRR pairs.
    pub vcnt: u8,
    /// Whether fixed-range MTRRs are supported.
    pub fixed_supported: bool,
    /// Whether write-combining type is supported.
    pub wc_supported: bool,
}

// ── MSR access helpers ───────────────────────────────────────────────────────

/// Read a 64-bit MSR.
///
/// # Safety
///
/// The caller must ensure `msr` is a valid, readable MSR for the
/// current privilege level (CPL 0).
#[cfg(target_arch = "x86_64")]
unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: RDMSR is privileged (CPL 0 only). Caller guarantees this.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nostack, nomem, preserves_flags),
        );
    }
    ((hi as u64) << 32) | lo as u64
}

/// Write a 64-bit MSR.
///
/// # Safety
///
/// The caller must ensure `msr` is a valid, writable MSR for CPL 0.
#[cfg(target_arch = "x86_64")]
unsafe fn wrmsr(msr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    // SAFETY: WRMSR is privileged (CPL 0 only). Caller guarantees this.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nostack, nomem, preserves_flags),
        );
    }
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn rdmsr(_msr: u32) -> u64 {
    0
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn wrmsr(_msr: u32, _value: u64) {}

// ── Mtrr ─────────────────────────────────────────────────────────────────────

/// MTRR controller.
pub struct Mtrr {
    /// Hardware capabilities.
    caps: MtrrCapabilities,
    /// Cached variable MTRR entries.
    variable: [MtrrVariableRange; MAX_VARIABLE_MTRR],
    /// Current default memory type.
    default_type: MtrrType,
    /// Whether MTRRs are globally enabled.
    enabled: bool,
    /// Whether fixed-range MTRRs are enabled.
    fixed_enabled: bool,
}

impl Mtrr {
    /// Create a new, uninitialised MTRR controller.
    pub const fn new() -> Self {
        const INIT: MtrrVariableRange = MtrrVariableRange {
            index: 0,
            base: 0,
            mask: 0,
            mtype: MtrrType::Uc,
            valid: false,
        };
        Self {
            caps: MtrrCapabilities {
                vcnt: 0,
                fixed_supported: false,
                wc_supported: false,
            },
            variable: [INIT; MAX_VARIABLE_MTRR],
            default_type: MtrrType::Uc,
            enabled: false,
            fixed_enabled: false,
        }
    }

    /// Read capabilities and current MTRR configuration from hardware.
    pub fn init(&mut self) {
        // SAFETY: RDMSR at CPL 0; MSR addresses are architectural Intel constants.
        let cap_raw = unsafe { rdmsr(MSR_MTRR_CAP) };
        self.caps = MtrrCapabilities {
            vcnt: (cap_raw & MTRR_CAP_VCNT_MASK) as u8,
            fixed_supported: cap_raw & MTRR_CAP_FIX != 0,
            wc_supported: cap_raw & MTRR_CAP_WC != 0,
        };

        // SAFETY: same as above.
        let def_raw = unsafe { rdmsr(MSR_MTRR_DEF_TYPE) };
        self.default_type =
            MtrrType::from_raw((def_raw & MTRR_DEF_TYPE_MASK) as u8).unwrap_or(MtrrType::Uc);
        self.enabled = def_raw & MTRR_DEF_ENABLE != 0;
        self.fixed_enabled = def_raw & MTRR_DEF_FIXED_ENABLE != 0;

        // Read variable MTRR pairs.
        let vcnt = self.caps.vcnt.min(MAX_VARIABLE_MTRR as u8);
        for i in 0..vcnt as usize {
            let base_msr = MSR_MTRR_PHYSBASE0 + (i as u32 * 2);
            let mask_msr = base_msr + 1;
            // SAFETY: MSR addresses are standard for variable MTRRs.
            let base_raw = unsafe { rdmsr(base_msr) };
            let mask_raw = unsafe { rdmsr(mask_msr) };

            self.variable[i] = MtrrVariableRange {
                index: i as u8,
                base: base_raw & PHYSBASE_ADDR_MASK,
                mask: mask_raw & PHYSBASE_ADDR_MASK,
                mtype: MtrrType::from_raw((base_raw & PHYSBASE_TYPE_MASK) as u8)
                    .unwrap_or(MtrrType::Uc),
                valid: mask_raw & PHYSMASK_VALID != 0,
            };
        }
    }

    /// Enable MTRRs globally.
    pub fn enable(&mut self) {
        // SAFETY: WRMSR at CPL 0; DEF_TYPE MSR is architectural.
        unsafe {
            let val = rdmsr(MSR_MTRR_DEF_TYPE) | MTRR_DEF_ENABLE;
            wrmsr(MSR_MTRR_DEF_TYPE, val);
        }
        self.enabled = true;
    }

    /// Disable MTRRs globally.
    pub fn disable(&mut self) {
        // SAFETY: same as enable.
        unsafe {
            let val = rdmsr(MSR_MTRR_DEF_TYPE) & !MTRR_DEF_ENABLE;
            wrmsr(MSR_MTRR_DEF_TYPE, val);
        }
        self.enabled = false;
    }

    /// Return whether MTRRs are enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Return the default memory type.
    pub fn default_type(&self) -> MtrrType {
        self.default_type
    }

    /// Set the default memory type.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `mtype` is not a valid
    /// MTRR type for the default field.
    pub fn set_default_type(&mut self, mtype: MtrrType) -> Result<()> {
        // SAFETY: WRMSR at CPL 0; DEF_TYPE MSR is architectural.
        unsafe {
            let val = (rdmsr(MSR_MTRR_DEF_TYPE) & !MTRR_DEF_TYPE_MASK) | mtype.as_raw() as u64;
            wrmsr(MSR_MTRR_DEF_TYPE, val);
        }
        self.default_type = mtype;
        Ok(())
    }

    /// Set a variable MTRR pair.
    ///
    /// `base` and `mask` must be 4 KiB-aligned.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `index` exceeds the hardware count
    ///   or addresses are misaligned.
    /// - [`Error::NotImplemented`] if Write-Combining is requested but
    ///   not supported by hardware.
    pub fn set_range(&mut self, index: usize, base: u64, mask: u64, mtype: MtrrType) -> Result<()> {
        if index >= self.caps.vcnt as usize || index >= MAX_VARIABLE_MTRR {
            return Err(Error::InvalidArgument);
        }
        if base & 0xFFF != 0 || mask & 0xFFF != 0 {
            return Err(Error::InvalidArgument);
        }
        if mtype == MtrrType::Wc && !self.caps.wc_supported {
            return Err(Error::NotImplemented);
        }

        let base_val = (base & PHYSBASE_ADDR_MASK) | mtype.as_raw() as u64;
        let mask_val = (mask & PHYSBASE_ADDR_MASK) | PHYSMASK_VALID;

        let base_msr = MSR_MTRR_PHYSBASE0 + (index as u32 * 2);
        let mask_msr = base_msr + 1;

        // SAFETY: WRMSR at CPL 0; variable MTRR MSR addresses are architectural.
        unsafe {
            wrmsr(base_msr, base_val);
            wrmsr(mask_msr, mask_val);
        }

        self.variable[index] = MtrrVariableRange {
            index: index as u8,
            base,
            mask,
            mtype,
            valid: true,
        };

        Ok(())
    }

    /// Disable a variable MTRR pair.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range.
    pub fn clear_range(&mut self, index: usize) -> Result<()> {
        if index >= self.caps.vcnt as usize || index >= MAX_VARIABLE_MTRR {
            return Err(Error::InvalidArgument);
        }
        let mask_msr = MSR_MTRR_PHYSBASE0 + (index as u32 * 2) + 1;
        // SAFETY: WRMSR at CPL 0; clearing the valid bit disables this MTRR.
        unsafe {
            wrmsr(mask_msr, 0);
        }
        self.variable[index].valid = false;
        Ok(())
    }

    /// Read a fixed-range MTRR MSR.
    ///
    /// Returns the raw 64-bit value encoding 8 sub-range types.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if fixed MTRRs are not supported.
    pub fn read_fixed_range(&self, msr: u32) -> Result<u64> {
        if !self.caps.fixed_supported {
            return Err(Error::NotImplemented);
        }
        // Validate known fixed MTRR MSR addresses.
        let valid = matches!(
            msr,
            MSR_MTRR_FIX64K | MSR_MTRR_FIX16K_80000 | MSR_MTRR_FIX16K_A0000 | 0x268..=0x26F
        ) || (MSR_MTRR_FIX4K_BASE..=MSR_MTRR_FIX4K_BASE + 7).contains(&msr);
        if !valid {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: RDMSR at CPL 0; MSR validated above.
        Ok(unsafe { rdmsr(msr) })
    }

    /// Return the hardware capabilities.
    pub fn capabilities(&self) -> &MtrrCapabilities {
        &self.caps
    }

    /// Return a reference to a variable MTRR entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of range.
    pub fn variable_range(&self, index: usize) -> Result<&MtrrVariableRange> {
        if index >= MAX_VARIABLE_MTRR {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.variable[index])
    }
}

impl Default for Mtrr {
    fn default() -> Self {
        Self::new()
    }
}
