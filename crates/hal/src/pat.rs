// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page Attribute Table (PAT) support.
//!
//! The PAT extends the MTRR system by allowing per-page memory type
//! overrides in the page tables. It is programmed via the
//! `IA32_PAT` MSR (0x277) and consists of 8 entries indexed by
//! the PAT/PCD/PWT bits in page table entries.
//!
//! # Default PAT layout (Intel recommended)
//!
//! | Index | PTE bits (PAT:PCD:PWT) | Type |
//! |-------|------------------------|------|
//! | 0     | 0:0:0                  | WB   |
//! | 1     | 0:0:1                  | WT   |
//! | 2     | 0:1:0                  | UC-  |
//! | 3     | 0:1:1                  | UC   |
//! | 4     | 1:0:0                  | WB   |
//! | 5     | 1:0:1                  | WT   |
//! | 6     | 1:1:0                  | UC-  |
//! | 7     | 1:1:1                  | UC   |
//!
//! ONCRIX uses a slightly different layout that enables WC at index 4:
//!
//! | Index | Type |
//! |-------|------|
//! | 0     | WB   |
//! | 1     | WT   |
//! | 2     | UC-  |
//! | 3     | UC   |
//! | 4     | WC   |
//! | 5     | WP   |
//! | 6     | UC-  |
//! | 7     | UC   |

use oncrix_lib::{Error, Result};

// ── MSR address ──────────────────────────────────────────────────────────────

/// IA32_PAT MSR address.
const MSR_IA32_PAT: u32 = 0x277;

// ── PatEntry ─────────────────────────────────────────────────────────────────

/// Memory type encoding for a PAT entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PatEntry {
    /// Uncacheable (UC).
    Uc = 0,
    /// Write-Combining (WC).
    Wc = 1,
    /// Write-Through (WT).
    Wt = 4,
    /// Write-Protected (WP).
    Wp = 5,
    /// Write-Back (WB).
    Wb = 6,
    /// Uncacheable- (UC-): overridable by MTRRs to WC/WT.
    UcMinus = 7,
}

impl PatEntry {
    /// Decode from a 3-bit raw value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for reserved encodings.
    pub fn from_raw(v: u8) -> Result<Self> {
        match v & 0x7 {
            0 => Ok(Self::Uc),
            1 => Ok(Self::Wc),
            4 => Ok(Self::Wt),
            5 => Ok(Self::Wp),
            6 => Ok(Self::Wb),
            7 => Ok(Self::UcMinus),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Return the raw 3-bit encoding.
    pub fn as_raw(self) -> u8 {
        self as u8
    }
}

// ── PatTable ─────────────────────────────────────────────────────────────────

/// The full PAT: 8 entries, one byte each.
#[derive(Debug, Clone, Copy)]
pub struct PatTable {
    /// Raw PAT MSR value (8 × 8-bit entries packed in 64 bits).
    raw: u64,
}

impl PatTable {
    /// Build a `PatTable` from an array of 8 entries.
    pub fn from_entries(entries: [PatEntry; 8]) -> Self {
        let mut raw = 0u64;
        for (i, e) in entries.iter().enumerate() {
            raw |= (e.as_raw() as u64) << (i * 8);
        }
        Self { raw }
    }

    /// Decode entry `index` (0–7).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if index > 7 or the stored
    /// encoding is reserved.
    pub fn get(&self, index: usize) -> Result<PatEntry> {
        if index > 7 {
            return Err(Error::InvalidArgument);
        }
        let byte = ((self.raw >> (index * 8)) & 0xFF) as u8;
        PatEntry::from_raw(byte)
    }

    /// Set entry `index` to `entry`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if index > 7.
    pub fn set(&mut self, index: usize, entry: PatEntry) -> Result<()> {
        if index > 7 {
            return Err(Error::InvalidArgument);
        }
        let shift = index * 8;
        self.raw &= !(0xFF << shift);
        self.raw |= (entry.as_raw() as u64) << shift;
        Ok(())
    }

    /// Return the raw 64-bit PAT MSR value.
    pub fn raw(&self) -> u64 {
        self.raw
    }
}

// ── Optimal PAT layout ───────────────────────────────────────────────────────

/// ONCRIX optimal PAT table (see module doc for layout).
pub const ONCRIX_PAT: PatTable = PatTable {
    raw: (PatEntry::Wb as u64)       // index 0: 0:0:0 → WB
       | ((PatEntry::Wt as u64) << 8)   // index 1: 0:0:1 → WT
       | ((PatEntry::UcMinus as u64) << 16) // index 2: 0:1:0 → UC-
       | ((PatEntry::Uc as u64) << 24) // index 3: 0:1:1 → UC
       | ((PatEntry::Wc as u64) << 32) // index 4: 1:0:0 → WC
       | ((PatEntry::Wp as u64) << 40) // index 5: 1:0:1 → WP
       | ((PatEntry::UcMinus as u64) << 48) // index 6: 1:1:0 → UC-
       | ((PatEntry::Uc as u64) << 56), // index 7: 1:1:1 → UC
};

// ── Pat controller ───────────────────────────────────────────────────────────

/// PAT driver.
pub struct Pat {
    /// Current PAT table.
    table: PatTable,
    /// Whether PAT is supported and enabled.
    enabled: bool,
}

impl Pat {
    /// Create a new PAT driver (not yet enabled).
    pub const fn new() -> Self {
        Self {
            table: ONCRIX_PAT,
            enabled: false,
        }
    }

    /// Initialise PAT — write the ONCRIX optimal PAT to the MSR.
    ///
    /// Caller must have verified PAT support via CPUID leaf 1, EDX bit 16.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if called on a non-x86_64 target.
    pub fn init(&mut self) -> Result<()> {
        self.table = ONCRIX_PAT;
        self.write_msr()?;
        self.enabled = true;
        Ok(())
    }

    /// Write a custom PAT table to the IA32_PAT MSR.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] on non-x86_64.
    pub fn set_table(&mut self, table: PatTable) -> Result<()> {
        self.table = table;
        self.write_msr()?;
        Ok(())
    }

    /// Return the current PAT table.
    pub fn table(&self) -> &PatTable {
        &self.table
    }

    /// Return whether PAT is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Look up the PAT index for the given PTE bit combination.
    ///
    /// PTE encoding: `pat_bit << 2 | pcd_bit << 1 | pwt_bit`.
    /// Index 0–7 maps directly to the 3-bit selector.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `pte_bits` > 7.
    pub fn pat_index_from_pte(pte_bits: u8) -> Result<usize> {
        if pte_bits > 7 {
            return Err(Error::InvalidArgument);
        }
        Ok(pte_bits as usize)
    }

    /// Look up the memory type for a given PAT/PCD/PWT bit combination.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`PatTable::get`] or
    /// [`Pat::pat_index_from_pte`].
    pub fn lookup(&self, pte_bits: u8) -> Result<PatEntry> {
        let idx = Self::pat_index_from_pte(pte_bits)?;
        self.table.get(idx)
    }

    /// Return the PTE PAT/PCD/PWT bits that select `desired_type`.
    ///
    /// Scans the PAT table for the first matching entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no PAT entry encodes `desired_type`.
    pub fn pte_bits_for_type(&self, desired_type: PatEntry) -> Result<u8> {
        for i in 0..8usize {
            if let Ok(e) = self.table.get(i) {
                if e == desired_type {
                    return Ok(i as u8);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Read the current IA32_PAT MSR into a `PatTable`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] on non-x86_64.
    pub fn read_msr() -> Result<PatTable> {
        #[cfg(target_arch = "x86_64")]
        {
            let raw = unsafe { rdmsr(MSR_IA32_PAT) };
            Ok(PatTable { raw })
        }
        #[cfg(not(target_arch = "x86_64"))]
        Err(Error::NotImplemented)
    }

    /// Write `self.table` to the IA32_PAT MSR.
    fn write_msr(&self) -> Result<()> {
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: WRMSR at CPL 0; IA32_PAT is an architectural MSR
            // safe to modify when MTRR/PAT usage is correctly coordinated.
            unsafe { wrmsr(MSR_IA32_PAT, self.table.raw) };
            Ok(())
        }
        #[cfg(not(target_arch = "x86_64"))]
        Err(Error::NotImplemented)
    }
}

impl Default for Pat {
    fn default() -> Self {
        Self::new()
    }
}

// ── MSR helpers (x86_64 only) ────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: RDMSR requires CPL 0. Caller's responsibility.
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

#[cfg(target_arch = "x86_64")]
unsafe fn wrmsr(msr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    // SAFETY: WRMSR requires CPL 0. Caller's responsibility.
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
