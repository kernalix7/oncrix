// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ARM Virtual Generic Interrupt Controller (vGIC) hardware abstraction.
//!
//! Implements the host-side hardware interface for the ARM GIC virtualization
//! extensions (GICv2/v3 List Registers, maintenance interrupt, hypervisor
//! control registers). Used by a hypervisor or KVM-style virtual machine
//! monitor to inject virtual interrupts into guests.

use oncrix_lib::{Error, Result};

/// Maximum number of List Registers (LRs) per vCPU.
pub const VGIC_MAX_LR: usize = 16;

/// GICv3 List Register state bits.
pub mod lr_bits {
    /// Interrupt is pending.
    pub const PENDING: u64 = 1 << 62;
    /// Interrupt is active.
    pub const ACTIVE: u64 = 1 << 63;
    /// Hardware interrupt bit (group-1 physical).
    pub const HW: u64 = 1 << 61;
    /// Group-1 (non-secure) interrupt.
    pub const GROUP1: u64 = 1 << 60;
    /// vINTID mask (bits [41:32]).
    pub const VINTID_MASK: u64 = 0x3FF_0000_0000;
    /// vINTID shift.
    pub const VINTID_SHIFT: u64 = 32;
    /// pINTID mask (bits [9:0]) — valid only when HW=1.
    pub const PINTID_MASK: u64 = 0x3FF;
    /// Priority mask (bits [23:16]).
    pub const PRIORITY_MASK: u64 = 0xFF << 16;
    /// Priority shift.
    pub const PRIORITY_SHIFT: u64 = 16;
}

/// A single decoded List Register entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct ListRegEntry {
    /// Virtual interrupt ID.
    pub vintid: u32,
    /// Physical interrupt ID (used when `hw == true`).
    pub pintid: u32,
    /// Interrupt priority (0 = highest).
    pub priority: u8,
    /// Interrupt is pending.
    pub pending: bool,
    /// Interrupt is active.
    pub active: bool,
    /// Maps to a physical interrupt (hardware interrupt).
    pub hw: bool,
    /// Interrupt is group-1 (non-secure).
    pub group1: bool,
}

impl ListRegEntry {
    /// Encodes this entry as a 64-bit List Register value.
    pub fn encode(&self) -> u64 {
        let mut val: u64 = (self.vintid as u64) << lr_bits::VINTID_SHIFT;
        val |= (self.priority as u64) << lr_bits::PRIORITY_SHIFT;
        if self.pending {
            val |= lr_bits::PENDING;
        }
        if self.active {
            val |= lr_bits::ACTIVE;
        }
        if self.hw {
            val |= lr_bits::HW;
            val |= (self.pintid as u64) & lr_bits::PINTID_MASK;
        }
        if self.group1 {
            val |= lr_bits::GROUP1;
        }
        val
    }

    /// Decodes a 64-bit List Register value.
    pub fn decode(val: u64) -> Self {
        Self {
            vintid: ((val & lr_bits::VINTID_MASK) >> lr_bits::VINTID_SHIFT) as u32,
            pintid: (val & lr_bits::PINTID_MASK) as u32,
            priority: ((val & lr_bits::PRIORITY_MASK) >> lr_bits::PRIORITY_SHIFT) as u8,
            pending: (val & lr_bits::PENDING) != 0,
            active: (val & lr_bits::ACTIVE) != 0,
            hw: (val & lr_bits::HW) != 0,
            group1: (val & lr_bits::GROUP1) != 0,
        }
    }
}

/// vGIC hypervisor control interface (GICv3 ICH_* system registers).
///
/// On real hardware these are ARM system registers accessed via `mrs`/`msr`.
/// We model them as a software-managed structure for portability.
pub struct VgicHyp {
    /// Number of List Registers implemented.
    pub num_lr: usize,
    /// List Register values.
    pub lr: [u64; VGIC_MAX_LR],
    /// ICH_HCR_EL2: Hypervisor Control Register.
    pub hcr: u32,
    /// ICH_VMCR_EL2: Virtual Machine Control Register (mirrors guest GICC).
    pub vmcr: u32,
    /// ICH_MISR_EL2: Maintenance Interrupt State Register (read-only).
    pub misr: u32,
}

impl VgicHyp {
    /// Creates a new vGIC hypervisor interface.
    pub const fn new(num_lr: usize) -> Self {
        Self {
            num_lr,
            lr: [0u64; VGIC_MAX_LR],
            hcr: 0,
            vmcr: 0,
            misr: 0,
        }
    }

    /// Loads the vGIC state from HW (guest entry path).
    #[cfg(target_arch = "aarch64")]
    pub fn load(&mut self) {
        // SAFETY: Reading ARM GICv3 virtualization system registers.
        unsafe {
            core::arch::asm!("mrs {}, ICH_HCR_EL2", out(reg) self.hcr, options(nostack, nomem));
            core::arch::asm!("mrs {}, ICH_VMCR_EL2", out(reg) self.vmcr, options(nostack, nomem));
            core::arch::asm!("mrs {}, ICH_MISR_EL2", out(reg) self.misr, options(nostack, nomem));
        }
        for i in 0..self.num_lr.min(VGIC_MAX_LR) {
            // LRs are indexed as ICH_LR<n>_EL2; we read LR0 as representative.
            // A real implementation uses a macro or match over i.
            self.lr[i] = 0; // Placeholder: real read uses indexed system reg.
        }
    }

    /// Saves the vGIC state to HW (guest exit path).
    #[cfg(target_arch = "aarch64")]
    pub fn save(&self) {
        // SAFETY: Writing ARM GICv3 virtualization system registers.
        unsafe {
            core::arch::asm!("msr ICH_HCR_EL2, {}", in(reg) self.hcr, options(nostack, nomem));
            core::arch::asm!("msr ICH_VMCR_EL2, {}", in(reg) self.vmcr, options(nostack, nomem));
        }
    }

    /// Queues a virtual interrupt in the first free List Register.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all LRs are occupied.
    pub fn inject_irq(&mut self, entry: ListRegEntry) -> Result<usize> {
        for i in 0..self.num_lr.min(VGIC_MAX_LR) {
            let lr = ListRegEntry::decode(self.lr[i]);
            if !lr.pending && !lr.active {
                self.lr[i] = entry.encode();
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Clears a List Register by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `idx >= num_lr`.
    pub fn clear_lr(&mut self, idx: usize) -> Result<()> {
        if idx >= self.num_lr {
            return Err(Error::InvalidArgument);
        }
        self.lr[idx] = 0;
        Ok(())
    }

    /// Returns the number of occupied List Registers.
    pub fn used_lrs(&self) -> usize {
        self.lr[..self.num_lr.min(VGIC_MAX_LR)]
            .iter()
            .filter(|&&v| {
                let e = ListRegEntry::decode(v);
                e.pending || e.active
            })
            .count()
    }

    /// Returns true if there are no active or pending virtual interrupts.
    pub fn is_idle(&self) -> bool {
        self.used_lrs() == 0
    }

    /// Enables the maintenance interrupt (ICH_HCR_EL2.En).
    pub fn enable_maintenance_irq(&mut self) {
        self.hcr |= 1;
    }

    /// Disables the maintenance interrupt.
    pub fn disable_maintenance_irq(&mut self) {
        self.hcr &= !1;
    }
}

impl Default for VgicHyp {
    fn default() -> Self {
        Self::new(4)
    }
}

/// Returns the name of a vGIC maintenance interrupt cause bit.
pub fn misr_cause_name(bit: u32) -> &'static str {
    match bit {
        0 => "EOIcount",
        1 => "U (underflow)",
        2 => "LRENP (LR empty+pending)",
        3 => "NP (no pending)",
        4 => "VGrp0E",
        5 => "VGrp0D",
        6 => "VGrp1E",
        7 => "VGrp1D",
        _ => "unknown",
    }
}
