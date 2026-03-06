// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hardware suspend/resume support (ACPI S3).
//!
//! Provides the `SuspendOps` trait, a `HwSuspendState` that captures
//! critical processor context across a sleep cycle, and helpers for
//! setting up the ACPI S3 wake vector.
//!
//! # S3 suspend flow
//!
//! 1. `SuspendOps::prepare` — quiesce devices, disable non-boot CPUs.
//! 2. Save CPU state (CR0, CR3, CR4, GDT, IDT) into `HwSuspendState`.
//! 3. `SuspendOps::enter` — write SLP_TYP to PM1a_CNT; CPU enters S3.
//! 4. BIOS/UEFI firmware executes the wake vector on resume.
//! 5. `SuspendOps::finish` — restore CPU state and re-enable devices.

use oncrix_lib::{Error, Result};

// ── Descriptor table pointer ──────────────────────────────────────────────────

/// An x86 descriptor table pointer (GDTR / IDTR register content).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C, packed)]
pub struct DescTablePtr {
    /// Limit (size - 1) in bytes.
    pub limit: u16,
    /// Linear base address.
    pub base: u64,
}

// ── HwSuspendState ───────────────────────────────────────────────────────────

/// Saved hardware state for S3 resume.
///
/// Stores the minimal CPU context required to restore kernel execution
/// after an ACPI S3 sleep cycle.
#[derive(Debug, Clone, Copy, Default)]
pub struct HwSuspendState {
    /// CR0: Protection Enable, Write Protect, etc.
    pub cr0: u64,
    /// CR3: Page-Directory Base Register (physical).
    pub cr3: u64,
    /// CR4: Extended features (PAE, PSE, etc.).
    pub cr4: u64,
    /// Saved GDTR.
    pub gdtr: DescTablePtr,
    /// Saved IDTR.
    pub idtr: DescTablePtr,
    /// IA32_EFER MSR value (long mode enable, NX enable).
    pub efer: u64,
    /// RSP at suspend time (stack pointer).
    pub rsp: u64,
    /// RIP of the resume entry point.
    pub resume_rip: u64,
    /// CS selector at suspend time.
    pub cs: u16,
    /// DS selector.
    pub ds: u16,
    /// ES selector.
    pub es: u16,
    /// SS selector.
    pub ss: u16,
    /// Whether the state has been saved (valid for restore).
    pub valid: bool,
}

impl HwSuspendState {
    /// Create a zeroed, invalid suspend state.
    pub const fn new() -> Self {
        Self {
            cr0: 0,
            cr3: 0,
            cr4: 0,
            gdtr: DescTablePtr { limit: 0, base: 0 },
            idtr: DescTablePtr { limit: 0, base: 0 },
            efer: 0,
            rsp: 0,
            resume_rip: 0,
            cs: 0,
            ds: 0,
            es: 0,
            ss: 0,
            valid: false,
        }
    }

    /// Save the current CPU state into this structure.
    ///
    /// On non-x86_64 platforms this is a no-op.
    pub fn save(&mut self) {
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: Reading control registers and descriptor table registers
            // is permitted at CPL 0. No memory is written except `self`.
            unsafe {
                let cr0: u64;
                let cr3: u64;
                let cr4: u64;
                core::arch::asm!("mov {}, cr0", out(reg) cr0, options(nostack, nomem));
                core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, nomem));
                core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nostack, nomem));
                self.cr0 = cr0;
                self.cr3 = cr3;
                self.cr4 = cr4;

                // Save GDTR / IDTR.
                core::arch::asm!(
                    "sgdt [{0}]",
                    in(reg) &mut self.gdtr as *mut DescTablePtr,
                    options(nostack),
                );
                core::arch::asm!(
                    "sidt [{0}]",
                    in(reg) &mut self.idtr as *mut DescTablePtr,
                    options(nostack),
                );

                // Read IA32_EFER (MSR 0xC000_0080).
                let lo: u32;
                let hi: u32;
                core::arch::asm!(
                    "rdmsr",
                    in("ecx") 0xC000_0080u32,
                    out("eax") lo,
                    out("edx") hi,
                    options(nostack, nomem, preserves_flags),
                );
                self.efer = ((hi as u64) << 32) | lo as u64;

                // Save segment selectors.
                let cs: u16;
                let ds: u16;
                let es: u16;
                let ss: u16;
                core::arch::asm!("mov {:x}, cs", out(reg) cs, options(nostack, nomem));
                core::arch::asm!("mov {:x}, ds", out(reg) ds, options(nostack, nomem));
                core::arch::asm!("mov {:x}, es", out(reg) es, options(nostack, nomem));
                core::arch::asm!("mov {:x}, ss", out(reg) ss, options(nostack, nomem));
                self.cs = cs;
                self.ds = ds;
                self.es = es;
                self.ss = ss;

                // Capture RSP.
                let rsp: u64;
                core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack, nomem));
                self.rsp = rsp;
            }
        }
        self.valid = true;
    }

    /// Restore the saved CPU state.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the state was never saved.
    pub fn restore(&self) -> Result<()> {
        if !self.valid {
            return Err(Error::InvalidArgument);
        }
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: Writing control registers and loading descriptor tables
            // is permitted at CPL 0. We restore values that were valid at
            // suspend time, so the system state remains coherent.
            unsafe {
                core::arch::asm!("mov cr3, {}", in(reg) self.cr3, options(nostack, nomem));
                core::arch::asm!(
                    "lgdt [{0}]",
                    in(reg) &self.gdtr as *const DescTablePtr,
                    options(nostack),
                );
                core::arch::asm!(
                    "lidt [{0}]",
                    in(reg) &self.idtr as *const DescTablePtr,
                    options(nostack),
                );
                core::arch::asm!("mov cr0, {}", in(reg) self.cr0, options(nostack, nomem));
                core::arch::asm!("mov cr4, {}", in(reg) self.cr4, options(nostack, nomem));
            }
        }
        Ok(())
    }
}

// ── SuspendOps ───────────────────────────────────────────────────────────────

/// Hardware suspend/resume callback trait.
///
/// Implementors provide platform-specific callbacks that are called
/// at each phase of the ACPI S3 suspend/resume cycle.
pub trait SuspendOps {
    /// Prepare hardware for suspend.
    ///
    /// Called before saving CPU state and entering sleep. Should
    /// quiesce devices and flush caches.
    ///
    /// # Errors
    ///
    /// Return an error to abort the suspend cycle.
    fn prepare(&mut self) -> Result<()>;

    /// Enter the sleep state.
    ///
    /// Writes SLP_TYP and SLP_EN to PM1a_CNT to initiate S3. This
    /// function should not return on success (the CPU enters sleep).
    /// If it returns, resume via `finish`.
    ///
    /// # Errors
    ///
    /// Return an error if the hardware refused to enter sleep.
    fn enter(&mut self) -> Result<()>;

    /// Finish resume after wake.
    ///
    /// Called after restoring CPU state to re-enable devices and
    /// restore platform-specific state.
    ///
    /// # Errors
    ///
    /// Return an error if resume fails (system may be in inconsistent state).
    fn finish(&mut self) -> Result<()>;
}

// ── AcpiSuspend ──────────────────────────────────────────────────────────────

/// ACPI S3 suspend controller.
pub struct AcpiSuspend {
    /// PM1a control block I/O port.
    pm1a_cnt_blk: u16,
    /// SLP_TYP for S3 (from ACPI DSDT `_S3` object, typically 0x05).
    slp_typ_s3: u8,
    /// Physical address of the 16-byte wake vector (reset vector style).
    wake_vector_phys: u64,
    /// Saved CPU state.
    pub state: HwSuspendState,
}

impl AcpiSuspend {
    /// Create a new ACPI suspend controller.
    ///
    /// `pm1a_cnt_blk` is the I/O port for PM1a_CNT_BLK (from FADT).
    /// `slp_typ_s3` is the SLP_TYP value for S3 from the DSDT.
    pub const fn new(pm1a_cnt_blk: u16, slp_typ_s3: u8) -> Self {
        Self {
            pm1a_cnt_blk,
            slp_typ_s3,
            wake_vector_phys: 0,
            state: HwSuspendState::new(),
        }
    }

    /// Set the physical address of the ACPI wake vector.
    ///
    /// The wake vector is written to the FACS (Firmware ACPI Control
    /// Structure) `FirmwareWakingVector` field before sleep.
    pub fn set_wake_vector(&mut self, phys: u64) {
        self.wake_vector_phys = phys;
    }

    /// Write `entry_phys` into the FACS wake vector slot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `wake_vector_phys` has not
    /// been set.
    pub fn install_wake_vector(&self, entry_phys: u32) -> Result<()> {
        if self.wake_vector_phys == 0 {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: wake_vector_phys is the physical address of the FACS
        // FirmwareWakingVector field, mapped into kernel virtual space.
        // Writing a u32 at this address is the standard ACPI mechanism.
        unsafe {
            core::ptr::write_volatile(self.wake_vector_phys as *mut u32, entry_phys);
        }
        Ok(())
    }
}

impl SuspendOps for AcpiSuspend {
    fn prepare(&mut self) -> Result<()> {
        self.state.save();
        Ok(())
    }

    fn enter(&mut self) -> Result<()> {
        if self.pm1a_cnt_blk == 0 {
            return Err(Error::InvalidArgument);
        }
        // Build PM1a_CNT value: SLP_TYP (bits 12:10) | SLP_EN (bit 13).
        let slp_val = ((self.slp_typ_s3 as u16) << 10) | (1 << 13);

        // SAFETY: Writing to the ACPI PM1a_CNT port at CPL 0 to initiate
        // the S3 sleep sequence. This is the standard ACPI power-down path.
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!(
                "out dx, ax",
                in("dx") self.pm1a_cnt_blk,
                in("ax") slp_val,
                options(nostack, nomem, preserves_flags),
            );
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        self.state.restore()
    }
}
