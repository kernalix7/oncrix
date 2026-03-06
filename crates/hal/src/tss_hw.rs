// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! TSS (Task State Segment) hardware management.
//!
//! Extends `crate::tss` with per-CPU TSS allocation helpers and IST stack
//! management. In 64-bit mode the TSS serves two primary roles:
//!
//! 1. **RSP0**: Kernel stack pointer loaded on any ring-3 → ring-0 transition.
//! 2. **IST stacks**: Dedicated emergency stacks for NMI, Double Fault, and
//!    Machine Check — used via the IDT gate IST field.
//!
//! This module is the interface layer between the generic `tss.rs` types and
//! the `gdt_hw.rs` / `idt_hw.rs` setup routines.
//!
//! Reference: Intel 64 and IA-32 Architectures Software Developer's Manual,
//! Volume 3A, §7.7 — Task Management in 64-bit Mode.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// IST Stack Configuration
// ---------------------------------------------------------------------------

/// Number of IST slots in the TSS (IST1–IST7).
pub const IST_SLOTS: usize = 7;

/// Default IST stack size per slot (16 KiB).
pub const IST_STACK_SIZE: usize = 16 * 1024;

/// IST slot indices (1-based, as the CPU uses them).
pub mod ist {
    /// IST1: Recommended for NMI handler.
    pub const NMI: u8 = 1;
    /// IST2: Recommended for Double Fault handler.
    pub const DOUBLE_FAULT: u8 = 2;
    /// IST3: Recommended for Machine Check handler.
    pub const MACHINE_CHECK: u8 = 3;
    /// IST4: General-purpose emergency stack 4.
    pub const EMERGENCY_4: u8 = 4;
    /// IST5: General-purpose emergency stack 5.
    pub const EMERGENCY_5: u8 = 5;
    /// IST6: General-purpose emergency stack 6.
    pub const EMERGENCY_6: u8 = 6;
    /// IST7: General-purpose emergency stack 7.
    pub const EMERGENCY_7: u8 = 7;
}

// ---------------------------------------------------------------------------
// TSS Hardware Structure
// ---------------------------------------------------------------------------

/// 64-bit TSS as specified by the Intel manual (Vol. 3A, Figure 7-11).
///
/// Must not exceed 0xFFFF + 1 bytes (the IOPB offset is a 16-bit value).
#[repr(C, packed)]
#[derive(Debug)]
pub struct TssHw {
    _reserved0: u32,
    /// RSP0: kernel stack pointer for ring-0 entry.
    pub rsp0: u64,
    /// RSP1: unused in ONCRIX.
    pub rsp1: u64,
    /// RSP2: unused in ONCRIX.
    pub rsp2: u64,
    _reserved1: u64,
    /// IST1–IST7: Interrupt Stack Table entries.
    pub ist: [u64; IST_SLOTS],
    _reserved2: u64,
    _reserved3: u16,
    /// IOPB offset from TSS base. `sizeof(TssHw)` disables all port I/O from ring 3.
    pub iopb_offset: u16,
}

impl TssHw {
    /// Returns `sizeof(TssHw) - 1` as required by the GDT TSS limit field.
    pub const fn limit() -> u32 {
        (core::mem::size_of::<TssHw>() - 1) as u32
    }

    /// Returns the IOPB offset value that disables ring-3 port I/O.
    pub const fn iopb_disabled() -> u16 {
        core::mem::size_of::<TssHw>() as u16
    }

    /// Creates a zeroed TSS with IOPB disabled.
    pub const fn new() -> Self {
        Self {
            _reserved0: 0,
            rsp0: 0,
            rsp1: 0,
            rsp2: 0,
            _reserved1: 0,
            ist: [0u64; IST_SLOTS],
            _reserved2: 0,
            _reserved3: 0,
            iopb_offset: core::mem::size_of::<TssHw>() as u16,
        }
    }

    /// Sets the RSP0 (kernel stack top used on ring-3 entry).
    pub fn set_rsp0(&mut self, stack_top: u64) {
        self.rsp0 = stack_top;
    }

    /// Sets an IST entry.
    ///
    /// # Parameters
    /// - `slot`: IST slot (1–7).
    /// - `stack_top`: Top of the dedicated stack (grows downward).
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if `slot == 0` or `slot > 7`.
    pub fn set_ist(&mut self, slot: u8, stack_top: u64) -> Result<()> {
        if slot == 0 || slot as usize > IST_SLOTS {
            return Err(Error::InvalidArgument);
        }
        self.ist[(slot - 1) as usize] = stack_top;
        Ok(())
    }

    /// Returns the IST entry for a given slot.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if `slot == 0` or `slot > 7`.
    pub fn get_ist(&self, slot: u8) -> Result<u64> {
        if slot == 0 || slot as usize > IST_SLOTS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.ist[(slot - 1) as usize])
    }

    /// Returns the base address of this TSS (for a GDT descriptor).
    pub fn base_addr(&self) -> u64 {
        self as *const Self as u64
    }
}

impl Default for TssHw {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// IST Stack Storage
// ---------------------------------------------------------------------------

/// Pre-allocated emergency IST stacks for a single CPU.
pub struct IstStorage {
    stacks: [[u8; IST_STACK_SIZE]; IST_SLOTS],
}

impl IstStorage {
    /// Creates zeroed IST stacks.
    pub fn new() -> Self {
        Self {
            stacks: [[0u8; IST_STACK_SIZE]; IST_SLOTS],
        }
    }

    /// Returns the stack top (highest address + 1) for slot `slot` (1-based).
    ///
    /// Stack grows downward, so the top is past the last byte of the array.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if `slot == 0` or `slot > IST_SLOTS`.
    pub fn stack_top(&self, slot: u8) -> Result<u64> {
        if slot == 0 || slot as usize > IST_SLOTS {
            return Err(Error::InvalidArgument);
        }
        let idx = (slot - 1) as usize;
        let top = self.stacks[idx].as_ptr() as u64 + IST_STACK_SIZE as u64;
        Ok(top)
    }
}

impl Default for IstStorage {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Per-CPU TSS Manager
// ---------------------------------------------------------------------------

/// Manages a CPU's TSS and its associated IST stacks.
pub struct TssManager {
    tss: TssHw,
    ist: IstStorage,
}

impl TssManager {
    /// Creates a new TSS manager (TSS zeroed, IST stacks allocated).
    pub fn new() -> Self {
        Self {
            tss: TssHw::new(),
            ist: IstStorage::new(),
        }
    }

    /// Initialises the TSS for this CPU.
    ///
    /// Sets RSP0 to `kernel_stack_top` and populates IST slots 1–3 with
    /// NMI, Double Fault, and Machine Check stacks respectively.
    ///
    /// # Parameters
    /// - `kernel_stack_top`: Top of the normal kernel interrupt stack.
    pub fn init(&mut self, kernel_stack_top: u64) -> Result<()> {
        self.tss.set_rsp0(kernel_stack_top);
        for slot in 1u8..=3 {
            let top = self.ist.stack_top(slot)?;
            self.tss.set_ist(slot, top)?;
        }
        Ok(())
    }

    /// Updates RSP0 on a task switch (hot path — no IST changes).
    pub fn update_rsp0(&mut self, kernel_stack_top: u64) {
        self.tss.set_rsp0(kernel_stack_top);
    }

    /// Returns the GDT TSS descriptor parameters.
    pub fn gdt_params(&self) -> (u64, u32) {
        (self.tss.base_addr(), TssHw::limit())
    }

    /// Returns a reference to the TSS.
    pub fn tss(&self) -> &TssHw {
        &self.tss
    }

    /// Returns a mutable reference to the TSS.
    pub fn tss_mut(&mut self) -> &mut TssHw {
        &mut self.tss
    }
}

impl Default for TssManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ltr Helper
// ---------------------------------------------------------------------------

/// Loads a TSS selector into TR.
///
/// # Safety
/// - `selector` must refer to an available TSS descriptor in the current GDT.
/// - The TSS must be fully initialised before this call.
/// - Should be called once per CPU after the GDT is loaded.
#[cfg(target_arch = "x86_64")]
pub unsafe fn load_tss_hw(selector: u16) {
    // SAFETY: Caller guarantees selector is a valid TSS descriptor.
    unsafe {
        core::arch::asm!("ltr {0:x}", in(reg) selector, options(nomem, nostack, preserves_flags));
    }
}

/// Reads the current task register (TR).
///
/// # Safety
/// Must be called from ring 0 (TR is privileged).
#[cfg(target_arch = "x86_64")]
pub unsafe fn read_tr() -> u16 {
    let tr: u16;
    // SAFETY: `str` is a safe read of a CPU register in ring 0.
    unsafe {
        core::arch::asm!("str {0:x}", out(reg) tr, options(nomem, nostack, preserves_flags));
    }
    tr
}
