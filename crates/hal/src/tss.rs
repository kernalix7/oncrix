// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Task State Segment (TSS) management.
//!
//! In 64-bit mode the TSS is no longer used for hardware task switching,
//! but is still required for:
//! - **RSP0**: The kernel stack pointer used when transitioning from ring 3
//!   to ring 0 (syscall/interrupt entry).
//! - **IST stacks** (IST1–IST7): Dedicated stacks for critical exceptions
//!   (NMI, Double Fault, Machine Check) that need a known-good stack.
//! - **IOPB offset**: The I/O Permission Bitmap base; set to `sizeof(TSS)`
//!   to forbid ring-3 port I/O by default.
//!
//! Reference: Intel 64 and IA-32 Architectures Software Developer's Manual,
//! Volume 3A, §7.7 — Task Management in 64-bit Mode.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of a single IST stack (16 KiB).
pub const IST_STACK_SIZE: usize = 16 * 1024;

/// Number of IST entries in the TSS (IST1–IST7).
pub const IST_COUNT: usize = 7;

/// IOPB offset value that disables all I/O port access from user space.
/// Setting this to `sizeof(Tss)` places the IOPB past the end of the segment,
/// which causes every I/O port access from CPL 3 to fault.
pub const IOPB_DISABLED: u16 = core::mem::size_of::<Tss>() as u16;

// ---------------------------------------------------------------------------
// TSS structure
// ---------------------------------------------------------------------------

/// 64-bit Task State Segment.
///
/// Must be 16-byte aligned for `ltr` to work correctly on some hardware.
/// The `#[repr(C, packed)]` ensures exact layout matching the hardware spec.
///
/// Intel manual Vol. 3A, Figure 7-11.
#[repr(C, packed)]
#[derive(Debug)]
pub struct Tss {
    /// Reserved / previous task link (unused in 64-bit).
    _reserved0: u32,
    /// RSP0: Kernel stack pointer for transitions from ring 0 to ring 0 via
    /// interrupts, and from ring 3 to ring 0 via `syscall`/`sysenter`.
    pub rsp0: u64,
    /// RSP1: Privilege-level-1 stack pointer (rarely used).
    pub rsp1: u64,
    /// RSP2: Privilege-level-2 stack pointer (rarely used).
    pub rsp2: u64,
    /// Reserved.
    _reserved1: u64,
    /// IST1: Interrupt Stack Table entry 1 (e.g., NMI).
    pub ist1: u64,
    /// IST2: Interrupt Stack Table entry 2 (e.g., Double Fault).
    pub ist2: u64,
    /// IST3: Interrupt Stack Table entry 3 (e.g., Machine Check).
    pub ist3: u64,
    /// IST4: Interrupt Stack Table entry 4.
    pub ist4: u64,
    /// IST5: Interrupt Stack Table entry 5.
    pub ist5: u64,
    /// IST6: Interrupt Stack Table entry 6.
    pub ist6: u64,
    /// IST7: Interrupt Stack Table entry 7.
    pub ist7: u64,
    /// Reserved.
    _reserved2: u64,
    /// Reserved (bits 15:0 of next field).
    _reserved3: u16,
    /// I/O Permission Bitmap base offset from the TSS base.
    pub iopb_offset: u16,
}

impl Tss {
    /// Creates a zeroed TSS with the IOPB disabled.
    pub const fn new() -> Self {
        Self {
            _reserved0: 0,
            rsp0: 0,
            rsp1: 0,
            rsp2: 0,
            _reserved1: 0,
            ist1: 0,
            ist2: 0,
            ist3: 0,
            ist4: 0,
            ist5: 0,
            ist6: 0,
            ist7: 0,
            _reserved2: 0,
            _reserved3: 0,
            iopb_offset: IOPB_DISABLED,
        }
    }

    /// Sets the kernel stack pointer (RSP0) used on ring-3 → ring-0 transitions.
    ///
    /// `stack_top` should be the **top** (highest address) of the kernel stack,
    /// since the stack grows downward on x86_64.
    pub fn set_kernel_stack(&mut self, stack_top: u64) {
        self.rsp0 = stack_top;
    }

    /// Sets an IST entry by index (1–7).
    ///
    /// `stack_top` is the top of a dedicated stack for critical exceptions.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if `ist_index` is 0 or > 7.
    pub fn set_ist(&mut self, ist_index: u8, stack_top: u64) -> Result<()> {
        match ist_index {
            1 => self.ist1 = stack_top,
            2 => self.ist2 = stack_top,
            3 => self.ist3 = stack_top,
            4 => self.ist4 = stack_top,
            5 => self.ist5 = stack_top,
            6 => self.ist6 = stack_top,
            7 => self.ist7 = stack_top,
            _ => return Err(Error::InvalidArgument),
        }
        Ok(())
    }

    /// Returns the virtual address (pointer) of this TSS.
    pub fn as_ptr(&self) -> *const Self {
        self as *const Self
    }

    /// Returns the base address suitable for a GDT TSS descriptor.
    pub fn base_addr(&self) -> u64 {
        self as *const Self as u64
    }

    /// Returns the limit value for a GDT TSS descriptor (`sizeof(Tss) - 1`).
    pub fn limit() -> u32 {
        (core::mem::size_of::<Tss>() - 1) as u32
    }
}

impl Default for Tss {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// IST Stack Storage
// ---------------------------------------------------------------------------

/// Pre-allocated IST stacks for NMI, Double Fault, and Machine Check.
pub struct IstStacks {
    /// Raw stack storage; each stack is `IST_STACK_SIZE` bytes.
    storage: [[u8; IST_STACK_SIZE]; IST_COUNT],
}

impl IstStacks {
    /// Creates zeroed IST stack storage.
    pub fn new() -> Self {
        Self {
            storage: [[0u8; IST_STACK_SIZE]; IST_COUNT],
        }
    }

    /// Returns the top (highest byte + 1) of IST stack `idx` (1-based).
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if `idx` is 0 or > `IST_COUNT`.
    pub fn stack_top(&self, idx: u8) -> Result<u64> {
        if idx == 0 || idx as usize > IST_COUNT {
            return Err(Error::InvalidArgument);
        }
        let slot = (idx - 1) as usize;
        let top = self.storage[slot].as_ptr() as u64 + IST_STACK_SIZE as u64;
        Ok(top)
    }
}

impl Default for IstStacks {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TSS Manager
// ---------------------------------------------------------------------------

/// Manages the TSS and its associated IST stacks for a single CPU.
pub struct TssManager {
    tss: Tss,
    ist_stacks: IstStacks,
}

impl TssManager {
    /// Creates a new TSS manager with pre-allocated IST stacks.
    pub fn new() -> Self {
        Self {
            tss: Tss::new(),
            ist_stacks: IstStacks::new(),
        }
    }

    /// Initialises IST entries for NMI (IST1), Double Fault (IST2), and
    /// Machine Check (IST3), then sets the kernel stack to `kernel_stack_top`.
    ///
    /// # Parameters
    /// - `kernel_stack_top`: Top of the per-CPU kernel stack used for ring-3 → ring-0 transitions.
    pub fn init(&mut self, kernel_stack_top: u64) -> Result<()> {
        self.tss.set_kernel_stack(kernel_stack_top);
        // IST1 = NMI, IST2 = Double Fault, IST3 = Machine Check
        for ist_idx in 1u8..=3 {
            let top = self.ist_stacks.stack_top(ist_idx)?;
            self.tss.set_ist(ist_idx, top)?;
        }
        Ok(())
    }

    /// Updates RSP0 (kernel stack) without re-initialising IST entries.
    pub fn set_kernel_stack(&mut self, stack_top: u64) {
        self.tss.set_kernel_stack(stack_top);
    }

    /// Returns the base address and limit for embedding in a GDT TSS descriptor.
    pub fn gdt_params(&self) -> (u64, u32) {
        (self.tss.base_addr(), Tss::limit())
    }

    /// Returns a reference to the managed TSS.
    pub fn tss(&self) -> &Tss {
        &self.tss
    }

    /// Returns a mutable reference to the managed TSS.
    pub fn tss_mut(&mut self) -> &mut Tss {
        &mut self.tss
    }
}

impl Default for TssManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Load TSS
// ---------------------------------------------------------------------------

/// Loads the TSS selector into TR using the `ltr` instruction.
///
/// # Safety
/// - `selector` must refer to a valid, present TSS descriptor in the GDT.
/// - The TSS descriptor must have been written before calling this function.
/// - Must be called once per CPU (the TR is per-CPU state).
#[cfg(target_arch = "x86_64")]
pub unsafe fn load_tss(selector: u16) {
    // SAFETY: Caller guarantees selector is a valid TSS descriptor.
    unsafe {
        core::arch::asm!("ltr {0:x}", in(reg) selector);
    }
}

/// Reads the current TSS selector from TR.
///
/// # Safety
/// The TR must be valid and loaded (i.e. `load_tss` was called).
#[cfg(target_arch = "x86_64")]
pub unsafe fn read_tr() -> u16 {
    let tr: u16;
    // SAFETY: `str` is a safe read of a CPU register.
    unsafe {
        core::arch::asm!("str {0:x}", out(reg) tr);
    }
    tr
}
