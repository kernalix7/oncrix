// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IDT (Interrupt Descriptor Table) setup and management.
//!
//! The IDT maps interrupt/exception vectors (0–255) to handler entry points.
//! In 64-bit mode every gate is a 16-byte interrupt or trap gate:
//!
//! ```text
//! Bits 127:96  Offset 63:32 (high 32 bits of handler address)
//! Bits 95:64   Reserved (must be zero)
//! Bits 63:48   Offset 31:16
//! Bits 47:40   Type/Attributes (present, DPL, gate type, IST)
//! Bits 39:32   Reserved (zero)
//! Bits 31:16   Target CS selector
//! Bits 15:0    Offset 15:0
//! ```
//!
//! Reference: Intel 64 and IA-32 Architectures Software Developer's Manual,
//! Volume 3A, Chapter 6 — Interrupt and Exception Handling.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Gate Type Constants
// ---------------------------------------------------------------------------

/// Gate type: 64-bit interrupt gate (auto-clears EFLAGS.IF on entry).
pub const GATE_TYPE_INTERRUPT: u8 = 0x0E;
/// Gate type: 64-bit trap gate (does NOT clear EFLAGS.IF).
pub const GATE_TYPE_TRAP: u8 = 0x0F;

/// Gate attribute: segment present.
pub const GATE_PRESENT: u8 = 0x80;

/// Gate DPL shift (bits 6:5 of the attribute byte).
pub const GATE_DPL_SHIFT: u8 = 5;

// ---------------------------------------------------------------------------
// Standard Vector Numbers
// ---------------------------------------------------------------------------

/// Vector 0: Divide Error (#DE).
pub const VEC_DIVIDE_ERROR: u8 = 0;
/// Vector 1: Debug Exception (#DB).
pub const VEC_DEBUG: u8 = 1;
/// Vector 2: Non-Maskable Interrupt (NMI).
pub const VEC_NMI: u8 = 2;
/// Vector 3: Breakpoint (#BP, `int3`).
pub const VEC_BREAKPOINT: u8 = 3;
/// Vector 4: Overflow (#OF, `into`).
pub const VEC_OVERFLOW: u8 = 4;
/// Vector 5: Bound Range (#BR).
pub const VEC_BOUND: u8 = 5;
/// Vector 6: Invalid Opcode (#UD).
pub const VEC_INVALID_OPCODE: u8 = 6;
/// Vector 7: Device Not Available (#NM — FPU not ready).
pub const VEC_DEVICE_NOT_AVAIL: u8 = 7;
/// Vector 8: Double Fault (#DF).
pub const VEC_DOUBLE_FAULT: u8 = 8;
/// Vector 10: Invalid TSS (#TS).
pub const VEC_INVALID_TSS: u8 = 10;
/// Vector 11: Segment Not Present (#NP).
pub const VEC_SEGMENT_NOT_PRESENT: u8 = 11;
/// Vector 12: Stack Segment Fault (#SS).
pub const VEC_STACK_FAULT: u8 = 12;
/// Vector 13: General Protection (#GP).
pub const VEC_GENERAL_PROTECTION: u8 = 13;
/// Vector 14: Page Fault (#PF).
pub const VEC_PAGE_FAULT: u8 = 14;
/// Vector 16: x87 FPU Floating-Point Error (#MF).
pub const VEC_FPU_ERROR: u8 = 16;
/// Vector 17: Alignment Check (#AC).
pub const VEC_ALIGNMENT_CHECK: u8 = 17;
/// Vector 18: Machine Check (#MC).
pub const VEC_MACHINE_CHECK: u8 = 18;
/// Vector 19: SIMD Floating-Point Exception (#XM/#XF).
pub const VEC_SIMD_FP: u8 = 19;
/// Vector 21: Control Protection Exception (#CP).
pub const VEC_CONTROL_PROTECTION: u8 = 21;

/// First vector available for external (PIC/APIC) device interrupts.
pub const VEC_IRQ_BASE: u8 = 32;
/// Local APIC spurious interrupt vector (recommended: 0xFF).
pub const VEC_SPURIOUS: u8 = 0xFF;

// ---------------------------------------------------------------------------
// IDT Gate Descriptor (16 bytes)
// ---------------------------------------------------------------------------

/// A 16-byte 64-bit interrupt/trap gate descriptor.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct IdtGate {
    /// Handler offset bits 15:0.
    pub offset_low: u16,
    /// Target code segment selector.
    pub selector: u16,
    /// IST index (bits 2:0); bits 7:3 must be zero.
    pub ist: u8,
    /// Gate type and attributes (present, DPL, type).
    pub attr: u8,
    /// Handler offset bits 31:16.
    pub offset_mid: u16,
    /// Handler offset bits 63:32.
    pub offset_high: u32,
    /// Reserved (must be zero).
    _reserved: u32,
}

impl IdtGate {
    /// Creates a null (not-present) gate.
    pub const fn null() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            attr: 0,
            offset_mid: 0,
            offset_high: 0,
            _reserved: 0,
        }
    }

    /// Creates an interrupt gate (clears IF on entry) targeting `handler`.
    ///
    /// # Parameters
    /// - `handler`: Virtual address of the assembly stub.
    /// - `cs`: Target code segment selector (typically `SEL_KERNEL_CODE`).
    /// - `dpl`: Descriptor Privilege Level (0 for kernel-only, 3 for `int N` from ring 3).
    /// - `ist`: IST index (0 = normal stack, 1–7 = dedicated IST stack).
    pub fn interrupt(handler: u64, cs: u16, dpl: u8, ist: u8) -> Self {
        let attr = GATE_PRESENT | ((dpl & 3) << GATE_DPL_SHIFT) | GATE_TYPE_INTERRUPT;
        Self {
            offset_low: (handler & 0xFFFF) as u16,
            selector: cs,
            ist: ist & 0x07,
            attr,
            offset_mid: ((handler >> 16) & 0xFFFF) as u16,
            offset_high: (handler >> 32) as u32,
            _reserved: 0,
        }
    }

    /// Creates a trap gate (preserves IF on entry) targeting `handler`.
    pub fn trap(handler: u64, cs: u16, dpl: u8, ist: u8) -> Self {
        let attr = GATE_PRESENT | ((dpl & 3) << GATE_DPL_SHIFT) | GATE_TYPE_TRAP;
        Self {
            offset_low: (handler & 0xFFFF) as u16,
            selector: cs,
            ist: ist & 0x07,
            attr,
            offset_mid: ((handler >> 16) & 0xFFFF) as u16,
            offset_high: (handler >> 32) as u32,
            _reserved: 0,
        }
    }

    /// Sets the IST index on an existing gate.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if `ist > 7`.
    pub fn set_ist(&mut self, ist: u8) -> Result<()> {
        if ist > 7 {
            return Err(Error::InvalidArgument);
        }
        self.ist = ist;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// IDT Table
// ---------------------------------------------------------------------------

/// Total number of IDT entries (one per vector, 256 for x86_64).
pub const IDT_ENTRIES: usize = 256;

/// IDTR descriptor loaded with `lidt`.
#[repr(C, packed)]
pub struct Idtr {
    /// Table size in bytes minus 1.
    pub limit: u16,
    /// Linear address of the IDT.
    pub base: u64,
}

/// Full 256-entry IDT.
pub struct IdtHw {
    gates: [IdtGate; IDT_ENTRIES],
}

impl IdtHw {
    /// Creates an IDT with all gates set to null (not-present).
    pub fn new() -> Self {
        Self {
            gates: [IdtGate::null(); IDT_ENTRIES],
        }
    }

    /// Sets a vector to an interrupt gate.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if `vector >= 256` (never with `u8` param).
    pub fn set_interrupt(&mut self, vector: u8, handler: u64, cs: u16, dpl: u8, ist: u8) {
        self.gates[vector as usize] = IdtGate::interrupt(handler, cs, dpl, ist);
    }

    /// Sets a vector to a trap gate.
    pub fn set_trap(&mut self, vector: u8, handler: u64, cs: u16, dpl: u8, ist: u8) {
        self.gates[vector as usize] = IdtGate::trap(handler, cs, dpl, ist);
    }

    /// Sets the IST stack index for a given vector.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if `ist > 7`.
    pub fn set_ist(&mut self, vector: u8, ist: u8) -> Result<()> {
        self.gates[vector as usize].set_ist(ist)
    }

    /// Builds the IDTR for this table.
    pub fn idtr(&self) -> Idtr {
        Idtr {
            limit: (IDT_ENTRIES * core::mem::size_of::<IdtGate>() - 1) as u16,
            base: self.gates.as_ptr() as u64,
        }
    }

    /// Returns a reference to the gate at `vector`.
    pub fn gate(&self, vector: u8) -> &IdtGate {
        &self.gates[vector as usize]
    }

    /// Returns a mutable reference to the gate at `vector`.
    pub fn gate_mut(&mut self, vector: u8) -> &mut IdtGate {
        &mut self.gates[vector as usize]
    }
}

impl Default for IdtHw {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Load IDT
// ---------------------------------------------------------------------------

/// Loads the IDT by writing the IDTR with `lidt`.
///
/// # Safety
/// - `idtr` must point to a valid, permanently resident IDT.
/// - All installed gates must have valid handler addresses and selectors.
/// - Must be called from ring 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn load_idt(idtr: &Idtr) {
    // SAFETY: Caller guarantees IDTR is valid and IDT is resident in memory.
    unsafe {
        core::arch::asm!(
            "lidt [{idtr}]",
            idtr = in(reg) idtr as *const Idtr,
            options(nomem, nostack, preserves_flags),
        );
    }
}

// ---------------------------------------------------------------------------
// Boot IDT
// ---------------------------------------------------------------------------

/// Boot IDT (all gates initially null; populated during early init).
static mut BOOT_IDT: IdtHw = IdtHw {
    gates: [IdtGate::null(); IDT_ENTRIES],
};

/// Installs a handler into the boot IDT and reloads IDTR.
///
/// # Safety
/// - `handler` must be the address of a valid interrupt stub that saves/restores registers.
/// - Must be called before enabling interrupts.
#[cfg(target_arch = "x86_64")]
pub unsafe fn set_boot_handler(vector: u8, handler: u64, cs: u16, dpl: u8, ist: u8, trap: bool) {
    // SAFETY: Boot-time single-CPU access; raw pointer avoids static_mut_refs.
    unsafe {
        let ptr = core::ptr::addr_of_mut!(BOOT_IDT);
        if trap {
            (*ptr).set_trap(vector, handler, cs, dpl, ist);
        } else {
            (*ptr).set_interrupt(vector, handler, cs, dpl, ist);
        }
    }
}

/// Loads the boot IDT. Must be called after all handlers are installed.
///
/// # Safety
/// See `load_idt`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn load_boot_idt() {
    // SAFETY: Boot IDT is static and resident; safe to load.
    unsafe {
        let ptr = core::ptr::addr_of!(BOOT_IDT);
        let idtr = (*ptr).idtr();
        load_idt(&idtr);
    }
}

/// Sets the IST stack for a boot-IDT vector.
///
/// # Errors
/// Returns `Error::InvalidArgument` if `ist > 7`.
///
/// # Safety
/// Must be called before interrupts are enabled.
pub fn set_boot_ist(vector: u8, ist: u8) -> Result<()> {
    // SAFETY: Boot-time single-CPU access; no interrupts yet.
    unsafe {
        let ptr = core::ptr::addr_of_mut!(BOOT_IDT);
        (*ptr).set_ist(vector, ist)
    }
}
