// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Interrupt Descriptor Table (IDT) management.
//!
//! The IDT maps CPU exception and interrupt vectors (0–255) to handler
//! functions. In 64-bit mode, each entry is 16 bytes and encodes:
//! - The handler offset (64-bit)
//! - The code segment selector
//! - The Interrupt Stack Table (IST) index for critical vectors
//! - Type and privilege attributes
//!
//! Reference: Intel 64 and IA-32 Architectures Software Developer's Manual,
//! Volume 3A, Chapter 6 — Interrupt and Exception Handling.

use oncrix_lib::Result;

// ---------------------------------------------------------------------------
// Gate Type Constants
// ---------------------------------------------------------------------------

/// IDT gate type: Interrupt gate (disables interrupts on entry, IF=0).
pub const GATE_INTERRUPT: u8 = 0x0E;

/// IDT gate type: Trap gate (does NOT clear IF on entry).
pub const GATE_TRAP: u8 = 0x0F;

/// IDT gate type: Task gate (switches to TSS on entry, rarely used).
pub const GATE_TASK: u8 = 0x05;

/// Type attribute flag: Present bit.
const TA_PRESENT: u8 = 1 << 7;

/// Type attribute DPL shift.
const TA_DPL_SHIFT: u8 = 5;

// ---------------------------------------------------------------------------
// IDT Entry
// ---------------------------------------------------------------------------

/// A single 16-byte IDT gate descriptor.
///
/// Layout (Intel manual Vol. 3A, Figure 6-8):
/// ```text
/// Bytes  0- 1: offset 15:0
/// Bytes  2- 3: segment selector
/// Byte   4:    IST index (bits 2:0) + reserved (bits 7:3)
/// Byte   5:    type + attributes (P | DPL | S | type)
/// Bytes  6- 7: offset 31:16
/// Bytes  8-11: offset 63:32
/// Bytes 12-15: reserved (must be zero)
/// ```
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct IdtEntry {
    /// Handler offset bits 0–15.
    pub offset_low: u16,
    /// Code segment selector (usually `KERNEL_CODE`).
    pub selector: u16,
    /// IST index (0 = no stack switch, 1–7 = IST entry).
    pub ist: u8,
    /// Type and attribute byte: Present | DPL | gate type.
    pub type_attr: u8,
    /// Handler offset bits 16–31.
    pub offset_mid: u16,
    /// Handler offset bits 32–63.
    pub offset_high: u32,
    /// Reserved, must be zero.
    _reserved: u32,
}

impl IdtEntry {
    /// Creates a zeroed (not-present) IDT entry.
    pub const fn null() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            _reserved: 0,
        }
    }

    /// Creates an interrupt gate entry for a handler at `handler_addr`.
    ///
    /// # Parameters
    /// - `handler_addr`: 64-bit virtual address of the handler function.
    /// - `selector`: Code segment selector (normally `KERNEL_CODE = 0x08`).
    /// - `dpl`: Descriptor Privilege Level (0 = kernel only, 3 = callable from user).
    /// - `ist`: IST index (0 = no switch, 1–7 for dedicated stacks).
    pub fn interrupt_gate(handler_addr: u64, selector: u16, dpl: u8, ist: u8) -> Self {
        let type_attr = TA_PRESENT | ((dpl & 0x3) << TA_DPL_SHIFT) | GATE_INTERRUPT;
        Self {
            offset_low: (handler_addr & 0xFFFF) as u16,
            selector,
            ist: ist & 0x7,
            type_attr,
            offset_mid: ((handler_addr >> 16) & 0xFFFF) as u16,
            offset_high: (handler_addr >> 32) as u32,
            _reserved: 0,
        }
    }

    /// Creates a trap gate entry (does not clear IF).
    ///
    /// # Parameters
    /// Same as `interrupt_gate`.
    pub fn trap_gate(handler_addr: u64, selector: u16, dpl: u8, ist: u8) -> Self {
        let type_attr = TA_PRESENT | ((dpl & 0x3) << TA_DPL_SHIFT) | GATE_TRAP;
        Self {
            offset_low: (handler_addr & 0xFFFF) as u16,
            selector,
            ist: ist & 0x7,
            type_attr,
            offset_mid: ((handler_addr >> 16) & 0xFFFF) as u16,
            offset_high: (handler_addr >> 32) as u32,
            _reserved: 0,
        }
    }

    /// Returns `true` if the Present bit is set.
    pub fn is_present(&self) -> bool {
        self.type_attr & TA_PRESENT != 0
    }

    /// Returns the full 64-bit handler offset.
    pub fn offset(&self) -> u64 {
        (self.offset_low as u64)
            | ((self.offset_mid as u64) << 16)
            | ((self.offset_high as u64) << 32)
    }

    /// Returns the IST index (0–7).
    pub fn ist_index(&self) -> u8 {
        self.ist & 0x7
    }

    /// Returns the gate type bits (lower 4 bits of type_attr).
    pub fn gate_type(&self) -> u8 {
        self.type_attr & 0x0F
    }
}

// ---------------------------------------------------------------------------
// IDT Table
// ---------------------------------------------------------------------------

/// IDTR descriptor loaded via `lidt`.
#[repr(C, packed)]
pub struct IdtDescriptor {
    /// Table size in bytes minus 1.
    pub limit: u16,
    /// Linear address of the IDT.
    pub base: u64,
}

/// The full Interrupt Descriptor Table with 256 entries.
pub struct IdtTable {
    entries: [IdtEntry; 256],
}

impl IdtTable {
    /// Creates a new IDT with all entries set to not-present.
    pub fn new() -> Self {
        Self {
            entries: [IdtEntry::null(); 256],
        }
    }

    /// Sets an interrupt gate for `vector`.
    ///
    /// # Parameters
    /// - `vector`: Interrupt/exception vector number (0–255).
    /// - `handler`: Virtual address of the handler function.
    /// - `selector`: Code segment selector.
    /// - `dpl`: DPL (0 = kernel, 3 = user-callable via `int N`).
    /// - `ist`: IST index for critical exceptions (0 = no IST).
    pub fn set_handler(
        &mut self,
        vector: u8,
        handler: u64,
        selector: u16,
        dpl: u8,
        ist: u8,
    ) -> Result<()> {
        self.entries[vector as usize] = IdtEntry::interrupt_gate(handler, selector, dpl, ist);
        Ok(())
    }

    /// Sets a trap gate for `vector`.
    pub fn set_trap(
        &mut self,
        vector: u8,
        handler: u64,
        selector: u16,
        dpl: u8,
        ist: u8,
    ) -> Result<()> {
        self.entries[vector as usize] = IdtEntry::trap_gate(handler, selector, dpl, ist);
        Ok(())
    }

    /// Clears (marks not-present) the entry for `vector`.
    pub fn clear_handler(&mut self, vector: u8) {
        self.entries[vector as usize] = IdtEntry::null();
    }

    /// Returns a reference to the entry for `vector`.
    pub fn entry(&self, vector: u8) -> &IdtEntry {
        &self.entries[vector as usize]
    }

    /// Returns the number of present entries.
    pub fn len(&self) -> usize {
        self.entries.iter().filter(|e| e.is_present()).count()
    }

    /// Returns `true` if no entries are present.
    pub fn is_empty(&self) -> bool {
        !self.entries.iter().any(|e| e.is_present())
    }

    /// Builds an `IdtDescriptor` for this table.
    pub fn descriptor(&self) -> IdtDescriptor {
        IdtDescriptor {
            limit: (core::mem::size_of::<[IdtEntry; 256]>() - 1) as u16,
            base: self.entries.as_ptr() as u64,
        }
    }
}

impl Default for IdtTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Load IDT
// ---------------------------------------------------------------------------

/// Loads the IDT using the `lidt` instruction.
///
/// # Safety
/// Caller must ensure the `idtr` descriptor points to a valid IDT that
/// will remain resident in memory for the processor's lifetime in this mode.
#[cfg(target_arch = "x86_64")]
pub unsafe fn load_idt(idtr: &IdtDescriptor) {
    // SAFETY: Caller guarantees the IDTR and the IDT it points to are valid.
    unsafe {
        core::arch::asm!("lidt [{0}]", in(reg) idtr as *const IdtDescriptor);
    }
}

// ---------------------------------------------------------------------------
// Well-Known Exception Vectors
// ---------------------------------------------------------------------------

/// Exception vector: Divide Error (#DE).
pub const VEC_DIVIDE_ERROR: u8 = 0;
/// Exception vector: Debug (#DB).
pub const VEC_DEBUG: u8 = 1;
/// Exception vector: Non-Maskable Interrupt (NMI).
pub const VEC_NMI: u8 = 2;
/// Exception vector: Breakpoint (#BP).
pub const VEC_BREAKPOINT: u8 = 3;
/// Exception vector: Overflow (#OF).
pub const VEC_OVERFLOW: u8 = 4;
/// Exception vector: Bound Range Exceeded (#BR).
pub const VEC_BOUND: u8 = 5;
/// Exception vector: Invalid Opcode (#UD).
pub const VEC_INVALID_OP: u8 = 6;
/// Exception vector: Device Not Available (#NM) — no FPU.
pub const VEC_DEVICE_NOT_AVAIL: u8 = 7;
/// Exception vector: Double Fault (#DF).
pub const VEC_DOUBLE_FAULT: u8 = 8;
/// Exception vector: Invalid TSS (#TS).
pub const VEC_INVALID_TSS: u8 = 10;
/// Exception vector: Segment Not Present (#NP).
pub const VEC_SEG_NOT_PRESENT: u8 = 11;
/// Exception vector: Stack-Segment Fault (#SS).
pub const VEC_STACK_FAULT: u8 = 12;
/// Exception vector: General Protection Fault (#GP).
pub const VEC_GENERAL_PROTECTION: u8 = 13;
/// Exception vector: Page Fault (#PF).
pub const VEC_PAGE_FAULT: u8 = 14;
/// Exception vector: x87 FPU Error (#MF).
pub const VEC_X87_FPU: u8 = 16;
/// Exception vector: Alignment Check (#AC).
pub const VEC_ALIGNMENT_CHECK: u8 = 17;
/// Exception vector: Machine Check (#MC).
pub const VEC_MACHINE_CHECK: u8 = 18;
/// Exception vector: SIMD Floating-Point Exception (#XM/#XF).
pub const VEC_SIMD_FP: u8 = 19;
/// Exception vector: Virtualization Exception (#VE).
pub const VEC_VIRTUALIZATION: u8 = 20;
/// First usable external IRQ vector (after remapped PIC/APIC).
pub const VEC_EXTERNAL_IRQ_BASE: u8 = 32;

/// IST index reserved for NMI handler stack.
pub const IST_NMI: u8 = 1;
/// IST index reserved for Double Fault handler stack.
pub const IST_DOUBLE_FAULT: u8 = 2;
/// IST index reserved for Machine Check handler stack.
pub const IST_MACHINE_CHECK: u8 = 3;

// ---------------------------------------------------------------------------
// Global IDT
// ---------------------------------------------------------------------------

/// Boot CPU IDT.
static mut BOOT_IDT: IdtTable = IdtTable {
    entries: [IdtEntry::null(); 256],
};

/// Registers an interrupt gate in the boot IDT.
///
/// # Safety
/// Must be called before `load_boot_idt`; the handler address must be valid
/// and correctly aligned as an interrupt handler stub.
pub unsafe fn set_boot_handler(
    vector: u8,
    handler: u64,
    selector: u16,
    dpl: u8,
    ist: u8,
) -> Result<()> {
    // SAFETY: Raw ptr avoids static_mut_refs lint; caller ensures exclusive boot access.
    unsafe {
        let idt_ptr = core::ptr::addr_of_mut!(BOOT_IDT);
        (*idt_ptr).set_handler(vector, handler, selector, dpl, ist)
    }
}

/// Loads the boot CPU IDT.
///
/// # Safety
/// All required exception handlers must have been registered before calling
/// this function. The IDT must remain resident for the CPU's lifetime.
#[cfg(target_arch = "x86_64")]
pub unsafe fn load_boot_idt() {
    // SAFETY: Raw ptr avoids static_mut_refs; IDT is always resident.
    unsafe {
        let idt_ptr = core::ptr::addr_of!(BOOT_IDT);
        let idtr = (*idt_ptr).descriptor();
        load_idt(&idtr);
    }
}
