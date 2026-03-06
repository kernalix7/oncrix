// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! x86_64 Interrupt Descriptor Table (IDT).
//!
//! The IDT maps interrupt/exception vectors (0..255) to handler
//! functions. The first 32 entries are CPU exceptions; the rest
//! are available for hardware IRQs and software interrupts.

/// Number of IDT entries (256 vectors).
pub const IDT_ENTRIES: usize = 256;

/// IDT gate types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GateType {
    /// Interrupt gate (clears IF on entry).
    Interrupt = 0xE,
    /// Trap gate (does not clear IF).
    Trap = 0xF,
}

/// A single 16-byte IDT entry (gate descriptor).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct IdtEntry {
    /// Handler address bits 0..15.
    offset_low: u16,
    /// Code segment selector.
    selector: u16,
    /// IST index (bits 0..2), rest reserved.
    ist: u8,
    /// Type and attributes (present, DPL, gate type).
    type_attr: u8,
    /// Handler address bits 16..31.
    offset_mid: u16,
    /// Handler address bits 32..63.
    offset_high: u32,
    /// Reserved, must be zero.
    _reserved: u32,
}

impl IdtEntry {
    /// An empty (not-present) IDT entry.
    pub const MISSING: Self = Self {
        offset_low: 0,
        selector: 0,
        ist: 0,
        type_attr: 0,
        offset_mid: 0,
        offset_high: 0,
        _reserved: 0,
    };

    /// Create a new IDT entry pointing to the given handler.
    ///
    /// - `handler`: virtual address of the handler function
    /// - `selector`: code segment selector (usually kernel CS)
    /// - `gate_type`: interrupt or trap gate
    /// - `dpl`: descriptor privilege level (0 = kernel, 3 = user)
    /// - `ist_index`: IST entry (0 = none, 1..7 = IST slot)
    pub const fn new(
        handler: u64,
        selector: u16,
        gate_type: GateType,
        dpl: u8,
        ist_index: u8,
    ) -> Self {
        Self {
            offset_low: handler as u16,
            selector,
            ist: ist_index & 0x7,
            type_attr: (1 << 7) // present
                | ((dpl & 0x3) << 5)
                | (gate_type as u8),
            offset_mid: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            _reserved: 0,
        }
    }
}

/// The full IDT (256 entries).
#[repr(C, align(16))]
pub struct Idt {
    /// Gate descriptors for vectors 0..255.
    pub entries: [IdtEntry; IDT_ENTRIES],
}

impl Default for Idt {
    fn default() -> Self {
        Self::new()
    }
}

impl Idt {
    /// Create an IDT with all entries set to not-present.
    pub const fn new() -> Self {
        Self {
            entries: [IdtEntry::MISSING; IDT_ENTRIES],
        }
    }

    /// Set a handler for the given vector.
    pub fn set_handler(&mut self, vector: u8, handler: u64, selector: u16, gate_type: GateType) {
        self.entries[vector as usize] = IdtEntry::new(handler, selector, gate_type, 0, 0);
    }

    /// Set a handler with a specific IST index.
    pub fn set_handler_ist(
        &mut self,
        vector: u8,
        handler: u64,
        selector: u16,
        gate_type: GateType,
        ist_index: u8,
    ) {
        self.entries[vector as usize] = IdtEntry::new(handler, selector, gate_type, 0, ist_index);
    }
}

/// IDT pointer structure for `lidt`.
#[repr(C, packed)]
pub struct IdtPointer {
    /// Size of the IDT minus 1.
    pub limit: u16,
    /// Virtual address of the IDT.
    pub base: u64,
}

/// Load the IDT.
///
/// # Safety
///
/// The IDT must contain valid entries and remain in memory for the
/// lifetime of the system.
pub unsafe fn load_idt(idt_ptr: &IdtPointer) {
    // SAFETY: Loading the IDT is required for interrupt handling.
    // The caller guarantees the IDT is valid and will remain in memory.
    unsafe {
        core::arch::asm!(
            "lidt [{}]",
            in(reg) idt_ptr,
            options(nostack, preserves_flags),
        );
    }
}

/// x86_64 CPU exception vector numbers.
pub mod exception {
    /// #DE — Divide Error.
    pub const DIVIDE_ERROR: u8 = 0;
    /// #DB — Debug Exception.
    pub const DEBUG: u8 = 1;
    /// NMI — Non-Maskable Interrupt.
    pub const NMI: u8 = 2;
    /// #BP — Breakpoint.
    pub const BREAKPOINT: u8 = 3;
    /// #OF — Overflow.
    pub const OVERFLOW: u8 = 4;
    /// #BR — Bound Range Exceeded.
    pub const BOUND_RANGE: u8 = 5;
    /// #UD — Invalid Opcode.
    pub const INVALID_OPCODE: u8 = 6;
    /// #NM — Device Not Available.
    pub const DEVICE_NOT_AVAILABLE: u8 = 7;
    /// #DF — Double Fault.
    pub const DOUBLE_FAULT: u8 = 8;
    /// #TS — Invalid TSS.
    pub const INVALID_TSS: u8 = 10;
    /// #NP — Segment Not Present.
    pub const SEGMENT_NOT_PRESENT: u8 = 11;
    /// #SS — Stack-Segment Fault.
    pub const STACK_SEGMENT: u8 = 12;
    /// #GP — General Protection Fault.
    pub const GENERAL_PROTECTION: u8 = 13;
    /// #PF — Page Fault.
    pub const PAGE_FAULT: u8 = 14;
    /// #MF — x87 Floating-Point Exception.
    pub const X87_FP: u8 = 16;
    /// #AC — Alignment Check.
    pub const ALIGNMENT_CHECK: u8 = 17;
    /// #MC — Machine Check.
    pub const MACHINE_CHECK: u8 = 18;
    /// #XM — SIMD Floating-Point Exception.
    pub const SIMD_FP: u8 = 19;
    /// #VE — Virtualization Exception.
    pub const VIRTUALIZATION: u8 = 20;
}

/// Interrupt stack frame pushed by the CPU on interrupt/exception entry.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct InterruptStackFrame {
    /// Instruction pointer at the time of the interrupt.
    pub rip: u64,
    /// Code segment selector.
    pub cs: u64,
    /// CPU flags.
    pub rflags: u64,
    /// Stack pointer.
    pub rsp: u64,
    /// Stack segment selector.
    pub ss: u64,
}
