// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! x86_64 Global Descriptor Table (GDT).
//!
//! In long mode, most segmentation is disabled. The GDT still needs
//! valid entries for kernel code/data and user code/data segments,
//! plus a Task State Segment (TSS) for interrupt stack switching.

use core::mem::size_of;

/// GDT segment selector indices (shifted left by 3 for the selector value).
pub mod selector {
    /// Null descriptor (index 0).
    pub const NULL: u16 = 0;
    /// Kernel code segment (index 1).
    pub const KERNEL_CODE: u16 = 1 << 3;
    /// Kernel data segment (index 2).
    pub const KERNEL_DATA: u16 = 2 << 3;
    /// User data segment (index 3), RPL=3.
    pub const USER_DATA: u16 = (3 << 3) | 3;
    /// User code segment (index 4), RPL=3.
    pub const USER_CODE: u16 = (4 << 3) | 3;
    /// TSS segment (index 5, occupies 2 entries for 64-bit TSS).
    pub const TSS: u16 = 5 << 3;
}

/// A single 8-byte GDT entry.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct GdtEntry(u64);

impl GdtEntry {
    /// Null descriptor.
    pub const NULL: Self = Self(0);

    /// Kernel code segment: 64-bit, present, DPL=0, executable, readable.
    pub const KERNEL_CODE: Self = Self(
        (1 << 43) // executable
        | (1 << 44) // code/data (S bit)
        | (1 << 47) // present
        | (1 << 53), // 64-bit (L bit)
    );

    /// Kernel data segment: present, DPL=0, writable.
    pub const KERNEL_DATA: Self = Self(
        (1 << 41) // writable
        | (1 << 44) // code/data (S bit)
        | (1 << 47), // present
    );

    /// User data segment: present, DPL=3, writable.
    pub const USER_DATA: Self = Self(
        (1 << 41) // writable
        | (1 << 44) // code/data (S bit)
        | (3 << 45) // DPL=3
        | (1 << 47), // present
    );

    /// User code segment: 64-bit, present, DPL=3, executable, readable.
    pub const USER_CODE: Self = Self(
        (1 << 43) // executable
        | (1 << 44) // code/data (S bit)
        | (3 << 45) // DPL=3
        | (1 << 47) // present
        | (1 << 53), // 64-bit (L bit)
    );

    /// Return the raw u64 value of this GDT entry.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// Task State Segment for x86_64.
///
/// Required for interrupt stack table (IST) entries and privilege
/// level stack switching.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct Tss {
    _reserved0: u32,
    /// Privilege level stack pointers (RSP0, RSP1, RSP2).
    pub privilege_stacks: [u64; 3],
    _reserved1: u64,
    /// Interrupt Stack Table entries (IST1..IST7).
    pub ist: [u64; 7],
    _reserved2: u64,
    _reserved3: u16,
    /// I/O map base address.
    pub iomap_base: u16,
}

impl Default for Tss {
    fn default() -> Self {
        Self::new()
    }
}

impl Tss {
    /// Create a zeroed TSS.
    pub const fn new() -> Self {
        Self {
            _reserved0: 0,
            privilege_stacks: [0; 3],
            _reserved1: 0,
            ist: [0; 7],
            _reserved2: 0,
            _reserved3: 0,
            iomap_base: size_of::<Self>() as u16,
        }
    }
}

/// Build the two u64 words for a 64-bit TSS descriptor.
///
/// A TSS descriptor in long mode spans 16 bytes (2 GDT slots).
pub fn tss_descriptor(tss: &Tss) -> [u64; 2] {
    let base = tss as *const _ as u64;
    let limit = (size_of::<Tss>() - 1) as u64;

    let mut low: u64 = 0;
    // Limit bits 0..15
    low |= limit & 0xFFFF;
    // Base bits 0..23
    low |= (base & 0xFFFF) << 16;
    low |= ((base >> 16) & 0xFF) << 32;
    // Type: 0x9 = 64-bit TSS (available)
    low |= 0x9 << 40;
    // Present
    low |= 1 << 47;
    // Limit bits 16..19
    low |= ((limit >> 16) & 0xF) << 48;
    // Base bits 24..31
    low |= ((base >> 24) & 0xFF) << 56;

    let high = base >> 32;

    [low, high]
}

/// GDT pointer structure for `lgdt`.
#[repr(C, packed)]
pub struct GdtPointer {
    /// Size of the GDT minus 1.
    pub limit: u16,
    /// Virtual address of the GDT.
    pub base: u64,
}

/// Load a GDT and reload segment registers.
///
/// # Safety
///
/// The GDT must contain valid entries and remain in memory for the
/// lifetime of the system. The caller must ensure segment selectors
/// are correct.
pub unsafe fn load_gdt(gdt_ptr: &GdtPointer) {
    // SAFETY: Loading the GDT is a privileged operation required for
    // correct CPU segmentation. The caller guarantees validity.
    unsafe {
        core::arch::asm!(
            "lgdt [{}]",
            in(reg) gdt_ptr,
            options(nostack, preserves_flags),
        );
    }
}

/// Reload CS by doing a far return, then load DS/ES/SS.
///
/// # Safety
///
/// Must be called after `load_gdt` with valid kernel code/data selectors.
pub unsafe fn reload_segments(code_sel: u16, data_sel: u16) {
    // SAFETY: We push the new CS and a return address onto the stack,
    // then `retfq` pops both, effectively performing a far jump to
    // reload CS. Then we load DS/ES/SS with the data selector.
    unsafe {
        core::arch::asm!(
            "push {code_sel:r}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            "mov ds, {data_sel:x}",
            "mov es, {data_sel:x}",
            "mov ss, {data_sel:x}",
            code_sel = in(reg) code_sel as u64,
            data_sel = in(reg) data_sel,
            tmp = lateout(reg) _,
            options(preserves_flags),
        );
    }
}

/// Load the Task Register with a TSS selector.
///
/// # Safety
///
/// The GDT must contain a valid TSS descriptor at the given selector.
pub unsafe fn load_tss(tss_sel: u16) {
    // SAFETY: `ltr` loads the task register with a valid TSS selector.
    unsafe {
        core::arch::asm!(
            "ltr {0:x}",
            in(reg) tss_sel,
            options(nostack, preserves_flags),
        );
    }
}
