// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! GDT (Global Descriptor Table) hardware setup helpers.
//!
//! This module provides higher-level GDT initialisation on top of the raw
//! descriptor structures in `crate::gdt`. It handles:
//!
//! - Per-CPU GDT allocation and population.
//! - Segment register reload after `lgdt`.
//! - TSS installation and `ltr` loading.
//! - Selector constants for the standard ONCRIX flat model.
//!
//! Reference: Intel 64 and IA-32 Architectures Software Developer's Manual,
//! Volume 3A, Chapter 3 — Protected-Mode Memory Management.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Selector Constants
// ---------------------------------------------------------------------------

/// Kernel null segment (index 0, TI=0, RPL=0).
pub const SEL_NULL: u16 = 0x00;
/// Kernel 64-bit code segment selector (index 1, TI=0, RPL=0).
pub const SEL_KERNEL_CODE: u16 = 0x08;
/// Kernel data segment selector (index 2, TI=0, RPL=0).
pub const SEL_KERNEL_DATA: u16 = 0x10;
/// User data segment selector (index 3, TI=0, RPL=3).
pub const SEL_USER_DATA: u16 = 0x1B;
/// User 64-bit code segment selector (index 4, TI=0, RPL=3).
pub const SEL_USER_CODE: u16 = 0x23;
/// TSS selector base (index 5; occupies two 8-byte slots).
pub const SEL_TSS: u16 = 0x28;

// ---------------------------------------------------------------------------
// Segment Descriptor Flags
// ---------------------------------------------------------------------------

/// Access byte: segment present.
const ACCESS_PRESENT: u8 = 0x80;
/// Access byte: DPL ring-0.
const ACCESS_DPL0: u8 = 0x00;
/// Access byte: DPL ring-3.
const ACCESS_DPL3: u8 = 0x60;
/// Access byte: code/data descriptor type.
const ACCESS_S: u8 = 0x10;
/// Access byte: executable segment.
const ACCESS_EXEC: u8 = 0x08;
/// Access byte: readable (code) / writable (data).
const ACCESS_RW: u8 = 0x02;
/// Access byte: TSS available (type 0x9).
const ACCESS_TSS_AVAIL: u8 = 0x09;

/// Granularity byte: 4 KiB page granularity.
const GRAN_4K: u8 = 0x80;
/// Granularity byte: 64-bit code segment (L bit).
const GRAN_L: u8 = 0x20;
/// Granularity byte: 32-bit default operand size (D/B bit).
const GRAN_DB: u8 = 0x40;

// ---------------------------------------------------------------------------
// GDT Entry
// ---------------------------------------------------------------------------

/// An 8-byte x86_64 segment descriptor.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct GdtEntry64 {
    /// Limit 15:0.
    pub limit_low: u16,
    /// Base 15:0.
    pub base_low: u16,
    /// Base 23:16.
    pub base_mid: u8,
    /// Access byte.
    pub access: u8,
    /// Limit 19:16 (low nibble) and granularity flags (high nibble).
    pub gran: u8,
    /// Base 31:24.
    pub base_high: u8,
}

impl GdtEntry64 {
    /// Creates a null descriptor.
    pub const fn null() -> Self {
        Self {
            limit_low: 0,
            base_low: 0,
            base_mid: 0,
            access: 0,
            gran: 0,
            base_high: 0,
        }
    }

    /// Creates a 64-bit flat code segment.
    pub const fn code64(dpl: u8) -> Self {
        let access = ACCESS_PRESENT | ((dpl & 3) << 5) | ACCESS_S | ACCESS_EXEC | ACCESS_RW;
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access,
            gran: GRAN_L | 0x0F, // L=1, limit bits 19:16 = 0xF
            base_high: 0,
        }
    }

    /// Creates a flat data segment (32/64-bit compatible).
    pub const fn data(dpl: u8) -> Self {
        let access = ACCESS_PRESENT | ((dpl & 3) << 5) | ACCESS_S | ACCESS_RW;
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access,
            gran: GRAN_4K | GRAN_DB | 0x0F,
            base_high: 0,
        }
    }

    /// Creates the low 8 bytes of a 64-bit TSS descriptor.
    pub fn tss_low(base: u64, limit: u32) -> Self {
        Self {
            limit_low: (limit & 0xFFFF) as u16,
            base_low: (base & 0xFFFF) as u16,
            base_mid: ((base >> 16) & 0xFF) as u8,
            access: ACCESS_PRESENT | ACCESS_TSS_AVAIL,
            gran: (((limit >> 16) & 0x0F) as u8) | GRAN_4K,
            base_high: ((base >> 24) & 0xFF) as u8,
        }
    }

    /// Creates the high 8 bytes of a 64-bit TSS descriptor.
    pub fn tss_high(base: u64) -> Self {
        let upper = (base >> 32) as u32;
        Self {
            limit_low: (upper & 0xFFFF) as u16,
            base_low: ((upper >> 16) & 0xFFFF) as u16,
            base_mid: 0,
            access: 0,
            gran: 0,
            base_high: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// GDT Table
// ---------------------------------------------------------------------------

/// Maximum GDT entries supported.
pub const GDT_MAX_ENTRIES: usize = 32;

/// GDTR descriptor for `lgdt`.
#[repr(C, packed)]
pub struct Gdtr {
    /// Limit: size in bytes minus 1.
    pub limit: u16,
    /// Linear base address.
    pub base: u64,
}

/// In-memory GDT for a single CPU.
pub struct GdtHw {
    entries: [GdtEntry64; GDT_MAX_ENTRIES],
    count: usize,
}

impl GdtHw {
    /// Creates a standard flat-model GDT:
    /// - Index 0: null
    /// - Index 1: kernel code64 (RPL=0)
    /// - Index 2: kernel data   (RPL=0)
    /// - Index 3: user data     (RPL=3)
    /// - Index 4: user code64   (RPL=3)
    pub fn new() -> Self {
        let mut gdt = Self {
            entries: [GdtEntry64::null(); GDT_MAX_ENTRIES],
            count: 5,
        };
        gdt.entries[1] = GdtEntry64::code64(0);
        gdt.entries[2] = GdtEntry64::data(0);
        gdt.entries[3] = GdtEntry64::data(3);
        gdt.entries[4] = GdtEntry64::code64(3);
        gdt
    }

    /// Installs a 64-bit TSS descriptor at index 5 (slots 5 and 6).
    ///
    /// # Parameters
    /// - `tss_base`: Virtual address of the TSS structure.
    /// - `tss_limit`: `sizeof(TSS) - 1`.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if there is no room for the two-slot TSS.
    pub fn install_tss(&mut self, tss_base: u64, tss_limit: u32) -> Result<()> {
        const TSS_IDX: usize = (SEL_TSS / 8) as usize;
        if TSS_IDX + 1 >= GDT_MAX_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        self.entries[TSS_IDX] = GdtEntry64::tss_low(tss_base, tss_limit);
        self.entries[TSS_IDX + 1] = GdtEntry64::tss_high(tss_base);
        if self.count < TSS_IDX + 2 {
            self.count = TSS_IDX + 2;
        }
        Ok(())
    }

    /// Builds the GDTR for this table.
    pub fn gdtr(&self) -> Gdtr {
        Gdtr {
            limit: (self.count * core::mem::size_of::<GdtEntry64>() - 1) as u16,
            base: self.entries.as_ptr() as u64,
        }
    }

    /// Returns the number of populated entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no valid entries beyond null.
    pub fn is_empty(&self) -> bool {
        self.count <= 1
    }
}

impl Default for GdtHw {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Load GDT
// ---------------------------------------------------------------------------

/// Loads the GDT and reloads all segment registers.
///
/// Uses a far return (`retfq`) to atomically switch CS to `SEL_KERNEL_CODE`.
///
/// # Safety
/// - `gdtr` must point to a valid, permanently resident GDT.
/// - The GDT must contain correct descriptors at all standard selector offsets.
/// - Must be called from ring 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn load_gdt(gdtr: &Gdtr) {
    let kcs = SEL_KERNEL_CODE as u64;
    let kds = SEL_KERNEL_DATA as u64;
    // SAFETY: Caller guarantees GDTR is valid and GDT is resident in memory.
    unsafe {
        core::arch::asm!(
            "lgdt [{gdtr}]",
            "push {kcs}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            "mov ax, {kds:x}",
            "mov ds, ax",
            "mov es, ax",
            "mov ss, ax",
            "xor ax, ax",
            "mov fs, ax",
            "mov gs, ax",
            gdtr = in(reg) gdtr as *const Gdtr,
            kcs  = in(reg) kcs,
            kds  = in(reg) kds,
            tmp  = out(reg) _,
            options(nostack),
        );
    }
}

/// Loads a TSS selector into TR using `ltr`.
///
/// # Safety
/// - `selector` must reference a valid, available TSS descriptor in the current GDT.
/// - The TSS must be fully initialised before this call.
#[cfg(target_arch = "x86_64")]
pub unsafe fn load_tr(selector: u16) {
    // SAFETY: Caller guarantees selector is a valid TSS.
    unsafe {
        core::arch::asm!("ltr {0:x}", in(reg) selector, options(nomem, nostack, preserves_flags));
    }
}

// ---------------------------------------------------------------------------
// Boot GDT
// ---------------------------------------------------------------------------

/// Boot-time GDT (shared across early SMP bring-up).
static mut BOOT_GDT: GdtHw = GdtHw {
    entries: [GdtEntry64::null(); GDT_MAX_ENTRIES],
    count: 0,
};

/// Initialises the boot GDT with the flat memory model and loads it.
///
/// Must be called once on the BSP before enabling interrupts.
///
/// # Safety
/// - Must be called exactly once, from the BSP, before SMP init.
/// - Not re-entrant; no synchronisation is performed.
#[cfg(target_arch = "x86_64")]
pub unsafe fn init_boot_gdt() {
    // SAFETY: Single-CPU early boot; exclusive mutable access via raw pointer.
    unsafe {
        let ptr = core::ptr::addr_of_mut!(BOOT_GDT);
        ptr.write(GdtHw::new());
        let gdtr = (*ptr).gdtr();
        load_gdt(&gdtr);
    }
}

/// Installs a TSS into the boot GDT and reloads TR.
///
/// # Parameters
/// - `tss_base`: Virtual address of the TSS.
/// - `tss_limit`: `sizeof(TSS) - 1`.
///
/// # Errors
/// Returns `Error::InvalidArgument` if TSS installation fails.
///
/// # Safety
/// Must be called after `init_boot_gdt()` and before enabling interrupts.
#[cfg(target_arch = "x86_64")]
pub unsafe fn install_boot_tss(tss_base: u64, tss_limit: u32) -> Result<()> {
    // SAFETY: Boot-time; exclusive access; raw pointer avoids aliasing lint.
    unsafe {
        let ptr = core::ptr::addr_of_mut!(BOOT_GDT);
        (*ptr).install_tss(tss_base, tss_limit)?;
        let gdtr = (*ptr).gdtr();
        load_gdt(&gdtr);
        load_tr(SEL_TSS);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns the DPL (ring level) encoded in a segment selector.
///
/// Bits 1:0 of a selector are the Requested Privilege Level.
pub const fn selector_rpl(sel: u16) -> u8 {
    (sel & 0x3) as u8
}

/// Returns the GDT index from a selector.
pub const fn selector_index(sel: u16) -> usize {
    (sel >> 3) as usize
}

/// Constructs a segment selector from an index and RPL.
pub const fn make_selector(index: usize, rpl: u8) -> u16 {
    ((index as u16) << 3) | (rpl as u16 & 0x3)
}
