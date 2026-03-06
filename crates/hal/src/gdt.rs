// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Global Descriptor Table (GDT) management.
//!
//! The GDT defines memory segments for the x86_64 processor. In 64-bit mode,
//! most segmentation is flat, but the GDT is still required for:
//! - Kernel/user code and data segments
//! - Task State Segment (TSS) descriptor for syscall/interrupt stacks
//! - Privilege level transitions (ring 0 / ring 3)
//!
//! Reference: Intel 64 and IA-32 Architectures Software Developer's Manual,
//! Volume 3A, Chapter 3 — Protected-Mode Memory Management.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Segment Selector Constants
// ---------------------------------------------------------------------------

/// Null segment selector (index 0).
pub const SEG_NULL: u16 = 0x00;

/// Kernel code segment selector (ring 0, 64-bit code).
pub const KERNEL_CODE: u16 = 0x08;

/// Kernel data segment selector (ring 0).
pub const KERNEL_DATA: u16 = 0x10;

/// User data segment selector (ring 3).
pub const USER_DATA: u16 = 0x18 | 3;

/// User code segment selector (ring 3, 64-bit code).
pub const USER_CODE: u16 = 0x20 | 3;

/// TSS low descriptor selector (64-bit TSS occupies 2 entries).
pub const TSS_SEL: u16 = 0x28;

/// Maximum number of GDT entries.
pub const GDT_ENTRIES: usize = 64;

// ---------------------------------------------------------------------------
// Access Byte Flags
// ---------------------------------------------------------------------------

/// Access byte: Segment present bit.
const ACCESS_PRESENT: u8 = 1 << 7;

/// Access byte: Descriptor Privilege Level shift.
const ACCESS_DPL_SHIFT: u8 = 5;

/// Access byte: Descriptor type (1 = code/data, 0 = system).
const ACCESS_DESC_TYPE: u8 = 1 << 4;

/// Access byte: Executable bit (code segment).
const ACCESS_EXEC: u8 = 1 << 3;

/// Access byte: Direction/Conforming bit.
const ACCESS_DC: u8 = 1 << 2;

/// Access byte: Readable/Writable bit.
const ACCESS_RW: u8 = 1 << 1;

/// Access byte: Accessed bit (CPU sets this on use).
const ACCESS_ACCESSED: u8 = 1 << 0;

/// Access byte: TSS available (system segment type for 64-bit TSS).
const ACCESS_TSS_AVAILABLE: u8 = 0x09;

// ---------------------------------------------------------------------------
// Granularity Byte Flags
// ---------------------------------------------------------------------------

/// Granularity byte: 4 KiB page granularity.
const GRAN_PAGE: u8 = 1 << 7;

/// Granularity byte: 32-bit protected mode default op size.
const GRAN_32BIT: u8 = 1 << 6;

/// Granularity byte: 64-bit code segment flag (L bit).
const GRAN_LONG: u8 = 1 << 5;

// ---------------------------------------------------------------------------
// GDT Entry
// ---------------------------------------------------------------------------

/// A single 8-byte GDT entry (segment descriptor).
///
/// Layout (Intel manual Vol. 3A, Figure 3-8):
/// ```text
/// Bits 63:56  Base 31:24
/// Bits 55:52  Flags (G, D/B, L, AVL)
/// Bits 51:48  Limit 19:16
/// Bits 47:40  Access byte
/// Bits 39:32  Base 23:16
/// Bits 31:16  Base 15:0
/// Bits 15:0   Limit 15:0
/// ```
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct GdtEntry {
    /// Limit bits 0-15.
    pub limit_low: u16,
    /// Base bits 0-15.
    pub base_low: u16,
    /// Base bits 16-23.
    pub base_mid: u8,
    /// Access byte (present, DPL, type, exec, DC, RW, accessed).
    pub access: u8,
    /// Limit bits 16-19 in low nibble; flags in high nibble.
    pub granularity: u8,
    /// Base bits 24-31.
    pub base_high: u8,
}

impl GdtEntry {
    /// Creates a null (empty) GDT entry.
    pub const fn null() -> Self {
        Self {
            limit_low: 0,
            base_low: 0,
            base_mid: 0,
            access: 0,
            granularity: 0,
            base_high: 0,
        }
    }

    /// Creates a flat 64-bit code segment descriptor.
    ///
    /// # Parameters
    /// - `dpl`: Descriptor Privilege Level (0 = kernel, 3 = user).
    pub const fn code64(dpl: u8) -> Self {
        let access =
            ACCESS_PRESENT | (dpl << ACCESS_DPL_SHIFT) | ACCESS_DESC_TYPE | ACCESS_EXEC | ACCESS_RW;
        let granularity = GRAN_LONG;
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access,
            granularity,
            base_high: 0,
        }
    }

    /// Creates a flat 64-bit data segment descriptor.
    ///
    /// # Parameters
    /// - `dpl`: Descriptor Privilege Level (0 = kernel, 3 = user).
    pub const fn data64(dpl: u8) -> Self {
        let access = ACCESS_PRESENT | (dpl << ACCESS_DPL_SHIFT) | ACCESS_DESC_TYPE | ACCESS_RW;
        let granularity = GRAN_PAGE | GRAN_32BIT;
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access,
            granularity,
            base_high: 0,
        }
    }

    /// Creates a 32-bit TSS descriptor (low 8 bytes of a 16-byte system entry).
    ///
    /// A 64-bit TSS descriptor occupies two consecutive GDT slots.
    /// This function builds the low half; the high half stores base bits 63:32.
    ///
    /// # Parameters
    /// - `base`: Virtual address of the TSS structure.
    /// - `limit`: Size of the TSS minus 1.
    pub fn tss_low(base: u64, limit: u32) -> Self {
        let access = ACCESS_PRESENT | ACCESS_TSS_AVAILABLE;
        Self {
            limit_low: (limit & 0xFFFF) as u16,
            base_low: (base & 0xFFFF) as u16,
            base_mid: ((base >> 16) & 0xFF) as u8,
            access,
            granularity: (((limit >> 16) & 0x0F) as u8) | GRAN_PAGE,
            base_high: ((base >> 24) & 0xFF) as u8,
        }
    }

    /// Creates the high 8 bytes of a 64-bit TSS descriptor.
    pub fn tss_high(base: u64) -> Self {
        // Upper 32 bits of base address stored in low 32 bits of this entry.
        let upper = (base >> 32) as u32;
        Self {
            limit_low: (upper & 0xFFFF) as u16,
            base_low: ((upper >> 16) & 0xFFFF) as u16,
            base_mid: 0,
            access: 0,
            granularity: 0,
            base_high: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// GDT Table
// ---------------------------------------------------------------------------

/// GDTR descriptor loaded with `lgdt`.
#[repr(C, packed)]
pub struct GdtDescriptor {
    /// Table size in bytes minus 1.
    pub limit: u16,
    /// Linear address of the GDT.
    pub base: u64,
}

/// Holds the full GDT with 64 entries.
pub struct GdtTable {
    entries: [GdtEntry; GDT_ENTRIES],
    count: usize,
}

impl GdtTable {
    /// Creates an empty GDT table with the mandatory null descriptor at index 0.
    pub fn new() -> Self {
        let mut t = Self {
            entries: [GdtEntry::null(); GDT_ENTRIES],
            count: 1, // entry 0 is always null
        };
        // Standard flat descriptors
        t.entries[1] = GdtEntry::code64(0); // 0x08 — kernel code
        t.entries[2] = GdtEntry::data64(0); // 0x10 — kernel data
        t.entries[3] = GdtEntry::data64(3); // 0x18 — user data
        t.entries[4] = GdtEntry::code64(3); // 0x20 — user code
        t.count = 5;
        t
    }

    /// Returns a pointer to the raw GDT entries array.
    pub fn as_ptr(&self) -> *const GdtEntry {
        self.entries.as_ptr()
    }

    /// Returns number of valid entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the table has no entries beyond the null descriptor.
    pub fn is_empty(&self) -> bool {
        self.count <= 1
    }

    /// Sets a TSS descriptor at `TSS_SEL` index (entries 5 and 6).
    ///
    /// # Parameters
    /// - `tss_base`: Virtual address of the TSS.
    /// - `tss_limit`: Size of the TSS structure minus 1.
    pub fn set_tss(&mut self, tss_base: u64, tss_limit: u32) -> Result<()> {
        let idx = (TSS_SEL / 8) as usize;
        if idx + 1 >= GDT_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        self.entries[idx] = GdtEntry::tss_low(tss_base, tss_limit);
        self.entries[idx + 1] = GdtEntry::tss_high(tss_base);
        if self.count < idx + 2 {
            self.count = idx + 2;
        }
        Ok(())
    }

    /// Builds the GDTR descriptor for this table.
    pub fn descriptor(&self) -> GdtDescriptor {
        GdtDescriptor {
            limit: (self.count * core::mem::size_of::<GdtEntry>() - 1) as u16,
            base: self.entries.as_ptr() as u64,
        }
    }
}

impl Default for GdtTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Load GDT
// ---------------------------------------------------------------------------

/// Loads the GDT and reloads segment registers.
///
/// # Safety
/// Caller must ensure `gdtr` points to a valid, correctly-sized GDT that
/// will remain resident in memory for the lifetime of the CPU mode.
/// Incorrect GDT contents will cause a General Protection Fault (#GP).
#[cfg(target_arch = "x86_64")]
pub unsafe fn load_gdt(gdtr: &GdtDescriptor) {
    // SAFETY: Caller guarantees the GDTR is valid and the GDT is resident.
    // We perform a far return (retfq) to atomically reload CS with KERNEL_CODE.
    unsafe {
        let kcs = KERNEL_CODE as u64;
        let kds = KERNEL_DATA as u64;
        core::arch::asm!(
            "lgdt [{gdtr}]",
            // Build a far-return frame: [RIP of 2f, CS]
            "push {kcs}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            // Reload data segment registers
            "mov ax, {kds:x}",
            "mov ds, ax",
            "mov es, ax",
            "mov fs, ax",
            "mov gs, ax",
            "mov ss, ax",
            gdtr = in(reg) gdtr as *const GdtDescriptor,
            kcs  = in(reg) kcs,
            kds  = in(reg) kds,
            tmp  = out(reg) _,
            options(nostack),
        );
    }
}

// ---------------------------------------------------------------------------
// Global GDT instance
// ---------------------------------------------------------------------------

/// Global GDT table for the boot CPU.
static mut BOOT_GDT: GdtTable = GdtTable {
    entries: [GdtEntry::null(); GDT_ENTRIES],
    count: 0,
};

/// Initialises the boot CPU GDT with standard flat descriptors and loads it.
///
/// # Safety
/// Must be called exactly once during early boot, before interrupts are
/// enabled, on the boot CPU. Not safe to call from multiple CPUs simultaneously.
#[cfg(target_arch = "x86_64")]
pub unsafe fn init_gdt() {
    // SAFETY: Called once before SMP init; exclusive mutable access via raw ptr.
    unsafe {
        let gdt_ptr = core::ptr::addr_of_mut!(BOOT_GDT);
        gdt_ptr.write(GdtTable::new());
        let gdtr = (*gdt_ptr).descriptor();
        load_gdt(&gdtr);
    }
}

/// Installs a TSS descriptor into the boot GDT and reloads.
///
/// # Safety
/// Must be called after `init_gdt` and before enabling interrupts.
/// `tss_base` must point to a valid TSS structure.
#[cfg(target_arch = "x86_64")]
pub unsafe fn install_tss(tss_base: u64, tss_limit: u32) -> Result<()> {
    // SAFETY: Caller ensures TSS is valid; raw ptr avoids static_mut_refs lint.
    unsafe {
        let gdt_ptr = core::ptr::addr_of_mut!(BOOT_GDT);
        (*gdt_ptr).set_tss(tss_base, tss_limit)?;
        let gdtr = (*gdt_ptr).descriptor();
        load_gdt(&gdtr);
    }
    Ok(())
}

/// Builds a segment descriptor from explicit parameters.
///
/// # Parameters
/// - `base`: 32-bit segment base address.
/// - `limit`: 20-bit limit (page or byte granularity depending on flags).
/// - `access`: Access byte value.
/// - `flags`: Upper nibble of the granularity byte (G, D/B, L, AVL).
pub fn build_descriptor(base: u32, limit: u32, access: u8, flags: u8) -> GdtEntry {
    GdtEntry {
        limit_low: (limit & 0xFFFF) as u16,
        base_low: (base & 0xFFFF) as u16,
        base_mid: ((base >> 16) & 0xFF) as u8,
        access,
        granularity: ((flags & 0x0F) << 4) | (((limit >> 16) & 0x0F) as u8),
        base_high: ((base >> 24) & 0xFF) as u8,
    }
}

/// Returns the access byte for a kernel code segment.
pub const fn kernel_code_access() -> u8 {
    ACCESS_PRESENT | ACCESS_DESC_TYPE | ACCESS_EXEC | ACCESS_RW
}

/// Returns the access byte for a kernel data segment.
pub const fn kernel_data_access() -> u8 {
    ACCESS_PRESENT | ACCESS_DESC_TYPE | ACCESS_RW
}

/// Returns the access byte for a user code segment (DPL 3).
pub const fn user_code_access() -> u8 {
    ACCESS_PRESENT | (3 << ACCESS_DPL_SHIFT) | ACCESS_DESC_TYPE | ACCESS_EXEC | ACCESS_RW
}

/// Returns the access byte for a user data segment (DPL 3).
pub const fn user_data_access() -> u8 {
    ACCESS_PRESENT | (3 << ACCESS_DPL_SHIFT) | ACCESS_DESC_TYPE | ACCESS_RW
}

/// Marks the accessed bit in an access byte (used by the CPU automatically).
pub const fn mark_accessed(access: u8) -> u8 {
    access | ACCESS_ACCESSED
}

/// Returns `true` if the given selector refers to a kernel segment.
pub const fn is_kernel_selector(sel: u16) -> bool {
    (sel & 0x3) == 0
}

/// Returns the ring level (0–3) of a selector.
pub const fn selector_dpl(sel: u16) -> u8 {
    (sel & 0x3) as u8
}

/// Returns the GDT index from a segment selector.
pub const fn selector_index(sel: u16) -> usize {
    (sel >> 3) as usize
}

/// Constructs a segment selector from an index and DPL.
pub const fn make_selector(index: usize, dpl: u8) -> u16 {
    ((index as u16) << 3) | (dpl as u16 & 0x3)
}
