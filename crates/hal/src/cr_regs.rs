// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! x86_64 Control Register access (CR0, CR2, CR3, CR4).
//!
//! Control registers govern fundamental CPU operating modes, including:
//! - **CR0**: Protected mode, paging, cache control, FPU mode.
//! - **CR2**: Page-fault linear address (set by hardware on #PF).
//! - **CR3**: Page table base address and optional PCID.
//! - **CR4**: Extended features (PAE, PSE, SSE, PCIDE, SMEP, SMAP, …).
//!
//! Reference: Intel 64 and IA-32 Architectures Software Developer's Manual,
//! Volume 3A, §2.5 — Control Registers.

// ---------------------------------------------------------------------------
// CR0 Flags
// ---------------------------------------------------------------------------

/// CR0 flag bit-masks.
pub mod cr0 {
    /// PE (Protection Enable): enables protected mode.
    pub const PE: u64 = 1 << 0;
    /// MP (Monitor Coprocessor): controls WAIT/FWAIT with TS.
    pub const MP: u64 = 1 << 1;
    /// EM (Emulation): set to emulate FPU; clears x87/MMX/SSE access.
    pub const EM: u64 = 1 << 2;
    /// TS (Task Switched): cleared by hardware on FPU use; causes #NM.
    pub const TS: u64 = 1 << 3;
    /// ET (Extension Type): read-only; always 1 on modern CPUs.
    pub const ET: u64 = 1 << 4;
    /// NE (Numeric Error): enables internal FPU error reporting (#MF).
    pub const NE: u64 = 1 << 5;
    /// WP (Write Protect): if set, kernel cannot write to read-only user pages.
    pub const WP: u64 = 1 << 16;
    /// AM (Alignment Mask): enables alignment checking when AC and CPL3.
    pub const AM: u64 = 1 << 18;
    /// NW (Not Write-through): if cleared, global write-through is enabled.
    pub const NW: u64 = 1 << 29;
    /// CD (Cache Disable): disables memory caching system-wide.
    pub const CD: u64 = 1 << 30;
    /// PG (Paging Enable): enables paging; requires PE.
    pub const PG: u64 = 1 << 31;
}

// ---------------------------------------------------------------------------
// CR4 Flags
// ---------------------------------------------------------------------------

/// CR4 flag bit-masks.
pub mod cr4 {
    /// VME (Virtual-8086 Mode Extensions).
    pub const VME: u64 = 1 << 0;
    /// PVI (Protected-Mode Virtual Interrupts).
    pub const PVI: u64 = 1 << 1;
    /// TSD (Time Stamp Disable): RDTSC only from ring 0.
    pub const TSD: u64 = 1 << 2;
    /// DE (Debugging Extensions): DR4/DR5 cause #UD.
    pub const DE: u64 = 1 << 3;
    /// PSE (Page Size Extensions): enables 4 MiB pages.
    pub const PSE: u64 = 1 << 4;
    /// PAE (Physical Address Extension): enables 36-bit physical addresses.
    pub const PAE: u64 = 1 << 5;
    /// MCE (Machine-Check Enable): enables `#MC` exception.
    pub const MCE: u64 = 1 << 6;
    /// PGE (Page Global Enable): enables global TLB entries.
    pub const PGE: u64 = 1 << 7;
    /// PCE (Performance-Monitoring Counter Enable): RDPMC from ring 3.
    pub const PCE: u64 = 1 << 8;
    /// OSFXSR: enables FXSAVE/FXRSTOR and SSE.
    pub const OSFXSR: u64 = 1 << 9;
    /// OSXMMEXCPT: enables unmasked SIMD FP exceptions.
    pub const OSXMMEXCPT: u64 = 1 << 10;
    /// UMIP (User-Mode Instruction Prevention): blocks SGDT/SIDT etc. from ring 3.
    pub const UMIP: u64 = 1 << 11;
    /// VMXE (VMX Enable): enables VMX operation.
    pub const VMXE: u64 = 1 << 13;
    /// SMXE (SMX Enable): enables `getsec` instruction.
    pub const SMXE: u64 = 1 << 14;
    /// FSGSBASE: enables RDFSBASE/WRFSBASE/RDGSBASE/WRGSBASE from ring 3.
    pub const FSGSBASE: u64 = 1 << 16;
    /// PCIDE (PCID Enable): enables Process-Context Identifiers in CR3.
    pub const PCIDE: u64 = 1 << 17;
    /// OSXSAVE: enables XSAVE/XRSTOR and the `xgetbv`/`xsetbv` instructions.
    pub const OSXSAVE: u64 = 1 << 18;
    /// KL (Key-Locker Enable): enables AES Key Locker.
    pub const KL: u64 = 1 << 19;
    /// SMEP (Supervisor Mode Execution Prevention): prevents kernel from
    /// executing user-space pages.
    pub const SMEP: u64 = 1 << 20;
    /// SMAP (Supervisor Mode Access Prevention): prevents kernel from
    /// accessing user-space pages unless AC is set.
    pub const SMAP: u64 = 1 << 21;
    /// PKE (Protection Keys for User pages): enables PKRU register.
    pub const PKE: u64 = 1 << 22;
    /// CET (Control-flow Enforcement Technology).
    pub const CET: u64 = 1 << 23;
    /// PKS (Protection Keys for Supervisor pages).
    pub const PKS: u64 = 1 << 24;
    /// UINTR (User Interrupts Enable).
    pub const UINTR: u64 = 1 << 25;
}

// ---------------------------------------------------------------------------
// CR3 helpers
// ---------------------------------------------------------------------------

/// CR3 PML4 table physical address mask (bits 51:12).
pub const CR3_PML4_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// CR3 PCID field (bits 11:0), valid only when CR4.PCIDE = 1.
pub const CR3_PCID_MASK: u64 = 0x0FFF;

/// CR3 bit 63: No-flush flag (only valid when PCIDE=1; skips TLB flush on reload).
pub const CR3_NO_FLUSH: u64 = 1 << 63;

// ---------------------------------------------------------------------------
// CR0 read/write
// ---------------------------------------------------------------------------

/// Reads the current value of CR0.
///
/// # Safety
/// Must be called from ring 0; accessing CR0 from user space causes #GP.
#[cfg(target_arch = "x86_64")]
pub unsafe fn read_cr0() -> u64 {
    let val: u64;
    // SAFETY: `mov %cr0, reg` is a privileged read; caller is in ring 0.
    unsafe {
        core::arch::asm!("mov {0}, cr0", out(reg) val, options(nomem, nostack, preserves_flags));
    }
    val
}

/// Writes a new value to CR0.
///
/// # Safety
/// Incorrect CR0 values can cause immediate CPU faults or silent data
/// corruption (e.g., disabling paging while in paged mode). The caller must
/// ensure the new value is logically consistent.
#[cfg(target_arch = "x86_64")]
pub unsafe fn write_cr0(val: u64) {
    // SAFETY: Caller is responsible for the correctness of `val`.
    unsafe {
        core::arch::asm!("mov cr0, {0}", in(reg) val, options(nomem, nostack, preserves_flags));
    }
}

/// Sets the specified bits in CR0.
///
/// # Safety
/// See `write_cr0`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn set_cr0_bits(bits: u64) {
    // SAFETY: Delegates to write_cr0; same safety requirements.
    unsafe {
        let val = read_cr0();
        write_cr0(val | bits);
    }
}

/// Clears the specified bits in CR0.
///
/// # Safety
/// See `write_cr0`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn clear_cr0_bits(bits: u64) {
    // SAFETY: Delegates to write_cr0; same safety requirements.
    unsafe {
        let val = read_cr0();
        write_cr0(val & !bits);
    }
}

// ---------------------------------------------------------------------------
// CR2 read
// ---------------------------------------------------------------------------

/// Reads CR2 (page-fault linear address).
///
/// Only meaningful inside a #PF handler before the next page fault occurs.
///
/// # Safety
/// Must be called from ring 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn read_cr2() -> u64 {
    let val: u64;
    // SAFETY: `mov %cr2, reg` is privileged; caller is in ring 0.
    unsafe {
        core::arch::asm!("mov {0}, cr2", out(reg) val, options(nomem, nostack, preserves_flags));
    }
    val
}

// ---------------------------------------------------------------------------
// CR3 read/write
// ---------------------------------------------------------------------------

/// Reads CR3 (page table base / PCID).
///
/// # Safety
/// Must be called from ring 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn read_cr3() -> u64 {
    let val: u64;
    // SAFETY: `mov %cr3, reg` is privileged.
    unsafe {
        core::arch::asm!("mov {0}, cr3", out(reg) val, options(nomem, nostack, preserves_flags));
    }
    val
}

/// Writes CR3, switching the active page table.
///
/// When `PCIDE` is disabled in CR4, writing CR3 also flushes the TLB (except
/// global entries). When PCIDE is enabled, set bit 63 of `val` to skip flush.
///
/// # Safety
/// `val` must contain a valid physical address of a PML4 page table. An
/// invalid CR3 will immediately cause a #PF or #GP.
#[cfg(target_arch = "x86_64")]
pub unsafe fn write_cr3(val: u64) {
    // SAFETY: Caller guarantees val is a valid PML4 physical address.
    unsafe {
        core::arch::asm!("mov cr3, {0}", in(reg) val, options(nomem, nostack, preserves_flags));
    }
}

/// Returns the physical address of the active PML4 from CR3.
///
/// # Safety
/// See `read_cr3`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn current_pml4() -> u64 {
    // SAFETY: Delegates to read_cr3.
    unsafe { read_cr3() & CR3_PML4_MASK }
}

// ---------------------------------------------------------------------------
// CR4 read/write
// ---------------------------------------------------------------------------

/// Reads CR4.
///
/// # Safety
/// Must be called from ring 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn read_cr4() -> u64 {
    let val: u64;
    // SAFETY: `mov %cr4, reg` is privileged.
    unsafe {
        core::arch::asm!("mov {0}, cr4", out(reg) val, options(nomem, nostack, preserves_flags));
    }
    val
}

/// Writes CR4.
///
/// # Safety
/// Changing CR4 flags can immediately alter TLB behaviour, SSE availability,
/// and memory protection. The caller must ensure the new value is compatible
/// with the current kernel state.
#[cfg(target_arch = "x86_64")]
pub unsafe fn write_cr4(val: u64) {
    // SAFETY: Caller is responsible for the correctness of `val`.
    unsafe {
        core::arch::asm!("mov cr4, {0}", in(reg) val, options(nomem, nostack, preserves_flags));
    }
}

/// Sets the specified bits in CR4.
///
/// # Safety
/// See `write_cr4`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn set_cr4_bits(bits: u64) {
    // SAFETY: Delegates to write_cr4.
    unsafe {
        let val = read_cr4();
        write_cr4(val | bits);
    }
}

/// Clears the specified bits in CR4.
///
/// # Safety
/// See `write_cr4`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn clear_cr4_bits(bits: u64) {
    // SAFETY: Delegates to write_cr4.
    unsafe {
        let val = read_cr4();
        write_cr4(val & !bits);
    }
}

/// Returns `true` if CR4.PAE (Physical Address Extension) is set.
///
/// # Safety
/// See `read_cr4`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn is_pae_enabled() -> bool {
    // SAFETY: Delegates to read_cr4.
    unsafe { read_cr4() & cr4::PAE != 0 }
}

/// Returns `true` if CR4.PCIDE is set.
///
/// # Safety
/// See `read_cr4`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn is_pcide_enabled() -> bool {
    // SAFETY: Delegates to read_cr4.
    unsafe { read_cr4() & cr4::PCIDE != 0 }
}
