// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Model-Specific Register (MSR) access for x86_64.
//!
//! MSRs provide access to CPU feature configuration, performance counters,
//! and system call dispatch addresses. Key MSRs on modern Intel/AMD CPUs:
//!
//! | MSR | Purpose |
//! |-----|---------|
//! | `IA32_EFER`       | Extended Feature Enable Register |
//! | `IA32_STAR`       | SYSCALL CS/SS selectors (ring 0 & 3) |
//! | `IA32_LSTAR`      | 64-bit SYSCALL entry point |
//! | `IA32_FMASK`      | SYSCALL EFLAGS mask |
//! | `IA32_FS_BASE`    | FS segment base (user-space TLS) |
//! | `IA32_GS_BASE`    | GS segment base (current CPU) |
//! | `IA32_KERNEL_GS_BASE` | Kernel GS base (swapped by `swapgs`) |
//! | `IA32_TSC`        | Time Stamp Counter |
//! | `IA32_APIC_BASE`  | Local APIC base address |
//! | `IA32_PAT`        | Page Attribute Table |
//!
//! Reference: Intel 64 and IA-32 Architectures Software Developer's Manual,
//! Volume 4 — Model-Specific Registers.

// ---------------------------------------------------------------------------
// Common MSR Addresses
// ---------------------------------------------------------------------------

/// IA32_EFER — Extended Feature Enable Register (SCE, LME, LMA, NXE).
pub const IA32_EFER: u32 = 0xC000_0080;

/// IA32_STAR — SYSCALL/SYSRET CS/SS selectors.
pub const IA32_STAR: u32 = 0xC000_0081;

/// IA32_LSTAR — 64-bit long-mode SYSCALL entry point.
pub const IA32_LSTAR: u32 = 0xC000_0082;

/// IA32_CSTAR — Compatibility-mode SYSCALL entry point (32-bit user code).
pub const IA32_CSTAR: u32 = 0xC000_0083;

/// IA32_FMASK — SYSCALL EFLAGS mask (bits set here are cleared on `syscall`).
pub const IA32_FMASK: u32 = 0xC000_0084;

/// IA32_FS_BASE — FS segment base address.
pub const IA32_FS_BASE: u32 = 0xC000_0100;

/// IA32_GS_BASE — GS segment base address (kernel per-CPU on entry).
pub const IA32_GS_BASE: u32 = 0xC000_0101;

/// IA32_KERNEL_GS_BASE — Kernel GS base (swapped by `swapgs`).
pub const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;

/// IA32_TSC — Time Stamp Counter (also readable with `rdtsc`).
pub const IA32_TSC: u32 = 0x0000_0010;

/// IA32_APIC_BASE — Local APIC base address MSR.
pub const IA32_APIC_BASE: u32 = 0x0000_001B;

/// IA32_PAT — Page Attribute Table.
pub const IA32_PAT: u32 = 0x0000_0277;

/// IA32_MTRR_CAP — MTRR Capability Register (read-only).
pub const IA32_MTRR_CAP: u32 = 0x0000_00FE;

/// IA32_MTRR_DEF_TYPE — MTRR Default Memory Type.
pub const IA32_MTRR_DEF_TYPE: u32 = 0x0000_02FF;

/// IA32_MTRR_PHYSBASE0 — First MTRR variable-range base register.
pub const IA32_MTRR_PHYSBASE0: u32 = 0x0000_0200;

/// IA32_MTRR_PHYSMASK0 — First MTRR variable-range mask register.
pub const IA32_MTRR_PHYSMASK0: u32 = 0x0000_0201;

/// IA32_MC0_CTL — Machine Check bank 0 control.
pub const IA32_MC0_CTL: u32 = 0x0000_0400;

/// IA32_MISC_ENABLE — Miscellaneous feature enables.
pub const IA32_MISC_ENABLE: u32 = 0x0000_01A0;

/// IA32_PERF_CTL — Performance state control.
pub const IA32_PERF_CTL: u32 = 0x0000_0199;

/// IA32_PERF_STATUS — Current performance state.
pub const IA32_PERF_STATUS: u32 = 0x0000_0198;

// ---------------------------------------------------------------------------
// EFER Flag Bits
// ---------------------------------------------------------------------------

/// EFER flags.
pub mod efer {
    /// SCE (System Call Extensions): enables `syscall`/`sysret`.
    pub const SCE: u64 = 1 << 0;
    /// LME (Long Mode Enable): enables IA-32e mode after PE+PG in CR0.
    pub const LME: u64 = 1 << 8;
    /// LMA (Long Mode Active): read-only; set by hardware when LME+PG.
    pub const LMA: u64 = 1 << 10;
    /// NXE (No-Execute Enable): enables the NX bit in page table entries.
    pub const NXE: u64 = 1 << 11;
    /// SVME (Secure Virtual Machine Enable): AMD-specific SVM.
    pub const SVME: u64 = 1 << 12;
    /// LMSLE (Long Mode Segment Limit Enable): AMD-specific.
    pub const LMSLE: u64 = 1 << 13;
    /// FFXSR (Fast FXSAVE/FXRSTOR): AMD-specific bypass for ring-0 saves.
    pub const FFXSR: u64 = 1 << 14;
    /// TCE (Translation Cache Extension): AMD-specific.
    pub const TCE: u64 = 1 << 15;
}

// ---------------------------------------------------------------------------
// APIC_BASE Flags
// ---------------------------------------------------------------------------

/// APIC_BASE MSR bit: Bootstrap Processor flag.
pub const APIC_BASE_BSP: u64 = 1 << 8;
/// APIC_BASE MSR bit: APIC global enable.
pub const APIC_BASE_ENABLE: u64 = 1 << 11;
/// APIC_BASE MSR mask: APIC base physical address (bits 51:12).
pub const APIC_BASE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// ---------------------------------------------------------------------------
// rdmsr / wrmsr
// ---------------------------------------------------------------------------

/// Reads a 64-bit MSR by address.
///
/// # Safety
/// - `msr` must be a valid MSR for the current CPU.
/// - Must be called from ring 0; accessing an invalid or privileged MSR
///   from user mode (or with an invalid address) causes `#GP`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: Caller guarantees `msr` is valid and we are in ring 0.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Writes a 64-bit value to an MSR.
///
/// # Safety
/// - `msr` must be a valid, writable MSR for the current CPU.
/// - An incorrect value can alter fundamental CPU behaviour (e.g., disabling
///   long mode, changing SYSCALL entry point, corrupting PAT).
/// - Must be called from ring 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn wrmsr(msr: u32, val: u64) {
    let lo = val as u32;
    let hi = (val >> 32) as u32;
    // SAFETY: Caller guarantees `msr` is valid and we are in ring 0.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
}

// ---------------------------------------------------------------------------
// Convenience wrappers
// ---------------------------------------------------------------------------

/// Reads the IA32_EFER MSR.
///
/// # Safety
/// See `rdmsr`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn read_efer() -> u64 {
    // SAFETY: IA32_EFER is valid on all long-mode CPUs; caller is ring 0.
    unsafe { rdmsr(IA32_EFER) }
}

/// Writes the IA32_EFER MSR.
///
/// # Safety
/// See `wrmsr`. Clearing LME while in long mode or clearing SCE while
/// syscall stubs reference LSTAR will cause faults.
#[cfg(target_arch = "x86_64")]
pub unsafe fn write_efer(val: u64) {
    // SAFETY: Caller ensures the value is safe to write to EFER.
    unsafe { wrmsr(IA32_EFER, val) }
}

/// Sets specific bits in IA32_EFER.
///
/// # Safety
/// See `write_efer`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn set_efer_bits(bits: u64) {
    // SAFETY: Read-modify-write is safe as long as caller verifies bits.
    unsafe {
        let v = read_efer();
        write_efer(v | bits);
    }
}

/// Reads the current FS base.
///
/// # Safety
/// See `rdmsr`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn read_fs_base() -> u64 {
    // SAFETY: IA32_FS_BASE is a standard MSR available in long mode.
    unsafe { rdmsr(IA32_FS_BASE) }
}

/// Writes the FS base (user-space TLS pointer).
///
/// # Safety
/// See `wrmsr`. Can corrupt the user's TLS if called with wrong value.
#[cfg(target_arch = "x86_64")]
pub unsafe fn write_fs_base(base: u64) {
    // SAFETY: Caller ensures base is a valid TLS pointer for the current task.
    unsafe { wrmsr(IA32_FS_BASE, base) }
}

/// Reads the current GS base.
///
/// # Safety
/// See `rdmsr`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn read_gs_base() -> u64 {
    // SAFETY: Standard MSR.
    unsafe { rdmsr(IA32_GS_BASE) }
}

/// Writes the GS base (per-CPU kernel data on ring-0 entry).
///
/// # Safety
/// See `wrmsr`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn write_gs_base(base: u64) {
    // SAFETY: Caller ensures base is a valid per-CPU pointer.
    unsafe { wrmsr(IA32_GS_BASE, base) }
}

/// Writes the kernel GS base (used with `swapgs`).
///
/// # Safety
/// See `wrmsr`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn write_kernel_gs_base(base: u64) {
    // SAFETY: Caller ensures base is a valid per-CPU kernel pointer.
    unsafe { wrmsr(IA32_KERNEL_GS_BASE, base) }
}

/// Reads the kernel GS base.
///
/// # Safety
/// See `rdmsr`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn read_kernel_gs_base() -> u64 {
    // SAFETY: Standard MSR.
    unsafe { rdmsr(IA32_KERNEL_GS_BASE) }
}

/// Returns the APIC base physical address from IA32_APIC_BASE.
///
/// # Safety
/// See `rdmsr`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn apic_base_addr() -> u64 {
    // SAFETY: IA32_APIC_BASE present on all x86 CPUs with APIC.
    unsafe { rdmsr(IA32_APIC_BASE) & APIC_BASE_ADDR_MASK }
}

/// Configures the SYSCALL/SYSRET mechanism.
///
/// Sets LSTAR to `entry_rip`, STAR to the provided CS/SS selectors,
/// and FMASK to clear `eflags_mask` on `syscall` entry.
///
/// # Parameters
/// - `entry_rip`: Virtual address of the 64-bit syscall handler.
/// - `kernel_cs`: Kernel code segment selector (CS on syscall entry).
/// - `user_cs32`: 32-bit compatibility CS (for sysret to compat mode, rarely used).
/// - `eflags_mask`: EFLAGS bits to clear on syscall entry (e.g., clear IF to avoid
///   taking interrupts while the user stack is active).
///
/// # Safety
/// Incorrect selectors or entry point will make every `syscall` instruction
/// jump to garbage or use the wrong stack. Must be called from ring 0 during boot.
#[cfg(target_arch = "x86_64")]
pub unsafe fn setup_syscall(entry_rip: u64, kernel_cs: u16, user_cs32: u16, eflags_mask: u32) {
    // SAFETY: Caller guarantees ring 0 and valid selectors.
    unsafe {
        // STAR: bits 63:48 = user CS-8 (SYSRET uses +16 for 64-bit),
        //        bits 47:32 = kernel CS
        let star: u64 = ((user_cs32 as u64) << 48) | ((kernel_cs as u64) << 32);
        wrmsr(IA32_STAR, star);
        wrmsr(IA32_LSTAR, entry_rip);
        wrmsr(IA32_FMASK, eflags_mask as u64);
        // Enable SCE bit in EFER
        set_efer_bits(efer::SCE);
    }
}
