// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! High-level MSR read/write abstraction with named register types.
//!
//! This module wraps the raw `rdmsr`/`wrmsr` instructions from `crate::msr`
//! into a typed, safe-ish API:
//!
//! - [`MsrId`] — strongly-typed MSR address.
//! - [`MsrValue`] — parsed representation of common MSRs.
//! - [`MsrBatch`] — read/write multiple MSRs atomically (best-effort).
//! - Convenience wrappers for frequently-used MSRs (EFER, PAT, SYSENTER, …).
//!
//! Reference: Intel 64 and IA-32 Architectures Software Developer's Manual,
//! Volume 4 — Model-Specific Registers.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// MSR Address Type
// ---------------------------------------------------------------------------

/// A strongly-typed MSR address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MsrId(pub u32);

impl MsrId {
    /// IA32_TSC — Time Stamp Counter.
    pub const IA32_TSC: Self = Self(0x0010);
    /// IA32_APIC_BASE — Local APIC base address.
    pub const IA32_APIC_BASE: Self = Self(0x001B);
    /// IA32_MISC_ENABLE — Miscellaneous enables (turbo, prefetch, …).
    pub const IA32_MISC_ENABLE: Self = Self(0x01A0);
    /// IA32_PERF_STATUS — Current P-state (read-only).
    pub const IA32_PERF_STATUS: Self = Self(0x0198);
    /// IA32_PERF_CTL — Target P-state request (write).
    pub const IA32_PERF_CTL: Self = Self(0x0199);
    /// IA32_THERM_STATUS — Thermal status and temperature target.
    pub const IA32_THERM_STATUS: Self = Self(0x019C);
    /// IA32_PAT — Page Attribute Table.
    pub const IA32_PAT: Self = Self(0x0277);
    /// IA32_MTRR_CAP — MTRR capability register.
    pub const IA32_MTRR_CAP: Self = Self(0x00FE);
    /// IA32_MTRR_DEF_TYPE — MTRR default memory type.
    pub const IA32_MTRR_DEF_TYPE: Self = Self(0x02FF);
    /// IA32_EFER — Extended Feature Enable Register.
    pub const IA32_EFER: Self = Self(0xC000_0080);
    /// IA32_STAR — SYSCALL/SYSRET CS/SS selectors.
    pub const IA32_STAR: Self = Self(0xC000_0081);
    /// IA32_LSTAR — 64-bit SYSCALL entry point (RIP).
    pub const IA32_LSTAR: Self = Self(0xC000_0082);
    /// IA32_CSTAR — Compat-mode SYSCALL entry point.
    pub const IA32_CSTAR: Self = Self(0xC000_0083);
    /// IA32_FMASK — SYSCALL EFLAGS mask.
    pub const IA32_FMASK: Self = Self(0xC000_0084);
    /// IA32_FS_BASE — FS segment base.
    pub const IA32_FS_BASE: Self = Self(0xC000_0100);
    /// IA32_GS_BASE — GS segment base.
    pub const IA32_GS_BASE: Self = Self(0xC000_0101);
    /// IA32_KERNEL_GS_BASE — Kernel GS base (swapped by `swapgs`).
    pub const IA32_KERNEL_GS_BASE: Self = Self(0xC000_0102);
    /// IA32_TSC_AUX — TSC auxiliary value (used by RDTSCP).
    pub const IA32_TSC_AUX: Self = Self(0xC000_0103);

    /// Returns the raw address.
    pub const fn addr(self) -> u32 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Raw MSR access
// ---------------------------------------------------------------------------

/// Reads a 64-bit MSR.
///
/// # Safety
/// - `id` must be a valid, readable MSR on the current CPU.
/// - Must be called from ring 0; an invalid address causes `#GP`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn read_msr(id: MsrId) -> u64 {
    // SAFETY: Caller guarantees id is valid and ring 0.
    unsafe { crate::msr::rdmsr(id.0) }
}

/// Writes a 64-bit value to an MSR.
///
/// # Safety
/// - `id` must be a valid, writable MSR on the current CPU.
/// - An incorrect value can alter fundamental CPU behaviour.
/// - Must be called from ring 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn write_msr(id: MsrId, val: u64) {
    // SAFETY: Caller guarantees id and val are valid.
    unsafe { crate::msr::wrmsr(id.0, val) }
}

/// Performs an atomic read-modify-write on an MSR (set bits, clear bits).
///
/// Reads current value, ORs in `set_mask`, clears `clear_mask`, then writes.
///
/// # Safety
/// See `write_msr`. The combined operation is NOT atomic with respect to other CPUs.
#[cfg(target_arch = "x86_64")]
pub unsafe fn modify_msr(id: MsrId, set_mask: u64, clear_mask: u64) {
    // SAFETY: Delegating to read_msr/write_msr; caller is responsible.
    unsafe {
        let val = read_msr(id);
        write_msr(id, (val | set_mask) & !clear_mask);
    }
}

// ---------------------------------------------------------------------------
// EFER helpers
// ---------------------------------------------------------------------------

/// EFER flag bits.
pub mod efer {
    /// SCE — System Call Extensions (`syscall`/`sysret` enable).
    pub const SCE: u64 = 1 << 0;
    /// LME — Long Mode Enable (set before enabling paging).
    pub const LME: u64 = 1 << 8;
    /// LMA — Long Mode Active (read-only; set by hardware).
    pub const LMA: u64 = 1 << 10;
    /// NXE — No-Execute Enable (enables the NX page table bit).
    pub const NXE: u64 = 1 << 11;
    /// SVME — AMD Secure Virtual Machine Enable.
    pub const SVME: u64 = 1 << 12;
}

/// Reads IA32_EFER.
///
/// # Safety
/// Must be called from ring 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn read_efer() -> u64 {
    // SAFETY: EFER is valid on all long-mode CPUs.
    unsafe { read_msr(MsrId::IA32_EFER) }
}

/// Writes IA32_EFER.
///
/// # Safety
/// Clearing LME while in long mode will cause a triple fault.
#[cfg(target_arch = "x86_64")]
pub unsafe fn write_efer(val: u64) {
    // SAFETY: Caller ensures val is a safe EFER value.
    unsafe { write_msr(MsrId::IA32_EFER, val) }
}

/// Enables the NX bit in EFER.
///
/// # Safety
/// Must be called from ring 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn enable_nx() {
    // SAFETY: Setting NXE is always safe on NX-capable CPUs.
    unsafe { modify_msr(MsrId::IA32_EFER, efer::NXE, 0) }
}

// ---------------------------------------------------------------------------
// SYSCALL setup
// ---------------------------------------------------------------------------

/// Configures SYSCALL/SYSRET using the standard MSRs.
///
/// # Parameters
/// - `lstar`: 64-bit SYSCALL entry point (kernel RIP).
/// - `kernel_cs`: Kernel code segment selector (bits 47:32 of STAR).
/// - `user_cs32`: User compatibility CS selector (bits 63:48 of STAR).
/// - `eflags_mask`: EFLAGS bits to clear on SYSCALL entry.
///
/// # Safety
/// - Must be called from ring 0 during boot.
/// - Incorrect `lstar` or selectors will corrupt every future SYSCALL.
#[cfg(target_arch = "x86_64")]
pub unsafe fn setup_syscall(lstar: u64, kernel_cs: u16, user_cs32: u16, eflags_mask: u32) {
    // SAFETY: Boot-time setup; caller guarantees valid params.
    unsafe {
        let star = ((user_cs32 as u64) << 48) | ((kernel_cs as u64) << 32);
        write_msr(MsrId::IA32_STAR, star);
        write_msr(MsrId::IA32_LSTAR, lstar);
        write_msr(MsrId::IA32_FMASK, eflags_mask as u64);
        // Enable SCE in EFER.
        modify_msr(MsrId::IA32_EFER, efer::SCE, 0);
    }
}

// ---------------------------------------------------------------------------
// FS/GS base helpers
// ---------------------------------------------------------------------------

/// Reads the FS segment base.
///
/// # Safety
/// Must be called from ring 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn read_fs_base() -> u64 {
    // SAFETY: Standard MSR; valid in long mode.
    unsafe { read_msr(MsrId::IA32_FS_BASE) }
}

/// Writes the FS segment base (user-space TLS pointer).
///
/// # Safety
/// Incorrect value corrupts the current task's TLS.
#[cfg(target_arch = "x86_64")]
pub unsafe fn write_fs_base(base: u64) {
    // SAFETY: Caller ensures base is the correct TLS pointer.
    unsafe { write_msr(MsrId::IA32_FS_BASE, base) }
}

/// Reads the GS segment base.
///
/// # Safety
/// Must be called from ring 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn read_gs_base() -> u64 {
    // SAFETY: Standard MSR.
    unsafe { read_msr(MsrId::IA32_GS_BASE) }
}

/// Writes the GS segment base (per-CPU pointer in kernel mode).
///
/// # Safety
/// Incorrect value corrupts per-CPU data access.
#[cfg(target_arch = "x86_64")]
pub unsafe fn write_gs_base(base: u64) {
    // SAFETY: Caller ensures base is a valid per-CPU pointer.
    unsafe { write_msr(MsrId::IA32_GS_BASE, base) }
}

/// Reads the kernel GS base (swapped in by `swapgs`).
///
/// # Safety
/// Must be called from ring 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn read_kernel_gs_base() -> u64 {
    // SAFETY: Standard MSR.
    unsafe { read_msr(MsrId::IA32_KERNEL_GS_BASE) }
}

/// Writes the kernel GS base.
///
/// # Safety
/// Incorrect value corrupts kernel per-CPU data on `swapgs`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn write_kernel_gs_base(base: u64) {
    // SAFETY: Caller ensures base is a valid kernel per-CPU pointer.
    unsafe { write_msr(MsrId::IA32_KERNEL_GS_BASE, base) }
}

// ---------------------------------------------------------------------------
// PAT helpers
// ---------------------------------------------------------------------------

/// PAT memory type encodings.
pub mod pat_type {
    /// Uncacheable (UC): no caching, serialising.
    pub const UC: u8 = 0x00;
    /// Write Combining (WC): buffered writes, no caching.
    pub const WC: u8 = 0x01;
    /// Write Through (WT): caching with write-through.
    pub const WT: u8 = 0x04;
    /// Write Protected (WP): reads cached, writes uncached.
    pub const WP: u8 = 0x05;
    /// Write Back (WB): fully cached write-back (default for RAM).
    pub const WB: u8 = 0x06;
    /// Uncacheable Minus (UC-): like UC but can be overridden by MTRRs.
    pub const UC_MINUS: u8 = 0x07;
}

/// Reads the current IA32_PAT value.
///
/// # Safety
/// Must be called from ring 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn read_pat() -> u64 {
    // SAFETY: Standard MSR, read-only semantics.
    unsafe { read_msr(MsrId::IA32_PAT) }
}

/// Writes a new IA32_PAT configuration.
///
/// The PAT register contains 8 entries (one byte each), indexed by bits
/// PAT+PCD+PWT from page table entries. Entry 0 is the default (WB).
///
/// # Safety
/// Incorrect PAT values corrupt memory type semantics for mapped pages.
/// Must be called from ring 0 during early boot.
#[cfg(target_arch = "x86_64")]
pub unsafe fn write_pat(val: u64) {
    // SAFETY: Caller ensures val encodes valid PAT entries.
    unsafe { write_msr(MsrId::IA32_PAT, val) }
}

/// Builds a PAT value from 8 individual memory type bytes.
///
/// # Parameters
/// - `entries`: Array of 8 PAT memory type bytes (use `pat_type::*` constants).
pub const fn build_pat(entries: [u8; 8]) -> u64 {
    (entries[0] as u64)
        | ((entries[1] as u64) << 8)
        | ((entries[2] as u64) << 16)
        | ((entries[3] as u64) << 24)
        | ((entries[4] as u64) << 32)
        | ((entries[5] as u64) << 40)
        | ((entries[6] as u64) << 48)
        | ((entries[7] as u64) << 56)
}

/// Sets up the standard ONCRIX PAT configuration:
/// - Index 0: WB (normal cacheable RAM)
/// - Index 1: WC (framebuffers, DMA rings)
/// - Index 2: WT (write-through mappings)
/// - Index 3: UC (MMIO, device registers)
/// - Index 4: WB (mirrors 0)
/// - Index 5: WP (write-protected)
/// - Index 6: UC- (MTRR-overridable UC)
/// - Index 7: UC (explicit uncacheable)
///
/// # Safety
/// Must be called from ring 0 before enabling paging or after a TLB shootdown.
#[cfg(target_arch = "x86_64")]
pub unsafe fn setup_pat() {
    let val = build_pat([
        pat_type::WB,
        pat_type::WC,
        pat_type::WT,
        pat_type::UC,
        pat_type::WB,
        pat_type::WP,
        pat_type::UC_MINUS,
        pat_type::UC,
    ]);
    // SAFETY: Caller ensures this is called at the appropriate boot stage.
    unsafe { write_pat(val) }
}

// ---------------------------------------------------------------------------
// MSR Batch
// ---------------------------------------------------------------------------

/// Maximum number of entries in a single MSR batch operation.
pub const MSR_BATCH_MAX: usize = 16;

/// A single entry in an MSR batch read or write.
#[derive(Clone, Copy, Debug, Default)]
pub struct MsrBatchEntry {
    /// MSR address.
    pub id: u32,
    /// Value read from or written to the MSR.
    pub value: u64,
}

/// A batch of MSR operations to be performed sequentially.
///
/// Useful for context switching where multiple MSRs must be saved/restored.
pub struct MsrBatch {
    entries: [MsrBatchEntry; MSR_BATCH_MAX],
    count: usize,
}

impl MsrBatch {
    /// Creates an empty batch.
    pub const fn new() -> Self {
        Self {
            entries: [MsrBatchEntry { id: 0, value: 0 }; MSR_BATCH_MAX],
            count: 0,
        }
    }

    /// Adds an MSR to the batch.
    ///
    /// # Errors
    /// Returns `Error::InvalidArgument` if the batch is full.
    pub fn add(&mut self, id: MsrId) -> Result<()> {
        if self.count >= MSR_BATCH_MAX {
            return Err(Error::InvalidArgument);
        }
        self.entries[self.count] = MsrBatchEntry { id: id.0, value: 0 };
        self.count += 1;
        Ok(())
    }

    /// Reads all MSRs in the batch and stores their values.
    ///
    /// # Safety
    /// All MSR IDs in the batch must be valid and readable from ring 0.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn read_all(&mut self) {
        for i in 0..self.count {
            let id = self.entries[i].id;
            // SAFETY: Caller guarantees all IDs are valid.
            self.entries[i].value = unsafe { crate::msr::rdmsr(id) };
        }
    }

    /// Writes all MSRs in the batch with the stored values.
    ///
    /// # Safety
    /// All MSR IDs must be valid and writable. Incorrect values crash the CPU.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn write_all(&self) {
        for i in 0..self.count {
            // SAFETY: Caller guarantees IDs and values are valid.
            unsafe { crate::msr::wrmsr(self.entries[i].id, self.entries[i].value) };
        }
    }

    /// Returns a reference to the entries slice.
    pub fn entries(&self) -> &[MsrBatchEntry] {
        &self.entries[..self.count]
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if there are no entries.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for MsrBatch {
    fn default() -> Self {
        Self::new()
    }
}
