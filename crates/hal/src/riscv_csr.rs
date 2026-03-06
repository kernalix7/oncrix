// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RISC-V Control and Status Register (CSR) access helpers.
//!
//! Provides safe wrappers around RISC-V CSR read/write operations for both
//! machine-mode (M-mode) and supervisor-mode (S-mode) registers. All
//! inline assembly is gated with `#[cfg(target_arch = "riscv64")]`.
//!
//! # CSR Address Space
//!
//! | Range       | Mode          | Description                     |
//! |-------------|---------------|---------------------------------|
//! | 0x000-0x0FF | URO / URW     | Unprivileged read-only/read-write|
//! | 0x100-0x1FF | SRW           | Supervisor read/write            |
//! | 0x200-0x2FF | HRW           | Hypervisor read/write            |
//! | 0x300-0x3FF | MRW           | Machine read/write               |
//! | 0xB00-0xBFF | MRW           | Machine counters/timers          |
//! | 0xC00-0xCFF | URO           | Unprivileged counters (read-only)|
//!
//! # Key CSRs
//!
//! | CSR      | Address | Mode | Description                        |
//! |----------|---------|------|------------------------------------|
//! | mstatus  | 0x300   | MRW  | Machine status                     |
//! | misa     | 0x301   | MRW  | ISA and extensions                 |
//! | mie      | 0x304   | MRW  | Machine interrupt enable           |
//! | mtvec    | 0x305   | MRW  | Machine trap-handler base          |
//! | mscratch | 0x340   | MRW  | Machine scratch                    |
//! | mepc     | 0x341   | MRW  | Machine exception PC               |
//! | mcause   | 0x342   | MRW  | Machine trap cause                 |
//! | mtval    | 0x343   | MRW  | Machine bad address/instruction    |
//! | mip      | 0x344   | MRW  | Machine interrupt pending          |
//! | sstatus  | 0x100   | SRW  | Supervisor status                  |
//! | sie      | 0x104   | SRW  | Supervisor interrupt enable        |
//! | stvec    | 0x105   | SRW  | Supervisor trap-handler base       |
//! | sepc     | 0x141   | SRW  | Supervisor exception PC            |
//! | scause   | 0x142   | SRW  | Supervisor trap cause              |
//! | stval    | 0x143   | SRW  | Supervisor bad address/instruction |
//! | sip      | 0x144   | SRW  | Supervisor interrupt pending       |
//! | satp     | 0x180   | SRW  | Supervisor address translation     |
//! | cycle    | 0xC00   | URO  | Cycle counter                      |
//! | time     | 0xC01   | URO  | Timer (mapped to MTIME)            |
//! | instret  | 0xC02   | URO  | Instructions retired counter       |
//!
//! Reference: RISC-V Privileged Architecture Specification v20211203.

// ---------------------------------------------------------------------------
// mstatus bit fields
// ---------------------------------------------------------------------------

/// mstatus: Machine Interrupt Enable.
pub const MSTATUS_MIE: u64 = 1 << 3;
/// mstatus: Supervisor Interrupt Enable.
pub const MSTATUS_SIE: u64 = 1 << 1;
/// mstatus: Machine Previous Interrupt Enable.
pub const MSTATUS_MPIE: u64 = 1 << 7;
/// mstatus: Supervisor Previous Interrupt Enable.
pub const MSTATUS_SPIE: u64 = 1 << 5;
/// mstatus: Machine Previous Privilege (2 bits, [12:11]).
pub const MSTATUS_MPP_MASK: u64 = 0x3 << 11;
/// mstatus: MPP = M-mode.
pub const MSTATUS_MPP_M: u64 = 0x3 << 11;
/// mstatus: MPP = S-mode.
pub const MSTATUS_MPP_S: u64 = 0x1 << 11;
/// mstatus: MPP = U-mode.
pub const MSTATUS_MPP_U: u64 = 0x0;
/// mstatus: Supervisor Previous Privilege.
pub const MSTATUS_SPP: u64 = 1 << 8;

// ---------------------------------------------------------------------------
// mie / sie bit fields
// ---------------------------------------------------------------------------

/// mie/sie: Machine Software Interrupt Enable.
pub const MIE_MSIE: u64 = 1 << 3;
/// mie/sie: Machine Timer Interrupt Enable.
pub const MIE_MTIE: u64 = 1 << 7;
/// mie/sie: Machine External Interrupt Enable.
pub const MIE_MEIE: u64 = 1 << 11;
/// sie: Supervisor Software Interrupt Enable.
pub const SIE_SSIE: u64 = 1 << 1;
/// sie: Supervisor Timer Interrupt Enable.
pub const SIE_STIE: u64 = 1 << 5;
/// sie: Supervisor External Interrupt Enable.
pub const SIE_SEIE: u64 = 1 << 9;

// ---------------------------------------------------------------------------
// mcause / scause fields
// ---------------------------------------------------------------------------

/// Interrupt bit in mcause/scause (bit 63 on RV64).
pub const CAUSE_INTERRUPT: u64 = 1 << 63;
/// Machine software interrupt cause code.
pub const CAUSE_M_SW_INTR: u64 = 3;
/// Machine timer interrupt cause code.
pub const CAUSE_M_TIMER: u64 = 7;
/// Machine external interrupt cause code.
pub const CAUSE_M_EXT: u64 = 11;
/// Supervisor software interrupt cause code.
pub const CAUSE_S_SW_INTR: u64 = 1;
/// Supervisor timer interrupt cause code.
pub const CAUSE_S_TIMER: u64 = 5;
/// Supervisor external interrupt cause code.
pub const CAUSE_S_EXT: u64 = 9;

// ---------------------------------------------------------------------------
// satp fields
// ---------------------------------------------------------------------------

/// satp: Sv39 paging mode (MODE=8).
pub const SATP_MODE_SV39: u64 = 8u64 << 60;
/// satp: Sv48 paging mode (MODE=9).
pub const SATP_MODE_SV48: u64 = 9u64 << 60;
/// satp: Sv57 paging mode (MODE=10).
pub const SATP_MODE_SV57: u64 = 10u64 << 60;
/// satp: Bare (no translation, MODE=0).
pub const SATP_MODE_BARE: u64 = 0;
/// satp: PPN field mask (bits [43:0]).
pub const SATP_PPN_MASK: u64 = (1u64 << 44) - 1;

// ---------------------------------------------------------------------------
// mtvec mode
// ---------------------------------------------------------------------------

/// mtvec/stvec: Direct mode (all traps to base address).
pub const TVEC_MODE_DIRECT: u64 = 0;
/// mtvec/stvec: Vectored mode (asynchronous interrupts to base + 4*cause).
pub const TVEC_MODE_VECTORED: u64 = 1;

// ---------------------------------------------------------------------------
// CSR read/write macros (riscv64 only)
// ---------------------------------------------------------------------------

/// Reads a CSR by name (riscv64 only).
#[macro_export]
macro_rules! csr_read {
    ($csr:literal) => {{
        #[cfg(target_arch = "riscv64")]
        {
            let val: u64;
            // SAFETY: CSR read is a privileged but non-destructive operation.
            unsafe { core::arch::asm!(concat!("csrr {}, ", $csr), out(reg) val) };
            val
        }
        #[cfg(not(target_arch = "riscv64"))]
        {
            0u64
        }
    }};
}

/// Writes a value to a CSR by name (riscv64 only).
#[macro_export]
macro_rules! csr_write {
    ($csr:literal, $val:expr) => {{
        #[cfg(target_arch = "riscv64")]
        {
            let v: u64 = $val;
            // SAFETY: CSR write updates privileged processor state; caller must
            // ensure the value is valid for the given CSR.
            unsafe { core::arch::asm!(concat!("csrw ", $csr, ", {}"), in(reg) v) };
        }
        #[cfg(not(target_arch = "riscv64"))]
        {
            let _ = $val;
        }
    }};
}

/// Sets bits in a CSR (CSRS instruction).
#[macro_export]
macro_rules! csr_set {
    ($csr:literal, $bits:expr) => {{
        #[cfg(target_arch = "riscv64")]
        {
            let v: u64 = $bits;
            // SAFETY: CSRS atomically sets the specified bits in the CSR.
            unsafe { core::arch::asm!(concat!("csrs ", $csr, ", {}"), in(reg) v) };
        }
        #[cfg(not(target_arch = "riscv64"))]
        {
            let _ = $bits;
        }
    }};
}

/// Clears bits in a CSR (CSRC instruction).
#[macro_export]
macro_rules! csr_clear {
    ($csr:literal, $bits:expr) => {{
        #[cfg(target_arch = "riscv64")]
        {
            let v: u64 = $bits;
            // SAFETY: CSRC atomically clears the specified bits in the CSR.
            unsafe { core::arch::asm!(concat!("csrc ", $csr, ", {}"), in(reg) v) };
        }
        #[cfg(not(target_arch = "riscv64"))]
        {
            let _ = $bits;
        }
    }};
}

// ---------------------------------------------------------------------------
// Typed CSR accessors
// ---------------------------------------------------------------------------

/// Reads the `mstatus` CSR.
#[cfg(target_arch = "riscv64")]
pub fn read_mstatus() -> u64 {
    let val: u64;
    // SAFETY: mstatus is readable in M-mode; non-destructive.
    unsafe { core::arch::asm!("csrr {}, mstatus", out(reg) val) };
    val
}

/// Stub returning 0 on non-riscv64.
#[cfg(not(target_arch = "riscv64"))]
pub fn read_mstatus() -> u64 {
    0
}

/// Writes `mstatus`.
#[cfg(target_arch = "riscv64")]
pub fn write_mstatus(val: u64) {
    // SAFETY: Updating mstatus modifies privilege settings; caller ensures validity.
    unsafe { core::arch::asm!("csrw mstatus, {}", in(reg) val) };
}

/// Stub on non-riscv64.
#[cfg(not(target_arch = "riscv64"))]
pub fn write_mstatus(_val: u64) {}

/// Reads the `sstatus` CSR.
#[cfg(target_arch = "riscv64")]
pub fn read_sstatus() -> u64 {
    let val: u64;
    // SAFETY: sstatus is readable in S-mode+; non-destructive.
    unsafe { core::arch::asm!("csrr {}, sstatus", out(reg) val) };
    val
}

/// Stub returning 0 on non-riscv64.
#[cfg(not(target_arch = "riscv64"))]
pub fn read_sstatus() -> u64 {
    0
}

/// Writes `sstatus`.
#[cfg(target_arch = "riscv64")]
pub fn write_sstatus(val: u64) {
    // SAFETY: Updating sstatus modifies supervisor interrupt and status bits.
    unsafe { core::arch::asm!("csrw sstatus, {}", in(reg) val) };
}

/// Stub on non-riscv64.
#[cfg(not(target_arch = "riscv64"))]
pub fn write_sstatus(_val: u64) {}

/// Reads the `satp` CSR (supervisor address translation and protection).
#[cfg(target_arch = "riscv64")]
pub fn read_satp() -> u64 {
    let val: u64;
    // SAFETY: satp is readable in S-mode+; non-destructive.
    unsafe { core::arch::asm!("csrr {}, satp", out(reg) val) };
    val
}

/// Stub returning 0 on non-riscv64.
#[cfg(not(target_arch = "riscv64"))]
pub fn read_satp() -> u64 {
    0
}

/// Writes `satp` (updates page table root; flushes TLB via sfence.vma).
#[cfg(target_arch = "riscv64")]
pub fn write_satp(val: u64) {
    // SAFETY: Writing satp switches the page table root. The caller must ensure
    // the new PPN points to a valid Sv39/Sv48/Sv57 root table and that the
    // sfence.vma below completes the TLB flush.
    unsafe {
        core::arch::asm!(
            "csrw satp, {}",
            "sfence.vma zero, zero",
            in(reg) val
        )
    };
}

/// Stub on non-riscv64.
#[cfg(not(target_arch = "riscv64"))]
pub fn write_satp(_val: u64) {}

/// Constructs a Sv39 satp value from a physical PPN and ASID.
pub const fn satp_sv39(ppn: u64, asid: u16) -> u64 {
    SATP_MODE_SV39 | ((asid as u64) << 44) | (ppn & SATP_PPN_MASK)
}

/// Reads the `mcause` CSR.
#[cfg(target_arch = "riscv64")]
pub fn read_mcause() -> u64 {
    let val: u64;
    // SAFETY: mcause is readable in M-mode; non-destructive.
    unsafe { core::arch::asm!("csrr {}, mcause", out(reg) val) };
    val
}

/// Stub on non-riscv64.
#[cfg(not(target_arch = "riscv64"))]
pub fn read_mcause() -> u64 {
    0
}

/// Returns `true` if the cause value represents an interrupt (vs exception).
pub const fn is_interrupt(cause: u64) -> bool {
    cause & CAUSE_INTERRUPT != 0
}

/// Returns the exception/interrupt code from a cause value.
pub const fn cause_code(cause: u64) -> u64 {
    cause & !CAUSE_INTERRUPT
}

/// Reads the `cycle` counter CSR (unprivileged).
#[cfg(target_arch = "riscv64")]
pub fn read_cycle() -> u64 {
    let val: u64;
    // SAFETY: cycle CSR is unprivileged read-only; non-destructive.
    unsafe { core::arch::asm!("csrr {}, cycle", out(reg) val) };
    val
}

/// Stub on non-riscv64.
#[cfg(not(target_arch = "riscv64"))]
pub fn read_cycle() -> u64 {
    0
}

/// Reads the `instret` (instructions retired) counter CSR.
#[cfg(target_arch = "riscv64")]
pub fn read_instret() -> u64 {
    let val: u64;
    // SAFETY: instret CSR is unprivileged read-only; non-destructive.
    unsafe { core::arch::asm!("csrr {}, instret", out(reg) val) };
    val
}

/// Stub on non-riscv64.
#[cfg(not(target_arch = "riscv64"))]
pub fn read_instret() -> u64 {
    0
}

/// Performs a full TLB flush (sfence.vma with no arguments).
#[cfg(target_arch = "riscv64")]
pub fn sfence_vma_all() {
    // SAFETY: sfence.vma flushes all TLB entries; safe to call any time.
    unsafe { core::arch::asm!("sfence.vma zero, zero") };
}

/// Stub on non-riscv64.
#[cfg(not(target_arch = "riscv64"))]
pub fn sfence_vma_all() {}

/// Flushes TLB entries for a specific virtual address.
#[cfg(target_arch = "riscv64")]
pub fn sfence_vma_addr(vaddr: u64) {
    // SAFETY: sfence.vma with a specific address flushes only matching TLB entries.
    unsafe { core::arch::asm!("sfence.vma {}, zero", in(reg) vaddr) };
}

/// Stub on non-riscv64.
#[cfg(not(target_arch = "riscv64"))]
pub fn sfence_vma_addr(_vaddr: u64) {}

/// Enables supervisor-mode interrupts (sets SIE in sstatus).
#[cfg(target_arch = "riscv64")]
pub fn enable_supervisor_irqs() {
    // SAFETY: Setting SIE enables supervisor interrupt delivery; requires S-mode.
    unsafe { core::arch::asm!("csrs sstatus, {}", in(reg) MSTATUS_SIE) };
}

/// Stub on non-riscv64.
#[cfg(not(target_arch = "riscv64"))]
pub fn enable_supervisor_irqs() {}

/// Disables supervisor-mode interrupts (clears SIE in sstatus).
#[cfg(target_arch = "riscv64")]
pub fn disable_supervisor_irqs() {
    // SAFETY: Clearing SIE disables supervisor interrupt delivery.
    unsafe { core::arch::asm!("csrc sstatus, {}", in(reg) MSTATUS_SIE) };
}

/// Stub on non-riscv64.
#[cfg(not(target_arch = "riscv64"))]
pub fn disable_supervisor_irqs() {}

/// Reads the `mhartid` CSR (current hart ID in M-mode).
#[cfg(target_arch = "riscv64")]
pub fn read_hartid() -> u64 {
    let val: u64;
    // SAFETY: mhartid is read-only M-mode register; non-destructive.
    unsafe { core::arch::asm!("csrr {}, mhartid", out(reg) val) };
    val
}

/// Returns 0 on non-riscv64.
#[cfg(not(target_arch = "riscv64"))]
pub fn read_hartid() -> u64 {
    0
}
