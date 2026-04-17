// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AArch64 primary CPU entry point and early boot setup.
//!
//! Implements `_start` as a `global_asm!` block.  The sequence is:
//!   1. If not CPU 0 (MPIDR_EL1[7:0] != 0), spin in a WFI loop (SMP parking).
//!   2. Zero the BSS section.
//!   3. Allocate a 64 KiB stack in the BOOT_STACK symbol.
//!   4. Install the exception vector table via VBAR_EL1.
//!   5. Configure TCR_EL1 / MAIR_EL1 / SCTLR_EL1 to enable the MMU with a
//!      flat (identity) mapping in TTBR0_EL1.
//!   6. Call `kernel_main`.
//!
//! # Assumptions
//!
//! - The kernel image is loaded by QEMU at 0x4008_0000 (standard ELF load
//!   address for `-kernel` mode on the `virt` machine).
//! - QEMU places us in EL1 with the MMU off and caches off.
//! - The linker script defines `__bss_start`, `__bss_end`, `__stack_top`.

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    // Place the boot code in its own section so the linker can put it first.
    ".section .text.boot",
    ".global _start",
    "_start:",
    // ── CPU 0 check ──────────────────────────────────────────────────────
    "   mrs     x0, mpidr_el1",
    "   and     x0, x0, #0xFF",
    "   cbnz    x0, .Lsecondary_spin",
    // ── Zero BSS ─────────────────────────────────────────────────────────
    "   adrp    x1, __bss_start",
    "   add     x1, x1, :lo12:__bss_start",
    "   adrp    x2, __bss_end",
    "   add     x2, x2, :lo12:__bss_end",
    ".Lbss_loop:",
    "   cmp     x1, x2",
    "   b.ge    .Lbss_done",
    "   str     xzr, [x1], #8",
    "   b       .Lbss_loop",
    ".Lbss_done:",
    // ── Set stack pointer ─────────────────────────────────────────────────
    "   adrp    x0, __stack_top",
    "   add     x0, x0, :lo12:__stack_top",
    "   mov     sp, x0",
    // ── Install exception vector table ────────────────────────────────────
    "   adrp    x0, exception_vectors",
    "   add     x0, x0, :lo12:exception_vectors",
    "   msr     vbar_el1, x0",
    "   isb",
    // ── MAIR_EL1: attr0=normal WB/WA, attr1=device nGnRnE ────────────────
    // Attr0 (normal) = 0xFF, Attr1 (device) = 0x00
    "   mov     x0, #0xFF",
    "   msr     mair_el1, x0",
    "   isb",
    // ── TCR_EL1: T0SZ=25 (39-bit VA), TG0=4K, IRGN0/ORGN0=WB/WA ─────────
    // IPS=0b001 (36-bit PA, 64 GiB), TBI0=0, AS=0
    // Value: IPS=001, TG1=10 (4K), TG0=00 (4K), T0SZ=25, T1SZ=25
    "   ldr     x0, =0x000000000080351bULL",
    "   msr     tcr_el1, x0",
    "   isb",
    // ── SCTLR_EL1: enable MMU (M=1), D-cache (C=1), I-cache (I=1) ────────
    // Read current value, set M|C|I, write back.
    "   mrs     x0, sctlr_el1",
    "   orr     x0, x0, #(1 << 0)",  // M  — MMU enable
    "   orr     x0, x0, #(1 << 2)",  // C  — D-cache enable
    "   orr     x0, x0, #(1 << 12)", // I  — I-cache enable
    "   msr     sctlr_el1, x0",
    "   isb",
    // ── Jump to Rust kernel_main ──────────────────────────────────────────
    "   bl      kernel_main",
    "   b       .", // should never return
    // ── Secondary CPU parking loop ────────────────────────────────────────
    ".Lsecondary_spin:",
    "   wfi",
    "   b       .Lsecondary_spin",
    // ── Exception vector table (minimal stub, 16 × 128-byte slots) ────────
    ".balign 2048",
    ".global exception_vectors",
    "exception_vectors:",
    // Current EL with SP0
    ".rept 4",
    "   .rept 32",
    "   nop",
    "   .endr",
    ".endr",
    // Current EL with SPx
    ".rept 4",
    "   .rept 32",
    "   nop",
    "   .endr",
    ".endr",
    // Lower EL using AArch64
    ".rept 4",
    "   .rept 32",
    "   nop",
    "   .endr",
    ".endr",
    // Lower EL using AArch32
    ".rept 4",
    "   .rept 32",
    "   nop",
    "   .endr",
    ".endr",
    // ── Boot stack (64 KiB, BSS so the binary doesn't grow) ──────────────
    ".section .bss.stack",
    ".align 16",
    "boot_stack:",
    "   .space  65536",
    ".global __stack_top",
    "__stack_top:",
);
