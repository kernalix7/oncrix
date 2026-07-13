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
    // ── Build a minimal identity page table in TTBR0_EL1 ─────────────────
    // With TCR T0SZ=27 (37-bit VA) and a 4 KiB granule, the top level is
    // L1 where each entry maps a 1 GiB block. We identity-map two 1 GiB
    // blocks, which covers everything the QEMU `virt` machine needs:
    //   entry 0: VA/PA 0x0000_0000..0x4000_0000 — device MMIO
    //            (GICD 0x0800_0000, GICR 0x080A_0000, PL011 0x0900_0000),
    //            MAIR index 1 (Device-nGnRnE).
    //   entry 1: VA/PA 0x4000_0000..0x8000_0000 — RAM (kernel loads at
    //            0x4008_0000), MAIR index 0 (Normal WB/WA).
    // Block descriptor bits: bit0=1 (valid), bit1=0 (block, not table),
    // AttrIndx = bits[4:2], NS=bit5, AP=0b00 bits[7:6] (EL1 RW), SH=0b11
    // bits[9:8] (inner shareable), AF=bit10 (access flag) = 1.
    // Normal block flags = AF|SH_inner|AttrIdx0|valid = (1<<10)|(3<<8)|(0<<2)|1
    // Device block flags = AF|AttrIdx1|valid = (1<<10)|(1<<2)|1
    // (device memory is outer-shareable implicitly; SH is ignored for it.)
    "   adrp    x0, __ttbr0_l1",
    "   add     x0, x0, :lo12:__ttbr0_l1",
    // entry 0 → device block at PA 0
    "   mov     x1, #0x0",
    "   movz    x2, #0x0405", // (1<<10)|(1<<2)|1 = 0x405
    "   orr     x1, x1, x2",
    "   str     x1, [x0]",
    // entry 1 → normal block at PA 0x4000_0000
    "   movz    x1, #0x4000, lsl #16", // PA 0x4000_0000
    "   movz    x2, #0x0701",          // (1<<10)|(3<<8)|1 = 0x701
    "   orr     x1, x1, x2",
    "   str     x1, [x0, #8]",
    // TTBR0_EL1 = &__ttbr0_l1
    "   msr     ttbr0_el1, x0",
    "   isb",
    // Invalidate TLB and ensure page-table writes are visible.
    "   dsb     ish",
    "   tlbi    vmalle1",
    "   dsb     ish",
    "   isb",
    // ── SCTLR_EL1: enable MMU (M=1), D-cache (C=1), I-cache (I=1) ────────
    "   mrs     x0, sctlr_el1",
    "   orr     x0, x0, #(1 << 0)",  // M — MMU enable
    "   orr     x0, x0, #(1 << 2)",  // C — D-cache enable
    "   orr     x0, x0, #(1 << 12)", // I — I-cache enable
    "   msr     sctlr_el1, x0",
    "   isb",
    // ── Enable FP/SIMD access at EL0/EL1 ─────────────────────────────────
    // Rust codegen for aarch64 emits Advanced SIMD/NEON (memcpy, slice ops,
    // formatting). Without CPACR_EL1.FPEN = 0b11 those instructions trap
    // (ESR EC=0x07) the first time they execute, so this must run before any
    // Rust code (kernel_main).
    "   mrs     x0, cpacr_el1",
    "   orr     x0, x0, #(0b11 << 20)",
    "   msr     cpacr_el1, x0",
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
    // ── TTBR0_EL1 level-1 identity page table (4 KiB, 4 KiB-aligned) ─────
    // 512 × 8-byte descriptors; only entries 0 (device) and 1 (RAM) are
    // populated by _start, the rest stay zero (invalid). BSS-resident so
    // it is zeroed by the boot BSS-clear before use.
    ".section .bss.pagetable",
    ".align 12",
    "__ttbr0_l1:",
    "   .space  4096",
);
