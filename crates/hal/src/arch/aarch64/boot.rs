// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AArch64 primary CPU entry point and early boot setup.
//!
//! Implements `_start` as a `global_asm!` block.  The sequence is:
//!   1. If not CPU 0 (MPIDR_EL1[7:0] != 0), spin in a WFI loop (SMP parking).
//!   2. Zero the BSS section.
//!   3. Allocate a 64 KiB stack in the BOOT_STACK symbol.
//!   4. Install the exception vector table via VBAR_EL1.
//!   5. Configure TCR_EL1 / MAIR_EL1 / SCTLR_EL1 and install the kernel and
//!      user mappings in TTBR0_EL1 before enabling the MMU.
//!   6. Call `kernel_main`.
//!
//! # Assumptions
//!
//! - The kernel image is loaded by QEMU at 0x4008_0000 (standard ELF load
//!   address for `-kernel` mode on the `virt` machine).
//! - QEMU places us in EL1 with the MMU off and caches off.
//! - The linker script defines the BSS, kernel stack, user text, and user stack symbols.

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
    // ── TCR_EL1: T0SZ=27 (37-bit VA), TG0=4K, IRGN0/ORGN0=WB/WA ─────────
    // SH0=inner-shareable, EPD1=1 (disable TTBR1 walks), IPS=000 (32-bit PA).
    // A 37-bit VA with a 4 KiB granule starts translation at level 1.
    "   ldr     x0, =0x000000000080351bULL",
    "   msr     tcr_el1, x0",
    "   isb",
    // ── Build the initial translation tables in TTBR0_EL1 ────────────────
    // With TCR T0SZ=27 (37-bit VA) and a 4 KiB granule, the top level is
    // L1 where each entry covers a 1 GiB range. We identity-map two 1 GiB
    // blocks for the QEMU `virt` machine and use page tables for userspace:
    //   entry 0: VA/PA 0x0000_0000..0x4000_0000 — device MMIO
    //            (GICD 0x0800_0000, GICR 0x080A_0000, PL011 0x0900_0000),
    //            MAIR index 1 (Device-nGnRnE).
    //   entry 1: VA/PA 0x4000_0000..0x8000_0000 — EL1-only RAM (kernel loads
    //            at 0x4008_0000), MAIR index 0 (Normal WB/WA).
    //   entry 3: VA 0xC000_0000..0x1_0000_0000 — L2/L3 user page tables.
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
    // entry 1 -> normal block at PA 0x4000_0000, EL1-only identity mapping.
    // PTE 0x0701 uses AP=0b00 (bits[7:6]=00), so EL0 cannot access it.
    "   movz    x1, #0x4000, lsl #16", // PA 0x4000_0000
    "   movz    x2, #0x0701",          // (1<<10)|(3<<8)|1 = 0x701 (EL1 RW/X)
    "   orr     x1, x1, x2",
    "   str     x1, [x0, #8]",
    // entry 3 -> L2 table for the user VA range beginning at 0xC000_0000.
    "   adrp    x1, __ttbr0_user_l2",
    "   add     x1, x1, :lo12:__ttbr0_user_l2",
    "   mov     x2, #0x3", // Valid level-1 table descriptor.
    "   orr     x4, x1, x2",
    "   str     x4, [x0, #24]",
    // L2[0] -> L3 table covering VA 0xC000_0000..0xC020_0000.
    "   adrp    x3, __ttbr0_user_l3",
    "   add     x3, x3, :lo12:__ttbr0_user_l3",
    "   orr     x4, x3, x2",
    "   str     x4, [x1]",
    // L3[0] maps the user text page read-only and executable only at EL0.
    "   adrp    x4, __user_text_start",
    "   add     x4, x4, :lo12:__user_text_start",
    "   ldr     x5, =0x0020000000000FC3ULL", // PXN|nG|AF|SH|AP11|page.
    "   orr     x4, x4, x5",
    "   str     x4, [x3]",
    // L3[1] stays invalid as a guard page. L3[2..5] map the 16 KiB user stack.
    "   adrp    x4, __user_stack_start",
    "   add     x4, x4, :lo12:__user_stack_start",
    "   ldr     x5, =0x0060000000000F43ULL", // UXN|PXN|nG|AF|SH|AP01|page.
    "   add     x3, x3, #16",
    "   mov     x6, #4",
    ".Lmap_user_stack:",
    "   orr     x7, x4, x5",
    "   str     x7, [x3], #8",
    "   add     x4, x4, #1, lsl #12",
    "   subs    x6, x6, #1",
    "   b.ne    .Lmap_user_stack",
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
    // ── Exception vector table (16 × 128-byte slots, 2 KiB-aligned) ──────
    // The kernel runs at EL1h (SP_EL1), so hardware IRQs are delivered to
    // the "Current EL with SPx / IRQ" slot at offset 0x280 (index 5). That
    // slot vectors to `el1h_irq`, which saves a full trap frame, calls the
    // Rust handler `aarch64_handle_irq`, restores, and `eret`s. Apart from that
    // IRQ slot and the handled lower-EL AArch64 synchronous slot, vectors use
    // `el1_default`, which spins so an unexpected exception stops at a known PC
    // (visible under `qemu -d int`). Each slot is padded to 128 bytes.
    ".balign 2048",
    ".global exception_vectors",
    "exception_vectors:",
    // Current EL with SP0 (unused — we run on SPx)
    "   b       el1_default", // 0x000 Sync
    ".balign 0x80",
    "   b       el1_default", // 0x080 IRQ
    ".balign 0x80",
    "   b       el1_default", // 0x100 FIQ
    ".balign 0x80",
    "   b       el1_default", // 0x180 SError
    ".balign 0x80",
    // Current EL with SPx (the kernel's own EL1h context)
    "   b       el1_default", // 0x200 Sync
    ".balign 0x80",
    "   b       el1h_irq", // 0x280 IRQ  ← timer / device interrupts
    ".balign 0x80",
    "   b       el1_default", // 0x300 FIQ
    ".balign 0x80",
    "   b       el1_default", // 0x380 SError
    ".balign 0x80",
    // Lower EL using AArch64 (userspace)
    "   b       el0_sync", // 0x400 Sync from EL0 (SVC / user fault)
    ".balign 0x80",
    "   b       el1_default", // 0x480 IRQ
    ".balign 0x80",
    "   b       el1_default", // 0x500 FIQ
    ".balign 0x80",
    "   b       el1_default", // 0x580 SError
    ".balign 0x80",
    // Lower EL using AArch32 (unsupported)
    "   b       el1_default", // 0x600 Sync
    ".balign 0x80",
    "   b       el1_default", // 0x680 IRQ
    ".balign 0x80",
    "   b       el1_default", // 0x700 FIQ
    ".balign 0x80",
    "   b       el1_default", // 0x780 SError
    ".balign 0x80",
    // ── el1h_irq: save trap frame, call Rust handler, restore, eret ──────
    // Frame (288 bytes, 16-byte aligned): x0..x30 in pairs, then ELR_EL1 +
    // SPSR_EL1. ELR/SPSR MUST be stacked because sched_yield_once may switch
    // to another thread whose own IRQ would otherwise clobber those system
    // registers before this thread is re-elected and eret's.
    "el1h_irq:",
    "   sub     sp, sp, #0x120",
    "   stp     x0, x1, [sp, #0x00]",
    "   stp     x2, x3, [sp, #0x10]",
    "   stp     x4, x5, [sp, #0x20]",
    "   stp     x6, x7, [sp, #0x30]",
    "   stp     x8, x9, [sp, #0x40]",
    "   stp     x10, x11, [sp, #0x50]",
    "   stp     x12, x13, [sp, #0x60]",
    "   stp     x14, x15, [sp, #0x70]",
    "   stp     x16, x17, [sp, #0x80]",
    "   stp     x18, x19, [sp, #0x90]",
    "   stp     x20, x21, [sp, #0xa0]",
    "   stp     x22, x23, [sp, #0xb0]",
    "   stp     x24, x25, [sp, #0xc0]",
    "   stp     x26, x27, [sp, #0xd0]",
    "   stp     x28, x29, [sp, #0xe0]",
    "   str     x30, [sp, #0xf0]",
    "   mrs     x0, elr_el1",
    "   mrs     x1, spsr_el1",
    "   stp     x0, x1, [sp, #0x100]",
    "   bl      aarch64_handle_irq",
    "   ldp     x0, x1, [sp, #0x100]",
    "   msr     elr_el1, x0",
    "   msr     spsr_el1, x1",
    "   ldp     x0, x1, [sp, #0x00]",
    "   ldp     x2, x3, [sp, #0x10]",
    "   ldp     x4, x5, [sp, #0x20]",
    "   ldp     x6, x7, [sp, #0x30]",
    "   ldp     x8, x9, [sp, #0x40]",
    "   ldp     x10, x11, [sp, #0x50]",
    "   ldp     x12, x13, [sp, #0x60]",
    "   ldp     x14, x15, [sp, #0x70]",
    "   ldp     x16, x17, [sp, #0x80]",
    "   ldp     x18, x19, [sp, #0x90]",
    "   ldp     x20, x21, [sp, #0xa0]",
    "   ldp     x22, x23, [sp, #0xb0]",
    "   ldp     x24, x25, [sp, #0xc0]",
    "   ldp     x26, x27, [sp, #0xd0]",
    "   ldp     x28, x29, [sp, #0xe0]",
    "   ldr     x30, [sp, #0xf0]",
    "   add     sp, sp, #0x120",
    "   eret",
    // ── el0_sync: synchronous exception from EL0 (SVC / user fault) ──────
    // Same 288-byte trap frame as el1h_irq. The Rust handler reads ESR_EL1
    // to classify the exception (SVC #imm for a syscall); on return we
    // restore ELR_EL1/SPSR_EL1 (still pointing just past the SVC, in EL0
    // state) and `eret` back to user. On EL0 entry the CPU is at EL1h, so
    // SP is the kernel stack — the frame is pushed there.
    "el0_sync:",
    "   sub     sp, sp, #0x120",
    "   stp     x0, x1, [sp, #0x00]",
    "   stp     x2, x3, [sp, #0x10]",
    "   stp     x4, x5, [sp, #0x20]",
    "   stp     x6, x7, [sp, #0x30]",
    "   stp     x8, x9, [sp, #0x40]",
    "   stp     x10, x11, [sp, #0x50]",
    "   stp     x12, x13, [sp, #0x60]",
    "   stp     x14, x15, [sp, #0x70]",
    "   stp     x16, x17, [sp, #0x80]",
    "   stp     x18, x19, [sp, #0x90]",
    "   stp     x20, x21, [sp, #0xa0]",
    "   stp     x22, x23, [sp, #0xb0]",
    "   stp     x24, x25, [sp, #0xc0]",
    "   stp     x26, x27, [sp, #0xd0]",
    "   stp     x28, x29, [sp, #0xe0]",
    "   str     x30, [sp, #0xf0]",
    "   mrs     x0, elr_el1",
    "   mrs     x1, spsr_el1",
    "   stp     x0, x1, [sp, #0x100]",
    "   bl      aarch64_handle_sync_lower",
    "   ldp     x0, x1, [sp, #0x100]",
    "   msr     elr_el1, x0",
    "   msr     spsr_el1, x1",
    "   ldp     x0, x1, [sp, #0x00]",
    "   ldp     x2, x3, [sp, #0x10]",
    "   ldp     x4, x5, [sp, #0x20]",
    "   ldp     x6, x7, [sp, #0x30]",
    "   ldp     x8, x9, [sp, #0x40]",
    "   ldp     x10, x11, [sp, #0x50]",
    "   ldp     x12, x13, [sp, #0x60]",
    "   ldp     x14, x15, [sp, #0x70]",
    "   ldp     x16, x17, [sp, #0x80]",
    "   ldp     x18, x19, [sp, #0x90]",
    "   ldp     x20, x21, [sp, #0xa0]",
    "   ldp     x22, x23, [sp, #0xb0]",
    "   ldp     x24, x25, [sp, #0xc0]",
    "   ldp     x26, x27, [sp, #0xd0]",
    "   ldp     x28, x29, [sp, #0xe0]",
    "   ldr     x30, [sp, #0xf0]",
    "   add     sp, sp, #0x120",
    "   eret",
    // ── el1_default: park on an unexpected exception ─────────────────────
    "el1_default:",
    "   b       .",
    // ── Boot stack (64 KiB, BSS so the binary doesn't grow) ──────────────
    ".section .bss.stack",
    ".align 16",
    "boot_stack:",
    "   .space  65536",
    ".global __stack_top",
    "__stack_top:",
    // ── TTBR0_EL1 translation tables (three 4 KiB-aligned pages) ──────────
    // L1 entries 0 and 1 are identity blocks; L1[3] points through L2[0] to
    // the L3 user mappings. BSS zeroing leaves every other entry invalid.
    ".section .bss.pagetable",
    ".align 12",
    "__ttbr0_l1:",
    "   .space  4096",
    ".align 12",
    "__ttbr0_user_l2:",
    "   .space  4096",
    ".align 12",
    "__ttbr0_user_l3:",
    "   .space  4096",
);
