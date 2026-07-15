// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RISC-V 64-bit primary hart entry point and early boot setup.
//!
//! OpenSBI (the M-mode firmware shipped with QEMU) transfers control to
//! S-mode at `_start` with:
//!   a0 = hartid (CPU number)
//!   a1 = FDT pointer (physical address of the device tree blob)
//!
//! Boot sequence:
//!   1. If hartid != 0, park secondary harts in a WFI loop.
//!   2. Zero the BSS section.
//!   3. Set the stack pointer to `__stack_top`.
//!   4. Install the trap vector via `stvec` (direct mode, 4-byte aligned).
//!   5. Enable Sv48 paging (satp = MODE_SV48 | PPN of root page table).
//!      For the early boot stub we skip identity paging and run with
//!      the MMU off (satp = 0) — the kernel runs at its physical load
//!      address 0x8020_0000 which QEMU maps 1:1.
//!   6. Call `kernel_main` with hartid (a0) and fdt_ptr (a1).
//!
//! # Assumptions
//!
//! - QEMU `-bios default` loads OpenSBI which places us in S-mode.
//! - QEMU `-kernel` ELF loads the image at 0x80200000 (after OpenSBI).
//! - The linker script defines `__bss_start`, `__bss_end`, `__stack_top`.

#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(
    ".section .text.boot",
    ".global _start",
    "_start:",
    // ── Hart 0 check (park secondaries) ──────────────────────────────────
    "   beqz    a0, .Lprimary_hart",
    ".Lsecondary_park:",
    "   wfi",
    "   j       .Lsecondary_park",
    ".Lprimary_hart:",
    // Save hartid and FDT pointer across BSS zero (a0/a1 are caller-saved).
    "   mv      s0, a0", // s0 = hartid
    "   mv      s1, a1", // s1 = fdt_ptr
    // ── Zero BSS ─────────────────────────────────────────────────────────
    "   la      t0, __bss_start",
    "   la      t1, __bss_end",
    ".Lbss_loop:",
    "   bgeu    t0, t1, .Lbss_done",
    "   sd      zero, 0(t0)",
    "   addi    t0, t0, 8",
    "   j       .Lbss_loop",
    ".Lbss_done:",
    // ── Set stack pointer ─────────────────────────────────────────────────
    "   la      sp, __stack_top",
    // ── Install trap vector (direct mode, 4-byte aligned) ────────────────
    // stvec[1:0] = 00 → Direct mode (all traps to BASE address).
    "   la      t0, riscv_trap_vector",
    "   csrw    stvec, t0",
    // ── Enable Sv39 paging with a minimal identity map ───────────────────
    // Sv39: 3-level, the root (L2) table has 512 entries, each mapping a
    // 1 GiB gigapage. Two identity entries cover everything QEMU virt needs:
    //   L2[0] → 0x0000_0000..0x4000_0000 — device MMIO (CLINT 0x0200_0000,
    //           PLIC 0x0C00_0000, NS16550 0x1000_0000).
    //   L2[2] → 0x8000_0000..0xC000_0000 — RAM (OpenSBI 0x8000_0000, kernel
    //           0x8020_0000).
    // Leaf PTE = (PPN << 10) | flags; flags V|R|W|X|A|D = 0xCF. A gigapage's
    // PPN is (phys >> 12) with PPN[1:0] zero (1 GiB aligned).
    "   la      t0, __riscv_root_pt",
    // L2[0]: phys 0x0 → PTE = 0x0 | 0xCF
    "   li      t1, 0xCF",
    "   sd      t1, 0(t0)",
    // L2[2]: phys 0x8000_0000 → PPN=0x80000, PTE=(0x80000<<10)|0xCF=0x200000CF
    "   li      t1, 0x200000CF",
    "   sd      t1, 16(t0)", // entry 2 = byte offset 16
    // satp = MODE_SV39 (8 << 60) | PPN(root >> 12)
    "   srli    t2, t0, 12", // root PPN
    "   li      t1, 8",
    "   slli    t1, t1, 60", // MODE = Sv39
    "   or      t1, t1, t2",
    "   sfence.vma",
    "   csrw    satp, t1",
    "   sfence.vma",
    // ── Restore hartid and FDT, jump to Rust kernel_main ─────────────────
    "   mv      a0, s0",
    "   mv      a1, s1",
    "   call    kernel_main",
    "   j       .", // should never return
    // ── S-mode trap vector (direct mode) ─────────────────────────────────
    // On any trap the CPU jumps here with interrupts disabled (SIE→SPIE),
    // sepc = trapped PC, scause/stval set, still on the kernel stack. Save
    // the caller-saved GPRs + sepc + sstatus into a 144-byte frame (18×8,
    // 16-byte aligned), call the Rust handler, restore, and `sret`. sepc and
    // sstatus MUST be stacked because a preemptive switch inside the handler
    // could otherwise clobber them before this thread is re-elected.
    // Callee-saved regs (s0-s11), sp, gp, tp are preserved by the C handler.
    ".balign 4",
    ".global riscv_trap_vector",
    "riscv_trap_vector:",
    "   addi    sp, sp, -144",
    "   sd      ra, 0(sp)",
    "   sd      t0, 8(sp)",
    "   sd      t1, 16(sp)",
    "   sd      t2, 24(sp)",
    "   sd      a0, 32(sp)",
    "   sd      a1, 40(sp)",
    "   sd      a2, 48(sp)",
    "   sd      a3, 56(sp)",
    "   sd      a4, 64(sp)",
    "   sd      a5, 72(sp)",
    "   sd      a6, 80(sp)",
    "   sd      a7, 88(sp)",
    "   sd      t3, 96(sp)",
    "   sd      t4, 104(sp)",
    "   sd      t5, 112(sp)",
    "   sd      t6, 120(sp)",
    "   csrr    t0, sepc",
    "   sd      t0, 128(sp)",
    "   csrr    t0, sstatus",
    "   sd      t0, 136(sp)",
    "   call    riscv_handle_trap",
    "   ld      t0, 136(sp)",
    "   csrw    sstatus, t0",
    "   ld      t0, 128(sp)",
    "   csrw    sepc, t0",
    "   ld      ra, 0(sp)",
    "   ld      t0, 8(sp)",
    "   ld      t1, 16(sp)",
    "   ld      t2, 24(sp)",
    "   ld      a0, 32(sp)",
    "   ld      a1, 40(sp)",
    "   ld      a2, 48(sp)",
    "   ld      a3, 56(sp)",
    "   ld      a4, 64(sp)",
    "   ld      a5, 72(sp)",
    "   ld      a6, 80(sp)",
    "   ld      a7, 88(sp)",
    "   ld      t3, 96(sp)",
    "   ld      t4, 104(sp)",
    "   ld      t5, 112(sp)",
    "   ld      t6, 120(sp)",
    "   addi    sp, sp, 144",
    "   sret",
    // ── Boot stack (64 KiB in BSS) ───────────────────────────────────────
    ".section .bss.stack",
    ".balign 16",
    "boot_stack:",
    "   .zero   65536",
    ".global __stack_top",
    "__stack_top:",
    // ── Sv39 root (L2) page table (4 KiB, 4 KiB-aligned) ─────────────────
    // 512 × 8-byte PTEs; only entries 0 (MMIO) and 2 (RAM) are populated by
    // _start, the rest stay zero (invalid). BSS-resident so the boot
    // BSS-clear zeroes it before use.
    ".section .bss.pagetable",
    ".balign 4096",
    "__riscv_root_pt:",
    "   .zero   4096",
);
