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
    // ── Restore hartid and FDT, jump to Rust kernel_main ─────────────────
    "   mv      a0, s0",
    "   mv      a1, s1",
    "   call    kernel_main",
    "   j       .", // should never return
    // ── Minimal trap vector stub ──────────────────────────────────────────
    // Keeps the CPU from faulting before Rust installs proper handlers.
    ".balign 4",
    ".global riscv_trap_vector",
    "riscv_trap_vector:",
    "   j       riscv_trap_vector", // spin until Rust handler is set
    // ── Boot stack (64 KiB in BSS) ───────────────────────────────────────
    ".section .bss.stack",
    ".balign 16",
    "boot_stack:",
    "   .zero   65536",
    ".global __stack_top",
    "__stack_top:",
);
