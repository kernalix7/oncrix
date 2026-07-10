// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RISC-V 64-bit embedded-userspace lookup and `rt_sigreturn` trampoline
//! constants.
//!
//! riscv64 build stub — not yet functional.
//!
//! Mirrors the public constants and accessors of
//! [`crate::arch::x86_64::init_embed`] so architecture-neutral fork/exec and
//! signal dispatch type-check on riscv64. No userspace images are embedded
//! for riscv64 yet, so the lookup functions always return `None`.

/// User VA at which the per-process `rt_sigreturn` trampoline is mapped.
///
/// Same layout as the x86_64 port: one page below the initial user stack,
/// inside the per-process 2 MiB region (0x400000..0x600000).
pub const SIGRETURN_TRAMPOLINE_VA: u64 = 0x0000_0000_005F_E000;

/// Offset of [`SIGRETURN_TRAMPOLINE_VA`] inside the 2 MiB user backing region.
pub const SIGRETURN_TRAMPOLINE_OFFSET: usize = 0x1FE000;

/// Bytes of the in-process `rt_sigreturn` trampoline.
///
/// riscv64 build stub — not yet functional. Filled with `ebreak`
/// (`0x00100073`, little-endian) so any accidental execution traps
/// deterministically instead of running stale x86 opcodes. The real
/// `ecall`-based riscv64 trampoline will replace this when U-mode signal
/// delivery is implemented.
pub const SIGRETURN_TRAMPOLINE_BYTES: [u8; 12] = [
    0x73, 0x00, 0x10, 0x00, // ebreak
    0x73, 0x00, 0x10, 0x00, // ebreak
    0x73, 0x00, 0x10, 0x00, // ebreak
];

/// Return the embedded `init` ELF bytes.
///
/// riscv64 build stub — not yet functional; always `None`.
pub fn embedded_init_elf() -> Option<&'static [u8]> {
    None
}

/// Look up an embedded executable by path.
///
/// riscv64 build stub — not yet functional; always `None`.
pub fn embedded_lookup(_path: &[u8]) -> Option<&'static [u8]> {
    None
}
