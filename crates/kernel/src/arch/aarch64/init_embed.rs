// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AArch64 embedded-userspace lookup and `rt_sigreturn` trampoline constants.
//!
//! aarch64 build stub — not yet functional.
//!
//! Mirrors the public constants and accessors of
//! [`crate::arch::x86_64::init_embed`] so architecture-neutral fork/exec and
//! signal dispatch type-check on aarch64. No userspace images are embedded
//! for aarch64 yet, so the lookup functions always return `None`.

/// User VA at which the per-process `rt_sigreturn` trampoline is mapped.
///
/// Same layout as the x86_64 port: one page below the initial user stack,
/// inside the per-process 2 MiB region (0x400000..0x600000).
pub const SIGRETURN_TRAMPOLINE_VA: u64 = 0x0000_0000_005F_E000;

/// Offset of [`SIGRETURN_TRAMPOLINE_VA`] inside the 2 MiB user backing region.
pub const SIGRETURN_TRAMPOLINE_OFFSET: usize = 0x1FE000;

/// Bytes of the in-process `rt_sigreturn` trampoline.
///
/// aarch64 build stub — not yet functional. Filled with `brk #0`
/// (`0xD420_0000`, little-endian) so any accidental execution traps
/// deterministically instead of running stale x86 opcodes. The real
/// `svc`-based aarch64 trampoline will replace this when EL0 signal
/// delivery is implemented.
pub const SIGRETURN_TRAMPOLINE_BYTES: [u8; 12] = [
    0x00, 0x00, 0x20, 0xD4, // brk #0
    0x00, 0x00, 0x20, 0xD4, // brk #0
    0x00, 0x00, 0x20, 0xD4, // brk #0
];

/// Return the embedded `init` ELF bytes.
///
/// aarch64 build stub — not yet functional; always `None`.
pub fn embedded_init_elf() -> Option<&'static [u8]> {
    None
}

/// Look up an embedded executable by path.
///
/// aarch64 build stub — not yet functional; always `None`.
pub fn embedded_lookup(_path: &[u8]) -> Option<&'static [u8]> {
    None
}
