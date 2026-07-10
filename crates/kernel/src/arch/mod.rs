// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Architecture-specific kernel modules.
//!
//! Each supported target provides a set of submodules (`clone`, `context`,
//! `init`, `init_embed`, `sched_glue`, `syscall_entry`) with a common public
//! API. The per-arch `pub use` re-exports below expose them under the
//! arch-neutral `crate::arch::<submod>` path so that generic kernel code does
//! not name a specific architecture. On aarch64 (and riscv64, once its
//! kernel submodules are written) these are build stubs.

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "riscv64")]
pub mod riscv64;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::{clone, context, init, init_embed, sched_glue, syscall_entry};

#[cfg(target_arch = "riscv64")]
pub use riscv64::{clone, context, init, init_embed, sched_glue, syscall_entry};

#[cfg(target_arch = "x86_64")]
pub use x86_64::{clone, context, init, init_embed, sched_glue, syscall_entry};
