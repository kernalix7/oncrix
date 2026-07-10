// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Architecture-specific HAL implementations.
//!
//! The per-arch `pub use` re-exports expose the console UART (and, on
//! x86_64, the port-I/O helpers) under the arch-neutral `oncrix_hal::arch`
//! path so that architecture-neutral kernel code can reference
//! `oncrix_hal::arch::uart` without naming a specific architecture. The
//! genuinely x86-only controllers (GDT/IDT/PIC/PIT/APIC) are intentionally
//! not re-exported; generic code that needs them is cfg-gated to x86_64.

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "riscv64")]
pub mod riscv64;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::uart;

#[cfg(target_arch = "riscv64")]
pub use riscv64::uart;

#[cfg(target_arch = "x86_64")]
pub use x86_64::{io, uart};
