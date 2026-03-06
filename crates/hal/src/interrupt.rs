// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Interrupt controller abstraction.

use oncrix_lib::Result;

/// Interrupt vector number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InterruptVector(pub u8);

/// Hardware-independent interrupt controller interface.
///
/// Implementations provide architecture-specific interrupt management
/// (e.g., x86_64 APIC, aarch64 GIC, riscv64 PLIC).
pub trait InterruptController {
    /// Enable a specific interrupt vector.
    fn enable(&mut self, vector: InterruptVector) -> Result<()>;

    /// Disable a specific interrupt vector.
    fn disable(&mut self, vector: InterruptVector) -> Result<()>;

    /// Acknowledge (end-of-interrupt) for the given vector.
    fn acknowledge(&mut self, vector: InterruptVector) -> Result<()>;

    /// Check whether a specific interrupt vector is enabled.
    fn is_enabled(&self, vector: InterruptVector) -> bool;

    /// Globally enable interrupts on the current CPU.
    ///
    /// # Safety
    ///
    /// Caller must ensure that interrupt handlers are properly installed
    /// before enabling interrupts.
    unsafe fn enable_all(&mut self);

    /// Globally disable interrupts on the current CPU and return
    /// whether interrupts were previously enabled.
    fn disable_all(&mut self) -> bool;
}
