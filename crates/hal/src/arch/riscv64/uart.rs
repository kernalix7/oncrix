// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RISC-V 64-bit console UART, exposed under the portable `uart` name.
//!
//! Architecture-neutral kernel code writes to the primary console via
//! `oncrix_hal::arch::uart::{COM1, Uart16550}`. On x86_64 that resolves to
//! the 16550 driver; on riscv64 this module provides a thin newtype over
//! the [`Ns16550`] driver under the same names so that shared code compiles
//! unchanged. This is a naming shim over a real 16550-compatible MMIO UART.

use super::ns16550::{NS16550_BASE, Ns16550};
use crate::serial::SerialPort;
use oncrix_lib::Result;

/// Primary console base address (NS16550 MMIO), named `COM1` for parity with
/// the x86_64 UART driver so architecture-neutral kernel code is identical.
pub const COM1: usize = NS16550_BASE;

/// RISC-V console UART.
///
/// A thin newtype over [`Ns16550`] exposed under the `Uart16550` name so that
/// architecture-neutral kernel code (`fd_table`, `fork_dispatch`) that writes
/// to `COM1` compiles unchanged on riscv64. The underlying NS16550 is itself
/// 16550-register-compatible; only the type/const names are shared with x86.
pub struct Uart16550(Ns16550);

impl Uart16550 {
    /// Create a console UART at the given MMIO base (e.g. [`COM1`]).
    ///
    /// Does NOT initialize the hardware; call [`init`](Self::init) first.
    pub const fn new(base: usize) -> Self {
        Self(Ns16550::new(base))
    }

    /// Initialize the underlying NS16550 (115200 baud, 8N1, FIFOs enabled).
    pub fn init(&self) {
        self.0.init();
    }
}

impl SerialPort for Uart16550 {
    fn write_byte(&mut self, byte: u8) -> Result<()> {
        self.0.write_byte(byte)
    }

    fn read_byte(&mut self) -> Result<u8> {
        self.0.read_byte()
    }
}
