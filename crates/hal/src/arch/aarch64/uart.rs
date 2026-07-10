// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AArch64 console UART, exposed under the portable `uart` name.
//!
//! Architecture-neutral kernel code writes to the primary console via
//! `oncrix_hal::arch::uart::{COM1, Uart16550}`. On x86_64 that resolves to
//! the 16550 driver; on aarch64 this module provides a thin newtype over
//! the [`Pl011`] driver under the same names so that shared code compiles
//! unchanged. This is a naming shim, not a 16550 emulation.

use super::pl011::{PL011_BASE, Pl011};
use crate::serial::SerialPort;
use oncrix_lib::Result;

/// Primary console base address (PL011 MMIO), named `COM1` for parity with
/// the x86_64 UART driver so architecture-neutral kernel code is identical.
pub const COM1: usize = PL011_BASE;

/// AArch64 console UART.
///
/// A thin newtype over [`Pl011`] exposed under the `Uart16550` name so that
/// architecture-neutral kernel code (`fd_table`, `fork_dispatch`) that
/// writes to `COM1` compiles unchanged on aarch64. The register-level
/// behaviour is entirely PL011; only the type/const names are shared.
pub struct Uart16550(Pl011);

impl Uart16550 {
    /// Create a console UART at the given MMIO base (e.g. [`COM1`]).
    ///
    /// Does NOT initialize the hardware; call [`init`](Self::init) first.
    pub const fn new(base: usize) -> Self {
        Self(Pl011::new(base))
    }

    /// Initialize the underlying PL011 (115200 baud, 8N1, FIFOs enabled).
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
