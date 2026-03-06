// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Serial port abstraction for early console output.

use oncrix_lib::Result;

/// Hardware-independent serial port interface.
///
/// Implementations provide architecture-specific serial I/O
/// (e.g., x86_64 UART 16550, aarch64 PL011).
pub trait SerialPort {
    /// Write a single byte to the serial port.
    fn write_byte(&mut self, byte: u8) -> Result<()>;

    /// Write a string slice to the serial port, byte by byte.
    fn write_str(&mut self, s: &str) -> Result<()> {
        for byte in s.bytes() {
            self.write_byte(byte)?;
        }
        Ok(())
    }

    /// Read a single byte from the serial port.
    ///
    /// Returns `Err(WouldBlock)` if no data is available.
    fn read_byte(&mut self) -> Result<u8>;
}
