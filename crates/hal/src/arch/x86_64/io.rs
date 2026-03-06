// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! x86_64 port I/O primitives.

/// Write a byte to an x86 I/O port.
///
/// # Safety
///
/// Caller must ensure `port` is a valid I/O port for the current
/// privilege level.
pub unsafe fn outb(port: u16, value: u8) {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Read a byte from an x86 I/O port.
///
/// # Safety
///
/// Caller must ensure `port` is a valid I/O port for the current
/// privilege level.
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    unsafe {
        core::arch::asm!(
            "in al, dx",
            out("al") value,
            in("dx") port,
            options(nomem, nostack, preserves_flags),
        );
    }
    value
}
