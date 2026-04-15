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
    // SAFETY: Port I/O is architecturally safe on x86_64 when the port
    // is valid for the current privilege level. This is guaranteed by
    // the caller as documented in the function safety contract.
    // `nomem` is intentionally omitted: port I/O has hardware side effects
    // (device register writes) that the compiler must not reorder relative
    // to surrounding memory accesses.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nostack, preserves_flags),
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
    // SAFETY: Port I/O is architecturally safe on x86_64 when the port
    // is valid for the current privilege level. This is guaranteed by
    // the caller as documented in the function safety contract.
    // `nomem` is intentionally omitted: port I/O has hardware side effects
    // (device register reads) that the compiler must not reorder relative
    // to surrounding memory accesses.
    unsafe {
        core::arch::asm!(
            "in al, dx",
            out("al") value,
            in("dx") port,
            options(nostack, preserves_flags),
        );
    }
    value
}
