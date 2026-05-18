// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/route` — kernel IP routing table display.
//!
//! Prints the kernel routing table. ONCRIX currently has only the loopback
//! network, so this emits a fixed three-line table (title + header + one
//! loopback route) modeled on net-tools `route(8)` output and exits 0.
//!
//! Reference: net-tools `route(8)`.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const OUTPUT: &[u8] = b"Kernel IP routing table\n\
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n\
127.0.0.0       0.0.0.0         255.0.0.0       U     0      0        0 lo\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_all(1, OUTPUT);
    libc::exit(0)
}

/// Write all bytes in `buf` to `fd`, retrying on short writes.
fn write_all(fd: i32, buf: &[u8]) {
    let mut pos = 0;
    while pos < buf.len() {
        // SAFETY: buf slice is valid for buf.len() bytes.
        let n = unsafe { libc::write(fd, buf[pos..].as_ptr(), buf.len() - pos) };
        if n <= 0 {
            break;
        }
        pos += n as usize;
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libc::exit(1)
}
