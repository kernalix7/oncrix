// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/lspci` — pciutils-style `lspci` stub.
//!
//! Lists PCI devices in the conventional `bus:dev.fn class: vendor device`
//! one-line format. ONCRIX has no real PCI enumeration yet, so this prints
//! a single placeholder host bridge entry and exits 0.
//!
//! Reference: pciutils `lspci(8)` (not part of POSIX).

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_all(1, b"00:00.0 Host bridge: ONCRIX Virtual Host Bridge\n");
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
