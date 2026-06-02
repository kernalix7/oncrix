// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/lsusb` — usbutils-style `lsusb` stub.
//!
//! Lists USB devices in the conventional `Bus NNN Device NNN: ID vvvv:pppp ...`
//! format. ONCRIX has no real USB enumeration yet, so this prints a single
//! placeholder hub entry and exits 0.
//!
//! Reference: usbutils `lsusb(8)` (not part of POSIX).

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_all(1, b"Bus 001 Device 001: ID 0000:0000 ONCRIX Virtual Hub\n");
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
