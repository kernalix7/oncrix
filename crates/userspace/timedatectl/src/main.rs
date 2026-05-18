// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/timedatectl` — systemd `timedatectl(1)` stub.
//!
//! Prints local/universal/RTC time and the active time zone. ONCRIX does
//! not yet have a wall-clock source wired through user space, so this
//! prints a fixed snapshot and exits 0.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const OUTPUT: &[u8] = b"               Local time: Mon 2026-05-18 11:00:00 UTC\n\
           Universal time: Mon 2026-05-18 11:00:00 UTC\n\
                 RTC time: Mon 2026-05-18 11:00:00\n\
                Time zone: UTC\n";

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
