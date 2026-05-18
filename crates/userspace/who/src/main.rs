// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/who` — POSIX `who` utility.
//!
//! Prints currently logged-in users. Real `who(1)` reads `/var/run/utmp`;
//! ONCRIX has no utmp/wtmp database, so we emit a single static line
//! representing the kernel session and exit 0.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/who.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_all(1, b"root     tty1         2026-05-18 11:00\n");
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
