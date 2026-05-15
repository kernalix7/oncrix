// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/users` — POSIX `users` utility.
//!
//! Prints the login names of users currently on the system, separated by
//! spaces and terminated by a newline. ONCRIX currently runs as the single
//! `root` identity, so this prints `root\n` and exits 0.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/users.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_all(1, b"root\n");
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
