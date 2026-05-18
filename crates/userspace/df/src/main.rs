// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/df` — POSIX `df` utility.
//!
//! Reports disk-space usage for mounted filesystems. ONCRIX currently mounts
//! a single in-memory `ramfs` at `/`, so this prints a fixed two-line table
//! describing that mount and exits 0.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/df.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const OUTPUT: &[u8] = b"Filesystem     1K-blocks    Used Available Use% Mounted on\n\
                        ramfs              16384       8     16376   1% /\n";

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
