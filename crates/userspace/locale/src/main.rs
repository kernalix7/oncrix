// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/locale` — POSIX `locale` utility.
//!
//! With no arguments, prints the current locale environment. ONCRIX
//! ships only the POSIX (`C`) locale, so all categories report `"C"`
//! and `LC_ALL` is empty (unset), matching the canonical POSIX default
//! output.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/locale.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const REPORT: &[u8] = b"\
LANG=C\n\
LC_CTYPE=\"C\"\n\
LC_NUMERIC=\"C\"\n\
LC_TIME=\"C\"\n\
LC_COLLATE=\"C\"\n\
LC_MONETARY=\"C\"\n\
LC_MESSAGES=\"C\"\n\
LC_PAPER=\"C\"\n\
LC_NAME=\"C\"\n\
LC_ADDRESS=\"C\"\n\
LC_ALL=\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_all(1, REPORT);
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
