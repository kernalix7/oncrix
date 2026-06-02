// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/at` — POSIX `at` utility stub.
//!
//! POSIX `at(1)` queues commands for later execution by the `atd` daemon.
//! ONCRIX currently has no `atd` daemon, so jobs cannot be queued, listed,
//! or removed. This stub reports the missing daemon on stderr and exits
//! 1, matching the conventional non-zero exit when `at` cannot operate.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/at.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const MSG: &[u8] = b"at: no atd daemon on ONCRIX\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_all(2, MSG);
    libc::exit(1)
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
