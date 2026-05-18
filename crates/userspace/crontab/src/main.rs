// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/crontab` — POSIX `crontab` utility stub.
//!
//! POSIX `crontab(1)` manages per-user cron tables submitted to a cron
//! daemon. ONCRIX currently has no cron daemon, so there is no table to
//! install, list, edit, or remove. This stub reports the missing daemon
//! on stderr and exits 1, matching the conventional non-zero exit when
//! `crontab` cannot operate.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/crontab.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const MSG: &[u8] = b"crontab: no cron daemon on ONCRIX\n";

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
