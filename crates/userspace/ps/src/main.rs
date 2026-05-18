// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/ps` — POSIX `ps(1)` utility.
//!
//! Prints a process status table: header row plus one row per known
//! process. ONCRIX currently has a fixed early-boot process table, so
//! this implementation prints the two known processes (`init` at PID 1
//! and `sh` at PID 2) with a controlling terminal of `?` and zero
//! accumulated CPU time.
//!
//! Reference: POSIX.1-2024 `ps(1)`.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // Header row: 5-char right-justified "PID", 8-char "TTY", 8-char "TIME", "CMD".
    write_all(1, b"  PID TTY          TIME CMD\n");
    // PID 1 → init.
    write_all(1, b"    1 ?        00:00:00 init\n");
    // PID 2 → sh.
    write_all(1, b"    2 ?        00:00:00 sh\n");
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
