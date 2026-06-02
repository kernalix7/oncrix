// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/vmstat` — report virtual memory statistics.
//!
//! Prints the classic two-line procps header followed by a single sample
//! row. ONCRIX does not yet expose live counters, so the row reports a
//! fixed snapshot (1 runnable proc, 98304 KiB free, otherwise zero).
//!
//! Reference: procps `vmstat(8)` (not POSIX). The column layout mirrors the
//! upstream `vmstat 1 1` output so existing parsers continue to work.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const OUTPUT: &[u8] = b"procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----\n r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st\n 1  0      0  98304      0      0    0    0     0     0    0    0  0  1 99  0  0\n";

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
