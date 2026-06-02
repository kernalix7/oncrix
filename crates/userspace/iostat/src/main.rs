// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/iostat` — report CPU and device I/O statistics.
//!
//! Prints the classic sysstat `iostat(1)` header, an `avg-cpu` block, and a
//! single device row. ONCRIX does not yet expose live counters, so the values
//! are a fixed snapshot (1% system, 99% idle, no I/O activity on `ram0`).
//!
//! Reference: sysstat `iostat(1)` (not POSIX). The column layout mirrors the
//! upstream `iostat` output so existing parsers continue to work.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const OUTPUT: &[u8] = b"Linux ONCRIX (oncrix)   05/18/2026   _x86_64_       (1 CPU)\n\navg-cpu:  %user   %nice %system %iowait  %steal   %idle\n           0.00    0.00    1.00    0.00    0.00   99.00\n\nDevice             tps    kB_read/s    kB_wrtn/s    kB_read    kB_wrtn\nram0              0.00         0.00         0.00          0          0\n";

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
