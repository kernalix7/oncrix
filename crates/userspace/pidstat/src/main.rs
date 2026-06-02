// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/pidstat` — report per-task statistics.
//!
//! Prints the classic sysstat `pidstat(1)` header. ONCRIX does not yet
//! enumerate task counters, so no per-task rows follow the header.
//!
//! Reference: sysstat `pidstat(1)` (not POSIX). The column layout mirrors the
//! upstream `pidstat` output so existing parsers continue to work.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const OUTPUT: &[u8] = b"Linux ONCRIX (oncrix)   05/18/2026   _x86_64_       (1 CPU)\n\n11:00:00      UID       PID    %usr %system  %guest   %wait    %CPU   CPU  Command\n";

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
