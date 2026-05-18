// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/top` — procps `top(1)` stub (non-interactive).
//!
//! Prints a single snapshot of system load, task counts, CPU breakdown,
//! memory, swap, and a per-process row for each known process, then
//! exits. ONCRIX has no live process / memory accounting yet, so all
//! counters are static placeholders matching the early-boot state
//! (init + sh on 128 MiB of RAM, no swap).
//!
//! Reference: procps `top(1)`.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // Single byte-literal: 5 summary lines, blank, column-header, 2 data rows.
    // `\` line continuations strip source-side whitespace; explicit `\x20`
    // escapes preserve the leading spaces required by the procps layout.
    write_all(
        1,
        b"top - 11:00:00 up  0:01,  1 user,  load average: 0.00, 0.00, 0.00\n\
Tasks:   2 total,   1 running,   1 sleeping,   0 stopped,   0 zombie\n\
%Cpu(s):  0.0 us,  1.0 sy,  0.0 ni, 99.0 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st\n\
MiB Mem :    128.0 total,    100.0 free,     16.0 used,     12.0 buff/cache\n\
MiB Swap:      0.0 total,      0.0 free,      0.0 used.    100.0 avail Mem\n\
\n\
\x20\x20PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n\
\x20\x20\x20\x20\x201 root      20   0   16384   4096   1024 S   0.0   3.1   0:00.00 init\n\
\x20\x20\x20\x20\x202 root      20   0   16384   4096   1024 S   0.0   3.1   0:00.00 sh\n",
    );
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
