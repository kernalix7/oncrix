// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/lsipc` — util-linux `lsipc` utility (non-POSIX).
//!
//! Prints an IPC summary table: header row plus one zero-usage row per
//! resource (message queues, semaphore identifiers, shared memory segments).
//! ONCRIX has no live IPC accounting yet, so limits are static and USED is 0.
//!
//! Reference: util-linux lsipc(1).

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_all(
        1,
        b"RESOURCE       DESCRIPTION                                     LIMIT  USED  USE%\n\
          MSGMNI         Number of message queues                         32000     0   0%\n\
          SEMMNI         Number of semaphore identifiers                  32000     0   0%\n\
          SHMMNI         Number of shared memory segments                  4096     0   0%\n",
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
