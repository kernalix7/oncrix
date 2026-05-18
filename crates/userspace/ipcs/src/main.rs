// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/ipcs` — POSIX `ipcs` utility.
//!
//! Prints a summary of active IPC facilities: message queues, shared
//! memory segments, and semaphore arrays. ONCRIX has no live System V
//! IPC accounting yet, so each section prints its header row followed
//! by an empty data area.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/ipcs.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const REPORT: &[u8] = b"\
------ Message Queues --------\n\
key        msqid      owner      perms      used-bytes   messages    \n\
\n\
------ Shared Memory Segments --------\n\
key        shmid      owner      perms      bytes      nattch     status      \n\
\n\
------ Semaphore Arrays --------\n\
key        semid      owner      perms      nsems     \n\
\n";

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
