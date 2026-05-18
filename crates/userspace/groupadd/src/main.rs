// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/groupadd` — shadow `groupadd(8)` utility stub.
//!
//! `groupadd(8)` creates a new group entry. ONCRIX has no mutable group
//! database — the single hard-coded `root` group is the only group and
//! cannot be augmented. This stub therefore reports failure on stderr
//! and exits 1, matching the conventional `groupadd` exit semantics for
//! "cannot add group".
//!
//! Reference: shadow-utils `groupadd(8)`; ONCRIX has no equivalent POSIX
//! utility specification since group account creation is not part of
//! POSIX.1-2024.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const MSG: &[u8] = b"groupadd: cannot add group (ONCRIX has fixed root group)\n";

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
