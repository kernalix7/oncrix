// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/usermod` — shadow `usermod(8)` utility stub.
//!
//! `usermod(8)` modifies an existing user account. ONCRIX has no mutable
//! user database — the single hard-coded `root` identity is immutable
//! and cannot be altered. This stub therefore reports failure on stderr
//! and exits 1, matching the conventional `usermod` exit semantics for
//! "cannot modify user".
//!
//! Reference: shadow-utils `usermod(8)`; ONCRIX has no equivalent POSIX
//! utility specification since user account modification is not part of
//! POSIX.1-2024.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const MSG: &[u8] = b"usermod: cannot modify user (ONCRIX has fixed root user)\n";

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
