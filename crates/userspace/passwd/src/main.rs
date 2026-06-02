// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/passwd` — POSIX `passwd` utility stub.
//!
//! POSIX `passwd(1)` changes a user's authentication token. ONCRIX
//! currently has no mutable authentication database — the single
//! hard-coded `root` identity has no password and cannot be modified.
//! This stub therefore reports failure on stderr and exits 1, matching
//! the conventional `passwd` exit semantics for "password not changed".
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/passwd.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const MSG: &[u8] = b"passwd: password not changed (ONCRIX read-only auth)\n";

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
