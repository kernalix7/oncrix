// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/groupdel` — shadow `groupdel(8)` utility stub.
//!
//! `groupdel(8)` deletes an existing group entry. ONCRIX has no mutable
//! group database — the single hard-coded `root` group is the only group
//! and cannot be removed. This stub therefore reports failure on stderr
//! and exits 1, matching the conventional `groupdel` exit semantics for
//! "cannot delete group".
//!
//! Reference: shadow-utils `groupdel(8)`; ONCRIX has no equivalent POSIX
//! utility specification since group account deletion is not part of
//! POSIX.1-2024.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const MSG: &[u8] = b"groupdel: cannot delete group (ONCRIX has fixed root group)\n";

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
