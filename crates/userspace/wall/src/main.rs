// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/wall` — POSIX `wall(1)` utility stub.
//!
//! POSIX `wall(1)` writes a message to all logged-in users' terminals.
//! ONCRIX currently has a single fixed `root` user and no terminal
//! multiplexing, so there are no other terminals to broadcast to. The
//! stub reports the condition on stderr and exits 0 — POSIX accepts a
//! zero exit even when there are no destinations.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/wall.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const MSG: &[u8] = b"wall: no other terminals to write to\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_all(2, MSG);
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
