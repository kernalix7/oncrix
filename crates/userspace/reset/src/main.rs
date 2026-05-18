// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/reset` — ncurses-style `reset(1)`.
//!
//! Re-initializes the terminal to a sane state: full reset (RIS),
//! cursor home, erase screen. ONCRIX's console is a fixed VT100/xterm
//! emulator, so this expands to a hard-coded escape sequence with no
//! termcap / terminfo lookup.
//!
//! Reference: ncurses `reset(1)` — not part of POSIX.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

/// Reset terminal (RIS) + cursor home + erase screen.
const RESET_SEQ: &[u8] = b"\x1bc\x1b[H\x1b[2J";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_all(1, RESET_SEQ);
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
