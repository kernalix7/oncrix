// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/tabs` — POSIX `tabs(1)`.
//!
//! Sets hardware tab stops. ONCRIX's VT100/xterm console only supports
//! the default eight-column tab grid, so this utility ignores its
//! arguments and emits a fixed sequence that:
//!
//! 1. Clears all existing tab stops (`ESC [ 3 g`).
//! 2. Re-installs default tab stops every 8 columns (`ESC [ 8 U`,
//!    xterm "tab every N" extension).
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/tabs.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

/// Clear all tab stops + set tabs every 8 columns.
const TABS_SEQ: &[u8] = b"\x1b[3g\x1b[8U";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_all(1, TABS_SEQ);
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
