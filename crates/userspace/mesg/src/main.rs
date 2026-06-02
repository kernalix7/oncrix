// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/mesg` — control / report terminal write permission.
//!
//! POSIX.1-2024 `mesg` toggles whether other users may send terminal
//! messages (via `write(1)`, `wall(1)`) to the controlling terminal of
//! the calling process. With no operand it reports the current state
//! as `is y` (allowed) or `is n` (denied), exit 0; the operands `y` and
//! `n` set the state.
//!
//! ONCRIX does not yet expose per-tty write-permission toggles — the
//! single console is always writable. So this stub unconditionally
//! reports `is y\n` to stdout and exits 0. When the tty subsystem
//! grows real permission flags, this utility will be rewritten to
//! parse operands and update the controlling-tty mode bits.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/mesg.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_all(1, b"is y\n");
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
