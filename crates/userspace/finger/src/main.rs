// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/finger` — display user information.
//!
//! `finger(1)` is a BSD utility (not POSIX) that reports information about
//! local users: login name, real name, home directory, login shell, last
//! login time, and any unread mail. The canonical multi-line layout used by
//! BSD `finger -m <user>` is:
//!
//! ```text
//! Login: root          Name: root
//! Directory: /root     Shell: /bin/sh
//! Last login: never
//! No mail.
//! ```
//!
//! ONCRIX has a fixed `root` user, no login records, and no mail spool, so
//! the four lines above are hard-coded. The utility ignores its operands.
//!
//! Exit status:
//!   * 0 — always.
//!
//! Reference: BSD `finger(1)`.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Entry point — no argv needed; the four lines are static.
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_all(
        1,
        b"Login: root          Name: root\n\
          Directory: /root     Shell: /bin/sh\n\
          Last login: never\n\
          No mail.\n",
    );
    libc::exit(0)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libc::exit(1)
}
