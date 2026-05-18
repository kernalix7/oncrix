// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/mv` — POSIX `mv(1)` utility stub.
//!
//! POSIX `mv(1)` moves or renames files. ONCRIX currently does not
//! implement the `SYS_RENAME` syscall; cross-directory atomic rename
//! requires VFS support not yet present. This stub reports failure on
//! stderr and exits 1.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/mv.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const MSG: &[u8] = b"mv: SYS_RENAME not implemented on ONCRIX\n";

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
