// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/ldconfig` — configure dynamic linker run-time bindings.
//!
//! ONCRIX has no dynamic libraries, so the shared-object cache is degenerate.
//! This stub prints a regeneration acknowledgement and exits 0 so init
//! scripts that unconditionally call `ldconfig` succeed cleanly.
//!
//! Reference: glibc `ldconfig(8)` (not POSIX).

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_all(
        1,
        b"/etc/ld.so.cache: regenerated (no dynamic libraries on ONCRIX)\n",
    );
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
