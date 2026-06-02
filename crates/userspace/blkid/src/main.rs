// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/blkid` — util-linux `blkid(8)` stub.
//!
//! Prints block-device attributes (UUID, TYPE) for known devices. ONCRIX
//! currently exposes a single in-memory ramfs-backed device `/dev/ram0`, so
//! this prints a fixed line describing it and exits 0.
//!
//! Reference: util-linux `blkid(8)` (not POSIX).

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_all(
        1,
        b"/dev/ram0: UUID=\"00000000-0000-0000-0000-000000000001\" TYPE=\"ramfs\"\n",
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
