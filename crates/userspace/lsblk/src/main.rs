// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/lsblk` — util-linux `lsblk(8)` stub.
//!
//! Lists block devices in a tree. ONCRIX currently exposes only the
//! ramfs-backed `ram0` device mounted at `/`, so this prints the standard
//! header plus a single row describing that device.
//!
//! Reference: util-linux `lsblk(8)` (not POSIX).

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_all(
        1,
        b"NAME    MAJ:MIN RM   SIZE RO TYPE MOUNTPOINTS\nram0      1:0    0    16M  0 disk /\n",
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
