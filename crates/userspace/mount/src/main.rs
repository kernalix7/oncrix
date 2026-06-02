// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/mount` — POSIX `mount` utility (listing mode).
//!
//! With no arguments, prints the current mount table in the conventional
//! `device on mountpoint type fstype (options)` format. ONCRIX currently
//! mounts a small set of ramfs trees during early init, which this stub
//! reports verbatim.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/mount.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_all(
        1,
        b"ramfs on / type ramfs (rw)\n\
          ramfs on /dev type ramfs (rw)\n\
          ramfs on /proc type ramfs (rw)\n\
          ramfs on /tmp type ramfs (rw)\n\
          ramfs on /sbin type ramfs (rw)\n\
          ramfs on /etc type ramfs (rw)\n",
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
