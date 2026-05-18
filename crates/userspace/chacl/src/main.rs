// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/chacl` — POSIX `chacl(1)` utility stub.
//!
//! `chacl(1)` (a POSIX.1e ACL extension utility) changes a file's access
//! control list. ONCRIX's current root filesystem is `ramfs`, which has no
//! on-disk inode storage for extended attributes and therefore cannot
//! represent POSIX ACLs. This stub reports the limitation on stderr and
//! exits 1.
//!
//! POSIX reference: POSIX.1e ACL extension (`chacl(1)`).

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const MSG: &[u8] = b"chacl: ramfs does not support ACLs\n";

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
