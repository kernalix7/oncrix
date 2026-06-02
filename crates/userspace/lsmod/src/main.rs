// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/lsmod` — util-linux `lsmod(1)` clone.
//!
//! Lists currently loaded kernel modules. ONCRIX is a microkernel and does
//! not support loadable kernel modules, so this prints only the canonical
//! header line and exits 0. An empty module list is the correct answer.
//!
//! Reference: `lsmod(1)` from util-linux. The utility is not part of
//! POSIX.1-2024.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

/// Canonical `lsmod` header line as printed by util-linux.
const HEADER: &[u8] = b"Module                  Size  Used by\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_all(1, HEADER);
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
