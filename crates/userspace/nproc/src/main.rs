// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/nproc` — print the number of processing units available.
//!
//! POSIX does not standardize `nproc`, but util-linux ships it as the
//! canonical way to query the count of online CPUs. ONCRIX currently
//! runs on a single CPU, so this prints `1\n` and exits 0.
//!
//! Reference: util-linux `nproc(1)`. POSIX equivalents are accessed via
//! `sysconf(_SC_NPROCESSORS_ONLN)` (see
//! `.priv-storage/.TheOpenGroup/susv5-html/functions/sysconf.html`).

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_all(1, b"1\n");
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
