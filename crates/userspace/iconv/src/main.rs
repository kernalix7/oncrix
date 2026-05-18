// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/iconv` — POSIX `iconv(1)` cat-like stub.
//!
//! POSIX `iconv(1)` converts text between character encodings. ONCRIX has
//! no charset conversion tables yet, so this stub behaves like `cat`:
//! it copies stdin to stdout in 256-byte chunks without transcoding,
//! ignoring any `-f` / `-t` arguments. Exits 0 on EOF.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/iconv.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const CHUNK: usize = 256;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut buf = [0u8; CHUNK];
    loop {
        // SAFETY: buf is valid writable storage of CHUNK bytes.
        let n = unsafe { libc::read(0, buf.as_mut_ptr(), CHUNK) };
        if n <= 0 {
            // EOF (n == 0) or error (n < 0): stop and exit 0.
            break;
        }
        write_all(1, &buf[..n as usize]);
    }
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
