// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/lscpu` — util-linux `lscpu` utility.
//!
//! Prints a fixed summary of the CPU architecture as seen by ONCRIX.
//! Not standardised by POSIX; modelled on util-linux `lscpu(1)`.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const OUTPUT: &[u8] = b"Architecture:                    x86_64\n\
                        CPU op-mode(s):                  64-bit\n\
                        Byte Order:                      Little Endian\n\
                        CPU(s):                          1\n\
                        Vendor ID:                       ONCRIX\n\
                        Model name:                      ONCRIX virtual CPU\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    write_all(1, OUTPUT);
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
