// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/hostnamectl` — systemd `hostnamectl(1)` stub.
//!
//! Prints static system identity information (hostname, icon, machine/boot
//! IDs, OS name, kernel release). ONCRIX does not yet have configurable
//! identity state, so this prints a fixed set of values and exits 0.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const OUTPUT: &[u8] = b"   Static hostname: oncrix\n\
         Icon name: computer\n\
        Machine ID: 0000000000000001\n\
           Boot ID: 0000000000000001\n\
  Operating System: ONCRIX\n\
            Kernel: ONCRIX 0.1.0\n";

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
