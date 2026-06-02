// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/ifconfig` — network interface configuration display.
//!
//! Prints the configuration of the loopback network interface. ONCRIX
//! currently exposes only the `lo` interface; this utility emits a fixed
//! four-line summary modeled on net-tools `ifconfig(8)` output and exits 0.
//!
//! Reference: net-tools `ifconfig(8)`.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const OUTPUT: &[u8] = b"lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n\
        inet 127.0.0.1  netmask 255.0.0.0\n\
        loop  txqueuelen 1000  (Local Loopback)\n\
        RX packets 0  bytes 0\n";

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
