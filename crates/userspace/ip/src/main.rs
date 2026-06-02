// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/ip` — iproute2-style network configuration display.
//!
//! Dispatches on the first positional argument (the iproute2 OBJECT):
//!
//! * `link`            — prints the loopback link summary line.
//! * `addr` / `address` — prints the loopback address line.
//! * `route`           — prints the loopback route line.
//!
//! With no arguments, prints the iproute2 usage banner to stderr and
//! exits 1. Any unrecognised OBJECT prints an error to stderr and exits 1.
//!
//! Reference: iproute2 `ip(8)`.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Entry point — naked, captures argc / argv from the SysV AMD64 initial stack.
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym ip_main,
    );
}

// ---------------------------------------------------------------------------
// ip logic
// ---------------------------------------------------------------------------

const USAGE: &[u8] = b"Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n";
const LINK_LINE: &[u8] = b"1: lo: <LOOPBACK,UP> mtu 65536\n";
const ADDR_LINE: &[u8] = b"1: lo: inet 127.0.0.1/8 scope host\n";
const ROUTE_LINE: &[u8] = b"127.0.0.0/8 dev lo scope link\n";
const UNKNOWN: &[u8] = b"ip: unknown subcommand\n";

extern "C" fn ip_main(argc: usize, argv: *const *const u8) -> ! {
    if argc < 2 {
        write_all(2, USAGE);
        libc::exit(1)
    }

    // SAFETY: argc >= 2 so argv[1] is a valid pointer slot laid out by
    // sys_execve.
    let arg1 = unsafe { argv.add(1).read() };
    if arg1.is_null() {
        write_all(2, USAGE);
        libc::exit(1)
    }

    if c_str_eq(arg1, b"link") {
        write_all(1, LINK_LINE);
        libc::exit(0)
    }
    if c_str_eq(arg1, b"addr") || c_str_eq(arg1, b"address") {
        write_all(1, ADDR_LINE);
        libc::exit(0)
    }
    if c_str_eq(arg1, b"route") {
        write_all(1, ROUTE_LINE);
        libc::exit(0)
    }

    write_all(2, UNKNOWN);
    libc::exit(1)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compare a null-terminated C string with a byte slice for exact equality.
fn c_str_eq(ptr: *const u8, expected: &[u8]) -> bool {
    for (i, &want) in expected.iter().enumerate() {
        // SAFETY: ptr is a null-terminated string from the kernel-constructed
        // argv; we stop at the terminator before walking past it.
        let got = unsafe { ptr.add(i).read() };
        if got == 0 || got != want {
            return false;
        }
    }
    // Require the terminator immediately after the matched prefix.
    // SAFETY: same as above; index `expected.len()` is the next byte.
    unsafe { ptr.add(expected.len()).read() == 0 }
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

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libc::exit(1)
}
