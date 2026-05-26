// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/truncate` — POSIX `truncate(1)` utility.
//!
//! Sets a file's length via the `truncate(2)` syscall (`SYS_TRUNCATE`,
//! number 76). Shrinking discards the tail; growing zero-fills.
//!
//! Usage: `truncate -s SIZE FILE`. SIZE is a decimal byte count.
//! Symbolic SIZE suffixes (K/M) and relative (+/-) forms are not yet
//! supported.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/truncate.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym truncate_main,
    );
}

const USAGE: &[u8] = b"truncate: usage: truncate -s SIZE FILE\n";

extern "C" fn truncate_main(argc: usize, argv: *const *const u8) -> ! {
    // Expect: argv[0]=truncate, argv[1]="-s", argv[2]=SIZE, argv[3]=FILE.
    if argc < 4 {
        write_all(2, USAGE);
        libc::exit(1)
    }

    // SAFETY: argc >= 4, so argv[1..=3] are valid pointer slots.
    let flag = unsafe { argv.add(1).read() };
    let size_s = unsafe { argv.add(2).read() };
    let file = unsafe { argv.add(3).read() };
    if flag.is_null() || size_s.is_null() || file.is_null() {
        write_all(2, USAGE);
        libc::exit(1)
    }

    // Only the `-s SIZE` form is supported.
    if first_two(flag) != [b'-', b's'] {
        write_all(2, USAGE);
        libc::exit(1)
    }

    let size = match parse_u64(size_s) {
        Some(s) => s,
        None => {
            write_all(2, b"truncate: invalid size\n");
            libc::exit(1)
        }
    };

    // SAFETY: file is a NUL-terminated argv string.
    let rc = unsafe { libc::truncate(file, size) };
    if rc < 0 {
        write_all(2, b"truncate: cannot truncate file\n");
        libc::exit(1)
    }
    libc::exit(0)
}

/// First two bytes of a NUL-terminated string (0-padded).
fn first_two(ptr: *const u8) -> [u8; 2] {
    // SAFETY: ptr is a NUL-terminated argv string; index 1 read only
    // after index 0 confirmed non-NUL.
    let b0 = unsafe { ptr.read() };
    if b0 == 0 {
        return [0, 0];
    }
    let b1 = unsafe { ptr.add(1).read() };
    [b0, b1]
}

/// Parse a NUL-terminated decimal string into a `u64`.
fn parse_u64(ptr: *const u8) -> Option<u64> {
    let mut val: u64 = 0;
    let mut i = 0usize;
    loop {
        // SAFETY: ptr is a NUL-terminated argv string.
        let c = unsafe { ptr.add(i).read() };
        if c == 0 {
            break;
        }
        if !c.is_ascii_digit() {
            return None;
        }
        val = val.checked_mul(10)?.checked_add((c - b'0') as u64)?;
        i += 1;
    }
    if i == 0 { None } else { Some(val) }
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
