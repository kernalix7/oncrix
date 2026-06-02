// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/readlink` — POSIX `readlink(1)` utility.
//!
//! Prints the target of the symbolic link named by its operand, via the
//! `readlink(2)` syscall (`SYS_READLINK`, number 89). A trailing newline
//! is appended (matching GNU coreutils default, not `-n`).
//!
//! Usage: `readlink FILE`. Exits 1 if the operand is missing or is not a
//! symbolic link.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/readlink.html`

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
        main = sym readlink_main,
    );
}

extern "C" fn readlink_main(argc: usize, argv: *const *const u8) -> ! {
    if argc < 2 {
        write_all(2, b"readlink: missing operand\n");
        libc::exit(1)
    }

    // SAFETY: argc >= 2, so argv[1] is a valid pointer slot.
    let path = unsafe { argv.add(1).read() };
    if path.is_null() {
        write_all(2, b"readlink: missing operand\n");
        libc::exit(1)
    }

    let mut buf = [0u8; 256];
    // SAFETY: path is NUL-terminated; buf is writable for its full length.
    let rc = unsafe { libc::readlink(path, buf.as_mut_ptr(), buf.len()) };
    if rc < 0 {
        // Not a symlink, or does not exist.
        libc::exit(1)
    }
    let n = rc as usize;
    write_all(1, &buf[..n.min(buf.len())]);
    write_all(1, b"\n");
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
