// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/rmdir` — POSIX `rmdir(1)` utility.
//!
//! Removes empty directories via the `rmdir(2)` syscall (`SYS_RMDIR`,
//! number 84). Fails if a directory is non-empty or does not exist.
//! Multiple operands are accepted and processed left to right.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/rmdir.html`

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
        main = sym rmdir_main,
    );
}

extern "C" fn rmdir_main(argc: usize, argv: *const *const u8) -> ! {
    if argc < 2 {
        write_all(2, b"rmdir: missing operand\n");
        libc::exit(1)
    }

    let mut status = 0;
    let mut i = 1usize;
    while i < argc {
        // SAFETY: i < argc, so argv[i] is a valid pointer slot.
        let path = unsafe { argv.add(i).read() };
        if path.is_null() {
            break;
        }
        // SAFETY: path is a NUL-terminated argv string.
        let rc = unsafe { libc::rmdir(path) };
        if rc < 0 {
            write_all(2, b"rmdir: failed to remove directory\n");
            status = 1;
        }
        i += 1;
    }
    libc::exit(status)
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
