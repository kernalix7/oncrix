// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/uname` — POSIX.1-2024 `uname` utility.
//!
//! With no arguments: prints `ONCRIX\n`.
//! With `-a` as `argv[1]`: prints `ONCRIX 0.1.0 x86_64\n`.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/uname.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// `_start` must be a *naked* function so the Rust prologue does not
/// shift the initial stack before we read argc/argv.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym uname_main,
    );
}

// ---------------------------------------------------------------------------
// uname logic (POSIX.1-2024)
// ---------------------------------------------------------------------------

extern "C" fn uname_main(argc: usize, argv: *const *const u8) -> ! {
    let all_flag = if argc >= 2 {
        // SAFETY: argv has at least argc valid pointers from the kernel stack.
        let ptr = unsafe { argv.add(1).read() };
        if ptr.is_null() {
            false
        } else {
            // Check for "-a\0"
            // SAFETY: ptr is a null-terminated argv string.
            unsafe { ptr.read() == b'-' && ptr.add(1).read() == b'a' && ptr.add(2).read() == 0 }
        }
    } else {
        false
    };

    if all_flag {
        write_all(1, b"ONCRIX 0.1.0 x86_64\n");
    } else {
        write_all(1, b"ONCRIX\n");
    }

    libc::exit(0)
}

// ---------------------------------------------------------------------------
// I/O helpers
// ---------------------------------------------------------------------------

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
    write_all(2, b"uname: panic\n");
    libc::exit(1)
}
