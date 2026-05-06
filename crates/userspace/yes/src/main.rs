// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/yes` — POSIX.1-2024 `yes` utility.
//!
//! Repeatedly prints STRING (default `"y"`) followed by `\n` to stdout.
//! The loop continues until a write error (e.g. SIGPIPE from the reader
//! closing its end of a pipe).
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/yes.html`

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
        main = sym yes_main,
    );
}

extern "C" fn yes_main(argc: usize, argv: *const *const u8) -> ! {
    // Use argv[1] as the string if provided, otherwise default to "y".
    let (ptr, len) = if argc >= 2 {
        // SAFETY: argv has at least argc valid pointers (sys_execve guarantee).
        let p = unsafe { argv.add(1).read() };
        if p.is_null() {
            (b"y".as_ptr(), 1usize)
        } else {
            let l = cstr_len(p);
            (p, l)
        }
    } else {
        (b"y".as_ptr(), 1usize)
    };

    loop {
        // SAFETY: ptr is a valid argv string (NUL-terminated, length known).
        let n = unsafe { libc::write(1, ptr, len) };
        if n <= 0 {
            break;
        }
        let n2 = unsafe { libc::write(1, b"\n".as_ptr(), 1) };
        if n2 <= 0 {
            break;
        }
    }
    libc::exit(0)
}

fn cstr_len(p: *const u8) -> usize {
    let mut len = 0usize;
    // SAFETY: p is a NUL-terminated argv string from sys_execve.
    while unsafe { p.add(len).read() } != 0 {
        len += 1;
    }
    len
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { libc::write(2, b"yes: panic\n".as_ptr(), 11) };
    libc::exit(1)
}
