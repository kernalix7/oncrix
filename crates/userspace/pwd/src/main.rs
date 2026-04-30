// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/pwd` — POSIX.1-2024 `pwd` utility.
//!
//! Prints the pathname of the current working directory followed by a newline.
//! Since `chdir` is not yet wired, the kernel root `/` is always the cwd.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/pwd.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// `_start` must be a *naked* function so the Rust prologue does not
/// allocate a local stack frame before we capture argc/argv from the
/// System V AMD64 initial stack layout.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym pwd_main,
    );
}

// ---------------------------------------------------------------------------
// pwd logic (POSIX.1-2024)
// ---------------------------------------------------------------------------

extern "C" fn pwd_main(_argc: usize, _argv: *const *const u8) -> ! {
    // chdir is not yet implemented; root is always the cwd.
    write_all(1, b"/\n");
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
    write_all(2, b"pwd: panic\n");
    libc::exit(1)
}
