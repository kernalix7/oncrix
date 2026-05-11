// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/logname` — POSIX.1-2024 `logname` utility.
//!
//! Prints the user's login name followed by `\n`. ONCRIX has no
//! `/var/run/utmp` and no `getlogin(3)` syscall, so the login name is
//! hard-coded to `root` (uid 0 is the only user).
//!
//! Per POSIX, `logname` takes no operands and no options:
//! - `logname` — print `root\n` to stdout, exit 0.
//! - Any positional operand → `logname: extra operand\n` on stderr, exit 1.
//! - Any `-X` option → `logname: invalid option\n` on stderr, exit 1.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/logname.html`

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
        main = sym logname_main,
    );
}

// ---------------------------------------------------------------------------
// logname logic (POSIX.1-2024)
// ---------------------------------------------------------------------------

extern "C" fn logname_main(argc: usize, argv: *const *const u8) -> ! {
    // Walk argv[1..]. Any argument is an error: options are unsupported,
    // and POSIX defines no operand for logname.
    if argc > 1 {
        // SAFETY: argv has `argc` valid pointers from the kernel stack.
        let arg = unsafe { argv.add(1).read() };
        if arg.is_null() {
            write_all(1, b"root\n");
            libc::exit(0);
        }
        // SAFETY: argv entries are NUL-terminated C strings; first byte is in bounds.
        let first = unsafe { arg.read() };
        if first == b'-' {
            // SAFETY: byte after '-' is part of the same NUL-terminated string.
            let second = unsafe { arg.add(1).read() };
            // Bare "-" is an operand per POSIX, but logname accepts no operand.
            if second == 0 {
                write_all(2, b"logname: extra operand\n");
            } else {
                write_all(2, b"logname: invalid option\n");
            }
        } else {
            write_all(2, b"logname: extra operand\n");
        }
        libc::exit(1);
    }

    // No arguments: print the hard-coded login name.
    write_all(1, b"root\n");
    libc::exit(0)
}

// ---------------------------------------------------------------------------
// I/O helpers
// ---------------------------------------------------------------------------

/// Write `buf` to `fd`, retrying on short writes. Errors are silently
/// dropped because there is no useful recovery from a failed `write(2)`
/// on stdout/stderr in a one-shot utility.
fn write_all(fd: i32, buf: &[u8]) {
    let mut pos = 0;
    while pos < buf.len() {
        // SAFETY: `buf` slice is valid for `buf.len()` bytes.
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
    write_all(2, b"logname: panic\n");
    libc::exit(1)
}
