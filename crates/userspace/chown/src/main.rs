// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/chown` — POSIX `chown(1)` utility stub.
//!
//! Changes the owner (and optionally group) of the supplied file operands.
//! ONCRIX ramfs does not yet track owner/group, so this stub treats every
//! successful invocation as a no-op and exits 0 (POSIX permits exit 0 on
//! a no-op success). Operand validation is limited to argc.
//!
//! Behaviour:
//!
//! * `chown` with fewer than two operands (owner + at least one file)
//!   → write `"chown: missing operand\n"` to fd 2, exit 1.
//! * Otherwise                                          → silent exit 0.
//!
//! Reference: POSIX `chown(1)`.
//! See `.priv-storage/.TheOpenGroup/susv5-html/utilities/chown.html`.

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
        main = sym chown_main,
    );
}

// ---------------------------------------------------------------------------
// chown logic
// ---------------------------------------------------------------------------

extern "C" fn chown_main(argc: usize, _argv: *const *const u8) -> ! {
    // POSIX `chown` requires at least an owner operand and one file operand,
    // so argc must be >= 3 (argv[0] = program name, argv[1] = owner[:group],
    // argv[2] = file).
    if argc < 3 {
        write_all(2, b"chown: missing operand\n");
        libc::exit(1)
    }

    // ramfs has no owner/group yet — no-op success.
    libc::exit(0)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
