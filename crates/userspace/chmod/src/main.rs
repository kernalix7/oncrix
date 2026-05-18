// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/chmod` — POSIX `chmod(1)` utility stub.
//!
//! Changes the file mode bits of the supplied operands. ONCRIX ramfs does
//! not yet implement real permissions, so this stub treats every successful
//! invocation as a no-op and exits 0 (POSIX permits exit 0 on a no-op
//! success). Operand validation is limited to argc.
//!
//! Behaviour:
//!
//! * `chmod` with fewer than two operands (mode + at least one file)
//!   → write `"chmod: missing operand\n"` to fd 2, exit 1.
//! * Otherwise                                          → silent exit 0.
//!
//! Reference: POSIX `chmod(1)`.
//! See `.priv-storage/.TheOpenGroup/susv5-html/utilities/chmod.html`.

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
        main = sym chmod_main,
    );
}

// ---------------------------------------------------------------------------
// chmod logic
// ---------------------------------------------------------------------------

extern "C" fn chmod_main(argc: usize, _argv: *const *const u8) -> ! {
    // POSIX `chmod` requires at least a mode operand and one file operand,
    // so argc must be >= 3 (argv[0] = program name, argv[1] = mode,
    // argv[2] = file).
    if argc < 3 {
        write_all(2, b"chmod: missing operand\n");
        libc::exit(1)
    }

    // ramfs has no permissions yet — no-op success.
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
