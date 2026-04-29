// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/echo` — POSIX.1-2024 `echo` utility.
//!
//! Writes each operand to stdout separated by a single space, followed
//! by a newline. Does not interpret escape sequences (XSI extensions
//! are not implemented). Exits with 0 on success.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/echo.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// `_start` must be a *naked* function. The kernel's `sys_execve`
/// places `argc` at `[RSP]` and `argv` pointers at `[RSP+8..]` on
/// the System V AMD64 initial stack. A normal Rust prologue would
/// `sub rsp, N` for locals before our asm could capture those values,
/// so naked it is.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym echo_main,
    );
}

// ---------------------------------------------------------------------------
// Echo logic (POSIX.1-2024)
// ---------------------------------------------------------------------------

extern "C" fn echo_main(argc: usize, argv: *const *const u8) -> ! {
    // argv[0] is the program name; operands start at argv[1].
    let mut first = true;
    for i in 1..argc {
        // SAFETY: argv has at least `argc` valid non-null pointers as laid
        // out by sys_execve.
        let ptr = unsafe { argv.add(i).read() };
        if ptr.is_null() {
            break;
        }
        if !first {
            write_all(1, b" ");
        }
        first = false;
        write_str(1, ptr);
    }
    write_all(1, b"\n");
    libc::exit(0)
}

// ---------------------------------------------------------------------------
// I/O helpers
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

/// Write a null-terminated C string to `fd`.
fn write_str(fd: i32, ptr: *const u8) {
    // Walk to null terminator to find length.
    let mut len = 0usize;
    // SAFETY: ptr is a null-terminated string from the kernel-constructed argv.
    while unsafe { ptr.add(len).read() } != 0 {
        len += 1;
    }
    if len > 0 {
        // SAFETY: ptr is valid for len bytes (we just counted them).
        write_all(fd, unsafe { core::slice::from_raw_parts(ptr, len) });
    }
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_all(2, b"echo: panic\n");
    libc::exit(1)
}
