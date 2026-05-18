// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/whatis` — man-db `whatis` utility stub (non-POSIX).
//!
//! Displays one-line manual-page descriptions. ONCRIX has no manual-page
//! database, so this implementation recognises a small fixed set of
//! built-in names and reports "nothing appropriate" for the rest,
//! matching man-db `whatis` semantics.
//!
//! Behaviour:
//!
//! * `whatis` (no args)        → write `"whatis: missing name\n"` to fd 2,
//!                               exit 1.
//! * `whatis init`             → `"init (1) - ONCRIX init system process\n"`
//!                               to fd 1, exit 0.
//! * `whatis sh`               → `"sh (1) - ONCRIX shell\n"` to fd 1,
//!                               exit 0.
//! * `whatis <other>`          → `"<other>: nothing appropriate\n"` to fd 1,
//!                               exit 1.
//!
//! Reference: man-db `whatis(1)`.

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
        main = sym whatis_main,
    );
}

// ---------------------------------------------------------------------------
// whatis logic
// ---------------------------------------------------------------------------

extern "C" fn whatis_main(argc: usize, argv: *const *const u8) -> ! {
    // No name given — error to fd 2 and exit 1.
    if argc < 2 {
        write_all(2, b"whatis: missing name\n");
        libc::exit(1)
    }

    // SAFETY: argc >= 2 so argv[1] is a valid pointer slot laid out by
    // sys_execve.
    let arg1 = unsafe { argv.add(1).read() };
    if arg1.is_null() {
        write_all(2, b"whatis: missing name\n");
        libc::exit(1)
    }

    if c_str_eq(arg1, b"init") {
        write_all(1, b"init (1) - ONCRIX init system process\n");
        libc::exit(0)
    }
    if c_str_eq(arg1, b"sh") {
        write_all(1, b"sh (1) - ONCRIX shell\n");
        libc::exit(0)
    }

    // Unknown name — "nothing appropriate" on stdout, exit 1.
    let name_len = c_strlen(arg1);
    // SAFETY: arg1 points to a null-terminated string of length `name_len`.
    let name = unsafe { core::slice::from_raw_parts(arg1, name_len) };
    write_all(1, name);
    write_all(1, b": nothing appropriate\n");
    libc::exit(1)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compare a null-terminated C string with a byte slice for exact equality.
fn c_str_eq(ptr: *const u8, expected: &[u8]) -> bool {
    for (i, &want) in expected.iter().enumerate() {
        // SAFETY: ptr is a null-terminated string from the kernel-constructed
        // argv; we stop at the terminator before walking past it.
        let got = unsafe { ptr.add(i).read() };
        if got == 0 || got != want {
            return false;
        }
    }
    // Require the terminator immediately after the matched prefix.
    // SAFETY: same as above; index `expected.len()` is the next byte.
    unsafe { ptr.add(expected.len()).read() == 0 }
}

/// Return the length of a null-terminated C string, excluding the terminator.
fn c_strlen(s: *const u8) -> usize {
    let mut n: usize = 0;
    // SAFETY: caller guarantees the string is null-terminated.
    while unsafe { s.add(n).read() } != 0 {
        n += 1;
    }
    n
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

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libc::exit(1)
}
