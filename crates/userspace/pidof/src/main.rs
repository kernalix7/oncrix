// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/pidof` — util-linux `pidof` utility (non-POSIX).
//!
//! Looks up the PIDs of running processes by name and prints them to
//! stdout, space-separated, terminated by a newline. ONCRIX currently
//! has a fixed early-boot process table, so this implementation
//! recognises a small set of well-known names:
//!
//! * `init` / `/bin/init` → PID 1
//! * `sh`   / `/bin/sh`   → PID 2
//!
//! Anything else (or missing argument) exits with status 1, matching
//! util-linux `pidof` semantics for "no processes matched".
//!
//! Reference: util-linux `pidof(1)`.

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
        main = sym pidof_main,
    );
}

// ---------------------------------------------------------------------------
// pidof logic
// ---------------------------------------------------------------------------

extern "C" fn pidof_main(argc: usize, argv: *const *const u8) -> ! {
    // No name given — POSIX-ish "no matches found".
    if argc < 2 {
        libc::exit(1)
    }

    // SAFETY: argc >= 2 so argv[1] is a valid pointer slot laid out by
    // sys_execve.
    let arg1 = unsafe { argv.add(1).read() };
    if arg1.is_null() {
        libc::exit(1)
    }

    if c_str_eq(arg1, b"init") || c_str_eq(arg1, b"/bin/init") {
        write_all(1, b"1\n");
        libc::exit(0)
    }
    if c_str_eq(arg1, b"sh") || c_str_eq(arg1, b"/bin/sh") {
        write_all(1, b"2\n");
        libc::exit(0)
    }

    // No matching process found.
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
