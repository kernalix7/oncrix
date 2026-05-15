// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/getent` — administrative `getent` utility.
//!
//! Queries an administrative database and prints matching entries to
//! stdout. ONCRIX ships a single hard-coded `root` identity, so the
//! supported databases are:
//!
//! * `passwd` — prints `root:x:0:0:root:/root:/bin/sh\n`
//! * `group`  — prints `root:x:0:\n`
//!
//! With no arguments, `getent` behaves like an unspecified `passwd`
//! query and prints the same `root` line. Any other database name
//! exits with status 2 (unknown database), matching glibc's `getent`.
//!
//! POSIX reference: `getent` is not in POSIX.1-2024 itself; this
//! implementation follows the de facto behavior documented in
//! glibc's `getent(1)` and the IEEE Std 1003.1 `passwd` / `group`
//! file formats from
//! `.priv-storage/.TheOpenGroup/susv5-html/basedefs/`.

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
        main = sym getent_main,
    );
}

// ---------------------------------------------------------------------------
// getent logic
// ---------------------------------------------------------------------------

const PASSWD_LINE: &[u8] = b"root:x:0:0:root:/root:/bin/sh\n";
const GROUP_LINE: &[u8] = b"root:x:0:\n";

extern "C" fn getent_main(argc: usize, argv: *const *const u8) -> ! {
    // argv[0] is the program name; the database argument is argv[1].
    if argc < 2 {
        // No database specified — behave like an unspecified `passwd` query.
        write_all(1, PASSWD_LINE);
        libc::exit(0)
    }

    // SAFETY: argc >= 2 so argv[1] is a valid pointer slot laid out by
    // sys_execve.
    let arg1 = unsafe { argv.add(1).read() };
    if arg1.is_null() {
        write_all(1, PASSWD_LINE);
        libc::exit(0)
    }

    if c_str_eq(arg1, b"passwd") {
        write_all(1, PASSWD_LINE);
        libc::exit(0)
    }
    if c_str_eq(arg1, b"group") {
        write_all(1, GROUP_LINE);
        libc::exit(0)
    }

    // Unknown database — exit status 2, matching glibc `getent`.
    libc::exit(2)
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
