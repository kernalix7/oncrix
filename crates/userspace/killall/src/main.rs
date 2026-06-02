// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/killall` — psmisc `killall(1)` utility.
//!
//! Sends `SIGTERM` to all processes matching a name. ONCRIX currently has a
//! fixed early-boot process table, so this implementation recognises a small
//! set of well-known names:
//!
//! * `init` → PID 1
//! * `sh`   → PID 2
//!
//! Unknown names produce `<name>: no process found` on stderr and exit 1.
//!
//! Reference: psmisc `killall(1)`.

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
        main = sym killall_main,
    );
}

// ---------------------------------------------------------------------------
// killall logic
// ---------------------------------------------------------------------------

extern "C" fn killall_main(argc: usize, argv: *const *const u8) -> ! {
    if argc < 2 {
        write_all(2, b"killall: missing process name\n");
        libc::exit(1)
    }

    // SAFETY: argc >= 2 so argv[1] is a valid pointer slot laid out by
    // sys_execve.
    let arg1 = unsafe { argv.add(1).read() };
    if arg1.is_null() {
        write_all(2, b"killall: missing process name\n");
        libc::exit(1)
    }

    if c_str_eq(arg1, b"init") {
        let _ = libc::kill(1, libc::SIGTERM);
        libc::exit(0)
    }
    if c_str_eq(arg1, b"sh") {
        let _ = libc::kill(2, libc::SIGTERM);
        libc::exit(0)
    }

    // Not found — emit `<name>: no process found\n` to stderr.
    let len = c_strlen(arg1);
    // SAFETY: c_strlen returns the count up to (but excluding) the null
    // terminator, so the first `len` bytes starting at arg1 are valid.
    write_all_raw(2, arg1, len);
    write_all(2, b": no process found\n");
    libc::exit(1)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the length of a null-terminated C string (capped to 4096).
fn c_strlen(ptr: *const u8) -> usize {
    if ptr.is_null() {
        return 0;
    }
    let mut len = 0usize;
    // SAFETY: ptr is a null-terminated C string from the kernel-constructed
    // argv; stop at the terminator or the 4096-byte safety cap.
    while unsafe { ptr.add(len).read() } != 0 {
        len += 1;
        if len >= 4096 {
            break;
        }
    }
    len
}

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

/// Write `len` bytes from a raw pointer to `fd`, retrying on short writes.
fn write_all_raw(fd: i32, ptr: *const u8, len: usize) {
    let mut pos = 0;
    while pos < len {
        // SAFETY: Caller guarantees `ptr..ptr+len` is readable; we offset
        // within that range.
        let n = unsafe { libc::write(fd, ptr.add(pos), len - pos) };
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
