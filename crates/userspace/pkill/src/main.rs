// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/pkill` — procps `pkill(1)` utility.
//!
//! Sends a signal (SIGTERM by default) to processes matching a name. ONCRIX
//! currently has a fixed early-boot process table, so this implementation
//! recognises a small set of well-known names:
//!
//! * `init` → PID 1
//! * `sh`   → PID 2
//!
//! Usage:
//!   pkill PATTERN
//!   pkill -SIG PATTERN          # signal ignored in this stub
//!
//! The `-SIG` form is accepted for command-line compatibility but the actual
//! signal sent is always `SIGTERM`, matching the task contract. Anything else
//! exits with status 1.
//!
//! Reference: procps `pkill(1)`.

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
        main = sym pkill_main,
    );
}

// ---------------------------------------------------------------------------
// pkill logic
// ---------------------------------------------------------------------------

extern "C" fn pkill_main(argc: usize, argv: *const *const u8) -> ! {
    if argc < 2 {
        write_all(2, b"pkill: missing pattern\n");
        libc::exit(1)
    }

    // SAFETY: argc >= 2 so argv[1] is a valid pointer slot laid out by
    // sys_execve.
    let arg1 = unsafe { argv.add(1).read() };
    if arg1.is_null() {
        write_all(2, b"pkill: missing pattern\n");
        libc::exit(1)
    }

    // Optional `-SIG` first argument: skip past it if present, target = argv[2].
    let target = if argc >= 3 && first_byte(arg1) == b'-' {
        // SAFETY: argc >= 3 so argv[2] is a valid pointer slot.
        let p = unsafe { argv.add(2).read() };
        if p.is_null() {
            libc::exit(1)
        }
        p
    } else {
        arg1
    };

    if c_str_eq(target, b"init") {
        let _ = libc::kill(1, libc::SIGTERM);
        libc::exit(0)
    }
    if c_str_eq(target, b"sh") {
        let _ = libc::kill(2, libc::SIGTERM);
        libc::exit(0)
    }

    libc::exit(1)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read the first byte of a C string, or 0 if the pointer is null.
fn first_byte(ptr: *const u8) -> u8 {
    if ptr.is_null() {
        return 0;
    }
    // SAFETY: ptr is a non-null pointer to a kernel-supplied C string; reading
    // index 0 either yields a payload byte or the null terminator.
    unsafe { ptr.read() }
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

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libc::exit(1)
}
