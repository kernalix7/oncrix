// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/lsattr` — e2fsprogs `lsattr(1)` utility stub (non-POSIX).
//!
//! Lists Linux extended (ext2/3/4) file attributes. ONCRIX uses an in-memory
//! ramfs which does not support extended attribute flags, so every target
//! reports the canonical "no flags set" line: fourteen dashes (the e2fsprogs
//! flag-column width), a space, the target path, and a newline.
//!
//! Behaviour:
//!
//! * `lsattr` (no args)      → write `"-------------- .\n"` to fd 1, exit 0.
//! * `lsattr <path>`         → write `"-------------- <path>\n"` to fd 1,
//!                             exit 0.
//!
//! Reference: e2fsprogs `lsattr(1)`.

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
        main = sym lsattr_main,
    );
}

// ---------------------------------------------------------------------------
// lsattr logic
// ---------------------------------------------------------------------------

extern "C" fn lsattr_main(argc: usize, argv: *const *const u8) -> ! {
    // Fourteen dashes followed by a space — matches the e2fsprogs flag column.
    const FLAGS: &[u8] = b"-------------- ";

    // Default target is the current directory when no operand is given.
    let (target_ptr, target_len) = if argc >= 2 {
        // SAFETY: argc >= 2 so argv[1] is a valid pointer slot laid out by
        // sys_execve.
        let arg1 = unsafe { argv.add(1).read() };
        if arg1.is_null() {
            (b".".as_ptr(), 1usize)
        } else {
            (arg1, c_strlen(arg1))
        }
    } else {
        (b".".as_ptr(), 1usize)
    };

    write_all(1, FLAGS);
    // SAFETY: target_ptr points to a buffer of at least `target_len` bytes —
    // either a literal "." or a null-terminated argv string whose length we
    // just measured.
    let target = unsafe { core::slice::from_raw_parts(target_ptr, target_len) };
    write_all(1, target);
    write_all(1, b"\n");

    libc::exit(0)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
