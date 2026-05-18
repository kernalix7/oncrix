// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/apropos` — POSIX `apropos` utility stub.
//!
//! Searches the manual-page short descriptions for a keyword. ONCRIX has
//! no manual-page database yet, so every search returns "nothing
//! appropriate" — matching the documented behavior of POSIX `apropos`
//! when no entries match.
//!
//! Behaviour:
//!
//! * `apropos` (no args)    → write `"apropos: missing keyword\n"`
//!                            to fd 2, exit 1.
//! * `apropos <keyword>`    → write `"<keyword>: nothing appropriate\n"`
//!                            to fd 1, exit 0.
//!
//! POSIX reference:
//! `.priv-storage/.TheOpenGroup/susv5-html/utilities/apropos.html`.

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
        main = sym apropos_main,
    );
}

// ---------------------------------------------------------------------------
// apropos logic
// ---------------------------------------------------------------------------

extern "C" fn apropos_main(argc: usize, argv: *const *const u8) -> ! {
    // No keyword given — error to fd 2 and exit 1.
    if argc < 2 {
        write_all(2, b"apropos: missing keyword\n");
        libc::exit(1)
    }

    // SAFETY: argc >= 2 so argv[1] is a valid pointer slot laid out by
    // sys_execve.
    let arg1 = unsafe { argv.add(1).read() };
    if arg1.is_null() {
        write_all(2, b"apropos: missing keyword\n");
        libc::exit(1)
    }

    let kw_len = c_strlen(arg1);

    // SAFETY: arg1 points to a null-terminated string of length `kw_len`.
    let keyword = unsafe { core::slice::from_raw_parts(arg1, kw_len) };

    // Print "<keyword>: nothing appropriate\n".
    write_all(1, keyword);
    write_all(1, b": nothing appropriate\n");

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
