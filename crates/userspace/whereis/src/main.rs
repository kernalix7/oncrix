// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/whereis` — util-linux `whereis` utility stub (non-POSIX).
//!
//! Locates the binary, source, and manual-page files for a command. ONCRIX
//! does not currently support PATH lookup or a manual-page database, so
//! this implementation is intentionally simplified: for any argument
//! `<name>`, it prints `"<name>: /bin/<name>\n"` to stdout, regardless of
//! whether `/bin/<name>` actually exists.
//!
//! Behaviour:
//!
//! * `whereis` (no args)    → exit 0 silently.
//! * `whereis <name>`       → write `"<name>: /bin/<name>\n"` to fd 1,
//!                            exit 0.
//!
//! Reference: util-linux `whereis(1)`.

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
        main = sym whereis_main,
    );
}

// ---------------------------------------------------------------------------
// whereis logic
// ---------------------------------------------------------------------------

extern "C" fn whereis_main(argc: usize, argv: *const *const u8) -> ! {
    // No name given — nothing to print, exit successfully.
    if argc < 2 {
        libc::exit(0)
    }

    // SAFETY: argc >= 2 so argv[1] is a valid pointer slot laid out by
    // sys_execve.
    let arg1 = unsafe { argv.add(1).read() };
    if arg1.is_null() {
        libc::exit(0)
    }

    let name_len = c_strlen(arg1);

    // SAFETY: arg1 points to a null-terminated string of length `name_len`.
    let name = unsafe { core::slice::from_raw_parts(arg1, name_len) };

    // Print "<name>: /bin/<name>\n".
    write_all(1, name);
    write_all(1, b": /bin/");
    write_all(1, name);
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
