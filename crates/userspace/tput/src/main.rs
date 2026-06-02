// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/tput` — POSIX `tput` minimal terminal capability query.
//!
//! Reads `argv[1]` as a terminfo capability name and emits the
//! corresponding ANSI/xterm control sequence (or numeric value) to
//! stdout. ONCRIX ships a fixed 80x25 console with VT100/xterm-style
//! escape support, so the capability set is hard-coded:
//!
//! * `clear` — cursor home + erase screen (`ESC [ H ESC [ 2 J`)
//! * `cols`  — `80\n`
//! * `lines` — `25\n`
//! * `reset` — terminal reset (`ESC c`)
//!
//! Exit codes:
//! * `0` — capability recognized and emitted.
//! * `1` — capability name not recognized.
//! * `2` — usage error (no capability argument), per POSIX.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/tput.html`

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
        main = sym tput_main,
    );
}

// ---------------------------------------------------------------------------
// tput logic
// ---------------------------------------------------------------------------

/// `clear` — cursor home + erase entire screen.
const SEQ_CLEAR: &[u8] = b"\x1b[H\x1b[2J";
/// `reset` — full terminal reset (RIS).
const SEQ_RESET: &[u8] = b"\x1bc";
/// `cols` — fixed console width.
const COLS_LINE: &[u8] = b"80\n";
/// `lines` — fixed console height.
const LINES_LINE: &[u8] = b"25\n";

extern "C" fn tput_main(argc: usize, argv: *const *const u8) -> ! {
    // argv[0] is the program name; the capability name is argv[1].
    if argc < 2 {
        // POSIX: usage error -> exit status 2.
        libc::exit(2)
    }

    // SAFETY: argc >= 2 so argv[1] is a valid pointer slot laid out by
    // sys_execve.
    let arg1 = unsafe { argv.add(1).read() };
    if arg1.is_null() {
        libc::exit(2)
    }

    if c_str_eq(arg1, b"clear") {
        write_all(1, SEQ_CLEAR);
        libc::exit(0)
    }
    if c_str_eq(arg1, b"cols") {
        write_all(1, COLS_LINE);
        libc::exit(0)
    }
    if c_str_eq(arg1, b"lines") {
        write_all(1, LINES_LINE);
        libc::exit(0)
    }
    if c_str_eq(arg1, b"reset") {
        write_all(1, SEQ_RESET);
        libc::exit(0)
    }

    // Unknown capability — POSIX exit status 1 ("unknown capability").
    libc::exit(1)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compare a null-terminated C string with a byte slice for exact equality.
///
/// Returns true only if the C string matches `expected` byte-for-byte and is
/// terminated by NUL immediately after the matched prefix (i.e. no trailing
/// characters).
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
