// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/chmod` — POSIX `chmod(1)` utility.
//!
//! Usage: `chmod OCTAL-MODE FILE`. Parses an octal mode operand
//! (e.g. `644`, `0755`) and applies it to `FILE` via the `chmod(2)`
//! syscall (`SYS_CHMOD`, number 90). ONCRIX ramfs stores the mode bits
//! but does not yet enforce permissions, so the change is observable
//! via `stat` only. Symbolic modes (`u+x`) and multiple file operands
//! are not yet supported.
//!
//! Behaviour:
//!
//! * `chmod` with fewer than two operands → `"chmod: missing operand\n"`
//!   to fd 2, exit 1.
//! * Non-octal mode operand → `"chmod: invalid mode\n"` to fd 2, exit 1.
//! * `chmod(2)` failure → `"chmod: cannot change mode\n"` to fd 2, exit 1.
//!
//! Reference: POSIX `chmod(1)`.
//! See `.priv-storage/.TheOpenGroup/susv5-html/utilities/chmod.html`.

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
        main = sym chmod_main,
    );
}

// ---------------------------------------------------------------------------
// chmod logic
// ---------------------------------------------------------------------------

extern "C" fn chmod_main(argc: usize, argv: *const *const u8) -> ! {
    // argv[0] = program, argv[1] = mode, argv[2] = file.
    if argc < 3 {
        write_all(2, b"chmod: missing operand\n");
        libc::exit(1)
    }

    // SAFETY: argc >= 3, so argv[1] and argv[2] are valid pointer slots.
    let mode_ptr = unsafe { argv.add(1).read() };
    let file_ptr = unsafe { argv.add(2).read() };
    if mode_ptr.is_null() || file_ptr.is_null() {
        write_all(2, b"chmod: missing operand\n");
        libc::exit(1)
    }

    let mode = match parse_octal(mode_ptr) {
        Some(m) => m,
        None => {
            write_all(2, b"chmod: invalid mode\n");
            libc::exit(1)
        }
    };

    // SAFETY: file_ptr is a NUL-terminated argv string.
    let rc = unsafe { libc::chmod(file_ptr, mode) };
    if rc < 0 {
        write_all(2, b"chmod: cannot change mode\n");
        libc::exit(1)
    }
    libc::exit(0)
}

/// Parse a NUL-terminated octal mode string (e.g. `"644"`, `"0755"`).
///
/// Returns `None` on an empty string or any non-octal digit. Capped at
/// 7 digits to avoid overflow.
fn parse_octal(ptr: *const u8) -> Option<u32> {
    let mut val: u32 = 0;
    let mut i = 0usize;
    loop {
        // SAFETY: ptr is a NUL-terminated argv string; we stop at the
        // terminator before reading past it.
        let c = unsafe { ptr.add(i).read() };
        if c == 0 {
            break;
        }
        if !(b'0'..=b'7').contains(&c) {
            return None;
        }
        val = val.checked_mul(8)?.checked_add((c - b'0') as u32)?;
        i += 1;
        if i > 7 {
            return None;
        }
    }
    if i == 0 { None } else { Some(val) }
}

// ---------------------------------------------------------------------------
// Helpers
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

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libc::exit(1)
}
