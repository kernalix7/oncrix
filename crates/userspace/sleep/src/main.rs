// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/sleep` — POSIX.1-2024 `sleep` utility.
//!
//! `sleep <SECONDS>` blocks for the requested number of whole seconds
//! via [`libc::nanosleep`]. Exits 0 on success, 1 if the operand is
//! missing or non-numeric.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/sleep.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

/// `_start` must be a *naked* function so the Rust prologue does not
/// allocate a local stack frame before we capture argc/argv from the
/// System V AMD64 initial stack.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym sleep_main,
    );
}

extern "C" fn sleep_main(argc: usize, argv: *const *const u8) -> ! {
    if argc < 2 {
        write_all(2, b"sleep: missing operand\n");
        libc::exit(1);
    }

    // SAFETY: argv has at least argc valid pointers (sys_execve guarantee).
    let arg_ptr = unsafe { argv.add(1).read() };
    if arg_ptr.is_null() {
        write_all(2, b"sleep: missing operand\n");
        libc::exit(1);
    }

    // SAFETY: arg_ptr is a NUL-terminated argv string from sys_execve.
    let arg = unsafe { cstr_to_slice(arg_ptr) };
    let secs = match parse_u64(arg) {
        Some(n) => n,
        None => {
            write_all(2, b"sleep: invalid number\n");
            libc::exit(1);
        }
    };

    let req = libc::Timespec {
        tv_sec: secs as i64,
        tv_nsec: 0,
    };
    // SAFETY: req is a stack-allocated valid Timespec; rem is null.
    unsafe { libc::nanosleep(&req, core::ptr::null_mut()) };

    libc::exit(0)
}

/// Walk a NUL-terminated argv string and return it as a byte slice.
///
/// # Safety
///
/// `p` must point to a NUL-terminated byte sequence.
unsafe fn cstr_to_slice<'a>(p: *const u8) -> &'a [u8] {
    let mut len = 0usize;
    while len < 64 {
        // SAFETY: caller-validated pointer; loop bounds prevent OOB.
        if unsafe { *p.add(len) } == 0 {
            break;
        }
        len += 1;
    }
    // SAFETY: we walked `len` bytes confirming they exist.
    unsafe { core::slice::from_raw_parts(p, len) }
}

/// Parse a non-negative decimal `u64` from `buf`. Returns `None` on
/// empty input or any non-digit character.
fn parse_u64(buf: &[u8]) -> Option<u64> {
    if buf.is_empty() {
        return None;
    }
    let mut n: u64 = 0;
    for &b in buf {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(n)
}

fn write_all(fd: i32, buf: &[u8]) {
    let mut pos = 0;
    while pos < buf.len() {
        // SAFETY: buf slice valid for buf.len() bytes.
        let n = unsafe { libc::write(fd, buf[pos..].as_ptr(), buf.len() - pos) };
        if n <= 0 {
            break;
        }
        pos += n as usize;
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_all(2, b"sleep: panic\n");
    libc::exit(1)
}
