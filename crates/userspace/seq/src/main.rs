// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/seq` — print a sequence of integers.
//!
//! Usage:
//!   seq LAST                  # 1 .. LAST inclusive, step 1
//!   seq FIRST LAST            # FIRST .. LAST inclusive, step 1
//!   seq FIRST INCREMENT LAST  # FIRST .. LAST inclusive, step INCREMENT
//!
//! Numbers are integers in the i64 range. Negative INCREMENT walks
//! downward; with FIRST > LAST and a positive INCREMENT (or the
//! reverse), the output is empty and exit status is 0 — matching the
//! GNU `seq` convention. POSIX does not standardise `seq` but it is
//! ubiquitous in shell scripts; we follow the de-facto behaviour.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym seq_main,
    );
}

extern "C" fn seq_main(argc: usize, argv: *const *const u8) -> ! {
    if argc < 2 {
        write_err(b"seq: missing operand\n");
        libc::exit(1);
    }

    // SAFETY: argv[1..argc] are valid C strings supplied by the kernel.
    let (first, increment, last) = match argc {
        2 => {
            let last = match parse_arg(argv, 1) {
                Some(v) => v,
                None => bad_arg(),
            };
            (1i64, 1i64, last)
        }
        3 => {
            let first = match parse_arg(argv, 1) {
                Some(v) => v,
                None => bad_arg(),
            };
            let last = match parse_arg(argv, 2) {
                Some(v) => v,
                None => bad_arg(),
            };
            (first, 1i64, last)
        }
        _ => {
            let first = match parse_arg(argv, 1) {
                Some(v) => v,
                None => bad_arg(),
            };
            let increment = match parse_arg(argv, 2) {
                Some(v) => v,
                None => bad_arg(),
            };
            let last = match parse_arg(argv, 3) {
                Some(v) => v,
                None => bad_arg(),
            };
            if increment == 0 {
                write_err(b"seq: increment must not be zero\n");
                libc::exit(1);
            }
            (first, increment, last)
        }
    };

    let mut current = first;
    let going_up = increment > 0;
    loop {
        if going_up && current > last {
            break;
        }
        if !going_up && current < last {
            break;
        }
        let mut buf = [0u8; 24];
        let n = format_i64(current, &mut buf);
        write_to(1, &buf[..n]);
        write_to(1, b"\n");
        match current.checked_add(increment) {
            Some(next) => current = next,
            None => break,
        }
    }
    libc::exit(0)
}

fn bad_arg() -> ! {
    write_err(b"seq: invalid integer\n");
    libc::exit(1)
}

/// SAFETY: caller guarantees `idx < argc` and `argv` is a valid argv pointer.
fn parse_arg(argv: *const *const u8, idx: usize) -> Option<i64> {
    let bytes = unsafe { cstr_at(argv, idx) };
    parse_i64(bytes)
}

/// SAFETY: caller guarantees `idx < argc` and `argv` is a valid argv pointer.
unsafe fn cstr_at(argv: *const *const u8, idx: usize) -> &'static [u8] {
    unsafe {
        let p = *argv.add(idx);
        if p.is_null() {
            return &[];
        }
        let mut len = 0usize;
        while *p.add(len) != 0 {
            len += 1;
            if len > 4096 {
                break;
            }
        }
        core::slice::from_raw_parts(p, len)
    }
}

fn parse_i64(bytes: &[u8]) -> Option<i64> {
    if bytes.is_empty() {
        return None;
    }
    let (negative, digits) = match bytes[0] {
        b'-' => (true, &bytes[1..]),
        b'+' => (false, &bytes[1..]),
        _ => (false, bytes),
    };
    if digits.is_empty() {
        return None;
    }
    let mut acc: i64 = 0;
    for &b in digits {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((b - b'0') as i64)?;
    }
    if negative { Some(-acc) } else { Some(acc) }
}

/// Format `value` into `out` and return the number of bytes written.
/// `out` must be at least 24 bytes (max i64 = -9223372036854775808 = 20 chars).
fn format_i64(value: i64, out: &mut [u8]) -> usize {
    if value == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 24];
    let (negative, mut n) = if value < 0 {
        (true, value.unsigned_abs())
    } else {
        (false, value as u64)
    };
    let mut len = 0usize;
    while n > 0 {
        tmp[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    let mut pos = 0;
    if negative {
        out[pos] = b'-';
        pos += 1;
    }
    for i in (0..len).rev() {
        out[pos] = tmp[i];
        pos += 1;
    }
    pos
}

fn write_to(fd: i32, buf: &[u8]) {
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

fn write_err(msg: &[u8]) {
    write_to(2, msg);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_err(b"seq: panic\n");
    libc::exit(1)
}
