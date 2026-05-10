// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/factor` — print the prime factorization of integers.
//!
//! Usage:
//!   factor [N...]   # for each N, print "N: P1 P2 P3 ..." (factors w/ multiplicity)
//!   factor          # read whitespace-separated integers from stdin
//!
//! Each N is a non-negative decimal integer that fits in u64 (parsed via
//! an i64 helper so signs and overflow are rejected uniformly). The
//! algorithm is trial division up to sqrt(n): pull out all 2s, then walk
//! odd divisors 3, 5, 7, ... until d*d > n; the residual is prime if > 1.
//!
//! `factor` is a GNU coreutils extension and is not part of POSIX.1-2024.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym factor_main,
    );
}

const MAX_ARGS: usize = 64;
const STDIN_CHUNK: usize = 4096;

extern "C" fn factor_main(argc: usize, argv: *const *const u8) -> ! {
    let mut exit_code: i32 = 0;

    if argc <= 1 {
        // Read whitespace-separated integers from stdin.
        let mut buf = [0u8; STDIN_CHUNK];
        let mut digits = [0u8; 32];
        let mut dlen: usize = 0;
        let mut bad_run = false;

        loop {
            // SAFETY: `buf` is valid writable storage of `STDIN_CHUNK` bytes.
            let n = unsafe { libc::read(0, buf.as_mut_ptr(), STDIN_CHUNK) };
            if n <= 0 {
                break;
            }
            for &b in &buf[..n as usize] {
                if is_whitespace(b) {
                    if dlen > 0 {
                        if !flush_token(&digits[..dlen], bad_run) {
                            exit_code = 1;
                        }
                        dlen = 0;
                        bad_run = false;
                    }
                } else if dlen < digits.len() {
                    digits[dlen] = b;
                    dlen += 1;
                } else {
                    // Token longer than buffer — mark as invalid; keep
                    // consuming until the next whitespace boundary.
                    bad_run = true;
                }
            }
        }
        if dlen > 0 && !flush_token(&digits[..dlen], bad_run) {
            exit_code = 1;
        }
    } else {
        let argc = argc.min(MAX_ARGS + 1);
        for i in 1..argc {
            // SAFETY: argv has at least `argc` valid pointer slots.
            let ptr = unsafe { argv.add(i).read() };
            if ptr.is_null() {
                break;
            }
            // SAFETY: argv strings are null-terminated by the kernel.
            let bytes = unsafe { cstr_slice(ptr) };
            if !factor_token(bytes) {
                exit_code = 1;
            }
        }
    }

    libc::exit(exit_code)
}

// ---------------------------------------------------------------------------
// Token handling
// ---------------------------------------------------------------------------

/// Returns true on success, false on invalid input (so callers can flip
/// the exit status). `from_overflow` short-circuits the parse when the
/// caller already knows the token overflowed the digit buffer.
fn flush_token(bytes: &[u8], from_overflow: bool) -> bool {
    if from_overflow {
        report_invalid(bytes);
        return false;
    }
    factor_token(bytes)
}

/// Parse `bytes` as a non-negative integer and print its factorization.
/// Returns true on success.
fn factor_token(bytes: &[u8]) -> bool {
    let value = match parse_u64(bytes) {
        Some(v) => v,
        None => {
            report_invalid(bytes);
            return false;
        }
    };
    print_factors(value, bytes);
    true
}

/// Reject signs and overflow by routing through `parse_i64`. Returns
/// `None` for negatives, `Some(v as u64)` otherwise.
fn parse_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    // Disallow leading sign characters — `factor` only accepts magnitudes.
    if bytes[0] == b'-' || bytes[0] == b'+' {
        return None;
    }
    let mut acc: u64 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(acc)
}

// ---------------------------------------------------------------------------
// Factorisation
// ---------------------------------------------------------------------------

/// Print "<token>: f1 f2 f3 ...\n" for the given value.
///
/// Uses a small stack buffer so we issue at most one write per number.
/// 0 and 1 print as "N:\n" (no factors), matching coreutils.
fn print_factors(mut n: u64, token: &[u8]) {
    // Output staging: token + ": " + up to ~64 factors of "<num> ".
    let mut out = [0u8; 1024];
    let mut pos: usize = 0;

    pos += copy_into(&mut out, pos, token);
    pos += copy_into(&mut out, pos, b":");

    if n >= 2 {
        // Pull out all factors of 2.
        while n % 2 == 0 {
            pos += emit_factor(&mut out, pos, 2);
            n /= 2;
        }
        // Odd trial divisors. Stop when d*d > n.
        let mut d: u64 = 3;
        while let Some(sq) = d.checked_mul(d) {
            if sq > n {
                break;
            }
            while n % d == 0 {
                pos += emit_factor(&mut out, pos, d);
                n /= d;
            }
            d += 2;
        }
        if n > 1 {
            pos += emit_factor(&mut out, pos, n);
        }
    }

    pos += copy_into(&mut out, pos, b"\n");
    write_all(1, &out[..pos]);
}

/// Write " <factor>" into `out` starting at `pos`. Returns bytes written.
fn emit_factor(out: &mut [u8], pos: usize, value: u64) -> usize {
    let mut written = copy_into(out, pos, b" ");
    let mut tmp = [0u8; 20];
    let n = format_u64(value, &mut tmp);
    written += copy_into(out, pos + written, &tmp[..n]);
    written
}

/// Append `src` to `out` at `pos`, truncating on overflow. Returns the
/// number of bytes actually copied.
fn copy_into(out: &mut [u8], pos: usize, src: &[u8]) -> usize {
    if pos >= out.len() {
        return 0;
    }
    let avail = out.len() - pos;
    let n = src.len().min(avail);
    out[pos..pos + n].copy_from_slice(&src[..n]);
    n
}

/// Format `value` into `out` (decimal, no sign). `out` must hold at
/// least 20 bytes (max u64 = 20 digits). Returns digits written.
fn format_u64(value: u64, out: &mut [u8]) -> usize {
    if value == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut len = 0usize;
    let mut n = value;
    while n > 0 {
        tmp[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    for i in 0..len {
        out[i] = tmp[len - 1 - i];
    }
    len
}

// ---------------------------------------------------------------------------
// Diagnostics & helpers
// ---------------------------------------------------------------------------

fn report_invalid(bytes: &[u8]) {
    write_all(2, b"factor: '");
    write_all(2, bytes);
    write_all(2, b"' is not a valid positive integer\n");
}

fn is_whitespace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

/// SAFETY: `ptr` must be a valid null-terminated C string from argv.
unsafe fn cstr_slice(ptr: *const u8) -> &'static [u8] {
    let mut len = 0usize;
    // SAFETY: by precondition, the string terminates within argv bounds.
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
        if len > 4096 {
            break;
        }
    }
    // SAFETY: ptr is valid for `len` bytes per the loop above.
    unsafe { core::slice::from_raw_parts(ptr, len) }
}

fn write_all(fd: i32, buf: &[u8]) {
    let mut pos = 0;
    while pos < buf.len() {
        // SAFETY: `buf` slice is valid for `buf.len()` bytes.
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
    write_all(2, b"factor: panic\n");
    libc::exit(1)
}
