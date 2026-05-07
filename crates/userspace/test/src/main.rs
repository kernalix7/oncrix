// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/test` — POSIX.1-2024 conditional expression evaluator.
//!
//! Also installable as `/bin/[`. When invoked as `[` the final argument
//! must be `]` (a closing bracket) and is stripped before evaluation;
//! POSIX requires this so the bracket form parses unambiguously.
//!
//! Supported expressions (POSIX subset):
//!
//! Strings:
//!   -z STRING            true if STRING has zero length
//!   -n STRING            true if STRING has non-zero length
//!   STRING               true if STRING is not empty (same as `-n`)
//!   STRING1 = STRING2    true if equal
//!   STRING1 != STRING2   true if not equal
//!
//! Integers (exit 2 if either side is not a valid integer):
//!   N1 -eq N2            true if equal
//!   N1 -ne N2            true if not equal
//!   N1 -lt N2            true if less than
//!   N1 -le N2            true if less or equal
//!   N1 -gt N2            true if greater than
//!   N1 -ge N2            true if greater or equal
//!
//! Files (only existence is checked — full stat-based predicates require
//! richer libc bindings than ONCRIX exposes today):
//!   -e PATH              true if PATH exists (uses libc::stat)
//!
//! Negation:
//!   ! EXPR               invert the result
//!
//! Exit status:
//!   0 — expression true
//!   1 — expression false
//!   2 — invalid expression / parse error
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/test.html`

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
        main = sym test_main,
    );
}

extern "C" fn test_main(argc: usize, argv: *const *const u8) -> ! {
    // SAFETY: argc/argv come from the kernel-supplied stack frame.
    let prog = unsafe { cstr_at(argv, 0) };
    let invoked_as_bracket = prog == b"[" || prog.ends_with(b"/[");

    // Collect arguments into a small fixed-size buffer.  POSIX `test`
    // expressions are short — capping at 16 tokens covers the typical
    // shell idioms (`[ -z "$x" ]`, `[ "$a" = "$b" ]`, etc.).
    const MAX_ARGS: usize = 16;
    let mut args: [&[u8]; MAX_ARGS] = [b""; MAX_ARGS];
    let mut nargs = 0usize;
    let mut i = 1usize;
    while i < argc && nargs < MAX_ARGS {
        // SAFETY: i < argc; argv[i] is a valid C string.
        let bytes = unsafe { cstr_at(argv, i) };
        args[nargs] = bytes;
        nargs += 1;
        i += 1;
    }

    if invoked_as_bracket {
        // POSIX: `[` requires the final argument to be `]`.
        if nargs == 0 || args[nargs - 1] != b"]" {
            write_err(b"[: missing ']'\n");
            libc::exit(2);
        }
        nargs -= 1;
    }

    let result = match evaluate(&args[..nargs]) {
        Ok(v) => v,
        Err(()) => {
            write_err(b"test: invalid expression\n");
            libc::exit(2);
        }
    };

    libc::exit(if result { 0 } else { 1 })
}

fn evaluate(args: &[&[u8]]) -> Result<bool, ()> {
    match args.len() {
        0 => Ok(false), // POSIX: empty expression is false.
        1 => Ok(!args[0].is_empty()),
        2 => match args[0] {
            b"!" => Ok(args[1].is_empty()),
            b"-z" => Ok(args[1].is_empty()),
            b"-n" => Ok(!args[1].is_empty()),
            b"-e" => Ok(path_exists(args[1])),
            _ => Err(()),
        },
        3 => {
            let lhs = args[0];
            let op = args[1];
            let rhs = args[2];
            match op {
                b"=" => Ok(lhs == rhs),
                b"!=" => Ok(lhs != rhs),
                b"-eq" | b"-ne" | b"-lt" | b"-le" | b"-gt" | b"-ge" => {
                    let l = parse_i64(lhs).ok_or(())?;
                    let r = parse_i64(rhs).ok_or(())?;
                    Ok(match op {
                        b"-eq" => l == r,
                        b"-ne" => l != r,
                        b"-lt" => l < r,
                        b"-le" => l <= r,
                        b"-gt" => l > r,
                        b"-ge" => l >= r,
                        _ => unreachable!(),
                    })
                }
                _ => Err(()),
            }
        }
        4 if args[0] == b"!" => evaluate(&args[1..]).map(|v| !v),
        _ => Err(()),
    }
}

fn path_exists(path: &[u8]) -> bool {
    if path.is_empty() {
        return false;
    }
    // libc::stat takes a NUL-terminated C string; `path` here is a slice
    // into argv whose terminator is past the slice end, so we copy.
    let mut buf = [0u8; 256];
    let n = path.len().min(buf.len() - 1);
    buf[..n].copy_from_slice(&path[..n]);
    // SAFETY: `Stat` is a `#[repr(C)]` POD whose bytes the kernel will
    // fully overwrite on success; we never read from `st` if `stat`
    // fails, so the zero-init is sound. `buf` is NUL-terminated by
    // construction.
    let mut st = core::mem::MaybeUninit::<libc::Stat>::zeroed();
    let r = unsafe { libc::stat(buf.as_ptr(), st.as_mut_ptr()) };
    r >= 0
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

fn write_err(msg: &[u8]) {
    let mut pos = 0;
    while pos < msg.len() {
        // SAFETY: msg is a valid byte slice; pointer is in-bounds.
        let n = unsafe { libc::write(2, msg[pos..].as_ptr(), msg.len() - pos) };
        if n <= 0 {
            break;
        }
        pos += n as usize;
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_err(b"test: panic\n");
    libc::exit(2)
}
