// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/printf` — format and print arguments.
//!
//! Usage:
//!   printf FORMAT [ARG ...]
//!
//! Conversion specifiers supported:
//!   %s   string
//!   %d   signed decimal integer (i64)
//!   %u   unsigned decimal integer (u64)
//!   %x   unsigned lowercase hexadecimal
//!   %X   unsigned uppercase hexadecimal
//!   %o   unsigned octal
//!   %c   single character (first byte of the argument)
//!   %%   literal percent
//!
//! Width is supported (e.g. `%5d`, `%10s`); precision is parsed but
//! only honoured for `%s` (truncation to N bytes). Flag characters
//! `-` (left-align) and `0` (zero-pad on numeric) are supported.
//!
//! Backslash escapes recognised in the format string and in `%b`-style
//! arguments: `\n` `\t` `\r` `\\` `\0` `\a` `\b` `\f` `\v`.
//!
//! When fewer ARGs are supplied than the format consumes, the format
//! is reused on remaining ARGs. POSIX behaviour.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/printf.html`

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
        main = sym printf_main,
    );
}

extern "C" fn printf_main(argc: usize, argv: *const *const u8) -> ! {
    if argc < 2 {
        write_err(b"printf: missing FORMAT\n");
        libc::exit(1);
    }

    // SAFETY: argv[1] is a valid C string from the kernel.
    let fmt = unsafe { cstr_at(argv, 1) };

    // Collect arg pointers/lens for the data list (argv[2..argc]).
    let mut arg_idx = 2usize;

    // POSIX: if FORMAT consumes fewer than (argc - 1) ARGS, reuse FORMAT
    // on the remaining ARGS. We loop here until no progress is made
    // (i.e. FORMAT had no conversions and ARGS remain).
    let mut had_error = false;
    loop {
        let prev_idx = arg_idx;
        if !render_once(fmt, argv, argc, &mut arg_idx, &mut had_error) {
            had_error = true;
            break;
        }
        if arg_idx >= argc {
            break;
        }
        if arg_idx == prev_idx {
            // No conversions consumed any args; would loop forever.
            break;
        }
    }

    libc::exit(if had_error { 1 } else { 0 })
}

fn render_once(
    fmt: &[u8],
    argv: *const *const u8,
    argc: usize,
    arg_idx: &mut usize,
    had_error: &mut bool,
) -> bool {
    let mut i = 0usize;
    while i < fmt.len() {
        let b = fmt[i];
        if b == b'\\' && i + 1 < fmt.len() {
            let escaped = match fmt[i + 1] {
                b'n' => b'\n',
                b't' => b'\t',
                b'r' => b'\r',
                b'\\' => b'\\',
                b'0' => 0,
                b'a' => 0x07,
                b'b' => 0x08,
                b'f' => 0x0c,
                b'v' => 0x0b,
                c => c,
            };
            let _ = write_all(1, &[escaped]);
            i += 2;
            continue;
        }
        if b != b'%' {
            let _ = write_all(1, &[b]);
            i += 1;
            continue;
        }
        // Parse a conversion specifier.
        i += 1;
        if i >= fmt.len() {
            // Trailing `%` — emit literally per common convention.
            let _ = write_all(1, b"%");
            break;
        }
        let mut left_align = false;
        let mut zero_pad = false;
        // Flags.
        while i < fmt.len() {
            match fmt[i] {
                b'-' => {
                    left_align = true;
                    i += 1;
                }
                b'0' => {
                    zero_pad = true;
                    i += 1;
                }
                b'+' | b' ' | b'#' => i += 1, // accepted, no-op for our subset
                _ => break,
            }
        }
        // Width.
        let mut width: usize = 0;
        while i < fmt.len() && fmt[i].is_ascii_digit() {
            width = width * 10 + (fmt[i] - b'0') as usize;
            i += 1;
        }
        // Precision.
        let mut precision: Option<usize> = None;
        if i < fmt.len() && fmt[i] == b'.' {
            i += 1;
            let mut p: usize = 0;
            while i < fmt.len() && fmt[i].is_ascii_digit() {
                p = p * 10 + (fmt[i] - b'0') as usize;
                i += 1;
            }
            precision = Some(p);
        }
        if i >= fmt.len() {
            *had_error = true;
            write_err(b"printf: incomplete conversion\n");
            return false;
        }
        let conv = fmt[i];
        i += 1;

        if conv == b'%' {
            let _ = write_all(1, b"%");
            continue;
        }

        // Pull next arg if needed.
        let arg_bytes = if *arg_idx < argc {
            // SAFETY: arg_idx < argc.
            let s = unsafe { cstr_at(argv, *arg_idx) };
            *arg_idx += 1;
            s
        } else {
            b""
        };

        let mut numbuf = [0u8; 32];
        let formatted: &[u8] = match conv {
            b's' => {
                let take = match precision {
                    Some(p) => arg_bytes.len().min(p),
                    None => arg_bytes.len(),
                };
                &arg_bytes[..take]
            }
            b'c' => {
                if !arg_bytes.is_empty() {
                    numbuf[0] = arg_bytes[0];
                    &numbuf[..1]
                } else {
                    &numbuf[..0]
                }
            }
            b'd' | b'i' => {
                let v = parse_i64(arg_bytes).unwrap_or(0);
                let n = format_i64(v, &mut numbuf);
                &numbuf[..n]
            }
            b'u' => {
                let v = parse_i64(arg_bytes).unwrap_or(0);
                let u = if v < 0 { v as u64 } else { v as u64 };
                let n = format_u64_radix(u, 10, false, &mut numbuf);
                &numbuf[..n]
            }
            b'x' => {
                let v = parse_i64(arg_bytes).unwrap_or(0) as u64;
                let n = format_u64_radix(v, 16, false, &mut numbuf);
                &numbuf[..n]
            }
            b'X' => {
                let v = parse_i64(arg_bytes).unwrap_or(0) as u64;
                let n = format_u64_radix(v, 16, true, &mut numbuf);
                &numbuf[..n]
            }
            b'o' => {
                let v = parse_i64(arg_bytes).unwrap_or(0) as u64;
                let n = format_u64_radix(v, 8, false, &mut numbuf);
                &numbuf[..n]
            }
            _ => {
                *had_error = true;
                write_err(b"printf: unknown conversion\n");
                return false;
            }
        };

        // Apply width/padding.
        if formatted.len() < width {
            let pad = width - formatted.len();
            let pad_byte = if zero_pad && !left_align && matches!(conv, b'd' | b'i' | b'u' | b'x' | b'X' | b'o') {
                b'0'
            } else {
                b' '
            };
            if left_align {
                let _ = write_all(1, formatted);
                for _ in 0..pad {
                    let _ = write_all(1, &[pad_byte]);
                }
            } else {
                for _ in 0..pad {
                    let _ = write_all(1, &[pad_byte]);
                }
                let _ = write_all(1, formatted);
            }
        } else {
            let _ = write_all(1, formatted);
        }
    }
    true
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

fn format_i64(value: i64, out: &mut [u8]) -> usize {
    if value == 0 {
        out[0] = b'0';
        return 1;
    }
    let (negative, n) = if value < 0 {
        (true, value.unsigned_abs())
    } else {
        (false, value as u64)
    };
    let mut tmp = [0u8; 24];
    let mut len = 0usize;
    let mut x = n;
    while x > 0 {
        tmp[len] = b'0' + (x % 10) as u8;
        x /= 10;
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

fn format_u64_radix(value: u64, radix: u32, upper: bool, out: &mut [u8]) -> usize {
    if value == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 32];
    let mut len = 0usize;
    let mut x = value;
    while x > 0 {
        let d = (x % radix as u64) as u8;
        tmp[len] = if d < 10 {
            b'0' + d
        } else if upper {
            b'A' + (d - 10)
        } else {
            b'a' + (d - 10)
        };
        x /= radix as u64;
        len += 1;
    }
    for i in 0..len {
        out[i] = tmp[len - 1 - i];
    }
    len
}

fn write_all(fd: i32, buf: &[u8]) -> bool {
    let mut pos = 0;
    while pos < buf.len() {
        // SAFETY: buf slice is valid for buf.len() bytes.
        let n = unsafe { libc::write(fd, buf[pos..].as_ptr(), buf.len() - pos) };
        if n <= 0 {
            return false;
        }
        pos += n as usize;
    }
    true
}

fn write_err(msg: &[u8]) {
    let _ = write_all(2, msg);
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

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_err(b"printf: panic\n");
    libc::exit(1)
}
