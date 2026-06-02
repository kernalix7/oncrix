// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/nl` — number lines of file or stdin.
//!
//! Usage:
//!   nl [-b STYLE] [-w WIDTH] [-s SEP] [-i INCREMENT] [-v START] [FILE]
//!
//! Numbers each input line and writes the result to stdout. Supported
//! flags (POSIX subset):
//!
//! * `-b STYLE`  number style: `a` (all lines), `t` (only non-empty,
//!               default), `n` (no numbers — line passed through
//!               unchanged).
//! * `-w WIDTH`  field width for the line number, right-justified
//!               with spaces (default 6).
//! * `-s SEP`    separator between number and text (default TAB).
//! * `-i INC`    increment per numbered line (default 1).
//! * `-v START`  starting line number (default 1).
//!
//! Reads stdin when no FILE argument; reads `FILE` (one only) otherwise.
//! `-` as FILE reads stdin.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/nl.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const LINE_MAX: usize = 8192;
const READ_CHUNK: usize = 4096;
const SEP_MAX: usize = 8;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Style {
    All,    // -ba
    NonEmpty, // -bt (default)
    None,   // -bn
}

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym nl_main,
    );
}

extern "C" fn nl_main(argc: usize, argv: *const *const u8) -> ! {
    let mut style = Style::NonEmpty;
    let mut width = 6usize;
    let mut sep_buf = [0u8; SEP_MAX];
    sep_buf[0] = b'\t';
    let mut sep_len = 1usize;
    let mut increment: i64 = 1;
    let mut current: i64 = 1;
    let mut idx = 1usize;

    while idx < argc {
        // SAFETY: idx < argc.
        let arg = unsafe { cstr_at(argv, idx) };
        if arg == b"-b" {
            idx += 1;
            if idx >= argc {
                fail(b"nl: -b needs STYLE\n");
            }
            // SAFETY: idx < argc.
            let s = unsafe { cstr_at(argv, idx) };
            style = match s {
                b"a" => Style::All,
                b"t" => Style::NonEmpty,
                b"n" => Style::None,
                _ => fail(b"nl: unsupported -b STYLE\n"),
            };
        } else if arg == b"-w" {
            idx += 1;
            if idx >= argc {
                fail(b"nl: -w needs WIDTH\n");
            }
            // SAFETY: idx < argc.
            let s = unsafe { cstr_at(argv, idx) };
            width = match parse_usize(s) {
                Some(v) => v.max(1).min(64),
                None => fail(b"nl: invalid WIDTH\n"),
            };
        } else if arg == b"-s" {
            idx += 1;
            if idx >= argc {
                fail(b"nl: -s needs SEP\n");
            }
            // SAFETY: idx < argc.
            let s = unsafe { cstr_at(argv, idx) };
            let n = s.len().min(SEP_MAX);
            sep_buf[..n].copy_from_slice(&s[..n]);
            sep_len = n;
        } else if arg == b"-i" {
            idx += 1;
            if idx >= argc {
                fail(b"nl: -i needs INCREMENT\n");
            }
            // SAFETY: idx < argc.
            let s = unsafe { cstr_at(argv, idx) };
            increment = match parse_i64(s) {
                Some(v) if v != 0 => v,
                _ => fail(b"nl: invalid INCREMENT\n"),
            };
        } else if arg == b"-v" {
            idx += 1;
            if idx >= argc {
                fail(b"nl: -v needs START\n");
            }
            // SAFETY: idx < argc.
            let s = unsafe { cstr_at(argv, idx) };
            current = match parse_i64(s) {
                Some(v) => v,
                None => fail(b"nl: invalid START\n"),
            };
        } else if arg == b"--" {
            idx += 1;
            break;
        } else if !arg.is_empty() && arg[0] == b'-' && arg != b"-" {
            fail(b"nl: unknown option\n");
        } else {
            break;
        }
        idx += 1;
    }

    let fd: i32 = if idx >= argc {
        0
    } else {
        // SAFETY: idx < argc.
        let path = unsafe { cstr_at(argv, idx) };
        if path == b"-" {
            0
        } else {
            let mut buf = [0u8; 256];
            let n = path.len().min(buf.len() - 1);
            buf[..n].copy_from_slice(&path[..n]);
            // SAFETY: buf is NUL-terminated.
            let r = unsafe { libc::open(buf.as_ptr(), libc::O_RDONLY, 0) };
            if r < 0 {
                fail(b"nl: cannot open file\n");
            }
            r as i32
        }
    };

    let mut linebuf = [0u8; LINE_MAX];
    let mut linelen = 0usize;
    let mut readbuf = [0u8; READ_CHUNK];

    loop {
        // SAFETY: readbuf is owned and writable.
        let n = unsafe { libc::read(fd, readbuf.as_mut_ptr(), readbuf.len()) };
        if n <= 0 {
            break;
        }
        for &b in &readbuf[..n as usize] {
            if b == b'\n' {
                emit_line(
                    &linebuf[..linelen],
                    style,
                    width,
                    &sep_buf[..sep_len],
                    &mut current,
                    increment,
                );
                linelen = 0;
            } else if linelen < linebuf.len() {
                linebuf[linelen] = b;
                linelen += 1;
            }
        }
    }
    if linelen > 0 {
        emit_line(
            &linebuf[..linelen],
            style,
            width,
            &sep_buf[..sep_len],
            &mut current,
            increment,
        );
    }

    if fd > 0 {
        let _ = libc::close(fd);
    }
    libc::exit(0)
}

fn emit_line(
    line: &[u8],
    style: Style,
    width: usize,
    sep: &[u8],
    current: &mut i64,
    increment: i64,
) {
    let numbered = match style {
        Style::All => true,
        Style::NonEmpty => !line.is_empty(),
        Style::None => false,
    };
    if numbered {
        let mut numbuf = [0u8; 32];
        let n = format_i64(*current, &mut numbuf);
        // Right-pad with spaces to `width`.
        if n < width {
            for _ in 0..(width - n) {
                let _ = write_all(1, b" ");
            }
        }
        let _ = write_all(1, &numbuf[..n]);
        let _ = write_all(1, sep);
        *current = current.saturating_add(increment);
    } else {
        // Unnumbered: just leave width spaces of padding (POSIX says
        // unnumbered lines retain the same indentation as numbered ones)
        // followed by the separator.
        for _ in 0..width {
            let _ = write_all(1, b" ");
        }
        let _ = write_all(1, sep);
    }
    let _ = write_all(1, line);
    let _ = write_all(1, b"\n");
}

fn parse_usize(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }
    let mut acc: usize = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((b - b'0') as usize)?;
    }
    Some(acc)
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
    let (negative, mut n) = if value < 0 {
        (true, value.unsigned_abs())
    } else {
        (false, value as u64)
    };
    let mut tmp = [0u8; 24];
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

fn fail(msg: &[u8]) -> ! {
    let _ = write_all(2, msg);
    libc::exit(1)
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
    let _ = write_all(2, b"nl: panic\n");
    libc::exit(1)
}
