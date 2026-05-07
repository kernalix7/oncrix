// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/cut` — extract bytes or fields from each line of input.
//!
//! Usage:
//!   cut -c LIST          # cut by character (1-indexed) — bytes since
//!                          this implementation is locale-unaware
//!   cut -f LIST [-d DELIM]  # cut by field, default delimiter TAB
//!
//! LIST is a comma-separated list of:
//!   * `N`       — the Nth byte/field
//!   * `N-M`     — bytes/fields N..=M
//!   * `N-`      — bytes/fields N..=end-of-line
//!   * `-M`      — bytes/fields 1..=M
//!
//! Reads stdin line by line and writes the selection to stdout, one
//! line per input line. Lines without the delimiter (in `-f` mode) are
//! emitted as-is, matching POSIX default (no `-s` flag implemented).
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/cut.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

/// Mode of operation derived from `-c` vs `-f`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Bytes,
    Fields,
}

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym cut_main,
    );
}

extern "C" fn cut_main(argc: usize, argv: *const *const u8) -> ! {
    let mut mode: Option<Mode> = None;
    let mut list_str: Option<&[u8]> = None;
    let mut delim: u8 = b'\t';
    let mut idx = 1usize;

    while idx < argc {
        // SAFETY: idx < argc.
        let arg = unsafe { cstr_at(argv, idx) };
        if arg == b"-c" {
            mode = Some(Mode::Bytes);
            idx += 1;
            if idx >= argc {
                fail(b"cut: -c needs LIST\n");
            }
            // SAFETY: idx < argc.
            list_str = Some(unsafe { cstr_at(argv, idx) });
            idx += 1;
            continue;
        }
        if arg == b"-f" {
            mode = Some(Mode::Fields);
            idx += 1;
            if idx >= argc {
                fail(b"cut: -f needs LIST\n");
            }
            // SAFETY: idx < argc.
            list_str = Some(unsafe { cstr_at(argv, idx) });
            idx += 1;
            continue;
        }
        if arg == b"-d" {
            idx += 1;
            if idx >= argc {
                fail(b"cut: -d needs DELIM\n");
            }
            // SAFETY: idx < argc.
            let d = unsafe { cstr_at(argv, idx) };
            if d.len() != 1 {
                fail(b"cut: delimiter must be a single byte\n");
            }
            delim = d[0];
            idx += 1;
            continue;
        }
        if arg == b"--" {
            idx += 1;
            break;
        }
        if !arg.is_empty() && arg[0] == b'-' && arg != b"-" {
            fail(b"cut: unknown option\n");
        }
        break;
    }

    let mode = match mode {
        Some(m) => m,
        None => fail(b"cut: must specify -c or -f\n"),
    };
    let list_str = match list_str {
        Some(s) => s,
        None => fail(b"cut: missing LIST\n"),
    };

    // Parse LIST into a sorted, deduplicated set of (start, end) ranges
    // in 1-indexed inclusive form. usize::MAX represents "to end".
    let mut ranges = [(0usize, 0usize); 32];
    let mut nranges = 0usize;
    if !parse_list(list_str, &mut ranges, &mut nranges) {
        fail(b"cut: invalid LIST\n");
    }

    // Read stdin and process line by line. We accumulate into a
    // 4 KiB line buffer; lines longer than that are flushed in
    // chunks (which still gives correct byte-mode output).
    let mut linebuf = [0u8; 4096];
    let mut linelen = 0usize;
    let mut readbuf = [0u8; 4096];

    loop {
        // SAFETY: readbuf is owned and writable.
        let n = unsafe { libc::read(0, readbuf.as_mut_ptr(), readbuf.len()) };
        if n <= 0 {
            break;
        }
        for &b in &readbuf[..n as usize] {
            if b == b'\n' {
                process_line(&linebuf[..linelen], mode, delim, &ranges[..nranges]);
                linelen = 0;
            } else if linelen < linebuf.len() {
                linebuf[linelen] = b;
                linelen += 1;
            } else {
                // Truncate quietly; further bytes of this line drop until \n.
            }
        }
    }
    if linelen > 0 {
        process_line(&linebuf[..linelen], mode, delim, &ranges[..nranges]);
    }
    libc::exit(0)
}

fn process_line(line: &[u8], mode: Mode, delim: u8, ranges: &[(usize, usize)]) {
    let mut out = [0u8; 4096];
    let mut out_len = 0usize;
    match mode {
        Mode::Bytes => {
            let mut chosen = [false; 4096];
            for &(s, e) in ranges {
                let end = if e == usize::MAX { line.len() } else { e };
                let lo = s.saturating_sub(1);
                let hi = end.min(line.len());
                if lo < hi {
                    for c in chosen.iter_mut().take(hi).skip(lo) {
                        *c = true;
                    }
                }
            }
            for (i, &b) in line.iter().enumerate() {
                if i < chosen.len() && chosen[i] && out_len < out.len() {
                    out[out_len] = b;
                    out_len += 1;
                }
            }
        }
        Mode::Fields => {
            // If the line has no delimiter, POSIX default emits it whole.
            if !line.contains(&delim) {
                let n = line.len().min(out.len());
                out[..n].copy_from_slice(&line[..n]);
                out_len = n;
            } else {
                let mut field_idx = 1usize;
                let mut field_start = 0usize;
                let mut emitted = false;
                for (i, &b) in line.iter().enumerate() {
                    if b == delim {
                        let field = &line[field_start..i];
                        if field_in_ranges(field_idx, ranges) {
                            if emitted && out_len < out.len() {
                                out[out_len] = delim;
                                out_len += 1;
                            }
                            let n = field.len().min(out.len() - out_len);
                            out[out_len..out_len + n].copy_from_slice(&field[..n]);
                            out_len += n;
                            emitted = true;
                        }
                        field_idx += 1;
                        field_start = i + 1;
                    }
                }
                // Last field.
                let field = &line[field_start..];
                if field_in_ranges(field_idx, ranges) {
                    if emitted && out_len < out.len() {
                        out[out_len] = delim;
                        out_len += 1;
                    }
                    let n = field.len().min(out.len() - out_len);
                    out[out_len..out_len + n].copy_from_slice(&field[..n]);
                    out_len += n;
                }
            }
        }
    }
    let _ = write_all(1, &out[..out_len]);
    let _ = write_all(1, b"\n");
}

fn field_in_ranges(idx: usize, ranges: &[(usize, usize)]) -> bool {
    for &(s, e) in ranges {
        let end = if e == usize::MAX { usize::MAX } else { e };
        if idx >= s && idx <= end {
            return true;
        }
    }
    false
}

fn parse_list(s: &[u8], out: &mut [(usize, usize)], n: &mut usize) -> bool {
    let mut len = 0usize;
    let mut i = 0usize;
    while i < s.len() {
        // Skip leading commas.
        while i < s.len() && s[i] == b',' {
            i += 1;
        }
        if i >= s.len() {
            break;
        }
        let item_start = i;
        while i < s.len() && s[i] != b',' {
            i += 1;
        }
        let item = &s[item_start..i];
        if item.is_empty() {
            continue;
        }
        let (start, end) = match parse_range(item) {
            Some(r) => r,
            None => return false,
        };
        if len >= out.len() {
            return false;
        }
        out[len] = (start, end);
        len += 1;
    }
    *n = len;
    len > 0
}

fn parse_range(item: &[u8]) -> Option<(usize, usize)> {
    let dash = item.iter().position(|&b| b == b'-');
    match dash {
        None => {
            let v = parse_usize(item)?;
            Some((v, v))
        }
        Some(0) => {
            // `-M`
            let v = parse_usize(&item[1..])?;
            Some((1, v))
        }
        Some(p) if p == item.len() - 1 => {
            // `N-`
            let v = parse_usize(&item[..p])?;
            Some((v, usize::MAX))
        }
        Some(p) => {
            let lo = parse_usize(&item[..p])?;
            let hi = parse_usize(&item[p + 1..])?;
            if lo > hi {
                return None;
            }
            Some((lo, hi))
        }
    }
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
    let _ = write_all(2, b"cut: panic\n");
    libc::exit(1)
}
