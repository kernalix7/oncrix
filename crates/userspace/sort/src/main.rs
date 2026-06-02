// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/sort` — sort lines of stdin.
//!
//! Usage:
//!   sort [-r] [-n] [-u]
//!
//! Reads all of stdin into a fixed-size buffer, slices it into lines,
//! sorts the slices, then writes them back to stdout in order. POSIX
//! flags supported:
//!   -r   reverse the comparison (descending)
//!   -n   compare leading optional-sign decimal integers numerically
//!   -u   suppress duplicate lines after sorting (adjacent equals collapse)
//!
//! No heap is available; storage is bounded:
//!   - 64 KiB byte buffer for stdin (`BUF_CAP`)
//!   - 4096 line slices via `(offset, length)` (`LINE_MAX`)
//!
//! Excess input or excess lines are dropped silently and a warning is
//! emitted to stderr at exit.
//!
//! Comparison is byte-wise (ASCII / unsigned bytes); numeric mode parses a
//! signed decimal prefix, falling back to byte comparison on ties.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/sort.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

/// Maximum number of bytes of stdin retained.
const BUF_CAP: usize = 64 * 1024;

/// Maximum number of input lines tracked.
const LINE_MAX: usize = 4096;

/// Read chunk size for the stdin loop.
const READ_CHUNK: usize = 4096;

/// Slice of the input buffer representing a single line (no trailing `\n`).
#[derive(Clone, Copy)]
struct Line {
    off: u32,
    len: u32,
}

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym sort_main,
    );
}

extern "C" fn sort_main(argc: usize, argv: *const *const u8) -> ! {
    let mut reverse = false;
    let mut numeric = false;
    let mut unique = false;

    let mut idx = 1usize;
    while idx < argc {
        // SAFETY: idx < argc by loop guard.
        let arg = unsafe { cstr_at(argv, idx) };
        if arg == b"--" {
            break;
        } else if arg == b"-r" {
            reverse = true;
        } else if arg == b"-n" {
            numeric = true;
        } else if arg == b"-u" {
            unique = true;
        } else if !arg.is_empty() && arg[0] == b'-' && arg.len() > 1 {
            // Bundled short flags such as -rn, -un, -rnu.
            let mut ok = true;
            for &c in &arg[1..] {
                match c {
                    b'r' => reverse = true,
                    b'n' => numeric = true,
                    b'u' => unique = true,
                    _ => {
                        ok = false;
                        break;
                    }
                }
            }
            if !ok {
                write_err(b"sort: unknown option\n");
                libc::exit(2);
            }
        } else {
            // No file-argument support yet — sort reads stdin only.
            write_err(b"sort: file arguments not supported, reading stdin\n");
            break;
        }
        idx += 1;
    }

    let mut buf = [0u8; BUF_CAP];
    let mut buf_len = 0usize;
    let mut input_truncated = false;

    let mut readbuf = [0u8; READ_CHUNK];
    loop {
        // SAFETY: readbuf is owned and writable for its full length.
        let n = unsafe { libc::read(0, readbuf.as_mut_ptr(), readbuf.len()) };
        if n < 0 {
            write_err(b"sort: read error\n");
            libc::exit(2);
        }
        if n == 0 {
            break;
        }
        let want = n as usize;
        let space = buf.len() - buf_len;
        let take = if want <= space { want } else { space };
        if take > 0 {
            buf[buf_len..buf_len + take].copy_from_slice(&readbuf[..take]);
            buf_len += take;
        }
        if take < want {
            input_truncated = true;
            // Drain remaining stdin so callers blocked on a pipe close gracefully.
            loop {
                // SAFETY: readbuf is owned and writable.
                let m = unsafe { libc::read(0, readbuf.as_mut_ptr(), readbuf.len()) };
                if m <= 0 {
                    break;
                }
            }
            break;
        }
    }

    let mut lines = [Line { off: 0, len: 0 }; LINE_MAX];
    let mut line_count = 0usize;
    let mut lines_dropped = false;

    let mut start = 0usize;
    let mut i = 0usize;
    while i < buf_len {
        if buf[i] == b'\n' {
            if line_count < LINE_MAX {
                lines[line_count] = Line {
                    off: start as u32,
                    len: (i - start) as u32,
                };
                line_count += 1;
            } else {
                lines_dropped = true;
            }
            start = i + 1;
        }
        i += 1;
    }
    // Trailing line without newline.
    if start < buf_len {
        if line_count < LINE_MAX {
            lines[line_count] = Line {
                off: start as u32,
                len: (buf_len - start) as u32,
            };
            line_count += 1;
        } else {
            lines_dropped = true;
        }
    }

    let slice = &mut lines[..line_count];
    insertion_sort(slice, &buf, numeric, reverse);

    let mut prev: Option<Line> = None;
    for &ln in slice.iter() {
        let cur = line_bytes(ln, &buf);
        if unique
            && let Some(p) = prev
            && line_bytes(p, &buf) == cur
        {
            continue;
        }
        let _ = write_all(1, cur);
        let _ = write_all(1, b"\n");
        prev = Some(ln);
    }

    if input_truncated {
        write_err(b"sort: input exceeded 64 KiB buffer; trailing data dropped\n");
    }
    if lines_dropped {
        write_err(b"sort: line count exceeded 4096; extra lines dropped\n");
    }

    libc::exit(0)
}

fn line_bytes(ln: Line, buf: &[u8]) -> &[u8] {
    let s = ln.off as usize;
    let e = s + ln.len as usize;
    &buf[s..e]
}

/// In-place insertion sort over the line index array.
///
/// `O(n^2)` worst-case but with `LINE_MAX = 4096` this is at most a few
/// million byte comparisons — entirely adequate for shell-script inputs
/// of a few hundred lines, and trivial to keep correct in `no_std`.
fn insertion_sort(lines: &mut [Line], buf: &[u8], numeric: bool, reverse: bool) {
    let n = lines.len();
    let mut i = 1;
    while i < n {
        let cur = lines[i];
        let cur_b = line_bytes(cur, buf);
        let mut j = i;
        while j > 0 {
            let other = lines[j - 1];
            let other_b = line_bytes(other, buf);
            let ord = compare(cur_b, other_b, numeric);
            let cur_is_before = if reverse { ord > 0 } else { ord < 0 };
            if !cur_is_before {
                break;
            }
            lines[j] = lines[j - 1];
            j -= 1;
        }
        lines[j] = cur;
        i += 1;
    }
}

/// Three-way comparison returning negative / zero / positive in the style
/// of C `memcmp`. In numeric mode we compare leading signed decimal
/// integers and fall back to byte order on a tie.
fn compare(a: &[u8], b: &[u8], numeric: bool) -> i32 {
    if numeric {
        let (an, a_ok) = parse_leading_int(a);
        let (bn, b_ok) = parse_leading_int(b);
        // POSIX says lines without a number sort as 0; we mirror that.
        let av = if a_ok { an } else { 0 };
        let bv = if b_ok { bn } else { 0 };
        if av < bv {
            return -1;
        }
        if av > bv {
            return 1;
        }
    }
    cmp_bytes(a, b)
}

fn cmp_bytes(a: &[u8], b: &[u8]) -> i32 {
    let n = a.len().min(b.len());
    let mut i = 0;
    while i < n {
        if a[i] != b[i] {
            return a[i] as i32 - b[i] as i32;
        }
        i += 1;
    }
    a.len() as i32 - b.len() as i32
}

/// Parse an optional leading `-`/`+` followed by decimal digits. Returns
/// `(value, found)` — `found` is `false` if no digits were present.
fn parse_leading_int(s: &[u8]) -> (i64, bool) {
    // Skip leading ASCII spaces and tabs (POSIX leading blanks).
    let mut i = 0;
    while i < s.len() && (s[i] == b' ' || s[i] == b'\t') {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'-' || s[i] == b'+') {
        neg = s[i] == b'-';
        i += 1;
    }
    let mut have = false;
    let mut acc: i64 = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        let d = (s[i] - b'0') as i64;
        // Saturate on overflow rather than panicking.
        acc = acc.saturating_mul(10).saturating_add(d);
        have = true;
        i += 1;
    }
    let value = if neg { acc.saturating_neg() } else { acc };
    (value, have)
}

fn write_all(fd: i32, buf: &[u8]) -> bool {
    let mut pos = 0;
    while pos < buf.len() {
        // SAFETY: buf is a borrowed slice valid for buf.len() bytes.
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
    write_err(b"sort: panic\n");
    libc::exit(1)
}
