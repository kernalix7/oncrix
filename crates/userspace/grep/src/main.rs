// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/grep` — fixed-string substring matcher.
//!
//! Usage:
//!   grep [-i] [-v] [-n] [-c] [-q] PATTERN [FILE ...]
//!
//! Implementation note: this is the fixed-string subset of grep
//! (POSIX `grep -F` semantics). Regular-expression support is
//! deferred — pulling in a regex engine would dwarf the rest of the
//! utility, and most shell scripts that drive grep look for literal
//! substrings anyway. Patterns are matched against each line; with no
//! file arguments stdin is searched.
//!
//! Flags:
//!   -i   case-insensitive match (ASCII only)
//!   -v   invert: select non-matching lines
//!   -n   prefix matching lines with `LINENO:` (relative to the file)
//!   -c   suppress matched-line output, print only the count
//!   -q   quiet: emit nothing, exit 0 on match / 1 on no match
//!
//! Exit status: 0 if any line matched, 1 if none matched, 2 on error.
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/grep.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const LINE_MAX: usize = 4096;
const PATTERN_MAX: usize = 1024;
const MAX_FILES: usize = 16;

#[derive(Clone, Copy, Default)]
struct Flags {
    ignore_case: bool,
    invert: bool,
    line_no: bool,
    count_only: bool,
    quiet: bool,
}

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym grep_main,
    );
}

extern "C" fn grep_main(argc: usize, argv: *const *const u8) -> ! {
    let mut flags = Flags::default();
    let mut idx = 1usize;

    while idx < argc {
        // SAFETY: idx < argc.
        let arg = unsafe { cstr_at(argv, idx) };
        if arg == b"-i" {
            flags.ignore_case = true;
        } else if arg == b"-v" {
            flags.invert = true;
        } else if arg == b"-n" {
            flags.line_no = true;
        } else if arg == b"-c" {
            flags.count_only = true;
        } else if arg == b"-q" {
            flags.quiet = true;
        } else if arg == b"--" {
            idx += 1;
            break;
        } else if !arg.is_empty() && arg[0] == b'-' && arg != b"-" {
            // POSIX permits combined short flags like -in but we keep
            // it simple — only recognised single-letter flags above.
            write_err(b"grep: unknown option\n");
            libc::exit(2);
        } else {
            break;
        }
        idx += 1;
    }

    if idx >= argc {
        write_err(b"grep: missing PATTERN\n");
        libc::exit(2);
    }
    // SAFETY: idx < argc.
    let pat_bytes = unsafe { cstr_at(argv, idx) };
    if pat_bytes.len() > PATTERN_MAX {
        write_err(b"grep: pattern too long\n");
        libc::exit(2);
    }
    let mut pattern = [0u8; PATTERN_MAX];
    let plen = pat_bytes.len();
    pattern[..plen].copy_from_slice(pat_bytes);
    if flags.ignore_case {
        for byte in pattern[..plen].iter_mut() {
            *byte = byte.to_ascii_lowercase();
        }
    }
    idx += 1;

    let mut files: [*const u8; MAX_FILES] = [core::ptr::null(); MAX_FILES];
    let mut nfiles = 0usize;
    while idx < argc && nfiles < MAX_FILES {
        // SAFETY: idx < argc.
        let p = unsafe { *argv.add(idx) };
        files[nfiles] = p;
        nfiles += 1;
        idx += 1;
    }

    let any_match = if nfiles == 0 {
        // Read stdin.
        scan_fd(0, &pattern[..plen], &flags, nfiles > 1, b"")
    } else {
        let mut any = false;
        for i in 0..nfiles {
            let p = files[i];
            if p.is_null() {
                continue;
            }
            // SAFETY: p is a NUL-terminated argv string.
            let path = unsafe { cstr_from_ptr(p) };
            if path == b"-" {
                if scan_fd(0, &pattern[..plen], &flags, nfiles > 1, b"(standard input)") {
                    any = true;
                }
                continue;
            }
            // Copy to a NUL-terminated buffer for libc::open.
            let mut path_buf = [0u8; 256];
            let n = path.len().min(path_buf.len() - 1);
            path_buf[..n].copy_from_slice(&path[..n]);
            // SAFETY: path_buf is NUL-terminated.
            let fd = unsafe { libc::open(path_buf.as_ptr(), libc::O_RDONLY, 0) };
            if fd < 0 {
                write_err(b"grep: cannot open file\n");
                continue;
            }
            if scan_fd(fd as i32, &pattern[..plen], &flags, nfiles > 1, path) {
                any = true;
            }
            let _ = libc::close(fd as i32);
        }
        any
    };

    libc::exit(if any_match { 0 } else { 1 })
}

fn scan_fd(fd: i32, pattern: &[u8], flags: &Flags, multi_file: bool, path: &[u8]) -> bool {
    let mut linebuf = [0u8; LINE_MAX];
    let mut linelen = 0usize;
    let mut overflow = false;
    let mut readbuf = [0u8; 4096];
    let mut lineno: u64 = 0;
    let mut match_count: u64 = 0;
    let mut any = false;

    loop {
        // SAFETY: readbuf is owned and writable.
        let n = unsafe { libc::read(fd, readbuf.as_mut_ptr(), readbuf.len()) };
        if n <= 0 {
            break;
        }
        for &b in &readbuf[..n as usize] {
            if b == b'\n' {
                lineno += 1;
                if !overflow
                    && line_matches(&linebuf[..linelen], pattern, flags) != flags.invert
                {
                    any = true;
                    match_count += 1;
                    if !flags.quiet && !flags.count_only {
                        emit_match(&linebuf[..linelen], lineno, flags, multi_file, path);
                    }
                    if flags.quiet {
                        return true;
                    }
                }
                linelen = 0;
                overflow = false;
            } else if linelen < linebuf.len() {
                linebuf[linelen] = b;
                linelen += 1;
            } else {
                overflow = true;
            }
        }
    }
    // Trailing line without newline.
    if linelen > 0 && !overflow {
        lineno += 1;
        if line_matches(&linebuf[..linelen], pattern, flags) != flags.invert {
            any = true;
            match_count += 1;
            if !flags.quiet && !flags.count_only {
                emit_match(&linebuf[..linelen], lineno, flags, multi_file, path);
            }
        }
    }

    if flags.count_only && !flags.quiet {
        if multi_file && !path.is_empty() {
            let _ = write_all(1, path);
            let _ = write_all(1, b":");
        }
        let mut buf = [0u8; 24];
        let n = format_u64(match_count, &mut buf);
        let _ = write_all(1, &buf[..n]);
        let _ = write_all(1, b"\n");
    }

    any
}

fn emit_match(line: &[u8], lineno: u64, flags: &Flags, multi_file: bool, path: &[u8]) {
    if multi_file && !path.is_empty() {
        let _ = write_all(1, path);
        let _ = write_all(1, b":");
    }
    if flags.line_no {
        let mut buf = [0u8; 24];
        let n = format_u64(lineno, &mut buf);
        let _ = write_all(1, &buf[..n]);
        let _ = write_all(1, b":");
    }
    let _ = write_all(1, line);
    let _ = write_all(1, b"\n");
}

fn line_matches(line: &[u8], pattern: &[u8], flags: &Flags) -> bool {
    if pattern.is_empty() {
        return true;
    }
    if flags.ignore_case {
        // Compare each candidate window against the lowercased pattern.
        if pattern.len() > line.len() {
            return false;
        }
        let max = line.len() - pattern.len();
        for start in 0..=max {
            let mut equal = true;
            for j in 0..pattern.len() {
                if line[start + j].to_ascii_lowercase() != pattern[j] {
                    equal = false;
                    break;
                }
            }
            if equal {
                return true;
            }
        }
        false
    } else {
        // Case-sensitive substring search via std slice helpers.
        line.windows(pattern.len()).any(|w| w == pattern)
    }
}

fn format_u64(value: u64, out: &mut [u8]) -> usize {
    if value == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 24];
    let mut n = value;
    let mut len = 0usize;
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
        cstr_from_ptr(p)
    }
}

/// SAFETY: caller guarantees `p` points to a NUL-terminated C string.
unsafe fn cstr_from_ptr(p: *const u8) -> &'static [u8] {
    unsafe {
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
    write_err(b"grep: panic\n");
    libc::exit(2)
}
