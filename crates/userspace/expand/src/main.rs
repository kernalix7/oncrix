// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/expand` — convert tabs to spaces.
//!
//! Usage:
//!   expand [-i] [-t TABLIST] [FILE...]
//!
//! Reads each FILE in sequence (stdin if none, or for `-`) and writes its
//! contents to stdout with TAB characters expanded to the appropriate
//! number of spaces.
//!
//! Flags (POSIX subset):
//!
//! * `-t TABLIST`  Either a single positive integer (uniform tab stops every
//!   N columns, default 8) or a comma-separated ascending list of column
//!   positions (e.g. `4,8,12`). After the final explicit stop, TABs become
//!   a single space.
//! * `-i`          (initial) Only expand TABs that occur in the leading
//!   whitespace of each line; once a non-blank byte is seen, subsequent
//!   TABs are emitted verbatim.
//!
//! Up to 16 file arguments are accepted. I/O uses a 4 KiB read chunk and
//! streams byte-by-byte, tracking column state.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/expand.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const READ_CHUNK: usize = 4096;
const MAX_FILES: usize = 16;
const MAX_TAB_STOPS: usize = 64;
const DEFAULT_TAB: usize = 8;

/// Tab stop configuration.
///
/// When `len == 0`, tab stops are uniform every `uniform` columns. Otherwise
/// `stops[..len]` is a strictly ascending list of explicit column positions
/// and `uniform` is unused; past the last stop, a TAB becomes one space.
#[derive(Clone, Copy)]
struct Tabs {
    uniform: usize,
    stops: [usize; MAX_TAB_STOPS],
    len: usize,
}

impl Tabs {
    const fn uniform(n: usize) -> Self {
        Self {
            uniform: n,
            stops: [0; MAX_TAB_STOPS],
            len: 0,
        }
    }
}

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym expand_main,
    );
}

extern "C" fn expand_main(argc: usize, argv: *const *const u8) -> ! {
    let mut tabs = Tabs::uniform(DEFAULT_TAB);
    let mut initial_only = false;
    let mut files: [&[u8]; MAX_FILES] = [&[]; MAX_FILES];
    let mut nfiles = 0usize;
    let mut idx = 1usize;

    while idx < argc {
        // SAFETY: idx < argc.
        let arg = unsafe { cstr_at(argv, idx) };
        if arg == b"-i" {
            initial_only = true;
        } else if arg == b"-t" {
            idx += 1;
            if idx >= argc {
                fail(b"expand: -t needs TABLIST\n");
            }
            // SAFETY: idx < argc.
            let s = unsafe { cstr_at(argv, idx) };
            tabs = match parse_tablist(s) {
                Some(t) => t,
                None => fail(b"expand: invalid tab list\n"),
            };
        } else if let Some(rest) = strip_prefix(arg, b"-t") {
            // Allow `-tN` / `-tLIST` (no space) for ergonomic POSIX usage.
            tabs = match parse_tablist(rest) {
                Some(t) => t,
                None => fail(b"expand: invalid tab list\n"),
            };
        } else if arg == b"--" {
            idx += 1;
            while idx < argc && nfiles < MAX_FILES {
                // SAFETY: idx < argc.
                files[nfiles] = unsafe { cstr_at(argv, idx) };
                nfiles += 1;
                idx += 1;
            }
            break;
        } else if !arg.is_empty() && arg[0] == b'-' && arg != b"-" {
            fail(b"expand: unknown option\n");
        } else {
            if nfiles >= MAX_FILES {
                fail(b"expand: too many file arguments\n");
            }
            files[nfiles] = arg;
            nfiles += 1;
        }
        idx += 1;
    }

    if nfiles == 0 {
        process_fd(0, &tabs, initial_only);
    } else {
        for f in files.iter().take(nfiles) {
            let fd = if *f == b"-" || f.is_empty() {
                0
            } else {
                let mut buf = [0u8; 256];
                let n = f.len().min(buf.len() - 1);
                buf[..n].copy_from_slice(&f[..n]);
                // SAFETY: buf is NUL-terminated within its length.
                let r = unsafe { libc::open(buf.as_ptr(), libc::O_RDONLY, 0) };
                if r < 0 {
                    fail(b"expand: cannot open file\n");
                }
                r as i32
            };
            process_fd(fd, &tabs, initial_only);
            if fd > 0 {
                let _ = libc::close(fd);
            }
        }
    }

    libc::exit(0)
}

/// Stream `fd` to stdout, expanding TABs per `tabs` and respecting `-i`.
fn process_fd(fd: i32, tabs: &Tabs, initial_only: bool) {
    let mut readbuf = [0u8; READ_CHUNK];
    let mut col: usize = 0;
    let mut leading = true;
    loop {
        // SAFETY: readbuf is owned and writable.
        let n = unsafe { libc::read(fd, readbuf.as_mut_ptr(), readbuf.len()) };
        if n <= 0 {
            break;
        }
        let slice = &readbuf[..n as usize];
        for &b in slice {
            match b {
                b'\n' => {
                    let _ = write_all(1, b"\n");
                    col = 0;
                    leading = true;
                }
                b'\t' => {
                    if initial_only && !leading {
                        // Pass TAB through verbatim; advance column to next
                        // 8-col stop so subsequent column tracking stays sane.
                        let _ = write_all(1, b"\t");
                        col = (col / DEFAULT_TAB + 1) * DEFAULT_TAB;
                    } else {
                        let next = next_stop(col, tabs);
                        let spaces = next - col;
                        emit_spaces(spaces);
                        col = next;
                    }
                }
                b'\x08' => {
                    // Backspace: emit and decrement column (saturating).
                    let _ = write_all(1, &[b]);
                    col = col.saturating_sub(1);
                    leading = false;
                }
                _ => {
                    let _ = write_all(1, &[b]);
                    col += 1;
                    if b != b' ' {
                        leading = false;
                    }
                }
            }
        }
    }
}

/// Compute the next column position when expanding a TAB at `col`.
fn next_stop(col: usize, tabs: &Tabs) -> usize {
    if tabs.len == 0 {
        // Uniform stops: always advance at least one column.
        return (col / tabs.uniform + 1) * tabs.uniform;
    }
    for &s in &tabs.stops[..tabs.len] {
        if s > col {
            return s;
        }
    }
    // Past the last explicit stop — a TAB becomes a single space.
    col + 1
}

/// Emit `count` space characters to stdout.
fn emit_spaces(count: usize) {
    const PAD: &[u8; 64] = &[b' '; 64];
    let mut remaining = count;
    while remaining > 0 {
        let chunk = remaining.min(PAD.len());
        let _ = write_all(1, &PAD[..chunk]);
        remaining -= chunk;
    }
}

/// Parse `-t` argument: either a single positive integer (uniform tab stops)
/// or a comma-separated ascending list of column positions.
fn parse_tablist(bytes: &[u8]) -> Option<Tabs> {
    if bytes.is_empty() {
        return None;
    }
    if !bytes.contains(&b',') {
        let n = parse_usize(bytes)?;
        if n == 0 {
            return None;
        }
        return Some(Tabs::uniform(n));
    }
    let mut stops = [0usize; MAX_TAB_STOPS];
    let mut len = 0usize;
    let mut last: usize = 0;
    for chunk in bytes.split(|&b| b == b',') {
        if chunk.is_empty() {
            return None;
        }
        let v = parse_usize(chunk)?;
        if v == 0 || v <= last {
            // POSIX requires strictly ascending positive integers.
            return None;
        }
        if len >= MAX_TAB_STOPS {
            return None;
        }
        stops[len] = v;
        len += 1;
        last = v;
    }
    if len == 0 {
        return None;
    }
    Some(Tabs {
        uniform: 0,
        stops,
        len,
    })
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

fn strip_prefix<'a>(bytes: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if bytes.len() > prefix.len() && &bytes[..prefix.len()] == prefix {
        Some(&bytes[prefix.len()..])
    } else {
        None
    }
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

/// Borrow the NUL-terminated argv entry at `idx` as a byte slice.
///
/// # Safety
/// Caller guarantees `idx < argc` and `argv` is a valid argv pointer.
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
    let _ = write_all(2, b"expand: panic\n");
    libc::exit(1)
}
