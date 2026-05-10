// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/rev` — reverse the byte order of every input line.
//!
//! Usage:
//!   rev [FILE...]
//!
//! For each input line (terminated by `\n` or end-of-file), the bytes
//! preceding the newline are written to stdout in reverse order, followed
//! by a single `\n`. With no FILE operand, stdin is processed; `-` is
//! treated as stdin. Up to 4 file operands are accepted.
//!
//! Limitations:
//! * Reversal is **byte-level only** — multibyte UTF-8 sequences are
//!   reversed as raw bytes and will not round-trip as valid text. This
//!   matches `util-linux rev` when invoked with `--no-unicode` (its
//!   behaviour prior to the `--unicode` opt-in).
//! * A line longer than [`LINE_MAX`] bytes is truncated; excess bytes
//!   are silently discarded until the next `\n`.
//!
//! `rev` is not specified by POSIX.1-2024; semantics follow util-linux.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const LINE_MAX: usize = 4096;
const READ_CHUNK: usize = 4096;
const MAX_FILES: usize = 4;
const PATH_MAX: usize = 256;

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym rev_main,
    );
}

extern "C" fn rev_main(argc: usize, argv: *const *const u8) -> ! {
    let mut idx = 1usize;

    // Parse leading options. `--` ends option processing; bare `-` is a
    // file operand (stdin), not an option. `rev` accepts no flags, so a
    // dash-prefixed token is rejected outright.
    if idx < argc {
        // SAFETY: idx < argc.
        let arg = unsafe { cstr_at(argv, idx) };
        if arg == b"--" {
            idx += 1;
        } else if !arg.is_empty() && arg[0] == b'-' && arg != b"-" {
            fail(b"rev: unknown option\n");
        }
    }

    let mut linebuf = [0u8; LINE_MAX];
    let mut readbuf = [0u8; READ_CHUNK];

    if idx >= argc {
        process_fd(0, &mut linebuf, &mut readbuf);
        libc::exit(0);
    }

    // Cap file operands at MAX_FILES so we never exceed our stack budget.
    let mut processed = 0usize;
    while idx < argc && processed < MAX_FILES {
        // SAFETY: idx < argc.
        let path = unsafe { cstr_at(argv, idx) };
        let fd = if path == b"-" {
            0
        } else {
            let mut buf = [0u8; PATH_MAX];
            let n = path.len().min(buf.len() - 1);
            buf[..n].copy_from_slice(&path[..n]);
            // SAFETY: buf is NUL-terminated (zero-initialised, n < len).
            let r = unsafe { libc::open(buf.as_ptr(), libc::O_RDONLY, 0) };
            if r < 0 {
                fail(b"rev: cannot open file\n");
            }
            r as i32
        };

        process_fd(fd, &mut linebuf, &mut readbuf);

        if fd > 0 {
            let _ = libc::close(fd);
        }
        idx += 1;
        processed += 1;
    }

    if idx < argc {
        // Too many files — silently ignore the remainder, matching the
        // documented MAX_FILES cap.
        let _ = write_all(2, b"rev: too many file operands\n");
    }

    libc::exit(0)
}

/// Read the given fd to end-of-file, emitting a reversed copy of each
/// line. Lines longer than `LINE_MAX` are truncated.
fn process_fd(fd: i32, linebuf: &mut [u8; LINE_MAX], readbuf: &mut [u8; READ_CHUNK]) {
    let mut linelen = 0usize;
    let mut overflow = false;

    loop {
        // SAFETY: readbuf is owned and writable for readbuf.len() bytes.
        let n = unsafe { libc::read(fd, readbuf.as_mut_ptr(), readbuf.len()) };
        if n <= 0 {
            break;
        }
        for &b in &readbuf[..n as usize] {
            if b == b'\n' {
                emit_reversed(&mut linebuf[..linelen]);
                linelen = 0;
                overflow = false;
            } else if !overflow && linelen < linebuf.len() {
                linebuf[linelen] = b;
                linelen += 1;
            } else {
                // Past the line buffer — drop bytes until the next '\n'.
                overflow = true;
            }
        }
    }
    // Trailing partial line (no terminating newline): emit reversed and
    // append our own '\n', mirroring util-linux behaviour.
    if linelen > 0 {
        emit_reversed(&mut linebuf[..linelen]);
    }
}

/// Reverse `line` in place (byte-level) and write it to stdout followed
/// by a single newline.
fn emit_reversed(line: &mut [u8]) {
    let mut i = 0usize;
    let mut j = line.len();
    while i + 1 < j {
        j -= 1;
        line.swap(i, j);
        i += 1;
    }
    let _ = write_all(1, line);
    let _ = write_all(1, b"\n");
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

fn fail(msg: &[u8]) -> ! {
    let _ = write_all(2, msg);
    libc::exit(1)
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
    let _ = write_all(2, b"rev: panic\n");
    libc::exit(1)
}
