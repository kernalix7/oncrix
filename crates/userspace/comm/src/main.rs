// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/comm` — compare two sorted files line by line.
//!
//! Usage:
//!   comm [-1] [-2] [-3] FILE1 FILE2
//!
//! Reads two pre-sorted line streams and emits three columns:
//!   col 1 — lines only in FILE1 (no leading tab)
//!   col 2 — lines only in FILE2 (one leading tab)
//!   col 3 — lines common to both (two leading tabs)
//!
//! Flags suppress the corresponding column:
//!   -1   omit col 1
//!   -2   omit col 2
//!   -3   omit col 3
//!
//! Either FILE may be `-` to read stdin (only one of the two may
//! be `-`, since stdin is a single stream).
//!
//! Implementation note: like POSIX comm, both inputs MUST be sorted
//! by byte order; misordered inputs produce undefined output. The
//! algorithm is a streaming two-pointer merge — no buffering of full
//! files, just one pending line per side.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/comm.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const LINE_MAX: usize = 4096;
const READ_CHUNK: usize = 4096;

/// Streaming line reader bound to a single fd.
///
/// Buffers raw input in `chunk`, accumulates a line in `line` until
/// `\n` or EOF, then exposes the assembled line via [`Self::current`].
struct LineReader {
    fd: i32,
    chunk: [u8; READ_CHUNK],
    chunk_len: usize,
    chunk_pos: usize,
    line: [u8; LINE_MAX],
    line_len: usize,
    eof: bool,
    have_line: bool,
}

impl LineReader {
    fn new(fd: i32) -> Self {
        Self {
            fd,
            chunk: [0u8; READ_CHUNK],
            chunk_len: 0,
            chunk_pos: 0,
            line: [0u8; LINE_MAX],
            line_len: 0,
            eof: false,
            have_line: false,
        }
    }

    /// Pull the next byte from the input stream, refilling as needed.
    /// Returns `None` at EOF.
    fn next_byte(&mut self) -> Option<u8> {
        if self.chunk_pos >= self.chunk_len {
            if self.eof {
                return None;
            }
            // SAFETY: chunk is owned and writable.
            let n = unsafe { libc::read(self.fd, self.chunk.as_mut_ptr(), self.chunk.len()) };
            if n <= 0 {
                self.eof = true;
                return None;
            }
            self.chunk_len = n as usize;
            self.chunk_pos = 0;
        }
        let b = self.chunk[self.chunk_pos];
        self.chunk_pos += 1;
        Some(b)
    }

    /// Assemble the next line (without trailing `\n`) into `self.line`.
    /// Sets `have_line = true` when one is available, `false` at final EOF.
    fn advance(&mut self) {
        self.line_len = 0;
        loop {
            match self.next_byte() {
                Some(b'\n') => {
                    self.have_line = true;
                    return;
                }
                Some(b) => {
                    if self.line_len < self.line.len() {
                        self.line[self.line_len] = b;
                        self.line_len += 1;
                    }
                    // Beyond LINE_MAX we drop bytes silently to stay within
                    // the static buffer; the line still terminates at the
                    // next `\n` or EOF.
                }
                None => {
                    // EOF — emit any partial trailing line, then stop.
                    self.have_line = self.line_len > 0;
                    self.eof = true;
                    return;
                }
            }
        }
    }

    fn current(&self) -> &[u8] {
        &self.line[..self.line_len]
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
        main = sym comm_main,
    );
}

extern "C" fn comm_main(argc: usize, argv: *const *const u8) -> ! {
    let mut suppress = [false; 3]; // [col1, col2, col3]
    let mut idx = 1usize;

    while idx < argc {
        // SAFETY: idx < argc.
        let arg = unsafe { cstr_at(argv, idx) };
        if arg == b"-1" {
            suppress[0] = true;
        } else if arg == b"-2" {
            suppress[1] = true;
        } else if arg == b"-3" {
            suppress[2] = true;
        } else if arg == b"--" {
            idx += 1;
            break;
        } else if !arg.is_empty() && arg[0] == b'-' && arg != b"-" {
            write_err(b"comm: unknown option\n");
            libc::exit(1);
        } else {
            break;
        }
        idx += 1;
    }

    if argc - idx != 2 {
        write_err(b"comm: usage: comm [-1] [-2] [-3] FILE1 FILE2\n");
        libc::exit(1);
    }

    // SAFETY: argv[idx] valid for both cases below.
    let path1 = unsafe { cstr_at(argv, idx) };
    let path2 = unsafe { cstr_at(argv, idx + 1) };

    let fd1 = open_or_stdin(path1);
    let fd2 = open_or_stdin(path2);
    if fd1 < 0 || fd2 < 0 {
        write_err(b"comm: cannot open file\n");
        libc::exit(1);
    }

    let mut a = LineReader::new(fd1);
    let mut b = LineReader::new(fd2);
    a.advance();
    b.advance();

    while a.have_line || b.have_line {
        if a.have_line && b.have_line {
            match cmp_bytes(a.current(), b.current()) {
                core::cmp::Ordering::Less => {
                    emit(0, a.current(), &suppress);
                    a.advance();
                }
                core::cmp::Ordering::Greater => {
                    emit(1, b.current(), &suppress);
                    b.advance();
                }
                core::cmp::Ordering::Equal => {
                    emit(2, a.current(), &suppress);
                    a.advance();
                    b.advance();
                }
            }
        } else if a.have_line {
            emit(0, a.current(), &suppress);
            a.advance();
        } else {
            emit(1, b.current(), &suppress);
            b.advance();
        }
    }

    if fd1 > 0 {
        let _ = libc::close(fd1);
    }
    if fd2 > 0 {
        let _ = libc::close(fd2);
    }
    libc::exit(0)
}

fn open_or_stdin(path: &[u8]) -> i32 {
    if path == b"-" {
        return 0;
    }
    let mut buf = [0u8; 256];
    let n = path.len().min(buf.len() - 1);
    buf[..n].copy_from_slice(&path[..n]);
    // SAFETY: buf is NUL-terminated by construction.
    unsafe { libc::open(buf.as_ptr(), libc::O_RDONLY, 0) as i32 }
}

fn emit(col: usize, line: &[u8], suppress: &[bool; 3]) {
    if suppress[col] {
        return;
    }
    // Compute leading tab count after suppression: a column's effective
    // position is its index minus the count of suppressed columns to its
    // left.
    let mut leading_tabs = 0usize;
    for i in 0..col {
        if !suppress[i] {
            leading_tabs += 1;
        }
    }
    for _ in 0..leading_tabs {
        let _ = write_all(1, b"\t");
    }
    let _ = write_all(1, line);
    let _ = write_all(1, b"\n");
}

fn cmp_bytes(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    let n = a.len().min(b.len());
    for i in 0..n {
        match a[i].cmp(&b[i]) {
            core::cmp::Ordering::Equal => continue,
            ord => return ord,
        }
    }
    a.len().cmp(&b.len())
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
    write_err(b"comm: panic\n");
    libc::exit(1)
}
