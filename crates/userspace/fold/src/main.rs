// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/fold` — wrap each input line at column WIDTH.
//!
//! Usage:
//!   fold [-bs] [-w WIDTH] [FILE...]
//!
//! Reads each FILE in sequence (stdin if none, or for `-`) and writes
//! its contents to stdout, inserting a `\n` whenever a logical line
//! would exceed WIDTH columns/bytes.
//!
//! Flags (POSIX subset):
//!
//! * `-w WIDTH`  wrap column (default 80, must be > 0).
//! * `-s`        if a line must be wrapped, break at the most recent
//!               whitespace (space or TAB) boundary inside the buffered
//!               segment if one exists; otherwise hard-wrap at WIDTH.
//! * `-b`        count bytes instead of display columns. Without `-b`,
//!               TAB advances column to the next multiple of 8,
//!               BACKSPACE decrements column (saturating at 0), and
//!               CARRIAGE-RETURN resets column to 0.
//!
//! Up to 16 file arguments are accepted. Reading uses a 4 KiB chunk;
//! the per-line wrap buffer is 4 KiB.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/fold.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const READ_CHUNK: usize = 4096;
const WRAP_BUF: usize = 4096;
const MAX_FILES: usize = 16;
const TAB_WIDTH: usize = 8;
const DEFAULT_WIDTH: usize = 80;

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym fold_main,
    );
}

extern "C" fn fold_main(argc: usize, argv: *const *const u8) -> ! {
    let mut width = DEFAULT_WIDTH;
    let mut break_ws = false;
    let mut count_bytes = false;
    let mut files: [&[u8]; MAX_FILES] = [&[]; MAX_FILES];
    let mut nfiles = 0usize;

    let mut idx = 1usize;
    while idx < argc {
        // SAFETY: idx < argc.
        let arg = unsafe { cstr_at(argv, idx) };
        if arg == b"--" {
            idx += 1;
            while idx < argc && nfiles < MAX_FILES {
                // SAFETY: idx < argc.
                files[nfiles] = unsafe { cstr_at(argv, idx) };
                nfiles += 1;
                idx += 1;
            }
            break;
        } else if arg == b"-" {
            if nfiles < MAX_FILES {
                files[nfiles] = arg;
                nfiles += 1;
            }
            idx += 1;
        } else if arg == b"-w" {
            idx += 1;
            if idx >= argc {
                fail(b"fold: -w needs WIDTH\n");
            }
            // SAFETY: idx < argc.
            let s = unsafe { cstr_at(argv, idx) };
            width = match parse_usize(s) {
                Some(v) if v > 0 => v,
                _ => fail(b"fold: invalid WIDTH\n"),
            };
            idx += 1;
        } else if !arg.is_empty() && arg[0] == b'-' && arg.len() > 1 {
            // Short flag cluster: -s, -b, -sb, -bs, -w80 (numeric width).
            // POSIX historical form -<digits> is also accepted as width.
            let rest = &arg[1..];
            if rest.iter().all(|c| c.is_ascii_digit()) {
                width = match parse_usize(rest) {
                    Some(v) if v > 0 => v,
                    _ => fail(b"fold: invalid WIDTH\n"),
                };
                idx += 1;
                continue;
            }
            let mut i = 0;
            while i < rest.len() {
                match rest[i] {
                    b's' => break_ws = true,
                    b'b' => count_bytes = true,
                    b'w' => {
                        // -wN form: digits follow, or next arg.
                        let after = &rest[i + 1..];
                        if !after.is_empty() {
                            width = match parse_usize(after) {
                                Some(v) if v > 0 => v,
                                _ => fail(b"fold: invalid WIDTH\n"),
                            };
                            i = rest.len();
                        } else {
                            idx += 1;
                            if idx >= argc {
                                fail(b"fold: -w needs WIDTH\n");
                            }
                            // SAFETY: idx < argc.
                            let s = unsafe { cstr_at(argv, idx) };
                            width = match parse_usize(s) {
                                Some(v) if v > 0 => v,
                                _ => fail(b"fold: invalid WIDTH\n"),
                            };
                            i = rest.len();
                        }
                    }
                    _ => fail(b"fold: unknown option\n"),
                }
                i += 1;
            }
            idx += 1;
        } else {
            if nfiles < MAX_FILES {
                files[nfiles] = arg;
                nfiles += 1;
            }
            idx += 1;
        }
    }

    let mut state = FoldState::new(width, break_ws, count_bytes);

    if nfiles == 0 {
        process_fd(0, &mut state);
    } else {
        for f in &files[..nfiles] {
            if *f == b"-" {
                process_fd(0, &mut state);
            } else {
                let mut path = [0u8; 512];
                if f.len() >= path.len() {
                    fail(b"fold: path too long\n");
                }
                path[..f.len()].copy_from_slice(f);
                // SAFETY: path is NUL-terminated (zero-initialized tail).
                let r = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY, 0) };
                if r < 0 {
                    fail(b"fold: cannot open file\n");
                }
                let fd = r as i32;
                process_fd(fd, &mut state);
                let _ = libc::close(fd);
            }
        }
    }

    state.flush();
    libc::exit(0)
}

/// Per-stream wrap state. Buffers the current pending line segment so
/// that when WIDTH is reached we can look back for a whitespace
/// boundary (`-s` mode).
struct FoldState {
    width: usize,
    break_ws: bool,
    count_bytes: bool,
    buf: [u8; WRAP_BUF],
    len: usize,
    col: usize,
}

impl FoldState {
    fn new(width: usize, break_ws: bool, count_bytes: bool) -> Self {
        Self {
            width,
            break_ws,
            count_bytes,
            buf: [0; WRAP_BUF],
            len: 0,
            col: 0,
        }
    }

    /// Compute the column position after consuming `byte` starting from `col`.
    /// In byte-counting mode every byte advances the column by 1.
    fn next_col(&self, col: usize, byte: u8) -> usize {
        if self.count_bytes {
            return col + 1;
        }
        match byte {
            b'\t' => (col / TAB_WIDTH + 1) * TAB_WIDTH,
            0x08 => col.saturating_sub(1), // ASCII BS (backspace)
            b'\r' => 0,
            _ => col + 1,
        }
    }

    /// Append a byte that does not trigger a wrap. The caller has
    /// already verified the resulting column fits inside WIDTH.
    fn append(&mut self, byte: u8, new_col: usize) {
        if self.len == self.buf.len() {
            // Buffer full but no wrap point reached — flush as a hard
            // boundary to avoid overflow on pathological inputs.
            self.flush_buffer();
            self.col = 0;
        }
        self.buf[self.len] = byte;
        self.len += 1;
        self.col = new_col;
    }

    /// Feed one input byte, performing wraps as needed.
    fn feed(&mut self, byte: u8) {
        if byte == b'\n' {
            self.flush_buffer();
            let _ = write_all(1, b"\n");
            self.col = 0;
            return;
        }

        let new_col = self.next_col(self.col, byte);
        if new_col <= self.width {
            self.append(byte, new_col);
            return;
        }

        // new_col would exceed width — wrap.
        if self.break_ws {
            // Look back for last space/tab boundary inside the buffer.
            // Boundary = the byte AFTER a space/tab, so the space stays
            // at the end of the wrapped line (POSIX).
            let mut split = None;
            let mut i = self.len;
            while i > 0 {
                i -= 1;
                if self.buf[i] == b' ' || self.buf[i] == b'\t' {
                    split = Some(i + 1);
                    break;
                }
            }
            if let Some(s) = split
                && s < self.len
                && s > 0
            {
                // Emit buf[..s] + "\n", keep buf[s..] as next line.
                let _ = write_all(1, &self.buf[..s]);
                let _ = write_all(1, b"\n");
                let tail_len = self.len - s;
                // Move tail bytes to front and recompute their columns.
                let mut tmp = [0u8; WRAP_BUF];
                tmp[..tail_len].copy_from_slice(&self.buf[s..self.len]);
                self.len = 0;
                self.col = 0;
                for k in 0..tail_len {
                    let nc = self.next_col(self.col, tmp[k]);
                    self.buf[self.len] = tmp[k];
                    self.len += 1;
                    self.col = nc;
                }
                // Now append the new byte.
                let nc = self.next_col(self.col, byte);
                if nc <= self.width {
                    self.append(byte, nc);
                } else {
                    // Tail + new byte still exceed width — hard wrap.
                    self.flush_buffer();
                    let _ = write_all(1, b"\n");
                    self.col = 0;
                    let nc2 = self.next_col(0, byte);
                    self.append(byte, nc2);
                }
                return;
            }
            // No boundary found — fall through to hard wrap.
        }

        // Hard wrap: flush buffer, emit \n, start new line with this byte.
        self.flush_buffer();
        let _ = write_all(1, b"\n");
        self.col = 0;
        let nc = self.next_col(0, byte);
        self.append(byte, nc);
    }

    fn flush_buffer(&mut self) {
        if self.len > 0 {
            let _ = write_all(1, &self.buf[..self.len]);
            self.len = 0;
        }
    }

    /// Final flush at end of input. Emits any buffered bytes without
    /// a trailing `\n` (mirroring POSIX behavior — fold preserves the
    /// absence of a final newline).
    fn flush(&mut self) {
        self.flush_buffer();
    }
}

fn process_fd(fd: i32, state: &mut FoldState) {
    let mut readbuf = [0u8; READ_CHUNK];
    loop {
        // SAFETY: readbuf is owned and writable for its full length.
        let n = unsafe { libc::read(fd, readbuf.as_mut_ptr(), readbuf.len()) };
        if n <= 0 {
            break;
        }
        for &b in &readbuf[..n as usize] {
            state.feed(b);
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
    let _ = write_all(2, b"fold: panic\n");
    libc::exit(1)
}
