// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/paste` — merge corresponding lines of input streams.
//!
//! Usage:
//!   paste [-d LIST] FILE...
//!   paste -s [-d LIST] FILE...
//!
//! Default mode: read one line from each FILE in turn and print them
//! joined by TAB on a single output line. Continues until every FILE
//! has reached EOF (an exhausted FILE contributes empty fields).
//!
//! `-s` (serial) — instead of merging, concatenate every line of each
//! FILE on a single output line, then advance to the next FILE.
//!
//! `-d LIST` — supply a delimiter list. Each character in LIST is used
//! in turn as the separator between adjacent fields, cycling back to
//! the first when exhausted. Backslash escapes recognised: `\\n`, `\\t`,
//! `\\r`, `\\\\`, `\\0`. A literal `\\` followed by any other char emits
//! that char as-is.
//!
//! `-` as a FILE reads stdin (only meaningful once, since stdin is
//! a single stream).
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/paste.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const MAX_FILES: usize = 8;
const MAX_DELIMS: usize = 16;
const LINE_MAX: usize = 4096;
const READ_CHUNK: usize = 4096;

/// Streaming line reader bound to a single fd.
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
                }
                None => {
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
        main = sym paste_main,
    );
}

extern "C" fn paste_main(argc: usize, argv: *const *const u8) -> ! {
    let mut serial = false;
    let mut delims: [u8; MAX_DELIMS] = [b'\t'; MAX_DELIMS];
    let mut delim_len: usize = 1;
    let mut idx = 1usize;

    while idx < argc {
        // SAFETY: idx < argc.
        let arg = unsafe { cstr_at(argv, idx) };
        if arg == b"-s" {
            serial = true;
            idx += 1;
            continue;
        }
        if arg == b"-d" {
            idx += 1;
            if idx >= argc {
                write_err(b"paste: -d needs LIST\n");
                libc::exit(1);
            }
            // SAFETY: idx < argc.
            let raw = unsafe { cstr_at(argv, idx) };
            if !expand_delims(raw, &mut delims, &mut delim_len) {
                write_err(b"paste: invalid delimiter list\n");
                libc::exit(1);
            }
            idx += 1;
            continue;
        }
        if arg == b"--" {
            idx += 1;
            break;
        }
        if !arg.is_empty() && arg[0] == b'-' && arg != b"-" {
            write_err(b"paste: unknown option\n");
            libc::exit(1);
        }
        break;
    }

    if idx >= argc {
        write_err(b"paste: missing FILE\n");
        libc::exit(1);
    }

    let mut fds = [-1i32; MAX_FILES];
    let mut nfiles = 0usize;
    while idx < argc && nfiles < MAX_FILES {
        // SAFETY: idx < argc.
        let path = unsafe { cstr_at(argv, idx) };
        let fd = open_or_stdin(path);
        if fd < 0 {
            write_err(b"paste: cannot open file\n");
            libc::exit(1);
        }
        fds[nfiles] = fd;
        nfiles += 1;
        idx += 1;
    }

    if serial {
        run_serial(&fds[..nfiles], &delims[..delim_len]);
    } else {
        run_parallel(&fds[..nfiles], &delims[..delim_len]);
    }

    for &fd in &fds[..nfiles] {
        if fd > 0 {
            let _ = libc::close(fd);
        }
    }

    libc::exit(0)
}

/// Default mode — round-robin one line from each fd per output line.
fn run_parallel(fds: &[i32], delims: &[u8]) {
    let mut readers: [Option<LineReader>; MAX_FILES] = [const { None }; MAX_FILES];
    for (i, &fd) in fds.iter().enumerate() {
        readers[i] = Some(LineReader::new(fd));
    }

    loop {
        let mut any = false;
        for r in readers.iter_mut().take(fds.len()) {
            if let Some(reader) = r.as_mut() {
                reader.advance();
                if reader.have_line {
                    any = true;
                }
            }
        }
        if !any {
            break;
        }
        for (i, r) in readers.iter_mut().take(fds.len()).enumerate() {
            if i > 0 {
                let d = delims[(i - 1) % delims.len()];
                if d != 0 {
                    let _ = write_all(1, &[d]);
                }
            }
            if let Some(reader) = r.as_mut()
                && reader.have_line
            {
                let _ = write_all(1, reader.current());
            }
        }
        let _ = write_all(1, b"\n");
    }
}

/// Serial mode — for each fd, concatenate all lines on one output line.
fn run_serial(fds: &[i32], delims: &[u8]) {
    for &fd in fds {
        let mut reader = LineReader::new(fd);
        let mut count = 0usize;
        loop {
            reader.advance();
            if !reader.have_line {
                break;
            }
            if count > 0 {
                let d = delims[(count - 1) % delims.len()];
                if d != 0 {
                    let _ = write_all(1, &[d]);
                }
            }
            let _ = write_all(1, reader.current());
            count += 1;
        }
        if count > 0 {
            let _ = write_all(1, b"\n");
        }
    }
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

fn expand_delims(spec: &[u8], out: &mut [u8], out_len: &mut usize) -> bool {
    let mut len = 0usize;
    let mut i = 0usize;
    while i < spec.len() {
        if len >= out.len() {
            return false;
        }
        if spec[i] == b'\\' && i + 1 < spec.len() {
            let escaped = match spec[i + 1] {
                b'n' => b'\n',
                b't' => b'\t',
                b'r' => b'\r',
                b'\\' => b'\\',
                b'0' => 0,
                c => c,
            };
            out[len] = escaped;
            len += 1;
            i += 2;
        } else {
            out[len] = spec[i];
            len += 1;
            i += 1;
        }
    }
    if len == 0 {
        return false;
    }
    *out_len = len;
    true
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
    write_err(b"paste: panic\n");
    libc::exit(1)
}
