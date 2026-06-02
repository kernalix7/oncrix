// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/cmp` — POSIX.1-2024 byte-by-byte file comparison (subset).
//!
//! Forms:
//!   * `cmp FILE1 FILE2`        — compare byte-by-byte. On the first differing
//!     byte print `FILE1 FILE2 differ: byte N, line L` to stdout (1-indexed)
//!     and exit 1. If lengths differ but the common prefix matches, print
//!     `cmp: EOF on FILE1` (or `FILE2`) to stderr and exit 1.
//!   * `cmp -s FILE1 FILE2`     — silent: suppress all output, exit status only.
//!   * `cmp -l FILE1 FILE2`     — verbose: print `BYTE OCT1 OCT2` for every
//!     differing byte; final exit is still 1.
//!
//! Either FILE may be `-`, meaning standard input.
//!
//! Exit status:
//!   * 0 — files identical
//!   * 1 — files differ (or stream lengths differ)
//!   * 2 — file open / I/O error
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/cmp.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// `_start` must be a *naked* function so the Rust prologue does not allocate
/// a local stack frame before we capture argc/argv. The kernel's `sys_execve`
/// lays out the System V AMD64 initial stack at `RSP = 0x5FF000` with
/// `[rsp] = argc` and `[rsp+8..] = argv`.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym cmp_main,
    );
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// I/O chunk size for the streaming compare loop.
const CHUNK: usize = 4096;

/// Standard file descriptors.
const STDIN: i32 = 0;
const STDOUT: i32 = 1;
const STDERR: i32 = 2;

// ---------------------------------------------------------------------------
// Mode flags
// ---------------------------------------------------------------------------

/// Output mode selected by `-s` / `-l` / default.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Default: print a single `differ` line, stop at first difference.
    Default,
    /// `-s` — suppress all output, exit status only.
    Silent,
    /// `-l` — print every differing byte, continue past first difference.
    Verbose,
}

// ---------------------------------------------------------------------------
// cmp logic
// ---------------------------------------------------------------------------

extern "C" fn cmp_main(argc: usize, argv: *const *const u8) -> ! {
    let mut mode = Mode::Default;
    let mut files: [*const u8; 2] = [core::ptr::null(); 2];
    let mut nfiles: usize = 0;

    // ---- Argument parsing -----------------------------------------------
    let mut i = 1;
    while i < argc {
        // SAFETY: argv has at least `argc` valid pointers from execve.
        let ptr = unsafe { argv.add(i).read() };
        if ptr.is_null() {
            break;
        }
        // SAFETY: argv strings are null-terminated.
        let first = unsafe { ptr.read() };
        // SAFETY: argv strings are null-terminated; reading byte 1 is safe
        // because if byte 0 is non-zero, byte 1 is at worst the terminator.
        let second = unsafe { ptr.add(1).read() };

        if first == b'-' && second != 0 {
            // Walk option characters: `-sl` is two flags, like POSIX.
            let mut j: usize = 1;
            loop {
                // SAFETY: ptr is null-terminated; we stop at the NUL.
                let c = unsafe { ptr.add(j).read() };
                if c == 0 {
                    break;
                }
                match c {
                    b's' => mode = Mode::Silent,
                    b'l' => mode = Mode::Verbose,
                    _ => {
                        write_all(STDERR, b"cmp: unsupported option\n");
                        libc::exit(2);
                    }
                }
                j += 1;
            }
        } else {
            // `-` is a regular operand meaning stdin, not an option.
            if nfiles >= 2 {
                write_all(STDERR, b"cmp: too many file arguments\n");
                libc::exit(2);
            }
            files[nfiles] = ptr;
            nfiles += 1;
        }
        i += 1;
    }

    if nfiles != 2 {
        write_all(STDERR, b"cmp: missing operand\n");
        libc::exit(2);
    }

    let fd1 = match open_operand(files[0]) {
        Some(fd) => fd,
        None => {
            if mode != Mode::Silent {
                write_all(STDERR, b"cmp: cannot open ");
                write_cstr(STDERR, files[0]);
                write_all(STDERR, b"\n");
            }
            libc::exit(2);
        }
    };
    let fd2 = match open_operand(files[1]) {
        Some(fd) => fd,
        None => {
            if fd1 != STDIN {
                libc::close(fd1);
            }
            if mode != Mode::Silent {
                write_all(STDERR, b"cmp: cannot open ");
                write_cstr(STDERR, files[1]);
                write_all(STDERR, b"\n");
            }
            libc::exit(2);
        }
    };

    let exit = compare(fd1, fd2, files[0], files[1], mode);

    if fd1 != STDIN {
        libc::close(fd1);
    }
    if fd2 != STDIN {
        libc::close(fd2);
    }
    libc::exit(exit)
}

/// Open an operand as O_RDONLY, or return `STDIN` if the operand is `"-"`.
///
/// Returns `None` on open failure. The returned fd is `STDIN` (0) for the
/// `-` operand and a fresh fd otherwise; callers must close non-stdin fds.
fn open_operand(path: *const u8) -> Option<i32> {
    // SAFETY: path is a null-terminated argv pointer.
    let first = unsafe { path.read() };
    let second = unsafe { path.add(1).read() };
    if first == b'-' && second == 0 {
        return Some(STDIN);
    }
    // SAFETY: path is a null-terminated argv pointer.
    let fd = unsafe { libc::open(path, libc::O_RDONLY, 0) };
    if fd < 0 { None } else { Some(fd as i32) }
}

// ---------------------------------------------------------------------------
// Comparison core
// ---------------------------------------------------------------------------

/// Streaming compare of two open file descriptors.
///
/// Maintains a 1-indexed byte offset and 1-indexed line counter (each LF in
/// the *common* prefix advances the line counter). Returns the process exit
/// code (0, 1, or 2).
fn compare(fd1: i32, fd2: i32, name1: *const u8, name2: *const u8, mode: Mode) -> i32 {
    let mut buf1 = [0u8; CHUNK];
    let mut buf2 = [0u8; CHUNK];

    // Independent fill pointers per stream; partial reads are normal for
    // pipes / stdin, so we refill each side on demand.
    let mut len1: usize = 0;
    let mut len2: usize = 0;
    let mut pos1: usize = 0;
    let mut pos2: usize = 0;
    let mut eof1 = false;
    let mut eof2 = false;

    let mut byte_off: u64 = 1; // POSIX: 1-indexed
    let mut line_no: u64 = 1; // 1-indexed
    let mut differ = false;

    loop {
        if pos1 == len1 && !eof1 {
            match fill(fd1, &mut buf1) {
                FillResult::Read(n) => {
                    len1 = n;
                    pos1 = 0;
                }
                FillResult::Eof => eof1 = true,
                FillResult::Err => {
                    if mode != Mode::Silent {
                        write_all(STDERR, b"cmp: read error on ");
                        write_cstr(STDERR, name1);
                        write_all(STDERR, b"\n");
                    }
                    return 2;
                }
            }
        }
        if pos2 == len2 && !eof2 {
            match fill(fd2, &mut buf2) {
                FillResult::Read(n) => {
                    len2 = n;
                    pos2 = 0;
                }
                FillResult::Eof => eof2 = true,
                FillResult::Err => {
                    if mode != Mode::Silent {
                        write_all(STDERR, b"cmp: read error on ");
                        write_cstr(STDERR, name2);
                        write_all(STDERR, b"\n");
                    }
                    return 2;
                }
            }
        }

        let avail1 = len1 - pos1;
        let avail2 = len2 - pos2;

        if avail1 == 0 && avail2 == 0 {
            // Both streams ended cleanly.
            return if differ { 1 } else { 0 };
        }
        if avail1 == 0 {
            // FILE1 ended first; FILE2 has more.
            if mode != Mode::Silent {
                write_all(STDERR, b"cmp: EOF on ");
                write_cstr(STDERR, name1);
                write_all(STDERR, b"\n");
            }
            return 1;
        }
        if avail2 == 0 {
            // FILE2 ended first; FILE1 has more.
            if mode != Mode::Silent {
                write_all(STDERR, b"cmp: EOF on ");
                write_cstr(STDERR, name2);
                write_all(STDERR, b"\n");
            }
            return 1;
        }

        let n = if avail1 < avail2 { avail1 } else { avail2 };
        let mut k: usize = 0;
        while k < n {
            let a = buf1[pos1 + k];
            let b = buf2[pos2 + k];
            if a != b {
                differ = true;
                match mode {
                    Mode::Silent => return 1,
                    Mode::Default => {
                        emit_differ(name1, name2, byte_off, line_no);
                        return 1;
                    }
                    Mode::Verbose => {
                        emit_verbose(byte_off, a, b);
                        // Continue scanning in `-l` mode.
                    }
                }
            }
            if a == b'\n' {
                line_no += 1;
            }
            byte_off += 1;
            k += 1;
        }
        pos1 += n;
        pos2 += n;
    }
}

/// Outcome of one fill attempt on a stream.
enum FillResult {
    /// `read` returned `n` bytes (n > 0).
    Read(usize),
    /// `read` returned 0 — clean EOF.
    Eof,
    /// `read` returned a negative errno.
    Err,
}

/// Read up to `buf.len()` bytes, classifying the result.
fn fill(fd: i32, buf: &mut [u8]) -> FillResult {
    // SAFETY: buf is valid for buf.len() writable bytes.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr(), buf.len()) };
    if n > 0 {
        FillResult::Read(n as usize)
    } else if n == 0 {
        FillResult::Eof
    } else {
        FillResult::Err
    }
}

// ---------------------------------------------------------------------------
// Diagnostic output helpers
// ---------------------------------------------------------------------------

/// Emit the default `FILE1 FILE2 differ: byte N, line L` line on stdout.
fn emit_differ(name1: *const u8, name2: *const u8, byte: u64, line: u64) {
    write_cstr(STDOUT, name1);
    write_all(STDOUT, b" ");
    write_cstr(STDOUT, name2);
    write_all(STDOUT, b" differ: byte ");
    write_u64(STDOUT, byte);
    write_all(STDOUT, b", line ");
    write_u64(STDOUT, line);
    write_all(STDOUT, b"\n");
}

/// Emit one verbose-mode line: `BYTE OCT1 OCT2`.
///
/// POSIX specifies the bytes are printed as octal numbers padded to 3 digits.
fn emit_verbose(byte: u64, a: u8, b: u8) {
    write_u64(STDOUT, byte);
    write_all(STDOUT, b" ");
    write_octal3(STDOUT, a);
    write_all(STDOUT, b" ");
    write_octal3(STDOUT, b);
    write_all(STDOUT, b"\n");
}

/// Format a `u64` as decimal ASCII and write it. No allocation.
fn write_u64(fd: i32, mut v: u64) {
    let mut buf = [0u8; 20]; // u64::MAX is 20 digits
    let mut idx = buf.len();
    if v == 0 {
        idx -= 1;
        buf[idx] = b'0';
    } else {
        while v > 0 {
            idx -= 1;
            buf[idx] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    }
    write_all(fd, &buf[idx..]);
}

/// Write a byte as a 3-digit octal number, e.g. 0 -> "000", 255 -> "377".
fn write_octal3(fd: i32, v: u8) {
    let buf = [
        b'0' + ((v >> 6) & 0x07),
        b'0' + ((v >> 3) & 0x07),
        b'0' + (v & 0x07),
    ];
    write_all(fd, &buf);
}

/// Write a null-terminated C string to `fd` (no NUL written).
fn write_cstr(fd: i32, s: *const u8) {
    let len = c_strlen(s);
    let mut pos: usize = 0;
    while pos < len {
        // SAFETY: s is null-terminated for at least `len` bytes; pos < len
        // ensures we read inside that span.
        let n = unsafe { libc::write(fd, s.add(pos), len - pos) };
        if n <= 0 {
            return;
        }
        pos += n as usize;
    }
}

/// Length of a null-terminated C string. Caller guarantees termination.
fn c_strlen(s: *const u8) -> usize {
    let mut n: usize = 0;
    // SAFETY: caller guarantees the string is null-terminated.
    while unsafe { s.add(n).read() } != 0 {
        n += 1;
    }
    n
}

/// Write the entire slice or stop on error. Used for diagnostics where we
/// don't care to distinguish partial writes.
fn write_all(fd: i32, buf: &[u8]) {
    let mut pos = 0;
    while pos < buf.len() {
        // SAFETY: buf slice is valid for buf.len() bytes.
        let n = unsafe { libc::write(fd, buf[pos..].as_ptr(), buf.len() - pos) };
        if n <= 0 {
            return;
        }
        pos += n as usize;
    }
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_all(STDERR, b"cmp: panic\n");
    libc::exit(2)
}
