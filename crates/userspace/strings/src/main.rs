// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/strings` — extract printable ASCII strings from a binary file.
//!
//! Form:
//!   * `strings [-a] [-n MIN] [-t {d,o,x}] [FILE...]` — for each FILE (or
//!     stdin when no operand is supplied, or `-` is given), emit every
//!     maximal run of at least MIN consecutive printable ASCII bytes on its
//!     own line on stdout. Default MIN is 4.
//!
//! Options:
//!   * `-a` — scan the entire file (accepted for compatibility; this is
//!     also the default behavior since we have no object-file parser yet).
//!   * `-n MIN` — minimum run length. MIN must be a positive decimal.
//!   * `-t d|o|x` — prefix each emitted run with its byte offset in
//!     decimal, octal, or hexadecimal respectively.
//!
//! "Printable" is defined as ASCII `0x20..=0x7E` plus `0x09` (TAB), matching
//! the conventional GNU binutils default for `strings -e s`.
//!
//! Implementation notes:
//!   * I/O is performed in 4 KiB chunks.
//!   * A 4 KiB accumulator buffers the current run; if a run grows beyond
//!     the buffer it is flushed as-is and scanning continues with an empty
//!     buffer (so over-long runs split at the buffer boundary).
//!   * A running 64-bit byte offset is maintained across reads.
//!
//! Exit status:
//!   * 0 — all operands processed successfully.
//!   * 1 — one or more operands could not be opened or read.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/strings.html`

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
        main = sym strings_main,
    );
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// I/O chunk size for the streaming scan loop.
const CHUNK: usize = 4096;

/// Maximum accumulated run length before we force-flush mid-run.
const RUN_BUF: usize = 4096;

/// Maximum number of FILE operands accepted on the command line.
const MAX_FILES: usize = 16;

/// Default minimum run length when `-n` is not supplied.
const DEFAULT_MIN: usize = 4;

/// Standard file descriptors.
const STDIN: i32 = 0;
const STDOUT: i32 = 1;
const STDERR: i32 = 2;

/// Offset radix selected by `-t`.
#[derive(Clone, Copy)]
enum Radix {
    None,
    Decimal,
    Octal,
    Hex,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

extern "C" fn strings_main(argc: usize, argv: *const *const u8) -> ! {
    let mut min_len: usize = DEFAULT_MIN;
    let mut radix: Radix = Radix::None;

    let mut files: [*const u8; MAX_FILES] = [core::ptr::null(); MAX_FILES];
    let mut nfiles: usize = 0;

    // ----- Argument parse -----
    let mut i = 1;
    while i < argc {
        // SAFETY: argv has at least `argc` valid pointers from execve.
        let arg = unsafe { argv.add(i).read() };
        if arg.is_null() {
            break;
        }

        // SAFETY: argv entries are null-terminated C strings.
        let first = unsafe { arg.read() };
        let second = unsafe { arg.add(1).read() };

        if first == b'-' && second != 0 {
            // Bare "-" is the stdin operand, handled in the else branch.
            // Parse a flag.
            match second {
                b'a' => {
                    // Accepted for compatibility; no-op (we always scan all).
                    if unsafe { arg.add(2).read() } != 0 {
                        unknown_flag(arg);
                        libc::exit(1);
                    }
                }
                b'n' => {
                    // `-n MIN` (next argv) or `-nMIN` (glued).
                    let value_ptr = if unsafe { arg.add(2).read() } != 0 {
                        // SAFETY: we know byte at offset 2 is non-NUL, so the
                        // rest of the C string starts there.
                        unsafe { arg.add(2) }
                    } else {
                        i += 1;
                        if i >= argc {
                            write_all(STDERR, b"strings: option requires an argument -- 'n'\n");
                            libc::exit(1);
                        }
                        // SAFETY: i < argc — argv has that many valid slots.
                        let p = unsafe { argv.add(i).read() };
                        if p.is_null() {
                            write_all(STDERR, b"strings: option requires an argument -- 'n'\n");
                            libc::exit(1);
                        }
                        p
                    };
                    match parse_positive_decimal(value_ptr) {
                        Some(v) if v > 0 => min_len = v,
                        _ => {
                            write_all(STDERR, b"strings: invalid minimum length\n");
                            libc::exit(1);
                        }
                    }
                }
                b't' => {
                    // `-t d|o|x` (next argv) or `-td` / `-to` / `-tx` (glued).
                    let value_ptr = if unsafe { arg.add(2).read() } != 0 {
                        unsafe { arg.add(2) }
                    } else {
                        i += 1;
                        if i >= argc {
                            write_all(STDERR, b"strings: option requires an argument -- 't'\n");
                            libc::exit(1);
                        }
                        // SAFETY: i < argc — argv has that many valid slots.
                        let p = unsafe { argv.add(i).read() };
                        if p.is_null() {
                            write_all(STDERR, b"strings: option requires an argument -- 't'\n");
                            libc::exit(1);
                        }
                        p
                    };
                    // The value must be exactly one of d/o/x followed by NUL.
                    // SAFETY: value_ptr is a null-terminated argv pointer.
                    let v0 = unsafe { value_ptr.read() };
                    let v1 = unsafe { value_ptr.add(1).read() };
                    if v1 != 0 {
                        write_all(STDERR, b"strings: invalid radix for -t\n");
                        libc::exit(1);
                    }
                    radix = match v0 {
                        b'd' => Radix::Decimal,
                        b'o' => Radix::Octal,
                        b'x' => Radix::Hex,
                        _ => {
                            write_all(STDERR, b"strings: invalid radix for -t\n");
                            libc::exit(1);
                        }
                    };
                }
                _ => {
                    unknown_flag(arg);
                    libc::exit(1);
                }
            }
        } else {
            // A FILE operand (including bare "-").
            if nfiles >= MAX_FILES {
                write_all(STDERR, b"strings: too many file arguments\n");
                libc::exit(1);
            }
            files[nfiles] = arg;
            nfiles += 1;
        }
        i += 1;
    }

    let mut exit_code: i32 = 0;

    if nfiles == 0 {
        if !scan_fd(STDIN, min_len, radix) {
            exit_code = 1;
        }
    } else {
        let mut k = 0;
        while k < nfiles {
            if !scan_operand(files[k], min_len, radix) {
                exit_code = 1;
            }
            k += 1;
        }
    }

    libc::exit(exit_code)
}

/// Emit a generic "unknown flag" diagnostic naming `arg` verbatim.
fn unknown_flag(arg: *const u8) {
    write_all(STDERR, b"strings: unknown option ");
    write_cstr(STDERR, arg);
    write_all(STDERR, b"\n");
}

// ---------------------------------------------------------------------------
// Per-operand dispatch
// ---------------------------------------------------------------------------

/// Open `path` (or attach to stdin for the bare `-` operand), then scan it.
/// Returns `true` on success, `false` on any open/read failure.
fn scan_operand(path: *const u8, min_len: usize, radix: Radix) -> bool {
    // SAFETY: path is a null-terminated argv pointer.
    let first = unsafe { path.read() };
    let second = unsafe { path.add(1).read() };

    if first == b'-' && second == 0 {
        return scan_fd(STDIN, min_len, radix);
    }

    // SAFETY: path is a null-terminated argv pointer.
    let fd = unsafe { libc::open(path, libc::O_RDONLY, 0) };
    if fd < 0 {
        write_all(STDERR, b"strings: cannot open ");
        write_cstr(STDERR, path);
        write_all(STDERR, b"\n");
        return false;
    }
    let fd = fd as i32;
    let ok = scan_fd(fd, min_len, radix);
    libc::close(fd);
    ok
}

// ---------------------------------------------------------------------------
// Scan loop
// ---------------------------------------------------------------------------

/// Stream `fd` through the printable-run detector. Emits each qualifying run
/// as one line on stdout, optionally prefixed by its byte offset.
///
/// Returns `true` on EOF, `false` on read error.
fn scan_fd(fd: i32, min_len: usize, radix: Radix) -> bool {
    let mut io_buf = [0u8; CHUNK];
    let mut run_buf = [0u8; RUN_BUF];
    let mut run_len: usize = 0;
    // Byte offset within the file of the first byte currently sitting in
    // `run_buf`. Only meaningful while `run_len > 0`.
    let mut run_start: u64 = 0;
    let mut file_offset: u64 = 0;

    loop {
        // SAFETY: io_buf is a stack array valid for CHUNK writable bytes.
        let n = unsafe { libc::read(fd, io_buf.as_mut_ptr(), io_buf.len()) };
        if n == 0 {
            break;
        }
        if n < 0 {
            write_all(STDERR, b"strings: read error\n");
            return false;
        }
        let got = n as usize;
        let mut j = 0;
        while j < got {
            let b = io_buf[j];
            if is_printable(b) {
                if run_len == 0 {
                    run_start = file_offset.wrapping_add(j as u64);
                }
                run_buf[run_len] = b;
                run_len += 1;
                if run_len == RUN_BUF {
                    // Over-long run: flush what we have and restart so we
                    // never lose data, accepting the artificial split.
                    if run_len >= min_len {
                        emit_run(&run_buf[..run_len], run_start, radix);
                    }
                    run_len = 0;
                    // The next printable byte begins a fresh logical run; its
                    // offset will be re-recorded when we see it.
                }
            } else if run_len > 0 {
                if run_len >= min_len {
                    emit_run(&run_buf[..run_len], run_start, radix);
                }
                run_len = 0;
            }
            j += 1;
        }
        file_offset = file_offset.wrapping_add(got as u64);
    }

    // EOF: flush a trailing qualifying run.
    if run_len >= min_len {
        emit_run(&run_buf[..run_len], run_start, radix);
    }

    true
}

/// Return `true` for bytes considered "printable" in the POSIX-default
/// `strings` sense: graphic ASCII (`0x20..=0x7E`) plus TAB (`0x09`).
#[inline(always)]
fn is_printable(b: u8) -> bool {
    b == 0x09 || (0x20..=0x7E).contains(&b)
}

/// Emit one qualifying run as `[OFFSET ]CONTENT\n`. The offset prefix is
/// included only when `radix` is not `Radix::None`.
fn emit_run(run: &[u8], offset: u64, radix: Radix) {
    match radix {
        Radix::None => {}
        Radix::Decimal => {
            write_u64_dec(STDOUT, offset);
            write_all(STDOUT, b" ");
        }
        Radix::Octal => {
            write_u64_oct(STDOUT, offset);
            write_all(STDOUT, b" ");
        }
        Radix::Hex => {
            write_u64_hex(STDOUT, offset);
            write_all(STDOUT, b" ");
        }
    }
    write_all(STDOUT, run);
    write_all(STDOUT, b"\n");
}

// ---------------------------------------------------------------------------
// Argument helpers
// ---------------------------------------------------------------------------

/// Parse a positive decimal integer from a null-terminated C string. Returns
/// `None` if the string is empty, contains non-digits, or overflows `usize`.
fn parse_positive_decimal(s: *const u8) -> Option<usize> {
    if s.is_null() {
        return None;
    }
    let mut v: usize = 0;
    let mut i = 0;
    let mut any = false;
    loop {
        // SAFETY: s is a null-terminated C string from argv.
        let c = unsafe { s.add(i).read() };
        if c == 0 {
            break;
        }
        if !(b'0'..=b'9').contains(&c) {
            return None;
        }
        let digit = (c - b'0') as usize;
        v = v.checked_mul(10)?.checked_add(digit)?;
        any = true;
        i += 1;
    }
    if any { Some(v) } else { None }
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

/// Format a `u64` as decimal ASCII and write it. No allocation.
fn write_u64_dec(fd: i32, mut v: u64) {
    let mut buf = [0u8; 20]; // u64::MAX is 20 digits in decimal.
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

/// Format a `u64` as octal ASCII and write it. No allocation, no leading 0.
fn write_u64_oct(fd: i32, mut v: u64) {
    let mut buf = [0u8; 22]; // u64::MAX is 22 octal digits.
    let mut idx = buf.len();
    if v == 0 {
        idx -= 1;
        buf[idx] = b'0';
    } else {
        while v > 0 {
            idx -= 1;
            buf[idx] = b'0' + (v & 0o7) as u8;
            v >>= 3;
        }
    }
    write_all(fd, &buf[idx..]);
}

/// Format a `u64` as lowercase hexadecimal ASCII and write it. No
/// allocation, no `0x` prefix.
fn write_u64_hex(fd: i32, mut v: u64) {
    let mut buf = [0u8; 16]; // u64::MAX is 16 hex digits.
    let mut idx = buf.len();
    if v == 0 {
        idx -= 1;
        buf[idx] = b'0';
    } else {
        while v > 0 {
            idx -= 1;
            let nib = (v & 0xf) as u8;
            buf[idx] = if nib < 10 { b'0' + nib } else { b'a' + (nib - 10) };
            v >>= 4;
        }
    }
    write_all(fd, &buf[idx..]);
}

/// Write a null-terminated C string to `fd` (no NUL written).
fn write_cstr(fd: i32, s: *const u8) {
    if s.is_null() {
        return;
    }
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

/// Write the entire slice or stop on error. Used for diagnostics and
/// output where we do not need to distinguish partial writes.
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
    write_all(STDERR, b"strings: panic\n");
    libc::exit(1)
}
