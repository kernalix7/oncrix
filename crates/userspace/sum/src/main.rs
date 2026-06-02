// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/sum` — POSIX.1-2024 file checksum utility (subset).
//!
//! Form:
//!   * `sum [-r|-s] [FILE...]` — for each FILE print a checksum and a block
//!     count to stdout. With no operands or with a `-` operand, read from
//!     stdin; the trailing FILENAME field is omitted for the no-operand
//!     stdin form.
//!
//! Algorithms (POSIX historical):
//!   * `-r` (default) — BSD: a 16-bit rotate-right add accumulator over each
//!     byte. Block count is the input length in 1024-byte blocks, rounded up.
//!     Output: `CHECKSUM BLOCKS [FILENAME]`, CHECKSUM in 5-digit decimal.
//!   * `-s`           — System V: an additive 32-bit accumulator folded down
//!     to 16 bits. Block count is the input length in 512-byte blocks,
//!     rounded up. Output: `CHECKSUM BLOCKS [FILENAME]`.
//!
//! Exit status:
//!   * 0 — every operand processed successfully
//!   * 1 — one or more operands could not be opened or read, or a usage
//!     error was reported
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/sum.html`

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
        main = sym sum_main,
    );
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// I/O chunk size for the streaming hash loop.
const CHUNK: usize = 4096;

/// Maximum number of FILE operands we accept on the command line.
const MAX_FILES: usize = 16;

/// Standard file descriptors.
const STDIN: i32 = 0;
const STDOUT: i32 = 1;
const STDERR: i32 = 2;

/// Selected checksum algorithm.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Algo {
    /// BSD rotate-right add, 1024-byte blocks. POSIX default.
    Bsd,
    /// System V additive, folded to 16 bits, 512-byte blocks.
    SysV,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

extern "C" fn sum_main(argc: usize, argv: *const *const u8) -> ! {
    let mut algo = Algo::Bsd;
    let mut files: [*const u8; MAX_FILES] = [core::ptr::null(); MAX_FILES];
    let mut nfiles: usize = 0;

    // Argument parse: `-r` and `-s` are the only flags; `--` ends option
    // processing; `-` alone is an operand (stdin).
    let mut i = 1;
    let mut end_of_opts = false;
    while i < argc {
        // SAFETY: argv has at least `argc` valid pointers from execve.
        let ptr = unsafe { argv.add(i).read() };
        if ptr.is_null() {
            break;
        }
        // SAFETY: argv entries are null-terminated C strings.
        let first = unsafe { ptr.read() };
        // SAFETY: same — past the first byte we are still inside the string
        // (or on its terminator).
        let second = unsafe { ptr.add(1).read() };

        if !end_of_opts && first == b'-' && second != 0 {
            // Long marker `--` ends option processing.
            // SAFETY: ptr.add(2) stays within the null-terminated string;
            // for "--" it lands on the trailing NUL.
            let third = unsafe { ptr.add(2).read() };
            if second == b'-' && third == 0 {
                end_of_opts = true;
                i += 1;
                continue;
            }
            // Walk the cluster of short flags.
            let mut j: usize = 1;
            loop {
                // SAFETY: bounded walk over a null-terminated string.
                let c = unsafe { ptr.add(j).read() };
                if c == 0 {
                    break;
                }
                match c {
                    b'r' => algo = Algo::Bsd,
                    b's' => algo = Algo::SysV,
                    other => {
                        write_all(STDERR, b"sum: invalid option -- '");
                        write_all(STDERR, &[other]);
                        write_all(STDERR, b"'\n");
                        write_all(STDERR, b"usage: sum [-r|-s] [file...]\n");
                        libc::exit(1);
                    }
                }
                j += 1;
            }
            i += 1;
            continue;
        }

        if nfiles >= MAX_FILES {
            write_all(STDERR, b"sum: too many file arguments\n");
            libc::exit(1);
        }
        files[nfiles] = ptr;
        nfiles += 1;
        i += 1;
    }

    let mut exit_code: i32 = 0;

    if nfiles == 0 {
        // No operands — checksum stdin, suppress filename in output.
        if !sum_fd(STDIN, core::ptr::null(), algo) {
            exit_code = 1;
        }
    } else {
        let mut k = 0;
        while k < nfiles {
            if !sum_operand(files[k], algo) {
                exit_code = 1;
            }
            k += 1;
        }
    }

    libc::exit(exit_code)
}

/// Process one operand: open it (or attach to stdin for `-`), checksum it,
/// emit one output line. Returns `true` on success, `false` on any error.
fn sum_operand(path: *const u8, algo: Algo) -> bool {
    // SAFETY: path is a null-terminated argv pointer.
    let first = unsafe { path.read() };
    // SAFETY: same — second byte is either inside the string or the NUL.
    let second = unsafe { path.add(1).read() };

    if first == b'-' && second == 0 {
        // `-` operand: read stdin, but DO print "-" as the filename per
        // POSIX (the no-operand form is the one that suppresses the name).
        return sum_fd(STDIN, path, algo);
    }

    // SAFETY: path is a null-terminated argv pointer.
    let fd = unsafe { libc::open(path, libc::O_RDONLY, 0) };
    if fd < 0 {
        write_all(STDERR, b"sum: cannot open ");
        write_cstr(STDERR, path);
        write_all(STDERR, b"\n");
        return false;
    }
    let fd = fd as i32;
    let ok = sum_fd(fd, path, algo);
    libc::close(fd);
    ok
}

/// Read every byte from `fd`, run the selected checksum, and emit
/// `CHECKSUM BLOCKS [FILENAME]\n`. `name_for_output` is non-null when the
/// line should include a trailing filename; pass null to suppress it
/// (stdin no-operand form).
fn sum_fd(fd: i32, name_for_output: *const u8, algo: Algo) -> bool {
    let mut buf = [0u8; CHUNK];
    let mut bsd: u16 = 0;
    let mut sysv: u32 = 0;
    let mut len: u64 = 0;

    loop {
        // SAFETY: buf is a stack array valid for CHUNK writable bytes.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr(), buf.len()) };
        if n == 0 {
            break;
        }
        if n < 0 {
            write_all(STDERR, b"sum: read error on ");
            if !name_for_output.is_null() {
                write_cstr(STDERR, name_for_output);
            } else {
                write_all(STDERR, b"stdin");
            }
            write_all(STDERR, b"\n");
            return false;
        }
        let got = n as usize;
        match algo {
            Algo::Bsd => {
                let mut k = 0;
                while k < got {
                    // 16-bit rotate right by one, then add the byte.
                    bsd = (bsd >> 1) | ((bsd & 1) << 15);
                    bsd = bsd.wrapping_add(buf[k] as u16);
                    k += 1;
                }
            }
            Algo::SysV => {
                let mut k = 0;
                while k < got {
                    sysv = sysv.wrapping_add(buf[k] as u32);
                    k += 1;
                }
            }
        }
        len = len.saturating_add(got as u64);
    }

    match algo {
        Algo::Bsd => {
            let blocks = div_ceil_u64(len, 1024);
            // POSIX: BSD checksum is printed in 5-digit decimal (zero-padded).
            write_u32_width(STDOUT, bsd as u32, 5);
            write_all(STDOUT, b" ");
            write_u64(STDOUT, blocks);
        }
        Algo::SysV => {
            // Fold the 32-bit accumulator down to 16 bits, twice — handles
            // the carry produced by the first fold.
            let s1 = (sysv & 0xFFFF) + (sysv >> 16);
            let s2 = (s1 & 0xFFFF) + (s1 >> 16);
            let folded = (s2 & 0xFFFF) as u16;
            let blocks = div_ceil_u64(len, 512);
            write_u32(STDOUT, folded as u32);
            write_all(STDOUT, b" ");
            write_u64(STDOUT, blocks);
        }
    }

    if name_for_output.is_null() {
        write_all(STDOUT, b"\n");
    } else {
        write_all(STDOUT, b" ");
        write_cstr(STDOUT, name_for_output);
        write_all(STDOUT, b"\n");
    }
    true
}

/// Ceiling division for `u64`, used to round bytes up to whole blocks.
#[inline(always)]
fn div_ceil_u64(n: u64, d: u64) -> u64 {
    if n == 0 { 0 } else { (n - 1) / d + 1 }
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

/// Format a `u32` as decimal ASCII and write it. No allocation.
fn write_u32(fd: i32, v: u32) {
    write_u64(fd, v as u64);
}

/// Format a `u32` as decimal ASCII zero-padded to at least `width` digits.
/// `width` is clamped at 10 (the maximum number of decimal digits in `u32`).
fn write_u32_width(fd: i32, mut v: u32, width: usize) {
    let mut buf = [b'0'; 10];
    let cap = buf.len();
    let mut idx = cap;
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
    let want = if width > cap { cap } else { width };
    let have = cap - idx;
    let start = if have >= want { idx } else { cap - want };
    write_all(fd, &buf[start..]);
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
    write_all(STDERR, b"sum: panic\n");
    libc::exit(1)
}
