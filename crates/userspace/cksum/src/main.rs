// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/cksum` — POSIX.1-2024 file checksum utility (subset).
//!
//! Form:
//!   * `cksum [FILE...]` — for each FILE print `CRC LENGTH FILENAME` to
//!     stdout. With no operands or with a `-` operand, read from stdin; the
//!     trailing FILENAME field is omitted for stdin.
//!
//! Algorithm: POSIX cksum CRC-32 using the IEEE 802.3 polynomial
//! 0x04C11DB7 in length-augmented form. After folding all data bytes into
//! the running CRC, the byte length of the input is itself fed through the
//! CRC machinery (most-significant non-zero byte first), then the result is
//! XORed with 0xFFFFFFFF and printed as an unsigned 32-bit decimal.
//!
//! Exit status:
//!   * 0 — every operand processed successfully
//!   * 1 — one or more operands could not be opened or read
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/cksum.html`

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
        main = sym cksum_main,
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

// ---------------------------------------------------------------------------
// CRC-32 table (POSIX cksum / IEEE 802.3, polynomial 0x04C11DB7, normal form)
// ---------------------------------------------------------------------------

/// Build the 256-entry lookup table for byte-wise CRC-32 with the IEEE 802.3
/// polynomial in *non-reflected* form (the variant POSIX cksum uses).
///
/// The table is computed once at startup; doing it in code instead of as a
/// `const` array keeps the binary small.
fn build_crc_table() -> [u32; 256] {
    const POLY: u32 = 0x04C1_1DB7;
    let mut table = [0u32; 256];
    let mut i: u32 = 0;
    while i < 256 {
        let mut c = i << 24;
        let mut k = 0;
        while k < 8 {
            c = if c & 0x8000_0000 != 0 {
                (c << 1) ^ POLY
            } else {
                c << 1
            };
            k += 1;
        }
        table[i as usize] = c;
        i += 1;
    }
    table
}

/// Fold one byte into the running CRC using the precomputed table.
#[inline(always)]
fn crc_step(crc: u32, byte: u8, table: &[u32; 256]) -> u32 {
    (crc << 8) ^ table[((crc >> 24) ^ byte as u32) as usize]
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

extern "C" fn cksum_main(argc: usize, argv: *const *const u8) -> ! {
    let table = build_crc_table();

    let mut files: [*const u8; MAX_FILES] = [core::ptr::null(); MAX_FILES];
    let mut nfiles: usize = 0;

    // Argument parse: every operand is a file (or `-` for stdin). cksum
    // takes no flags in the POSIX subset we implement.
    let mut i = 1;
    while i < argc {
        // SAFETY: argv has at least `argc` valid pointers from execve.
        let ptr = unsafe { argv.add(i).read() };
        if ptr.is_null() {
            break;
        }
        if nfiles >= MAX_FILES {
            write_all(STDERR, b"cksum: too many file arguments\n");
            libc::exit(1);
        }
        files[nfiles] = ptr;
        nfiles += 1;
        i += 1;
    }

    let mut exit_code: i32 = 0;

    if nfiles == 0 {
        // No operands — checksum stdin, suppress filename in output.
        if !checksum_fd(STDIN, core::ptr::null(), &table, b"-") {
            exit_code = 1;
        }
    } else {
        let mut k = 0;
        while k < nfiles {
            if !checksum_operand(files[k], &table) {
                exit_code = 1;
            }
            k += 1;
        }
    }

    libc::exit(exit_code)
}

/// Process one operand: open it (or attach to stdin for `-`), checksum it,
/// emit one output line. Returns `true` on success, `false` on any error.
fn checksum_operand(path: *const u8, table: &[u32; 256]) -> bool {
    // SAFETY: path is a null-terminated argv pointer.
    let first = unsafe { path.read() };
    let second = unsafe { path.add(1).read() };

    if first == b'-' && second == 0 {
        // `-` operand: read stdin, but DO print "-" as the filename per
        // POSIX (the no-operand form is the one that suppresses the name).
        return checksum_fd(STDIN, path, table, b"-");
    }

    // SAFETY: path is a null-terminated argv pointer.
    let fd = unsafe { libc::open(path, libc::O_RDONLY, 0) };
    if fd < 0 {
        write_all(STDERR, b"cksum: cannot open ");
        write_cstr(STDERR, path);
        write_all(STDERR, b"\n");
        return false;
    }
    let fd = fd as i32;
    let ok = checksum_fd(fd, path, table, b"<file>");
    libc::close(fd);
    ok
}

/// Read every byte from `fd`, run the POSIX cksum CRC over it, and emit
/// `CRC LENGTH [FILENAME]\n`. `name_for_output` is non-null when the line
/// should include a trailing filename; pass null to suppress it (stdin form).
///
/// `err_label` is used purely for the `read error on …` diagnostic.
fn checksum_fd(fd: i32, name_for_output: *const u8, table: &[u32; 256], err_label: &[u8]) -> bool {
    let mut buf = [0u8; CHUNK];
    let mut crc: u32 = 0;
    let mut len: u64 = 0;

    loop {
        // SAFETY: buf is a stack array valid for CHUNK writable bytes.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr(), buf.len()) };
        if n == 0 {
            break;
        }
        if n < 0 {
            write_all(STDERR, b"cksum: read error on ");
            if !name_for_output.is_null() {
                write_cstr(STDERR, name_for_output);
            } else {
                write_all(STDERR, err_label);
            }
            write_all(STDERR, b"\n");
            return false;
        }
        let got = n as usize;
        let mut k = 0;
        while k < got {
            crc = crc_step(crc, buf[k], table);
            k += 1;
        }
        len = len.saturating_add(got as u64);
    }

    // Length-augmentation step: feed the byte length through the CRC,
    // most-significant non-zero byte first. POSIX phrases this as
    // serialising the length LSB-first via repeated `>>8` until zero, then
    // running those bytes back through the CRC in reverse order.
    let mut len_bytes = [0u8; 9];
    let mut nlen: usize = 0;
    let mut tmp = len;
    if tmp == 0 {
        // For empty input the spec still requires zero length bytes to be
        // emitted (no augmentation), so leave nlen at 0.
    } else {
        while tmp != 0 {
            len_bytes[nlen] = (tmp & 0xff) as u8;
            tmp >>= 8;
            nlen += 1;
        }
    }
    // Feed in reverse: last pushed byte (most significant non-zero) first.
    let mut idx = nlen;
    while idx > 0 {
        idx -= 1;
        crc = crc_step(crc, len_bytes[idx], table);
    }

    crc ^= 0xFFFF_FFFF;

    // Emit the result line.
    write_u32(STDOUT, crc);
    write_all(STDOUT, b" ");
    write_u64(STDOUT, len);
    if is_stdin_no_name(name_for_output) {
        write_all(STDOUT, b"\n");
    } else {
        write_all(STDOUT, b" ");
        write_cstr(STDOUT, name_for_output);
        write_all(STDOUT, b"\n");
    }
    true
}

/// Return `true` if `name` indicates the no-operand stdin form (null pointer)
/// where POSIX requires the filename column to be omitted.
fn is_stdin_no_name(name: *const u8) -> bool {
    name.is_null()
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

/// Format a `u32` as decimal ASCII and write it. No allocation.
fn write_u32(fd: i32, v: u32) {
    write_u64(fd, v as u64);
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
    write_all(STDERR, b"cksum: panic\n");
    libc::exit(1)
}
