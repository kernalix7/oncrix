// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/wc` — POSIX.1-2024 `wc` utility.
//!
//! Counts lines, words, and bytes from stdin or a named file. Output format
//! matches POSIX default (`-lwc`): "  L  W  B filename\n". No flag parsing
//! in v1; all three counts are always printed.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/wc.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// `_start` must be a *naked* function — see `cat`/`echo` for the
/// rationale (Rust prologue would shift `[rsp]` away from argc).
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym wc_main,
    );
}

// ---------------------------------------------------------------------------
// Wc logic (POSIX.1-2024)
// ---------------------------------------------------------------------------

const CHUNK: usize = 4096;

/// Counts held for a single input source.
struct Counts {
    lines: u64,
    words: u64,
    bytes: u64,
}

impl Counts {
    const fn zero() -> Self {
        Self {
            lines: 0,
            words: 0,
            bytes: 0,
        }
    }
}

extern "C" fn wc_main(argc: usize, argv: *const *const u8) -> ! {
    let mut exit_code: i32 = 0;

    if argc <= 1 {
        let counts = count_fd(0);
        print_counts(&counts, b"");
    } else {
        for i in 1..argc {
            // SAFETY: argv has at least `argc` valid non-null pointers.
            let ptr = unsafe { argv.add(i).read() };
            if ptr.is_null() {
                break;
            }

            // SAFETY: ptr is a null-terminated argv string from sys_execve.
            let fd = unsafe { libc::open(ptr, 0, 0) };
            if fd < 0 {
                write_all(2, b"wc: cannot open file\n");
                exit_code = 1;
                continue;
            }
            let counts = count_fd(fd as i32);
            libc::close(fd as i32);
            // SAFETY: ptr is a valid null-terminated argv string.
            print_counts(&counts, ptr_as_slice(ptr));
        }
    }

    libc::exit(exit_code)
}

/// Count lines, words, and bytes from `fd`.
fn count_fd(fd: i32) -> Counts {
    let mut buf = [0u8; CHUNK];
    let mut c = Counts::zero();
    let mut in_word = false;

    loop {
        // SAFETY: buf is valid writable storage of CHUNK bytes.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr(), CHUNK) };
        if n <= 0 {
            break;
        }
        let slice = &buf[..n as usize];
        c.bytes += n as u64;
        for &byte in slice {
            if byte == b'\n' {
                c.lines += 1;
            }
            let is_space = matches!(byte, b' ' | b'\t' | b'\n' | b'\r');
            if is_space {
                in_word = false;
            } else if !in_word {
                in_word = true;
                c.words += 1;
            }
        }
    }
    c
}

/// Print counts in POSIX `wc` default format.
fn print_counts(c: &Counts, name: &[u8]) {
    // Format: right-aligned 7-char fields for lines, words, bytes.
    write_u64_field(c.lines);
    write_u64_field(c.words);
    write_u64_field(c.bytes);
    if !name.is_empty() {
        write_all(1, b" ");
        write_all(1, name);
    }
    write_all(1, b"\n");
}

/// Write a u64 right-aligned in a 7-char field followed by a space.
fn write_u64_field(n: u64) {
    // Produce ASCII digits into a stack buffer (max 20 digits for u64).
    let mut tmp = [0u8; 20];
    let mut pos = 20usize;
    let mut val = n;
    if val == 0 {
        pos -= 1;
        tmp[pos] = b'0';
    } else {
        while val > 0 {
            pos -= 1;
            tmp[pos] = b'0' + (val % 10) as u8;
            val /= 10;
        }
    }
    let digits = &tmp[pos..]; // length 1..=20

    // Build a 8-byte field: 7 chars right-aligned + trailing space.
    let mut field = [b' '; 8];
    let dlen = digits.len().min(7);
    let start = 7 - dlen;
    field[start..7].copy_from_slice(&digits[..dlen]);
    write_all(1, &field);
}

/// Turn a null-terminated C string pointer into a byte slice (without the null).
fn ptr_as_slice(ptr: *const u8) -> &'static [u8] {
    let mut len = 0usize;
    // SAFETY: ptr is a null-terminated argv string.
    while unsafe { ptr.add(len).read() } != 0 {
        len += 1;
    }
    if len == 0 {
        return b"";
    }
    // SAFETY: ptr is valid for `len` bytes (we just verified it).
    unsafe { core::slice::from_raw_parts(ptr, len) }
}

// ---------------------------------------------------------------------------
// I/O helpers
// ---------------------------------------------------------------------------

fn write_all(fd: i32, buf: &[u8]) {
    let mut pos = 0;
    while pos < buf.len() {
        // SAFETY: buf slice is valid for buf.len() bytes.
        let n = unsafe { libc::write(fd, buf[pos..].as_ptr(), buf.len() - pos) };
        if n <= 0 {
            break;
        }
        pos += n as usize;
    }
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_all(2, b"wc: panic\n");
    libc::exit(1)
}
