// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/head` — POSIX.1-2024 `head` utility.
//!
//! Prints the first N lines (default 10) from stdin or a named file.
//! Supports `-n N` to override the line count. Exits 0 on success, 1 on error.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/head.html`

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
        main = sym head_main,
    );
}

// ---------------------------------------------------------------------------
// Head logic (POSIX.1-2024)
// ---------------------------------------------------------------------------

const CHUNK: usize = 4096;
const DEFAULT_LINES: u64 = 10;

extern "C" fn head_main(argc: usize, argv: *const *const u8) -> ! {
    let mut n_lines = DEFAULT_LINES;
    let mut file_idx = 1usize;
    let mut exit_code: i32 = 0;

    // Parse optional `-n N` flag.
    if argc >= 3 {
        // SAFETY: argv has at least `argc` valid pointers.
        let flag = unsafe { argv.add(1).read() };
        if !flag.is_null() && parse_flag_n(flag) {
            // SAFETY: flag is valid null-terminated string.
            let val_ptr = unsafe { argv.add(2).read() };
            if !val_ptr.is_null() {
                n_lines = parse_u64(val_ptr).unwrap_or(DEFAULT_LINES);
                file_idx = 3;
            }
        }
    }

    if file_idx >= argc {
        // No file operands — read stdin.
        if !head_fd(0, n_lines) {
            exit_code = 1;
        }
    } else {
        for i in file_idx..argc {
            // SAFETY: argv has at least `argc` valid non-null pointers.
            let ptr = unsafe { argv.add(i).read() };
            if ptr.is_null() {
                break;
            }
            // SAFETY: ptr is null-terminated argv string.
            let fd = unsafe { libc::open(ptr, 0, 0) };
            if fd < 0 {
                write_all(2, b"head: cannot open file\n");
                exit_code = 1;
                continue;
            }
            if !head_fd(fd as i32, n_lines) {
                exit_code = 1;
            }
            libc::close(fd as i32);
        }
    }

    libc::exit(exit_code)
}

/// Returns true if `ptr` points to the two-byte string "-n\0".
fn parse_flag_n(ptr: *const u8) -> bool {
    // SAFETY: ptr is a null-terminated argv string of at least 1 byte.
    unsafe { ptr.read() == b'-' && ptr.add(1).read() == b'n' && ptr.add(2).read() == 0 }
}

/// Parse a null-terminated ASCII decimal string. Returns None on parse failure.
fn parse_u64(ptr: *const u8) -> Option<u64> {
    let mut n = 0u64;
    let mut i = 0usize;
    loop {
        // SAFETY: ptr is a null-terminated argv string.
        let byte = unsafe { ptr.add(i).read() };
        if byte == 0 {
            break;
        }
        if !byte.is_ascii_digit() {
            return None;
        }
        n = n.saturating_mul(10).saturating_add((byte - b'0') as u64);
        i += 1;
    }
    if i == 0 { None } else { Some(n) }
}

/// Print the first `n_lines` lines from `fd`. Returns true on clean completion.
fn head_fd(fd: i32, n_lines: u64) -> bool {
    let mut buf = [0u8; CHUNK];
    let mut remaining = n_lines;

    loop {
        if remaining == 0 {
            break;
        }
        // SAFETY: buf is valid writable storage of CHUNK bytes.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr(), CHUNK) };
        if n == 0 {
            break; // EOF
        }
        if n < 0 {
            write_all(2, b"head: read error\n");
            return false;
        }
        let slice = &buf[..n as usize];
        let mut start = 0usize;
        for (idx, &byte) in slice.iter().enumerate() {
            if byte == b'\n' {
                write_all(1, &slice[start..=idx]);
                start = idx + 1;
                remaining -= 1;
                if remaining == 0 {
                    break;
                }
            }
        }
        // If we stopped mid-line (remaining == 0 and start < n), the partial
        // line is not written — POSIX head only outputs complete lines.
        // If remaining > 0 and start < n, there's a partial last line in the
        // buffer with no trailing newline; write it only at EOF.
        if remaining > 0 && start < n as usize {
            // Peek: we didn't exhaust line budget, this is a partial final chunk.
            // We must write it if EOF comes next — easiest: just write it now
            // since remaining > 0 means we still want output.
            write_all(1, &slice[start..]);
        }
    }
    true
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
    write_all(2, b"head: panic\n");
    libc::exit(1)
}
