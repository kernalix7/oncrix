// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/tail` — POSIX.1-2024 `tail` utility.
//!
//! Prints the last N lines (default 10) from stdin or a named file.
//! Strategy: read into a 4 KiB sliding window (shift-by-half when full),
//! then walk backwards from the end counting newlines.
//! Exits 0 on success, 1 on error.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/tail.html`

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
        main = sym tail_main,
    );
}

// ---------------------------------------------------------------------------
// Tail logic (POSIX.1-2024)
// ---------------------------------------------------------------------------

/// Fixed read buffer. For inputs larger than this we keep only the tail
/// BUF_SIZE bytes, which is sufficient to find the last DEFAULT_LINES lines
/// of any typical text file.
const BUF_SIZE: usize = 4096;
const DEFAULT_LINES: u64 = 10;

extern "C" fn tail_main(argc: usize, argv: *const *const u8) -> ! {
    let mut n_lines = DEFAULT_LINES;
    let mut file_idx = 1usize;
    let mut exit_code: i32 = 0;

    // Parse optional `-n N` flag.
    if argc >= 3 {
        // SAFETY: argv has at least `argc` valid pointers.
        let flag = unsafe { argv.add(1).read() };
        if !flag.is_null() && parse_flag_n(flag) {
            // SAFETY: argv[2] is within the valid argv range.
            let val_ptr = unsafe { argv.add(2).read() };
            if !val_ptr.is_null() {
                n_lines = parse_u64(val_ptr).unwrap_or(DEFAULT_LINES);
                file_idx = 3;
            }
        }
    }

    if file_idx >= argc {
        if !tail_fd(0, n_lines) {
            exit_code = 1;
        }
    } else {
        for i in file_idx..argc {
            // SAFETY: argv has at least `argc` valid non-null pointers.
            let ptr = unsafe { argv.add(i).read() };
            if ptr.is_null() {
                break;
            }
            // SAFETY: ptr is a null-terminated argv string.
            let fd = unsafe { libc::open(ptr, 0, 0) };
            if fd < 0 {
                write_all(2, b"tail: cannot open file\n");
                exit_code = 1;
                continue;
            }
            if !tail_fd(fd as i32, n_lines) {
                exit_code = 1;
            }
            libc::close(fd as i32);
        }
    }

    libc::exit(exit_code)
}

/// Returns true if `ptr` is the two-byte string "-n\0".
fn parse_flag_n(ptr: *const u8) -> bool {
    // SAFETY: ptr is a null-terminated argv string of at least 1 byte.
    unsafe { ptr.read() == b'-' && ptr.add(1).read() == b'n' && ptr.add(2).read() == 0 }
}

/// Parse a null-terminated ASCII decimal string. Returns None on failure.
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

/// Print the last `n_lines` lines from `fd`. Returns true on clean completion.
///
/// Maintains a sliding 4 KiB window: when the buffer fills, the first half is
/// discarded and data is shifted down, keeping the most-recent bytes.
fn tail_fd(fd: i32, n_lines: u64) -> bool {
    let mut buf = [0u8; BUF_SIZE];
    // `filled` tracks how many bytes are valid starting from buf[0].
    let mut filled = 0usize;

    loop {
        let avail = BUF_SIZE - filled;
        if avail == 0 {
            // Buffer full: discard first half to make room.
            let half = BUF_SIZE / 2;
            buf.copy_within(half.., 0);
            filled = BUF_SIZE - half;
            continue;
        }
        // SAFETY: buf[filled..filled+avail] is valid writable storage.
        let n = unsafe { libc::read(fd, buf[filled..].as_mut_ptr(), avail) };
        if n == 0 {
            break; // EOF
        }
        if n < 0 {
            write_all(2, b"tail: read error\n");
            return false;
        }
        filled += n as usize;
    }

    let data = &buf[..filled];
    if data.is_empty() {
        return true;
    }

    // Walk backwards counting newlines to locate the tail boundary.
    // Skip a trailing newline so it does not count as an empty final line.
    let scan_end = if data.last() == Some(&b'\n') {
        data.len() - 1
    } else {
        data.len()
    };

    let mut newlines_seen = 0u64;
    let mut start_idx = 0usize;
    let mut i = scan_end;
    while i > 0 {
        i -= 1;
        if data[i] == b'\n' {
            newlines_seen += 1;
            if newlines_seen == n_lines {
                start_idx = i + 1;
                break;
            }
        }
    }
    // If we saw fewer newlines than requested, start_idx stays 0 (whole file).

    write_all(1, &data[start_idx..]);
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
    write_all(2, b"tail: panic\n");
    libc::exit(1)
}
