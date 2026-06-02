// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/uniq` — filter adjacent duplicate lines.
//!
//! Usage:
//!   uniq [-c] [-d] [-u]
//!
//! Reads stdin, compares each line to the previous, and emits a single
//! representative for each run of identical lines. POSIX flags:
//!   -c   prefix each line with its run length, then a space
//!   -d   only emit lines that appeared at least twice (a real duplicate run)
//!   -u   only emit lines that appeared exactly once (no duplicates)
//!
//! `-d` and `-u` are mutually exclusive in the strict POSIX sense; we
//! accept both being set but in that case nothing is emitted (the
//! intersection of "duplicated" and "unique" is empty), which matches
//! GNU coreutils behaviour.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/uniq.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

/// Maximum line length supported by the streaming buffer.
const LINE_MAX: usize = 4096;

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym uniq_main,
    );
}

extern "C" fn uniq_main(argc: usize, argv: *const *const u8) -> ! {
    let mut count = false;
    let mut only_dup = false;
    let mut only_uniq = false;
    let mut idx = 1usize;

    while idx < argc {
        // SAFETY: idx < argc.
        let arg = unsafe { cstr_at(argv, idx) };
        if arg == b"-c" {
            count = true;
        } else if arg == b"-d" {
            only_dup = true;
        } else if arg == b"-u" {
            only_uniq = true;
        } else if arg == b"--" {
            idx += 1;
            break;
        } else if !arg.is_empty() && arg[0] == b'-' {
            write_err(b"uniq: unknown option\n");
            libc::exit(1);
        } else {
            break;
        }
        idx += 1;
    }

    // Streaming line reader. Two line buffers — `prev` holds the
    // representative of the current run; `cur` is the line just
    // assembled. We emit `prev` when the run breaks (or at EOF).
    let mut prev = [0u8; LINE_MAX];
    let mut prev_len = 0usize;
    let mut prev_count: u64 = 0;
    let mut have_prev = false;

    let mut cur = [0u8; LINE_MAX];
    let mut cur_len = 0usize;
    let mut cur_overflowed = false;

    let mut readbuf = [0u8; 4096];
    loop {
        // SAFETY: readbuf is owned and writable.
        let n = unsafe { libc::read(0, readbuf.as_mut_ptr(), readbuf.len()) };
        if n <= 0 {
            break;
        }
        for &b in &readbuf[..n as usize] {
            if b == b'\n' {
                if !cur_overflowed {
                    handle_line(
                        &cur[..cur_len],
                        &mut prev,
                        &mut prev_len,
                        &mut prev_count,
                        &mut have_prev,
                        count,
                        only_dup,
                        only_uniq,
                    );
                }
                cur_len = 0;
                cur_overflowed = false;
            } else if cur_len < cur.len() {
                cur[cur_len] = b;
                cur_len += 1;
            } else {
                cur_overflowed = true;
            }
        }
    }
    // Trailing line without newline — POSIX says still process it.
    if cur_len > 0 && !cur_overflowed {
        handle_line(
            &cur[..cur_len],
            &mut prev,
            &mut prev_len,
            &mut prev_count,
            &mut have_prev,
            count,
            only_dup,
            only_uniq,
        );
    }
    if have_prev {
        emit_run(&prev[..prev_len], prev_count, count, only_dup, only_uniq);
    }

    libc::exit(0)
}

#[allow(clippy::too_many_arguments)]
fn handle_line(
    line: &[u8],
    prev: &mut [u8; LINE_MAX],
    prev_len: &mut usize,
    prev_count: &mut u64,
    have_prev: &mut bool,
    count: bool,
    only_dup: bool,
    only_uniq: bool,
) {
    if *have_prev && line == &prev[..*prev_len] {
        *prev_count += 1;
        return;
    }
    if *have_prev {
        emit_run(&prev[..*prev_len], *prev_count, count, only_dup, only_uniq);
    }
    let n = line.len().min(prev.len());
    prev[..n].copy_from_slice(&line[..n]);
    *prev_len = n;
    *prev_count = 1;
    *have_prev = true;
}

fn emit_run(line: &[u8], run_count: u64, count: bool, only_dup: bool, only_uniq: bool) {
    let is_dup = run_count > 1;
    if only_dup && !is_dup {
        return;
    }
    if only_uniq && is_dup {
        return;
    }
    if count {
        let mut buf = [0u8; 24];
        let n = format_u64(run_count, &mut buf);
        let _ = write_all(1, &buf[..n]);
        let _ = write_all(1, b" ");
    }
    let _ = write_all(1, line);
    let _ = write_all(1, b"\n");
}

fn format_u64(value: u64, out: &mut [u8]) -> usize {
    if value == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 24];
    let mut n = value;
    let mut len = 0usize;
    while n > 0 {
        tmp[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    for i in 0..len {
        out[i] = tmp[len - 1 - i];
    }
    len
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
    write_err(b"uniq: panic\n");
    libc::exit(1)
}
