// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/touch` — create empty files / update access & modification times.
//!
//! Usage:
//!   touch [-c] FILE...
//!
//! For each FILE:
//!   - If it does not exist and `-c` was not given, create it with mode 0o644
//!     via `open(path, O_WRONLY | O_CREAT, 0o644)` and immediately close.
//!   - If it does not exist and `-c` was given, silently skip.
//!   - If it already exists, opening it `O_RDONLY` is treated as success.
//!     Updating the access/modification timestamps is a no-op because the
//!     ONCRIX libc has no `futimens`/`utimensat` yet — the existing-file
//!     branch returns success without touching mtime/atime.
//!
//! Exit status: 0 if all files were processed successfully, 1 if any FILE
//! could not be opened/created. Per-file failures do not abort the loop.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/touch.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

/// Maximum number of FILE arguments accepted per invocation.
const MAX_FILES: usize = 16;

/// Maximum byte length of a single path argument (NUL terminator included).
const PATH_BUF: usize = 256;

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym touch_main,
    );
}

extern "C" fn touch_main(argc: usize, argv: *const *const u8) -> ! {
    let mut no_create = false;
    let mut idx = 1usize;

    // Parse leading option flags. Supported: `-c`, `--`.
    while idx < argc {
        // SAFETY: idx < argc, argv is a valid argv from the loader.
        let arg = unsafe { cstr_at(argv, idx) };
        if arg == b"-c" {
            no_create = true;
            idx += 1;
            continue;
        }
        if arg == b"--" {
            idx += 1;
            break;
        }
        if arg.len() > 1 && arg[0] == b'-' {
            write_err(b"touch: unknown option\n");
            libc::exit(1);
        }
        break;
    }

    if idx >= argc {
        write_err(b"touch: missing file operand\n");
        libc::exit(1);
    }

    let mut had_error = false;
    let mut processed = 0usize;
    while idx < argc && processed < MAX_FILES {
        // SAFETY: idx < argc.
        let path = unsafe { cstr_at(argv, idx) };
        if !touch_one(path, no_create) {
            had_error = true;
        }
        processed += 1;
        idx += 1;
    }

    if idx < argc {
        // More than MAX_FILES were supplied; remaining are ignored with error.
        write_err(b"touch: too many file operands\n");
        had_error = true;
    }

    libc::exit(if had_error { 1 } else { 0 })
}

/// Create or "touch" a single FILE. Returns `true` on success.
fn touch_one(path: &[u8], no_create: bool) -> bool {
    if path.is_empty() {
        write_err(b"touch: empty path\n");
        return false;
    }
    let mut buf = [0u8; PATH_BUF];
    if path.len() >= buf.len() {
        write_err(b"touch: path too long\n");
        return false;
    }
    buf[..path.len()].copy_from_slice(path);
    // buf[path.len()] is already 0 from initialization — NUL terminator.

    // First try to open the existing file read-only. If it succeeds, we are
    // done (no timestamp update available yet on ONCRIX).
    // SAFETY: buf is NUL-terminated within PATH_BUF bytes.
    let fd = unsafe { libc::open(buf.as_ptr(), libc::O_RDONLY, 0) };
    if fd >= 0 {
        let _ = libc::close(fd as i32);
        return true;
    }

    // File doesn't exist (or otherwise unreadable). With `-c`, treat
    // missing-file as a silent skip — POSIX: "shall not be created".
    if no_create {
        return true;
    }

    // Create the file with mode 0o644.
    // SAFETY: buf is NUL-terminated within PATH_BUF bytes.
    let fd = unsafe { libc::open(buf.as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o644) };
    if fd < 0 {
        write_err(b"touch: cannot create file\n");
        return false;
    }
    let _ = libc::close(fd as i32);
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

/// Read the C string at `argv[idx]` as a byte slice (NUL-terminated, no NUL
/// byte included in the slice). Returns an empty slice for null pointers.
///
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
    write_err(b"touch: panic\n");
    libc::exit(1)
}
