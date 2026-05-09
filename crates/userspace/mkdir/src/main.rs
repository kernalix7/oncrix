// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/mkdir` — create directories.
//!
//! Usage:
//!   mkdir [-p] [-m MODE] DIR...
//!
//! Options:
//!   -p          create parent directories as needed; succeed silently if the
//!               final DIR already exists.
//!   -m MODE     octal mode for newly created directories (default 0o755).
//!               Accepts forms `0755`, `755`, `0o755`. Applied to every
//!               directory the command itself creates; pre-existing parents
//!               are left untouched.
//!
//! For each DIR `mkdir(path, mode)` is invoked. Without `-p`, an EEXIST
//! result on DIR is an error. With `-p`, intermediate components are walked
//! left-to-right and EEXIST is tolerated on every component (including the
//! final one).
//!
//! Exit status: 0 if every DIR succeeded, 1 if any DIR failed. Per-DIR
//! failures do not abort the loop.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/mkdir.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

/// Maximum number of DIR arguments accepted per invocation.
const MAX_DIRS: usize = 16;

/// Maximum byte length of a single path argument (NUL terminator included).
const PATH_BUF: usize = 256;

/// Default mode applied to created directories when `-m` is not supplied.
const DEFAULT_MODE: u32 = 0o755;

/// Linux `EEXIST` errno value, returned by `mkdir` as `-17` when the target
/// path already exists.
const NEG_EEXIST: i64 = -17;

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym mkdir_main,
    );
}

extern "C" fn mkdir_main(argc: usize, argv: *const *const u8) -> ! {
    let mut parents = false;
    let mut mode: u32 = DEFAULT_MODE;
    let mut idx = 1usize;

    // Parse leading option flags. Supported: `-p`, `-m MODE`, `--`.
    while idx < argc {
        // SAFETY: idx < argc, argv is a valid argv from the loader.
        let arg = unsafe { cstr_at(argv, idx) };
        if arg == b"-p" {
            parents = true;
            idx += 1;
            continue;
        }
        if arg == b"-m" {
            idx += 1;
            if idx >= argc {
                write_err(b"mkdir: option requires an argument -- 'm'\n");
                libc::exit(1);
            }
            // SAFETY: idx < argc.
            let mode_arg = unsafe { cstr_at(argv, idx) };
            match parse_octal_mode(mode_arg) {
                Some(m) => mode = m,
                None => {
                    write_err(b"mkdir: invalid mode\n");
                    libc::exit(1);
                }
            }
            idx += 1;
            continue;
        }
        if arg == b"--" {
            idx += 1;
            break;
        }
        if arg.len() > 1 && arg[0] == b'-' {
            write_err(b"mkdir: unknown option\n");
            libc::exit(1);
        }
        break;
    }

    if idx >= argc {
        write_err(b"mkdir: missing operand\n");
        libc::exit(1);
    }

    let mut had_error = false;
    let mut processed = 0usize;
    while idx < argc && processed < MAX_DIRS {
        // SAFETY: idx < argc.
        let path = unsafe { cstr_at(argv, idx) };
        if !mkdir_one(path, mode, parents) {
            had_error = true;
        }
        processed += 1;
        idx += 1;
    }

    if idx < argc {
        write_err(b"mkdir: too many operands\n");
        had_error = true;
    }

    libc::exit(if had_error { 1 } else { 0 })
}

/// Create a single DIR. Returns `true` on success.
///
/// In `parents` mode, walks the path component-by-component and creates each
/// missing intermediate directory; `EEXIST` is tolerated on every component
/// including the final one. In normal mode, a single `mkdir` syscall is
/// issued and `EEXIST` is treated as an error.
fn mkdir_one(path: &[u8], mode: u32, parents: bool) -> bool {
    if path.is_empty() {
        write_err(b"mkdir: empty path\n");
        return false;
    }
    if path.len() >= PATH_BUF {
        write_err(b"mkdir: path too long\n");
        return false;
    }

    if !parents {
        let mut buf = [0u8; PATH_BUF];
        buf[..path.len()].copy_from_slice(path);
        // SAFETY: buf is NUL-terminated within PATH_BUF bytes.
        let rc = unsafe { libc::mkdir(buf.as_ptr(), mode) };
        if rc == 0 {
            return true;
        }
        write_err(b"mkdir: cannot create directory\n");
        return false;
    }

    // `-p` mode: progressively NUL-terminate at each separator and call
    // mkdir on the prefix. Tolerate EEXIST on every component.
    let mut buf = [0u8; PATH_BUF];
    buf[..path.len()].copy_from_slice(path);
    let len = path.len();

    let mut i = 0usize;
    // Skip a leading '/' so we never try to mkdir("") or mkdir("/").
    if buf[0] == b'/' {
        i = 1;
    }

    while i < len {
        // Advance to the next separator (or end of string).
        while i < len && buf[i] != b'/' {
            i += 1;
        }
        // Skip empty components produced by consecutive '/'.
        if i == 0 {
            i += 1;
            continue;
        }
        let saved = if i < len { buf[i] } else { 0 };
        buf[i] = 0;
        // SAFETY: buf[..=i] is NUL-terminated within PATH_BUF bytes.
        let rc = unsafe { libc::mkdir(buf.as_ptr(), mode) };
        if rc != 0 && rc != NEG_EEXIST {
            write_err(b"mkdir: cannot create directory\n");
            return false;
        }
        if i < len {
            buf[i] = saved;
            i += 1;
        }
    }
    true
}

/// Parse an octal mode string. Accepts `755`, `0755`, and `0o755` (any case
/// for the `o`). Returns `None` on empty, overlong, or non-octal input.
fn parse_octal_mode(s: &[u8]) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    let mut i = 0usize;
    if s[0] == b'0' && s.len() >= 2 && (s[1] == b'o' || s[1] == b'O') {
        i = 2;
    }
    if i >= s.len() {
        return None;
    }
    let mut value: u32 = 0;
    let mut digits = 0usize;
    while i < s.len() {
        let c = s[i];
        if !(b'0'..=b'7').contains(&c) {
            return None;
        }
        // Cap at 7 octal digits (21 bits) to keep the value within u32 and
        // reject absurd inputs like "07777777777777".
        if digits >= 7 {
            return None;
        }
        value = (value << 3) | u32::from(c - b'0');
        digits += 1;
        i += 1;
    }
    if digits == 0 { None } else { Some(value) }
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
/// # Safety
///
/// Caller guarantees `idx < argc` and `argv` is a valid argv pointer.
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
    write_err(b"mkdir: panic\n");
    libc::exit(1)
}
