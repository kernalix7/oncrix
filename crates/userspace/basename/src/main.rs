// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/basename` — strip directory and optionally suffix from a path.
//!
//! Usage:
//!   basename PATH
//!   basename PATH SUFFIX
//!
//! POSIX.1-2024 semantics:
//! 1. If PATH is empty, print "." and exit 0.
//! 2. If PATH consists entirely of '/', print "/" and exit 0.
//! 3. Otherwise strip trailing slashes, then strip leading directories,
//!    then optionally remove the trailing SUFFIX (only if it's not equal
//!    to the entire result).
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/basename.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym basename_main,
    );
}

extern "C" fn basename_main(argc: usize, argv: *const *const u8) -> ! {
    if argc < 2 {
        write_err(b"basename: missing operand\n");
        libc::exit(1);
    }

    // SAFETY: argv[1..argc] are valid C strings supplied by the kernel.
    let path = unsafe { cstr_at(argv, 1) };
    let suffix = if argc >= 3 {
        // SAFETY: same.
        Some(unsafe { cstr_at(argv, 2) })
    } else {
        None
    };

    let mut buf = [0u8; 256];
    let result = compute_basename(path, suffix, &mut buf);
    write_line(result);
    libc::exit(0)
}

/// Strip directory and optional suffix per POSIX.1-2024 basename(1).
///
/// Returns a slice into `out` containing the result.
fn compute_basename<'a>(path: &[u8], suffix: Option<&[u8]>, out: &'a mut [u8]) -> &'a [u8] {
    if path.is_empty() {
        out[0] = b'.';
        return &out[..1];
    }

    // If path is all slashes, return "/".
    if path.iter().all(|&b| b == b'/') {
        out[0] = b'/';
        return &out[..1];
    }

    // Strip trailing slashes.
    let mut end = path.len();
    while end > 1 && path[end - 1] == b'/' {
        end -= 1;
    }
    let trimmed = &path[..end];

    // Strip leading directories: keep everything after the last '/'.
    let start = trimmed.iter().rposition(|&b| b == b'/').map_or(0, |p| p + 1);
    let stripped = &trimmed[start..];

    // Optionally strip the trailing suffix, but only if it's not the whole name.
    let final_slice = match suffix {
        Some(sfx) if !sfx.is_empty() && stripped.len() > sfx.len() && stripped.ends_with(sfx) => {
            &stripped[..stripped.len() - sfx.len()]
        }
        _ => stripped,
    };

    let n = final_slice.len().min(out.len());
    out[..n].copy_from_slice(&final_slice[..n]);
    &out[..n]
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

fn write_line(msg: &[u8]) {
    write_to(1, msg);
    write_to(1, b"\n");
}

fn write_err(msg: &[u8]) {
    write_to(2, msg);
}

fn write_to(fd: i32, msg: &[u8]) {
    let mut pos = 0;
    while pos < msg.len() {
        // SAFETY: msg is a valid byte slice; pointer is in-bounds.
        let n = unsafe { libc::write(fd, msg[pos..].as_ptr(), msg.len() - pos) };
        if n <= 0 {
            break;
        }
        pos += n as usize;
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_err(b"basename: panic\n");
    libc::exit(1)
}
