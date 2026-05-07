// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/dirname` — strip the last component from a path.
//!
//! Usage:
//!   dirname PATH
//!
//! POSIX.1-2024 semantics:
//! 1. If PATH is empty, print "." and exit 0.
//! 2. If PATH contains no '/', print "." and exit 0.
//! 3. If PATH is "/" (or all '/'), print "/".
//! 4. Otherwise strip trailing slashes, strip the last component, then
//!    strip the trailing slash that separated it (or print "/" if the
//!    result becomes empty).
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/dirname.html`

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
        main = sym dirname_main,
    );
}

extern "C" fn dirname_main(argc: usize, argv: *const *const u8) -> ! {
    if argc < 2 {
        write_err(b"dirname: missing operand\n");
        libc::exit(1);
    }

    // SAFETY: argv[1] is a valid C string supplied by the kernel.
    let path = unsafe { cstr_at(argv, 1) };

    let mut buf = [0u8; 256];
    let result = compute_dirname(path, &mut buf);
    write_line(result);
    libc::exit(0)
}

/// Strip the last component per POSIX.1-2024 dirname(1).
fn compute_dirname<'a>(path: &[u8], out: &'a mut [u8]) -> &'a [u8] {
    if path.is_empty() {
        out[0] = b'.';
        return &out[..1];
    }
    // All slashes: yields "/".
    if path.iter().all(|&b| b == b'/') {
        out[0] = b'/';
        return &out[..1];
    }
    // No slash at all: yields ".".
    if !path.contains(&b'/') {
        out[0] = b'.';
        return &out[..1];
    }

    // Strip trailing slashes (but keep at least one byte).
    let mut end = path.len();
    while end > 1 && path[end - 1] == b'/' {
        end -= 1;
    }
    let trimmed = &path[..end];

    // Find the last '/' in the trimmed path.
    let last_slash = trimmed.iter().rposition(|&b| b == b'/').unwrap_or(0);
    if last_slash == 0 {
        // Path was like "foo" (no slash) — handled earlier; or "/foo".
        // For "/foo" the head before the slash is empty, dirname is "/".
        out[0] = b'/';
        return &out[..1];
    }

    // Strip trailing slashes from the head.
    let mut head_end = last_slash;
    while head_end > 1 && trimmed[head_end - 1] == b'/' {
        head_end -= 1;
    }
    let head = &trimmed[..head_end];

    let n = head.len().min(out.len());
    out[..n].copy_from_slice(&head[..n]);
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
    write_err(b"dirname: panic\n");
    libc::exit(1)
}
