// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/printenv` — print environment variables.
//!
//! With no operand: prints every `NAME=VALUE` entry from the inherited
//! environment, each followed by a newline. Today ONCRIX's `execve` ships
//! an empty `envp`, so the no-arg invocation is observationally a no-op
//! that still exits 0 — but the codepath is in place for when inherited
//! environment gains real entries.
//!
//! With one operand `NAME`: walks `envp` for an entry whose key (the
//! bytes up to the first `=`) matches `NAME`. On a match, the value
//! (bytes after the `=`) plus a trailing newline is written to stdout
//! and the process exits 0. On no match, exit status is 1. Additional
//! operands beyond the first are ignored, matching the common
//! single-name lookup form documented by GNU coreutils.
//!
//! Per the System V AMD64 ABI the initial stack is:
//! ```text
//! [rsp]              = argc
//! [rsp + 8]          = argv[0]
//! ...
//! [rsp + 8*argc]     = argv[argc-1]
//! [rsp + 8*(argc+1)] = NULL          (end of argv)
//! [rsp + 8*(argc+2)] = envp[0]
//! ...
//! ```
//!
//! POSIX reference: `printenv` is not specified by POSIX.1-2024; this
//! follows the de facto GNU coreutils behavior. See also the `env`
//! utility at `.priv-storage/.TheOpenGroup/susv5-html/utilities/env.html`
//! for the broader environment-handling family.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Entry point — naked, captures argc / argv / envp from the SysV AMD64 stack.
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        // rdi = argc
        "mov rdi, [rsp]",
        // rsi = &argv[0]
        "lea rsi, [rsp + 8]",
        // rdx = &envp[0] = rsi + 8*(argc+1) = rsi + 8*argc + 8
        "lea rdx, [rsi + rdi*8 + 8]",
        "call {main}",
        "ud2",
        main = sym printenv_main,
    );
}

// ---------------------------------------------------------------------------
// printenv logic
// ---------------------------------------------------------------------------

extern "C" fn printenv_main(argc: usize, argv: *const *const u8, envp: *const *const u8) -> ! {
    if argc < 2 {
        // No NAME argument: dump the full inherited environment.
        let mut i = 0usize;
        loop {
            // SAFETY: envp is a NULL-terminated array of pointers laid out
            // by the kernel on the initial stack.
            let ptr = unsafe { envp.add(i).read() };
            if ptr.is_null() {
                break;
            }
            // SAFETY: each envp entry is a NUL-terminated C string.
            let len = unsafe { c_strlen(ptr) };
            // SAFETY: len matches the C-string body, exclusive of the NUL.
            write_all_raw(1, ptr, len);
            write_all(1, b"\n");
            i += 1;
        }
        libc::exit(0)
    }

    // argc >= 2 — look up argv[1] as the variable name.
    // SAFETY: argv has at least argc + 1 entries (the +1 is the trailing
    // NULL); index 1 is in range when argc >= 2.
    let name_ptr = unsafe { argv.add(1).read() };
    if name_ptr.is_null() {
        libc::exit(1)
    }
    // SAFETY: argv entries are NUL-terminated C strings.
    let name_len = unsafe { c_strlen(name_ptr) };

    let mut i = 0usize;
    loop {
        // SAFETY: envp is NULL-terminated; we stop when we hit the NULL.
        let entry = unsafe { envp.add(i).read() };
        if entry.is_null() {
            break;
        }
        // Locate the `=` separating KEY from VALUE.
        // SAFETY: entry is a NUL-terminated C string from the kernel envp.
        if let Some(eq_pos) = unsafe { find_eq(entry) } {
            if eq_pos == name_len && entry_key_eq(entry, name_ptr, name_len) {
                // SAFETY: entry has at least eq_pos + 1 bytes (the `=`); the
                // value continues until the NUL terminator.
                let value_ptr = unsafe { entry.add(eq_pos + 1) };
                // SAFETY: value_ptr points into the same NUL-terminated string.
                let value_len = unsafe { c_strlen(value_ptr) };
                write_all_raw(1, value_ptr, value_len);
                write_all(1, b"\n");
                libc::exit(0)
            }
        }
        i += 1;
    }

    // Not found.
    libc::exit(1)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Length of a NUL-terminated C string, exclusive of the terminator.
///
/// # Safety
///
/// `ptr` must point to a readable NUL-terminated byte sequence.
unsafe fn c_strlen(ptr: *const u8) -> usize {
    let mut n = 0usize;
    loop {
        // SAFETY: caller guarantees ptr is NUL-terminated.
        let b = unsafe { ptr.add(n).read() };
        if b == 0 {
            return n;
        }
        n += 1;
    }
}

/// Find the offset of the first `=` in a NUL-terminated C string, or `None`
/// if no `=` appears before the NUL.
///
/// # Safety
///
/// `ptr` must point to a readable NUL-terminated byte sequence.
unsafe fn find_eq(ptr: *const u8) -> Option<usize> {
    let mut n = 0usize;
    loop {
        // SAFETY: caller guarantees ptr is NUL-terminated.
        let b = unsafe { ptr.add(n).read() };
        if b == 0 {
            return None;
        }
        if b == b'=' {
            return Some(n);
        }
        n += 1;
    }
}

/// Compare `entry[..name_len]` with the `name_ptr` C string of length
/// `name_len`. Returns `true` only when every byte matches.
fn entry_key_eq(entry: *const u8, name_ptr: *const u8, name_len: usize) -> bool {
    for i in 0..name_len {
        // SAFETY: caller has already established both strings have at
        // least `name_len` readable bytes (entry up to its `=`, name up
        // to its NUL).
        let a = unsafe { entry.add(i).read() };
        let b = unsafe { name_ptr.add(i).read() };
        if a != b {
            return false;
        }
    }
    true
}

/// Write all bytes from a raw pointer/length to `fd`, retrying on short
/// writes.
fn write_all_raw(fd: i32, ptr: *const u8, len: usize) {
    let mut pos = 0;
    while pos < len {
        // SAFETY: the caller passes a valid pointer covering `len` bytes;
        // we only advance within that range.
        let n = unsafe { libc::write(fd, ptr.wrapping_add(pos), len - pos) };
        if n <= 0 {
            break;
        }
        pos += n as usize;
    }
}

/// Write all bytes in `buf` to `fd`, retrying on short writes.
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
    libc::exit(1)
}
