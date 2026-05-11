// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/id` — POSIX.1-2024 `id` utility.
//!
//! ONCRIX has no user database yet, so every process runs as
//! `uid=0`/`gid=0` (the `root` user, group `root`). Output is therefore
//! a fixed identity string.
//!
//! Supported invocations:
//! - `id` — `uid=0(root) gid=0(root) groups=0(root)\n`
//! - `id -u` — `0\n`
//! - `id -g` — `0\n`
//! - `id -G` — `0\n`
//! - `id -un` / `id -gn` / `id -nu` / `id -ng` — `root\n`
//! - `id <name>` — same as the no-arg form when `<name> == "root"`;
//!   otherwise prints `id: <name>: no such user` to stderr and exits 1.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/id.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// `_start` must be a *naked* function so the Rust prologue does not
/// shift the initial stack before we read argc/argv.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym id_main,
    );
}

// ---------------------------------------------------------------------------
// id logic (POSIX.1-2024)
// ---------------------------------------------------------------------------

/// Parsed command-line flag combination.
#[derive(Copy, Clone)]
struct Flags {
    /// `-u` requested.
    show_uid: bool,
    /// `-g` requested.
    show_gid: bool,
    /// `-G` requested.
    show_all_gids: bool,
    /// `-n` requested (only meaningful with `-u` or `-g`).
    name_form: bool,
}

extern "C" fn id_main(argc: usize, argv: *const *const u8) -> ! {
    let mut flags = Flags {
        show_uid: false,
        show_gid: false,
        show_all_gids: false,
        name_form: false,
    };
    let mut operand: *const u8 = core::ptr::null();

    // Walk argv[1..]. Stop on first non-flag operand; only one operand
    // is accepted (POSIX permits at most one `user` operand).
    let mut i = 1usize;
    while i < argc {
        // SAFETY: argv has `argc` valid pointers from the kernel stack.
        let arg = unsafe { argv.add(i).read() };
        if arg.is_null() {
            break;
        }
        // SAFETY: argv entries are null-terminated C strings.
        let first = unsafe { arg.read() };
        if first == b'-' {
            // SAFETY: byte after '-' is part of the same NUL-terminated string.
            let second = unsafe { arg.add(1).read() };
            // Bare "-" is treated as an operand per POSIX; we don't accept it.
            if second == 0 {
                operand = arg;
                i += 1;
                continue;
            }
            // Walk every flag char in the cluster (e.g. "-un", "-Gn").
            let mut j = 1usize;
            loop {
                // SAFETY: walking within the same NUL-terminated argv string.
                let c = unsafe { arg.add(j).read() };
                if c == 0 {
                    break;
                }
                match c {
                    b'u' => flags.show_uid = true,
                    b'g' => flags.show_gid = true,
                    b'G' => flags.show_all_gids = true,
                    b'n' => flags.name_form = true,
                    _ => {
                        write_all(2, b"id: invalid option\n");
                        libc::exit(1);
                    }
                }
                j += 1;
            }
        } else {
            operand = arg;
        }
        i += 1;
    }

    // Validate the operand: only "root" is recognised.
    if !operand.is_null() && !cstr_eq(operand, b"root") {
        write_all(2, b"id: ");
        write_cstr(2, operand);
        write_all(2, b": no such user\n");
        libc::exit(1);
    }

    // POSIX: -u, -g, -G are mutually exclusive. If more than one was
    // given, reject. -n on its own (no -u/-g) is also an error.
    let selectors = (flags.show_uid as u8) + (flags.show_gid as u8) + (flags.show_all_gids as u8);
    if selectors > 1 {
        write_all(2, b"id: cannot print only one of -u, -g, -G\n");
        libc::exit(1);
    }
    if flags.name_form && selectors == 0 {
        write_all(2, b"id: cannot print only names without -u or -g\n");
        libc::exit(1);
    }
    // -n is meaningless with -G in POSIX (no portable behaviour); accept
    // it silently to mirror GNU coreutils, which prints "root".
    if flags.show_all_gids && flags.name_form {
        write_all(1, b"root\n");
        libc::exit(0);
    }

    if flags.show_uid || flags.show_gid {
        write_all(1, if flags.name_form { b"root\n" } else { b"0\n" });
    } else if flags.show_all_gids {
        write_all(1, b"0\n");
    } else {
        write_all(1, b"uid=0(root) gid=0(root) groups=0(root)\n");
    }

    libc::exit(0)
}

// ---------------------------------------------------------------------------
// I/O helpers
// ---------------------------------------------------------------------------

/// Write `buf` to `fd`, retrying on short writes. Errors are silently
/// dropped because there is no useful recovery from a failed `write(2)`
/// on stdout/stderr in a one-shot utility.
fn write_all(fd: i32, buf: &[u8]) {
    let mut pos = 0;
    while pos < buf.len() {
        // SAFETY: `buf` slice is valid for `buf.len()` bytes.
        let n = unsafe { libc::write(fd, buf[pos..].as_ptr(), buf.len() - pos) };
        if n <= 0 {
            break;
        }
        pos += n as usize;
    }
}

/// Write the NUL-terminated C string at `s` to `fd` (excluding the NUL).
fn write_cstr(fd: i32, s: *const u8) {
    let len = cstr_len(s);
    // SAFETY: `s` is a NUL-terminated string with `len` readable bytes.
    let n = unsafe { libc::write(fd, s, len) };
    let _ = n;
}

/// Length of the NUL-terminated C string at `s`, excluding the NUL.
fn cstr_len(s: *const u8) -> usize {
    let mut n = 0usize;
    // SAFETY: caller passes a NUL-terminated argv string.
    while unsafe { s.add(n).read() } != 0 {
        n += 1;
    }
    n
}

/// Returns `true` if the NUL-terminated C string at `s` equals `needle`.
fn cstr_eq(s: *const u8, needle: &[u8]) -> bool {
    let mut i = 0usize;
    while i < needle.len() {
        // SAFETY: `s` is NUL-terminated; reading byte-by-byte is in-bounds
        // until the NUL.
        let c = unsafe { s.add(i).read() };
        if c == 0 || c != needle[i] {
            return false;
        }
        i += 1;
    }
    // Must end exactly at the NUL — no trailing characters.
    // SAFETY: same as above.
    unsafe { s.add(i).read() == 0 }
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_all(2, b"id: panic\n");
    libc::exit(1)
}
