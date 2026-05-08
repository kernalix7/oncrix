// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/rm` — remove (unlink) files.
//!
//! Usage:
//!   rm [-fiRr] FILE...
//!
//! POSIX.1-2024 semantics (subset):
//! - Each FILE is removed via `libc::unlink`. Per-file errors are reported
//!   to stderr and processing continues; exit status is 1 if any file
//!   failed, 0 otherwise.
//! - `-f` (force): suppress diagnostics for missing files (ENOENT, errno
//!   `-2`) and never let a missing file influence the exit status. Other
//!   errors are still reported.
//! - `-i` (interactive): accepted for POSIX compatibility but currently a
//!   no-op — ONCRIX has no terminal yes/no prompt path yet, so the flag
//!   behaves like the default unlink.
//! - `-r` / `-R` (recursive): accepted but unsupported. Recursive directory
//!   descent requires an `opendir`/`readdir` libc wrapper, which is not yet
//!   exposed. When set, rm prints a diagnostic and exits 1 without
//!   touching any file (refusing rather than silently mis-handling
//!   directories is the safer choice).
//!
//! Limits: up to 16 file operands; each path up to 255 bytes plus NUL.
//! No heap; all path buffers live on the stack.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/rm.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

/// Maximum number of file operands accepted in a single invocation.
const MAX_FILES: usize = 16;

/// Maximum path length (including the NUL terminator) for each operand.
const PATH_BUF_LEN: usize = 256;

/// Kernel errno value returned by `unlink` when the path does not exist.
const ENOENT: i64 = -2;

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym rm_main,
    );
}

extern "C" fn rm_main(argc: usize, argv: *const *const u8) -> ! {
    let mut force = false;
    let mut recursive = false;

    // Collect non-option operand indices (1-based into argv).
    let mut files: [usize; MAX_FILES] = [0; MAX_FILES];
    let mut nfiles = 0usize;
    let mut end_of_options = false;

    let mut i = 1usize;
    while i < argc {
        // SAFETY: 0 <= i < argc; the kernel guarantees argv[0..argc] are
        // valid C strings.
        let arg = unsafe { cstr_at(argv, i) };

        if !end_of_options && arg == b"--" {
            end_of_options = true;
        } else if !end_of_options && arg.len() >= 2 && arg[0] == b'-' && arg != b"-" {
            // Cluster of short options: -fiR etc.
            for &c in &arg[1..] {
                match c {
                    b'f' => force = true,
                    b'i' => { /* accepted, no-op (no terminal prompt yet). */ }
                    b'r' | b'R' => recursive = true,
                    _ => {
                        write_err(b"rm: invalid option: -");
                        write_err(&[c]);
                        write_err(b"\n");
                        libc::exit(1);
                    }
                }
            }
        } else if nfiles < MAX_FILES {
            files[nfiles] = i;
            nfiles += 1;
        } else {
            write_err(b"rm: too many file operands\n");
            libc::exit(1);
        }

        i += 1;
    }

    if nfiles == 0 {
        if force {
            // POSIX: `rm -f` with no operands is a silent success.
            libc::exit(0);
        }
        write_err(b"rm: missing operand\n");
        libc::exit(1);
    }

    if recursive {
        // No opendir/readdir wrapper yet — refuse rather than mis-handle.
        write_err(b"rm: -r/-R not supported yet (no recursive descent)\n");
        libc::exit(1);
    }

    let mut status: i32 = 0;

    for &idx in &files[..nfiles] {
        // SAFETY: idx was recorded only when 0 < idx < argc.
        let path = unsafe { cstr_at(argv, idx) };

        let mut buf = [0u8; PATH_BUF_LEN];
        let Some(cpath) = copy_cstring(path, &mut buf) else {
            // Path too long for our stack buffer; report and continue.
            write_err(b"rm: path too long: ");
            write_err(path);
            write_err(b"\n");
            status = 1;
            continue;
        };

        // SAFETY: `cpath` points into `buf`, which contains a NUL-terminated
        // copy of `path` valid for the duration of this call.
        let rc = unsafe { libc::unlink(cpath) };
        if rc < 0 {
            if force && rc == ENOENT {
                // -f silences missing files and does not flip exit status.
                continue;
            }
            write_err(b"rm: cannot remove '");
            write_err(path);
            write_err(b"': ");
            write_err(errno_message(rc));
            write_err(b"\n");
            status = 1;
        }
    }

    libc::exit(status)
}

/// Copy `src` into `out` followed by a trailing NUL.
///
/// Returns a pointer to the start of `out` on success, or `None` if `src`
/// would not fit (we need one byte for the terminator).
fn copy_cstring(src: &[u8], out: &mut [u8; PATH_BUF_LEN]) -> Option<*const u8> {
    if src.len() >= out.len() {
        return None;
    }
    out[..src.len()].copy_from_slice(src);
    out[src.len()] = 0;
    Some(out.as_ptr())
}

/// Return a short human-readable string for the kernel errno values rm
/// can plausibly receive from `unlink`.
fn errno_message(rc: i64) -> &'static [u8] {
    match rc {
        -1 => b"operation not permitted",
        -2 => b"no such file or directory",
        -13 => b"permission denied",
        -14 => b"bad address",
        -21 => b"is a directory",
        -22 => b"invalid argument",
        -30 => b"read-only file system",
        -36 => b"file name too long",
        _ => b"error",
    }
}

/// SAFETY: caller guarantees `idx < argc` and `argv` is a valid argv pointer
/// supplied by the kernel.
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

fn write_err(msg: &[u8]) {
    let mut pos = 0;
    while pos < msg.len() {
        // SAFETY: msg is a valid byte slice; pointer arithmetic stays in-bounds.
        let n = unsafe { libc::write(2, msg[pos..].as_ptr(), msg.len() - pos) };
        if n <= 0 {
            break;
        }
        pos += n as usize;
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_err(b"rm: panic\n");
    libc::exit(1)
}
