// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/env` — POSIX.1-2024 `env` utility (print-only subset).
//!
//! With no arguments: walks `envp` from the initial System V AMD64 stack
//! layout and writes each `VAR=value` string followed by a newline. The
//! `-i` (or `--ignore-environment`) flag suppresses that walk so the
//! inherited environment is dropped — a no-op today since ONCRIX execve
//! always passes an empty envp, but accepted so portable scripts work.
//!
//! Per the System V AMD64 ABI the initial stack is:
//! ```text
//! [rsp]            = argc
//! [rsp + 8]        = argv[0]
//! ...
//! [rsp + 8*argc]   = argv[argc-1]
//! [rsp + 8*(argc+1)] = NULL          (end of argv)
//! [rsp + 8*(argc+2)] = envp[0]
//! ...
//! ```
//! The naked `_start` hands us `argc` and `argv`; `envp` is immediately
//! after the NULL terminator that closes argv.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/env.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// `_start` must be a *naked* function so the Rust prologue does not shift
/// the initial stack before we read argc/argv. Additionally we pass `envp`
/// (located right after the NULL that terminates argv) as the third argument
/// per the System V AMD64 ABI.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        // rdi = argc
        "mov rdi, [rsp]",
        // rsi = &argv[0]
        "lea rsi, [rsp + 8]",
        // rdx = &envp[0] = rsp + 8 + 8*(argc+1)
        // = rsp + 8*(argc+2)
        // rdi holds argc; lea can't use it directly for scaled index in one go,
        // so compute: rdx = rsi + 8*(argc+1) = rsi + 8*argc + 8
        "lea rdx, [rsi + rdi*8 + 8]",
        "call {main}",
        "ud2",
        main = sym env_main,
    );
}

// ---------------------------------------------------------------------------
// env logic (POSIX.1-2024)
// ---------------------------------------------------------------------------

extern "C" fn env_main(argc: usize, argv: *const *const u8, envp: *const *const u8) -> ! {
    // Parse the leading `-i` flag. POSIX.1-2024 `env -i` means "ignore the
    // inherited environment". ONCRIX's execve currently passes an empty
    // envp array, so the flag is structurally a no-op today — but we still
    // accept and recognise it so portably-written scripts do not fail. The
    // long form `--ignore-environment` is also accepted as a GNU
    // compatibility nicety; unknown leading `-…` arguments are reported on
    // stderr and the utility exits with status 125 (the GNU env convention
    // for "the env utility itself failed", distinct from the launched
    // command's exit status).
    let mut idx = 1usize;
    let mut ignore_env = false;
    while idx < argc {
        // SAFETY: idx < argc; argv is a kernel-supplied valid pointer array.
        let ptr = unsafe { argv.add(idx).read() };
        if ptr.is_null() {
            break;
        }
        // SAFETY: argv entries are NUL-terminated C strings.
        let arg = unsafe { cstr(ptr) };
        if arg == b"-i" || arg == b"--ignore-environment" {
            ignore_env = true;
            idx += 1;
            continue;
        }
        if arg == b"--" {
            idx += 1;
            break;
        }
        if !arg.is_empty() && arg[0] == b'-' {
            // Unknown option — POSIX treats this as an error.
            write_all(2, b"env: unrecognised option: ");
            write_all(2, arg);
            write_all(2, b"\n");
            libc::exit(125);
        }
        // First non-flag argument: positional command, leave for fallthrough.
        break;
    }

    // Walk envp unless `-i` was given (which strips the inherited
    // environment from the print). On a system whose envp is already
    // empty this is observationally identical, but the codepath is
    // distinct so future support for inherited env will work.
    if !ignore_env {
        let mut i = 0usize;
        loop {
            // SAFETY: envp is a NULL-terminated array of pointers from the kernel stack.
            let ptr = unsafe { envp.add(i).read() };
            if ptr.is_null() {
                break;
            }
            write_str(1, ptr);
            write_all(1, b"\n");
            i += 1;
        }
    }

    // ONCRIX does not yet support invoking an arbitrary utility via env.
    // When extra positional arguments follow the flag list, we exit 0
    // silently; a real POSIX env would `execve(argv[idx])` here. sh
    // already provides direct execve, so we keep this utility print-only.
    libc::exit(0)
}

/// Read a C string up to a 4 KiB safety bound.
///
/// SAFETY: `p` must point to a NUL-terminated byte sequence; the safety
/// bound caps runaway scans at 4096 bytes.
unsafe fn cstr(p: *const u8) -> &'static [u8] {
    unsafe {
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

fn write_str(fd: i32, ptr: *const u8) {
    let mut len = 0usize;
    // SAFETY: ptr is a null-terminated string from the kernel-constructed envp.
    while unsafe { ptr.add(len).read() } != 0 {
        len += 1;
    }
    if len > 0 {
        // SAFETY: ptr is valid for len bytes.
        write_all(fd, unsafe { core::slice::from_raw_parts(ptr, len) });
    }
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_all(2, b"env: panic\n");
    libc::exit(1)
}
