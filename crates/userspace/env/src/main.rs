// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/env` — POSIX.1-2024 `env` utility (print-only subset).
//!
//! With no arguments: walks `envp` from the initial System V AMD64 stack
//! layout and writes each `VAR=value` string followed by a newline.
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

extern "C" fn env_main(_argc: usize, _argv: *const *const u8, envp: *const *const u8) -> ! {
    // Walk envp until NULL.
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
    libc::exit(0)
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
