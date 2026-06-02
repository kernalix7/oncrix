// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/hostname` — print (or, when supported, set) the system hostname.
//!
//! ONCRIX does not yet implement `SYS_GETHOSTNAME` / `SYS_SETHOSTNAME`,
//! so the hostname is the hard-coded literal `oncrix`. Any attempt to *set*
//! the hostname (i.e. invoking `hostname NAME`) is reported on stderr and
//! exits with status 1.
//!
//! Supported flags (all forms print the same `oncrix` literal because we
//! have no FQDN/domain split yet):
//! - no args, `-s`, `-f` → print `oncrix\n` to stdout
//! - `-d`               → print an empty line (no domain)
//!
//! POSIX/util-linux reference: `hostname(1)` (util-linux). POSIX itself does
//! not standardize `hostname(1)`; this follows the common GNU/util-linux
//! behavior.

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
        main = sym hostname_main,
    );
}

// ---------------------------------------------------------------------------
// Hostname logic
// ---------------------------------------------------------------------------

/// Hard-coded system hostname (no `SYS_GETHOSTNAME` syscall yet).
const HOSTNAME: &[u8] = b"oncrix\n";

/// Empty domain — ONCRIX has no FQDN concept yet.
const EMPTY_DOMAIN: &[u8] = b"\n";

extern "C" fn hostname_main(argc: usize, argv: *const *const u8) -> ! {
    // Walk argv[1..] to classify the first non-flag/flag argument.
    let i = 1usize;
    while i < argc {
        // SAFETY: argv has at least argc valid pointers from the kernel stack.
        let ptr = unsafe { argv.add(i).read() };
        if ptr.is_null() {
            break;
        }

        // SAFETY: ptr is a null-terminated argv string supplied by the kernel.
        let c0 = unsafe { ptr.read() };
        if c0 != b'-' {
            // Non-flag → attempt to set hostname (not supported).
            write_all(2, b"hostname: cannot set hostname (no kernel support)\n");
            libc::exit(1)
        }

        // SAFETY: argv strings are null-terminated; reading ptr+1 is safe even
        // for the lone "-" case (it yields the NUL terminator).
        let c1 = unsafe { ptr.add(1).read() };
        // SAFETY: same justification — reading the byte after `c1`. For 2-char
        // flags ("-s\0") this is the NUL; for unknown longer flags it is the
        // next character which we treat as a parse error.
        let c2 = unsafe { ptr.add(2).read() };

        match (c1, c2) {
            (b's', 0) | (b'f', 0) => {
                // Short / FQDN form — both equivalent to the default.
                write_all(1, HOSTNAME);
                libc::exit(0)
            }
            (b'd', 0) => {
                // Domain form — empty since we have no FQDN.
                write_all(1, EMPTY_DOMAIN);
                libc::exit(0)
            }
            _ => {
                write_all(2, b"hostname: unrecognized option\n");
                libc::exit(1)
            }
        }
    }

    // No arguments → print the hostname.
    write_all(1, HOSTNAME);
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

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_all(2, b"hostname: panic\n");
    libc::exit(1)
}
