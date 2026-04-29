// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/cat` — POSIX.1-2024 `cat` utility.
//!
//! Concatenates files named as operands to stdout. With no operands (or
//! when an operand is `-`) reads from stdin. Reads in 4 KiB chunks.
//! Exits with 0 if no errors occurred, 1 otherwise.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/cat.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let (argc, argv): (usize, *const *const u8);
    // SAFETY: RSP points to the System V AMD64 initial stack from sys_execve.
    unsafe {
        core::arch::asm!(
            "mov {argc}, [rsp]",
            "lea {argv}, [rsp + 8]",
            argc = out(reg) argc,
            argv = out(reg) argv,
            options(nostack, readonly),
        );
    }
    cat_main(argc, argv)
}

// ---------------------------------------------------------------------------
// Cat logic (POSIX.1-2024)
// ---------------------------------------------------------------------------

const CHUNK: usize = 4096;

fn cat_main(argc: usize, argv: *const *const u8) -> ! {
    let mut exit_code: i32 = 0;

    if argc <= 1 {
        // No operands: read from stdin.
        if !cat_fd(0) {
            exit_code = 1;
        }
    } else {
        for i in 1..argc {
            // SAFETY: argv has at least `argc` valid non-null pointers.
            let ptr = unsafe { argv.add(i).read() };
            if ptr.is_null() {
                break;
            }

            // POSIX: operand "-" means stdin.
            // SAFETY: ptr is a null-terminated argv string.
            let is_dash = unsafe { ptr.read() } == b'-' && unsafe { ptr.add(1).read() } == 0;
            if is_dash {
                if !cat_fd(0) {
                    exit_code = 1;
                }
                continue;
            }

            // Open the named file (O_RDONLY = 0).
            // SAFETY: ptr is null-terminated (from sys_execve argv layout).
            let fd = unsafe { libc::open(ptr, 0, 0) };
            if fd < 0 {
                write_all(2, b"cat: cannot open file\n");
                exit_code = 1;
                continue;
            }
            if !cat_fd(fd as i32) {
                exit_code = 1;
            }
            libc::close(fd as i32);
        }
    }

    libc::exit(exit_code)
}

/// Copy all bytes from `fd` to stdout. Returns `true` on clean EOF.
fn cat_fd(fd: i32) -> bool {
    let mut buf = [0u8; CHUNK];
    loop {
        // SAFETY: buf is valid writable storage of CHUNK bytes.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr(), CHUNK) };
        if n == 0 {
            return true; // EOF
        }
        if n < 0 {
            write_all(2, b"cat: read error\n");
            return false;
        }
        write_all(1, &buf[..n as usize]);
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

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_all(2, b"cat: panic\n");
    libc::exit(1)
}
