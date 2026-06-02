// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/pmap` — procps `pmap(1)` utility (non-POSIX).
//!
//! Prints the memory map of a process given by PID on the command line.
//! ONCRIX currently has a fixed early-boot process table and no live
//! VMA accounting, so this implementation prints a fixed three-region
//! map (`r-x--` text, `r----` rodata, `rw---` data) plus a one-page
//! stack — identical regardless of which PID is supplied — and exits
//! successfully.
//!
//! With no PID argument we follow util-linux semantics: write
//! `pmap: missing PID\n` to stderr and exit 1.
//!
//! Reference: procps `pmap(1)`.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Entry point — naked, captures argc / argv from the SysV AMD64 initial stack.
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym pmap_main,
    );
}

// ---------------------------------------------------------------------------
// pmap logic
// ---------------------------------------------------------------------------

extern "C" fn pmap_main(argc: usize, _argv: *const *const u8) -> ! {
    // Missing PID argument — procps prints diagnostic to stderr and exits 1.
    if argc < 2 {
        write_all(2, b"pmap: missing PID\n");
        libc::exit(1)
    }

    // ONCRIX has only fixed early-boot processes; print the same fixed map
    // regardless of which PID was requested.
    write_all(1, b"1:   init\n");
    write_all(1, b"0000000000400000      8K r-x-- init\n");
    write_all(1, b"0000000000600000      4K r---- init\n");
    write_all(1, b"0000000000601000      4K rw--- init\n");
    write_all(1, b"00000000005ff000      4K rw---   [ stack ]\n");
    write_all(1, b" total              20K\n");
    libc::exit(0)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
