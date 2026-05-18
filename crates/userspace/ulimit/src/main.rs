// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/ulimit` — POSIX `ulimit` utility.
//!
//! `ulimit` reports (and in shells, sets) per-process resource limits.
//! ONCRIX ships a standalone binary that prints the current limits in
//! the bash-compatible `ulimit -a` table format when invoked with `-a`,
//! and a single `unlimited\n` line otherwise. Values are hard-coded to
//! reflect the kernel's current static limits.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/ulimit.html`

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
        main = sym ulimit_main,
    );
}

// ---------------------------------------------------------------------------
// ulimit logic
// ---------------------------------------------------------------------------

const TABLE: &[u8] = b"core file size          (blocks, -c) 0\n\
data seg size           (kbytes, -d) unlimited\n\
scheduling priority             (-e) 0\n\
file size               (blocks, -f) unlimited\n\
pending signals                 (-i) 1024\n\
max locked memory       (kbytes, -l) 8192\n\
max memory size         (kbytes, -m) unlimited\n\
open files                      (-n) 32\n\
pipe size            (512 bytes, -p) 8\n\
POSIX message queues     (bytes, -q) 819200\n\
real-time priority              (-r) 0\n\
stack size              (kbytes, -s) 8192\n\
cpu time               (seconds, -t) unlimited\n\
virtual memory          (kbytes, -v) unlimited\n";

const UNLIMITED: &[u8] = b"unlimited\n";

extern "C" fn ulimit_main(argc: usize, argv: *const *const u8) -> ! {
    if argc >= 2 {
        // SAFETY: argc >= 2 so argv[1] is a valid pointer slot laid out by
        // sys_execve.
        let arg1 = unsafe { argv.add(1).read() };
        if !arg1.is_null() && c_str_starts_with(arg1, b"-a") {
            write_all(1, TABLE);
            libc::exit(0)
        }
    }

    write_all(1, UNLIMITED);
    libc::exit(0)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return true if the null-terminated C string at `ptr` starts with `prefix`.
fn c_str_starts_with(ptr: *const u8, prefix: &[u8]) -> bool {
    for (i, &want) in prefix.iter().enumerate() {
        // SAFETY: ptr is a null-terminated string from the kernel-constructed
        // argv; we stop at the terminator before walking past it.
        let got = unsafe { ptr.add(i).read() };
        if got == 0 || got != want {
            return false;
        }
    }
    true
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
