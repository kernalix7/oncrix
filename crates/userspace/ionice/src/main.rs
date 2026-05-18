// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/ionice` — set or get I/O scheduling class and priority.
//!
//! `ionice(1)` is a util-linux utility (not POSIX) that adjusts a process's
//! I/O scheduling class (idle / best-effort / realtime) and priority. The
//! canonical "run a command under a given I/O class" form is:
//!
//! ```text
//! ionice [-c class] [-n level] <command> [args...]
//! ```
//!
//! ONCRIX has no I/O scheduler with priority classes, so this stub ignores
//! the requested class/level and simply `execve`s the trailing command with
//! the inherited environment.
//!
//! Argument handling:
//!   * `argc < 2` — no command supplied → exit 1.
//!   * If `argc >= 4` and `argv[1]` begins with `-` — treat `argv[1]` as a
//!     flag (e.g. `-c` or `-n`), `argv[2]` as its value, and use `&argv[3]`
//!     as the new argv.
//!   * Otherwise — use `&argv[1]` as the new argv (no flag form).
//!
//! Exit status:
//!   * 0 — never (execve replaces the process).
//!   * 1 — missing operand or could not exec the command.
//!
//! Reference: util-linux `ionice(1)`.

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
        main = sym ionice_main,
    );
}

// ---------------------------------------------------------------------------
// ionice logic
// ---------------------------------------------------------------------------

extern "C" fn ionice_main(argc: usize, argv: *const *const u8, envp: *const *const u8) -> ! {
    if argc < 2 {
        write_all(2, b"ionice: missing operand\n");
        libc::exit(1)
    }

    // SAFETY: argc >= 2, so argv[1] is in range. argv is NULL-terminated by
    // the kernel (slot argv[argc] is NULL), so any in-range slot is readable.
    let arg1 = unsafe { argv.add(1).read() };
    if arg1.is_null() {
        write_all(2, b"ionice: missing operand\n");
        libc::exit(1)
    }

    // Decide where the new argv starts:
    //   argc >= 4 and argv[1] starts with '-' → flag form, new argv = &argv[3]
    //   otherwise                              → new argv = &argv[1]
    // SAFETY: arg1 is a kernel-supplied NUL-terminated C string; the first
    // byte is always readable (worst case it is the NUL terminator).
    let first_byte = unsafe { arg1.read() };
    let offset: usize = if argc >= 4 && first_byte == b'-' { 3 } else { 1 };

    // SAFETY: offset is at most 3, and we only choose 3 when argc >= 4 so
    // argv + 3 is within the argc + 1 slot array. When offset == 1, argc >= 2
    // guarantees argv + 1 is in range. The trailing NULL terminator at
    // argv[argc] remains in place, so new_argv is a valid C-style argv.
    let new_argv = unsafe { argv.add(offset) };

    // SAFETY: new_argv[0] is within the argc + 1 readable slots.
    let new_path = unsafe { new_argv.read() };
    if new_path.is_null() {
        write_all(2, b"ionice: missing operand\n");
        libc::exit(1)
    }

    // SAFETY: new_path, new_argv, and envp are all kernel-supplied NUL- /
    // NULL-terminated arrays.
    let _ = unsafe { libc::execve(new_path, new_argv, envp) };

    // execve only returns on failure.
    write_all(2, b"ionice: cannot exec command\n");
    libc::exit(1)
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
