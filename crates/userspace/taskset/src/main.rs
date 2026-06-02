// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/taskset` — set or retrieve a process's CPU affinity.
//!
//! `taskset(1)` is a util-linux utility (not POSIX) that binds a process to a
//! subset of CPUs via a hexadecimal CPU mask. The canonical "run a command
//! under a given affinity" form is:
//!
//! ```text
//! taskset <mask> <command> [args...]
//! ```
//!
//! ONCRIX does not yet expose a CPU affinity API to userspace, so this stub
//! ignores the requested mask and simply `execve`s the trailing command with
//! the inherited environment. That preserves the visible behaviour of
//! `taskset <mask> <cmd>` — the command runs — while making explicit that the
//! affinity argument has no effect on this system.
//!
//! Argument handling:
//!   * `argc < 3` — no command supplied → exit 1.
//!   * Otherwise — `argv[1]` is the CPU mask (ignored), `argv[2]` is the
//!     program path, `&argv[2]` is the new argv, environment is inherited.
//!
//! Exit status:
//!   * 0 — never (execve replaces the process).
//!   * 1 — missing operand or could not exec the command.
//!
//! Reference: util-linux `taskset(1)`.

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
        main = sym taskset_main,
    );
}

// ---------------------------------------------------------------------------
// taskset logic
// ---------------------------------------------------------------------------

extern "C" fn taskset_main(argc: usize, argv: *const *const u8, envp: *const *const u8) -> ! {
    if argc < 3 {
        write_all(2, b"taskset: missing operand\n");
        libc::exit(1)
    }

    // argv[1] is the CPU mask — ignored by this stub. argv[2] is the
    // command to exec.
    // SAFETY: argc >= 3 so argv[2] is in range. argv is NULL-terminated by
    // the kernel (slot argv[argc] is NULL), so any in-range slot is readable.
    let path = unsafe { argv.add(2).read() };
    if path.is_null() {
        write_all(2, b"taskset: missing operand\n");
        libc::exit(1)
    }

    // Pass the tail of argv (starting at argv[2]) as the new argv. The
    // kernel's argv array is NULL-terminated at argv[argc], so offsetting
    // the base by two yields a still-valid C-style argv whose final slot is
    // the same NULL.
    // SAFETY: argv has argc + 1 readable slots; argv + 2 is within bounds
    // because argc >= 3.
    let new_argv = unsafe { argv.add(2) };

    // SAFETY: path, new_argv, and envp are all kernel-supplied NUL- /
    // NULL-terminated arrays.
    let _ = unsafe { libc::execve(path, new_argv, envp) };

    // execve only returns on failure.
    write_all(2, b"taskset: cannot exec command\n");
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
