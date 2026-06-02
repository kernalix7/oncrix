// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/chrt` — manipulate the real-time attributes of a process.
//!
//! `chrt(1)` is a util-linux utility (not POSIX) that sets or queries a
//! process's scheduling policy and priority. The canonical "run a command
//! under a given policy" form is:
//!
//! ```text
//! chrt <policy/priority> <command> [args...]
//! ```
//!
//! ONCRIX has a single fixed scheduler with no priority knob, so this stub
//! ignores the requested policy/priority and simply `execve`s the trailing
//! command with the inherited environment. That preserves the visible
//! behaviour of `chrt <p> <cmd>` — the command runs — while making explicit
//! that the priority argument has no effect on this system.
//!
//! Argument handling:
//!   * `argc < 3` — no command supplied → exit 1.
//!   * Otherwise — `argv[1]` is the policy/priority (ignored), `argv[2]` is
//!     the program path, `&argv[2]` is the new argv, environment is inherited.
//!
//! Exit status:
//!   * 0 — never (execve replaces the process).
//!   * 1 — missing operand or could not exec the command.
//!
//! Reference: util-linux `chrt(1)`.

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
        main = sym chrt_main,
    );
}

// ---------------------------------------------------------------------------
// chrt logic
// ---------------------------------------------------------------------------

extern "C" fn chrt_main(argc: usize, argv: *const *const u8, envp: *const *const u8) -> ! {
    if argc < 3 {
        write_all(2, b"chrt: missing operand\n");
        libc::exit(1)
    }

    // argv[1] is the policy/priority — ignored by this stub. argv[2] is the
    // command to exec.
    // SAFETY: argc >= 3 so argv[2] is in range. argv is NULL-terminated by
    // the kernel (slot argv[argc] is NULL), so any in-range slot is readable.
    let path = unsafe { argv.add(2).read() };
    if path.is_null() {
        write_all(2, b"chrt: missing operand\n");
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
    write_all(2, b"chrt: cannot exec command\n");
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
