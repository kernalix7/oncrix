// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/sudo` — execute a command as another user.
//!
//! `sudo(8)` is not part of POSIX; it is a de-facto standard tool from the
//! sudo project. The canonical form is `sudo command [args...]`, which
//! authenticates the caller, then `execve`s the command with elevated
//! privileges.
//!
//! ONCRIX has a fixed `root` user and no authentication, so this stub
//! simply passes the tail of argv straight to `execve`. There is no
//! privilege change because there is no separate user identity to switch
//! from.
//!
//! Argument handling:
//!   * `argc < 2` — no command supplied → exit 1.
//!   * Otherwise — `argv[1]` is the program path, `&argv[1]` is the new
//!     argv, environment is inherited.
//!
//! Exit status:
//!   * 0 — never (execve replaces the process).
//!   * 1 — missing command or could not exec it.

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
        main = sym sudo_main,
    );
}

// ---------------------------------------------------------------------------
// sudo logic
// ---------------------------------------------------------------------------

extern "C" fn sudo_main(argc: usize, argv: *const *const u8, envp: *const *const u8) -> ! {
    if argc < 2 {
        write_all(2, b"sudo: missing command\n");
        libc::exit(1)
    }

    // SAFETY: argc >= 2 so argv[1] is in range. argv is NULL-terminated by
    // the kernel (slot argv[argc] is NULL), so any in-range slot is readable.
    let path = unsafe { argv.add(1).read() };
    if path.is_null() {
        write_all(2, b"sudo: missing command\n");
        libc::exit(1)
    }

    // Pass the tail of argv as the new argv. The kernel's argv array is
    // NULL-terminated at argv[argc], so offsetting the base by one yields a
    // still-valid C-style argv whose final slot is the same NULL.
    // SAFETY: argv has argc + 1 readable slots; argv + 1 is within bounds.
    let new_argv = unsafe { argv.add(1) };

    // SAFETY: path, new_argv, and envp are all kernel-supplied NUL- /
    // NULL-terminated arrays.
    let _ = unsafe { libc::execve(path, new_argv, envp) };

    // execve only returns on failure.
    write_all(2, b"sudo: cannot exec command\n");
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
