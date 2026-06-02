// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/login` — sign on to the system.
//!
//! POSIX.1-2024 `login` prompts for a user name and password, validates
//! credentials, sets up the user's session (uid/gid, env, cwd, utmp), then
//! `execve`s the user's login shell.
//!
//! ONCRIX has a fixed `root` user and no authentication backend, so this
//! implementation prints a stub banner identifying the auto-logged-in user
//! and `execve`s `/bin/sh` with an empty environment. The `Last login` line
//! is hard-coded to `never` because ONCRIX does not yet maintain login
//! records.
//!
//! Output banner (36 bytes, written to stdout before exec):
//!
//! ```text
//! ONCRIX login: root
//! Last login: never
//! ```
//!
//! Exit status:
//!   * 0 — never (execve replaces the process).
//!   * 1 — could not exec `/bin/sh`.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/login.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
//
// `login` does not need argc / argv / envp — it ignores its operands and
// runs the new shell with an empty environment, so a plain `_start` that
// jumps straight to `login_main` is sufficient.

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    login_main()
}

// ---------------------------------------------------------------------------
// login logic
// ---------------------------------------------------------------------------

fn login_main() -> ! {
    // 36-byte banner: "ONCRIX login: root\nLast login: never\n"
    write_all(1, b"ONCRIX login: root\nLast login: never\n");

    // Build argv = ["sh", NULL] and a NULL-only envp on the stack.
    let sh_name: *const u8 = b"sh\0".as_ptr();
    let new_argv: [*const u8; 2] = [sh_name, core::ptr::null()];
    let new_envp: [*const u8; 1] = [core::ptr::null()];

    // SAFETY: path is a static NUL-terminated string; new_argv and new_envp
    // are local NULL-terminated arrays of C-string pointers.
    let _ = unsafe {
        libc::execve(
            b"/bin/sh\0".as_ptr(),
            new_argv.as_ptr(),
            new_envp.as_ptr(),
        )
    };

    // execve only returns on failure.
    write_all(2, b"login: cannot exec /bin/sh\n");
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
