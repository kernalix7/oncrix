// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/su` — switch user.
//!
//! POSIX.1-2024 `su [-] [name [arg...]]` is supposed to:
//!
//! 1. Authenticate as the target user (or `root` if no name given).
//! 2. Optionally simulate a full login (`-` / `-l`).
//! 3. Spawn a shell (or run a command via `-c`) as the new user.
//!
//! ONCRIX has a fixed `root` user and no authentication or per-user state
//! yet, so this implementation skips the auth/identity steps entirely and
//! simply `execve`s `/bin/sh`. The supplied user name (if any) is ignored
//! because no other user exists.
//!
//! Argument handling:
//!   * `argc < 2` — no operand → exec `/bin/sh` directly.
//!   * `argv[1]` starts with `-` (e.g. `-`, `-l`, `-c CMD`) — option form,
//!     ignored; exec `/bin/sh` directly.
//!   * Otherwise — `argv[1]` is a user name; ignored, exec `/bin/sh`.
//!
//! Exit status:
//!   * 0 — never (execve replaces the process).
//!   * 1 — could not exec `/bin/sh`.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/su.html`

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
        main = sym su_main,
    );
}

// ---------------------------------------------------------------------------
// su logic
// ---------------------------------------------------------------------------

extern "C" fn su_main(argc: usize, argv: *const *const u8, envp: *const *const u8) -> ! {
    // Regardless of argv contents, ONCRIX only has the root user, so we
    // always end up exec'ing /bin/sh. Detect the option form purely so we
    // could differentiate behavior later (login shell vs interactive).
    let _is_option_form = if argc < 2 {
        true
    } else {
        // SAFETY: argc >= 2 so argv[1] is in range; argv is NULL-terminated
        // by the kernel so reading is well-defined.
        let arg1 = unsafe { argv.add(1).read() };
        if arg1.is_null() {
            true
        } else {
            // SAFETY: arg1 is a NUL-terminated C string from the kernel.
            let b0 = unsafe { arg1.read() };
            b0 == b'-'
        }
    };

    // Build argv = ["sh", NULL] on the stack.
    let sh_name: *const u8 = b"sh\0".as_ptr();
    let new_argv: [*const u8; 2] = [sh_name, core::ptr::null()];

    // SAFETY: path is a static NUL-terminated string; new_argv is a local
    // NULL-terminated array of two C-string pointers; envp is the kernel's
    // NULL-terminated environment array.
    let _ = unsafe { libc::execve(b"/bin/sh\0".as_ptr(), new_argv.as_ptr(), envp) };

    // execve only returns on failure.
    write_all(2, b"su: cannot exec /bin/sh\n");
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
