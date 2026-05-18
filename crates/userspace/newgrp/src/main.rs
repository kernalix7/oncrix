// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/newgrp` — change to a new group.
//!
//! POSIX.1-2024 `newgrp` changes the caller's real and effective group ID
//! to the named group, then `execve`s a new shell so subsequent commands
//! run with the updated group. With no operand, `newgrp` reverts to the
//! user's primary group from the password database.
//!
//! ONCRIX has a fixed `root` user with a single group, so there is no
//! group switch to perform. This stub simply `execve`s `/bin/sh` with an
//! empty argv and empty environment, matching the "exec a fresh shell"
//! tail of the POSIX algorithm.
//!
//! Exit status:
//!   * 0 — never (execve replaces the process).
//!   * 1 — could not exec `/bin/sh`.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/newgrp.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
//
// `newgrp` ignores its operands in this stub — it always execs `/bin/sh`
// with an empty argv and empty environment, so a plain `_start` that jumps
// straight to `newgrp_main` is sufficient.

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    newgrp_main()
}

// ---------------------------------------------------------------------------
// newgrp logic
// ---------------------------------------------------------------------------

fn newgrp_main() -> ! {
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
    write_all(2, b"newgrp: cannot exec /bin/sh\n");
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
