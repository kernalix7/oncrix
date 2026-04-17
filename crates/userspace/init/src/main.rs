// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX PID 1 init process.
//!
//! Responsibilities:
//! 1. Reap zombie child processes (SIGCHLD handling via waitpid loop).
//! 2. Spawn `/bin/sh` as the first interactive session.
//! 3. Respawn `/bin/sh` if it exits (simple restart policy).
//!
//! This is a skeleton implementation. A full init would parse
//! `/etc/inittab`, manage runlevels, and coordinate shutdown.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Userspace entry point
// ---------------------------------------------------------------------------

/// ELF entry point — the dynamic linker or kernel jumps here.
///
/// Sets up a minimal C-compatible environment and calls [`init_main`].
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    // In a real ELF binary the kernel passes argc/argv/envp on the stack.
    // For this skeleton we ignore them and go straight to init logic.
    init_main()
}

// ---------------------------------------------------------------------------
// Init logic
// ---------------------------------------------------------------------------

/// Null-terminated path to the shell binary.
const SH_PATH: &[u8] = b"/bin/sh\0";
/// Null-terminated shell argv[0].
const SH_ARG0: &[u8] = b"sh\0";

/// Main init loop: spawn sh and reap zombies indefinitely.
fn init_main() -> ! {
    loop {
        let child = libc::fork();

        if child == 0 {
            // Child: exec /bin/sh
            // argv = ["/bin/sh", NULL], envp = [NULL]
            let argv: [*const u8; 2] = [SH_ARG0.as_ptr(), core::ptr::null()];
            let envp: [*const u8; 1] = [core::ptr::null()];
            // SAFETY: SH_PATH is a valid null-terminated string.
            // argv and envp are valid null-terminated pointer arrays.
            let ret = unsafe { libc::execve(SH_PATH.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
            // execve only returns on error.
            let _ = ret;
            libc::exit(1);
        }

        // Parent: reap all zombie children.
        reap_zombies();
    }
}

/// Call waitpid(-1, ...) in a loop to reap any zombie children.
fn reap_zombies() {
    loop {
        let mut status: i32 = 0;
        // SAFETY: `status` is a valid i32 on our stack.
        let pid = unsafe { libc::waitpid(-1, &mut status as *mut i32, 0) };
        if pid <= 0 {
            // No more children to reap (ECHILD) or error.
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // Write a minimal message then abort.
    let msg = b"init: panic\n";
    // SAFETY: `msg` is valid for `msg.len()` bytes.
    unsafe { libc::write(2, msg.as_ptr(), msg.len()) };
    libc::exit(127)
}
