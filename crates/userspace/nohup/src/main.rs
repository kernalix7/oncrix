// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/nohup` — run a utility immune to hangups.
//!
//! POSIX.1-2024 `nohup utility [argument...]` is supposed to:
//!
//! 1. Set the disposition of `SIGHUP` to `SIG_IGN` in the calling process.
//! 2. If stdout is a tty, redirect it to `nohup.out` (or `$HOME/nohup.out`).
//! 3. If stderr is a tty, redirect it to stdout's destination.
//! 4. `execve(utility, ...)` the supplied command.
//!
//! ONCRIX does not yet expose `sigaction` from userspace (the syscall is
//! present in the kernel but signal delivery is not wired up), and ttys
//! do not yet honor write-permission toggles. So this implementation
//! does the only step that matters today: it `execve`s the requested
//! utility directly. The signal-mask and tty-redirect steps will be
//! revisited once `sigaction(3)` and a tty subsystem are in place.
//!
//! Exit status convention (matches POSIX nohup):
//!   * 125 — nohup itself encountered an error (missing operand).
//!   * 126 — utility was found but could not be invoked (not used yet).
//!   * 127 — utility could not be found / execve returned an error.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/nohup.html`

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
        main = sym nohup_main,
    );
}

// ---------------------------------------------------------------------------
// nohup logic
// ---------------------------------------------------------------------------

extern "C" fn nohup_main(argc: usize, argv: *const *const u8, envp: *const *const u8) -> ! {
    if argc < 2 {
        write_all(2, b"nohup: missing operand\n");
        libc::exit(125)
    }

    // Build the new argv: `&argv[1]` — the launched utility expects its
    // own argv[0] to be the name it was invoked as. The argv array on the
    // stack is already NULL-terminated (slot `argv[argc]` is NULL), so
    // shifting the base pointer one slot leaves a still-valid C-style
    // argv whose final slot is the same NULL terminator.
    // SAFETY: argv has argc + 1 readable slots; offsetting by 1 yields a
    // slice of argc slots ending in the original NULL terminator.
    let new_argv = unsafe { argv.add(1) };

    // SAFETY: argv[1] was bounds-checked above (argc >= 2).
    let path = unsafe { argv.add(1).read() };
    if path.is_null() {
        write_all(2, b"nohup: missing operand\n");
        libc::exit(125)
    }

    // SAFETY: pathname, new_argv, and envp are all valid kernel-supplied
    // NUL-terminated / NULL-terminated arrays.
    let _ = unsafe { libc::execve(path, new_argv, envp) };

    // execve only returns on failure.
    write_all(2, b"nohup: cannot execute\n");
    libc::exit(127)
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
