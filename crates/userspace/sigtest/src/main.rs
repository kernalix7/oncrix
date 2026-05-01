// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `sigaction(2)` end-to-end smoke test.
//!
//! 1. Writes "[sigtest] installing SIGCHLD handler\n" to fd 2.
//! 2. Installs a `SIGCHLD` handler that writes "GOT SIGCHLD\n" to fd 1
//!    and sets a static flag.
//! 3. Forks; child calls `_exit(0)`; parent calls `waitpid` then checks
//!    the flag and exits 0 on success, 1 otherwise.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, Ordering};

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Entry point — naked so `[rsp]` reads argc, not a Rust local.
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym sigtest_main,
    );
}

// ---------------------------------------------------------------------------
// Test logic
// ---------------------------------------------------------------------------

static HANDLER_RAN: AtomicU32 = AtomicU32::new(0);

extern "C" fn sigchld_handler(_signum: i32) {
    HANDLER_RAN.store(1, Ordering::SeqCst);
    let msg = b"GOT SIGCHLD\n";
    // SAFETY: msg is a static byte slice with a known length.
    unsafe { libc::write(1, msg.as_ptr(), msg.len()) };
}

extern "C" fn sigtest_main(_argc: usize, _argv: *const *const u8) -> ! {
    write_all(2, b"[sigtest] installing SIGCHLD handler\n");

    let act = libc::Sigaction {
        sa_handler: sigchld_handler as u64,
        sa_flags: 0,
        sa_restorer: 0,
        sa_mask: 0,
    };
    // SAFETY: `act` is a valid stack pointer to a Sigaction; oldact is null.
    let rc = unsafe { libc::sigaction(libc::SIGCHLD, &act, core::ptr::null_mut()) };
    if rc != 0 {
        write_all(2, b"[sigtest] sigaction failed\n");
        libc::exit(1);
    }

    let pid = libc::fork();
    if pid == 0 {
        libc::exit(0);
    } else if pid < 0 {
        write_all(2, b"[sigtest] fork failed\n");
        libc::exit(1);
    }

    let mut status: i32 = 0;
    // SAFETY: `status` is a valid writable i32.
    let _ = unsafe { libc::waitpid(pid, &mut status, 0) };

    if HANDLER_RAN.load(Ordering::SeqCst) == 1 {
        write_all(2, b"[sigtest] handler ran - PASS\n");
        libc::exit(0);
    }
    write_all(2, b"[sigtest] handler did not run - FAIL\n");
    libc::exit(1);
}

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

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_all(2, b"[sigtest] panic\n");
    libc::exit(1);
}
