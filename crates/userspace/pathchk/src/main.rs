// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/pathchk` — POSIX path validation utility.
//!
//! Without the `-p` / `-P` flags, `pathchk` accepts any non-empty path
//! whose length fits within `_POSIX_PATH_MAX` and whose components fit
//! within `_POSIX_NAME_MAX`. ONCRIX has no real path length limits yet,
//! so this implementation accepts any non-empty path: if at least one
//! operand is supplied and its first byte is not the null terminator,
//! exit 0; otherwise exit 1.
//!
//! POSIX reference:
//! `.priv-storage/.TheOpenGroup/susv5-html/utilities/pathchk.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Entry point — naked, captures argc / argv from the SysV AMD64 initial stack.
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym pathchk_main,
    );
}

// ---------------------------------------------------------------------------
// pathchk logic
// ---------------------------------------------------------------------------

extern "C" fn pathchk_main(argc: usize, argv: *const *const u8) -> ! {
    // argv[0] is the program name; the first path operand is argv[1].
    if argc < 2 {
        libc::exit(1)
    }

    // SAFETY: argc >= 2 so argv[1] is a valid pointer slot laid out by
    // sys_execve.
    let arg1 = unsafe { argv.add(1).read() };
    if arg1.is_null() {
        libc::exit(1)
    }

    // Reject empty path (first byte is the null terminator).
    // SAFETY: arg1 is a kernel-constructed null-terminated string; reading the
    // first byte is always valid.
    let first = unsafe { arg1.read() };
    if first == 0 {
        libc::exit(1)
    }

    libc::exit(0)
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libc::exit(1)
}
