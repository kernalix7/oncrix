// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/whoami` — print effective user name.
//!
//! Prints the current user name followed by `\n`. The kernel hard-codes
//! uid 0, so the only valid user is `root`.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/id.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym whoami_main,
    );
}

extern "C" fn whoami_main(_argc: usize, _argv: *const *const u8) -> ! {
    // uid is always 0 — no user database yet.
    const NAME: &[u8] = b"root\n";
    let mut pos = 0;
    while pos < NAME.len() {
        // SAFETY: NAME is a static byte slice, valid for its length.
        let n = unsafe { libc::write(1, NAME[pos..].as_ptr(), NAME.len() - pos) };
        if n <= 0 {
            break;
        }
        pos += n as usize;
    }
    libc::exit(0)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { libc::write(2, b"whoami: panic\n".as_ptr(), 14) };
    libc::exit(1)
}
