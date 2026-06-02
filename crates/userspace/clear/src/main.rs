// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/clear` — clear the terminal screen.
//!
//! Writes the ANSI escape sequence `ESC[2J ESC[H` to stdout to erase
//! the screen and move the cursor to the home position. Exits 0.

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
        main = sym clear_main,
    );
}

extern "C" fn clear_main(_argc: usize, _argv: *const *const u8) -> ! {
    // ESC[2J clears the screen; ESC[H moves the cursor to row 1, column 1.
    const CLEAR_SEQ: &[u8] = b"\x1b[2J\x1b[H";
    let mut pos = 0;
    while pos < CLEAR_SEQ.len() {
        // SAFETY: CLEAR_SEQ is a static byte slice, valid for its length.
        let n = unsafe { libc::write(1, CLEAR_SEQ[pos..].as_ptr(), CLEAR_SEQ.len() - pos) };
        if n <= 0 {
            break;
        }
        pos += n as usize;
    }
    libc::exit(0)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { libc::write(2, b"clear: panic\n".as_ptr(), 13) };
    libc::exit(1)
}
