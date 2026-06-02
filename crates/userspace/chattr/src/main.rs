// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/chattr` — e2fsprogs `chattr(1)` utility stub (non-POSIX).
//!
//! Changes Linux extended (ext2/3/4) file attributes. ONCRIX uses an in-memory
//! ramfs which does not support extended attribute flags, so this
//! implementation reports the limitation on stderr and exits with a non-zero
//! status regardless of arguments.
//!
//! Behaviour:
//!
//! * any invocation → write `"chattr: ramfs has no extended attributes\n"`
//!                    to fd 2, exit 1.
//!
//! Reference: e2fsprogs `chattr(1)`.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Entry point — naked stub; arguments are intentionally ignored.
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym chattr_main,
    );
}

// ---------------------------------------------------------------------------
// chattr logic
// ---------------------------------------------------------------------------

extern "C" fn chattr_main(_argc: usize, _argv: *const *const u8) -> ! {
    // 41 bytes total, including the trailing newline.
    write_all(2, b"chattr: ramfs has no extended attributes\n");
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
