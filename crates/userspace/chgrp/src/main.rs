// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/chgrp` — POSIX `chgrp(1)` utility stub.
//!
//! Changes the group ownership of the supplied file operands. ONCRIX ramfs
//! does not yet track group ownership, so this stub treats every successful
//! invocation as a no-op and exits 0 (POSIX permits exit 0 on a no-op
//! success). Operand validation is limited to argc.
//!
//! Behaviour:
//!
//! * `chgrp` with fewer than two operands (group + at least one file)
//!   → write `"chgrp: missing operand\n"` to fd 2, exit 1.
//! * Otherwise                                          → silent exit 0.
//!
//! Reference: POSIX `chgrp(1)`.
//! See `.priv-storage/.TheOpenGroup/susv5-html/utilities/chgrp.html`.

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
        main = sym chgrp_main,
    );
}

// ---------------------------------------------------------------------------
// chgrp logic
// ---------------------------------------------------------------------------

extern "C" fn chgrp_main(argc: usize, _argv: *const *const u8) -> ! {
    // POSIX `chgrp` requires at least a group operand and one file operand,
    // so argc must be >= 3 (argv[0] = program name, argv[1] = group,
    // argv[2] = file).
    if argc < 3 {
        write_all(2, b"chgrp: missing operand\n");
        libc::exit(1)
    }

    // ramfs has no group ownership yet — no-op success.
    libc::exit(0)
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
