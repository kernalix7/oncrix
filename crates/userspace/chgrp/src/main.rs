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

extern "C" fn chgrp_main(argc: usize, argv: *const *const u8) -> ! {
    // argv[0] = program, argv[1] = group (numeric), argv[2] = file.
    if argc < 3 {
        write_all(2, b"chgrp: missing operand\n");
        libc::exit(1)
    }

    // SAFETY: argc >= 3, so argv[1] and argv[2] are valid pointer slots.
    let grp = unsafe { argv.add(1).read() };
    let file = unsafe { argv.add(2).read() };
    if grp.is_null() || file.is_null() {
        write_all(2, b"chgrp: missing operand\n");
        libc::exit(1)
    }

    let gid = match parse_u32(grp) {
        Some(g) => g,
        None => {
            write_all(2, b"chgrp: invalid group\n");
            libc::exit(1)
        }
    };

    // chown with uid = u32::MAX leaves the owner unchanged, only the group.
    // SAFETY: file is a NUL-terminated argv string.
    let rc = unsafe { libc::chown(file, u32::MAX, gid) };
    if rc < 0 {
        write_all(2, b"chgrp: cannot change group\n");
        libc::exit(1)
    }
    libc::exit(0)
}

/// Parse a NUL-terminated decimal string into a `u32`.
///
/// Returns `None` on an empty string or any non-decimal digit.
fn parse_u32(ptr: *const u8) -> Option<u32> {
    let mut val: u32 = 0;
    let mut i = 0usize;
    loop {
        // SAFETY: ptr is a NUL-terminated argv string.
        let c = unsafe { ptr.add(i).read() };
        if c == 0 {
            break;
        }
        if !c.is_ascii_digit() {
            return None;
        }
        val = val.checked_mul(10)?.checked_add((c - b'0') as u32)?;
        i += 1;
    }
    if i == 0 { None } else { Some(val) }
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
