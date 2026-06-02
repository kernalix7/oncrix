// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/getfacl` — POSIX `getfacl(1)` utility stub.
//!
//! Displays the Access Control List of a file. ONCRIX ramfs stores no ACLs,
//! so this implementation prints a canonical "default" ACL listing that
//! mirrors the file's notional `mode 0755` owned by `root:root`.
//!
//! Behaviour:
//!
//! * `getfacl` (no args)   → write `"getfacl: missing operand\n"` to fd 2,
//!                           exit 1.
//! * `getfacl <path>`      → write the seven-line ACL block (six content
//!                           lines plus the trailing POSIX blank line) to
//!                           fd 1, exit 0.
//!
//! Output for `getfacl <path>`:
//! ```text
//! # file: <path>
//! # owner: root
//! # group: root
//! user::rwx
//! group::r-x
//! other::r-x
//!
//! ```
//!
//! Reference: POSIX `getfacl(1)` (POSIX.1e draft 17 / Linux acl extension).
//! See `.priv-storage/.TheOpenGroup/susv5-html/utilities/getfacl.html`.

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
        main = sym getfacl_main,
    );
}

// ---------------------------------------------------------------------------
// getfacl logic
// ---------------------------------------------------------------------------

extern "C" fn getfacl_main(argc: usize, argv: *const *const u8) -> ! {
    // No operand — error to fd 2 and exit 1.
    if argc < 2 {
        write_all(2, b"getfacl: missing operand\n");
        libc::exit(1)
    }

    // SAFETY: argc >= 2 so argv[1] is a valid pointer slot laid out by
    // sys_execve.
    let arg1 = unsafe { argv.add(1).read() };
    if arg1.is_null() {
        write_all(2, b"getfacl: missing operand\n");
        libc::exit(1)
    }

    let name_len = c_strlen(arg1);
    // SAFETY: arg1 points to a null-terminated string of length `name_len`.
    let name = unsafe { core::slice::from_raw_parts(arg1, name_len) };

    // Line 1: "# file: <path>\n"
    write_all(1, b"# file: ");
    write_all(1, name);
    write_all(1, b"\n");

    // Lines 2–6: fixed owner/group + canonical 0755 ACL entries.
    // Line 7: trailing blank line per POSIX getfacl output convention.
    write_all(
        1,
        b"# owner: root\n# group: root\nuser::rwx\ngroup::r-x\nother::r-x\n\n",
    );

    libc::exit(0)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return the length of a null-terminated C string, excluding the terminator.
fn c_strlen(s: *const u8) -> usize {
    let mut n: usize = 0;
    // SAFETY: caller guarantees the string is null-terminated.
    while unsafe { s.add(n).read() } != 0 {
        n += 1;
    }
    n
}

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
