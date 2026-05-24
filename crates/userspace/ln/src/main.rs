// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/ln` — POSIX `ln(1)` utility (hard links).
//!
//! Creates `LINK_NAME` as a hard link to `TARGET` via the `link(2)`
//! syscall (`SYS_LINK`, number 86). The ramfs implementation bumps the
//! target inode's link count, so removing either name keeps the file
//! alive until the last link is unlinked.
//!
//! Usage: `ln TARGET LINK_NAME`. Symbolic links (`-s`) are not yet
//! supported (ramfs has no symlink inode type) and are rejected.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/ln.html`

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
        main = sym ln_main,
    );
}

const USAGE: &[u8] = b"ln: usage: ln TARGET LINK_NAME\n";
const ESYM: &[u8] = b"ln: symbolic links not supported on ONCRIX\n";
const EFAIL: &[u8] = b"ln: cannot create link\n";

extern "C" fn ln_main(argc: usize, argv: *const *const u8) -> ! {
    if argc < 3 {
        write_all(2, USAGE);
        libc::exit(1)
    }

    // SAFETY: argc >= 3, so argv[1] and argv[2] are valid pointer slots.
    let a1 = unsafe { argv.add(1).read() };
    let a2 = unsafe { argv.add(2).read() };
    if a1.is_null() || a2.is_null() {
        write_all(2, USAGE);
        libc::exit(1)
    }

    // Reject the `-s` (symbolic) option — unsupported.
    if first_two(a1) == [b'-', b's'] {
        write_all(2, ESYM);
        libc::exit(1)
    }

    // SAFETY: a1 (target) and a2 (link name) are NUL-terminated argv strings.
    let rc = unsafe { libc::link(a1, a2) };
    if rc < 0 {
        write_all(2, EFAIL);
        libc::exit(1)
    }
    libc::exit(0)
}

/// Return the first two bytes of a NUL-terminated string (0-padded).
fn first_two(ptr: *const u8) -> [u8; 2] {
    // SAFETY: ptr is a NUL-terminated argv string; read index 0 first,
    // and only read index 1 when index 0 is non-NUL.
    let b0 = unsafe { ptr.read() };
    if b0 == 0 {
        return [0, 0];
    }
    let b1 = unsafe { ptr.add(1).read() };
    [b0, b1]
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

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libc::exit(1)
}
