// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/mv` — POSIX `mv(1)` utility.
//!
//! Renames or moves `SOURCE` to `DEST` via the `rename(2)` syscall
//! (`SYS_RENAME`, number 82). The ramfs implementation preserves the
//! underlying inode, so the operation is atomic within the in-memory
//! filesystem and works both within a directory (pure rename) and
//! across directories (move).
//!
//! Usage: `mv SOURCE DEST`. Multi-operand `mv SRC... DIR` form is not
//! yet supported.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/mv.html`

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
        main = sym mv_main,
    );
}

const USAGE: &[u8] = b"mv: usage: mv SOURCE DEST\n";
const EFAIL: &[u8] = b"mv: cannot move file\n";

extern "C" fn mv_main(argc: usize, argv: *const *const u8) -> ! {
    if argc < 3 {
        write_all(2, USAGE);
        libc::exit(1)
    }

    // SAFETY: argc >= 3 so argv[1] and argv[2] are valid pointer slots
    // laid out by sys_execve.
    let src = unsafe { argv.add(1).read() };
    let dst = unsafe { argv.add(2).read() };
    if src.is_null() || dst.is_null() {
        write_all(2, USAGE);
        libc::exit(1)
    }

    // SAFETY: src and dst are NUL-terminated argv strings.
    let rc = unsafe { libc::rename(src, dst) };
    if rc < 0 {
        write_all(2, EFAIL);
        libc::exit(1)
    }
    libc::exit(0)
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
