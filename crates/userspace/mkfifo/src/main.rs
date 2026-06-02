// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/mkfifo` — POSIX `mkfifo(1)` utility.
//!
//! Creates named pipes (FIFOs) via `mkfifo(3)` → `mknod(2)`
//! (`SYS_MKNOD`, number 133). The FIFO node is created in the ramfs
//! with type `FileType::Fifo`; connecting it to a working pipe ring on
//! open is not yet wired, so the node exists (visible to `ls`) but
//! read/write through it is not yet supported.
//!
//! Usage: `mkfifo NAME...`. Default mode 0644.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/mkfifo.html`

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
        main = sym mkfifo_main,
    );
}

extern "C" fn mkfifo_main(argc: usize, argv: *const *const u8) -> ! {
    if argc < 2 {
        write_all(2, b"mkfifo: missing operand\n");
        libc::exit(1)
    }

    let mut status = 0;
    let mut i = 1usize;
    while i < argc {
        // SAFETY: i < argc, so argv[i] is a valid pointer slot.
        let path = unsafe { argv.add(i).read() };
        if path.is_null() {
            break;
        }
        // SAFETY: path is a NUL-terminated argv string.
        let rc = unsafe { libc::mkfifo(path, 0o644) };
        if rc < 0 {
            write_all(2, b"mkfifo: cannot create fifo\n");
            status = 1;
        }
        i += 1;
    }
    libc::exit(status)
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
