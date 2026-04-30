// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/ls` — POSIX.1-2024 `ls` utility.
//!
//! Lists the contents of one directory (defaults to `/`). Reads via
//! `getdents64(2)` and prints each entry name on its own line. No flag
//! parsing, no recursion, no formatting beyond `name\n` — POSIX
//! `ls -1` essentially.
//!
//! Exit status:
//!   0 — success
//!   1 — open(2) failed (likely ENOENT or ENOTDIR)
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/ls.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

/// `_start` must be a *naked* function — see `cat`/`echo` for the
/// rationale (Rust prologue would shift `[rsp]` away from argc).
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym ls_main,
    );
}

extern "C" fn ls_main(argc: usize, argv: *const *const u8) -> ! {
    // Default target is `/` if no argv[1] given.
    let target: &[u8] = if argc <= 1 {
        b"/"
    } else {
        // SAFETY: argv has at least argc valid pointers.
        let p = unsafe { argv.add(1).read() };
        if p.is_null() {
            b"/"
        } else {
            // SAFETY: p is a NUL-terminated argv string from sys_execve.
            unsafe { cstr_to_slice(p) }
        }
    };

    let exit_code = if list_dir(target) { 0 } else { 1 };
    libc::exit(exit_code);
}

/// Walk a NUL-terminated argv string and return it as a byte slice
/// (excluding the terminator). Returns `b""` if the string is longer
/// than 256 bytes.
///
/// # Safety
///
/// `p` must point to a NUL-terminated byte sequence in user space.
unsafe fn cstr_to_slice<'a>(p: *const u8) -> &'a [u8] {
    let mut len = 0usize;
    while len < 256 {
        // SAFETY: caller-validated pointer; loop bounds prevent OOB.
        if unsafe { *p.add(len) } == 0 {
            break;
        }
        len += 1;
    }
    // SAFETY: we just walked `len` bytes confirming they exist.
    unsafe { core::slice::from_raw_parts(p, len) }
}

/// Open `target` and dump its directory entries to stdout, one per line.
/// Returns `true` on success.
fn list_dir(target: &[u8]) -> bool {
    // Stack-allocated NUL-terminated path buffer.
    let mut path_buf = [0u8; 257];
    let len = target.len().min(256);
    path_buf[..len].copy_from_slice(&target[..len]);

    // SAFETY: path_buf is zero-initialised, so it is NUL-terminated.
    let fd = unsafe { libc::open(path_buf.as_ptr(), 0, 0) };
    if fd < 0 {
        write_all(2, b"ls: cannot open: ");
        write_all(2, target);
        write_all(2, b"\n");
        return false;
    }

    let mut buf = [0u8; 4096];
    loop {
        // SAFETY: buf is a valid 4096-byte writable buffer.
        let n = unsafe { libc::getdents64(fd as i32, buf.as_mut_ptr(), buf.len()) };
        if n <= 0 {
            break;
        }
        // Walk linux_dirent64 records.
        //   d_ino:    u64   offset  0
        //   d_off:    u64   offset  8
        //   d_reclen: u16   offset 16
        //   d_type:    u8   offset 18
        //   d_name:  []u8   offset 19, NUL-terminated
        let mut pos = 0usize;
        while pos < n as usize {
            if pos + 19 > n as usize {
                break;
            }
            let reclen = u16::from_ne_bytes([buf[pos + 16], buf[pos + 17]]) as usize;
            if reclen == 0 || pos + reclen > n as usize {
                break;
            }
            let name_start = pos + 19;
            let name_end = buf[name_start..pos + reclen]
                .iter()
                .position(|&b| b == 0)
                .map(|i| name_start + i)
                .unwrap_or(pos + reclen);
            let name = &buf[name_start..name_end];
            write_all(1, name);
            write_all(1, b"\n");
            pos += reclen;
        }
    }

    libc::close(fd as i32);
    true
}

fn write_all(fd: i32, buf: &[u8]) {
    let mut pos = 0;
    while pos < buf.len() {
        // SAFETY: buf slice valid for buf.len() bytes.
        let n = unsafe { libc::write(fd, buf[pos..].as_ptr(), buf.len() - pos) };
        if n <= 0 {
            break;
        }
        pos += n as usize;
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_all(2, b"ls: panic\n");
    libc::exit(1)
}
