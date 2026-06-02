// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/tee` — copy stdin to stdout and to each file argument.
//!
//! Usage:
//!   tee [-a] [FILE ...]
//!
//! Without `-a`, each output file is opened with O_TRUNC; with `-a`,
//! O_APPEND. Stdin is always copied to stdout in addition to any
//! files. POSIX exit status: 0 on success, >0 if any file open or
//! write fails (the utility continues writing to remaining destinations
//! on failure — POSIX says "shall not terminate" for write errors).
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/tee.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

/// Maximum number of output file destinations supported.
/// POSIX scripts almost never invoke `tee` with more than a couple
/// of targets; keeping a fixed-size array avoids heap usage.
const MAX_FILES: usize = 8;

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym tee_main,
    );
}

extern "C" fn tee_main(argc: usize, argv: *const *const u8) -> ! {
    let mut append = false;
    let mut idx = 1usize;

    // Parse leading flags (`-a` for append; `--` to end option parsing).
    while idx < argc {
        // SAFETY: idx < argc.
        let arg = unsafe { cstr_at(argv, idx) };
        if arg == b"-a" {
            append = true;
            idx += 1;
            continue;
        }
        if arg == b"--" {
            idx += 1;
            break;
        }
        if !arg.is_empty() && arg[0] == b'-' && arg != b"-" {
            write_err(b"tee: unknown option\n");
            libc::exit(1);
        }
        break;
    }

    // Open output files.
    let mut fds = [-1i32; MAX_FILES];
    let mut nfiles = 0usize;
    let mut had_error = false;
    while idx < argc && nfiles < MAX_FILES {
        // SAFETY: idx < argc.
        let path_bytes = unsafe { cstr_at(argv, idx) };
        // Copy to a NUL-terminated buffer.
        let mut buf = [0u8; 256];
        let n = path_bytes.len().min(buf.len() - 1);
        buf[..n].copy_from_slice(&path_bytes[..n]);
        let flags = libc::O_WRONLY
            | libc::O_CREAT
            | if append { libc::O_APPEND } else { libc::O_TRUNC };
        // Mode 0o644.
        // SAFETY: buf is NUL-terminated.
        let fd = unsafe { libc::open(buf.as_ptr(), flags, 0o644) };
        if fd < 0 {
            write_err(b"tee: cannot open file\n");
            had_error = true;
        } else {
            fds[nfiles] = fd as i32;
            nfiles += 1;
        }
        idx += 1;
    }

    // Copy stdin to stdout + each file.
    let mut buf = [0u8; 4096];
    loop {
        // SAFETY: buf is owned and writable.
        let n = unsafe { libc::read(0, buf.as_mut_ptr(), buf.len()) };
        if n <= 0 {
            break;
        }
        let chunk = &buf[..n as usize];
        if !write_all(1, chunk) {
            had_error = true;
        }
        for fd in &fds[..nfiles] {
            if !write_all(*fd, chunk) {
                had_error = true;
            }
        }
    }

    for fd in &fds[..nfiles] {
        let _ = libc::close(*fd);
    }

    libc::exit(if had_error { 1 } else { 0 })
}

fn write_all(fd: i32, buf: &[u8]) -> bool {
    let mut pos = 0;
    while pos < buf.len() {
        // SAFETY: buf slice is valid for buf.len() bytes.
        let n = unsafe { libc::write(fd, buf[pos..].as_ptr(), buf.len() - pos) };
        if n <= 0 {
            return false;
        }
        pos += n as usize;
    }
    true
}

fn write_err(msg: &[u8]) {
    let _ = write_all(2, msg);
}

/// SAFETY: caller guarantees `idx < argc` and `argv` is a valid argv pointer.
unsafe fn cstr_at(argv: *const *const u8, idx: usize) -> &'static [u8] {
    unsafe {
        let p = *argv.add(idx);
        if p.is_null() {
            return &[];
        }
        let mut len = 0usize;
        while *p.add(len) != 0 {
            len += 1;
            if len > 4096 {
                break;
            }
        }
        core::slice::from_raw_parts(p, len)
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_err(b"tee: panic\n");
    libc::exit(1)
}
