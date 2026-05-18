// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/mountpoint` — util-linux `mountpoint(1)` clone.
//!
//! Checks whether the given path is a mountpoint. ONCRIX has no real
//! `statfs`/`mountinfo` plumbing yet, so the check is performed against a
//! fixed list of paths that the kernel mounts at boot:
//!
//! * `/`
//! * `/dev`
//! * `/proc`
//! * `/tmp`
//! * `/sbin`
//! * `/etc`
//!
//! Exit status:
//!   * 0 — the path is a known mountpoint.
//!   * 1 — the path is not a mountpoint (or no operand was provided).
//!
//! Reference: `mountpoint(1)` from util-linux. The utility is not part of
//! POSIX.1-2024.

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
        main = sym mountpoint_main,
    );
}

// ---------------------------------------------------------------------------
// mountpoint logic
// ---------------------------------------------------------------------------

/// Fixed list of paths considered mountpoints in the current ONCRIX boot.
const KNOWN_MOUNTPOINTS: &[&[u8]] = &[
    b"/",
    b"/dev",
    b"/proc",
    b"/tmp",
    b"/sbin",
    b"/etc",
];

extern "C" fn mountpoint_main(argc: usize, argv: *const *const u8) -> ! {
    if argc < 2 {
        write_all(2, b"mountpoint: missing operand\n");
        libc::exit(1)
    }

    // SAFETY: argc >= 2 so argv[1] is a valid pointer slot laid out by
    // sys_execve.
    let path_ptr = unsafe { argv.add(1).read() };
    if path_ptr.is_null() {
        write_all(2, b"mountpoint: missing operand\n");
        libc::exit(1)
    }

    // SAFETY: argv entries are NUL-terminated C strings from the kernel.
    let path_len = unsafe { c_strlen(path_ptr) };

    let is_mp = KNOWN_MOUNTPOINTS
        .iter()
        .any(|&mp| c_str_eq(path_ptr, mp));

    // Always emit the path followed by the verdict, matching util-linux's
    // diagnostic output.
    write_all_raw(1, path_ptr, path_len);
    if is_mp {
        write_all(1, b" is a mountpoint\n");
        libc::exit(0)
    } else {
        write_all(1, b" is not a mountpoint\n");
        libc::exit(1)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Length of a NUL-terminated C string, exclusive of the terminator.
///
/// # Safety
///
/// `ptr` must point to a readable NUL-terminated byte sequence.
unsafe fn c_strlen(ptr: *const u8) -> usize {
    let mut n = 0usize;
    loop {
        // SAFETY: caller guarantees ptr is NUL-terminated.
        let b = unsafe { ptr.add(n).read() };
        if b == 0 {
            return n;
        }
        n += 1;
    }
}

/// Compare a NUL-terminated C string with a byte slice for exact equality.
/// The string must match `expected` byte-for-byte and the next byte must be
/// the NUL terminator.
fn c_str_eq(ptr: *const u8, expected: &[u8]) -> bool {
    for (i, &want) in expected.iter().enumerate() {
        // SAFETY: ptr is a NUL-terminated string from the kernel-constructed
        // argv; we bail at the terminator before walking past it.
        let got = unsafe { ptr.add(i).read() };
        if got == 0 || got != want {
            return false;
        }
    }
    // Require the terminator immediately after the matched prefix.
    // SAFETY: same as above; index `expected.len()` is the next byte.
    unsafe { ptr.add(expected.len()).read() == 0 }
}

/// Write all bytes from a raw pointer/length to `fd`, retrying on short
/// writes.
fn write_all_raw(fd: i32, ptr: *const u8, len: usize) {
    let mut pos = 0;
    while pos < len {
        // SAFETY: the caller passes a valid pointer covering `len` bytes;
        // we only advance within that range.
        let n = unsafe { libc::write(fd, ptr.wrapping_add(pos), len - pos) };
        if n <= 0 {
            break;
        }
        pos += n as usize;
    }
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
