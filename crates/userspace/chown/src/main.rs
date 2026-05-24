// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/chown` — POSIX `chown(1)` utility.
//!
//! Usage: `chown OWNER[:GROUP] FILE`. OWNER and GROUP are numeric ids
//! (ONCRIX has no name service); the change is applied via the
//! `chown(2)` syscall (`SYS_CHOWN`, number 92). An omitted GROUP leaves
//! the group unchanged. Owner/group are stored in the inode but not yet
//! enforced. Symbolic names are not supported.
//!
//! Behaviour:
//!
//! * fewer than two operands → `"chown: missing operand\n"`, exit 1.
//! * non-numeric owner/group → `"chown: invalid owner\n"`, exit 1.
//! * `chown(2)` failure → `"chown: cannot change owner\n"`, exit 1.
//!
//! Reference: POSIX `chown(1)`.
//! See `.priv-storage/.TheOpenGroup/susv5-html/utilities/chown.html`.

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
        main = sym chown_main,
    );
}

// ---------------------------------------------------------------------------
// chown logic
// ---------------------------------------------------------------------------

extern "C" fn chown_main(argc: usize, argv: *const *const u8) -> ! {
    // argv[0] = program, argv[1] = owner[:group], argv[2] = file.
    if argc < 3 {
        write_all(2, b"chown: missing operand\n");
        libc::exit(1)
    }

    // SAFETY: argc >= 3, so argv[1] and argv[2] are valid pointer slots.
    let spec = unsafe { argv.add(1).read() };
    let file = unsafe { argv.add(2).read() };
    if spec.is_null() || file.is_null() {
        write_all(2, b"chown: missing operand\n");
        libc::exit(1)
    }

    // Parse OWNER[:GROUP]. u32::MAX means "leave unchanged".
    let (uid, gid) = match parse_owner_group(spec) {
        Some(pair) => pair,
        None => {
            write_all(2, b"chown: invalid owner\n");
            libc::exit(1)
        }
    };

    // SAFETY: file is a NUL-terminated argv string.
    let rc = unsafe { libc::chown(file, uid, gid) };
    if rc < 0 {
        write_all(2, b"chown: cannot change owner\n");
        libc::exit(1)
    }
    libc::exit(0)
}

/// Parse a NUL-terminated `OWNER[:GROUP]` spec into `(uid, gid)`.
///
/// Both fields are decimal. An omitted group yields `u32::MAX` (leave
/// unchanged). Returns `None` on any non-decimal digit or empty owner.
fn parse_owner_group(ptr: *const u8) -> Option<(u32, u32)> {
    let mut uid: u32 = 0;
    let mut have_uid = false;
    let mut i = 0usize;

    // Owner digits up to ':' or NUL.
    loop {
        // SAFETY: ptr is a NUL-terminated argv string.
        let c = unsafe { ptr.add(i).read() };
        if c == 0 || c == b':' {
            break;
        }
        if !c.is_ascii_digit() {
            return None;
        }
        uid = uid.checked_mul(10)?.checked_add((c - b'0') as u32)?;
        have_uid = true;
        i += 1;
    }
    if !have_uid {
        return None;
    }

    // SAFETY: same NUL-terminated string.
    let sep = unsafe { ptr.add(i).read() };
    if sep == 0 {
        // No group component.
        return Some((uid, u32::MAX));
    }

    // Group digits after ':'.
    i += 1;
    let mut gid: u32 = 0;
    let mut have_gid = false;
    loop {
        // SAFETY: same NUL-terminated string.
        let c = unsafe { ptr.add(i).read() };
        if c == 0 {
            break;
        }
        if !c.is_ascii_digit() {
            return None;
        }
        gid = gid.checked_mul(10)?.checked_add((c - b'0') as u32)?;
        have_gid = true;
        i += 1;
    }
    if !have_gid {
        return None;
    }
    Some((uid, gid))
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
