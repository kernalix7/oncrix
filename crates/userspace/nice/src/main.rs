// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/nice` — POSIX `nice` utility.
//!
//! POSIX.1-2024 `nice [-n increment] utility [argument...]` runs `utility`
//! at a lowered scheduling priority. ONCRIX has no per-process scheduling
//! priority API yet, so this implementation parses (and discards) any
//! leading `-n NUM` operand and then `execve`s the remaining command line
//! with the inherited environment.
//!
//! Argument handling:
//!   * `argc < 2` — no utility supplied → exit 125.
//!   * `argv[1] == "-n"` and `argc >= 4` — skip `-n` plus its value, use
//!     `argv[3]` as the new program path.
//!   * `argv[1]` starts with `-` (e.g. `-10`, `--`, `-n5`) — skip just
//!     `argv[1]`, use `argv[2]` as the new program path.
//!   * Otherwise — use `argv[1]` as the new program path.
//!
//! Exit status convention (matches POSIX nice):
//!   * 125 — nice itself encountered an error (missing operand).
//!   * 126 — utility was found but could not be invoked (not used yet).
//!   * 127 — utility could not be found / execve returned an error.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/nice.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Entry point — naked, captures argc / argv / envp from the SysV AMD64 stack.
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        // rdi = argc
        "mov rdi, [rsp]",
        // rsi = &argv[0]
        "lea rsi, [rsp + 8]",
        // rdx = &envp[0] = rsi + 8*(argc+1) = rsi + 8*argc + 8
        "lea rdx, [rsi + rdi*8 + 8]",
        "call {main}",
        "ud2",
        main = sym nice_main,
    );
}

// ---------------------------------------------------------------------------
// nice logic
// ---------------------------------------------------------------------------

extern "C" fn nice_main(argc: usize, argv: *const *const u8, envp: *const *const u8) -> ! {
    if argc < 2 {
        write_all(2, b"nice: missing operand\n");
        libc::exit(125)
    }

    // SAFETY: argc >= 2, so argv[1] is in range. argv is NULL-terminated by
    // the kernel (slot argv[argc] is NULL), so any in-range slot is readable.
    let arg1 = unsafe { argv.add(1).read() };
    if arg1.is_null() {
        write_all(2, b"nice: missing operand\n");
        libc::exit(125)
    }

    // Decide where the new argv starts.
    //
    //   argv[1] == "-n" and argc >= 4   → skip 2 slots, new argv = &argv[3]
    //   argv[1] starts with "-"         → skip 1 slot,  new argv = &argv[2]
    //   otherwise                       → new argv = &argv[1]
    let skip: usize = if argc >= 4 && starts_with_dash_n(arg1) {
        2
    } else if starts_with_dash(arg1) {
        1
    } else {
        0
    };

    // After skipping, we need at least one more slot for the utility name.
    if argc < 2 + skip {
        write_all(2, b"nice: missing operand\n");
        libc::exit(125)
    }

    // SAFETY: argv has argc + 1 readable slots ending in NULL. (1 + skip)
    // is <= argc, so offsetting by that much still yields a valid array
    // whose final slot is the original NULL terminator.
    let new_argv = unsafe { argv.add(1 + skip) };

    // SAFETY: the (1 + skip) slot is < argc + 1 and is the new argv[0].
    let new_path = unsafe { new_argv.read() };
    if new_path.is_null() {
        write_all(2, b"nice: missing operand\n");
        libc::exit(125)
    }

    // SAFETY: new_path, new_argv, and envp are all kernel-supplied
    // NUL-terminated / NULL-terminated arrays.
    let _ = unsafe { libc::execve(new_path, new_argv, envp) };

    // execve only returns on failure.
    write_all(2, b"nice: cannot execute\n");
    libc::exit(127)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns `true` if the C string at `ptr` starts with a single `-`.
fn starts_with_dash(ptr: *const u8) -> bool {
    // SAFETY: ptr is a NUL-terminated C string from the kernel argv.
    let b = unsafe { ptr.read() };
    b == b'-'
}

/// Returns `true` if the C string at `ptr` starts with the exact two-byte
/// sequence `-n` (used to detect the `-n NUM` option form).
fn starts_with_dash_n(ptr: *const u8) -> bool {
    // SAFETY: ptr is a NUL-terminated C string from the kernel argv; we
    // stop at the terminator before reading past it.
    let b0 = unsafe { ptr.read() };
    if b0 != b'-' {
        return false;
    }
    // SAFETY: the first byte is non-NUL so index 1 is still within the
    // string (worst case it is the NUL terminator).
    let b1 = unsafe { ptr.add(1).read() };
    b1 == b'n'
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
