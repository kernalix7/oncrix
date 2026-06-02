// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/renice` — POSIX `renice` utility.
//!
//! POSIX.1-2024 `renice -n increment [-g|-p|-u] ID...` alters the
//! scheduling nice value of running processes. ONCRIX has no
//! process-group or per-user scheduling and no cross-process priority
//! API yet, so this implementation applies the requested nice value to
//! the **calling process** via `setpriority(PRIO_PROCESS, 0, prio)` and
//! prints the result. Any trailing `ID` operands are parsed but, lacking
//! cross-process control, are not individually retargeted; the value is
//! applied to self. This is documented divergence pending PRIO_PGRP /
//! PRIO_USER support.
//!
//! Accepted forms:
//!   * `renice PRIO`            — absolute nice value applied to self.
//!   * `renice -n PRIO`         — same, explicit `-n` flag.
//!   * `renice -n PRIO ID...`   — `-n` form with (ignored) target IDs.
//!
//! Exit status:
//!   * 0   — priority set.
//!   * 1   — usage error or setpriority failure.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/renice.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

/// `which` selector for `setpriority`: act on a process.
const PRIO_PROCESS: i32 = 0;
/// Lowest (most favourable) POSIX nice value.
const NICE_MIN: i32 = -20;
/// Highest (least favourable) POSIX nice value.
const NICE_MAX: i32 = 19;

// ---------------------------------------------------------------------------
// Entry point — naked, captures argc / argv from the SysV AMD64 stack.
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        // rdi = argc
        "mov rdi, [rsp]",
        // rsi = &argv[0]
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym renice_main,
    );
}

// ---------------------------------------------------------------------------
// renice logic
// ---------------------------------------------------------------------------

extern "C" fn renice_main(argc: usize, argv: *const *const u8) -> ! {
    if argc < 2 {
        write_all(2, b"usage: renice [-n] priority [id...]\n");
        libc::exit(1)
    }

    // SAFETY: argc >= 2 so argv[1] is in range; the kernel argv array is
    // NULL-terminated, so every in-range slot is a readable pointer.
    let arg1 = unsafe { argv.add(1).read() };
    if arg1.is_null() {
        write_all(2, b"usage: renice [-n] priority [id...]\n");
        libc::exit(1)
    }

    // Locate the priority operand: either argv[1], or argv[2] after "-n".
    let prio_ptr = if is_dash_n(arg1) {
        if argc < 3 {
            write_all(2, b"renice: option requires an argument -- n\n");
            libc::exit(1)
        }
        // SAFETY: argc >= 3 keeps argv[2] in range; array stays readable.
        unsafe { argv.add(2).read() }
    } else {
        arg1
    };

    if prio_ptr.is_null() {
        write_all(2, b"renice: missing priority\n");
        libc::exit(1)
    }

    let nice = match parse_i32(prio_ptr) {
        Some(n) => clamp_nice(n),
        None => {
            write_all(2, b"renice: invalid priority\n");
            libc::exit(1)
        }
    };

    // Apply to self. ID operands are accepted but not individually
    // retargeted (no cross-process scheduling control yet).
    // SAFETY: setpriority is a plain syscall wrapper with scalar args.
    let rc = unsafe { libc::setpriority(PRIO_PROCESS, 0, nice) };
    if rc < 0 {
        write_all(2, b"renice: failed to set priority\n");
        libc::exit(1)
    }

    write_all(1, b"renice: priority set\n");
    libc::exit(0)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns `true` if the C string at `ptr` is exactly `"-n"`.
fn is_dash_n(ptr: *const u8) -> bool {
    // SAFETY: ptr is a NUL-terminated C string from the kernel argv; we
    // stop reading at the terminator.
    let b0 = unsafe { ptr.read() };
    if b0 != b'-' {
        return false;
    }
    // SAFETY: b0 is non-NUL, so index 1 is still within the string.
    let b1 = unsafe { ptr.add(1).read() };
    if b1 != b'n' {
        return false;
    }
    // SAFETY: b1 is non-NUL, so index 2 is within the string.
    let b2 = unsafe { ptr.add(2).read() };
    b2 == 0
}

/// Parse a signed decimal integer from a NUL-terminated C string.
///
/// Returns `None` on empty input, a stray sign, or any non-digit byte.
fn parse_i32(ptr: *const u8) -> Option<i32> {
    let mut i = 0usize;
    let mut neg = false;

    // SAFETY: ptr is a NUL-terminated C string from the kernel argv.
    let first = unsafe { ptr.read() };
    if first == b'-' || first == b'+' {
        neg = first == b'-';
        i = 1;
    }

    let mut acc: i32 = 0;
    let mut saw_digit = false;
    loop {
        // SAFETY: we advance only while the previous byte was non-NUL, so
        // each indexed read stays within the C string.
        let b = unsafe { ptr.add(i).read() };
        if b == 0 {
            break;
        }
        if !b.is_ascii_digit() {
            return None;
        }
        let d = (b - b'0') as i32;
        acc = acc.checked_mul(10)?.checked_add(d)?;
        saw_digit = true;
        i += 1;
    }

    if !saw_digit {
        return None;
    }
    Some(if neg { -acc } else { acc })
}

/// Clamp a nice value to the POSIX `[-20, 19]` range.
fn clamp_nice(nice: i32) -> i32 {
    nice.clamp(NICE_MIN, NICE_MAX)
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
