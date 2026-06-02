// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/tty` — print the name of the terminal connected to stdin.
//!
//! POSIX subset:
//!   `tty`          — print `/dev/console\n` if stdin is a character device,
//!                    otherwise print `not a tty\n`.
//!   `tty -s`       — silent mode; emit nothing, exit status only.
//!
//! Exit status:
//!   0  — stdin is a terminal
//!   1  — stdin is not a terminal
//!   2  — `fstat` failed or invalid option
//!
//! ONCRIX has no `isatty(3)` yet, so this checks `fstat(0)` and treats any
//! character device on fd 0 as the controlling terminal (`/dev/console`).
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/tty.html`

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
        main = sym tty_main,
    );
}

extern "C" fn tty_main(argc: usize, argv: *const *const u8) -> ! {
    let mut silent = false;

    let mut i = 1usize;
    while i < argc {
        // SAFETY: 0 < i < argc; argv[i] is a valid C string.
        let arg = unsafe { cstr_at(argv, i) };
        match arg {
            b"-s" => silent = true,
            b"--" => {
                i += 1;
                break;
            }
            _ => {
                if !silent {
                    write_err(b"tty: usage: tty [-s]\n");
                }
                libc::exit(2);
            }
        }
        i += 1;
    }

    // Any remaining positional arguments are an error per POSIX usage.
    if i < argc {
        if !silent {
            write_err(b"tty: usage: tty [-s]\n");
        }
        libc::exit(2);
    }

    // SAFETY: `Stat` is a `#[repr(C)]` POD; the kernel fully overwrites it
    // on success and we never read it on failure.
    let mut st = core::mem::MaybeUninit::<libc::Stat>::zeroed();
    let r = unsafe { libc::fstat(0, st.as_mut_ptr()) };
    if r < 0 {
        if !silent {
            write_out(b"not a tty\n");
        }
        libc::exit(2);
    }

    // SAFETY: `fstat` returned success, so the kernel initialized `st`.
    let st = unsafe { st.assume_init() };
    let is_tty = (st.st_mode & libc::S_IFMT) == libc::S_IFCHR;

    if is_tty {
        if !silent {
            write_out(b"/dev/console\n");
        }
        libc::exit(0);
    } else {
        if !silent {
            write_out(b"not a tty\n");
        }
        libc::exit(1);
    }
}

fn write_out(msg: &[u8]) {
    write_fd(1, msg);
}

fn write_err(msg: &[u8]) {
    write_fd(2, msg);
}

fn write_fd(fd: i32, msg: &[u8]) {
    let mut pos = 0;
    while pos < msg.len() {
        // SAFETY: `msg` is a valid byte slice; the offset is in-bounds.
        let n = unsafe { libc::write(fd, msg[pos..].as_ptr(), msg.len() - pos) };
        if n <= 0 {
            break;
        }
        pos += n as usize;
    }
}

/// Returns the `idx`-th argv entry as a byte slice (without NUL).
///
/// # Safety
///
/// Caller guarantees `idx < argc` and `argv` is a valid argv pointer.
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
    // SAFETY: static byte slice with valid pointer and length.
    unsafe { libc::write(2, b"tty: panic\n".as_ptr(), 11) };
    libc::exit(2)
}
